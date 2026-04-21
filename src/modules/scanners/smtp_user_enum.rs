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

use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use telnet::{Telnet, Event};
use crossbeam_channel::unbounded;
use crate::utils::{
    cfg_prompt_default, cfg_prompt_port, cfg_prompt_yes_no,
    cfg_prompt_int_range, cfg_prompt_existing_file, cfg_prompt_output_file,
};
use crate::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};

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

        crate::mprint!(
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
        crate::mprintln!();
        let total = self.total_checked.load(Ordering::Relaxed);
        let valid = self.valid_users.load(Ordering::Relaxed);
        let invalid = self.invalid_users.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();

        crate::mprintln!("{}", "=== Statistics ===".bold());
        crate::mprintln!("  Total checked:     {}", total);
        crate::mprintln!("  Valid users:        {}", valid.to_string().green().bold());
        crate::mprintln!("  Invalid users:      {}", invalid);
        crate::mprintln!("  Errors:             {}", errors.to_string().red());
        crate::mprintln!("  Elapsed time:       {:.2}s", elapsed);
        if elapsed > 0.0 {
            crate::mprintln!("  Average rate:       {:.1} checks/s", total as f64 / elapsed);
        }
    }
}

fn display_banner() {
    if crate::utils::is_batch_mode() { return; }
    crate::mprintln!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   SMTP Username Enumeration Scanner                        ║".cyan());
    crate::mprintln!("{}", "║   Enumerates usernames using SMTP VRFY command             ║".cyan());
    crate::mprintln!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
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
    if is_mass_scan_target(target) {
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "SMTP-Enum",
            default_port: 25,
            state_file: "smtp_user_enum_mass_state.log",
            default_output: "smtp_user_enum_mass_results.txt",
            default_concurrency: 500,
        }, move |ip, port| {
            async move {
                if crate::utils::tcp_port_open(ip, port, std::time::Duration::from_secs(3)).await {
                    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                    Some(format!("[{}] {}:{} SMTP-Enum open\n", ts, ip, port))
                } else {
                    None
                }
            }
        }).await;
    }

    display_banner();
    crate::mprintln!("{}", format!("[*] Initial target: {}", target).cyan());
    crate::mprintln!();

    crate::mprintln!("{}", "[ Configuration Menu ]".bold().green());
    crate::mprintln!("  1. Single target (use current target only)");
    crate::mprintln!("  2. Targets from file (ignore current target)");
    crate::mprintln!("  3. Current target + targets from file");
    crate::mprintln!();
    let mode = cfg_prompt_default("mode", "Select mode [1-3] (default 1)", "1").await?;

    // Build initial target list based on selected mode
    let mut targets: Vec<String> = Vec::new();
    match mode.trim() {
        "2" => {
            let file_path = cfg_prompt_existing_file("target_file", "Targets file (one IP/hostname per line)").await?;
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
            let file_path = cfg_prompt_existing_file("additional_target_file", "Additional targets file (one IP/hostname per line)").await?;
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

    let port = cfg_prompt_port("port", "SMTP Port", DEFAULT_SMTP_PORT).await?;
    let username_wordlist = cfg_prompt_existing_file("wordlist", "Username wordlist file").await?;
    let threads = cfg_prompt_int_range("threads", "Threads", DEFAULT_THREADS as i64, 1, 1024).await? as usize;
    let timeout_ms = cfg_prompt_int_range("timeout_ms", "Timeout in milliseconds", DEFAULT_TIMEOUT_MS as i64, 100, 60000).await? as u64;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;

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
                crate::mprintln!(
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

        crate::mprintln!("{}", format!("[*] Loaded {} username(s).", usernames.len()).cyan());
        crate::mprintln!(
            "{}",
            format!(
                "[*] Total targets: {} (port {})",
                normalized_targets.len(),
                config.port
            )
            .cyan()
        );
        crate::mprintln!("{}", format!("[*] Threads: {}", config.threads).cyan());
        crate::mprintln!("{}", format!("[*] Timeout: {}ms", config.timeout_ms).cyan());
        crate::mprintln!();

        let found = Arc::new(Mutex::new(Vec::new()));
        let unknown = Arc::new(Mutex::new(Vec::new()));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Statistics::new());
        let semaphore = Arc::new(tokio::sync::Semaphore::new(config.threads));
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

        // Worker tasks
        let mut handles = Vec::new();
        for _ in 0..config.threads {
            let rx = rx.clone();
            let stop_flag = Arc::clone(&stop_flag);
            let found = Arc::clone(&found);
            let unknown = Arc::clone(&unknown);
            let stats = Arc::clone(&stats);
            let config = config.clone();
            let semaphore = Arc::clone(&semaphore);

            let handle = tokio::spawn(async move {
                while let Ok((raw_target, addr, username)) = rx.recv() {
                    if stop_flag.load(Ordering::Relaxed) {
                        break;
                    }

                    let _permit = semaphore.acquire().await;

                    let addr_c = addr.clone();
                    let username_c = username.clone();
                    let timeout_ms = config.timeout_ms;
                    let result = tokio::task::spawn_blocking(move || {
                        verify_smtp_user(&addr_c, &username_c, timeout_ms)
                    }).await;

                    let result = match result {
                        Ok(r) => r,
                        Err(e) => Err(anyhow::anyhow!("Task join error: {}", e)),
                    };

                    match result {
                        Ok(Some(response)) => {
                            crate::mprintln!(
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
                                crate::mprintln!(
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
                                    crate::meprintln!(
                                        "\r{}",
                                        format!(
                                            "[?] {}@{} -> {}",
                                            username, raw_target, msg
                                        )
                                        .yellow()
                                    );
                                }
                            } else if config.verbose {
                                crate::meprintln!("\r{}", format!("[!] {}: {}", username, msg).red());
                            }
                        }
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }

        // Stop progress reporter
        stop_flag.store(true, Ordering::Relaxed);
        let _ = progress_handle.join();

        // Final reporting including unknown responses
        return finalize_and_report(found, unknown, stats).await;
    }

    // Streaming mode for very large username lists
    let size_mb = (size_bytes as f64) / (1024.0 * 1024.0);
    crate::mprintln!(
        "{}",
        format!(
            "[*] Large username wordlist detected (~{:.1} MB) – streaming line by line",
            size_mb
        )
        .cyan()
    );
    crate::mprintln!(
        "{}",
        format!(
            "[*] Total targets: {} (port {})",
            normalized_targets.len(),
            config.port
        )
        .cyan()
    );
    crate::mprintln!("{}", format!("[*] Threads: {}", config.threads).cyan());
    crate::mprintln!("{}", format!("[*] Timeout: {}ms", config.timeout_ms).cyan());
    crate::mprintln!();
    
    let found = Arc::new(Mutex::new(Vec::new()));
    let unknown = Arc::new(Mutex::new(Vec::new()));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Statistics::new());
    let semaphore = Arc::new(tokio::sync::Semaphore::new(config.threads));
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
                crate::meprintln!(
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
    
    // Worker tasks
    let mut handles = Vec::new();
    for _ in 0..config.threads {
        let rx = rx.clone();
        let stop_flag = Arc::clone(&stop_flag);
        let found = Arc::clone(&found);
        let unknown = Arc::clone(&unknown);
        let stats = Arc::clone(&stats);
        let config = config.clone();
        let semaphore = Arc::clone(&semaphore);

        let handle = tokio::spawn(async move {
            while let Ok((raw_target, addr, username)) = rx.recv() {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }

                let _permit = semaphore.acquire().await;

                let addr_c = addr.clone();
                let username_c = username.clone();
                let timeout_ms = config.timeout_ms;
                let result = tokio::task::spawn_blocking(move || {
                    verify_smtp_user(&addr_c, &username_c, timeout_ms)
                }).await;

                let result = match result {
                    Ok(r) => r,
                    Err(e) => Err(anyhow::anyhow!("Task join error: {}", e)),
                };

                match result {
                    Ok(Some(response)) => {
                        crate::mprintln!(
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
                            crate::mprintln!(
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
                                crate::meprintln!(
                                    "\r{}",
                                    format!(
                                        "[?] {}@{} -> {}",
                                        username, raw_target, msg
                                    )
                                    .yellow()
                                );
                            }
                        } else if config.verbose {
                            crate::meprintln!("\r{}", format!("[!] {}: {}", username, msg).red());
                        }
                    }
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }
    
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
    
    let stream = crate::utils::blocking_tcp_connect(&socket, Duration::from_millis(timeout_ms))
        .context("Connection timeout")?;
    let _ = stream.set_nodelay(true);

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
    
    // Read VRFY response (cap at 8KB to prevent OOM from malicious servers)
    let start = Instant::now();
    let mut response_text = String::new();
    const MAX_RESPONSE: usize = 8192;

    while start.elapsed() < timeout {
        match telnet.read() {
            Ok(Event::Data(data)) => {
                let response = String::from_utf8_lossy(&data);
                if response_text.len() + response.len() > MAX_RESPONSE {
                    break; // Cap response accumulation
                }
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

    let found_empty = {
        let found_guard = found.lock().unwrap_or_else(|e| e.into_inner());
        if found_guard.is_empty() {
            crate::mprintln!("{}", "[-] No valid usernames found.".yellow());
            true
        } else {
            crate::mprintln!(
                "{}",
                format!("[+] Found {} valid username(s):", found_guard.len())
                    .green()
                    .bold()
            );
            for (username, response) in found_guard.iter() {
                crate::mprintln!("  {}  {} - {}", "✓".green(), username, response);
            }
            false
        }
    }; // guard dropped here — before any .await

    if !found_empty {
        if cfg_prompt_yes_no("save_valid", "Save valid usernames?", false).await? {
            let filename = cfg_prompt_output_file("valid_output", "What should the valid results be saved as?", "smtp_valid_users.txt").await?;
            if filename.is_empty() {
                crate::mprintln!("{}", "[-] Filename cannot be empty.".red());
            } else {
                let found_guard = found.lock().unwrap_or_else(|e| e.into_inner());
                save_results(&filename, &found_guard)?;
                crate::mprintln!("{}", format!("[+] Results saved to {}", filename).green());
            }
        }
    }

    let unknown_has_data = {
        let unknown_guard = unknown.lock().unwrap_or_else(|e| e.into_inner());
        if !unknown_guard.is_empty() {
            crate::mprintln!(
                "{}",
                format!(
                    "[?] Collected {} unknown VRFY response(s).",
                    unknown_guard.len()
                )
                .yellow()
                .bold()
            );
            true
        } else {
            false
        }
    }; // guard dropped before await

    if unknown_has_data {
        if cfg_prompt_yes_no("save_unknown", "Save unknown responses to file?", false).await? {
            let default_name = "smtp_unknown_responses.txt";
            let chosen = cfg_prompt_output_file("unknown_output", "What should the unknown results be saved as?", default_name).await?;
            let unknown_guard = unknown.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(e) = save_unknown_responses(&chosen, &unknown_guard) {
                crate::mprintln!(
                    "{}",
                    format!("[!] Failed to save unknown responses: {}", e).red()
                );
            } else {
                crate::mprintln!(
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

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "SMTP User Enumeration".to_string(),
        description: "Enumerates valid usernames on SMTP servers using VRFY commands with wordlist-based concurrent scanning.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}


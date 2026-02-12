use anyhow::{anyhow, Result, Context};
use colored::*;
use suppaftp::tokio::{AsyncFtpStream, AsyncNativeTlsFtpStream, AsyncNativeTlsConnector};
use suppaftp::async_native_tls::TlsConnector;
use tokio::time::{timeout, Duration};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Semaphore;
use tokio::process::Command;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use rand::Rng;
use tokio::net::TcpStream; // For fast connect check

use crate::utils::{prompt_default, prompt_int_range, prompt_yes_no}; 

const DEFAULT_TIMEOUT_SECS: u64 = 5;
const CONNECT_TIMEOUT_MS: u64 = 3000;
const STATE_FILE: &str = "ftp_hose_state.log";

// Hardcoded exclusions
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

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   FTP Anonymous Login Checker                             ║".cyan());
    println!("{}", "║   Supports IPv4/IPv6 & Mass Scanning (Hose Mode)          ║".cyan());
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
        let clean = if target.starts_with('[') && target.ends_with(']') {
            &target[1..target.len() - 1]
        } else {
            target
        };
        if clean.contains(':') {
            format!("[{}]:{}", clean, port)
        } else {
            format!("{}:{}", clean, port)
        }
    }
}

/// Anonymous FTP/FTPS login test with IPv6 support
pub async fn run(target: &str) -> Result<()> {
    display_banner();

    // Check for Mass Scan Mode conditions
    let is_mass_scan = target == "random" || target == "0.0.0.0" || target == "0.0.0.0/0" || std::path::Path::new(target).is_file();

    if is_mass_scan {
        println!("{}", format!("[*] Target: {}", target).cyan());
        println!("{}", "[*] Mode: Mass Scan / Hose".yellow());
        return run_mass_scan(target).await;
    }

    // --- Standard Single Target Logic ---
    let addr = format_addr(target, 21);
    let domain = target
        .trim_start_matches('[')
        .split(&[']', ':'][..])
        .next()
        .unwrap_or(target);

    println!("{}", format!("[*] Target: {}", target).cyan());
    println!("{}", format!("[*] Connecting to FTP service on {}...", addr).cyan());
    println!();

    // 1️⃣ Try plain FTP first
    match timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS), AsyncFtpStream::connect(&addr)).await {
        Ok(Ok(mut ftp)) => {
            let result = ftp.login("anonymous", "anonymous").await;
            if result.is_ok() {
                println!("{}", "[+] Anonymous login successful (FTP)".green().bold());
                // Optional: Check if we can run command?
                // For single target, we usually just report login success in legacy mode.
                // But let's be consistent and try listing.
                match ftp.list(None).await {
                    Ok(_) => println!("{}", "[+] LIST command successful - Read Access Confirmed".green()),
                    Err(e) => println!("{}", format!("[-] Login worked but LIST failed: {}", e).yellow()),
                }
                let _ = ftp.quit().await;
                return Ok(());
            } else if let Err(e) = result {
                if e.to_string().contains("530") {
                    println!("{}", "[-] Anonymous login rejected (FTP)".yellow());
                    return Ok(());
                } else if e.to_string().contains("550 SSL") {
                    println!("{}", "[*] FTP server requires TLS — upgrading to FTPS...".cyan());
                } else {
                    return Err(anyhow!("FTP error: {}", e));
                }
            }
        }
        Ok(Err(e)) => println!("{}", format!("[!] FTP connection error: {}", e).red()),
        Err(_) => println!("{}", "[-] FTP connection timed out".yellow()),
    }

    // 2️⃣ Fallback to FTPS
    println!("{}", "[*] Attempting FTPS connection...".cyan());
    
    let mut ftps = AsyncNativeTlsFtpStream::connect(&addr)
        .await
        .map_err(|e| anyhow!("FTPS connect failed: {}", e))?;

    let connector = AsyncNativeTlsConnector::from(
        TlsConnector::new()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true),
    );

    ftps = ftps
        .into_secure(connector, domain)
        .await
        .map_err(|e| anyhow!("FTPS TLS upgrade failed: {}", e))?;

    match ftps.login("anonymous", "anonymous").await {
        Ok(_) => {
            println!("{}", "[+] Anonymous login successful (FTPS)".green().bold());
             match ftps.list(None).await {
                Ok(_) => println!("{}", "[+] LIST command successful - Read Access Confirmed".green()),
                Err(e) => println!("{}", format!("[-] Login worked but LIST failed: {}", e).yellow()),
            }
            let _ = ftps.quit().await;
        }
        Err(e) if e.to_string().contains("530") => {
            println!("{}", "[-] Anonymous login rejected (FTPS)".yellow());
        }
        Err(e) => return Err(anyhow!("FTPS login error: {}", e)),
    }

    Ok(())
}

async fn run_mass_scan(target: &str) -> Result<()> {
    // Prep
    let concurrency = prompt_int_range("Max concurrent hosts to scan", 500, 1, 10000)? as usize;
    let _verbose = prompt_yes_no("Verbose mode?", false)?; 
    let output_file = prompt_default("Output result file", "ftp_mass_results.txt")?;

    // Ask about exclusions
    let use_exclusions = prompt_yes_no("Exclude reserved/private ranges?", true)?;
    
    // Parse exclusions
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

    // Stats
    let s_checked = stats_checked.clone();
    let s_found = stats_found.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            println!(
                "[*] Status: {} IPs scanned, {} open anonymous FTP found",
                s_checked.load(Ordering::Relaxed),
                s_found.load(Ordering::Relaxed).to_string().green().bold()
            );
        }
    });

    let run_random = target == "random" || target == "0.0.0.0" || target == "0.0.0.0/0";

    if run_random {
        // Initialize state file
        OpenOptions::new().create(true).write(true).open(STATE_FILE).await?;

        println!("{}", "[*] Starting Random Internet Scan...".green());
        loop {
             let permit = semaphore.clone().acquire_owned().await.context("Semaphore acquisition failed")?;
             let exc = exclusions.clone();
             let sc = stats_checked.clone();
             let sf = stats_found.clone();
             let of = output_file.clone();
             
             tokio::spawn(async move {
                 let ip = generate_random_public_ip(&exc);
                 if !is_ip_checked(&ip).await {
                     mark_ip_checked(&ip).await;
                     mass_scan_host(ip, sf, of).await;
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
             let sc = stats_checked.clone();
             let sf = stats_found.clone();
             let of = output_file.clone();
             
             // Simple IP parse
             if let Ok(ip) = ip_str.parse::<IpAddr>() {
                 tokio::spawn(async move {
                    if !is_ip_checked(&ip).await {
                        mark_ip_checked(&ip).await;
                        mass_scan_host(ip, sf, of).await;
                    }
                    sc.fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                 });
             } else {
                 drop(permit); 
             }
        }
        
        for _ in 0..concurrency {
            let _ = semaphore.acquire().await.context("Semaphore acquisition failed")?;
        }
    }

    Ok(())
}

async fn mass_scan_host(
    ip: IpAddr, 
    stats_found: Arc<AtomicUsize>,
    output_file: String,
) {
    let sa = SocketAddr::new(ip, 21);
    
    // 1. Connection Check
    if timeout(Duration::from_millis(CONNECT_TIMEOUT_MS), TcpStream::connect(&sa)).await.is_err() {
        return;
    }

    // 2. FTP Login (Plain only for speed/mass scan)
    let addr_str = format!("{}:21", ip);
    match timeout(Duration::from_millis(5000), AsyncFtpStream::connect(&addr_str)).await {
        Ok(Ok(mut ftp)) => {
            let result = ftp.login("anonymous", "anonymous").await;
            if result.is_ok() {
                // LOGIN OK - Now VERIFY command capability
                // We use LIST (None implies current directory)
                // We set a short timeout for list because sometimes passive mode hangs on bad NATs
                match timeout(Duration::from_secs(5), ftp.list(None)).await {
                    Ok(Ok(_)) => {
                        // Success: Login + List
                        // Format: IP:PORT:USER:PASS
                        let msg = format!("{}:21:anonymous:anonymous", ip);
                        println!("\r{}", format!("[+] FOUND: {}", msg).green().bold());
                        
                        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&output_file).await {
                           let _ = file.write_all(format!("{}\n", msg).as_bytes()).await;
                        }
                        stats_found.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(Err(_)) => {
                        // Login ok, List failed (550 or similar)
                    }
                    Err(_) => {
                        // List timed out (PASV issue?)
                    }
                }
                let _ = ftp.quit().await;
            }
        }
        _ => {}
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
        
        if !excluded {
            return ip_addr;
        }
    }
}

async fn is_ip_checked(ip: &impl ToString) -> bool {
    if !std::path::Path::new(STATE_FILE).exists() {
        return false;
    }

    let ip_s = ip.to_string();
    let status = Command::new("grep")
        .arg("-F")
        .arg("-q")
        .arg(format!("checked: {}", ip_s))
        .arg(STATE_FILE)
        .stderr(std::process::Stdio::null()) // Suppress stderr just in case
        .status()
        .await;
    
    match status {
        Ok(s) => s.success(), 
        Err(_) => false, 
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

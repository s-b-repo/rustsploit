//! SSH Service Scanner Module
//! 
//! Based on SSHPWN framework - scans for SSH services and grabs banners.
//! Supports IPv4/IPv6, CIDR ranges, and concurrent scanning.
//!
//! For authorized penetration testing only.

use anyhow::{anyhow, Result};
use colored::*;
use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::Semaphore,
    task::spawn_blocking,
    time::sleep,
};
use ipnetwork::IpNetwork;

const DEFAULT_SSH_PORT: u16 = 22;
const DEFAULT_TIMEOUT_SECS: u64 = 5;
const DEFAULT_THREADS: usize = 50;
const PROGRESS_INTERVAL_SECS: u64 = 2;

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   SSH Service Scanner                                             ║".cyan());
    println!("{}", "║   Scan networks for SSH services and grab banners                 ║".cyan());
    println!("{}", "║                                                                   ║".cyan());
    println!("{}", "║   Features:                                                       ║".cyan());
    println!("{}", "║   - CIDR range support                                            ║".cyan());
    println!("{}", "║   - IPv4/IPv6 support                                             ║".cyan());
    println!("{}", "║   - Banner grabbing                                               ║".cyan());
    println!("{}", "║   - Concurrent scanning                                           ║".cyan());
    println!("{}", "║   - Results export                                                ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════════════╝".cyan());
    println!();
}

/// Statistics tracking
struct Statistics {
    total_scanned: AtomicU64,
    ssh_found: AtomicU64,
    errors: AtomicU64,
    start_time: Instant,
}

impl Statistics {
    fn new() -> Self {
        Self {
            total_scanned: AtomicU64::new(0),
            ssh_found: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }
    
    fn record_scan(&self, found_ssh: bool, error: bool) {
        self.total_scanned.fetch_add(1, Ordering::Relaxed);
        if found_ssh {
            self.ssh_found.fetch_add(1, Ordering::Relaxed);
        }
        if error {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    fn print_progress(&self) {
        let scanned = self.total_scanned.load(Ordering::Relaxed);
        let found = self.ssh_found.load(Ordering::Relaxed);
        let errors = self.errors.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 { scanned as f64 / elapsed } else { 0.0 };
        
        print!(
            "\r{} {} scanned | {} SSH | {} errors | {:.1}/s    ",
            "[Progress]".cyan(),
            scanned.to_string().bold(),
            found.to_string().green(),
            errors.to_string().red(),
            rate
        );
        let _ = std::io::stdout().flush();
    }
    
    fn print_summary(&self) {
        println!();
        println!("{}", "=== Scan Summary ===".cyan().bold());
        println!("Total scanned: {}", self.total_scanned.load(Ordering::Relaxed));
        println!("SSH services found: {}", self.ssh_found.load(Ordering::Relaxed).to_string().green());
        println!("Errors: {}", self.errors.load(Ordering::Relaxed));
        println!("Elapsed: {:.2}s", self.start_time.elapsed().as_secs_f64());
    }
}

/// SSH scan result
#[derive(Clone, Debug)]
pub struct SshScanResult {
    pub host: String,
    pub port: u16,
    pub banner: String,
}

/// Grab SSH banner from a host
fn grab_ssh_banner(host: &str, port: u16, timeout_secs: u64) -> Option<String> {
    // Build address
    let addr_str = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };
    
    // Resolve and connect
    let addrs: Vec<SocketAddr> = match addr_str.to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(_) => return None,
    };
    
    if addrs.is_empty() {
        return None;
    }
    
    let timeout = Duration::from_secs(timeout_secs);
    
    for addr in addrs {
        if let Ok(stream) = TcpStream::connect_timeout(&addr, timeout) {
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            
            let mut stream = stream;
            let mut buffer = [0u8; 256];
            
            match stream.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buffer[..n])
                        .trim()
                        .to_string();
                    if banner.starts_with("SSH-") {
                        return Some(banner);
                    }
                }
                _ => {}
            }
        }
    }
    
    None
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

/// Load targets from file
fn load_targets_from_file(path: &str, port: u16) -> Result<Vec<(String, u16)>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut targets = Vec::new();
    
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        // Check for port override (host:port)
        if let Some((host, port_str)) = line.rsplit_once(':') {
            if let Ok(p) = port_str.parse::<u16>() {
                targets.push((host.to_string(), p));
                continue;
            }
        }
        
        targets.push((line.to_string(), port));
    }
    
    Ok(targets)
}

/// Main scan function
pub async fn scan_ssh(
    targets: Vec<(String, u16)>,
    threads: usize,
    timeout_secs: u64,
) -> Vec<SshScanResult> {
    let total = targets.len();
    println!("{}", format!("[*] Scanning {} targets...", total).cyan());
    
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
    
    // Scan tasks
    let mut handles = Vec::new();
    
    for (host, port) in targets {
        let semaphore = Arc::clone(&semaphore);
        let results = Arc::clone(&results);
        let stats = Arc::clone(&stats);
        
        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            
            let host_clone = host.clone();
            let result = spawn_blocking(move || {
                grab_ssh_banner(&host_clone, port, timeout_secs)
            }).await;
            
            match result {
                Ok(Some(banner)) => {
                    stats.record_scan(true, false);
                    let result = SshScanResult {
                        host: host.clone(),
                        port,
                        banner: banner.clone(),
                    };
                    println!("\r{}", format!("[+] {}:{} - {}", host, port, banner).green());
                    let _ = std::io::stdout().flush();
                    results.lock().await.push(result);
                }
                Ok(None) => {
                    stats.record_scan(false, false);
                }
                Err(_) => {
                    stats.record_scan(false, true);
                }
            }
        });
        
        handles.push(handle);
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
fn save_results(results: &[SshScanResult], path: &str) -> Result<()> {
    let mut file = File::create(path)?;
    
    writeln!(file, "# SSH Scan Results")?;
    writeln!(file, "# Generated by RustSploit SSH Scanner")?;
    writeln!(file, "# Total: {} SSH services found", results.len())?;
    writeln!(file)?;
    
    for result in results {
        writeln!(file, "{}:{} - {}", result.host, result.port, result.banner)?;
    }
    
    println!("{}", format!("[+] Results saved to: {}", path).green());
    Ok(())
}

/// Prompt helper
fn prompt(message: &str) -> Result<String> {
    print!("{}: ", message);
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn prompt_default(message: &str, default: &str) -> Result<String> {
    print!("{} [{}]: ", message, default);
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
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
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_lowercase();
    match trimmed.as_str() {
        "" => Ok(default),
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => Ok(default),
    }
}

/// Main entry point
pub async fn run(target: &str) -> Result<()> {
    display_banner();
    
    let mut targets = Vec::new();
    
    // Parse initial target
    if !target.trim().is_empty() {
        println!("{}", format!("[*] Initial target: {}", target).cyan());
    }
    
    // Get port
    let port: u16 = prompt_default("SSH Port", "22")?.parse().unwrap_or(DEFAULT_SSH_PORT);
    
    // Get additional targets
    let more_targets = prompt("Additional targets (comma-separated, CIDR, or leave empty)")?;
    
    // Add initial target
    if !target.trim().is_empty() {
        targets.extend(parse_targets(target, port));
    }
    
    // Add additional targets
    if !more_targets.is_empty() {
        targets.extend(parse_targets(&more_targets, port));
    }
    
    // Load from file?
    if prompt_yes_no("Load targets from file?", false)? {
        let file_path = prompt("File path")?;
        if !file_path.is_empty() {
            match load_targets_from_file(&file_path, port) {
                Ok(file_targets) => {
                    println!("{}", format!("[*] Loaded {} targets from file", file_targets.len()).cyan());
                    targets.extend(file_targets);
                }
                Err(e) => {
                    println!("{}", format!("[-] Failed to load file: {}", e).red());
                }
            }
        }
    }
    
    // Deduplicate
    let unique: HashSet<_> = targets.into_iter().collect();
    let targets: Vec<_> = unique.into_iter().collect();
    
    if targets.is_empty() {
        return Err(anyhow!("No targets specified"));
    }
    
    println!("{}", format!("[*] Total unique targets: {}", targets.len()).cyan());
    
    // Get scan options
    let threads: usize = prompt_default("Concurrent threads", &DEFAULT_THREADS.to_string())?
        .parse()
        .unwrap_or(DEFAULT_THREADS);
    let timeout: u64 = prompt_default("Connection timeout (seconds)", &DEFAULT_TIMEOUT_SECS.to_string())?
        .parse()
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    
    println!();
    
    // Run scan
    let results = scan_ssh(targets, threads, timeout).await;
    
    // Save results?
    if !results.is_empty() && prompt_yes_no("Save results to file?", true)? {
        let output_path = prompt_default("Output file", "ssh_scan_results.txt")?;
        if let Err(e) = save_results(&results, &output_path) {
            println!("{}", format!("[-] Failed to save: {}", e).red());
        }
    }
    
    println!();
    println!("{}", format!("[*] SSH scanner complete. Found {} services.", results.len()).green());
    
    Ok(())
}


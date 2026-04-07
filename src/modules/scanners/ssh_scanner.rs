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
    net::{SocketAddr, ToSocketAddrs},
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
use crate::modules::creds::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_yes_no, cfg_prompt_output_file,
};

const DEFAULT_SSH_PORT: u16 = 22;
const DEFAULT_TIMEOUT_SECS: u64 = 5;
const DEFAULT_THREADS: usize = 50;
const PROGRESS_INTERVAL_SECS: u64 = 2;

fn display_banner() {
    crate::mprintln!("{}", "╔═══════════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   SSH Service Scanner                                             ║".cyan());
    crate::mprintln!("{}", "║   Scan networks for SSH services and grab banners                 ║".cyan());
    crate::mprintln!("{}", "║                                                                   ║".cyan());
    crate::mprintln!("{}", "║   Features:                                                       ║".cyan());
    crate::mprintln!("{}", "║   - CIDR range support                                            ║".cyan());
    crate::mprintln!("{}", "║   - IPv4/IPv6 support                                             ║".cyan());
    crate::mprintln!("{}", "║   - Banner grabbing                                               ║".cyan());
    crate::mprintln!("{}", "║   - Concurrent scanning                                           ║".cyan());
    crate::mprintln!("{}", "║   - Results export                                                ║".cyan());
    crate::mprintln!("{}", "╚═══════════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
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
        
        crate::mprint!(
            "\r{} {} scanned | {} SSH | {} errors | {:.1}/s    ",
            "[Progress]".cyan(),
            scanned.to_string().bold(),
            found.to_string().green(),
            errors.to_string().red(),
            rate
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
    
    fn print_summary(&self) {
        crate::mprintln!();
        crate::mprintln!("{}", "=== Scan Summary ===".cyan().bold());
        crate::mprintln!("Total scanned: {}", self.total_scanned.load(Ordering::Relaxed));
        crate::mprintln!("SSH services found: {}", self.ssh_found.load(Ordering::Relaxed).to_string().green());
        crate::mprintln!("Errors: {}", self.errors.load(Ordering::Relaxed));
        crate::mprintln!("Elapsed: {:.2}s", self.start_time.elapsed().as_secs_f64());
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
        if let Ok(stream) = crate::utils::blocking_tcp_connect(&addr, timeout) {
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            
            let mut stream = stream;
            let mut buffer = [0u8; 1024];
            
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
                const MAX_CIDR_HOSTS: usize = 65536;
                let host_count: u128 = match network.size() {
                    ipnetwork::NetworkSize::V4(n) => n as u128,
                    ipnetwork::NetworkSize::V6(n) => n,
                };
                if host_count > MAX_CIDR_HOSTS as u128 {
                    crate::mprintln!("{}", format!("[!] CIDR {} has {} hosts — scanning first {} only",
                        s, host_count, MAX_CIDR_HOSTS).yellow());
                }
                for ip in network.iter().take(MAX_CIDR_HOSTS) {
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
    crate::mprintln!("{}", format!("[*] Scanning {} targets...", total).cyan());
    
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
        
        let handle: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.context("Semaphore acquisition failed")?;
            
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
                    crate::mprintln!("\r{}", format!("[+] {}:{} - {}", host, port, banner).green());
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    results.lock().await.push(result);
                }
                Ok(None) => {
                    stats.record_scan(false, false);
                }
                Err(_) => {
                    stats.record_scan(false, true);
                }
            }
            Ok(())
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
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));

    writeln!(file, "# SSH Scan Results")?;
    writeln!(file, "# Generated by RustSploit SSH Scanner")?;
    writeln!(file, "# Total: {} SSH services found", results.len())?;
    writeln!(file)?;
    
    for result in results {
        writeln!(file, "{}:{} - {}", result.host, result.port, result.banner)?;
    }
    
    crate::mprintln!("{}", format!("[+] Results saved to: {}", path).green());
    Ok(())
}

/// Main entry point
pub async fn run(target: &str) -> Result<()> {
    if is_mass_scan_target(target) {
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "SSH-Scanner",
            default_port: 22,
            state_file: "ssh_scanner_mass_state.log",
            default_output: "ssh_scanner_mass_results.txt",
            default_concurrency: 500,
        }, move |ip, port| {
            async move {
                if crate::utils::tcp_port_open(ip, port, std::time::Duration::from_secs(3)).await {
                    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                    Some(format!("[{}] {}:{} SSH-Scanner open\n", ts, ip, port))
                } else {
                    None
                }
            }
        }).await;
    }

    display_banner();

    let mut targets = Vec::new();
    
    // Parse initial target
    if !target.trim().is_empty() {
        crate::mprintln!("{}", format!("[*] Initial target: {}", target).cyan());
    }
    
    // Get port
    let port_str = cfg_prompt_default("port", "SSH Port", "22").await?;
    let port: u16 = port_str.parse().unwrap_or(DEFAULT_SSH_PORT);
    
    // Get additional targets
    let more_targets = cfg_prompt_default("additional_targets", "Additional targets (comma-separated, CIDR, or leave empty)", "").await?;
    
    // Add initial target
    if !target.trim().is_empty() {
        targets.extend(parse_targets(target, port));
    }
    
    // Add additional targets
    if !more_targets.is_empty() {
        targets.extend(parse_targets(&more_targets, port));
    }
    
    // Load from file?
    if cfg_prompt_yes_no("load_from_file", "Load targets from file?", false).await? {
        let file_path = cfg_prompt_default("target_file", "File path", "").await?;
        if !file_path.is_empty() {
            match load_targets_from_file(&file_path, port) {
                Ok(file_targets) => {
                    crate::mprintln!("{}", format!("[*] Loaded {} targets from file", file_targets.len()).cyan());
                    targets.extend(file_targets);
                }
                Err(e) => {
                    crate::mprintln!("{}", format!("[-] Failed to load file: {}", e).red());
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
    
    crate::mprintln!("{}", format!("[*] Total unique targets: {}", targets.len()).cyan());
    
    // Get scan options
    let threads_str = cfg_prompt_default("threads", "Concurrent threads", &DEFAULT_THREADS.to_string()).await?;
    let threads: usize = threads_str.parse().unwrap_or(DEFAULT_THREADS);
    let timeout_str = cfg_prompt_default("timeout", "Connection timeout (seconds)", &DEFAULT_TIMEOUT_SECS.to_string()).await?;
    let timeout: u64 = timeout_str.parse().unwrap_or(DEFAULT_TIMEOUT_SECS);
    
    crate::mprintln!();
    
    // Run scan
    let results = scan_ssh(targets, threads, timeout).await;
    
    // Save results?
    if !results.is_empty() && cfg_prompt_yes_no("save_results", "Save results to file?", true).await? {
        let output_path = cfg_prompt_output_file("output_file", "Output file", "ssh_scan_results.txt").await?;
        if let Err(e) = save_results(&results, &output_path) {
            crate::mprintln!("{}", format!("[-] Failed to save: {}", e).red());
        }
    }
    
    crate::mprintln!();
    crate::mprintln!("{}", format!("[*] SSH scanner complete. Found {} services.", results.len()).green());

    Ok(())
}

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "SSH Service Scanner".to_string(),
        description: "Scans networks for SSH services with banner grabbing, CIDR range support, and concurrent scanning.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}


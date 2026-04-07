//! Redis Unauthenticated Access Scanner
//!
//! Detects Redis instances with no authentication, extracts server info,
//! and identifies potential exploitation vectors.
//!
//! For authorized penetration testing only.

use anyhow::{Result, Context, anyhow};
use colored::*;
use std::time::Duration;
use tokio::time::timeout;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::utils::{cfg_prompt_port, cfg_prompt_yes_no, cfg_prompt_output_file, cfg_prompt_int_range};
use crate::modules::creds::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Redis Unauthenticated Access Scanner".into(),
        description: "Scans for Redis instances with no authentication. Extracts server \
            version, configuration, key count, and identifies potential exploitation \
            vectors such as writable directories and empty requirepass."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec![
            "https://book.hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html".into(),
            "https://redis.io/docs/latest/operate/oss_and_stack/management/security/".into(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

fn display_banner() {
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   Redis Unauthenticated Access Scanner                       ║".cyan());
    crate::mprintln!("{}", "║   Detects open Redis instances and extracts server info       ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

/// Send a Redis command and read the response
async fn redis_command(
    stream: &mut tokio::net::TcpStream,
    cmd: &str,
    timeout_dur: Duration,
) -> Result<String> {
    stream.write_all(cmd.as_bytes()).await
        .context("Failed to send Redis command")?;
    stream.flush().await?;

    let mut buf = vec![0u8; 8192];
    let n = timeout(timeout_dur, stream.read(&mut buf))
        .await
        .context("Redis read timed out")?
        .context("Failed to read Redis response")?;

    if n == 0 {
        return Err(anyhow!("Connection closed by Redis server"));
    }

    Ok(String::from_utf8_lossy(&buf[..n]).to_string())
}

/// Extract a value from Redis INFO output
fn extract_info_field(info: &str, field: &str) -> Option<String> {
    for line in info.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(&format!("{}:", field)) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// Extract value from CONFIG GET response (RESP array format).
/// CONFIG GET returns: *2\r\n$N\r\nKEY\r\n$M\r\nVALUE\r\n
/// Lines: [0]="*2" [1]="$N" [2]="key" [3]="$M" [4]="value"
fn extract_config_value(response: &str) -> Option<String> {
    let lines: Vec<&str> = response.split("\r\n")
        .chain(response.lines()) // handle both \r\n and \n endings
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    // Find value: skip RESP protocol markers (*N, $N), take the 2nd non-marker line
    let mut data_lines = Vec::new();
    for line in &lines {
        if !line.starts_with('*') && !line.starts_with('$') && !line.starts_with('-') {
            data_lines.push(*line);
        }
    }
    // data_lines[0] = key name, data_lines[1] = value
    if data_lines.len() >= 2 {
        let val = data_lines[1];
        if !val.is_empty() {
            return Some(val.to_string());
        }
    }
    // Single data line = key with empty value
    None
}

/// Extract number from DBSIZE response (+N or :N format)
fn extract_dbsize(response: &str) -> Option<u64> {
    let trimmed = response.trim();
    if let Some(rest) = trimmed.strip_prefix(':') {
        return rest.trim().parse().ok();
    }
    if let Some(rest) = trimmed.strip_prefix('+') {
        return rest.trim().parse().ok();
    }
    None
}

pub async fn run(target: &str) -> Result<()> {
    if is_mass_scan_target(target) {
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "Redis",
            default_port: 6379,
            state_file: "redis_scanner_mass_state.log",
            default_output: "redis_scanner_mass_results.txt",
            default_concurrency: 500,
        }, move |ip, port| {
            async move {
                if crate::utils::tcp_port_open(ip, port, Duration::from_secs(3)).await {
                    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                    Some(format!("[{}] {}:{} Redis open\n", ts, ip, port))
                } else {
                    None
                }
            }
        }).await;
    }

    display_banner();

    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());

    let port = cfg_prompt_port("port", "Redis port", 6379).await?;
    let timeout_secs = cfg_prompt_int_range("timeout", "Connection timeout (seconds)", 5, 1, 30).await? as u64;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", false).await?;

    let timeout_dur = Duration::from_secs(timeout_secs);
    let addr = format!("{}:{}", target, port);

    crate::mprintln!();
    crate::mprintln!("{}", format!("[*] Connecting to {}...", addr).bold());

    let mut stream = timeout(timeout_dur, tokio::net::TcpStream::connect(&addr))
        .await
        .context("Connection timed out")?
        .context("Failed to connect to Redis")?;

    // Step 1: PING
    crate::mprintln!("{}", "[*] Sending PING...".dimmed());
    let ping_resp = redis_command(&mut stream, "PING\r\n", timeout_dur).await?;
    let ping_ok = ping_resp.trim().contains("+PONG");

    if ping_ok {
        crate::mprintln!("{}", "[+] PONG received - Redis has NO authentication!".green().bold());
    } else if ping_resp.contains("-NOAUTH") || ping_resp.contains("-ERR") {
        crate::mprintln!("{}", "[-] Redis requires authentication.".yellow());
        crate::mprintln!("{}", format!("    Response: {}", ping_resp.trim()).dimmed());
        return Ok(());
    } else {
        crate::mprintln!("{}", format!("[-] Unexpected PING response: {}", ping_resp.trim()).yellow());
        return Ok(());
    }

    let mut report_lines: Vec<String> = Vec::new();
    report_lines.push(format!("Target: {}:{}", target, port));
    report_lines.push("Authentication: NONE (unauthenticated access)".into());

    // Step 2: INFO
    crate::mprintln!("{}", "[*] Gathering server info...".dimmed());
    match redis_command(&mut stream, "INFO\r\n", timeout_dur).await {
        Ok(info_resp) => {
            let version = extract_info_field(&info_resp, "redis_version")
                .unwrap_or_else(|| "unknown".into());
            let clients = extract_info_field(&info_resp, "connected_clients")
                .unwrap_or_else(|| "unknown".into());
            let memory = extract_info_field(&info_resp, "used_memory_human")
                .unwrap_or_else(|| "unknown".into());
            let os = extract_info_field(&info_resp, "os")
                .unwrap_or_else(|| "unknown".into());
            let tcp_port_val = extract_info_field(&info_resp, "tcp_port")
                .unwrap_or_else(|| port.to_string());

            crate::mprintln!("{}", format!("[+] Redis version:      {}", version).green());
            crate::mprintln!("{}", format!("[+] Connected clients:  {}", clients).green());
            crate::mprintln!("{}", format!("[+] Memory usage:       {}", memory).green());
            crate::mprintln!("{}", format!("[+] OS:                 {}", os).green());
            crate::mprintln!("{}", format!("[+] TCP port:           {}", tcp_port_val).green());

            report_lines.push(format!("Version: {}", version));
            report_lines.push(format!("Clients: {}", clients));
            report_lines.push(format!("Memory: {}", memory));
            report_lines.push(format!("OS: {}", os));
        }
        Err(e) => {
            crate::mprintln!("{}", format!("[!] INFO command failed: {}", e).yellow());
        }
    }

    // Step 3: CONFIG GET requirepass
    crate::mprintln!("{}", "[*] Checking requirepass...".dimmed());
    match redis_command(&mut stream, "CONFIG GET requirepass\r\n", timeout_dur).await {
        Ok(resp) => {
            let pass_val = extract_config_value(&resp).unwrap_or_default();
            if pass_val.is_empty() {
                crate::mprintln!("{}", "[+] requirepass is EMPTY - no password set!".red().bold());
                report_lines.push("requirepass: EMPTY (no password)".into());
            } else {
                crate::mprintln!("{}", "[-] requirepass is set (but was bypassed via unauthenticated access)".yellow());
                report_lines.push(format!("requirepass: set (value: {})", pass_val));
            }
        }
        Err(e) => {
            crate::mprintln!("{}", format!("[!] CONFIG GET requirepass failed: {}", e).yellow());
        }
    }

    // Step 4: CONFIG GET dir
    crate::mprintln!("{}", "[*] Checking working directory...".dimmed());
    match redis_command(&mut stream, "CONFIG GET dir\r\n", timeout_dur).await {
        Ok(resp) => {
            let dir_val = extract_config_value(&resp).unwrap_or_else(|| "unknown".into());
            crate::mprintln!("{}", format!("[+] Working directory:  {}", dir_val).green());
            report_lines.push(format!("Working directory: {}", dir_val));

            if dir_val.contains("/var") || dir_val.contains("/tmp") || dir_val.contains("/home") {
                crate::mprintln!("{}", "[!] Writable directory detected - potential RCE via CONFIG SET dir + dbfilename".red().bold());
                report_lines.push("EXPLOITATION: Writable dir may allow RCE via CONFIG SET".into());
            }
        }
        Err(e) => {
            crate::mprintln!("{}", format!("[!] CONFIG GET dir failed: {}", e).yellow());
        }
    }

    // Step 5: DBSIZE
    crate::mprintln!("{}", "[*] Checking database size...".dimmed());
    match redis_command(&mut stream, "DBSIZE\r\n", timeout_dur).await {
        Ok(resp) => {
            if let Some(count) = extract_dbsize(&resp) {
                crate::mprintln!("{}", format!("[+] Database keys:      {}", count).green());
                report_lines.push(format!("Database keys: {}", count));
            } else {
                crate::mprintln!("{}", format!("[*] DBSIZE response: {}", resp.trim()).dimmed());
            }
        }
        Err(e) => {
            crate::mprintln!("{}", format!("[!] DBSIZE failed: {}", e).yellow());
        }
    }

    // Summary
    crate::mprintln!();
    crate::mprintln!("{}", "=== Exploitation Vectors ===".bold().red());
    crate::mprintln!("  1. Write SSH key:     CONFIG SET dir /root/.ssh; SET key <pubkey>; CONFIG SET dbfilename authorized_keys; BGSAVE");
    crate::mprintln!("  2. Write crontab:     CONFIG SET dir /var/spool/cron; CONFIG SET dbfilename root; SET key <cron payload>; BGSAVE");
    crate::mprintln!("  3. Write webshell:    CONFIG SET dir /var/www/html; CONFIG SET dbfilename shell.php; SET key <php shell>; BGSAVE");
    crate::mprintln!("  4. Lua RCE (< 5.0):  EVAL \"os.execute('id')\" 0");

    // Save results
    if save_results {
        let output_path = cfg_prompt_output_file("output_file", "Output file", "redis_scan_results.txt").await?;
        let content = report_lines.join("\n");
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&output_path)
                .with_context(|| format!("Failed to write results to {}", output_path))?;
            writeln!(f, "\n--- Scan at {} ---", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
                .with_context(|| format!("Failed to write results to {}", output_path))?;
            f.write_all(content.as_bytes())
                .with_context(|| format!("Failed to write results to {}", output_path))?;
        }
        crate::mprintln!("{}", format!("[+] Results saved to '{}'", output_path).green());
    }

    Ok(())
}

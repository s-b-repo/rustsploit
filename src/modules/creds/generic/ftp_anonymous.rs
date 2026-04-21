use anyhow::{anyhow, Result};
use colored::*;
use std::net::IpAddr;
use suppaftp::async_native_tls::TlsConnector;
use suppaftp::tokio::{AsyncFtpStream, AsyncNativeTlsConnector, AsyncNativeTlsFtpStream};
use tokio::time::{timeout, Duration};

use crate::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};
use crate::utils::cfg_prompt_yes_no;

const DEFAULT_TIMEOUT_SECS: u64 = 5;

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "FTP Anonymous Login Checker".to_string(),
        description: "Checks for anonymous FTP access on targets. Supports plain FTP and FTPS, IPv4/IPv6, and mass scanning (hose mode).".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

fn display_banner() {
    if crate::utils::is_batch_mode() { return; }
    crate::mprintln!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   FTP Anonymous Login Checker                             ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Supports IPv4/IPv6 & Mass Scanning (Hose Mode)          ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

/// Format IPv4 or IPv6 addresses with port
fn format_addr(target: &str, port: u16) -> String {
    if target.starts_with('[') && target.contains("]:") {
        target.to_string()
    } else if target.matches(':').count() == 1 && !target.contains('[') {
        target.to_string()
    } else {
        let clean = if target.starts_with('[') && target.ends_with(']') {
            &target[1..target.len() - 1]
        } else {
            target
        };
        if clean.contains(':') {
            format!("[{}]:{}", clean, port)
        } else {
            format!("{}:{}", clean, port)
        }
    }
}

/// Anonymous FTP/FTPS login test with IPv6 support
pub async fn run(target: &str) -> Result<()> {
    display_banner();

    // Check for Mass Scan Mode conditions (also handles CIDR subnets concurrently)
    if is_mass_scan_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());
        crate::mprintln!("{}", "[*] Mode: Mass Scan / Hose".yellow());

        return run_mass_scan(
            target,
            MassScanConfig {
                protocol_name: "FTP Anonymous",
                default_port: 21,
                state_file: "ftp_hose_state.log",
                default_output: "ftp_mass_results.txt",
                default_concurrency: 500,
            },
            |ip: IpAddr, port: u16| async move {
                // Quick connect check
                if !crate::utils::tcp_port_open(ip, port, std::time::Duration::from_secs(3)).await {
                    return None;
                }

                // Plain FTP anonymous login
                let addr_str = format!("{}:{}", ip, port);
                match timeout(
                    Duration::from_millis(5000),
                    AsyncFtpStream::connect(&addr_str),
                )
                .await
                {
                    Ok(Ok(mut ftp)) => {
                        if ftp.login("anonymous", "anonymous").await.is_ok() {
                            match timeout(Duration::from_secs(5), ftp.list(None)).await {
                                Ok(Ok(_)) => {
                                    let msg = format!("{}:{}:anonymous:anonymous", ip, port);
                                    crate::mprintln!(
                                        "\r{}",
                                        format!("[+] FOUND: {}", msg).green().bold()
                                    );
                                    let _ = ftp.quit().await;
                                    return Some(format!("{}\n", msg));
                                }
                                _ => {}
                            }
                            let _ = ftp.quit().await;
                        }
                    }
                    _ => {}
                }
                None
            },
        )
        .await;
    }

    // --- Standard Single Target Logic ---
    let verbose = cfg_prompt_yes_no("verbose", "Verbose output?", false).await?;

    let addr = format_addr(target, 21);
    let domain = target
        .trim_start_matches('[')
        .split(&[']', ':'][..])
        .next()
        .unwrap_or(target);

    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());
    crate::mprintln!(
        "{}",
        format!("[*] Connecting to FTP service on {}...", addr).cyan()
    );
    crate::mprintln!();

    // 1. Try plain FTP first
    if verbose {
        crate::mprintln!(
            "{}",
            format!("[VERBOSE] Attempting plain FTP connection to {}...", addr).dimmed()
        );
    }
    match timeout(
        Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        AsyncFtpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(mut ftp)) => {
            if verbose {
                crate::mprintln!(
                    "{}",
                    format!("[VERBOSE] FTP connection established to {}", addr).dimmed()
                );
                crate::mprintln!(
                    "{}",
                    "[VERBOSE] Sending USER anonymous / PASS anonymous ...".dimmed()
                );
            }
            let result = ftp.login("anonymous", "anonymous").await;
            if result.is_ok() {
                crate::mprintln!("{}", "[+] Anonymous login successful (FTP)".green().bold());
                match ftp.list(None).await {
                    Ok(entries) => {
                        crate::mprintln!(
                            "{}",
                            "[+] LIST command successful - Read Access Confirmed".green()
                        );
                        if verbose {
                            crate::mprintln!(
                                "{}",
                                format!("[VERBOSE] LIST returned {} entries", entries.len())
                                    .dimmed()
                            );
                            for entry in entries.iter().take(20) {
                                crate::mprintln!("{}", format!("[VERBOSE]   {}", entry).dimmed());
                            }
                            if entries.len() > 20 {
                                crate::mprintln!(
                                    "{}",
                                    format!(
                                        "[VERBOSE]   ... and {} more entries",
                                        entries.len() - 20
                                    )
                                    .dimmed()
                                );
                            }
                        }
                    }
                    Err(e) => crate::mprintln!(
                        "{}",
                        format!("[-] Login worked but LIST failed: {}", e).yellow()
                    ),
                }
                // Persist credential to framework credential store
                let _ = crate::cred_store::store_credential(
                    domain,
                    21,
                    "ftp",
                    "anonymous",
                    "anonymous@",
                    crate::cred_store::CredType::Password,
                    "creds/generic/ftp_anonymous",
                )
                .await;
                let _ = ftp.quit().await;
                return Ok(());
            } else if let Err(e) = result {
                if e.to_string().contains("530") {
                    crate::mprintln!("{}", "[-] Anonymous login rejected (FTP)".yellow());
                    if verbose {
                        crate::mprintln!(
                            "{}",
                            format!("[VERBOSE] Server response: {}", e).dimmed()
                        );
                    }
                    return Ok(());
                } else if e.to_string().contains("550 SSL") {
                    crate::mprintln!(
                        "{}",
                        "[*] FTP server requires TLS — upgrading to FTPS...".cyan()
                    );
                    if verbose {
                        crate::mprintln!(
                            "{}",
                            format!("[VERBOSE] SSL required response: {}", e).dimmed()
                        );
                    }
                } else {
                    return Err(anyhow!("FTP error: {}", e));
                }
            }
        }
        Ok(Err(e)) => {
            crate::mprintln!("{}", format!("[!] FTP connection error: {}", e).red());
            if verbose {
                crate::mprintln!(
                    "{}",
                    format!("[VERBOSE] Connection error details: {:?}", e).dimmed()
                );
            }
        }
        Err(_) => {
            crate::mprintln!("{}", "[-] FTP connection timed out".yellow());
            if verbose {
                crate::mprintln!(
                    "{}",
                    format!(
                        "[VERBOSE] Timeout after {}s connecting to {}",
                        DEFAULT_TIMEOUT_SECS, addr
                    )
                    .dimmed()
                );
            }
        }
    }

    // 2. Fallback to FTPS
    crate::mprintln!("{}", "[*] Attempting FTPS connection...".cyan());
    if verbose {
        crate::mprintln!(
            "{}",
            format!("[VERBOSE] Initiating TLS connection to {}...", addr).dimmed()
        );
    }

    let mut ftps = AsyncNativeTlsFtpStream::connect(&addr)
        .await
        .map_err(|e| anyhow!("FTPS connect failed: {}", e))?;

    if verbose {
        crate::mprintln!(
            "{}",
            "[VERBOSE] FTPS TCP connection established, performing TLS upgrade...".dimmed()
        );
    }

    let connector = AsyncNativeTlsConnector::from(
        TlsConnector::new()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true),
    );

    ftps = ftps
        .into_secure(connector, domain)
        .await
        .map_err(|e| anyhow!("FTPS TLS upgrade failed: {}", e))?;

    if verbose {
        crate::mprintln!(
            "{}",
            "[VERBOSE] TLS handshake complete, sending anonymous credentials...".dimmed()
        );
    }

    match ftps.login("anonymous", "anonymous").await {
        Ok(_) => {
            crate::mprintln!("{}", "[+] Anonymous login successful (FTPS)".green().bold());
            match ftps.list(None).await {
                Ok(entries) => {
                    crate::mprintln!(
                        "{}",
                        "[+] LIST command successful - Read Access Confirmed".green()
                    );
                    if verbose {
                        crate::mprintln!(
                            "{}",
                            format!("[VERBOSE] LIST returned {} entries", entries.len()).dimmed()
                        );
                        for entry in entries.iter().take(20) {
                            crate::mprintln!("{}", format!("[VERBOSE]   {}", entry).dimmed());
                        }
                        if entries.len() > 20 {
                            crate::mprintln!(
                                "{}",
                                format!("[VERBOSE]   ... and {} more entries", entries.len() - 20)
                                    .dimmed()
                            );
                        }
                    }
                }
                Err(e) => crate::mprintln!(
                    "{}",
                    format!("[-] Login worked but LIST failed: {}", e).yellow()
                ),
            }
            // Persist credential to framework credential store
            let _ = crate::cred_store::store_credential(
                domain,
                21,
                "ftp",
                "anonymous",
                "anonymous@",
                crate::cred_store::CredType::Password,
                "creds/generic/ftp_anonymous",
            )
            .await;
            let _ = ftps.quit().await;
        }
        Err(e) if e.to_string().contains("530") => {
            crate::mprintln!("{}", "[-] Anonymous login rejected (FTPS)".yellow());
            if verbose {
                crate::mprintln!("{}", format!("[VERBOSE] FTPS rejection: {}", e).dimmed());
            }
        }
        Err(e) => return Err(anyhow!("FTPS login error: {}", e)),
    }

    Ok(())
}

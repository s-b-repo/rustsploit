//! Synology DSM — Unauthenticated API Disclosure Scanner
//! ======================================================
//!
//! Synology DiskStation Manager (DSM 6.x / 7.x) exposes a `/webapi/entry.cgi`
//! dispatch interface. Several APIs are reachable WITHOUT an authenticated
//! session and leak high-value configuration data:
//!
//!   * `SYNO.API.Info`            — full API catalog (typically 800+ entries)
//!   * `SYNO.API.Auth.Type`       — accepted authentication methods
//!   * `SYNO.API.Auth.UIConfig`   — login UI / 2FA configuration
//!   * `SYNO.API.Encryption`      — 4096-bit RSA login encryption pubkey
//!   * `SYNO.Core.Desktop.SessionData` — hostname, internal HTTP/HTTPS ports,
//!     `is_secure` flag, language, 2FA settings
//!   * `SYNO.Core.Desktop.Initdata`    — installed package list (often
//!     reveals pirated / unofficial SPK packages such as `dmtc.spk`)
//!
//! This module is detection-only — it sends GET requests against the public
//! webapi dispatcher and records which endpoints leaked usable data.

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::safe_io::DEFAULT_BODY_CAP;
use crate::utils::{cfg_prompt_default, cfg_prompt_port, normalize_target};

const DEFAULT_PORT: u16 = 5000;
const TIMEOUT_SECS: u64 = 12;

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Synology DSM — Unauthenticated API Disclosure".to_string(),
        description: "Probes Synology DiskStation Manager web APIs reachable without\n\
                       authentication: API catalog, SessionData, Initdata, Auth type,\n\
                       RSA encryption key. Detects pirated / unofficial packages such\n\
                       as dmtc.spk and reports hostname / internal port mapping."
            .to_string(),
        authors: vec!["RustSploit Team".to_string()],
        references: vec![
            "https://kb.synology.com/en-global/DG/DSM_developer_guide/preface".to_string(),
        ],
        disclosure_date: Some("2026-06-12".to_string()),
        rank: ModuleRank::Great,
        default_port: Some(DEFAULT_PORT),
    }
}

const PROBE_APIS: &[(&str, &str, &str)] = &[
    (
        "/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=all",
        "SYNO.API.Info",
        "api_catalog",
    ),
    (
        "/webapi/entry.cgi?api=SYNO.API.Auth.Type&version=1&method=get",
        "SYNO.API.Auth.Type",
        "auth_type",
    ),
    (
        "/webapi/entry.cgi?api=SYNO.API.Auth.UIConfig&version=1&method=get",
        "SYNO.API.Auth.UIConfig",
        "auth_ui_config",
    ),
    (
        "/webapi/entry.cgi?api=SYNO.API.Encryption&version=1&method=getinfo",
        "SYNO.API.Encryption",
        "rsa_pubkey",
    ),
    (
        "/webapi/entry.cgi?api=SYNO.Core.Desktop.SessionData&version=1&method=get",
        "SYNO.Core.Desktop.SessionData",
        "session_data",
    ),
    (
        "/webapi/entry.cgi?api=SYNO.Core.Desktop.Initdata&version=1&method=get",
        "SYNO.Core.Desktop.Initdata",
        "initdata",
    ),
];

const PIRATED_PACKAGES: &[&str] = &["dmtc.spk", "yunmeng", "clouddream"];
const UNOFFICIAL_PACKAGES: &[&str] = &["alist3", "aliyundrive-webdav", "aria2", "homebridge"];

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("synology_dsm_disclosure requires a single-host target")?;
    let normalized = normalize_target(target)?;
    let port = cfg_prompt_port("port", "DSM HTTP port (often 5000, 5001 HTTPS)", DEFAULT_PORT).await?;
    let scheme = cfg_prompt_default("scheme", "Scheme (http/https)", "http").await?;
    let base = format!("{}://{}:{}", scheme, normalized, port);

    let client = crate::utils::build_http_client(Duration::from_secs(TIMEOUT_SECS))
        .context("HTTP client")?;

    crate::mprintln!(
        "{}",
        "╔═══════════════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║  Synology DSM — Unauthenticated API Disclosure                    ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚═══════════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!("{} {}", "[*] Target:".yellow(), base);

    let mut outcome = ModuleOutcome::ok();
    let mut leaked_apis: Vec<String> = Vec::new();
    let mut detected_packages: Vec<String> = Vec::new();
    let mut pirated_hits: Vec<String> = Vec::new();
    let mut hostname: Option<String> = None;
    let mut http_port_internal: Option<u32> = None;
    let mut https_port_internal: Option<u32> = None;
    let mut is_secure: Option<bool> = None;
    let mut api_count: Option<usize> = None;
    let mut dsm_fingerprinted = false;

    for (path, api_name, label) in PROBE_APIS {
        let url = format!("{}{}", base, path);
        if let Ok(r) = client.get(&url).send().await {
            let status = r.status();
            if !status.is_success() {
                continue;
            }
            let body = match crate::utils::network::read_http_body_text_capped(r, DEFAULT_BODY_CAP).await {
                Ok(b) => b,
                Err(e) => {
                    crate::mprintln!("{} {} body read failed: {}", "[-]".yellow(), api_name, e);
                    continue;
                }
            };
            // Synology returns JSON-like text — looking for {"success":true,"data":...}
            if !body.contains("\"success\":true") && !body.contains("\"data\"") {
                continue;
            }
            dsm_fingerprinted = true;
            crate::mprintln!("{} {} reachable ({} bytes)", "[+]".green(), api_name, body.len());
            leaked_apis.push((*api_name).to_string());

            match *label {
                "api_catalog" => {
                    // Count distinct "SYNO." references as a coarse API count
                    let count = body.matches("\"SYNO.").count();
                    if count > 0 {
                        api_count = Some(count);
                    }
                }
                "session_data" | "initdata" => {
                    if let Some(h) = extract_string_value(&body, "hostname") {
                        hostname.get_or_insert(h);
                    }
                    if let Some(p) = extract_num_value(&body, "dsm_http_port") {
                        http_port_internal.get_or_insert(p);
                    }
                    if let Some(p) = extract_num_value(&body, "dsm_https_port") {
                        https_port_internal.get_or_insert(p);
                    }
                    if let Some(b) = extract_bool_value(&body, "is_secure") {
                        is_secure.get_or_insert(b);
                    }
                    // Scan for installed packages — extract names referenced as keys
                    let lower = body.to_lowercase();
                    for pkg in PIRATED_PACKAGES {
                        if lower.contains(&pkg.to_lowercase()) {
                            pirated_hits.push((*pkg).to_string());
                        }
                    }
                    for pkg in UNOFFICIAL_PACKAGES {
                        if lower.contains(&pkg.to_lowercase()) {
                            detected_packages.push((*pkg).to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if !dsm_fingerprinted {
        crate::mprintln!(
            "{} no DSM webapi responses — target may not be Synology or is firewalled",
            "[-]".yellow()
        );
        return Ok(outcome);
    }

    if let Some(h) = &hostname {
        crate::mprintln!("{} hostname: {}", "[+]".green(), h);
    }
    if let Some(p) = http_port_internal {
        crate::mprintln!("{} internal HTTP port: {}", "[+]".green(), p);
    }
    if let Some(p) = https_port_internal {
        crate::mprintln!("{} internal HTTPS port: {}", "[+]".green(), p);
    }
    if let Some(s) = is_secure {
        crate::mprintln!("{} is_secure flag: {}", "[+]".green(), s);
    }
    if let Some(c) = api_count {
        crate::mprintln!("{} approximate API catalog size: {}", "[+]".green(), c);
    }
    if !detected_packages.is_empty() {
        crate::mprintln!(
            "{} unofficial packages: {}",
            "[+]".green(),
            detected_packages.join(", ")
        );
    }
    if !pirated_hits.is_empty() {
        crate::mprintln!(
            "{} PIRATED / cracked packages detected: {}",
            "[!]".red().bold(),
            pirated_hits.join(", ")
        );
    }

    crate::workspace::track_host(&normalized, hostname.as_deref(), Some("Synology DSM")).await;
    outcome.findings.push(Finding {
        target: normalized.clone(),
        kind: FindingKind::Vulnerable,
        message: format!(
            "Synology DSM at {} exposes {} unauthenticated API endpoint(s)",
            base,
            leaked_apis.len()
        ),
        data: Some(serde_json::json!({
            "host": normalized,
            "port": port,
            "leaked_apis": leaked_apis,
            "hostname": hostname,
            "http_port_internal": http_port_internal,
            "https_port_internal": https_port_internal,
            "is_secure": is_secure,
            "api_catalog_size": api_count,
            "unofficial_packages": detected_packages,
            "pirated_packages": pirated_hits,
        })),
    });

    if !pirated_hits.is_empty() {
        outcome.findings.push(Finding {
            target: normalized.clone(),
            kind: FindingKind::Vulnerable,
            message: format!(
                "Synology DSM at {} runs pirated package(s): {}",
                normalized,
                pirated_hits.join(", ")
            ),
            data: Some(serde_json::json!({
                "host": normalized,
                "pirated_packages": pirated_hits,
            })),
        });
    }

    Ok(outcome)
}

fn extract_string_value(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":", key);
    let idx = body.find(&needle)?;
    let tail = &body[idx + needle.len()..].trim_start();
    let tail = tail.strip_prefix('"')?;
    let end = tail.find('"')?;
    Some(tail[..end].to_string())
}

fn extract_num_value(body: &str, key: &str) -> Option<u32> {
    let needle = format!("\"{}\":", key);
    let idx = body.find(&needle)?;
    let tail = body[idx + needle.len()..].trim_start();
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

fn extract_bool_value(body: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{}\":", key);
    let idx = body.find(&needle)?;
    let tail = body[idx + needle.len()..].trim_start();
    if tail.starts_with("true") {
        Some(true)
    } else if tail.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_string_value() {
        let body = r#"{"hostname":"ChenHome","other":"x"}"#;
        assert_eq!(extract_string_value(body, "hostname"), Some("ChenHome".to_string()));
    }

    #[test]
    fn parses_num_value() {
        let body = r#"{"dsm_http_port":5000,"dsm_https_port":5001}"#;
        assert_eq!(extract_num_value(body, "dsm_http_port"), Some(5000));
    }

    #[test]
    fn parses_bool_value() {
        assert_eq!(extract_bool_value(r#"{"is_secure":false}"#, "is_secure"), Some(false));
        assert_eq!(extract_bool_value(r#"{"is_secure":true}"#, "is_secure"), Some(true));
    }
}

crate::register_native_module!(
    crate::module::Category::Scanners,
    "synology_dsm_disclosure",
    native
);

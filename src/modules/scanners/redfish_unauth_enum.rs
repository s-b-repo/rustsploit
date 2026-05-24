//! Redfish unauthenticated information-disclosure enumerator.
//!
//! BMCs (Baseboard Management Controllers) frequently misconfigure ACLs on
//! their Redfish API: while `/redfish/v1` is intentionally open for
//! discovery, deep system nodes (`Systems/1`, `Managers/1`, `Chassis/1`,
//! `AccountService`, `SecurityService`) are supposed to require auth — but
//! many vendors leave them readable to anonymous (or "guest") sessions
//! gated by nothing more than a cookie like `RSAIndex=28`.
//!
//! This module walks the standard Redfish tree against a target and reports
//! which sensitive endpoints answer 200 without credentials. Each hit
//! discloses fingerprintable data: serial number, model, firmware versions,
//! account-lockout policy, MAC addresses, RSA modulus, etc. — exactly the
//! "glass box" that lets an attacker pivot to a precision-targeted exploit
//! without burning a single login attempt.
//!
//! Also probes the auxiliary `/cc/bmc_cc.xml` capabilities file, which on
//! many vendors leaks the full set of error strings (and therefore the
//! account-lockout / pairing / firmware-upgrade subsystem layout) without
//! authentication.
//!
//! FOR AUTHORIZED TESTING ONLY.

use anyhow::{ Context, Result };
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ CheckResult, ModuleInfo, ModuleRank };
use crate::utils::{
    build_http_client,
    cfg_prompt_default,
    cfg_prompt_int_range,
    cfg_prompt_yes_no,
};

const HTTP_TIMEOUT_SECS: u64 = 8;

/// Redfish endpoints that should require authentication on a properly
/// configured BMC. Each entry: (path, description, expected sensitive fields).
const SENSITIVE_ENDPOINTS: &[(&str, &str, &[&str])] = &[
    ("/redfish/v1/Systems/1", "system identity", &["SerialNumber", "UUID", "Manufacturer", "Model", "HostName"]),
    ("/redfish/v1/Managers/1", "BMC manager", &["FirmwareVersion", "Model", "DateTime", "GraphicalConsole"]),
    ("/redfish/v1/Managers/1/EthernetInterfaces", "BMC NICs", &["MACAddress", "IPv4Addresses"]),
    ("/redfish/v1/Chassis/1", "chassis", &["SerialNumber", "PartNumber", "AssetTag"]),
    ("/redfish/v1/Systems/1/Bios", "BIOS settings", &["AttributeRegistry", "Attributes"]),
    ("/redfish/v1/AccountService", "account policy", &["AccountLockoutThreshold", "AccountLockoutDuration", "MinPasswordLength"]),
    ("/redfish/v1/AccountService/Accounts", "user accounts", &["UserName", "RoleId"]),
    ("/redfish/v1/SessionService/Sessions", "active sessions", &["UserName", "ClientOriginIPAddress"]),
    ("/redfish/v1/Managers/1/SecurityService", "security service", &["RSAModulus", "PublicKey", "CertificateCollection"]),
    ("/redfish/v1/UpdateService/FirmwareInventory", "firmware inventory", &["Version", "SoftwareId"]),
    ("/redfish/v1/Systems/1/LogServices", "system logs", &["Entries"]),
    ("/redfish/v1/Managers/1/LogServices/SEL/Entries", "BMC SEL", &["EntryType", "Message"]),
];

/// Auxiliary endpoints — non-Redfish but commonly disclosed without auth on
/// the same management plane.
const AUX_ENDPOINTS: &[(&str, &str)] = &[
    ("/cc/bmc_cc.xml", "BMC capability/error catalog"),
    ("/api/settings/lan", "LAN settings (vendor REST)"),
    ("/api/system/system_info", "system info (vendor REST)"),
];

fn display_banner() {
    if crate::utils::is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   Redfish Unauthenticated Enumeration                        ║".cyan());
    crate::mprintln!("{}", "║   Walks Systems/Managers/Chassis/AccountService anonymously  ║".cyan());
    crate::mprintln!("{}", "║   Reports any BMC that leaks identity / firmware / policy    ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Redfish Unauthenticated Enumeration".to_string(),
        description: "Walks the standard Redfish tree (Systems, Managers, Chassis, AccountService, \
                      SecurityService, UpdateService) against a BMC target and reports any endpoint \
                      that returns sensitive identity/firmware/policy data without authentication. \
                      Also probes vendor-aux endpoints like /cc/bmc_cc.xml that commonly leak \
                      capability catalogs and error-string enums.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://www.dmtf.org/standards/redfish".to_string(),
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/".to_string(),
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Great,
        default_port: None,
    }
}

/// Non-destructive check: does `/redfish/v1` respond, and does at least one
/// sensitive endpoint return 200 unauthenticated?
pub async fn check(ctx: &ModuleCtx) -> CheckResult {
    let target = match ctx.target.as_single() {
        Some(t) => t,
        None => return CheckResult::Error("redfish_unauth_enum requires a single-host target".to_string()),
    };
    let host = sanitize_host(target);
    let client = match build_http_client(Duration::from_secs(HTTP_TIMEOUT_SECS)) {
        Ok(c) => c,
        Err(e) => return CheckResult::Error(format!("HTTP client build failed: {}", e)),
    };

    // Try HTTPS first (BMCs usually default to it), then fall back to HTTP.
    for scheme in &["https", "http"] {
        let root_url = format!("{}://{}/redfish/v1", scheme, host);
        if let Ok(resp) = client.get(&root_url).send().await {
            if !resp.status().is_success() {
                continue;
            }
            // Probe one cheap sensitive endpoint
            let probe = format!("{}://{}/redfish/v1/Systems/1", scheme, host);
            if let Ok(probe_resp) = client.get(&probe).send().await
                && probe_resp.status().is_success()
                    && let Ok(body) = probe_resp.text().await
                        && (body.contains("SerialNumber") || body.contains("Manufacturer")) {
                            return CheckResult::Vulnerable(format!(
                                "Redfish Systems/1 returns identity data without auth on {}",
                                scheme
                            ));
                        }
            return CheckResult::Unknown(format!("Redfish reachable on {} but Systems/1 was not anonymous-readable", scheme));
        }
    }
    CheckResult::NotVulnerable("Redfish endpoint not reachable".into())
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("redfish_unauth_enum requires a single-host target")?;

    display_banner();
    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());

    let mut outcome = ModuleOutcome::ok();

    let scheme = cfg_prompt_default("scheme", "Scheme (http/https/auto)", "auto").await?;
    let timeout_secs = cfg_prompt_int_range("timeout", "HTTP timeout (seconds)", HTTP_TIMEOUT_SECS as i64, 1, 60).await? as u64;
    let probe_aux = cfg_prompt_yes_no("probe_aux", "Probe auxiliary endpoints (bmc_cc.xml, /api/...)", true).await?;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose (show 401/403 too)", false).await?;

    let host = sanitize_host(target);
    let client = build_http_client(Duration::from_secs(timeout_secs))
        .context("Failed to build HTTP client")?;

    // Resolve scheme — try requested first, fall back to the other if "auto"
    let schemes: &[&str] = match scheme.to_lowercase().as_str() {
        "http" => &["http"],
        "https" => &["https"],
        _ => &["https", "http"],
    };

    let mut working_scheme: Option<&str> = None;
    for s in schemes {
        let root = format!("{}://{}/redfish/v1", s, host);
        ctx.rate_limit(&host).await;
        match client.get(&root).send().await {
            Ok(r) if r.status().is_success() => {
                working_scheme = Some(s);
                crate::mprintln!("{}", format!("[+] Redfish reachable: {} ({})", root, r.status()).green());
                break;
            }
            Ok(r) => {
                if verbose {
                    crate::mprintln!("{}", format!("[-] {} -> {}", root, r.status()).dimmed());
                }
            }
            Err(e) => {
                if verbose {
                    crate::mprintln!("{}", format!("[-] {}: {}", root, e).dimmed());
                }
            }
        }
    }

    let Some(scheme) = working_scheme else {
        crate::mprintln!("{}", "[-] No Redfish endpoint reachable on either scheme.".red());
        return Ok(outcome);
    };

    let mut hits = 0usize;

    crate::mprintln!("\n{}", "── Redfish endpoints ──".bold());
    for (path, label, fields) in SENSITIVE_ENDPOINTS {
        let url = format!("{}://{}{}", scheme, host, path);
        ctx.rate_limit(&host).await;
        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    let body = match resp.text().await {
                        Ok(b) => b,
                        Err(e) => {
                            crate::mprintln!("{} body decode failed: {}", "[-]".red(), e);
                            String::new()
                        }
                    };
                    let leaked: Vec<&&str> = fields.iter().filter(|f| body.contains(**f)).collect();
                    if leaked.is_empty() {
                        crate::mprintln!("{}", format!("[~] {} ({}) -> 200 but no sensitive fields matched", path, label).yellow());
                    } else {
                        hits += 1;
                        let leaked_names: Vec<String> = leaked.iter().map(|s| (**s).to_string()).collect();
                        crate::mprintln!("{}", format!(
                            "[+] {} ({}) -> 200 — leaks: {}",
                            path, label,
                            leaked_names.join(", ")
                        ).red().bold());
                        // Surface up to 3 sample leaked field values
                        for f in leaked.iter().take(3) {
                            if let Some(snippet) = extract_field_snippet(&body, f) {
                                crate::mprintln!("    {} = {}", f, snippet.dimmed());
                            }
                        }
                        outcome.findings.push(Finding {
                            target: host.clone(),
                            kind: FindingKind::Vulnerable,
                            message: format!("Redfish unauthenticated leak at {} ({}): {}", url, label, leaked_names.join(", ")),
                            data: Some(serde_json::json!({
                                "host": host,
                                "url": url,
                                "label": label,
                                "leaked_fields": leaked_names,
                            })),
                        });
                    }
                } else if verbose {
                    crate::mprintln!("{}", format!("[-] {} -> {}", path, status).dimmed());
                }
            }
            Err(e) => {
                if verbose {
                    crate::mprintln!("{}", format!("[-] {}: {}", path, e).dimmed());
                }
            }
        }
    }

    if probe_aux {
        crate::mprintln!("\n{}", "── Auxiliary endpoints ──".bold());
        for (path, label) in AUX_ENDPOINTS {
            let url = format!("{}://{}{}", scheme, host, path);
            ctx.rate_limit(&host).await;
            if let Ok(resp) = client.get(&url).send().await {
                let status = resp.status();
                if status.is_success() {
                    let len = resp
                        .content_length()
                        .map(|l| l as usize)
                        .unwrap_or_else(|| resp.headers().get("content-length")
                            .and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok()).unwrap_or(0));
                    hits += 1;
                    crate::mprintln!("{}", format!(
                        "[+] {} ({}) -> 200 ({} bytes leaked unauth)",
                        path, label, len
                    ).red().bold());
                    outcome.findings.push(Finding {
                        target: host.clone(),
                        kind: FindingKind::Vulnerable,
                        message: format!("Auxiliary unauth endpoint {} ({}) returned {} bytes", url, label, len),
                        data: Some(serde_json::json!({
                            "host": host,
                            "url": url,
                            "label": label,
                            "size": len,
                        })),
                    });
                } else if verbose {
                    crate::mprintln!("{}", format!("[-] {} -> {}", path, status).dimmed());
                }
            }
        }
    }

    crate::mprintln!();
    if hits == 0 {
        crate::mprintln!("{}", "[*] Redfish reachable but no sensitive endpoint disclosed without auth.".cyan());
    } else {
        crate::mprintln!("{}", format!("[!] {} unauthenticated info-disclosure endpoint(s) found.", hits).red().bold());
    }

    Ok(outcome)
}

/// Extract a short snippet of a JSON field's value for display.
/// Defensive — handles both quoted strings and bare values.
fn extract_field_snippet(body: &str, field: &str) -> Option<String> {
    let needle = format!("\"{}\"", field);
    let pos = body.find(&needle)?;
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
    let snippet: String = if let Some(stripped) = rest.strip_prefix('"') {
        stripped.chars().take_while(|c| *c != '"').take(80).collect()
    } else {
        rest.chars().take_while(|c| *c != ',' && *c != '}' && *c != '\n').take(80).collect()
    };
    let trimmed = snippet.trim();
    if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
}

/// Strip scheme + trailing slash so the host can be re-formatted with the
/// chosen scheme. Accepts "1.2.3.4", "1.2.3.4:443", "https://1.2.3.4/...",
/// etc.
fn sanitize_host(target: &str) -> String {
    let mut t = target.trim().to_string();
    for prefix in &["https://", "http://"] {
        if let Some(stripped) = t.strip_prefix(prefix) {
            t = stripped.to_string();
            break;
        }
    }
    if let Some(slash) = t.find('/') {
        t.truncate(slash);
    }
    t
}

crate::register_native_module!(crate::module::Category::Scanners, "redfish_unauth_enum", native, has_check);

//! H3C CloudOS management API enumerator.
//!
//! The H3C CloudOS cloud management platform exposes a rich set of REST APIs
//! for identity/auth (Kinton/Keystone), compute, image, and resource
//! management. Misconfigurations commonly leave these endpoints accessible
//! without authentication, disclosing tenant lists, server inventories,
//! quota configurations, LDAP settings, and user entities.
//!
//! This module probes the known CloudOS API families as well as common API
//! discovery/management endpoints (Swagger, API explorer, status, etc.) and
//! reports any that respond with data without requiring credentials. It also
//! attempts a known default `Authorization: Basic` header (derived from a
//! well-known default access_id) to check whether default credentials grant
//! additional access.
//!
//! FOR AUTHORIZED TESTING ONLY.

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{
    build_http_client,
    cfg_prompt_default,
    cfg_prompt_int_range,
    cfg_prompt_yes_no,
};

const HTTP_TIMEOUT_SECS: u64 = 8;

/// Known default access_id encoded as Basic auth (base64).
const DEFAULT_BASIC_AUTH: &str = "Basic eGJkNjFuYnJ4b3hmbGpqbHVhYjN0c3dteGd5ZWRteHl2emQwazIyeHlkY294Zmxq";

/// H3C CloudOS platform API endpoints that should require authentication.
/// Each entry: (path template, description).
const CLOUDOS_ENDPOINTS: &[(&str, &str)] = &[
    // Identity / Auth
    ("/os/kinton/v1/v3/users-entities", "CloudOS user entities"),
    ("/os/kinton/v1/keystone/types/UserProjectGroup/assigments", "User-project-group assignments"),

    // Compute
    ("/os/compute/v1/v2/{tenant_id}/servers", "Compute servers list"),
    ("/os/compute/v1/v2/{tenant_id}/flavors/detail", "Compute flavors"),
    ("/os/compute/v1/cloudos/azones/{azone_id}", "Availability zones"),

    // Image
    ("/os/image/v1/v2/images", "OS images list"),
    ("/os/kinton/v1/cloudos/imagetype/opsys/{os_type}", "Image types by OS"),

    // Resource management
    ("/os/kinton/v1/cloudos/resource/norms/{serviceUuid}", "Resource norms"),
    ("/os/kinton/v1/cloudos/resource/normConfi", "Resource norm config"),
    ("/os/kinton/v1/quotaMange/saveQuotaManage", "Quota management"),
];

/// Common API discovery / management endpoints that may be present alongside
/// the CloudOS platform.
const DISCOVERY_ENDPOINTS: &[(&str, &str)] = &[
    ("/api/v1/status", "API status"),
    ("/api/v1/node", "Node info"),
    ("/api/system/v1", "System API"),
    ("/api/explorer", "API explorer"),
    ("/api/swaggerui", "Swagger UI"),
    ("/api/config", "API config"),
    ("/api/v1/users", "Users API"),
    ("/api/v1/terminal/sessions", "Terminal sessions"),
    ("/api/v1/files", "Files API"),
    ("/api/ldap/config", "LDAP config"),
    ("/api-third-party/download/public", "Third-party public downloads"),
    ("/api/onboarding", "Onboarding API"),
];

fn display_banner() {
    if crate::utils::is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   H3C CloudOS API Enumerator                                ║".cyan());
    crate::mprintln!("{}", "║   Probes identity, compute, image & resource APIs            ║".cyan());
    crate::mprintln!("{}", "║   Reports unauthenticated disclosure & default credentials   ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "H3C CloudOS API Enumeration".to_string(),
        description: "Probes H3C CloudOS management platform APIs (Kinton/Keystone identity, \
                      compute, image, resource management) and common API discovery endpoints \
                      for unauthenticated information disclosure, misconfigurations, and default \
                      credentials. Reports any endpoint that returns sensitive data without \
                      requiring authentication. FOR AUTHORIZED TESTING ONLY.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://www.h3c.com/en/Products_And_Solutions/Cloud_Computing/".to_string(),
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/".to_string(),
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/".to_string(),
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Great,
        default_port: None,
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("h3c_cloudos_api_enum requires a single-host target")?;

    display_banner();
    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());

    let mut outcome = ModuleOutcome::ok();

    // ── Configuration prompts ──────────────────────────────────────────
    let scheme = cfg_prompt_default("scheme", "Scheme (http/https/auto)", "auto").await?;
    let port = cfg_prompt_int_range("port", "Target port", 443, 1, 65535).await? as u16;
    let timeout_secs = cfg_prompt_int_range("timeout", "HTTP timeout (seconds)", HTTP_TIMEOUT_SECS as i64, 1, 60).await? as u64;
    let tenant_id = cfg_prompt_default("tenant_id", "Tenant ID for compute endpoints", "default").await?;
    let os_type = cfg_prompt_default("os_type", "OS type for image endpoints", "Linux").await?;
    let azone_id = cfg_prompt_default("azone_id", "Availability zone ID", "1").await?;
    let service_uuid = cfg_prompt_default("service_uuid", "Service UUID (blank for none)", "").await?;
    let probe_discovery = cfg_prompt_yes_no("probe_discovery", "Probe API discovery/management endpoints", true).await?;
    let try_default_creds = cfg_prompt_yes_no("try_default_creds", "Try known default Basic auth header", true).await?;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose (show 401/403 too)", false).await?;

    let host = sanitize_host(target);
    let host_with_port = if port == 443 || port == 80 {
        host.clone()
    } else {
        format!("{}:{}", host, port)
    };

    let client = build_http_client(Duration::from_secs(timeout_secs))
        .context("Failed to build HTTP client")?;

    // ── Resolve working scheme ─────────────────────────────────────────
    let schemes: &[&str] = match scheme.to_lowercase().as_str() {
        "http" => &["http"],
        "https" => &["https"],
        _ => &["https", "http"],
    };

    let mut working_scheme: Option<&str> = None;
    for s in schemes {
        let probe_url = format!("{}://{}/", s, host_with_port);
        ctx.rate_limit(&host).await;
        match client.get(&probe_url).send().await {
            Ok(r) => {
                working_scheme = Some(s);
                crate::mprintln!("{}", format!("[+] Host reachable: {} (HTTP {})", probe_url, r.status()).green());
                break;
            }
            Err(e) => {
                if verbose {
                    crate::mprintln!("{}", format!("[-] {}: {}", probe_url, e).dimmed());
                }
            }
        }
    }

    let Some(scheme) = working_scheme else {
        crate::mprintln!("{}", "[-] Target not reachable on either scheme.".red());
        return Ok(outcome);
    };

    let base = format!("{}://{}", scheme, host_with_port);
    let mut hits = 0usize;
    // Track endpoints that already returned 2xx WITHOUT any auth, so the
    // default-credentials phase can tell whether the credential materially
    // changed access (true default-cred finding) vs. re-counting an endpoint
    // that needs no auth at all (false positive).
    let mut unauth_success: std::collections::HashSet<String> = std::collections::HashSet::new();

    // ── CloudOS endpoints ──────────────────────────────────────────────
    crate::mprintln!("\n{}", "── CloudOS API endpoints ──".bold());
    for (path_template, label) in CLOUDOS_ENDPOINTS {
        let path = path_template
            .replace("{tenant_id}", &tenant_id)
            .replace("{azone_id}", &azone_id)
            .replace("{serviceUuid}", &service_uuid)
            .replace("{os_type}", &os_type);
        let url = format!("{}{}", base, path);

        ctx.rate_limit(&host).await;
        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    let body = crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await.unwrap_or_default();
                    hits += 1;
                    unauth_success.insert(url.clone());
                    crate::mprintln!("{}", format!(
                        "[+] {} ({}) -> {} — data disclosed without auth ({} bytes)",
                        path, label, status, body.len()
                    ).red().bold());
                    // Try to extract key JSON fields for display
                    display_json_summary(&body);
                    outcome.findings.push(Finding {
                        target: host.clone(),
                        kind: FindingKind::Vulnerable,
                        message: format!(
                            "CloudOS unauthenticated disclosure at {} ({}): {} bytes returned",
                            url, label, body.len()
                        ),
                        data: Some(serde_json::json!({
                            "host": host,
                            "url": url,
                            "label": label,
                            "status": status.as_u16(),
                            "size": body.len(),
                            "auth": "none",
                        })),
                    });
                } else if status.as_u16() == 401 || status.as_u16() == 403 {
                    if verbose {
                        crate::mprintln!("{}", format!("[-] {} ({}) -> {} (auth required, properly gated)", path, label, status).dimmed());
                    }
                } else if verbose {
                    crate::mprintln!("{}", format!("[-] {} ({}) -> {}", path, label, status).dimmed());
                }
            }
            Err(e) => {
                if verbose {
                    crate::mprintln!("{}", format!("[-] {} ({}): {}", path, label, e).dimmed());
                }
            }
        }
    }

    // ── Discovery / management endpoints ───────────────────────────────
    if probe_discovery {
        crate::mprintln!("\n{}", "── API discovery / management endpoints ──".bold());
        for (path, label) in DISCOVERY_ENDPOINTS {
            let url = format!("{}{}", base, path);
            ctx.rate_limit(&host).await;
            match client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        let body = crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await.unwrap_or_default();
                        hits += 1;
                        unauth_success.insert(url.clone());
                        crate::mprintln!("{}", format!(
                            "[+] {} ({}) -> {} — accessible without auth ({} bytes)",
                            path, label, status, body.len()
                        ).red().bold());
                        display_json_summary(&body);
                        outcome.findings.push(Finding {
                            target: host.clone(),
                            kind: FindingKind::Vulnerable,
                            message: format!(
                                "Discovery endpoint unauthenticated at {} ({}): {} bytes",
                                url, label, body.len()
                            ),
                            data: Some(serde_json::json!({
                                "host": host,
                                "url": url,
                                "label": label,
                                "status": status.as_u16(),
                                "size": body.len(),
                                "auth": "none",
                            })),
                        });
                    } else if status.as_u16() == 401 || status.as_u16() == 403 {
                        if verbose {
                            crate::mprintln!("{}", format!("[-] {} ({}) -> {} (properly gated)", path, label, status).dimmed());
                        }
                    } else if verbose {
                        crate::mprintln!("{}", format!("[-] {} ({}) -> {}", path, label, status).dimmed());
                    }
                }
                Err(e) => {
                    if verbose {
                        crate::mprintln!("{}", format!("[-] {} ({}): {}", path, label, e).dimmed());
                    }
                }
            }
        }
    }

    // ── Default credentials probe ──────────────────────────────────────
    if try_default_creds {
        crate::mprintln!("\n{}", "── Default credentials probe ──".bold());
        // Re-probe CloudOS endpoints with the known default Basic auth header
        // to see if default credentials grant additional access beyond what
        // was already found unauthenticated.
        let mut default_cred_hits = 0usize;
        for (path_template, label) in CLOUDOS_ENDPOINTS {
            let path = path_template
                .replace("{tenant_id}", &tenant_id)
                .replace("{azone_id}", &azone_id)
                .replace("{serviceUuid}", &service_uuid)
                .replace("{os_type}", &os_type);
            let url = format!("{}{}", base, path);

            // Skip endpoints already accessible WITHOUT auth: a 2xx here only
            // proves the endpoint needs no auth (already reported), not that
            // the default credential granted access.
            if unauth_success.contains(&url) {
                if verbose {
                    crate::mprintln!("{}", format!("[-] {} ({}) already unauthenticated — skipping default-cred check", path, label).dimmed());
                }
                continue;
            }
            ctx.rate_limit(&host).await;
            let req = client
                .get(&url)
                .header("Authorization", DEFAULT_BASIC_AUTH);
            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        let body = crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await.unwrap_or_default();
                        default_cred_hits += 1;
                        crate::mprintln!("{}", format!(
                            "[+] {} ({}) -> {} with default creds ({} bytes)",
                            path, label, status, body.len()
                        ).red().bold());
                        display_json_summary(&body);
                        outcome.findings.push(Finding {
                            target: host.clone(),
                            kind: FindingKind::Vulnerable,
                            message: format!(
                                "CloudOS default credentials accepted at {} ({}): {} bytes",
                                url, label, body.len()
                            ),
                            data: Some(serde_json::json!({
                                "host": host,
                                "url": url,
                                "label": label,
                                "status": status.as_u16(),
                                "size": body.len(),
                                "auth": "default_basic",
                            })),
                        });
                    } else if verbose {
                        crate::mprintln!("{}", format!("[-] {} ({}) -> {} with default creds", path, label, status).dimmed());
                    }
                }
                Err(e) => {
                    if verbose {
                        crate::mprintln!("{}", format!("[-] {} ({}): {}", path, label, e).dimmed());
                    }
                }
            }
        }

        // Also probe discovery endpoints with default creds
        for (path, label) in DISCOVERY_ENDPOINTS {
            let url = format!("{}{}", base, path);
            // Skip endpoints already accessible WITHOUT auth (see above).
            if unauth_success.contains(&url) {
                if verbose {
                    crate::mprintln!("{}", format!("[-] {} ({}) already unauthenticated — skipping default-cred check", path, label).dimmed());
                }
                continue;
            }
            ctx.rate_limit(&host).await;
            let req = client
                .get(&url)
                .header("Authorization", DEFAULT_BASIC_AUTH);
            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        let body = crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await.unwrap_or_default();
                        default_cred_hits += 1;
                        crate::mprintln!("{}", format!(
                            "[+] {} ({}) -> {} with default creds ({} bytes)",
                            path, label, status, body.len()
                        ).red().bold());
                        display_json_summary(&body);
                        outcome.findings.push(Finding {
                            target: host.clone(),
                            kind: FindingKind::Vulnerable,
                            message: format!(
                                "Default credentials accepted at {} ({}): {} bytes",
                                url, label, body.len()
                            ),
                            data: Some(serde_json::json!({
                                "host": host,
                                "url": url,
                                "label": label,
                                "status": status.as_u16(),
                                "size": body.len(),
                                "auth": "default_basic",
                            })),
                        });
                    } else if verbose {
                        crate::mprintln!("{}", format!("[-] {} ({}) -> {} with default creds", path, label, status).dimmed());
                    }
                }
                Err(e) => {
                    if verbose {
                        crate::mprintln!("{}", format!("[-] {} ({}): {}", path, label, e).dimmed());
                    }
                }
            }
        }

        if default_cred_hits == 0 {
            crate::mprintln!("{}", "[*] Default credentials did not grant additional access.".cyan());
        } else {
            hits += default_cred_hits;
            crate::mprintln!("{}", format!(
                "[!] {} endpoint(s) accessible via default credentials.",
                default_cred_hits
            ).red().bold());
        }
    }

    // ── Summary ────────────────────────────────────────────────────────
    crate::mprintln!();
    if hits == 0 {
        crate::mprintln!("{}", "[*] No unauthenticated or default-credential disclosures found.".cyan());
    } else {
        crate::mprintln!("{}", format!(
            "[!] {} total finding(s) across CloudOS and discovery endpoints.",
            hits
        ).red().bold());
    }

    Ok(outcome)
}

/// Attempt to parse a response body as JSON and display a brief summary of
/// top-level keys and array lengths, so the operator gets immediate feedback
/// about what was disclosed.
fn display_json_summary(body: &str) {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(body) {
        match &val {
            serde_json::Value::Object(map) => {
                let keys: Vec<&String> = map.keys().take(8).collect();
                if !keys.is_empty() {
                    let key_names: Vec<String> = keys.iter().map(|k| {
                        match map.get(*k) {
                            Some(serde_json::Value::Array(arr)) => format!("{}[{}]", k, arr.len()),
                            Some(serde_json::Value::String(s)) => {
                                let preview: String = s.chars().take(40).collect();
                                format!("{}=\"{}\"", k, preview)
                            }
                            Some(serde_json::Value::Number(n)) => format!("{}={}", k, n),
                            Some(serde_json::Value::Bool(b)) => format!("{}={}", k, b),
                            _ => k.to_string(),
                        }
                    }).collect();
                    crate::mprintln!("    {}", format!("keys: {}", key_names.join(", ")).dimmed());
                }
            }
            serde_json::Value::Array(arr) => {
                crate::mprintln!("    {}", format!("array with {} element(s)", arr.len()).dimmed());
            }
            _ => {}
        }
    }
}

/// Strip scheme and trailing path so the host can be re-formatted with the
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
    // Strip port if present — we handle it separately via the port prompt
    if let Some(colon) = t.rfind(':') {
        let after_colon = &t[colon + 1..];
        if after_colon.chars().all(|c| c.is_ascii_digit()) {
            t.truncate(colon);
        }
    }
    t
}

crate::register_native_module!(crate::module::Category::Scanners, "h3c_cloudos_api_enum", native);

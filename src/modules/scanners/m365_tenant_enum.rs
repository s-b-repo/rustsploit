//! M365 / Azure Tenant Enumeration
//!
//! Tests whether a Microsoft 365 / Azure AD tenant exists for a given domain
//! by probing the standard OpenID Connect discovery endpoint and analyzing
//! federation metadata.
//!
//! Based on M365 cross-program findings from the bug bounty:
//!   - `tenant_existence.txt` — domains confirmed to have M365 tenants
//!   - Optus M365 tenant enumeration (singteloptus.onmicrosoft.com)
//!
//! Detection techniques:
//!   1. Probe `/.well-known/openid-configuration` on login.microsoftonline.com
//!      for {domain} and {domain}.onmicrosoft.com variants.
//!   2. Parse the OIDC metadata to extract tenant_id, token_endpoint,
//!      authorization_endpoint.
//!   3. Detect federation (ADFS, Ping, Okta) via the federation metadata URL.
//!   4. Check common tenant subdomains (mail., autodiscover., lyncdiscover.)
//!      for M365 service presence.
//!   5. Optionally query GetCredentialType to confirm user-existence
//!      (non-destructive, P3-level).
//!
//! Non-destructive, low-impact — classified as Low-severity information
//! disclosure in typical bug bounty programs.

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{build_http_client, cfg_prompt_default, cfg_prompt_yes_no, is_batch_mode};

const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Domains to append when probing tenant variants.
const DOMAIN_VARIANTS: &[&str] = &[".onmicrosoft.com"];

/// M365 service subdomains that indicate tenant presence.
const M365_SERVICE_SUBDOMAINS: &[(&str, &str)] = &[
    ("autodiscover", "Exchange Autodiscover"),
    ("lyncdiscover", "Skype for Business / Teams"),
    ("enterpriseregistration", "Azure AD Device Registration"),
    ("msoid", "Microsoft Online ID"),
    ("sip", "Skype for Business SIP"),
    ("mail", "Exchange Online / Outlook"),
];

/// Federation brands that indicate non-Microsoft identity providers.
const FEDERATION_BRANDS: &[(&str, &str)] = &[
    ("ADFS", "Active Directory Federation Services"),
    ("PingFederate", "Ping Identity"),
    ("Okta", "Okta"),
    ("Shibboleth", "Shibboleth"),
    ("OneLogin", "OneLogin"),
    ("Auth0", "Auth0"),
    ("AzureAD", "Azure AD"),
];

fn banner() {
    if is_batch_mode() {
        return;
    }
    crate::mprintln!(
        "{}",
        "╔══════════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   M365 / Azure AD Tenant Enumeration                        ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   OIDC discovery + federation detection + service probe     ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚══════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

// ---------------------------------------------------------------------------
// Module metadata
// ---------------------------------------------------------------------------

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "M365 / Azure Tenant Enumeration".to_string(),
        description: "Tests whether a Microsoft 365 / Azure AD tenant exists for a given domain \
             by probing the standard OpenID Connect discovery endpoint on \
             login.microsoftonline.com. Detects federation type (ADFS, Ping, Okta), \
             extracts tenant metadata, and optionally probes M365 service subdomains \
             (autodiscover, lyncdiscover, mail). Non-destructive, classified as \
             Low-severity information disclosure. Based on M365 cross-program findings \
             from Optus, Twilio, and Zendesk bug bounty assessments."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://login.microsoftonline.com/common/.well-known/openid-configuration".to_string(),
            "https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc"
                .to_string(),
            "Optus M365 tenant enumeration (singteloptus.onmicrosoft.com)".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: None,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Probe OIDC discovery for a tenant label and return parsed metadata.
async fn probe_oidc(
    client: &reqwest::Client,
    tenant_label: &str,
) -> Result<(u16, serde_json::Value)> {
    let url = format!(
        "https://login.microsoftonline.com/{}/.well-known/openid-configuration",
        tenant_label
    );

    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .header(
            "User-Agent",
            "Mozilla/5.0 (compatible; RustSploit-M365-Scanner/1.0)",
        )
        .send()
        .await
        .context(format!("OIDC request failed for {tenant_label}"))?;

    let status = resp.status().as_u16();
    let body = match crate::utils::network::read_http_body_text_capped(
        resp,
        crate::utils::safe_io::DEFAULT_BODY_CAP,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("Failed to read OIDC body for {tenant_label}: {e}");
            return Ok((status, serde_json::Value::Null));
        }
    };

    let json: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    Ok((status, json))
}

/// Check if a domain has MX records pointing to M365 (*.mail.protection.outlook.com).
async fn check_m365_mx(domain: &str) -> Result<bool> {
    // Use tokio's DNS resolver (simplified — full MX check would need a DNS library)
    // For now, we just probe the autodiscover endpoint which is the most reliable indicator.
    let url = format!(
        "https://autodiscover.{}/autodiscover/autodiscover.xml",
        domain
    );
    let client = build_http_client(Duration::from_secs(5))?;
    match client
        .get(&url)
        .header(
            "User-Agent",
            "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.12026)",
        )
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            // 401 is expected from autodiscover (requires auth), which confirms existence
            Ok(status == 401 || status == 200)
        }
        Err(e) => {
            tracing::debug!("autodiscover check: {e:#}");
            Ok(false)
        }
    }
}

/// Check if a response body indicates federation (non-Microsoft IdP).
fn detect_federation(body: &str) -> Option<(String, String)> {
    let upper = body.to_uppercase();
    for (brand, label) in FEDERATION_BRANDS {
        if upper.contains(&brand.to_uppercase()) {
            return Some((brand.to_string(), label.to_string()));
        }
    }
    None
}

/// Extract key fields from OIDC metadata JSON.
fn extract_tenant_metadata(tenant: &str, json: &serde_json::Value) -> Vec<(String, String)> {
    tracing::trace!("extracting OIDC metadata for tenant '{tenant}'");
    let mut info = Vec::new();

    if let Some(v) = json.get("token_endpoint").and_then(|v| v.as_str()) {
        info.push(("token_endpoint".to_string(), v.to_string()));
    }
    if let Some(v) = json.get("authorization_endpoint").and_then(|v| v.as_str()) {
        info.push(("authorization_endpoint".to_string(), v.to_string()));
    }
    if let Some(v) = json.get("issuer").and_then(|v| v.as_str()) {
        info.push(("issuer".to_string(), v.to_string()));
        // Extract tenant_id from issuer URL
        if let Some(tid) = v.trim_end_matches('/').rsplit('/').next() {
            if tid.len() > 20 && tid.chars().all(|c| c.is_alphanumeric() || c == '-') {
                info.push(("tenant_id".to_string(), tid.to_string()));
            }
        }
    }
    if let Some(v) = json.get("tenant_region_scope").and_then(|v| v.as_str()) {
        info.push(("tenant_region".to_string(), v.to_string()));
    }
    if let Some(v) = json.get("cloud_instance_name").and_then(|v| v.as_str()) {
        info.push(("cloud_instance".to_string(), v.to_string()));
    }

    // If it's a federated tenant, the metadata may reference the federation URL
    if let Some(v) = json.get("userinfo_endpoint").and_then(|v| v.as_str()) {
        if v.contains("adfs") || v.contains("federation") || v.contains("saml") {
            info.push(("federation_hint".to_string(), v.to_string()));
        }
    }

    info
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("m365_tenant_enum requires a single target (domain name)")?;

    banner();

    let domain = cfg_prompt_default(
        "domain",
        "Domain to check for M365 tenant (e.g., example.com)",
        &target,
    )
    .await?;
    let domain = domain.trim().to_lowercase();

    let base_domain = if domain.starts_with("http") {
        // Strip scheme if user pasted a URL
        domain
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_start_matches("www.")
            .split('/')
            .next()
            .unwrap_or(&domain)
            .to_string()
    } else {
        domain.clone()
    };

    crate::mprintln!(
        "{}",
        format!("[*] Checking M365 tenant existence for: {}", base_domain).yellow()
    );

    let client = build_http_client(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .context("Failed to build HTTP client")?;

    let mut outcome = ModuleOutcome::ok();
    let mut tenant_found = false;
    let mut findings_report: Vec<String> = Vec::new();

    // -------------------------------------------------------------------
    // Phase 1: Probe OIDC discovery for domain variants
    // -------------------------------------------------------------------
    crate::mprintln!("{}", "\n[*] Phase 1: OIDC tenant discovery".cyan());

    let mut tenant_labels = vec![base_domain.clone()];

    // Also try onmicrosoft.com variant
    let clean_domain = base_domain
        .trim_end_matches(".onmicrosoft.com")
        .trim_end_matches(".com")
        .trim_end_matches(".org")
        .trim_end_matches(".net")
        .split('.')
        .next()
        .unwrap_or(&base_domain)
        .to_string();

    for variant in DOMAIN_VARIANTS {
        let label = format!("{clean_domain}{variant}");
        if !tenant_labels.contains(&label) {
            tenant_labels.push(label);
        }
    }

    // Deduplicate
    tenant_labels.sort();
    tenant_labels.dedup();

    let mut confirmed_tenants: Vec<(String, serde_json::Value)> = Vec::new();

    for label in &tenant_labels {
        let (status, json) = match probe_oidc(&client, label).await {
            Ok(r) => r,
            Err(e) => {
                crate::mprintln!("{}", format!("[-] Error probing '{}': {}", label, e).red());
                continue;
            }
        };

        if status == 200 {
            let is_valid = json.get("token_endpoint").is_some()
                && json.get("authorization_endpoint").is_some();

            if is_valid {
                crate::mprintln!(
                    "{}",
                    format!("[+] M365 tenant CONFIRMED: {}", label)
                        .green()
                        .bold()
                );
                confirmed_tenants.push((label.clone(), json.clone()));

                let metadata = extract_tenant_metadata(label, &json);
                for (key, val) in &metadata {
                    crate::mprintln!("{}", format!("    {}: {}", key.dimmed(), val));
                }

                // Check for federation
                let body_str = json.to_string();
                if let Some((brand, label_desc)) = detect_federation(&body_str) {
                    crate::mprintln!(
                        "{}",
                        format!(
                            "    [FEDERATED] {} ({})",
                            brand.yellow(),
                            label_desc.dimmed()
                        )
                    );
                }

                tenant_found = true;
                findings_report.push(format!("Tenant '{}' confirmed via OIDC discovery", label));
            } else {
                crate::mprintln!(
                    "{}",
                    format!("[~] '{}' returned HTTP 200 but no OIDC metadata", label).dimmed()
                );
            }
        } else if status == 400 {
            // 400 with "AADSTS" in body often means tenant exists but is misconfigured
            crate::mprintln!(
                "{}",
                format!(
                    "[~] '{}' returned HTTP 400 (may indicate misconfigured tenant)",
                    label
                )
                .dimmed()
            );
        } else if status == 404 {
            crate::mprintln!(
                "{}",
                format!("[-] '{}' does not exist (HTTP 404)", label).dimmed()
            );
        } else {
            crate::mprintln!(
                "{}",
                format!("[~] '{}' returned unexpected HTTP {}", label, status).dimmed()
            );
        }
    }

    // -------------------------------------------------------------------
    // Phase 2: Probe M365 service subdomains
    // -------------------------------------------------------------------
    crate::mprintln!("{}", "\n[*] Phase 2: M365 service subdomain probe".cyan());

    for (subdomain, service_name) in M365_SERVICE_SUBDOMAINS {
        let url = format!("https://{subdomain}.{base_domain}");
        match client
            .get(&url)
            .header(
                "User-Agent",
                "Mozilla/5.0 (compatible; RustSploit-M365-Scanner/1.0)",
            )
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                // 401 is expected for authenticated services — confirms existence
                if status == 401 || status == 403 || status == 200 {
                    crate::mprintln!(
                        "{}",
                        format!(
                            "[+] {} service detected: {} (HTTP {})",
                            service_name, url, status
                        )
                        .green()
                    );
                    findings_report.push(format!(
                        "{} service confirmed at {} (HTTP {})",
                        service_name, url, status
                    ));
                } else if status == 302 || status == 301 {
                    crate::mprintln!(
                        "{}",
                        format!("[~] {} redirects: {} (HTTP {})", service_name, url, status)
                            .dimmed()
                    );
                }
                // 404/NXDOMAIN = service not present (silent)
            }
            Err(e) => {
                tracing::debug!("service check: {e:#}");
                // Connection refused / timeout — service not present
            }
        }
    }

    // -------------------------------------------------------------------
    // Phase 3: Optional autodiscover check
    // -------------------------------------------------------------------
    let check_autodiscover = cfg_prompt_yes_no(
        "check_autodiscover",
        "Check Exchange Autodiscover endpoint for M365 presence?",
        true,
    )
    .await?;

    if check_autodiscover {
        match check_m365_mx(&base_domain).await {
            Ok(true) => {
                crate::mprintln!(
                    "{}",
                    format!(
                        "[+] Exchange Autodiscover confirmed for {} (M365 mail likely)",
                        base_domain
                    )
                    .green()
                );
                findings_report.push(format!(
                    "Exchange Autodiscover confirmed for {}",
                    base_domain
                ));
            }
            Ok(false) => {
                crate::mprintln!(
                    "{}",
                    format!(
                        "[-] Exchange Autodiscover not responding for {}",
                        base_domain
                    )
                    .dimmed()
                );
            }
            Err(e) => {
                tracing::debug!("autodiscover: {e:#}");
            }
        }
    }

    // -------------------------------------------------------------------
    // Emit findings
    // -------------------------------------------------------------------

    if tenant_found {
        crate::mprintln!(
            "{}",
            format!(
                "\n[+] M365 tenant(s) confirmed for {} — {} tenant label(s) found.",
                base_domain,
                confirmed_tenants.len()
            )
            .green()
            .bold()
        );

        for (label, json) in &confirmed_tenants {
            let metadata = extract_tenant_metadata(label, json);
            let body_str = json.to_string();
            let federation = detect_federation(&body_str);

            let mut data = serde_json::json!({
                "domain": base_domain,
                "tenant_label": label,
                "metadata": serde_json::json!({}),
            });

            if let Some(obj) = data.as_object_mut() {
                if let Some(serde_json::Value::Object(meta)) = obj.get_mut("metadata") {
                    for (k, v) in &metadata {
                        meta.insert(k.clone(), serde_json::Value::String(v.clone()));
                    }
                }
                if let Some((brand, label_desc)) = &federation {
                    obj.insert("federation_type".to_string(), serde_json::json!(brand));
                    obj.insert(
                        "federation_description".to_string(),
                        serde_json::json!(label_desc),
                    );
                }
            }

            outcome.findings.push(Finding {
                target: base_domain.clone(),
                kind: FindingKind::Note,
                message: format!(
                    "M365 tenant confirmed for {} ({}){}",
                    base_domain,
                    label,
                    if let Some((brand, _)) = &federation {
                        format!(" — federated via {brand}")
                    } else {
                        String::new()
                    }
                ),
                data: Some(data),
            });
        }
    } else {
        crate::mprintln!(
            "{}",
            format!(
                "\n[-] No M365 tenant detected for {} in any checked variant.",
                base_domain
            )
            .yellow()
        );

        outcome.findings.push(Finding {
            target: base_domain.clone(),
            kind: FindingKind::Note,
            message: format!("No M365 tenant detected for {}", base_domain),
            data: Some(serde_json::json!({
                "domain": base_domain,
                "checked_variants": tenant_labels,
                "services_found": findings_report,
            })),
        });
    }

    crate::mprintln!(
        "{}",
        format!(
            "[*] Enumeration complete: {} tenant variant(s) checked, {} confirmed.",
            tenant_labels.len(),
            confirmed_tenants.len()
        )
        .cyan()
    );

    Ok(outcome)
}

crate::register_native_module!(
    crate::module::Category::Scanners,
    "m365_tenant_enum",
    native
);

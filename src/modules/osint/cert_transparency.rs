//! Certificate Transparency subdomain enumeration via crt.sh.
//!
//! Queries the public crt.sh log search (`https://crt.sh/?q=<domain>&output=json`)
//! for every certificate ever issued to `<domain>` or its subdomains, parses
//! the common-name and subject-alternative-name fields, and emits a sorted,
//! deduplicated subdomain list.
//!
//! This is pure OSINT — no traffic is sent to the target itself. The only
//! external dependency is the public crt.sh service.

use anyhow::{Context, Result};
use colored::*;
use std::collections::BTreeSet;
use std::time::Duration;

use crate::module_info::{CheckResult, ModuleInfo, ModuleRank};

const CRT_SH_BASE: &str = "https://crt.sh";
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const MAX_RESULTS_DISPLAYED: usize = 500;
// Cap the JSON body. crt.sh routinely returns 5–50 MB for popular domains;
// 64 MiB is generous for legitimate use and forbids gigabyte allocations.
const MAX_CRTSH_BODY: usize = 64 * 1024 * 1024;

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Certificate Transparency subdomain enumeration".to_string(),
        description: "Queries crt.sh for every TLS certificate issued to the target \
                      domain or its subdomains, then extracts unique subdomain names \
                      from the CN / SAN fields. Pure OSINT — no traffic to the target."
            .to_string(),
        authors: vec!["RustSploit Team".to_string()],
        references: vec![
            "https://crt.sh/".to_string(),
            "https://certificate.transparency.dev/".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Normal,
    }
}

pub async fn check(_target: &str) -> CheckResult {
    // OSINT modules don't have a "vulnerable" state — they always run.
    CheckResult::Unknown("OSINT enumeration; no vulnerability check applicable".to_string())
}

pub async fn run(target: &str) -> Result<()> {
    if crate::utils::is_mass_scan_target(target) {
        anyhow::bail!("cert_transparency does not support mass-scan targets — it queries crt.sh by domain, target should be a registrable domain like example.com");
    }
    let domain = sanitize_domain(target)
        .context("invalid target — expected a registrable domain like example.com")?;

    crate::mprintln!(
        "{}",
        format!("[*] crt.sh subdomain enumeration for {}", domain).cyan()
    );

    let client = crate::utils::build_http_client(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .context("failed to build HTTP client")?;

    let url = format!("{}/?q=%25.{}&output=json", CRT_SH_BASE, urlencoding_encode(&domain));
    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .context("crt.sh request failed (network or service unavailable)")?;

    if !resp.status().is_success() {
        anyhow::bail!("crt.sh returned HTTP {}", resp.status());
    }

    let body_bytes =
        crate::utils::read_http_body_capped(resp, MAX_CRTSH_BODY)
            .await
            .context("failed to read crt.sh response body")?;
    let entries: Vec<CrtEntry> =
        serde_json::from_slice(&body_bytes).context("failed to parse crt.sh JSON response")?;

    let mut subdomains: BTreeSet<String> = BTreeSet::new();
    for entry in &entries {
        if crate::context::is_cancelled() {
            crate::mprintln!("{}", "[!] Cancelled during result parsing".yellow());
            return Ok(());
        }
        for name in entry.all_names() {
            if let Some(clean) = normalize_name(&name, &domain) {
                subdomains.insert(clean);
            }
        }
    }

    if subdomains.is_empty() {
        crate::mprintln!("{}", "[-] No subdomains found in CT logs".yellow());
        return Ok(());
    }

    crate::mprintln!(
        "{}",
        format!(
            "[+] Found {} unique subdomains across {} certificate records",
            subdomains.len(),
            entries.len()
        )
        .green()
    );

    for (i, sd) in subdomains.iter().enumerate() {
        if i >= MAX_RESULTS_DISPLAYED {
            crate::mprintln!(
                "{}",
                format!(
                    "    ... and {} more (truncated; total {})",
                    subdomains.len() - MAX_RESULTS_DISPLAYED,
                    subdomains.len()
                )
                .dimmed()
            );
            break;
        }
        crate::mprintln!("    {}", sd);
    }

    // Persist as a loot entry so the workspace tracks the finding.
    let summary = subdomains.iter().cloned().collect::<Vec<_>>().join("\n");
    let description = format!(
        "crt.sh certificate-transparency subdomains for {} ({} entries)",
        domain,
        subdomains.len()
    );
    let loot_id = crate::loot::store_loot(
        &domain,
        "subdomain-list",
        &description,
        summary.as_bytes(),
        "osint/cert_transparency",
    )
    .await;

    // Structured event for API/MCP/WS subscribers (no-op when no subscribers).
    if let Some(id) = loot_id {
        crate::events::emit(crate::events::ModuleEvent::LootStored {
            id,
            host: domain.clone(),
            kind: "subdomain-list".to_string(),
        });
    }
    for sd in &subdomains {
        crate::events::emit(crate::events::ModuleEvent::HostUp { host: sd.clone() });
    }

    Ok(())
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct CrtEntry {
    /// May be `null` for some old entries; tolerate missing fields.
    #[serde(default)]
    common_name: Option<String>,
    #[serde(default)]
    name_value: Option<String>,
}

impl CrtEntry {
    fn all_names(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(cn) = &self.common_name {
            out.push(cn.clone());
        }
        if let Some(nv) = &self.name_value {
            // `name_value` is newline-separated for multi-SAN certs.
            for line in nv.split('\n') {
                out.push(line.to_string());
            }
        }
        out
    }
}

/// Strict-ish domain validator. Accepts ASCII letters, digits, hyphens, dots.
/// Rejects anything that looks like a URL, scheme, port, or path.
fn sanitize_domain(input: &str) -> Result<String> {
    let trimmed = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() > 253 {
        anyhow::bail!("domain length out of range (1..=253)");
    }
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        anyhow::bail!("domain contains characters that are not letters, digits, '-' or '.'");
    }
    if trimmed.starts_with('.') || trimmed.starts_with('-') {
        anyhow::bail!("domain cannot start with '.' or '-'");
    }
    // Must contain at least one dot (TLDs alone aren't useful here).
    if !trimmed.contains('.') {
        anyhow::bail!("expected at least one '.' (e.g. example.com)");
    }
    Ok(trimmed)
}

/// Normalise a CT-log name string into a candidate subdomain. Filters out
/// wildcards, email addresses, and entries unrelated to the queried domain.
fn normalize_name(raw: &str, domain: &str) -> Option<String> {
    let s = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() || s.contains('@') {
        return None;
    }
    // Strip leading wildcard label.
    let s = s.strip_prefix("*.").unwrap_or(&s).to_string();
    if s == domain || s.ends_with(&format!(".{}", domain)) {
        Some(s)
    } else {
        None
    }
}

/// Minimal URL-component encoder for the query path. `urlencoding` crate is
/// not in the dep tree, but `crate::utils::url_encode` exists and proxies to
/// the vendored `native::url_encoding` helper.
fn urlencoding_encode(s: &str) -> String {
    crate::utils::url_encode(s)
}

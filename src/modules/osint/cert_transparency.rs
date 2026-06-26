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

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};

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
        default_port: None,
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("cert_transparency requires a single domain target")?;
    let domain = sanitize_domain(target)
        .with_context(|| format!("invalid domain '{}'", target))?;

    if !crate::utils::is_batch_mode() {
        crate::mprintln!("{}", "=== Certificate Transparency Subdomain Enum ===".bold());
        crate::mprintln!("[*] Querying crt.sh for {}", domain.cyan());
    }

    let url = format!(
        "{}/?q={}&output=json",
        CRT_SH_BASE,
        urlencoding_encode(&domain)
    );
    let client = crate::utils::build_http_client(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .context("failed to construct HTTP client")?;
    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .with_context(|| format!("crt.sh request to {} failed", url))?;
    if !resp.status().is_success() {
        anyhow::bail!("crt.sh returned status {}", resp.status());
    }
    // Cap the response body to avoid OOM on popular domains (crt.sh
    // commonly returns 5–50 MB JSON for high-traffic certs).
    let body = crate::utils::read_http_body_capped(resp, MAX_CRTSH_BODY)
        .await
        .context("reading crt.sh response body")?;
    let entries: Vec<CrtEntry> = serde_json::from_slice(&body)
        .context("crt.sh response was not valid JSON")?;

    let mut subdomains: BTreeSet<String> = BTreeSet::new();
    for entry in &entries {
        for name in entry.all_names() {
            if let Some(s) = normalize_name(&name, &domain) {
                subdomains.insert(s);
            }
        }
    }

    if subdomains.is_empty() {
        crate::mprintln!(
            "{}",
            format!("[-] No subdomains found for {} in CT logs.", domain).yellow()
        );
        return Ok(ModuleOutcome::ok());
    }

    let mut outcome = ModuleOutcome::ok();
    for sub in &subdomains {
        outcome.findings.push(Finding {
            target: domain.clone(),
            kind: FindingKind::Note,
            message: format!("CT log: subdomain {}", sub),
            data: Some(serde_json::json!({
                "vector": "crt.sh",
                "subdomain": sub,
                "parent_domain": domain,
            })),
        });
    }

    let total = subdomains.len();
    crate::mprintln!(
        "{}",
        format!(
            "[+] {} unique subdomain{} discovered for {}:",
            total,
            if total == 1 { "" } else { "s" },
            domain
        )
        .green()
        .bold()
    );

    // Cap on-screen output; the operator can re-run with `setg verbose y`
    // to get the full set if needed.
    for (shown, sub) in subdomains.iter().enumerate() {
        if shown >= MAX_RESULTS_DISPLAYED {
            crate::mprintln!(
                "{}",
                format!(
                    "  ... ({} more, omitted from console; raise MAX_RESULTS_DISPLAYED to see all)",
                    total - shown
                )
                .dimmed()
            );
            break;
        }
        crate::mprintln!("  {}", sub);
    }

    // Auto-populate workspace with the discovered names so downstream
    // resolvers and crawlers pick them up without operator effort.
    // (The Finding records above also flow through `route_findings` →
    // workspace::add_note for kind=Note, so this is intentional double-write
    // to preserve the existing operator-visible note format. Will be
    // collapsed once the route handles structured `data:` payloads.)
    for sub in &subdomains {
        crate::workspace::add_note(&domain, &format!("[cert_transparency] subdomain: {}", sub)).await;
    }

    Ok(outcome)
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

crate::register_native_module!(crate::module::Category::Osint, "cert_transparency", native);

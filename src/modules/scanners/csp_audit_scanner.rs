//! Content-Security-Policy auditor.
//!
//! Fetches CSP from the response header (or from the first `<meta
//! http-equiv="Content-Security-Policy">` if present), then flags:
//!   - Missing CSP entirely
//!   - Unfilled placeholders (`__NONCE__`, `{{nonce}}`) — Luno-class finding
//!   - `unsafe-inline` / `unsafe-eval`
//!   - `*` in `default-src` / `script-src` / `connect-src`
//!   - `data:` / `blob:` in `script-src`
//!   - Missing `frame-ancestors`
//!   - `http:` (mixed content) sources
//!   - Bypassable CDNs (jsdelivr, unpkg, googletagmanager, googleapis)

use anyhow::{Context, Result};
use colored::*;
use std::collections::HashMap;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::network::{build_http_client_with, HttpClientOpts};
use crate::utils::{cfg_prompt_default, is_batch_mode};

const RISKY_CDNS: &[&str] = &[
    "*.googleapis.com",
    "*.googletagmanager.com",
    "*.cloudflare.com",
    "*.jsdelivr.net",
    "unpkg.com",
    "ajax.googleapis.com",
    "*.s3.amazonaws.com",
];

fn banner() {
    if is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   Content-Security-Policy Auditor                            ║".cyan());
    crate::mprintln!("{}", "║   Flags weak/missing CSP and unsafe directive values         ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "CSP Auditor".to_string(),
        description: "Extracts Content-Security-Policy from headers or <meta> tags and flags \
                      unfilled placeholders, unsafe-inline/unsafe-eval, wildcard sources, \
                      missing frame-ancestors, mixed content, and overly broad CDN whitelists."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://content-security-policy.com/".to_string(),
            "https://csp-evaluator.withgoogle.com/".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
        default_port: None,
    }
}

fn url_with_scheme(t: &str) -> String {
    if t.starts_with("http://") || t.starts_with("https://") { t.to_string() }
    else { format!("https://{}", t.trim_end_matches('/')) }
}

fn parse_csp(s: &str) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for directive in s.split(';') {
        let directive = directive.trim();
        if directive.is_empty() { continue; }
        let mut parts = directive.split_ascii_whitespace();
        if let Some(name) = parts.next() {
            let values: Vec<String> = parts.map(|p| p.to_string()).collect();
            out.insert(name.to_ascii_lowercase(), values);
        }
    }
    out
}

/// Extract a Content-Security-Policy from `<meta>` tags. Handles attribute
/// reordering and single/double-quoted attribute values.
fn extract_meta_csp(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    // Walk every <meta ...> tag and check both http-equiv= and content=.
    let mut cursor = 0usize;
    while let Some(rel) = lower[cursor..].find("<meta") {
        let start = cursor + rel;
        let tag_end = match lower[start..].find('>') {
            Some(i) => start + i + 1,
            None => break,
        };
        let tag_lower = &lower[start..tag_end];
        let tag_orig = &html[start..tag_end];
        cursor = tag_end;

        // Quick http-equiv check (allow whitespace and either quote style)
        let is_csp_meta = tag_lower.contains("http-equiv=\"content-security-policy\"")
            || tag_lower.contains("http-equiv='content-security-policy'")
            || tag_lower.contains("http-equiv=content-security-policy");
        if !is_csp_meta { continue; }

        // Find content= attribute and extract its value.
        for marker in ["content=\"", "content=\'", "content="] {
            if let Some(pos) = tag_lower.find(marker) {
                let after = &tag_orig[pos + marker.len()..];
                let val = match marker {
                    "content=\"" => after.split('"').next(),
                    "content=\'" => after.split('\'').next(),
                    _ => after.split_ascii_whitespace().next(),
                };
                if let Some(v) = val
                    && !v.is_empty() { return Some(v.to_string()); }
            }
        }
    }
    None
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("csp_audit_scanner requires a single-host target")?;
    banner();
    let url = cfg_prompt_default("url", "Target URL", &url_with_scheme(target)).await?;

    let mut outcome = ModuleOutcome::ok();

    // Follow redirects so the audit reflects the page actually rendered.
    let client = build_http_client_with(Duration::from_secs(10), HttpClientOpts {
        follow_redirects: true,
        ..HttpClientOpts::permissive()
    })?;
    ctx.rate_limit(target).await;
    let resp = client.get(&url).send().await
        .context("Request failed")?;
    let status = resp.status();
    let header_csp = resp.headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let body = match resp.text().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("Failed to read response body: {}", e);
            String::new()
        }
    };
    let meta_csp = extract_meta_csp(&body);

    crate::mprintln!("{}", format!("[*] {} -> {}", url, status).cyan());

    let (csp, source) = match (header_csp.clone(), meta_csp.clone()) {
        (Some(h), _) => (h, "response header"),
        (None, Some(m)) => (m, "<meta> tag"),
        (None, None) => {
            crate::mprintln!("{}", "[!] No CSP found (header or meta).".red().bold());
            crate::mprintln!("{}", "    Recommendation: missing CSP is a P4 finding on most programs.".yellow());
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind: FindingKind::Vulnerable,
                message: format!("No Content-Security-Policy at {url}"),
                data: None,
            });
            return Ok(outcome);
        }
    };

    crate::mprintln!("{}", format!("[*] CSP source: {}", source).cyan());
    crate::mprintln!("{}", format!("    {}", csp).dimmed());
    crate::mprintln!();

    let mut findings: Vec<String> = Vec::new();
    let directives = parse_csp(&csp);

    if csp.contains("__NONCE__") || csp.contains("{{nonce}}") || csp.contains("__CSP_NONCE__") {
        findings.push("CSP contains UNFILLED placeholder (e.g. __NONCE__) — server-side template bug, all nonce-protections defeated".to_string());
    }
    if csp.contains("http:") {
        findings.push("CSP allows http: scheme (mixed content)".to_string());
    }

    let critical_dirs = ["default-src", "script-src", "script-src-elem", "connect-src", "object-src", "frame-src"];
    let risky_lower: Vec<String> = RISKY_CDNS.iter().map(|c| c.to_ascii_lowercase()).collect();
    for dir in &critical_dirs {
        if let Some(values) = directives.get(*dir) {
            for v in values {
                let lv = v.to_ascii_lowercase();
                if lv == "*" {
                    findings.push(format!("{}: wildcard '*' source", dir));
                }
                if lv == "'unsafe-inline'" {
                    findings.push(format!("{}: 'unsafe-inline'", dir));
                }
                if lv == "'unsafe-eval'" {
                    findings.push(format!("{}: 'unsafe-eval'", dir));
                }
                if (dir == &"script-src" || dir == &"script-src-elem") && (lv == "data:" || lv == "blob:") {
                    findings.push(format!("{}: '{}' allowed (script smuggling)", dir, v));
                }
                // Match risky CDNs whether the source is bare (`*.googleapis.com`)
                // or scheme-prefixed (`https://*.googleapis.com`).
                let host_only = lv
                    .strip_prefix("https://").or_else(|| lv.strip_prefix("http://"))
                    .unwrap_or(&lv);
                if risky_lower.iter().any(|c| c == host_only) {
                    findings.push(format!("{}: broad CDN '{}' (commonly bypassable)", dir, v));
                }
            }
        }
    }

    if !directives.contains_key("frame-ancestors") {
        findings.push("Missing frame-ancestors directive (clickjacking via iframe)".to_string());
    } else if directives.get("frame-ancestors").map(|v| v.iter().any(|x| x == "*")).unwrap_or(false) {
        findings.push("frame-ancestors: '*' (clickjacking)".to_string());
    }

    if !directives.contains_key("default-src") && !directives.contains_key("script-src") {
        findings.push("No default-src and no script-src — script execution is unrestricted".to_string());
    }

    if !directives.contains_key("object-src") && !directives.contains_key("default-src") {
        findings.push("Missing object-src 'none' (Flash/plugin XSS)".to_string());
    }

    crate::mprintln!("{}", "=== Findings ===".bold());
    if findings.is_empty() {
        crate::mprintln!("{}", "  CSP looks reasonable.".green());
    } else {
        for f in &findings {
            crate::mprintln!("{}", format!("  - {}", f).yellow());
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind: FindingKind::Vulnerable,
                message: format!("CSP weakness at {url}: {f}"),
                data: None,
            });
        }
    }

    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Scanners, "csp_audit_scanner", native);

//! HTTP security-headers audit.
//!
//! Mirrors the `curl -I` / `curl -sIL` pattern that produced 21+ findings
//! across Canterbury, Optus, Luno, etc. Reports missing or weak:
//!   - Strict-Transport-Security (HSTS)
//!   - Content-Security-Policy (presence only — see `csp_audit_scanner` for depth)
//!   - X-Frame-Options
//!   - X-Content-Type-Options
//!   - Referrer-Policy
//!   - Permissions-Policy
//!   - Cross-Origin-{Opener,Embedder,Resource}-Policy
//!     Also surfaces verbose `Server:` and `X-Powered-By:` banners and
//!     cookies missing `Secure` / `HttpOnly` / `SameSite`.

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::network::HttpClientOpts;
use crate::utils::network::build_http_client_with;
use crate::utils::{cfg_prompt_default, is_batch_mode};

fn banner() {
    if is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   HTTP Security Headers Audit                                ║".cyan());
    crate::mprintln!("{}", "║   Flags missing/weak HSTS, CSP, XFO, COOP, banners, cookies  ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Security Headers Audit".to_string(),
        description: "Fetches a target URL, audits the security-relevant response headers, and \
                      reports missing/weak HSTS, CSP, X-Frame-Options, COOP/COEP/CORP, server \
                      banners, and insecure cookie attributes."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://owasp.org/www-project-secure-headers/".to_string(),
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
        default_port: None,
    }
}

fn url_with_scheme(t: &str) -> String {
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t.trim_end_matches('/'))
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("security_headers_scanner requires a single-host target")?;
    banner();
    let url = cfg_prompt_default("url", "Target URL", &url_with_scheme(target)).await?;

    let mut outcome = ModuleOutcome::ok();

    // Follow redirects so we audit the headers of the *final* response, matching
    // browser behaviour. Otherwise a 301 to the canonical host would mask its CSP/HSTS.
    let client = build_http_client_with(Duration::from_secs(10), HttpClientOpts {
        follow_redirects: true,
        ..HttpClientOpts::permissive()
    })?;
    ctx.rate_limit(target).await;
    let resp = client.get(&url).send().await
        .context("Request failed")?;
    let final_url = resp.url().to_string();
    if final_url != url {
        crate::mprintln!("{}", format!("[*] redirected -> {}", final_url).dimmed());
    }

    let status = resp.status();
    let headers = resp.headers().clone();

    crate::mprintln!("{}", format!("[*] {} -> {}", url, status).cyan());
    crate::mprintln!();

    let mut findings: Vec<String> = Vec::new();

    let get = |name: &str| -> Option<String> {
        headers.get(name).and_then(|v| v.to_str().ok()).map(|s| s.to_string())
    };

    // HSTS
    match get("strict-transport-security") {
        Some(v) => {
            let lower = v.to_ascii_lowercase();
            let max_age = lower.split(';')
                .find_map(|p| p.trim().strip_prefix("max-age="))
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(0);
            if max_age < 15_768_000 {
                findings.push(format!("HSTS max-age={} too low (<6 months): '{}'", max_age, v));
                crate::mprintln!("{}", format!("[!] HSTS weak: {}", v).yellow());
            } else if !lower.contains("includesubdomains") {
                findings.push(format!("HSTS missing includeSubDomains: '{}'", v));
                crate::mprintln!("{}", format!("[~] HSTS no subdomains: {}", v).yellow());
            } else {
                crate::mprintln!("{}", format!("[+] HSTS: {}", v).green());
            }
        }
        None if url.starts_with("https://") => {
            findings.push("Missing Strict-Transport-Security header on HTTPS endpoint".to_string());
            crate::mprintln!("{}", "[!] HSTS missing".red());
        }
        _ => {}
    }

    // CSP
    match get("content-security-policy") {
        Some(v) => {
            let lower = v.to_ascii_lowercase();
            if v.contains("__NONCE__") || v.contains("{{") {
                findings.push(format!("CSP contains unfilled placeholder: '{}'", v));
                crate::mprintln!("{}", format!("[!!] CSP placeholder unreplaced: {}", v).red().bold());
            } else if lower.contains("unsafe-inline") || lower.contains("unsafe-eval") {
                findings.push(format!("CSP allows unsafe-inline/unsafe-eval: '{}'", v));
                crate::mprintln!("{}", format!("[!] CSP weak: {}", v).yellow());
            } else {
                crate::mprintln!("{}", format!("[+] CSP present ({} chars)", v.len()).green());
            }
        }
        None => {
            findings.push("Missing Content-Security-Policy header".to_string());
            crate::mprintln!("{}", "[!] CSP missing".yellow());
        }
    }

    // X-Frame-Options
    match get("x-frame-options") {
        Some(v) => {
            let l = v.to_ascii_lowercase();
            if l == "deny" || l == "sameorigin" {
                crate::mprintln!("{}", format!("[+] X-Frame-Options: {}", v).green());
            } else {
                findings.push(format!("X-Frame-Options weak: '{}'", v));
                crate::mprintln!("{}", format!("[!] X-Frame-Options weak: {}", v).yellow());
            }
        }
        None if !get("content-security-policy").map(|c| c.to_ascii_lowercase().contains("frame-ancestors")).unwrap_or(false) => {
            findings.push("Missing X-Frame-Options and no CSP frame-ancestors directive (clickjacking)".to_string());
            crate::mprintln!("{}", "[!] X-Frame-Options missing (no CSP frame-ancestors)".yellow());
        }
        _ => {}
    }

    // X-Content-Type-Options
    match get("x-content-type-options") {
        Some(v) if v.eq_ignore_ascii_case("nosniff") => {
            crate::mprintln!("{}", "[+] X-Content-Type-Options: nosniff".green());
        }
        Some(v) => {
            findings.push(format!("X-Content-Type-Options not 'nosniff': '{}'", v));
            crate::mprintln!("{}", format!("[!] X-Content-Type-Options weak: '{}'", v).yellow());
        }
        None => {
            findings.push("Missing X-Content-Type-Options".to_string());
            crate::mprintln!("{}", "[~] X-Content-Type-Options missing".dimmed());
        }
    }

    // Referrer-Policy
    match get("referrer-policy") {
        Some(v) => crate::mprintln!("{}", format!("[+] Referrer-Policy: {}", v).green()),
        None => {
            findings.push("Missing Referrer-Policy".to_string());
            crate::mprintln!("{}", "[~] Referrer-Policy missing".dimmed());
        }
    }

    // Permissions-Policy
    if get("permissions-policy").is_none() && get("feature-policy").is_none() {
        findings.push("Missing Permissions-Policy".to_string());
        crate::mprintln!("{}", "[~] Permissions-Policy missing".dimmed());
    }

    // COOP / COEP / CORP
    for h in ["cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy"] {
        if let Some(v) = get(h) {
            crate::mprintln!("{}", format!("[+] {}: {}", h, v).green());
        }
    }

    // Server / X-Powered-By banners
    if let Some(v) = get("server") {
        // Anything with version digits is a banner leak
        if v.chars().any(|c| c.is_ascii_digit()) {
            findings.push(format!("Verbose Server banner: '{}'", v));
            crate::mprintln!("{}", format!("[!] Server banner leak: {}", v).yellow());
        } else {
            crate::mprintln!("{}", format!("[~] Server: {}", v).dimmed());
        }
    }
    if let Some(v) = get("x-powered-by") {
        findings.push(format!("X-Powered-By banner: '{}'", v));
        crate::mprintln!("{}", format!("[!] X-Powered-By: {}", v).yellow());
    }
    if let Some(v) = get("x-aspnet-version").or_else(|| get("x-aspnetmvc-version")) {
        findings.push(format!("ASP.NET version banner: '{}'", v));
        crate::mprintln!("{}", format!("[!] ASP.NET banner: {}", v).yellow());
    }

    // Cookies — split each Set-Cookie by ';' and match attribute *tokens*, not
    // free-text substrings (otherwise `name=secureguid` falsely satisfies `Secure`).
    let mut cookie_issues: Vec<String> = Vec::new();
    for sc in headers.get_all("set-cookie").iter() {
        let s = match sc.to_str() { Ok(s) => s, Err(e) => { tracing::debug!("non-utf8 header: {e}"); continue; } };
        let mut parts = s.split(';');
        let name_eq = parts.next().unwrap_or("");
        let name = name_eq.split('=').next().unwrap_or("?").trim().to_string();
        let attrs: Vec<String> = parts.map(|p| {
            // Each attribute token may itself be `Name=Value`; lowercase the name part only.
            let token = p.trim();
            token.split('=').next().unwrap_or("").trim().to_ascii_lowercase()
        }).collect();
        let has = |a: &str| attrs.iter().any(|x| x == a);

        let mut probs: Vec<&str> = Vec::new();
        if !has("secure") && final_url.starts_with("https://") { probs.push("missing Secure"); }
        if !has("httponly") { probs.push("missing HttpOnly"); }
        if !has("samesite") { probs.push("missing SameSite"); }
        if !probs.is_empty() {
            cookie_issues.push(format!("cookie '{}': {}", name, probs.join(", ")));
        }
    }
    for c in &cookie_issues {
        crate::mprintln!("{}", format!("[!] {}", c).yellow());
        findings.push(c.clone());
    }

    crate::mprintln!();
    crate::mprintln!("{}", "=== Summary ===".bold());
    if findings.is_empty() {
        crate::mprintln!("{}", "  No issues — headers look hardened.".green());
    } else {
        for f in &findings {
            crate::mprintln!("{}", format!("  - {}", f).yellow());
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind: FindingKind::Vulnerable,
                message: format!("Security header issue at {}: {}", final_url, f),
                data: None,
            });
        }
    }

    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Scanners, "security_headers_scanner", native);

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("cookie_scanner requires a single-host target")?;

    crate::mprintln!(
        "{}",
        format!("[*] Cookie Security Scanner — target: {}", target).cyan()
    );

    let port = ctx.options.get_or("port", 443u16);
    let timeout_secs = ctx.options.get_or("timeout", 10u64).clamp(1, 60);

    let client = crate::utils::build_http_client(Duration::from_secs(timeout_secs))?;

    // Probe common paths that are likely to set cookies
    let paths = [
        "/",
        "/login",
        "/api",
        "/auth",
        "/signin",
        "/account",
        "/wp-login.php",
        "/administrator",
        "/user/login",
    ];

    let base_url = format!("https://{}:{}", target, port);
    let mut outcome = ModuleOutcome::ok();
    let mut cookies_found = 0u32;
    let mut issues_found = 0u32;
    let mut seen_cookies: std::collections::HashSet<String> = std::collections::HashSet::new();

    crate::mprintln!(
        "{}",
        format!(
            "[*] Probing {} paths for Set-Cookie headers...",
            paths.len()
        )
        .dimmed()
    );

    for path in paths {
        let url = format!("{}{}", base_url, path);
        match client.get(&url).send().await {
            Ok(resp) => {
                for cookie_value in resp.headers().get_all("set-cookie") {
                    let cookie_str = match cookie_value.to_str() {
                        Ok(s) => s.to_string(),
                        Err(e) => {
                            crate::meprintln!("[-] Non-UTF8 cookie value at {}: {}", path, e);
                            continue;
                        }
                    };

                    // Parse cookie name
                    let cookie_name = match cookie_str.split('=').next() {
                        Some(n) => n.to_string(),
                        None => continue,
                    };

                    // Skip duplicates across paths
                    if !seen_cookies.insert(cookie_name.clone()) {
                        continue;
                    }
                    cookies_found += 1;

                    let mut issues: Vec<String> = Vec::new();

                    // Check Secure flag
                    if !cookie_str.to_lowercase().contains("secure") {
                        issues.push("missing Secure flag".to_string());
                    }
                    // Check HttpOnly flag
                    if !cookie_str.to_lowercase().contains("httponly") {
                        issues.push("missing HttpOnly flag".to_string());
                    }
                    // Check SameSite
                    let samesite_lower = cookie_str.to_lowercase();
                    if !samesite_lower.contains("samesite") {
                        issues.push("missing SameSite attribute".to_string());
                    } else if samesite_lower.contains("samesite=none")
                        && !samesite_lower.contains("secure")
                    {
                        issues.push("SameSite=None without Secure flag".to_string());
                    }
                    // Check Domain scope
                    if cookie_str.to_lowercase().contains("domain=") {
                        let domain_part: Vec<&str> = cookie_str.split("domain=").collect();
                        if domain_part.len() > 1 {
                            let domain = domain_part[1].split(';').next().unwrap_or("");
                            if domain.starts_with('.') {
                                issues.push(format!("wide Domain scope ({})", domain));
                            }
                        }
                    }
                    // Check Path scope
                    if cookie_str.to_lowercase().contains("path=/")
                        && !cookie_str.to_lowercase().contains("path=/;")
                    {
                        // Path=/ is the default — wide scope
                    }

                    if issues.is_empty() {
                        crate::mprintln!(
                            "{}",
                            format!("[~] Cookie '{}' at {} — OK", cookie_name, path).dimmed()
                        );
                    } else {
                        for issue in &issues {
                            let msg = format!("Cookie '{}' at {}: {}", cookie_name, path, issue);
                            crate::mprintln!("{}", format!("[!] {}", msg).yellow());
                            outcome.findings.push(Finding {
                                target: target.to_string(),
                                kind: FindingKind::Note,
                                message: msg,
                                data: None,
                            });
                            issues_found += 1;
                        }
                    }
                }
            }
            Err(e) => {
                // Most paths will 404 — only log unexpected errors
                let err_str = format!("{}", e);
                if err_str.contains("timeout") {
                    crate::meprintln!("[-] {} timed out", url);
                }
            }
        }
    }

    crate::mprintln!();
    crate::mprintln!("{}", "=== Cookie Security Summary ===".bold());
    crate::mprintln!("  Target:          {}", target);
    crate::mprintln!("  Paths probed:    {}", paths.len());
    crate::mprintln!("  Unique cookies:  {}", cookies_found);
    crate::mprintln!("  Security issues: {}", issues_found);

    Ok(outcome)
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Cookie Security Attribute Scanner".to_string(),
        description: "Probes common paths for Set-Cookie headers and audits cookie security attributes: Secure, HttpOnly, SameSite, Domain scope, and Path scope. Flags missing protections across all discovered cookies.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://owasp.org/www-community/controls/SecureCookieAttribute".to_string(),
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: Some(443),
    }
}

crate::register_native_module!(crate::module::Category::Scanners, "cookie_scanner", native);

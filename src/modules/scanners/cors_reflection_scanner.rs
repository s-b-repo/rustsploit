//! CORS reflection / misconfiguration scanner.
//!
//! Probes a target URL with a battery of `Origin:` headers (attacker, null,
//! suffix-confusion, scheme-downgrade) and an OPTIONS preflight to detect:
//!   - Origin reflection in `Access-Control-Allow-Origin`
//!   - Wildcard ACAO with `Access-Control-Allow-Credentials: true`
//!   - `null` origin acceptance
//!   - Suffix/prefix bypasses (`https://target.com.attacker.evil`)
//!   - Trust of arbitrary subdomains via `*` ACAO with credentials
//!
//! Mirrors the `curl -H "Origin: ..."` pattern used across Twilio, Optus,
//! Playtika, Luno engagements.

use anyhow::{anyhow, Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::parallel::{run_buffered, BoxFut};
use crate::utils::{build_http_client, cfg_prompt_default, cfg_prompt_yes_no, is_batch_mode};

const CORS_CONCURRENCY: usize = 8;

fn banner() {
    if is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   CORS Reflection Scanner                                    ║".cyan());
    crate::mprintln!("{}", "║   Tests Access-Control-Allow-Origin trust boundaries         ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "CORS Reflection Scanner".to_string(),
        description:
            "Sends a battery of Origin headers (attacker, null, suffix/prefix confusion, scheme \
             downgrade) plus an OPTIONS preflight, and reports any reflected or wildcard ACAO, \
             especially when paired with Access-Control-Allow-Credentials: true."
                .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties".to_string(),
            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

fn url_with_scheme(t: &str) -> String {
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t.trim_end_matches('/'))
    }
}

fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url).ok().and_then(|u| u.host_str().map(|s| s.to_string()))
}

fn origin_payloads(target_host: &str) -> Vec<(&'static str, String)> {
    vec![
        ("attacker", "https://attacker.evil".to_string()),
        ("null", "null".to_string()),
        ("file", "file://".to_string()),
        ("data", "data://attacker.evil".to_string()),
        ("scheme-downgrade", format!("http://{}", target_host)),
        ("suffix-confusion", format!("https://{}.attacker.evil", target_host)),
        ("prefix-confusion", format!("https://attacker{}", target_host)),
        ("subdomain-wildcard", format!("https://evil.{}", target_host)),
        ("trailing-dot", format!("https://{}..attacker.evil", target_host)),
        ("https-wild", "https://*".to_string()),
    ]
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("cors_reflection_scanner requires a single-host target")?;
    banner();

    let url = cfg_prompt_default("url", "Target URL (will infer scheme)", &url_with_scheme(target)).await?;
    let host = host_of(&url).ok_or_else(|| anyhow!("Could not parse host from URL: {}", url))?;

    let test_preflight = cfg_prompt_yes_no("preflight", "Run OPTIONS preflight tests?", true).await?;
    let timeout_secs = 10u64;

    let client = build_http_client(Duration::from_secs(timeout_secs))?;
    let mut outcome = ModuleOutcome::ok();

    crate::mprintln!("{}", format!("[*] Target: {}", url).cyan());
    crate::mprintln!("{}", format!("[*] Host:   {}", host).cyan());
    crate::mprintln!();

    let mut findings: Vec<String> = Vec::new();

    // Probe each Origin payload concurrently (up to CORS_CONCURRENCY in
    // flight). Output preserves payload order so the operator reads a
    // stable per-payload table.
    ctx.rate_limit(target).await;
    let work: Vec<BoxFut<(&'static str, String, reqwest::Result<reqwest::Response>)>> =
        origin_payloads(&host).into_iter().map(|(label, origin)| {
            let client = client.clone();
            let url = url.clone();
            Box::pin(async move {
                let resp = client.get(&url).header("Origin", &origin).send().await;
                (label, origin, resp)
            }) as _
        }).collect();
    let results = run_buffered(work, CORS_CONCURRENCY).await;

    for (label, origin, result) in results {
        let resp = match result {
            Ok(r) => r,
            Err(e) => {
                crate::mprintln!("{}", format!("[-] {:<18} -> request error: {}", label, e).red());
                continue;
            }
        };

        let status = resp.status();
        let acao = resp.headers().get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let acac = resp.headers().get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let acam = resp.headers().get("access-control-allow-methods")
            .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let vary = resp.headers().get("vary")
            .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();

        let credentials = acac.eq_ignore_ascii_case("true");
        let reflected = !acao.is_empty() && acao.eq_ignore_ascii_case(&origin);
        let wildcard = acao == "*";

        let severity = if reflected && credentials {
            let msg = format!("CRITICAL: Origin '{}' reflected with credentials (status {})", origin, status);
            findings.push(msg.clone());
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind: FindingKind::Vulnerable,
                message: msg,
                data: None,
            });
            "CRIT".red().bold().to_string()
        } else if reflected {
            let msg = format!("HIGH: Origin '{}' reflected (no credentials)", origin);
            findings.push(msg.clone());
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind: FindingKind::Vulnerable,
                message: msg,
                data: None,
            });
            "HIGH".yellow().bold().to_string()
        } else if wildcard && credentials {
            let msg = format!("CRITICAL: Wildcard ACAO with credentials (origin '{}')", origin);
            findings.push(msg.clone());
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind: FindingKind::Vulnerable,
                message: msg,
                data: None,
            });
            "CRIT".red().bold().to_string()
        } else if matches!(label, "null" | "file" | "data") && acao == origin {
            let msg = format!("HIGH: opaque origin '{}' trusted (label={})", origin, label);
            findings.push(msg.clone());
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind: FindingKind::Vulnerable,
                message: msg,
                data: None,
            });
            "HIGH".yellow().bold().to_string()
        } else if !acao.is_empty() {
            "ok ".dimmed().to_string()
        } else {
            "—  ".dimmed().to_string()
        };

        crate::mprintln!(
            "[{}] {:<18} status={} acao='{}' creds='{}' methods='{}' vary='{}'",
            severity, label, status.as_u16(), acao, acac, acam, vary
        );
    }

    if test_preflight {
        crate::mprintln!();
        crate::mprintln!("{}", "[*] Preflight (OPTIONS) tests".cyan());
        let preflight_origins = vec![
            ("attacker", "https://attacker.evil"),
            ("null", "null"),
        ];
        for (label, origin) in preflight_origins {
            ctx.rate_limit(target).await;
            let resp = client
                .request(reqwest::Method::OPTIONS, &url)
                .header("Origin", origin)
                .header("Access-Control-Request-Method", "GET")
                .header("Access-Control-Request-Headers", "authorization,content-type")
                .send()
                .await;
            match resp {
                Ok(r) => {
                    let status = r.status();
                    let acao = r.headers().get("access-control-allow-origin")
                        .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                    let acac = r.headers().get("access-control-allow-credentials")
                        .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                    let acah = r.headers().get("access-control-allow-headers")
                        .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                    if !acao.is_empty() && (acao == origin || acao == "*") {
                        let creds = acac.eq_ignore_ascii_case("true");
                        let tag = if creds { "CRIT".red().bold().to_string() } else { "HIGH".yellow().bold().to_string() };
                        let msg = format!("Preflight {} accepted with origin '{}' creds={}", label, origin, creds);
                        findings.push(msg.clone());
                        outcome.findings.push(Finding {
                            target: target.to_string(),
                            kind: FindingKind::Vulnerable,
                            message: msg,
                            data: None,
                        });
                        crate::mprintln!("[{}] preflight {:<8} status={} acao='{}' creds='{}' headers='{}'",
                            tag, label, status.as_u16(), acao, acac, acah);
                    } else {
                        crate::mprintln!("[ ok ] preflight {:<8} status={} acao='{}' creds='{}'",
                            label, status.as_u16(), acao, acac);
                    }
                }
                Err(e) => {
                    crate::mprintln!("{}", format!("[-] preflight {} -> {}", label, e).red());
                }
            }
        }
    }

    crate::mprintln!();
    crate::mprintln!("{}", "=== Summary ===".bold());
    if findings.is_empty() {
        crate::mprintln!("{}", "  No CORS misconfigurations detected.".green());
    } else {
        for f in &findings {
            crate::mprintln!("{}", format!("  - {}", f).yellow());
        }
    }

    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Scanners, "cors_reflection_scanner", native);

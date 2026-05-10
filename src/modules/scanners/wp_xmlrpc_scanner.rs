//! WordPress XML-RPC scanner (Canterbury / Pureplesier finding pattern).
//!
//! Probes `/xmlrpc.php` and reports:
//!   - Endpoint reachable (HEAD/GET 405 means it's there)
//!   - `system.listMethods` returns method list
//!   - `system.multicall` available (used to amplify password-spray and
//!     pingback DDoS)
//!   - `pingback.ping` available (SSRF / pingback DDoS primitive)

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{build_http_client, cfg_prompt_default, is_batch_mode};

fn banner() {
    if is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   WordPress XML-RPC Scanner                                  ║".cyan());
    crate::mprintln!("{}", "║   Detects xmlrpc.php + system.multicall + pingback primitives║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "WordPress XML-RPC Scanner".to_string(),
        description: "Detects /xmlrpc.php exposure on WordPress sites, enumerates allowed methods \
                      via system.listMethods, and flags system.multicall (password-spray amplifier) \
                      and pingback.ping (SSRF / DDoS primitive)."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://hackerone.com/reports/178665".to_string(),
            "https://www.acunetix.com/blog/articles/wordpress-xml-rpc-amplification/".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

fn url_with_scheme(t: &str) -> String {
    if t.starts_with("http://") || t.starts_with("https://") { t.to_string() }
    else { format!("https://{}", t.trim_end_matches('/')) }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("wp_xmlrpc_scanner requires a single-host target")?;
    banner();
    let base = cfg_prompt_default("url", "Target base URL", &url_with_scheme(target)).await?;
    let endpoint = format!("{}/xmlrpc.php", base.trim_end_matches('/'));

    let client = build_http_client(Duration::from_secs(10))?;
    let mut outcome = ModuleOutcome::ok();

    // 1) GET should return 405 "XML-RPC server accepts POST requests only."
    crate::mprintln!("{}", format!("[*] GET  {}", endpoint).cyan());
    ctx.rate_limit(target).await;
    let get = client.get(&endpoint).send().await;
    let mut reachable = false;
    if let Ok(r) = get {
        let s = r.status().as_u16();
        let body = r.text().await.unwrap_or_default();
        if body.contains("XML-RPC server accepts POST requests only") || s == 405 {
            crate::mprintln!("{}", format!("[+] xmlrpc.php reachable (status {})", s).green().bold());
            reachable = true;
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind: FindingKind::Note,
                message: format!("WordPress xmlrpc.php reachable at {endpoint} (status {s})"),
                data: None,
            });
        } else if s == 404 {
            crate::mprintln!("{}", format!("[~] {} -> 404, no WordPress XML-RPC here", endpoint).dimmed());
            return Ok(outcome);
        } else {
            crate::mprintln!("{}", format!("[?] status={} body[..100]={:?}", s, body.chars().take(100).collect::<String>()).yellow());
        }
    }
    if !reachable {
        crate::mprintln!("{}", "[~] Endpoint did not confirm WordPress; continuing with POST tests anyway".dimmed());
    }

    // 2) system.listMethods
    let list_body = r#"<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"#;
    crate::mprintln!("{}", format!("[*] POST system.listMethods -> {}", endpoint).cyan());
    ctx.rate_limit(target).await;
    let resp = client.post(&endpoint)
        .header("Content-Type", "text/xml")
        .body(list_body)
        .send().await;

    let mut has_multicall = false;
    let mut has_pingback = false;

    if let Ok(r) = resp {
        let s = r.status().as_u16();
        let body = r.text().await.unwrap_or_default();
        if body.contains("methodResponse") && body.contains("<string>") {
            has_multicall = body.contains("system.multicall");
            has_pingback = body.contains("pingback.ping");
            let count = body.matches("<string>").count();
            crate::mprintln!("{}", format!("[+] listMethods OK (status {}, ~{} methods)", s, count).green().bold());
            if has_multicall {
                crate::mprintln!("{}", "[!!] system.multicall AVAILABLE — password-spray amplifier (200+ creds per request)".red().bold());
                outcome.findings.push(Finding {
                    target: target.to_string(),
                    kind: FindingKind::Vulnerable,
                    message: format!("system.multicall enabled at {endpoint} — password-spray amplifier"),
                    data: None,
                });
            }
            if has_pingback {
                crate::mprintln!("{}", "[!!] pingback.ping AVAILABLE — SSRF / pingback-DDoS primitive".red().bold());
                outcome.findings.push(Finding {
                    target: target.to_string(),
                    kind: FindingKind::Vulnerable,
                    message: format!("pingback.ping enabled at {endpoint} — SSRF / DDoS primitive"),
                    data: None,
                });
            }
        } else {
            crate::mprintln!("{}", format!("[?] status={} body[..200]={:?}", s, body.chars().take(200).collect::<String>()).yellow());
        }
    }

    // 3) Active pingback.ping probe (NON-destructive — points target at itself, no delivery target)
    if has_pingback {
        crate::mprintln!("{}", "[*] (Skipping live pingback.ping probe — would require attacker callback URL.)".dimmed());
    }

    crate::mprintln!();
    crate::mprintln!("{}", "=== Summary ===".bold());
    if has_multicall || has_pingback {
        crate::mprintln!("{}", format!("  Findings: multicall={} pingback={} — file as low/medium with amplification CVSS",
            has_multicall, has_pingback).yellow());
    } else if reachable {
        crate::mprintln!("  xmlrpc.php reachable but no high-risk methods detected.");
    } else {
        crate::mprintln!("{}", "  No xmlrpc.php exposure.".green());
    }

    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Scanners, "wp_xmlrpc_scanner", native);

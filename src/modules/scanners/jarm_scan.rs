//! JARM Active TLS Server Fingerprinting Scanner
//!
//! JARM (Salesforce, BSD-3-Clause) actively fingerprints a TLS server by
//! sending 10 hand-crafted ClientHello packets and folding the ServerHello
//! responses into a 62-character hash. The hash is comparable with other JARM
//! tooling and is useful for identifying server stacks, clustering
//! infrastructure, and spotting malware C2 / default deployments.
//!
//! For authorized security testing only.

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::cfg_prompt_port;
use crate::utils::tls_fingerprint::jarm_fingerprint;

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "JARM TLS Server Fingerprint".into(),
        description: "Actively fingerprints a TLS server using the JARM technique: sends 10 \
            crafted TLS ClientHello packets and folds the ServerHello responses into a \
            62-character hash for server-stack identification and infrastructure clustering."
            .into(),
        authors: vec![
            "rustsploit contributors".into(),
            "Salesforce (JARM algorithm, BSD-3-Clause)".into(),
        ],
        references: vec![
            "https://github.com/salesforce/jarm".into(),
            "https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a".into(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
        default_port: Some(443),
    }
}

fn display_banner() {
    if crate::utils::is_batch_mode() {
        return;
    }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   JARM TLS Server Fingerprint                                ║".cyan());
    crate::mprintln!("{}", "║   10-probe active TLS fingerprint (Salesforce JARM)           ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("jarm_scan requires a single-host target")?;

    display_banner();

    let mut outcome = ModuleOutcome::ok();

    let port = cfg_prompt_port("port", "TLS port", 443).await?;
    let timeout = Duration::from_secs(10);

    crate::mprintln!("{}", format!("[*] Target: {}:{}", target, port).cyan());
    crate::mprintln!("{}", "[*] Sending 10 JARM probes...".dimmed());

    // Honour the rate limiter before the network round-trips. The fingerprint
    // opens one connection per probe; gate at the top so mass-scan runs stay
    // within the operator's configured RPS.
    ctx.rate_limit(target).await;

    let report = jarm_fingerprint(target, port, timeout)
        .await
        .with_context(|| format!("JARM fingerprint of {}:{} failed", target, port))?;

    let responsive = report.probes.iter().filter(|p| p.responded()).count();
    let all_zero = report.jarm.chars().all(|c| c == '0');

    if all_zero {
        crate::mprintln!(
            "{}",
            format!("[-] No JARM response from {}:{} (host down, not TLS, or all probes rejected)", target, port)
                .yellow()
        );
        crate::mprintln!("{}", format!("    JARM: {}", report.jarm).dimmed());
    } else {
        crate::mprintln!("{}", format!("[+] JARM: {}", report.jarm).green().bold());
        crate::mprintln!(
            "{}",
            format!("[+] {}/{} probes elicited a ServerHello", responsive, report.probes.len()).green()
        );
        if let Some(ref ja3s) = report.ja3s {
            crate::mprintln!("{}", format!("[+] JA3S: {}", ja3s).green());
        }
    }
    if let Some(ref ja3) = report.client_ja3 {
        crate::mprintln!("{}", format!("[*] Client JA3 (this scan): {}", ja3).dimmed());
    }

    outcome.findings.push(Finding {
        target: format!("{}:{}", target, port),
        kind: FindingKind::Banner,
        message: format!("JARM fingerprint {} ({}:{})", report.jarm, target, port),
        data: Some(serde_json::json!({
            "host": target,
            "port": port,
            "service": "tls",
            "jarm": report.jarm,
            "ja3s": report.ja3s,
            "client_ja3": report.client_ja3,
            "probes_responded": responsive,
            "probes_total": report.probes.len(),
        })),
    });

    crate::events::emit(crate::events::ModuleEvent::ServiceDetected {
        host: target.to_string(),
        port,
        service: "tls".to_string(),
        version: Some(format!("JARM={}", report.jarm)),
    });

    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Scanners, "jarm_scan", native);

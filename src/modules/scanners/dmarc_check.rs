//! DMARC policy detector.
//!
//! Looks up `_dmarc.<domain>` TXT records on a public resolver and reports
//! whether DMARC is missing, set to `p=none` (monitoring only), or properly
//! enforced (`p=quarantine` / `p=reject`). Missing or non-enforcing DMARC
//! is a common finding because it lets attackers spoof email From headers.

use anyhow::{Context, Result};
use colored::*;
use std::net::{IpAddr, SocketAddr};
use tokio::time::{timeout, Duration};

use hickory_client::client::{Client, ClientHandle};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::udp::UdpClientStream;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{CheckResult, ModuleInfo, ModuleRank};
use crate::utils::cfg_prompt_default;

const DNS_TIMEOUT_SECS: u64 = 5;

fn display_banner() {
    if crate::utils::is_batch_mode() {
        return;
    }
    crate::mprintln!(
        "{}",
        "╔══════════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   DMARC Policy Detector                                      ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Flags missing or non-enforcing DMARC records               ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚══════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "DMARC Policy Detector".to_string(),
        description: "Queries _dmarc.<domain> TXT records to determine whether DMARC is missing, \
                      set to p=none (monitoring only), or enforced (p=quarantine / p=reject). \
                      Missing or non-enforcing DMARC enables email spoofing and phishing."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://datatracker.ietf.org/doc/html/rfc7489".to_string(),
            "https://www.dmarc.org/".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

pub async fn check(ctx: &ModuleCtx) -> CheckResult {
    let target = match ctx.target.as_single() {
        Some(t) => t,
        None => return CheckResult::Error("dmarc_check requires a single-host target".to_string()),
    };
    let domain = registrable_domain(&sanitize_host(target));
    match lookup_dmarc(&domain, "1.1.1.1").await {
        Ok(Some(rec)) => {
            let lower = rec.to_ascii_lowercase();
            if lower.contains("p=none") {
                CheckResult::Vulnerable(format!(
                    "DMARC present but policy is p=none (monitoring only): {}",
                    rec
                ))
            } else if lower.contains("p=quarantine") || lower.contains("p=reject") {
                CheckResult::NotVulnerable(format!("DMARC enforced: {}", rec))
            } else {
                CheckResult::Unknown(format!("DMARC record found but policy unclear: {}", rec))
            }
        }
        Ok(None) => CheckResult::Vulnerable(format!(
            "No DMARC TXT record at _dmarc.{} — domain is open to spoofing",
            domain
        )),
        Err(e) => CheckResult::Error(e.to_string()),
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("dmarc_check requires a single-host target")?;
    display_banner();

    let host = sanitize_host(target);
    let domain = registrable_domain(&host);
    let resolver_input =
        cfg_prompt_default("resolver", "Public resolver to query", "1.1.1.1").await?;
    let resolver = resolver_input.trim();

    crate::mprintln!("{}", format!("[*] Domain: {}", domain).cyan());
    crate::mprintln!("{}", format!("[*] Resolver: {}", resolver).cyan());

    let mut outcome = ModuleOutcome::ok();
    ctx.rate_limit(&domain).await;

    match lookup_dmarc(&domain, resolver).await {
        Ok(Some(rec)) => {
            let lower = rec.to_ascii_lowercase();
            if lower.contains("p=none") {
                crate::mprintln!(
                    "{}",
                    format!("[!] DMARC present but p=none (monitoring only): {}", rec)
                        .yellow()
                        .bold()
                );
                outcome.findings.push(Finding {
                    target: domain.clone(),
                    kind: FindingKind::Vulnerable,
                    message: format!("DMARC p=none for {domain} (monitoring only): {rec}"),
                    data: None,
                });
            } else if lower.contains("p=quarantine") || lower.contains("p=reject") {
                crate::mprintln!(
                    "{}",
                    format!("[+] DMARC enforced: {}", rec).green().bold()
                );
            } else {
                crate::mprintln!(
                    "{}",
                    format!("[?] DMARC record found but policy unclear: {}", rec).yellow()
                );
                outcome.findings.push(Finding {
                    target: domain.clone(),
                    kind: FindingKind::Note,
                    message: format!("DMARC record present but policy unclear for {domain}: {rec}"),
                    data: None,
                });
            }
        }
        Ok(None) => {
            crate::mprintln!(
                "{}",
                format!(
                    "[!] No DMARC TXT record at _dmarc.{} — domain is open to spoofing",
                    domain
                )
                .red()
                .bold()
            );
            outcome.findings.push(Finding {
                target: domain.clone(),
                kind: FindingKind::Vulnerable,
                message: format!("No DMARC record at _dmarc.{domain} — open to email spoofing"),
                data: None,
            });
        }
        Err(e) => {
            crate::meprintln!("{}", format!("[!] DMARC lookup failed: {}", e).red());
            outcome.success = false;
        }
    }
    Ok(outcome)
}

async fn lookup_dmarc(domain: &str, resolver: &str) -> Result<Option<String>> {
    let resolver_ip: IpAddr = resolver.parse()?;
    let socket = SocketAddr::new(resolver_ip, 53);
    let stream = UdpClientStream::builder(socket, TokioRuntimeProvider::new()).build();
    let (mut client, bg) = Client::connect(stream).await?;
    tokio::spawn(bg);

    let qname = Name::from_str_relaxed(&format!("_dmarc.{}", domain))?;
    let resp = timeout(
        Duration::from_secs(DNS_TIMEOUT_SECS),
        client.query(qname, DNSClass::IN, RecordType::TXT),
    )
    .await??;
    let (msg, _) = resp.into_parts();
    for rec in msg.answers() {
        let s = format!("{}", rec.data());
        if s.to_ascii_lowercase().contains("v=dmarc1") {
            return Ok(Some(s));
        }
    }
    Ok(None)
}

fn sanitize_host(target: &str) -> String {
    let t = target.trim();
    let t = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t);
    let t = t.split('/').next().unwrap_or(t);
    let t = t.split(':').next().unwrap_or(t);
    t.to_string()
}

fn registrable_domain(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        host.to_string()
    }
}

crate::register_native_module!(crate::module::Category::Scanners, "dmarc_check", native, has_check);

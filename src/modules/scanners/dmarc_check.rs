//! DMARC policy detector.
//!
//! Looks up `_dmarc.<domain>` TXT records on a public resolver and reports
//! whether DMARC is missing, set to `p=none` (monitoring only), or properly
//! enforced (`p=quarantine` / `p=reject`). Missing or non-enforcing DMARC
//! is a common finding because it lets attackers spoof email From headers.

use anyhow::Result;
use colored::*;
use std::net::{IpAddr, SocketAddr};
use tokio::time::{timeout, Duration};

use hickory_client::client::{Client, ClientHandle};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::udp::UdpClientStream;

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

pub async fn check(target: &str) -> CheckResult {
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

pub async fn run(target: &str) -> Result<()> {
    display_banner();

    let host = sanitize_host(target);
    let domain = registrable_domain(&host);
    let resolver_input =
        cfg_prompt_default("resolver", "Public resolver to query", "1.1.1.1").await?;
    let resolver = resolver_input.trim();

    crate::mprintln!("{}", format!("[*] Domain: {}", domain).cyan());
    crate::mprintln!("{}", format!("[*] Resolver: {}", resolver).cyan());

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
                crate::events::emit(crate::events::ModuleEvent::ServiceDetected {
                    host: domain.clone(),
                    port: 53,
                    service: "dmarc-monitor-only".to_string(),
                    version: Some(rec),
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
            crate::events::emit(crate::events::ModuleEvent::ServiceDetected {
                host: domain.clone(),
                port: 53,
                service: "dmarc-missing".to_string(),
                version: None,
            });
        }
        Err(e) => {
            crate::meprintln!("{}", format!("[!] DMARC lookup failed: {}", e).red());
        }
    }
    Ok(())
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

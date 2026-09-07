//! DMARC policy detector.
//!
//! Looks up `_dmarc.<domain>` TXT records on a public resolver and reports
//! whether DMARC is missing, set to `p=none` (monitoring only), or properly
//! enforced (`p=quarantine` / `p=reject`). Missing or non-enforcing DMARC
//! is a common finding because it lets attackers spoof email From headers.

use anyhow::{Context, Result};
use colored::*;
use std::net::{IpAddr, SocketAddr};
use tokio::time::{Duration, timeout};

use hickory_client::client::{Client, ClientHandle};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::udp::UdpClientStream;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::cfg_prompt_default;

const DNS_TIMEOUT_SECS: u64 = 5;

/// Common multi-label public suffixes. Taking "the last two labels" as the
/// registrable domain queries `_dmarc.co.uk` instead of
/// `_dmarc.example.co.uk` for domains under these suffixes, which almost
/// always finds nothing and produces a bogus "no DMARC" finding. When the
/// last two labels form one of these, the registrable domain is the last
/// THREE labels. (A full Public Suffix List needs a crate dependency; this
/// covers the overwhelmingly common cases.)
const MULTI_LABEL_SUFFIXES: &[&str] = &[
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "me.uk",
    "net.uk",
    "ltd.uk",
    "plc.uk",
    "sch.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "id.au",
    "co.nz",
    "net.nz",
    "org.nz",
    "govt.nz",
    "ac.nz",
    "school.nz",
    "co.jp",
    "or.jp",
    "ne.jp",
    "ac.jp",
    "ad.jp",
    "ed.jp",
    "go.jp",
    "gr.jp",
    "lg.jp",
    "co.in",
    "net.in",
    "org.in",
    "gov.in",
    "ac.in",
    "edu.in",
    "res.in",
    "com.br",
    "net.br",
    "org.br",
    "gov.br",
    "edu.br",
    "com.cn",
    "net.cn",
    "org.cn",
    "gov.cn",
    "edu.cn",
    "ac.cn",
    "co.za",
    "net.za",
    "org.za",
    "gov.za",
    "ac.za",
    "web.za",
    "com.mx",
    "org.mx",
    "net.mx",
    "edu.mx",
    "gob.mx",
    "com.tr",
    "net.tr",
    "org.tr",
    "gov.tr",
    "edu.tr",
    "co.kr",
    "or.kr",
    "go.kr",
    "re.kr",
    "pe.kr",
    "com.sg",
    "net.sg",
    "org.sg",
    "gov.sg",
    "edu.sg",
    "per.sg",
    "com.hk",
    "org.hk",
    "net.hk",
    "gov.hk",
    "edu.hk",
    "idv.hk",
    "com.tw",
    "org.tw",
    "net.tw",
    "gov.tw",
    "edu.tw",
    "idv.tw",
    "com.ar",
    "net.ar",
    "org.ar",
    "gov.ar",
    "edu.ar",
    "com.co",
    "net.co",
    "org.co",
    "gov.co",
    "edu.co",
    "co.il",
    "org.il",
    "net.il",
    "gov.il",
    "ac.il",
    "muni.il",
    "co.th",
    "or.th",
    "go.th",
    "ac.th",
    "in.th",
    "com.my",
    "net.my",
    "org.my",
    "gov.my",
    "edu.my",
    "com.ph",
    "net.ph",
    "org.ph",
    "gov.ph",
    "edu.ph",
    "com.vn",
    "net.vn",
    "org.vn",
    "gov.vn",
    "edu.vn",
    "co.id",
    "or.id",
    "web.id",
    "go.id",
    "ac.id",
    "com.pk",
    "net.pk",
    "org.pk",
    "gov.pk",
    "edu.pk",
    "com.ua",
    "net.ua",
    "org.ua",
    "gov.ua",
    "edu.ua",
    "in.ua",
    "com.ng",
    "net.ng",
    "org.ng",
    "gov.ng",
    "edu.ng",
    "com.eg",
    "net.eg",
    "org.eg",
    "gov.eg",
    "edu.eg",
];

/// DMARC candidate domains for `host`, most specific first: the exact host
/// itself, then the registrable (organizational) domain. Per RFC 7489 the
/// policy is looked up at the From domain and, if absent, at the
/// organizational domain — never deeper than that.
fn dmarc_candidates(host: &str) -> Vec<String> {
    let host = host.trim_end_matches('.');
    let mut candidates = vec![host.to_string()];

    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        let last2 = format!(
            "{}.{}",
            parts[parts.len() - 2].to_ascii_lowercase(),
            parts[parts.len() - 1].to_ascii_lowercase()
        );
        let last2_is_public_suffix = MULTI_LABEL_SUFFIXES
            .iter()
            .any(|s| last2.eq_ignore_ascii_case(s));
        if last2_is_public_suffix {
            // e.g. example.co.uk → the naive last-two-labels registrable
            // domain would be `co.uk` (a public suffix), so the organizational
            // domain is the last THREE labels.
            if parts.len() >= 3 {
                candidates.push(format!(
                    "{}.{}.{}",
                    parts[parts.len() - 3],
                    parts[parts.len() - 2],
                    parts[parts.len() - 1]
                ));
            }
        } else {
            // e.g. sub.example.com → example.com (the framework helper's
            // last-two-labels rule is correct for single-label suffixes).
            let two_label = crate::utils::sanitize::registrable_domain(host);
            if two_label != host {
                candidates.push(two_label);
            }
        }
    }
    candidates.dedup();
    candidates
}

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
        default_port: None,
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("dmarc_check requires a single-host target")?;
    display_banner();

    let host = crate::utils::sanitize::sanitize_host(target);
    let candidates = dmarc_candidates(&host);
    let domain = candidates.last().cloned().unwrap_or_else(|| host.clone());
    let resolver_input =
        cfg_prompt_default("resolver", "Public resolver to query", "1.1.1.1").await?;
    let resolver = resolver_input.trim();

    crate::mprintln!("{}", format!("[*] Target host: {}", host).cyan());
    if domain != host {
        crate::mprintln!(
            "{}",
            format!("[*] Organizational domain: {}", domain).cyan()
        );
    }
    crate::mprintln!("{}", format!("[*] Resolver: {}", resolver).cyan());

    let mut outcome = ModuleOutcome::ok();
    ctx.rate_limit(&domain).await;

    // Per RFC 7489, query the exact host first, then the organizational
    // (registrable) domain. The FIRST hit wins; every failed lookup along the
    // way is logged so a resolver failure is never indistinguishable from a
    // missing record.
    let mut lookup_err: Option<anyhow::Error> = None;
    let mut found: Option<String> = None;
    for candidate in &candidates {
        let qname = format!("_dmarc.{}", candidate);
        match lookup_dmarc(&qname, resolver).await {
            Ok(Some(rec)) => {
                crate::mprintln!("{}", format!("[*] DMARC record found at {} ", qname).cyan());
                found = Some(rec);
                break;
            }
            Ok(None) => {
                crate::mprintln!(
                    "{}",
                    format!("[-] No DMARC TXT record at {}", qname).dimmed()
                );
            }
            Err(e) => {
                crate::meprintln!("[!] DMARC lookup at {} failed: {}", qname, e);
                lookup_err.get_or_insert(e);
            }
        }
    }

    if let Some(rec) = found {
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
            crate::mprintln!("{}", format!("[+] DMARC enforced: {}", rec).green().bold());
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
    } else if lookup_err.is_some() {
        // At least one candidate failed to resolve: do NOT report a clean
        // "open to spoofing" verdict on an incomplete lookup — a resolver
        // outage must never be indistinguishable from a missing record.
        outcome.success = false;
        crate::meprintln!("[!] DMARC lookup incomplete (resolver error above) — no verdict");
        outcome.findings.push(Finding {
            target: domain.clone(),
            kind: FindingKind::Note,
            message: format!(
                "DMARC lookup for {domain} was incomplete due to resolver errors — policy undetermined"
            ),
            data: None,
        });
    } else {
        crate::mprintln!(
            "{}",
            format!(
                "[!] No DMARC TXT record at _dmarc.{domain} — domain is open to spoofing",
                domain = domain
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
    Ok(outcome)
}

/// Query `_dmarc.<name>` TXT records on the given resolver. Returns the first
/// record that carries the `v=dmarc1` tag, or None when the name resolved but
/// carries no DMARC record.
async fn lookup_dmarc(qname: &str, resolver: &str) -> Result<Option<String>> {
    let resolver_ip: IpAddr = resolver.parse()?;
    let socket = SocketAddr::new(resolver_ip, 53);
    let stream = UdpClientStream::builder(socket, TokioRuntimeProvider::new()).build();
    let (mut client, bg) = Client::connect(stream).await?;
    tokio::spawn(async {
        if let Err(e) = bg.await {
            tracing::error!("DNS background task failed: {}", e);
        }
    });

    let name = Name::from_str_relaxed(qname.to_string())?;
    let resp = timeout(
        Duration::from_secs(DNS_TIMEOUT_SECS),
        client.query(name, DNSClass::IN, RecordType::TXT),
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

crate::register_native_module!(crate::module::Category::Scanners, "dmarc_check", native);

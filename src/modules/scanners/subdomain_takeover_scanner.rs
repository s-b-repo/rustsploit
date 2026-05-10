//! Subdomain takeover detector (live + dangling).
//!
//! Resolves a host's CNAME chain via UDP DNS, checks the terminal record
//! against a fingerprint table of well-known cloud services, then GETs the
//! URL and scans for service-specific "claim me" body fingerprints. Mirrors
//! the Optus / Canterbury / Playtika SDT chain workflow:
//!   `subfinder | dnsx -cname -resp-only | grep cloudfront/heroku/github.io | httpx`

use anyhow::Result;
use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use colored::*;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;

use hickory_client::client::{Client, ClientHandle};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::udp::UdpClientStream;

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::network::{build_http_client_with, HttpClientOpts};
use crate::utils::{cfg_prompt_default, is_batch_mode};

const DNS_TIMEOUT_SECS: u64 = 5;

/// (provider label, CNAME suffix, body fingerprint that proves dangling/unclaimed)
///
/// Fingerprints are intentionally specific — a generic "404" will produce
/// false positives because almost every cloud provider returns 404s for
/// unmapped hosts. We prefer literal phrases known to appear *only* on the
/// provider's unclaimed-resource page.
const FINGERPRINTS: &[(&str, &str, &str)] = &[
    ("AWS CloudFront",   ".cloudfront.net",       "The request could not be satisfied"),
    ("AWS S3",           ".s3.amazonaws.com",     "<Code>NoSuchBucket</Code>"),
    ("AWS S3 (region)",  ".s3-website",           "<Code>NoSuchBucket</Code>"),
    ("Heroku",           ".herokuapp.com",        "No such app"),
    ("Heroku DNS",       ".herokudns.com",        "No such app"),
    ("GitHub Pages",     ".github.io",            "There isn't a GitHub Pages site here"),
    ("Azure CDN",        ".azureedge.net",        "Resource Not Found"),
    ("Azure Web",        ".azurewebsites.net",    "404 Web Site not found"),
    ("Azure TM",         ".trafficmanager.net",   "Our services aren't available right now"),
    ("Netlify",          ".netlify.app",          "Not Found - Request ID"),
    ("Netlify (legacy)", ".netlify.com",          "Not Found - Request ID"),
    ("WPEngine",         ".wpengine.com",         "The site you were looking for couldn"),
    ("Beanstalk",        ".elasticbeanstalk.com", "Environment is not Found"),
    ("Surge",            ".surge.sh",             "project not found"),
    ("Pantheon",         ".pantheonsite.io",      "The gods are wise"),
    ("Bitbucket",        ".bitbucket.io",         "Repository not found"),
    ("Fastly",           ".fastly.net",           "Fastly error: unknown domain"),
    ("Ghost",            ".ghost.io",             "Domain error"),
    ("Helpjuice",        ".helpjuice.com",        "We could not find what you're looking for"),
    ("Helpscout",        ".helpscoutdocs.com",    "No settings were found for this company"),
    ("Tumblr",           ".tumblr.com",           "Whatever you were looking for doesn't currently exist"),
    ("Shopify",          ".myshopify.com",        "Sorry, this shop is currently unavailable"),
    ("Statuspage",       ".statuspage.io",        "There is no app configured at that hostname"),
    ("Readthedocs",      ".readthedocs.io",       "unknown to Read the Docs"),
    ("Webflow",          ".webflow.io",           "The page you are looking for doesn't exist"),
    ("Cargo",            ".cargocollective.com",  "404 Not Found"),
    ("Squarespace",      ".squarespace.com",      "No Such Account"),
    ("Vercel",           ".vercel.app",           "DEPLOYMENT_NOT_FOUND"),
    ("Zendesk",          ".zendesk.com",          "Help Center Closed"),
];

fn banner() {
    if is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   Subdomain Takeover Detector                                ║".cyan());
    crate::mprintln!("{}", "║   Resolves CNAME → matches provider → checks live fingerprint║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Subdomain Takeover Detector".to_string(),
        description: "Resolves the CNAME chain for a host, identifies the cloud provider, and \
                      probes the live URL for the provider-specific 'unclaimed' fingerprint. \
                      Covers CloudFront, Heroku, GitHub Pages, Azure, Netlify, WPEngine, Surge, \
                      Pantheon, Fastly, Vercel, Shopify, Statuspage, Zendesk, and 18 more."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://github.com/EdOverflow/can-i-take-over-xyz".to_string(),
            "https://0xpatrik.com/subdomain-takeover-basics/".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

fn sanitize_host(target: &str) -> String {
    let t = target.trim();
    let t = t.strip_prefix("https://").or_else(|| t.strip_prefix("http://")).unwrap_or(t);
    let t = t.split('/').next().unwrap_or(t);
    let t = t.split(':').next().unwrap_or(t);
    t.to_string()
}

async fn dns_lookup(name: &str, rtype: RecordType, resolver: &str) -> Result<Vec<String>> {
    let resolver_ip: IpAddr = resolver.parse()?;
    let socket = SocketAddr::new(resolver_ip, 53);
    let stream = UdpClientStream::builder(socket, TokioRuntimeProvider::new()).build();
    let (mut client, bg) = Client::connect(stream).await?;
    tokio::spawn(bg);
    let qname = Name::from_str_relaxed(name)?;
    let resp = timeout(Duration::from_secs(DNS_TIMEOUT_SECS), client.query(qname, DNSClass::IN, rtype)).await??;
    let (msg, _) = resp.into_parts();
    Ok(msg.answers().iter().map(|r| format!("{}", r.data())).collect())
}

async fn resolve_cname_chain(host: &str, resolver: &str) -> Vec<String> {
    let mut chain: Vec<String> = Vec::new();
    let mut current = host.to_string();
    for _ in 0..10 {
        match dns_lookup(&current, RecordType::CNAME, resolver).await {
            Ok(answers) => {
                let next = answers.into_iter()
                    .map(|s| s.trim_end_matches('.').to_string())
                    .find(|s| !s.is_empty() && s != &current);
                match next {
                    Some(n) => { chain.push(n.clone()); current = n; }
                    None => break,
                }
            }
            Err(_) => break,
        }
    }
    chain
}

async fn resolves_to_a(host: &str, resolver: &str) -> bool {
    dns_lookup(host, RecordType::A, resolver).await.map(|v| !v.is_empty()).unwrap_or(false)
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().unwrap_or("");
    banner();
    let mut outcome = ModuleOutcome::ok();

    let host = cfg_prompt_default("host", "Target host (no scheme)", &sanitize_host(target)).await?;
    let resolver = cfg_prompt_default("resolver", "DNS resolver", "1.1.1.1").await?;

    crate::mprintln!("{}", format!("[*] Resolving CNAME chain for {} via {}...", host, resolver).cyan());
    let chain = resolve_cname_chain(&host, &resolver).await;
    if chain.is_empty() {
        crate::mprintln!("{}", "[~] No CNAME records.".dimmed());
    } else {
        for (i, c) in chain.iter().enumerate() {
            crate::mprintln!("    [{}] {}", i, c);
        }
    }

    let terminal = chain.last().cloned().unwrap_or_else(|| host.clone());

    let mut matched_provider: Option<&'static str> = None;
    let mut matched_fp: Option<&'static str> = None;
    for (label, suffix, fp) in FINGERPRINTS {
        if terminal.to_ascii_lowercase().ends_with(&suffix.to_ascii_lowercase()) {
            matched_provider = Some(label);
            matched_fp = Some(fp);
            break;
        }
    }

    if let Some(p) = matched_provider {
        crate::mprintln!("{}", format!("[!] Provider matched: {} (terminal CNAME = {})", p, terminal).yellow());
    } else {
        crate::mprintln!("{}", "[~] Terminal CNAME does not match any known takeover provider.".dimmed());
    }

    let resolves = resolves_to_a(&host, &resolver).await;
    if !resolves && !chain.is_empty() {
        crate::mprintln!("{}", format!(
            "[!!] Host has CNAME but does not resolve to an A record — DANGLING (potential takeover for {})",
            terminal
        ).red().bold());
        outcome.findings.push(Finding {
            target: host.clone(),
            kind: FindingKind::Vulnerable,
            message: format!("Dangling CNAME: {host} -> {terminal} (no A record)"),
            data: None,
        });
    }

    // Follow redirects: cloud providers often 302 to a generic error page that
    // contains the takeover fingerprint. We need that final page.
    let client = build_http_client_with(Duration::from_secs(10), HttpClientOpts {
        follow_redirects: true,
        ..HttpClientOpts::permissive()
    })?;
    for scheme in ["https", "http"] {
        let url = format!("{}://{}/", scheme, host);
        match client.get(&url).send().await {
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                let snippet: String = body.chars().take(200).collect();
                crate::mprintln!("{}", format!("[*] {} status={} body[0..200]={:?}", url, status, snippet).cyan());
                if let Some(fp) = matched_fp
                    && body.contains(fp) {
                        crate::mprintln!("{}", format!(
                            "[!!!] TAKEOVER FINGERPRINT MATCHED on {}: '{}' — register the resource on {} to claim",
                            url, fp, matched_provider.unwrap_or("?")
                        ).red().bold());
                        outcome.findings.push(Finding {
                            target: host.clone(),
                            kind: FindingKind::Vulnerable,
                            message: format!("subdomain takeover candidate: {host} matches {} fingerprint at {url}", matched_provider.unwrap_or("?")),
                            data: None,
                        });
                    }
            }
            Err(e) => {
                crate::mprintln!("{}", format!("[-] {} -> {}", url, e).dimmed());
            }
        }
    }

    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Scanners, "subdomain_takeover_scanner", native);

//! CNAME chain follower (osint).
//!
//! Workflow primitive used 6+ times across Pureplesier / Tasteofcannabis /
//! Reddit (`dig CNAME` is a top-9 sub-pattern). Follows CNAME chains for one
//! host or a file of hosts and tags terminal records that match known cloud
//! providers — feeder for `subdomain_takeover_scanner`.

use anyhow::{anyhow, Result};
use colored::*;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;

use hickory_client::client::{Client, ClientHandle};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::udp::UdpClientStream;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::parallel::{run_buffered, BoxFut};
use crate::utils::{cfg_prompt_default, cfg_prompt_yes_no, is_batch_mode};

const CNAME_CONCURRENCY: usize = 16;

const SUFFIXES: &[(&str, &str)] = &[
    (".cloudfront.net",       "AWS CloudFront"),
    (".s3.amazonaws.com",     "AWS S3"),
    (".s3-website",           "AWS S3 (region)"),
    (".elasticbeanstalk.com", "AWS Beanstalk"),
    (".herokuapp.com",        "Heroku"),
    (".herokudns.com",        "Heroku DNS"),
    (".github.io",            "GitHub Pages"),
    (".azureedge.net",        "Azure CDN"),
    (".azurewebsites.net",    "Azure WebApp"),
    (".trafficmanager.net",   "Azure TM"),
    (".netlify.app",          "Netlify"),
    (".netlify.com",          "Netlify legacy"),
    (".wpengine.com",         "WPEngine"),
    (".surge.sh",             "Surge"),
    (".pantheonsite.io",      "Pantheon"),
    (".bitbucket.io",         "Bitbucket"),
    (".fastly.net",           "Fastly"),
    (".ghost.io",             "Ghost"),
    (".helpjuice.com",        "Helpjuice"),
    (".helpscoutdocs.com",    "Helpscout"),
    (".tumblr.com",           "Tumblr"),
    (".myshopify.com",        "Shopify"),
    (".statuspage.io",        "Statuspage"),
    (".readthedocs.io",       "Readthedocs"),
    (".webflow.io",           "Webflow"),
    (".vercel.app",           "Vercel"),
    (".zendesk.com",          "Zendesk"),
    (".cloudflare.net",       "Cloudflare"),
    (".akamaihd.net",         "Akamai"),
    (".akadns.net",           "Akamai"),
];

const DNS_TIMEOUT_SECS: u64 = 4;

fn banner() {
    if is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   CNAME Chain Follower (OSINT)                               ║".cyan());
    crate::mprintln!("{}", "║   Recursive CNAME → A; tags terminal cloud providers         ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "CNAME Chain Follower".to_string(),
        description: "Recursively follows CNAMEs for a single host (or a newline-separated file \
                      of hosts), tags terminal records that match known cloud providers, and \
                      flags hosts whose CNAME does not resolve to an A record (dangling)."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://datatracker.ietf.org/doc/html/rfc1034#section-3.6.2".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
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

async fn chain_for(host: &str, resolver: &str) -> (Vec<String>, bool) {
    let mut chain = Vec::new();
    let mut current = host.to_string();
    for _ in 0..10 {
        match dns_lookup(&current, RecordType::CNAME, resolver).await {
            Ok(ans) => {
                let next = ans.into_iter().map(|s| s.trim_end_matches('.').to_string()).find(|s| !s.is_empty() && s != &current);
                match next { Some(n) => { chain.push(n.clone()); current = n; } None => break }
            }
            Err(_) => break,
        }
    }
    let resolves = dns_lookup(host, RecordType::A, resolver).await.map(|v| !v.is_empty()).unwrap_or(false);
    (chain, resolves)
}

fn tag_provider(host: &str) -> Option<&'static str> {
    let lh = host.to_ascii_lowercase();
    for (suf, lbl) in SUFFIXES { if lh.ends_with(&suf.to_ascii_lowercase()) { return Some(lbl); } }
    None
}

fn sanitize(t: &str) -> String {
    t.trim().trim_start_matches("https://").trim_start_matches("http://")
        .split('/').next().unwrap_or("").split(':').next().unwrap_or("").to_string()
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().unwrap_or("");
    banner();
    let mut outcome = ModuleOutcome::ok();
    let resolver = cfg_prompt_default("resolver", "DNS resolver", "1.1.1.1").await?;
    let from_file = cfg_prompt_yes_no("from_file", "Treat target as a path to a host list?", false).await?;

    let hosts: Vec<String> = if from_file {
        let raw = std::fs::read_to_string(target)
            .map_err(|e| anyhow!("read {}: {}", target, e))?;
        raw.lines().map(sanitize).filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
    } else {
        vec![sanitize(target)]
    };

    let mut dangling: usize = 0;
    let mut tagged: usize = 0;

    // Resolve up to CNAME_CONCURRENCY hosts in parallel; preserve input order.
    let work: Vec<BoxFut<(String, Vec<String>, bool)>> = hosts.into_iter().map(|host| {
        let resolver = resolver.clone();
        Box::pin(async move {
            let (chain, resolves) = chain_for(&host, &resolver).await;
            (host, chain, resolves)
        }) as _
    }).collect();
    let resolved = run_buffered(work, CNAME_CONCURRENCY).await;

    for (host, chain, resolves) in resolved {
        let terminal = chain.last().cloned().unwrap_or_else(|| host.clone());
        let provider = tag_provider(&terminal);
        let chain_str = if chain.is_empty() { "(none)".to_string() } else { chain.join(" -> ") };

        let dangling_tag = !resolves && !chain.is_empty();
        if dangling_tag { dangling += 1; }
        if provider.is_some() { tagged += 1; }

        let label = match (provider.clone(), dangling_tag) {
            (_, true) => "[!!] DANGLING".red().bold().to_string(),
            (Some(ref p), false) => format!("[!] {}", p).yellow().to_string(),
            (None, false) if chain.is_empty() => "[ ]".dimmed().to_string(),
            (None, false) => "[+]".green().to_string(),
        };
        crate::mprintln!("{} {} -> {} (resolves={})", label, host, chain_str, resolves);
        if dangling_tag {
            outcome.findings.push(Finding {
                target: host.clone(),
                kind: FindingKind::Vulnerable,
                message: format!("Dangling CNAME {host} -> {chain_str} (terminal does not resolve)"),
                data: None,
            });
        } else if let Some(p) = provider {
            outcome.findings.push(Finding {
                target: host.clone(),
                kind: FindingKind::Note,
                message: format!("CNAME {host} -> {chain_str} (provider: {p})"),
                data: None,
            });
        }
    }

    crate::mprintln!();
    crate::mprintln!("{}", "=== Summary ===".bold());
    crate::mprintln!("  dangling CNAMEs: {}", dangling);
    crate::mprintln!("  cloud-tagged:    {}", tagged);
    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Osint, "cname_chain", native);

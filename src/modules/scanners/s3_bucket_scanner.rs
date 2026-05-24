//! AWS S3 bucket exposure scanner.
//!
//! Mirrors the `curl S3 bucket probe` pattern (twilio + reddit findings).
//! Given a bucket name (or candidate hostname), probes:
//!   - `https://<bucket>.s3.amazonaws.com/` — list / AccessDenied
//!   - `https://s3.amazonaws.com/<bucket>/` — alternate path style
//!   - `?list-type=2` — v2 list
//!   - `?acl` — ACL disclosure
//!   - `?policy` — bucket policy disclosure
//!   - `?versioning`, `?logging`, `?location`
//!     Reports public-listing, AccessDenied (exists but locked), and NoSuchBucket
//!     (free for registration in the org's name = takeover opportunity).

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::parallel::{run_buffered, BoxFut};
use crate::utils::{build_http_client, cfg_prompt_default, is_batch_mode};

const S3_CONCURRENCY: usize = 4;

fn banner() {
    if is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   AWS S3 Bucket Exposure Scanner                             ║".cyan());
    crate::mprintln!("{}", "║   Public-list / ACL / policy disclosure / takeover candidate ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "S3 Bucket Exposure Scanner".to_string(),
        description: "Probes an S3 bucket via virtual-hosted and path-style URLs for public \
                      listing, ACL/policy disclosure, and bucket-existence (NoSuchBucket → \
                      registration takeover candidate)."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://hackerone.com/reports/406003".to_string(),
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/RESTAuthentication.html".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
        default_port: None,
    }
}

fn extract_bucket(target: &str) -> String {
    let t = target.trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    if let Some(prefix) = t.strip_suffix(".s3.amazonaws.com") {
        return prefix.to_string();
    }
    if let Some(rest) = t.strip_prefix("s3.amazonaws.com/") {
        return rest.split('/').next().unwrap_or(rest).to_string();
    }
    if let Some((bucket, _)) = t.split_once(".s3.") {
        return bucket.to_string();
    }
    t.split('/').next().unwrap_or(t).to_string()
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("s3_bucket_scanner requires a single-host target")?;
    banner();
    let bucket = cfg_prompt_default("bucket", "S3 bucket name", &extract_bucket(target)).await?;
    let mut outcome = ModuleOutcome::ok();
    ctx.rate_limit(target).await;

    let client = build_http_client(Duration::from_secs(10))?;
    let urls = vec![
        ("vhost",     format!("https://{}.s3.amazonaws.com/", bucket)),
        ("path",      format!("https://s3.amazonaws.com/{}/", bucket)),
        ("v2-list",   format!("https://{}.s3.amazonaws.com/?list-type=2", bucket)),
        ("acl",       format!("https://{}.s3.amazonaws.com/?acl", bucket)),
        ("policy",    format!("https://{}.s3.amazonaws.com/?policy", bucket)),
        ("versioning",format!("https://{}.s3.amazonaws.com/?versioning", bucket)),
        ("logging",   format!("https://{}.s3.amazonaws.com/?logging", bucket)),
        ("location",  format!("https://{}.s3.amazonaws.com/?location", bucket)),
    ];

    // Probe all 8 URLs concurrently (up to S3_CONCURRENCY in flight).
    let work: Vec<BoxFut<(&'static str, String, reqwest::Result<reqwest::Response>)>> =
        urls.into_iter().map(|(label, url)| {
            let client = client.clone();
            Box::pin(async move {
                let resp = client.get(&url).send().await;
                (label, url, resp)
            }) as _
        }).collect();
    let probes = run_buffered(work, S3_CONCURRENCY).await;

    let mut state: &str = "Unknown";
    let mut findings: Vec<String> = Vec::new();

    for (label, url, result) in probes {
        let resp = match result {
            Ok(r) => r,
            Err(e) => { crate::mprintln!("{}", format!("[-] {} -> {}", label, e).dimmed()); continue; }
        };
        let status = resp.status().as_u16();
        let body = match resp.text().await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("Failed to read response body: {}", e);
                String::new()
            }
        };
        let snippet: String = body.chars().take(160).collect();

        if body.contains("<Code>NoSuchBucket</Code>") {
            state = "NoSuchBucket";
            crate::mprintln!("{}", format!("[!] {} {} -> NoSuchBucket (registration-takeover candidate)", label, url).yellow());
            findings.push(format!("Bucket does not exist — registration-takeover candidate via {}", url));
            outcome.findings.push(Finding {
                target: bucket.clone(),
                kind: FindingKind::Vulnerable,
                message: format!("S3 bucket {bucket} returns NoSuchBucket — registration-takeover candidate"),
                data: None,
            });
            break;
        } else if body.contains("<Code>AccessDenied</Code>") {
            state = "AccessDenied";
            crate::mprintln!("{}", format!("[~] {} status={} AccessDenied (bucket exists, listing locked)", label, status).dimmed());
        } else if body.contains("<ListBucketResult") {
            state = "PublicList";
            let key_count = body.matches("<Key>").count();
            crate::mprintln!("{}", format!("[!!] {} status={} PUBLIC LISTING ({} keys visible)", label, status, key_count).red().bold());
            findings.push(format!("Public listing on {} ({} keys)", url, key_count));
            crate::mprintln!("    {}", snippet.dimmed());
            outcome.findings.push(Finding {
                target: bucket.clone(),
                kind: FindingKind::Vulnerable,
                message: format!("S3 bucket {bucket} public-lists {key_count} keys via {url}"),
                data: None,
            });
        } else if body.contains("<AccessControlPolicy>") {
            crate::mprintln!("{}", format!("[!] {} ACL disclosed: {}", label, snippet).yellow());
            findings.push(format!("ACL disclosed via {}", url));
            outcome.findings.push(Finding {
                target: bucket.clone(),
                kind: FindingKind::Note,
                message: format!("S3 bucket {bucket} ACL disclosed via {url}"),
                data: None,
            });
        } else if label == "policy"
            && status == 200
            && (body.contains("\"Statement\"") || body.contains("<PolicyDocument>") || body.contains("\"Effect\""))
        {
            crate::mprintln!("{}", format!("[!] {} policy disclosed: {}", label, snippet).yellow());
            findings.push(format!("Bucket policy disclosed via {}", url));
            outcome.findings.push(Finding {
                target: bucket.clone(),
                kind: FindingKind::Note,
                message: format!("S3 bucket {bucket} policy disclosed via {url}"),
                data: None,
            });
        } else if status < 400 {
            crate::mprintln!("{}", format!("[+] {} status={} :: {}", label, status, snippet).green());
        } else {
            crate::mprintln!("{}", format!("[~] {} status={} :: {}", label, status, snippet).dimmed());
        }
    }

    crate::mprintln!();
    crate::mprintln!("{}", format!("=== Bucket: {} ({}) ===", bucket, state).bold());
    if findings.is_empty() {
        crate::mprintln!("{}", "  No exposure flagged.".green());
    } else {
        for f in &findings {
            crate::mprintln!("{}", format!("  - {}", f).yellow());
        }
    }

    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Scanners, "s3_bucket_scanner", native);

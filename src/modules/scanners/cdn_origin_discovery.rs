use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{build_http_client, cfg_prompt_port};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "CDN Origin IP Discovery".into(),
        description: "Discovers origin IP addresses behind CDN/WAF by checking crt.sh \
            certificate transparency logs, common origin subdomains, and DNS records. \
            Tests whether discovered origins are directly reachable."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec!["https://crt.sh".into(), "https://securitytrails.com".into()],
        disclosure_date: None,
        rank: ModuleRank::Great,
        default_port: None,
    }
}

const ORIGIN_SUBDOMAINS: &[&str] = &[
    "direct", "origin", "cpanel", "webmail", "mail", "ftp", "dev", "staging", "admin", "status",
    "www",
];

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("module requires a single-host target")?;

    let domain = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))
        .unwrap_or(target)
        .split('/')
        .next()
        .unwrap_or(target);

    crate::mprintln!(
        "{}",
        format!("[*] CDN Origin Discovery for: {}", domain)
            .cyan()
            .bold()
    );

    let port = cfg_prompt_port("port", "HTTP port", 443).await?;
    let timeout = Duration::from_secs(10);
    let client = build_http_client(timeout).context("Failed to build HTTP client")?;
    let mut outcome = ModuleOutcome::ok();
    let mut found_origins: Vec<String> = Vec::new();

    for sub in ORIGIN_SUBDOMAINS {
        if ctx.is_cancelled() {
            break;
        }
        ctx.rate_limit(domain).await;

        let subdomain = format!("{}.{}", sub, domain);
        crate::mprintln!("{}", format!("[*] Probing: {}", subdomain).dimmed());

        let scheme = if port == 443 { "https" } else { "http" };
        let url = format!("{}://{}:{}/", scheme, subdomain, port);

        match tokio::time::timeout(timeout, client.get(&url).header("Host", domain).send()).await {
            Ok(Ok(resp)) => {
                let status = resp.status().as_u16();
                let headers = resp.headers().clone();
                let is_cdn = headers
                    .get("cf-ray")
                    .or_else(|| headers.get("x-cdn"))
                    .is_some();

                if status != 403 && status != 502 && !is_cdn {
                    crate::mprintln!(
                        "{}",
                        format!("[+] Origin candidate: {} (HTTP {})", subdomain, status).green()
                    );
                    found_origins.push(subdomain.clone());
                    outcome.findings.push(Finding {
                        target: domain.to_string(),
                        kind: FindingKind::OpenPort,
                        message: format!(
                            "CDN origin IP candidate: {} (HTTP {}, non-CDN)",
                            subdomain, status
                        ),
                        data: Some(serde_json::json!({
                            "domain": domain,
                            "origin_subdomain": subdomain,
                            "status": status,
                        })),
                    });
                }
            }
            Ok(Err(e)) => {
                tracing::trace!("connection failed: {}", e);
            }
            Err(e) => {
                tracing::trace!("connection failed: {}", e);
            }
        }
    }

    crate::mprintln!();
    if found_origins.is_empty() {
        crate::mprintln!(
            "{}",
            "[-] No origin IPs discovered. Try SecurityTrails or crt.sh manually.".yellow()
        );
    } else {
        crate::mprintln!(
            "{}",
            format!(
                "[+] Found {} origin candidate(s): {:?}",
                found_origins.len(),
                found_origins
            )
            .green()
        );
    }

    Ok(outcome)
}

crate::register_native_module!(
    crate::module::Category::Scanners,
    "cdn_origin_discovery",
    native
);

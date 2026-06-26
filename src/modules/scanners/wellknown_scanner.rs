//! `.well-known` discovery scanner.
//!
//! Probes the curated list of `.well-known/*` and root-level discovery
//! endpoints that produced 4 distinct findings across Optus (autodiscover →
//! AWS EC2 IDs, Citrix OIDC), Canterbury, Twilio, etc. Each hit is reported
//! with status, content-type, length, and a short body snippet.

use anyhow::Result;
use anyhow::Context;
use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use colored::*;
use std::time::Duration;

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::parallel::{run_buffered, BoxFut};
use crate::utils::{build_http_client, cfg_prompt_default, is_batch_mode};

const WELLKNOWN_CONCURRENCY: usize = 16;

/// Result from probing a single well-known path: (path, full_url, optional (status, content_type, body)).
type WellknownProbeResult = (&'static str, String, Option<(u16, String, String)>);

const PATHS: &[&str] = &[
    // RFC / standards
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/.well-known/jwks.json",
    "/.well-known/host-meta",
    "/.well-known/host-meta.json",
    "/.well-known/webfinger",
    "/.well-known/change-password",
    "/.well-known/dnt-policy.txt",
    "/.well-known/mta-sts.txt",
    "/.well-known/gpc.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
    "/apple-app-site-association",
    // Discovery / metadata
    "/robots.txt",
    "/sitemap.xml",
    "/humans.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    // Microsoft / Exchange
    "/autodiscover/autodiscover.json",
    "/autodiscover/autodiscover.xml",
    "/owa/auth/logon.aspx",
    "/ews/exchange.asmx",
    // SaaS / dev hints
    "/api-docs",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
    "/openapi.json",
    "/graphql",
    "/graphiql",
    "/.git/config",
    "/.git/HEAD",
    "/.env",
    "/.env.production",
    "/.DS_Store",
    "/server-status",
    "/server-info",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/metrics",
    "/health",
    "/healthz",
    "/readyz",
    "/version",
    "/build-info",
];

fn banner() {
    if is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   .well-known / Discovery Endpoint Scanner                   ║".cyan());
    crate::mprintln!("{}", "║   security.txt, OIDC config, autodiscover, swagger, .env...  ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: ".well-known Discovery".to_string(),
        description: "Probes ~50 common discovery endpoints (security.txt, OIDC config, \
                      autodiscover, swagger, .env, .git, actuator, healthz) and reports \
                      reachable resources with status, content-type, length, and snippet."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml".to_string(),
            "https://datatracker.ietf.org/doc/html/rfc8615".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
        default_port: None,
    }
}

fn url_with_scheme(t: &str) -> String {
    if t.starts_with("http://") || t.starts_with("https://") { t.to_string() }
    else { format!("https://{}", t.trim_end_matches('/')) }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("module requires a single-host target")?;
    banner();
    let mut outcome = ModuleOutcome::ok();
    let base = cfg_prompt_default("url", "Target base URL", &url_with_scheme(target)).await?;
    let base = base.trim_end_matches('/').to_string();

    let client = build_http_client(Duration::from_secs(8))?;

    // Baseline probe: a deliberately nonexistent path. SPAs often return
    // 200 + index.html for everything; if so, we suppress hits whose body
    // matches that baseline so the report isn't drowned in false-positives.
    let baseline_path = "/__rustsploit_nonexistent_8a5d_probe__";
    let baseline_full = format!("{}{}", base, baseline_path);
    let baseline = match client.get(&baseline_full).send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let ct = r.headers().get("content-type")
                .and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
            let body = match crate::utils::network::read_http_body_text_capped(r, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!("Failed to read response body: {}", e);
                    String::new()
                }
            };
            Some((status, ct, body.len()))
        }
        Err(e) => { tracing::debug!("baseline request failed: {e}"); None }
    };
    let spa_fallback = baseline.as_ref().map(|(s, ct, _)| *s < 400 && (ct.contains("text/html") || ct.is_empty())).unwrap_or(false);
    if spa_fallback {
        crate::mprintln!(
            "{}",
            format!("[*] SPA detected: nonexistent path returns {} HTML — suppressing same-shape hits.",
                baseline.as_ref().map(|(s,_,_)| *s).unwrap_or(0)).dimmed()
        );
    }

    // Probe all paths concurrently (up to WELLKNOWN_CONCURRENCY in flight).
    let work: Vec<BoxFut<WellknownProbeResult>> =
        PATHS.iter().copied().map(|path| {
            let client = client.clone();
            let full = format!("{}{}", base, path);
            Box::pin(async move {
                let resp = match client.get(&full).send().await { Ok(r) => r, Err(e) => { tracing::debug!("request failed: {e}"); return (path, full, None); } };
                let status = resp.status().as_u16();
                if status >= 400 { return (path, full, None); }
                let ct = resp.headers().get("content-type")
                    .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                let body = match crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!("Failed to read response body: {}", e);
                        String::new()
                    }
                };
                (path, full, Some((status, ct, body)))
            }) as _
        }).collect();
    let probes = run_buffered(work, WELLKNOWN_CONCURRENCY).await;

    let mut hits: Vec<(String, u16, String, usize)> = Vec::new();

    for (path, full, fetched) in probes {
        let (status, ct, body) = match fetched { Some(v) => v, None => continue };
        let len = body.len();
        if len == 0 { continue; }

        // Suppress SPA-fallback noise: same status, same length within ±5%, HTML body.
        if spa_fallback
            && let Some((bs, _, blen)) = baseline.as_ref() {
                let diff = (len as isize - *blen as isize).unsigned_abs();
                let tolerance = (*blen / 20).max(64);
                if status == *bs && diff <= tolerance &&
                   (ct.to_ascii_lowercase().contains("text/html") || body.trim_start().starts_with('<')) {
                    continue;
                }
            }

        let lower = body.to_ascii_lowercase();
        let interesting = if path.contains(".env") || path.contains(".git") {
            !lower.contains("<html") && !lower.contains("<!doctype")
        } else {
            true
        };
        if !interesting { continue; }

        let snippet: String = body.chars().take(140).collect::<String>()
            .replace(['\n', '\r'], " ");
        let tag = match path {
            "/.git/config" | "/.git/HEAD" | "/.env" | "/.env.production" |
            "/.DS_Store" | "/server-status" | "/actuator/env" =>
                "[!!]".red().bold().to_string(),
            "/.well-known/openid-configuration" |
            "/autodiscover/autodiscover.json" | "/autodiscover/autodiscover.xml" |
            "/.well-known/jwks.json" | "/swagger.json" | "/openapi.json" |
            "/v2/api-docs" | "/swagger/v1/swagger.json" =>
                "[!!]".yellow().bold().to_string(),
            _ => "[+]".green().to_string(),
        };
        crate::mprintln!(
            "{} {} status={} ct='{}' len={} :: {}",
            tag, full, status, ct, len, snippet
        );
        outcome.findings.push(Finding {
            target: target.to_string(),
            kind: FindingKind::Note,
            message: format!("well-known path {full} reachable (status {status}, {len} bytes)"),
            data: None,
        });
        hits.push((full, status, ct, len));
    }

    crate::mprintln!();
    crate::mprintln!("{}", "=== Summary ===".bold());
    crate::mprintln!("  hits: {}", hits.len());

    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Scanners, "wellknown_scanner", native);

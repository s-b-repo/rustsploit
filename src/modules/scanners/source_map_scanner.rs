//! Source-map disclosure scanner.
//!
//! Reproduces the Reddit Devvit (P4 baseline ~$500) and Luno
//! `prod.lunostatic.com` (4-9 MB sourcemap) findings: fetches a target page,
//! pulls every `<script src=...>`, and probes each asset's `.map` companion.
//! Also probes a handful of common bundler conventions (main.*.js.map,
//! vendors~*.js.map) on the same path.

use anyhow::{Result, Context};
use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use colored::*;
use std::collections::BTreeSet;
use std::time::Duration;

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::parallel::{run_buffered, run_buffered_unordered, BoxFut};
use crate::utils::{build_http_client, cfg_prompt_default, is_batch_mode};

const SOURCEMAP_CONCURRENCY: usize = 12;

/// Result from checking a single source-map URL: (status, byte_length, snippet).
type MapProbeResult = (String, Option<(u16, usize, String)>);

fn banner() {
    if is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   JavaScript Source-Map Disclosure Scanner                   ║".cyan());
    crate::mprintln!("{}", "║   Probes <script src> + bundler conventions for .map leaks   ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Source-Map Disclosure Scanner".to_string(),
        description: "Crawls the target HTML for <script src> URLs, then probes each .map \
                      companion to detect exposed JavaScript source-maps that leak original \
                      source code, internal API paths, and embedded secrets."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://hackerone.com/reports/2025-source-map-disclosure".to_string(),
            "https://github.com/denandz/sourcemapper".to_string(),
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

fn extract_script_srcs(html: &str, base: &url::Url) -> Vec<url::Url> {
    let lower = html.to_ascii_lowercase();
    let mut out: BTreeSet<url::Url> = BTreeSet::new();
    let mut cursor = 0usize;
    while let Some(rel) = lower[cursor..].find("<script") {
        let start = cursor + rel;
        let tag_end = match html[start..].find('>') {
            Some(i) => start + i,
            None => break,
        };
        let tag = &html[start..tag_end];
        if let Some(src_pos) = tag.to_ascii_lowercase().find("src=") {
            let after = &tag[src_pos + 4..];
            let src = if let Some(rest) = after.strip_prefix('"') {
                rest.split('"').next().unwrap_or("")
            } else if let Some(rest) = after.strip_prefix('\'') {
                rest.split('\'').next().unwrap_or("")
            } else {
                after.split_ascii_whitespace().next().unwrap_or("")
            };
            if !src.is_empty()
                && let Ok(u) = base.join(src) {
                    out.insert(u);
                }
        }
        cursor = tag_end + 1;
    }
    out.into_iter().collect()
}

const COMMON_BUNDLE_PATHS: &[&str] = &[
    "/static/js/main.js.map",
    "/static/js/bundle.js.map",
    "/static/js/runtime-main.js.map",
    "/dist/main.js.map",
    "/dist/bundle.js.map",
    "/dist/app.js.map",
    "/build/static/js/main.js.map",
    "/_next/static/chunks/main.js.map",
    "/_next/static/chunks/webpack.js.map",
    "/assets/index.js.map",
    "/assets/main.js.map",
    "/js/app.js.map",
    "/js/main.js.map",
    "/js/bundle.js.map",
    "/app.js.map",
    "/main.js.map",
    "/bundle.js.map",
    "/vendor.js.map",
];

/// Probe a candidate sourcemap URL. Only returns Some when the body has
/// the recognizable JSON sourcemap shape — never on plain HTML, since SPAs
/// commonly serve the same index.html for any path and would otherwise
/// flood the report with false positives.
async fn check_map(client: &reqwest::Client, url: &str) -> Option<(u16, usize, String)> {
    // CDNs serving JS assets occasionally 429 under burst load. The probe is
    // best-effort and we'd rather move on than wait minutes on a Retry-After,
    // so use the lenient backoff preset (1 retry, ≤10s cap).
    let r = crate::utils::throttle::with_backoff(
        crate::utils::throttle::BackoffConfig::lenient(),
        url.to_string(),
        || async { client.get(url).send().await },
    )
    .await
    .ok()?;
    let status = r.status().as_u16();
    if status >= 400 { return None; }
    let ct = r.headers().get("content-type")
        .and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    let body = crate::utils::network::read_http_body_text_capped(r, crate::utils::safe_io::DEFAULT_BODY_CAP).await.ok()?;
    let trimmed = body.trim_start();
    let looks_like_map = trimmed.starts_with('{')
        && body.contains("\"version\":")
        && (body.contains("\"sources\"") || body.contains("\"mappings\""));
    let html_fallback = trimmed.starts_with("<!") || trimmed.starts_with("<html") || ct.starts_with("text/html");
    if looks_like_map && !html_fallback {
        let snippet: String = body.chars().take(160).collect();
        Some((status, body.len(), snippet))
    } else {
        None
    }
}

/// Strip query string and fragment from a URL before appending `.map` —
/// otherwise `https://x/main.js?v=1` becomes `https://x/main.js?v=1.map`,
/// which is meaningless to the server.
fn map_url_for(asset: &url::Url) -> String {
    let mut copy = asset.clone();
    copy.set_query(None);
    copy.set_fragment(None);
    format!("{}.map", copy)
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("module requires a single-host target")?;
    banner();
    let mut outcome = ModuleOutcome::ok();
    let url = cfg_prompt_default("url", "Target URL", &url_with_scheme(target)).await?;
    let base = url::Url::parse(&url).context("bad URL")?;

    let client = build_http_client(Duration::from_secs(15))?;

    crate::mprintln!("{}", format!("[*] Fetching {} ...", url).cyan());
    let resp = client.get(&url).send().await.context("fetch")?;
    let html = match crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("Failed to read response body: {}", e);
            String::new()
        }
    };
    let scripts = extract_script_srcs(&html, &base);
    crate::mprintln!("{}", format!("[*] Discovered {} <script src> URLs", scripts.len()).cyan());

    let mut hits: Vec<(String, usize)> = Vec::new();

    // Phase 1: probe each script's companion .map (concurrent fan-out).
    let phase1_work: Vec<BoxFut<MapProbeResult>> =
        scripts.iter().map(|s| {
            let map_url = map_url_for(s);
            let client = client.clone();
            Box::pin(async move {
                let r = check_map(&client, &map_url).await;
                (map_url, r)
            }) as _
        }).collect();
    for (map_url, r) in run_buffered(phase1_work, SOURCEMAP_CONCURRENCY).await {
        if let Some((_status, len, snippet)) = r {
            crate::mprintln!("{}", format!("[+] {} -> {} bytes (valid sourcemap)", map_url, len).green());
            crate::mprintln!("{}", format!("    {}", snippet).dimmed());
            hits.push((map_url, len));
        }
    }

    // Phase 2: probe bundler-convention paths under the origin.
    let origin = format!("{}://{}", base.scheme(), base.host_str().unwrap_or(""));
    crate::mprintln!();
    crate::mprintln!("{}", format!("[*] Probing {} common bundler paths...", COMMON_BUNDLE_PATHS.len()).cyan());
    let phase2_work: Vec<BoxFut<MapProbeResult>> =
        COMMON_BUNDLE_PATHS.iter().map(|path| {
            let full = format!("{}{}", origin, path);
            let client = client.clone();
            Box::pin(async move {
                let r = check_map(&client, &full).await;
                (full, r)
            }) as _
        }).collect();
    // Bundler-convention probes are independent and printed as-they-complete,
    // so prefer completion-order over input-order — operators see hits faster
    // and the final summary sorts hits by URL regardless.
    for (full, r) in run_buffered_unordered(phase2_work, SOURCEMAP_CONCURRENCY).await {
        if let Some((_status, len, _snippet)) = r {
            crate::mprintln!("{}", format!("[+] {} -> {} bytes (valid sourcemap)", full, len).green());
            hits.push((full, len));
        }
    }

    crate::mprintln!();
    crate::mprintln!("{}", "=== Summary ===".bold());
    if hits.is_empty() {
        crate::mprintln!("{}", "  No source-maps found.".green());
    } else {
        let total: usize = hits.iter().map(|(_, l)| *l).sum();
        crate::mprintln!("{}", format!(
            "  {} valid source-map(s), {} bytes total — file each as P4 disclosure",
            hits.len(), total
        ).yellow());
        for (u, l) in hits {
            crate::mprintln!("    - {} ({} bytes)", u, l);
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind: FindingKind::Note,
                message: format!("source-map disclosed at {u} ({l} bytes)"),
                data: None,
            });
        }
    }

    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Scanners, "source_map_scanner", native);

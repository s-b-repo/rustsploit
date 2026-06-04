//! PHP end-of-life detector + Vicidial install probe.
//!
//! Reads the X-Powered-By header from / and a small list of common PHP /
//! Vicidial paths. Reports any PHP major branch that has reached
//! end-of-life (5.x, 7.x), and notes when a Vicidial control panel
//! responds — Vicidial installs frequently pin to legacy PHP and so
//! often cluster with this finding.

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{build_http_client, cfg_prompt_int_range, cfg_prompt_yes_no};

const HTTP_TIMEOUT_SECS: u64 = 8;

const VICIDIAL_PATHS: &[&str] = &[
    "/vicidial/welcome.php",
    "/vicidial/admin.php",
    "/vicidial/AST_VDauto_dial.php",
    "/agc/vicidial.php",
];

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
        "║   PHP EOL + Vicidial Detector                                ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Flags X-Powered-By PHP/4.x/5.x/7.x and Vicidial endpoints  ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚══════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "PHP EOL + Vicidial Detector".to_string(),
        description: "Reads the X-Powered-By header from /, then probes a small list of common \
                      Vicidial paths. Flags PHP major branches that have reached EOL (4.x, 5.x, \
                      7.x — all unsupported as of 2026). Detection only — no exploitation."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://www.php.net/supported-versions.php".to_string(),
            "https://www.cvedetails.com/product/128/PHP-PHP.html".to_string(),
            "https://www.vicidial.org/".to_string(),
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
        .context("php_version_eol requires a single-host target")?;
    display_banner();
    let host = sanitize_host(target);
    crate::mprintln!("{}", format!("[*] Target: {}", host).cyan());

    let mut outcome = ModuleOutcome::ok();

    let timeout_secs = cfg_prompt_int_range(
        "timeout",
        "Per-request HTTP timeout (seconds)",
        HTTP_TIMEOUT_SECS as i64,
        2,
        60,
    )
    .await? as u64;
    let probe_vicidial = cfg_prompt_yes_no(
        "probe_vicidial",
        "Probe common Vicidial paths?",
        true,
    )
    .await?;

    let client = build_http_client(Duration::from_secs(timeout_secs))
        .context("Failed to build HTTP client")?;

    let mut php_seen: Option<(String, String)> = None;
    for scheme in ["https", "http"] {
        let url = format!("{}://{}/", scheme, host);
        ctx.rate_limit(&host).await;
        match client.get(&url).send().await {
            Ok(resp) => {
                if let Some(banner) = resp
                    .headers()
                    .get("x-powered-by")
                    .and_then(|v| v.to_str().ok())
                {
                    php_seen = Some((url.clone(), banner.to_string()));
                    if is_eol_php(banner) {
                        crate::mprintln!(
                            "{}",
                            format!("[!] EOL PHP detected via {}: X-Powered-By: {}", url, banner)
                                .red()
                                .bold()
                        );
                        outcome.findings.push(Finding {
                            target: host.clone(),
                            kind: FindingKind::Vulnerable,
                            message: format!("EOL PHP at {}: {}", url, banner),
                            data: Some(serde_json::json!({
                                "host": host,
                                "url": url,
                                "x_powered_by": banner,
                            })),
                        });
                    } else {
                        crate::mprintln!(
                            "{}",
                            format!("[*] PHP banner on {}: {}", url, banner).cyan()
                        );
                    }
                } else {
                    crate::mprintln!(
                        "{}",
                        format!("[-] No X-Powered-By header on {}", url).dimmed()
                    );
                }
            }
            Err(e) => {
                crate::mprintln!(
                    "{}",
                    format!("[-] {} unreachable: {}", url, redact_err(&e.to_string())).dimmed()
                );
            }
        }
    }

    if php_seen.is_none() {
        crate::mprintln!(
            "{}",
            "[*] No PHP banner observed (server may strip headers or not be PHP)".dimmed()
        );
    }

    if probe_vicidial {
        crate::mprintln!();
        crate::mprintln!("{}", "[*] Probing Vicidial paths...".cyan());
        let mut vicidial_hit = false;
        for path in VICIDIAL_PATHS {
            for scheme in ["http", "https"] {
                let url = format!("{}://{}{}", scheme, host, path);
                ctx.rate_limit(&host).await;
                if let Ok(resp) = client.get(&url).send().await {
                    let status = resp.status();
                    let banner = resp
                        .headers()
                        .get("x-powered-by")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    if !(status.is_success() || status.as_u16() == 401 || status.as_u16() == 302) {
                        continue;
                    }
                    // Read the body so we can require a Vicidial-specific fingerprint.
                    // A bare success/401/302 status is returned by a huge fraction of
                    // ordinary endpoints and is NOT proof of Vicidial.
                    let body = match crate::utils::network::read_http_body_text_capped(resp, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::debug!("body read failed for {}: {}", url, redact_err(&e.to_string()));
                            continue;
                        }
                    };
                    let is_vicidial = is_vicidial_fingerprint(&body);
                    vicidial_hit = true;
                    if is_vicidial {
                        crate::mprintln!(
                            "{}",
                            format!(
                                "[+] Vicidial install confirmed: {} (status={}, X-Powered-By='{}')",
                                url, status, banner
                            )
                            .green()
                            .bold()
                        );
                        outcome.findings.push(Finding {
                            target: host.clone(),
                            kind: FindingKind::Vulnerable,
                            message: format!("Vicidial install confirmed at {} (status {})", url, status),
                            data: Some(serde_json::json!({
                                "host": host,
                                "url": url,
                                "status": status.as_u16(),
                                "x_powered_by": banner,
                                "fingerprint": "vicidial-marker-in-body",
                            })),
                        });
                    } else {
                        crate::mprintln!(
                            "{}",
                            format!(
                                "[*] Vicidial path reachable but unconfirmed: {} (status={}, X-Powered-By='{}')",
                                url, status, banner
                            )
                            .cyan()
                        );
                        outcome.findings.push(Finding {
                            target: host.clone(),
                            kind: FindingKind::Note,
                            message: format!(
                                "Vicidial path {} reachable (status {}) but no Vicidial fingerprint in body; unconfirmed",
                                url, status
                            ),
                            data: Some(serde_json::json!({
                                "host": host,
                                "url": url,
                                "status": status.as_u16(),
                                "x_powered_by": banner,
                            })),
                        });
                    }
                }
            }
        }
        if !vicidial_hit {
            crate::mprintln!(
                "{}",
                "[-] No Vicidial endpoint responded on the probed paths".dimmed()
            );
        }
    }

    Ok(outcome)
}

fn is_eol_php(banner: &str) -> bool {
    if !banner.starts_with("PHP/") {
        return false;
    }
    let rest = banner.trim_start_matches("PHP/");
    rest.starts_with("4.")
        || rest.starts_with("5.")
        || rest.starts_with("7.")
}

/// Returns true only when the response body carries a Vicidial-specific
/// fingerprint. A reachable path / success-or-redirect status alone is NOT
/// sufficient — those are returned by countless unrelated endpoints.
fn is_vicidial_fingerprint(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("vicidial")
        || lower.contains("vicidial.org")
        || lower.contains("vicidial group")
        || lower.contains("astguiclient")
}

fn redact_err(s: &str) -> String {
    s.replace('\n', " ").chars().take(200).collect()
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

crate::register_native_module!(crate::module::Category::Scanners, "php_version_eol", native);

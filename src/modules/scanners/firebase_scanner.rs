//! Firebase Configuration Scanner
//!
//! Probes for exposed Firebase / Google Cloud configurations,
//! real-time database URLs, and storage bucket misconfigurations
//! that leak application secrets and data.
//!
//! Based on common bug bounty findings where Firebase configs are
//! exposed in client-side JavaScript, misconfigured hosting, or
//! inadvertently published debug endpoints.

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::parallel::{BoxFut, run_buffered};
use crate::utils::{build_http_client, cfg_prompt_default, cfg_prompt_yes_no, is_batch_mode};

const FIREBASE_CONCURRENCY: usize = 10;

/// Firebase / Google Cloud paths to probe.
const FIREBASE_PATHS: &[(&str, &str)] = &[
    // Firebase hosting config
    ("firebase.json", "/firebase.json"),
    ("firebase config", "/__/firebase/init.json"),
    ("firebase init", "/__/firebase/init.js"),
    // Google services
    ("google-services.json", "/google-services.json"),
    ("GoogleService-Info.plist", "/GoogleService-Info.plist"),
    // Firebase realtime database
    ("realtime DB .json", "/.json"),
    ("realtime DB config", "/.settings/rules.json"),
    // Firebase storage
    ("storage config", "/__/firebase/storage"),
    // Common debug / dev
    ("debug config", "/__/debug"),
    ("emulator config", "/__/emulator"),
    // Well-known
    ("well-known firebase", "/.well-known/firebase"),
    ("well-known assetlinks", "/.well-known/assetlinks.json"),
    ("apple-app-site", "/apple-app-site-association"),
    (
        "apple-app-site wellknown",
        "/.well-known/apple-app-site-association",
    ),
];

/// Patterns that indicate an exposed Firebase config.
const CONFIG_MARKERS: &[&str] = &[
    "apiKey",
    "authDomain",
    "databaseURL",
    "projectId",
    "storageBucket",
    "messagingSenderId",
    "appId",
    "measurementId",
    "firebase",
];

/// Patterns that indicate exposed Google service account credentials.
const SA_MARKERS: &[&str] = &[
    "type\": \"service_account\"",
    "project_id",
    "private_key_id",
    "private_key",
    "client_email",
    "client_id",
    "auth_uri",
    "token_uri",
];

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
        "║   Firebase / Google Cloud Config Scanner                     ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Discovers exposed Firebase RTDB, storage, and configs      ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚══════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Firebase Config Scanner".to_string(),
        description: "Probes for exposed Firebase / Google Cloud configurations, \
                      real-time database URLs, storage bucket endpoints, and \
                      Google service-account credentials. Detects firebase.json, \
                      google-services.json, Firebase Init configs, and open \
                      Realtime Database instances."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://firebase.google.com/docs/hosting/reserved-urls".to_string(),
            "https://cloud.google.com/docs/authentication".to_string(),
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

/// Check if body content looks like a Firebase config (JSON with Firebase keys).
fn is_firebase_config(body: &str) -> Option<&'static str> {
    let lower = body.to_ascii_lowercase();
    let mut hits = 0u32;
    let mut is_sa = false;

    for marker in CONFIG_MARKERS {
        if lower.contains(&marker.to_ascii_lowercase()) {
            hits += 1;
        }
    }

    for marker in SA_MARKERS {
        if lower.contains(&marker.to_ascii_lowercase()) {
            is_sa = true;
        }
    }

    if is_sa {
        return Some("Google Service Account credentials exposed");
    }

    if hits >= 3 {
        return Some("Firebase configuration exposed");
    }

    if hits >= 1 && (body.trim_start().starts_with('{') || body.trim_start().starts_with("const")) {
        return Some("Possible Firebase/Google config fragment");
    }

    None
}

/// Check if the response body looks like a Firebase Realtime Database response.
fn is_firebase_rtdb(body: &str) -> Option<&'static str> {
    let trimmed = body.trim();
    // Firebase RTDB returns JSON with a root object or null
    if trimmed == "null" {
        return Some("Firebase Realtime Database accessible (empty root)");
    }
    if trimmed.starts_with('{')
        && (trimmed.contains("\"users\"")
            || trimmed.contains("\"data\"")
            || trimmed.contains("\"config\""))
    {
        return Some("Firebase Realtime Database with exposed data");
    }
    if trimmed.starts_with('{') && trimmed.len() > 50 {
        return Some("Possible Firebase Realtime Database response");
    }
    None
}

/// Check if body looks like Firebase storage rules/config.
fn is_storage_config(body: &str) -> Option<&'static str> {
    let lower = body.to_ascii_lowercase();
    if lower.contains("allow read") || lower.contains("allow write") || lower.contains("match /{") {
        return Some("Firebase Storage/Firestore rules exposed");
    }
    None
}

/// Result from probing a single Firebase path.
type ProbeResult = (String, String, Option<(u16, String, String)>);

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("firebase_scanner requires a single-host target")?;
    banner();

    let mut outcome = ModuleOutcome::ok();
    let base = cfg_prompt_default("url", "Target base URL", &url_with_scheme(target)).await?;
    let base = base.trim_end_matches('/').to_string();
    let probe_rtdb = cfg_prompt_yes_no(
        "probe_rtdb",
        "Probe open Firebase Realtime Database URLs?",
        true,
    )
    .await?;
    let timeout_secs: u64 = ctx.options.get_or("timeout", 12u64);

    let client = build_http_client(Duration::from_secs(timeout_secs))?;

    crate::mprintln!("{}", format!("[*] Target: {}", base).cyan());
    crate::mprintln!(
        "{}",
        format!(
            "[*] Probing {} Firebase/Google config paths...",
            FIREBASE_PATHS.len()
        )
        .cyan()
    );
    crate::mprintln!();

    // Phase 1: Probe all Firebase paths concurrently
    let work: Vec<BoxFut<ProbeResult>> = FIREBASE_PATHS
        .iter()
        .map(|(label, path)| {
            let full = format!("{}{}", base, path);
            let client = client.clone();
            let label = label.to_string();
            Box::pin(async move {
                let resp = client.get(&full).send().await;
                match resp {
                    Ok(r) => {
                        let status = r.status().as_u16();
                        if status >= 400 {
                            return (label, full, None);
                        }
                        let ct = r
                            .headers()
                            .get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        let body = crate::utils::network::read_http_body_text_capped(
                            r,
                            crate::utils::safe_io::DEFAULT_BODY_CAP,
                        )
                        .await
                        .unwrap_or_default();
                        (label, full, Some((status, ct, body)))
                    }
                    Err(e) => {
                        tracing::debug!("Firebase probe failed for {}: {e}", full);
                        (label, full, None)
                    }
                }
            }) as _
        })
        .collect();

    let results = run_buffered(work, FIREBASE_CONCURRENCY).await;

    let mut hits: Vec<(String, String, String)> = Vec::new();

    for (label, full, fetched) in results {
        let (status, ct, body) = match fetched {
            Some(v) => v,
            None => continue,
        };
        if body.is_empty() {
            continue;
        }

        // Classify the response
        let mut classified = false;

        if let Some(msg) = is_firebase_config(&body) {
            let sev = if msg.contains("Service Account") {
                "CRITICAL"
            } else {
                "HIGH"
            };
            let colored_sev = match sev {
                "CRITICAL" => sev.red().bold().to_string(),
                _ => sev.yellow().bold().to_string(),
            };
            crate::mprintln!(
                "[{}] {} -> {} status={} ct='{}' len={}",
                colored_sev,
                label,
                full,
                status,
                ct,
                body.len()
            );
            crate::mprintln!("{}", format!("      {}", msg).dimmed());
            hits.push((full.clone(), sev.to_string(), msg.to_string()));
            classified = true;
        }

        if let Some(msg) = is_firebase_rtdb(&body) {
            let sev = if msg.contains("exposed data") {
                "CRITICAL"
            } else {
                "HIGH"
            };
            let colored_sev = match sev {
                "CRITICAL" => sev.red().bold().to_string(),
                _ => sev.yellow().bold().to_string(),
            };
            if !classified {
                crate::mprintln!(
                    "[{}] {} -> {} status={} len={}",
                    colored_sev,
                    label,
                    full,
                    status,
                    body.len()
                );
            }
            crate::mprintln!("{}", format!("      {}", msg).dimmed());
            hits.push((full.clone(), sev.to_string(), msg.to_string()));
            classified = true;
        }

        if let Some(msg) = is_storage_config(&body) {
            let colored_sev = "HIGH".yellow().bold().to_string();
            if !classified {
                crate::mprintln!(
                    "[{}] {} -> {} status={} len={}",
                    colored_sev,
                    label,
                    full,
                    status,
                    body.len()
                );
            }
            crate::mprintln!("{}", format!("      {}", msg).dimmed());
            hits.push((full.clone(), "HIGH".to_string(), msg.to_string()));
            classified = true;
        }

        if !classified && !ct.contains("text/html") && !ct.is_empty() {
            crate::mprintln!(
                "{}",
                format!(
                    "  [+] {} -> {} status={} ct='{}' len={} (unclassified)",
                    label,
                    full,
                    status,
                    ct,
                    body.len()
                )
                .dimmed()
            );
            hits.push((
                full.clone(),
                "LOW".to_string(),
                format!("Unclassified non-HTML response (len={})", body.len()),
            ));
        }
    }

    // Phase 2: If target looks like a Firebase project, probe RTDB directly
    if probe_rtdb {
        // Check if we found any firebase config with a databaseURL or projectId
        for (_, _, msg) in &hits {
            if msg.contains("Firebase configuration") || msg.contains("project") {
                crate::mprintln!();
                crate::mprintln!(
                    "{}",
                    "[*] Phase 2: Checking common Firebase project patterns...".bold()
                );

                // Extract possible project ID from target hostname
                let host = base
                    .strip_prefix("https://")
                    .or_else(|| base.strip_prefix("http://"))
                    .unwrap_or(&base);
                let host = host.split('/').next().unwrap_or(host);
                let host = host.split(':').next().unwrap_or(host);

                // Try common Firebase project ID patterns
                let candidates = vec![
                    host.to_string(),
                    host.replace('.', "-"),
                    host.split('.').next().unwrap_or(host).to_string(),
                ];

                for project_id in &candidates {
                    let rtdb_url =
                        format!("https://{}-default-rtdb.firebaseio.com/.json", project_id);
                    let storage_url = format!(
                        "https://firebasestorage.googleapis.com/v0/b/{}.appspot.com",
                        project_id
                    );

                    ctx.rate_limit(target).await;
                    if let Ok(resp) = client.get(&rtdb_url).send().await {
                        let status = resp.status().as_u16();
                        if status < 400 {
                            let body = crate::utils::network::read_http_body_text_capped(
                                resp,
                                crate::utils::safe_io::DEFAULT_BODY_CAP,
                            )
                            .await
                            .unwrap_or_default();
                            if let Some(msg) = is_firebase_rtdb(&body) {
                                let colored_sev = "CRITICAL".red().bold().to_string();
                                crate::mprintln!(
                                    "[{}] RTDB {} -> {} status={} len={}",
                                    colored_sev,
                                    project_id,
                                    rtdb_url,
                                    status,
                                    body.len()
                                );
                                crate::mprintln!("{}", format!("      {}", msg).dimmed());
                                hits.push((
                                    rtdb_url.clone(),
                                    "CRITICAL".to_string(),
                                    msg.to_string(),
                                ));
                            }
                        }
                    }

                    ctx.rate_limit(target).await;
                    if let Ok(resp) = client.get(&storage_url).send().await {
                        let status = resp.status().as_u16();
                        if status < 400 {
                            crate::mprintln!(
                                "{}",
                                format!(
                                    "  [+] Storage bucket accessible: {} (status={})",
                                    storage_url, status
                                )
                                .yellow()
                            );
                            hits.push((
                                storage_url.clone(),
                                "HIGH".to_string(),
                                "Firebase Storage bucket publicly accessible".to_string(),
                            ));
                        }
                    }
                }
                break;
            }
        }
    }

    // Summary
    crate::mprintln!();
    crate::mprintln!("{}", "=== Firebase Config Scan Results ===".bold());
    crate::mprintln!("  Target: {}", base);

    if hits.is_empty() {
        crate::mprintln!("  {}", "No Firebase or Google Cloud configs found.".green());
    } else {
        let critical = hits.iter().filter(|(_, s, _)| s == "CRITICAL").count();
        let high = hits.iter().filter(|(_, s, _)| s == "HIGH").count();
        crate::mprintln!(
            "{}",
            format!(
                "  {} findings: {} CRITICAL, {} HIGH, {} LOW",
                hits.len(),
                critical,
                high,
                hits.len() - critical - high
            )
            .yellow()
        );

        for (url, severity, msg) in &hits {
            let kind = if severity == "CRITICAL" || severity == "HIGH" {
                FindingKind::Vulnerable
            } else {
                FindingKind::Note
            };
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind,
                message: format!("Firebase exposure at {}: {}", url, msg),
                data: Some(serde_json::json!({
                    "url": url,
                    "severity": severity,
                    "detail": msg,
                })),
            });
        }
    }

    Ok(outcome)
}

crate::register_native_module!(
    crate::module::Category::Scanners,
    "firebase_scanner",
    native
);

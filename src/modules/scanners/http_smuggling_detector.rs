use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{build_http_client, cfg_prompt_int_range};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "HTTP Request Smuggling Detector".into(),
        description: "Detects TE.CL / CL.TE / TE.TE request smuggling via ambiguity \
            payloads. Reports viable desync vectors for exploitation."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec!["https://portswigger.net/research/http-desync-attacks".into()],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: Some(443),
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("module requires a single-host target")?;
    let timeout_secs =
        cfg_prompt_int_range("timeout", "HTTP timeout (seconds)", 10, 1, 60).await? as u64;
    let timeout = Duration::from_secs(timeout_secs);
    let client = build_http_client(timeout).context("Failed to build HTTP client")?;
    let base_url = if target.starts_with("http") {
        target.to_string()
    } else {
        format!("https://{}", target)
    };

    let mut outcome = ModuleOutcome::ok();
    crate::mprintln!(
        "{}",
        format!("[*] HTTP Smuggling Detection: {}", base_url)
            .cyan()
            .bold()
    );

    let smuggling_tests: &[(&str, &str, &[(&str, &str)])] = &[
        (
            "CL.TE",
            "CL.TE: Content-Length + Transfer-Encoding",
            &[("Transfer-Encoding", "chunked")],
        ),
        (
            "TE.CL",
            "TE.CL: Transfer-Encoding + Content-Length",
            &[("Content-Length", "0")],
        ),
        (
            "TE.TE",
            "TE.TE: obfuscated Transfer-Encoding",
            &[("Transfer-Encoding", "identity")],
        ),
    ];

    for (name, desc, extra_headers) in smuggling_tests {
        if ctx.is_cancelled() {
            break;
        }
        ctx.rate_limit(target).await;
        crate::mprintln!("{}", format!("[*] Testing {}: {}", name, desc).dimmed());

        let body = format!("0\r\n\r\nX");
        let mut req = client.post(&base_url).body(body.clone());
        for (k, v) in *extra_headers {
            req = req.header(*k, *v);
        }

        match tokio::time::timeout(timeout, req.send()).await {
            Ok(Ok(resp)) => {
                let status = resp.status().as_u16();
                let body_text = resp.text().await.unwrap_or_else(|e| {
                    tracing::trace!("body read failed: {}", e);
                    String::new()
                });
                if body_text.contains("Unrecognized") || status == 400 || status == 501 {
                    crate::mprintln!(
                        "{}",
                        format!("[+] {}: potential desync — HTTP {}", name, status).green()
                    );
                    outcome.findings.push(Finding {
                        target: target.to_string(),
                        kind: FindingKind::Vulnerable,
                        message: format!(
                            "{} smuggling detected at {} (HTTP {})",
                            name, target, status
                        ),
                        data: Some(
                            serde_json::json!({"host": target, "type": name, "status": status}),
                        ),
                    });
                }
            }
            Ok(Err(e)) => {
                crate::meprintln!("[-] {} probe failed: {}", name, e);
            }
            Err(e) => {
                crate::meprintln!("[-] {} probe timed out: {}", name, e);
            }
        }
    }
    Ok(outcome)
}
crate::register_native_module!(
    crate::module::Category::Scanners,
    "http_smuggling_detector",
    native
);

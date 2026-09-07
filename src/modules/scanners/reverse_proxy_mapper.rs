use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{build_http_client, cfg_prompt_int_range};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Reverse Proxy Host Mapper".into(),
        description: "Tests CDN/reverse proxy Host-header routing to discover which \
            internal hostnames are proxied. Sends requests with various Host values \
            and compares response differences."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec!["https://book.hacktricks.xyz/pentesting-web/host-header-injection".into()],
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
    let timeout = Duration::from_secs(
        cfg_prompt_int_range("timeout", "Timeout (seconds)", 10, 1, 30).await? as u64,
    );
    let client = build_http_client(timeout).context("Failed to build HTTP client")?;
    let base_url = if target.starts_with("http") {
        target.to_string()
    } else {
        format!("https://{}", target)
    };
    let mut outcome = ModuleOutcome::ok();
    let host_values = &[
        "127.0.0.1",
        "localhost",
        "internal",
        "admin",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",
    ];
    let mut baseline_len: Option<usize> = None;
    for host in host_values {
        if ctx.is_cancelled() {
            break;
        }
        ctx.rate_limit(target).await;
        match tokio::time::timeout(timeout, client.get(&base_url).header("Host", *host).send())
            .await
        {
            Ok(Ok(resp)) => {
                let body = resp.text().await.unwrap_or_else(|e| {
                    tracing::trace!("body read failed: {}", e);
                    String::new()
                });
                let len = body.len();
                if let Some(bl) = baseline_len {
                    let diff = if len > bl { len - bl } else { bl - len };
                    if diff > bl / 4 && diff > 100 {
                        crate::mprintln!(
                            "{}",
                            format!(
                                "[+] Host '{}' routes to different backend ({} vs {} bytes)",
                                host, bl, len
                            )
                            .green()
                        );
                        outcome.findings.push(Finding {
                            target: target.to_string(),
                            kind: FindingKind::Note,
                            message: format!(
                                "Reverse proxy routes '{}' to different backend",
                                host
                            ),
                            data: Some(serde_json::json!({"host": target, "routed_host": host})),
                        });
                    }
                } else {
                    baseline_len = Some(len);
                }
            }
            e => {
                tracing::trace!("probe timed out or connection failed: {:?}", e);
            }
        }
    }
    Ok(outcome)
}
crate::register_native_module!(
    crate::module::Category::Scanners,
    "reverse_proxy_mapper",
    native
);

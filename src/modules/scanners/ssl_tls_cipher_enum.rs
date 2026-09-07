use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{build_http_client, cfg_prompt_int_range};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "SSL/TLS Cipher Scan".into(),
        description: "TLS fingerprint and certificate scan using JARM + HTTP probe.".into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec!["https://github.com/salesforce/jarm".into()],
        disclosure_date: None,
        rank: ModuleRank::Great,
        default_port: Some(443),
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("requires single-host target")?;
    let timeout = Duration::from_secs(
        cfg_prompt_int_range("timeout", "Timeout (seconds)", 15, 5, 60).await? as u64,
    );
    let client = build_http_client(timeout).context("build http client")?;
    let mut outcome = ModuleOutcome::ok();

    let base_url = if target.starts_with("http") {
        target.to_string()
    } else {
        format!("https://{}", target)
    };
    let host = base_url
        .strip_prefix("https://")
        .or_else(|| base_url.strip_prefix("http://"))
        .unwrap_or(&target);
    let port = base_url
        .split(':')
        .nth(2)
        .and_then(|p| p.split('/').next())
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(443);

    crate::mprintln!(
        "{}",
        format!("[*] SSL/TLS Scan: {}:{}", host, port).cyan().bold()
    );

    ctx.rate_limit(host).await;
    match tokio::time::timeout(timeout, client.get(&base_url).send()).await {
        Ok(Ok(resp)) => {
            let server = resp
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown");
            crate::mprintln!("{}", format!("[+] Server: {}", server).green());
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind: FindingKind::Banner,
                message: format!("TLS server: {} on {}:{}", server, host, port),
                data: Some(serde_json::json!({"host": host, "port": port, "server": server})),
            });
        }
        _ => {
            crate::meprintln!("[-] HTTPS probe failed");
        }
    }

    // JARM fingerprint
    ctx.rate_limit(host).await;
    match crate::utils::tls_fingerprint::jarm_fingerprint(host, port, timeout).await {
        Ok(jarm) => {
            crate::mprintln!("{}", format!("[+] JARM: {}", jarm.jarm).green());
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind: FindingKind::Banner,
                message: format!("JARM: {} on {}:{}", jarm.jarm, host, port),
                data: Some(serde_json::json!({"host": host, "port": port, "jarm": jarm.jarm})),
            });
        }
        Err(e) => {
            crate::meprintln!("[-] JARM probe: {}", e);
        }
    }

    Ok(outcome)
}
crate::register_native_module!(
    crate::module::Category::Scanners,
    "ssl_tls_cipher_enum",
    native
);

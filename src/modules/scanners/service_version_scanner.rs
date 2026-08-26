use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::cfg_prompt_int_range;

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Service Version Scanner".into(),
        description: "Enhanced service detection with version fingerprinting using \
            Recog banner matching and heuristic version extraction."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec!["https://github.com/rapid7/recog".into()],
        disclosure_date: None,
        rank: ModuleRank::Great,
        default_port: None,
    }
}

const COMMON_SERVICE_PORTS: &[(u16, &str)] = &[
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (80, "http"),
    (110, "pop3"),
    (143, "imap"),
    (443, "https"),
    (993, "imaps"),
    (995, "pop3s"),
    (3306, "mysql"),
    (5432, "postgresql"),
    (6379, "redis"),
    (27017, "mongodb"),
    (8080, "http"),
];

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("module requires a single-host target")?;
    let timeout = Duration::from_secs(
        cfg_prompt_int_range("timeout", "Timeout (seconds)", 5, 1, 15).await? as u64,
    );
    let mut outcome = ModuleOutcome::ok();

    crate::mprintln!(
        "{}",
        format!("[*] Service Version Scanner: {}", target)
            .cyan()
            .bold()
    );

    for (port, service) in COMMON_SERVICE_PORTS {
        if ctx.is_cancelled() {
            break;
        }
        ctx.rate_limit(target).await;

        let addr_str = format!("{}:{}", target, port);
        let socket_addr = match tokio::net::lookup_host(&addr_str).await {
            Ok(mut addrs) => match addrs.next() {
                Some(a) => a,
                None => continue,
            },
            Err(e) => {
                tracing::debug!("DNS resolve '{}' failed: {}", addr_str, e);
                continue;
            }
        };

        match tokio::time::timeout(
            timeout,
            crate::utils::network::tcp_connect_addr(socket_addr, timeout),
        )
        .await
        {
            Ok(Ok(mut stream)) => {
                let mut buf = [0u8; 512];
                use tokio::io::AsyncReadExt;
                match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                        if !banner.is_empty() {
                            let fingerprint = crate::utils::recog::match_banner(service, &banner);
                            let version = if fingerprint.matched {
                                let product = fingerprint.product().unwrap_or(service);
                                let ver = fingerprint.get("service.version").unwrap_or("");
                                format!("{} {}", product, ver).trim().to_string()
                            } else {
                                format!("detected {}", service)
                            };

                            crate::mprintln!(
                                "{}",
                                format!(
                                    "[+] {}:{}/{} — {}",
                                    target,
                                    port,
                                    service,
                                    banner.chars().take(80).collect::<String>()
                                )
                                .green()
                            );
                            outcome.findings.push(Finding {
                                target: target.to_string(), kind: FindingKind::Banner,
                                message: format!("{}:{} {} — {}", target, port, service, version),
                                data: Some(serde_json::json!({"host": target, "port": port, "service": service, "banner": banner})),
                            });
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    Ok(outcome)
}
crate::register_native_module!(
    crate::module::Category::Scanners,
    "service_version_scanner",
    native
);

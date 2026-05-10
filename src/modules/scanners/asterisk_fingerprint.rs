//! Asterisk PBX fingerprint detector.
//!
//! Pulls the HTTPS Server header from the Asterisk built-in HTTP/WS interface
//! (default port 8089) and flags end-of-life branches (≤ 16). Asterisk 13.x
//! reached EOL on 2021-10-24; running it leaves the PBX without security
//! updates and exposes it to a long list of remote DoS / crash CVEs.
//!
//! Only fingerprinting — no exploit traffic is sent.

use anyhow::{Context, Result};
use colored::*;
use std::net::IpAddr;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{CheckResult, ModuleInfo, ModuleRank};
use crate::utils::{cfg_prompt_default, cfg_prompt_int_range, cfg_prompt_port, tcp_port_open};

const HTTP_TIMEOUT_SECS: u64 = 8;
const TCP_PROBE_TIMEOUT_SECS: u64 = 4;

const EOL_MAJOR_PREFIXES: &[&str] = &[
    "/1.", "/10.", "/11.", "/12.", "/13.", "/14.", "/15.", "/16.",
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
        "║   Asterisk PBX Fingerprint                                   ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Identifies version + flags EOL branches (≤ 16)             ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚══════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Asterisk PBX Fingerprint".to_string(),
        description: "Connects to the Asterisk built-in HTTPS interface (default 8089/tcp), reads \
                      the Server header, and flags EOL major branches (1.x through 16.x). \
                      Detection only — no exploit traffic, no DoS vectors."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://www.asterisk.org/downloads/asterisk/all-asterisk-versions/".to_string(),
            "https://www.cvedetails.com/vendor/4528/Asterisk.html".to_string(),
            "https://wiki.asterisk.org/wiki/display/AST/Asterisk+Version+Numbers".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

pub async fn check(ctx: &ModuleCtx) -> CheckResult {
    let target = ctx.target.as_single().unwrap_or("");
    let host = sanitize_host(target);
    let ip = match resolve_first_ip(&host).await {
        Some(ip) => ip,
        None => return CheckResult::Error(format!("Could not resolve {}", host)),
    };
    if !tcp_port_open(ip, 8089, Duration::from_secs(TCP_PROBE_TIMEOUT_SECS)).await {
        return CheckResult::NotVulnerable(format!("{}:8089 closed/filtered", host));
    }
    match fetch_server_header(&host, 8089).await {
        Ok(server) => {
            if !server.to_ascii_lowercase().contains("asterisk") {
                return CheckResult::Unknown(format!(
                    "8089 reachable but Server header is not Asterisk: '{}'",
                    server
                ));
            }
            if is_eol_version(&server) {
                CheckResult::Vulnerable(format!("EOL Asterisk fingerprint: {}", server))
            } else {
                CheckResult::NotVulnerable(format!("Asterisk in supported branch: {}", server))
            }
        }
        Err(e) => CheckResult::Error(e.to_string()),
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().unwrap_or("");
    display_banner();
    let mut outcome = ModuleOutcome::ok();
    let host = sanitize_host(target);

    let asterisk_host_input =
        cfg_prompt_default("asterisk_host", "Asterisk host (blank = use target)", "").await?;
    let host = if asterisk_host_input.trim().is_empty() {
        host
    } else {
        sanitize_host(asterisk_host_input.trim())
    };

    let port = cfg_prompt_port("port", "Asterisk HTTP/WS port", 8089).await?;
    let _timeout_secs = cfg_prompt_int_range(
        "timeout",
        "HTTPS timeout (seconds)",
        HTTP_TIMEOUT_SECS as i64,
        2,
        60,
    )
    .await? as u64;

    crate::mprintln!("{}", format!("[*] Target: {}:{}", host, port).cyan());

    let ip = resolve_first_ip(&host)
        .await
        .with_context(|| format!("Could not resolve {}", host))?;
    if !tcp_port_open(ip, port, Duration::from_secs(TCP_PROBE_TIMEOUT_SECS)).await {
        crate::mprintln!(
            "{}",
            format!("[-] {}:{} closed/filtered", host, port).red()
        );
        return Ok(outcome);
    }
    crate::mprintln!(
        "{}",
        format!("[+] {}:{} reachable; pulling HTTPS banner...", host, port).cyan()
    );

    match fetch_server_header(&host, port).await {
        Ok(server) => {
            let s = server.to_ascii_lowercase();
            if !s.contains("asterisk") {
                crate::mprintln!(
                    "{}",
                    format!(
                        "[?] Server header is not Asterisk: '{}' — port may be reused",
                        server
                    )
                    .yellow()
                );
            } else if is_eol_version(&server) {
                crate::mprintln!(
                    "{}",
                    format!(
                        "[!] EOL Asterisk fingerprint: {} — branch is no longer maintained",
                        server
                    )
                    .red()
                    .bold()
                );
                outcome.findings.push(Finding {
                    target: host.clone(),
                    kind: FindingKind::Vulnerable,
                    message: format!("EOL Asterisk on {host}:{port}: {server}"),
                    data: Some(serde_json::json!({"host": host, "port": port, "service": "asterisk-eol", "banner": server})),
                });
            } else {
                crate::mprintln!(
                    "{}",
                    format!("[+] Asterisk in supported branch: {}", server).green()
                );
                outcome.findings.push(Finding {
                    target: host.clone(),
                    kind: FindingKind::Banner,
                    message: format!("Asterisk on {host}:{port}: {server}"),
                    data: Some(serde_json::json!({"host": host, "port": port, "service": "asterisk", "banner": server})),
                });
            }
        }
        Err(e) => {
            crate::meprintln!("{}", format!("[!] Banner pull failed: {}", e).red());
        }
    }
    Ok(outcome)
}

fn is_eol_version(server: &str) -> bool {
    EOL_MAJOR_PREFIXES.iter().any(|p| server.contains(p))
}

async fn fetch_server_header(host: &str, port: u16) -> Result<String> {
    let opts = crate::utils::network::HttpClientOpts::permissive();
    let client = crate::utils::network::build_http_client_with(
        Duration::from_secs(HTTP_TIMEOUT_SECS),
        opts,
    )
    .context("HTTPS client init failed")?;
    let url = format!("https://{}:{}/", host, port);
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {} failed", url))?;
    Ok(resp
        .headers()
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string())
}

async fn resolve_first_ip(host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    let host_owned = host.to_string();
    tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        let addrs = (host_owned.as_str(), 0u16).to_socket_addrs().ok()?;
        addrs.into_iter().map(|s| s.ip()).next()
    })
    .await
    .ok()
    .flatten()
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

crate::register_native_module!(crate::module::Category::Scanners, "asterisk_fingerprint", native, has_check);

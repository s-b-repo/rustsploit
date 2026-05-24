//! MySQL/MariaDB exposure detector.
//!
//! Connects to TCP/3306 (configurable), reads the initial server-greeting
//! handshake packet and reports the server protocol + version. If the
//! server replies with an ERR packet (often "Host '...' is not allowed to
//! connect"), that still confirms the service is exposed and reachable
//! from the test origin — which is itself a finding.

use anyhow::{Context, Result};
use colored::*;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{CheckResult, ModuleInfo, ModuleRank};
use crate::utils::{cfg_prompt_int_range, cfg_prompt_port, tcp_port_open};

const TCP_TIMEOUT_SECS: u64 = 4;

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
        "║   MySQL / MariaDB Exposure Detector                          ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Reads handshake banner — exposes version & ACL behaviour   ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚══════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "MySQL / MariaDB Exposure Detector".to_string(),
        description: "Connects to TCP/3306 (configurable), reads the server greeting handshake, \
                      and reports the protocol byte + advertised version. If the server replies \
                      with an ERR packet (host not allowed) the banner still confirms exposure. \
                      Detection only — no authentication is attempted."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://dev.mysql.com/doc/internals/en/connection-phase-packets.html".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
        default_port: None,
    }
}

pub async fn check(ctx: &ModuleCtx) -> CheckResult {
    let target = match ctx.target.as_single() {
        Some(t) => t,
        None => return CheckResult::Error("mysql_exposure requires a single-host target".to_string()),
    };
    let host = sanitize_host(target);
    let ip = match resolve_first_ip(&host).await {
        Some(ip) => ip,
        None => return CheckResult::Error(format!("Could not resolve {}", host)),
    };
    if !tcp_port_open(ip, 3306, Duration::from_secs(TCP_TIMEOUT_SECS)).await {
        return CheckResult::NotVulnerable(format!("{}:3306 closed/filtered", host));
    }
    match grab_handshake(ip, 3306).await {
        Ok(banner) => CheckResult::Vulnerable(format!("MySQL/MariaDB exposed: {}", banner)),
        Err(e) => CheckResult::Unknown(format!("3306 reachable but banner read failed: {}", e)),
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("mysql_exposure requires a single-host target")?;
    display_banner();
    let host = sanitize_host(target);

    let port = cfg_prompt_port("port", "MySQL port", 3306).await?;
    let timeout_secs = cfg_prompt_int_range(
        "timeout",
        "TCP timeout (seconds)",
        TCP_TIMEOUT_SECS as i64,
        1,
        30,
    )
    .await? as u64;

    crate::mprintln!("{}", format!("[*] Target: {}:{}", host, port).cyan());

    let mut outcome = ModuleOutcome::ok();
    ctx.rate_limit(&host).await;

    let ip = resolve_first_ip(&host)
        .await
        .with_context(|| format!("Could not resolve {}", host))?;
    if !tcp_port_open(ip, port, Duration::from_secs(timeout_secs)).await {
        crate::mprintln!(
            "{}",
            format!("[-] {}:{} closed/filtered", host, port).red()
        );
        return Ok(outcome);
    }

    match grab_handshake(ip, port).await {
        Ok(banner) => {
            crate::mprintln!(
                "{}",
                format!("[+] MySQL/MariaDB exposed on {}:{} — {}", host, port, banner)
                    .green()
                    .bold()
            );
            outcome.findings.push(Finding {
                target: host.clone(),
                kind: FindingKind::Banner,
                message: format!("MySQL/MariaDB on {host}:{port} — {banner}"),
                data: Some(serde_json::json!({
                    "host": host,
                    "port": port,
                    "service": "mysql",
                    "banner": banner,
                })),
            });
        }
        Err(e) => {
            crate::mprintln!(
                "{}",
                format!("[?] {}:{} reachable but banner read failed: {}", host, port, e).yellow()
            );
        }
    }
    Ok(outcome)
}

async fn grab_handshake(ip: IpAddr, port: u16) -> Result<String> {
    let addr = SocketAddr::new(ip, port);
    let stream = crate::utils::network::tcp_connect_addr(addr, Duration::from_secs(TCP_TIMEOUT_SECS))
        .await
        .context("connect failed")?;
    let mut stream = stream;
    let mut buf = [0u8; 256];
    let n = timeout(Duration::from_secs(TCP_TIMEOUT_SECS), stream.read(&mut buf))
        .await
        .context("read timeout")?
        .context("read failed")?;
    if n < 5 {
        anyhow::bail!("short handshake ({} bytes)", n);
    }
    Ok(parse_mysql_handshake(&buf[..n]))
}

fn parse_mysql_handshake(buf: &[u8]) -> String {
    if buf[4] == 0xff {
        let tail = &buf[buf.len().saturating_sub(96)..];
        let s: String = tail
            .iter()
            .map(|b| if (0x20..=0x7e).contains(b) { *b as char } else { '.' })
            .collect();
        return format!("ERR packet: {}", s.trim());
    }
    let protocol = buf[4];
    let mut end = 5;
    while end < buf.len() && buf[end] != 0 {
        end += 1;
    }
    let version = std::str::from_utf8(&buf[5..end]).unwrap_or("<non-utf8>");
    format!("proto={} version={}", protocol, version)
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

crate::register_native_module!(crate::module::Category::Scanners, "mysql_exposure", native, has_check);

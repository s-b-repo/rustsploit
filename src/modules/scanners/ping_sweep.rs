//! Single-host liveness probe. The scheduler handles target fan-out
//! (CIDR / file / random / multi); this module only probes one host.
//!
//! Probe order: one ICMP echo (via the system `ping` binary so we don't
//! need cap_net_raw), then a TCP connect on a small set of commonly-open
//! ports. Reports a host as up if any probe succeeds.
//!
//! Honours the global `port` option for the TCP probe (falls back to a
//! built-in port list).

use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use colored::*;
use tokio::process::Command;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};

const DEFAULT_TCP_PORTS: &[u16] = &[80, 443, 22, 445, 3389, 8080];
const DEFAULT_ICMP_TIMEOUT_SECS: u64 = 2;
const DEFAULT_TCP_TIMEOUT_MS: u64 = 800;

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "ICMP Ping Sweep".to_string(),
        description: "Single-host liveness probe — ICMP echo, then a small TCP connect \
                      pre-check on common ports. Used as a per-host probe inside the \
                      scheduler's CIDR / random / file fan-out, so the operator gets \
                      the same `up?` answer for one host or a /16 with no extra plumbing."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
        default_port: None,
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("ping_sweep requires a single-host target")?;
    let host = host_only(target);
    let ip: IpAddr = match resolve(&host) {
        Ok(ip) => ip,
        Err(e) => {
            crate::meprintln!("[-] {}: resolve failed: {e:#}", host);
            return Ok(ModuleOutcome::ok());
        }
    };

    let icmp_ok = icmp_probe(&host, DEFAULT_ICMP_TIMEOUT_SECS).await;
    let tcp_ok = if !icmp_ok {
        tcp_fallback(ip).await
    } else {
        true
    };

    if !icmp_ok && !tcp_ok {
        if !crate::utils::is_batch_mode() {
            crate::mprintln!("{}", format!("[-] {}: no response", host).dimmed());
        }
        return Ok(ModuleOutcome::ok());
    }

    let method = if icmp_ok { "ICMP" } else { "TCP" };
    crate::mprintln!(
        "{}",
        format!("[+] {} is up ({})", host, method).green().bold()
    );
    crate::workspace::track_host(&host, None, None).await;
    crate::workspace::add_note(
        &host,
        &format!("[ping_sweep] alive via {}", method),
    )
    .await;

    let mut outcome = ModuleOutcome::ok();
    outcome.findings.push(Finding {
        target: host.clone(),
        kind: FindingKind::Note,
        message: format!("{} is up (via {})", host, method),
        data: Some(serde_json::json!({
            "method": method,
            "ip": ip.to_string(),
        })),
    });
    Ok(outcome)
}

fn host_only(target: &str) -> String {
    if let Some(stripped) = target.strip_prefix('[')
        && let Some(end) = stripped.find(']') {
            return stripped[..end].to_string();
        }
    if let Some((before, after)) = target.rsplit_once(':')
        && after.chars().all(|c| c.is_ascii_digit()) {
            return before.to_string();
        }
    target.to_string()
}

fn resolve(host: &str) -> Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let lookup = format!("{}:0", host);
    let mut addrs = lookup
        .to_socket_addrs()
        .with_context(|| format!("DNS lookup failed for '{}'", host))?;
    addrs
        .next()
        .map(|a| a.ip())
        .ok_or_else(|| anyhow!("no addresses returned for '{}'", host))
}

async fn icmp_probe(host: &str, timeout_secs: u64) -> bool {
    #[cfg(target_os = "linux")]
    let timeout_str = timeout_secs.to_string();
    #[cfg(target_os = "linux")]
    let args = vec!["-c", "1", "-W", timeout_str.as_str(), host];

    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    let timeout_str = timeout_secs.to_string();
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    let args = vec!["-c", "1", "-t", timeout_str.as_str(), host];

    #[cfg(target_os = "windows")]
    let timeout_str = (timeout_secs * 1000).to_string();
    #[cfg(target_os = "windows")]
    let args = vec!["-n", "1", "-w", timeout_str.as_str(), host];

    let result = tokio::time::timeout(
        Duration::from_secs(timeout_secs + 1),
        Command::new("ping").args(&args).output(),
    )
    .await;
    match result {
        Ok(Ok(out)) => out.status.success(),
        _ => false,
    }
}

async fn tcp_fallback(ip: IpAddr) -> bool {
    let mut ports: Vec<u16> = Vec::with_capacity(DEFAULT_TCP_PORTS.len() + 1);
    if let Some(p) = crate::tenant::resolve()
        .global_options()
        .try_get("port")
        .and_then(|v| v.parse::<u16>().ok())
    {
        ports.push(p);
    }
    for &p in DEFAULT_TCP_PORTS {
        if !ports.contains(&p) {
            ports.push(p);
        }
    }

    let timeout = Duration::from_millis(DEFAULT_TCP_TIMEOUT_MS);
    for port in ports {
        if crate::utils::tcp_port_open(ip, port, timeout).await {
            return true;
        }
    }
    false
}

crate::register_native_module!(crate::module::Category::Scanners, "ping_sweep", native);

//! IUSB virtual-media protocol probe.
//!
//! Many BMC firmwares (AMI-derived, used by multiple server-vendor brands)
//! expose a Virtual Media service on a small range of TCP ports — typically
//! 5120/5123/5124/5126/5127 — that speaks a custom binary protocol whose
//! handshake begins with the ASCII magic `IUSB` followed by four spaces and
//! four NUL bytes (`49 55 53 42 20 20 20 20 00 00 00 00`).
//!
//! The service answers either in plaintext or wrapped in TLS depending on
//! configuration. A reachable IUSB endpoint is high-impact: paired with
//! valid BMC credentials (or a credential-disclosure flaw elsewhere) it
//! lets an attacker mount a remote ISO and reinstall the host OS or boot
//! arbitrary code with the privileges of the physical operator.
//!
//! This module probes a configurable list of ports per target, attempts the
//! magic handshake in plaintext first, then re-tries each port over TLS
//! (with cert verification disabled), and reports which ports speak the
//! protocol. The check is non-destructive — we only send the 12-byte
//! handshake and read the reply.
//!
//! FOR AUTHORIZED TESTING ONLY.

use anyhow::{anyhow, Result};
use colored::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::module_info::{CheckResult, ModuleInfo, ModuleRank};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_int_range, cfg_prompt_yes_no,
    is_mass_scan_target, run_mass_scan, MassScanConfig,
};

const DEFAULT_PORTS: &[u16] = &[5120, 5123, 5124, 5126, 5127];
const HANDSHAKE: &[u8] = b"IUSB\x20\x20\x20\x20\x00\x00\x00\x00";
const PROBE_TIMEOUT_MS: u64 = 5_000;

fn display_banner() {
    if crate::utils::is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   IUSB Virtual-Media Protocol Probe                          ║".cyan());
    crate::mprintln!("{}", "║   Detects BMC virtual-media services on 5120/5123/5124/...   ║".cyan());
    crate::mprintln!("{}", "║   Plaintext + TLS handshake, reports each speaking port      ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "IUSB Virtual-Media Protocol Probe".to_string(),
        description: "Probes a BMC for a reachable IUSB virtual-media service by sending the \
                      12-byte protocol handshake (ASCII 'IUSB' + 4 spaces + 4 NUL) to ports \
                      5120/5123/5124/5126/5127 in plaintext, then over TLS. Reports each port \
                      whose reply echoes the IUSB magic — those ports accept remote ISO mounts \
                      with valid BMC credentials, which paired with credential-leak or default-\
                      password issues is a full host-OS compromise vector."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://www.dmtf.org/standards/redfish".to_string(),
            "https://www.ami.com/products/server-management/megarac-sp/".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Great,
    }
}

pub async fn check(target: &str) -> CheckResult {
    let host = sanitize_host(target);
    for &port in DEFAULT_PORTS {
        if probe_one(&host, port, false).await.unwrap_or(false) {
            return CheckResult::Vulnerable(format!("IUSB virtual-media accepted on {}:{} (plaintext)", host, port));
        }
        if probe_one(&host, port, true).await.unwrap_or(false) {
            return CheckResult::Vulnerable(format!("IUSB virtual-media accepted on {}:{} (TLS)", host, port));
        }
    }
    CheckResult::NotVulnerable("No IUSB-speaking port among the default set".into())
}

pub async fn run(target: &str) -> Result<()> {
    if is_mass_scan_target(target) {
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "IUSB Virtual-Media",
            default_port: 5124,
            state_file: "iusb_virtualmedia_mass_state.log",
            default_output: "iusb_virtualmedia_mass_results.txt",
            default_concurrency: 200,
        }, |ip, port| async move {
            let host = ip.to_string();
            if probe_one(&host, port, false).await.unwrap_or(false) {
                Some(format!("{}:{} IUSB plaintext\n", host, port))
            } else if probe_one(&host, port, true).await.unwrap_or(false) {
                Some(format!("{}:{} IUSB TLS\n", host, port))
            } else {
                None
            }
        }).await;
    }

    display_banner();
    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());

    let port_input = cfg_prompt_default(
        "ports",
        "Ports to probe (comma-separated)",
        &DEFAULT_PORTS.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","),
    ).await?;
    let ports: Vec<u16> = port_input.split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    if ports.is_empty() {
        return Err(anyhow!("No valid ports parsed from '{}'", port_input));
    }

    let try_tls = cfg_prompt_yes_no("try_tls", "Also try TLS-wrapped handshake?", true).await?;
    let timeout_ms = cfg_prompt_int_range("timeout_ms", "Per-port timeout (ms)", PROBE_TIMEOUT_MS as i64, 500, 30_000).await? as u64;

    let host = sanitize_host(target);
    let mut hits = 0usize;

    for port in ports {
        crate::mprint!("{}", format!("[*] {}:{} ", host, port).cyan());
        match probe_one_with_timeout(&host, port, false, timeout_ms).await {
            Ok(true) => {
                hits += 1;
                crate::mprintln!("{}", "→ IUSB (plaintext) ✓".green().bold());
                continue;
            }
            Ok(false) => {
                if try_tls {
                    match probe_one_with_timeout(&host, port, true, timeout_ms).await {
                        Ok(true) => {
                            hits += 1;
                            crate::mprintln!("{}", "→ IUSB (TLS) ✓".green().bold());
                        }
                        Ok(false) => crate::mprintln!("{}", "→ no IUSB reply".dimmed()),
                        Err(e) => crate::mprintln!("{}", format!("→ TLS error: {}", e).dimmed()),
                    }
                } else {
                    crate::mprintln!("{}", "→ no plaintext IUSB reply".dimmed());
                }
            }
            Err(e) => crate::mprintln!("{}", format!("→ error: {}", e).dimmed()),
        }
    }

    crate::mprintln!();
    if hits > 0 {
        crate::mprintln!("{}", format!("[!] {} IUSB-speaking port(s) — virtual-media is reachable.", hits).red().bold());
        crate::mprintln!("{}", "    Pair with valid BMC credentials to mount a remote ISO.".yellow());
    } else {
        crate::mprintln!("{}", "[*] No IUSB-speaking ports detected.".cyan());
    }

    Ok(())
}

async fn probe_one(host: &str, port: u16, tls: bool) -> Result<bool> {
    probe_one_with_timeout(host, port, tls, PROBE_TIMEOUT_MS).await
}

async fn probe_one_with_timeout(host: &str, port: u16, tls: bool, timeout_ms: u64) -> Result<bool> {
    let timeout = Duration::from_millis(timeout_ms);
    let addr = format!("{}:{}", host, port);

    if tls {
        // TLS path — use the project's vendored dangerous-cert connector
        // (BMCs ship self-signed certs whose CN never matches the IP).
        use tokio_rustls::rustls::pki_types::ServerName;
        let stream = match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(anyhow!(e)),
            Err(_) => return Err(anyhow!("TCP connect timed out")),
        };
        let connector = crate::native::async_tls::make_dangerous_tls_connector();
        // ServerName::try_from will fail for bare IP literals on some rustls
        // versions — fall back to a plain "localhost" sentinel since we
        // disabled cert verification anyway.
        let server_name = ServerName::try_from(host.to_string())
            .or_else(|_| ServerName::try_from("localhost".to_string()))
            .map_err(|e| anyhow!("ServerName: {}", e))?;
        let mut tls_stream = match tokio::time::timeout(timeout, connector.connect(server_name, stream)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(anyhow!(e)),
            Err(_) => return Err(anyhow!("TLS handshake timed out")),
        };
        match tokio::time::timeout(timeout, tls_stream.write_all(HANDSHAKE)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(anyhow!(e)),
            Err(_) => return Err(anyhow!("write timed out")),
        }
        let mut buf = [0u8; 64];
        match tokio::time::timeout(timeout, tls_stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => Ok(buf[..n].windows(4).any(|w| w == b"IUSB")),
            Ok(Ok(_)) => Ok(false),
            Ok(Err(_)) => Ok(false),
            Err(_) => Ok(false),
        }
    } else {
        let mut sock = match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(anyhow!(e)),
            Err(_) => return Err(anyhow!("TCP connect timed out")),
        };
        match tokio::time::timeout(timeout, sock.write_all(HANDSHAKE)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(anyhow!(e)),
            Err(_) => return Err(anyhow!("write timed out")),
        }
        let mut buf = [0u8; 64];
        match tokio::time::timeout(timeout, sock.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => Ok(buf[..n].windows(4).any(|w| w == b"IUSB")),
            Ok(Ok(_)) => Ok(false),
            Ok(Err(_)) => Ok(false),
            Err(_) => Ok(false),
        }
    }
}

fn sanitize_host(target: &str) -> String {
    let mut t = target.trim().to_string();
    for prefix in &["https://", "http://"] {
        if let Some(stripped) = t.strip_prefix(prefix) {
            t = stripped.to_string();
            break;
        }
    }
    if let Some(slash) = t.find('/') { t.truncate(slash); }
    if let Some(colon) = t.find(':') { t.truncate(colon); }
    t
}

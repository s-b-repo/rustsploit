//! Open Proxy Scanner
//!
//! Detects open HTTP CONNECT, SOCKS4, SOCKS5, and HTTP transparent proxies.
//! Supports single-target, subnet, and mass scan modes.
//!
//! FOR AUTHORIZED SECURITY TESTING ONLY.

use anyhow::{anyhow, Result};
use colored::*;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

use crate::utils::cfg_prompt_default;
use crate::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};

const DEFAULT_PORTS: &str = "8080,3128,1080,8888,9050,80,3129,8118";
const CONNECT_HOST: &str = "httpbin.org";
const CONNECT_IP: [u8; 4] = [54, 147, 74, 89]; // httpbin.org fallback IP

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "Open Proxy Scanner".to_string(),
        description: "Scans for open proxy servers: HTTP CONNECT, SOCKS4, SOCKS5, and HTTP transparent. Identifies proxies that can be used for traffic relay without authentication.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

// ============================================================================
// PROXY DETECTION
// ============================================================================

#[derive(Debug, Clone)]
struct ProxyHit {
    port: u16,
    kind: &'static str,
    detail: String,
}

/// Check for HTTP CONNECT proxy.
async fn check_http_connect(ip: IpAddr, port: u16, dur: Duration) -> Option<ProxyHit> {
    let addr = format!("{}:{}", ip, port);
    let mut stream = crate::utils::network::tcp_connect(&addr, dur).await.ok()?;
    let req = format!("CONNECT {}:80 HTTP/1.1\r\nHost: {}\r\n\r\n", CONNECT_HOST, CONNECT_HOST);
    timeout(dur, stream.write_all(req.as_bytes())).await.ok()?.ok()?;
    let mut buf = [0u8; 1024];
    let n = timeout(dur, stream.read(&mut buf)).await.ok()?.ok()?;
    let resp = String::from_utf8_lossy(&buf[..n]);
    if resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200") {
        Some(ProxyHit { port, kind: "HTTP CONNECT", detail: "tunnel established".to_string() })
    } else if resp.starts_with("HTTP/") && resp.contains("407") {
        Some(ProxyHit { port, kind: "HTTP CONNECT (auth required)", detail: "proxy requires authentication".to_string() })
    } else {
        None
    }
}

/// Check for SOCKS5 proxy (no auth).
async fn check_socks5(ip: IpAddr, port: u16, dur: Duration) -> Option<ProxyHit> {
    let addr = format!("{}:{}", ip, port);
    let mut stream = crate::utils::network::tcp_connect(&addr, dur).await.ok()?;
    // Greeting: version 5, 2 methods (no-auth + user/pass)
    timeout(dur, stream.write_all(&[0x05, 0x02, 0x00, 0x02])).await.ok()?.ok()?;
    let mut buf = [0u8; 2];
    timeout(dur, stream.read_exact(&mut buf)).await.ok()?.ok()?;
    if buf[0] != 0x05 { return None; }
    match buf[1] {
        0x00 => Some(ProxyHit { port, kind: "SOCKS5", detail: "open, no auth required".to_string() }),
        0x02 => Some(ProxyHit { port, kind: "SOCKS5 (auth required)", detail: "accepts user/pass auth".to_string() }),
        _ => None,
    }
}

/// Check for SOCKS4 proxy.
async fn check_socks4(ip: IpAddr, port: u16, dur: Duration) -> Option<ProxyHit> {
    let addr = format!("{}:{}", ip, port);
    let mut stream = crate::utils::network::tcp_connect(&addr, dur).await.ok()?;
    // SOCKS4 CONNECT to httpbin.org:80
    let mut pkt = vec![0x04u8, 0x01, 0x00, 0x50]; // version, connect, port 80
    pkt.extend_from_slice(&CONNECT_IP);
    pkt.push(0x00); // null-terminated userid
    timeout(dur, stream.write_all(&pkt)).await.ok()?.ok()?;
    let mut buf = [0u8; 8];
    let n = timeout(dur, stream.read(&mut buf)).await.ok()?.ok()?;
    if n >= 2 && buf[1] == 0x5A {
        Some(ProxyHit { port, kind: "SOCKS4", detail: "request granted".to_string() })
    } else if n >= 2 && buf[1] == 0x5B {
        Some(ProxyHit { port, kind: "SOCKS4 (rejected)", detail: "request rejected".to_string() })
    } else {
        None
    }
}

/// Check for HTTP transparent/forward proxy.
async fn check_http_forward(ip: IpAddr, port: u16, dur: Duration) -> Option<ProxyHit> {
    let addr = format!("{}:{}", ip, port);
    let mut stream = crate::utils::network::tcp_connect(&addr, dur).await.ok()?;
    let req = format!(
        "GET http://{}/ip HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        CONNECT_HOST, CONNECT_HOST
    );
    timeout(dur, stream.write_all(req.as_bytes())).await.ok()?.ok()?;
    let mut buf = [0u8; 2048];
    let n = timeout(dur, stream.read(&mut buf)).await.ok()?.ok()?;
    let resp = String::from_utf8_lossy(&buf[..n]);
    if resp.starts_with("HTTP/") && resp.contains("200") && resp.contains("origin") {
        Some(ProxyHit { port, kind: "HTTP Forward", detail: "transparent proxy (forwards requests)".to_string() })
    } else {
        None
    }
}

/// Probe all proxy types on a single port.
async fn probe_port(ip: IpAddr, port: u16, dur: Duration) -> Vec<ProxyHit> {
    let mut hits = Vec::new();
    // Try SOCKS5 first (fastest detection)
    if let Some(h) = check_socks5(ip, port, dur).await { hits.push(h); return hits; }
    // SOCKS4
    if let Some(h) = check_socks4(ip, port, dur).await { hits.push(h); return hits; }
    // HTTP CONNECT
    if let Some(h) = check_http_connect(ip, port, dur).await { hits.push(h); return hits; }
    // HTTP Forward
    if let Some(h) = check_http_forward(ip, port, dur).await { hits.push(h); return hits; }
    hits
}

// ============================================================================
// MAIN
// ============================================================================

fn display_banner() {
    if crate::utils::is_batch_mode() { return; }
    crate::mprintln!("{}", "+=================================================================+".cyan());
    crate::mprintln!("{}", "|              Open Proxy Scanner                                 |".cyan());
    crate::mprintln!("{}", "|   HTTP CONNECT | SOCKS4 | SOCKS5 | HTTP Forward                |".cyan());
    crate::mprintln!("{}", "+=================================================================+".cyan());
    crate::mprintln!();
}

pub async fn run(target: &str) -> Result<()> {
    // --- Mass scan ---
    if is_mass_scan_target(target) {
        let ports_input = cfg_prompt_default("ports", "Ports to scan", DEFAULT_PORTS).await?;
        let ports = parse_ports(&ports_input);
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "ProxyScan",
            default_port: 8080,
            state_file: "proxy_scan_mass_state.log",
            default_output: "proxy_scan_mass_results.txt",
            default_concurrency: 500,
        }, move |ip: IpAddr, _port: u16| {
            let ports = ports.clone();
            async move {
                let dur = Duration::from_secs(5);
                let mut lines = Vec::new();
                for &p in &ports {
                    let hits = probe_port(ip, p, dur).await;
                    for h in hits {
                        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                        lines.push(format!("[{}] {}:{} {} ({})", ts, ip, h.port, h.kind, h.detail));
                        crate::mprintln!("\r{}", format!("[+] {}:{} {} — {}", ip, h.port, h.kind, h.detail).green().bold());
                    }
                }
                if lines.is_empty() { None } else { Some(lines.join("\n") + "\n") }
            }
        }).await;
    }

    // --- Single target ---
    display_banner();

    let ports_input = cfg_prompt_default("ports", "Ports to scan", DEFAULT_PORTS).await?;
    let ports = parse_ports(&ports_input);
    let timeout_ms: u64 = cfg_prompt_default("timeout", "Timeout (ms)", "5000").await?.parse().unwrap_or(5000);
    let dur = Duration::from_millis(timeout_ms);
    let verbose = !crate::utils::is_batch_mode();

    if verbose {
        crate::mprintln!("[*] Target: {}", target.yellow());
        crate::mprintln!("[*] Ports: {:?}", ports);
        crate::mprintln!("[*] Timeout: {}ms", timeout_ms);
        crate::mprintln!();
    }

    let ip: IpAddr = resolve_target(target)?;
    let mut found = Vec::new();

    for &port in &ports {
        if verbose {
            crate::mprintln!("[*] Probing {}:{}...", ip, port);
        }
        let hits = probe_port(ip, port, dur).await;
        if hits.is_empty() && verbose {
            crate::mprintln!("  {}", format!("[-] {}:{} — no proxy detected", ip, port).dimmed());
        }
        for h in &hits {
            crate::mprintln!("  {}", format!("[+] {}:{} — {} ({})", ip, h.port, h.kind, h.detail).green().bold());
        }
        found.extend(hits);
    }

    if verbose {
        crate::mprintln!();
        if found.is_empty() {
            crate::mprintln!("{}", "[-] No open proxies found.".yellow());
        } else {
            crate::mprintln!("{}", format!("[+] {} proxy(ies) found:", found.len()).green().bold());
            crate::mprintln!();
            crate::mprintln!("  {:<8} {:<25} {}", "Port".bold(), "Type".bold(), "Detail".bold());
            crate::mprintln!("  {}", "-".repeat(60).dimmed());
            for h in &found {
                crate::mprintln!("  {:<8} {:<25} {}", h.port, h.kind.green(), h.detail);
            }
        }
        crate::mprintln!();
    }
    Ok(())
}

fn parse_ports(input: &str) -> Vec<u16> {
    input.split(',')
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .filter(|&p| p > 0)
        .collect()
}

fn resolve_target(target: &str) -> Result<IpAddr> {
    target.parse::<IpAddr>().or_else(|_| {
        use std::net::ToSocketAddrs;
        format!("{}:0", target).to_socket_addrs()
            .map_err(|e| anyhow!("Cannot resolve {}: {}", target, e))?
            .next()
            .map(|sa| sa.ip())
            .ok_or_else(|| anyhow!("No addresses for {}", target))
    })
}

//! Banner Grabber Scanner
//!
//! Grabs service banners from open ports to identify software versions
//! and potential vulnerabilities. Supports multi-port scanning with
//! protocol-specific probes.
//!
//! FOR AUTHORIZED SECURITY TESTING ONLY.

use anyhow::{anyhow, Result};
use colored::*;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

use crate::utils::{cfg_prompt_default, cfg_prompt_port};
use crate::modules::creds::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};

const DEFAULT_TIMEOUT_MS: u64 = 5000;

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "Banner Grabber".to_string(),
        description: "Grabs service banners from open ports with protocol-specific probes (HTTP, FTP, SMTP, SSH, POP3, IMAP, MySQL, Redis, RTSP, Telnet). Identifies software versions for vulnerability assessment.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

#[derive(Debug, Clone)]
struct BannerResult {
    service: &'static str,
    banner: String,
}

/// Get the protocol-specific probe bytes for a port.
fn probe_for_port(port: u16) -> Option<&'static [u8]> {
    match port {
        80 | 443 | 8080 | 8443 | 8888 => Some(b"GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"),
        554 => Some(b"OPTIONS rtsp://target/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"),
        _ => None, // Most services send banners on connect without a probe
    }
}

/// Identify service from banner content.
fn identify_service(port: u16, banner: &str) -> &'static str {
    let lower = banner.to_lowercase();
    if lower.contains("ssh") { return "SSH"; }
    if lower.contains("ftp") { return "FTP"; }
    if lower.contains("smtp") || lower.contains("postfix") || lower.contains("exim") { return "SMTP"; }
    if lower.contains("pop3") || lower.contains("+ok") { return "POP3"; }
    if lower.contains("imap") { return "IMAP"; }
    if lower.contains("http") { return "HTTP"; }
    if lower.contains("mysql") || (banner.len() > 4 && banner.as_bytes()[0] < 0x20) { return "MySQL"; }
    if lower.contains("redis") || lower.contains("+pong") { return "Redis"; }
    if lower.contains("rtsp") { return "RTSP"; }
    if lower.contains("vnc") || lower.starts_with("RFB ") { return "VNC"; }
    if lower.contains("mongo") { return "MongoDB"; }
    match port {
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 | 587 => "SMTP",
        80 | 443 | 8080 => "HTTP", 110 => "POP3", 143 => "IMAP",
        3306 => "MySQL", 5432 => "PostgreSQL", 6379 => "Redis",
        _ => "Unknown",
    }
}

/// Grab banner from a single port.
async fn grab_banner(ip: IpAddr, port: u16, dur: Duration) -> Option<BannerResult> {
    let addr = format!("{}:{}", ip, port);
    let mut stream = crate::utils::network::tcp_connect(&addr, dur).await.ok()?;

    // Send probe if needed, then read
    if let Some(probe) = probe_for_port(port) {
        timeout(dur, stream.write_all(probe)).await.ok()?.ok()?;
    }

    let mut buf = [0u8; 4096];
    let n = timeout(dur, stream.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 { return None; }

    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    if banner.is_empty() { return None; }

    let service = identify_service(port, &banner);
    Some(BannerResult { service, banner })
}

fn display_banner() {
    crate::mprintln!("{}", "+=================================================================+".cyan());
    crate::mprintln!("{}", "|                    Banner Grabber                               |".cyan());
    crate::mprintln!("{}", "|   Grab service banners to identify software versions            |".cyan());
    crate::mprintln!("{}", "+=================================================================+".cyan());
    crate::mprintln!();
}

pub async fn run(target: &str) -> Result<()> {
    if is_mass_scan_target(target) {
        let port: u16 = cfg_prompt_port("port", "Port to grab banners from", 22).await?;
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "BannerGrab",
            default_port: port,
            state_file: "banner_grab_mass_state.log",
            default_output: "banner_grab_mass_results.txt",
            default_concurrency: 500,
        }, move |ip: IpAddr, port: u16| {
            async move {
                let result = grab_banner(ip, port, Duration::from_secs(5)).await?;
                let first_line = result.banner.lines().next().unwrap_or("").to_string();
                let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                crate::mprintln!("\r{}", format!("[+] {}:{} [{}] {}", ip, port, result.service, first_line).green());
                Some(format!("[{}] {}:{} [{}] {}\n", ts, ip, port, result.service, first_line))
            }
        }).await;
    }

    display_banner();

    let ports_input = cfg_prompt_default("ports", "Ports to scan (comma-separated)", "21,22,23,25,80,110,143,443,3306,5432,6379,8080").await?;
    let ports: Vec<u16> = ports_input.split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    let timeout_ms: u64 = cfg_prompt_default("timeout", "Timeout (ms)", "5000").await?.parse().unwrap_or(DEFAULT_TIMEOUT_MS);
    let dur = Duration::from_millis(timeout_ms);

    let ip: IpAddr = target.parse().or_else(|_| {
        use std::net::ToSocketAddrs;
        format!("{}:0", target).to_socket_addrs()
            .map_err(|e| anyhow!("Cannot resolve {}: {}", target, e))?
            .next().map(|sa| sa.ip())
            .ok_or_else(|| anyhow!("No addresses for {}", target))
    })?;

    crate::mprintln!("[*] Target: {}", ip.to_string().yellow());
    crate::mprintln!("[*] Ports: {:?}", ports);
    crate::mprintln!();

    let mut results = Vec::new();
    for &port in &ports {
        match grab_banner(ip, port, dur).await {
            Some(r) => {
                let first_line = r.banner.lines().next().unwrap_or("");
                crate::mprintln!("  {} {:<6} {:<12} {}",
                    "+".green(), port, r.service.cyan(), first_line);
                results.push(r);
            }
            None => {
                crate::mprintln!("  {} {:<6} {}", "-".dimmed(), port, "no banner / closed".dimmed());
            }
        }
    }

    crate::mprintln!();
    crate::mprintln!("[*] {} banner(s) grabbed from {} port(s) scanned", results.len().to_string().green(), ports.len());
    Ok(())
}

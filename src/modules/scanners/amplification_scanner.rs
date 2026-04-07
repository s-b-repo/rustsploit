//! Amplification Scanner Module
//!
//! Scans for servers vulnerable to UDP amplification attacks.
//! Probes DNS (open resolvers), NTP (monlist), SSDP (M-SEARCH),
//! and Memcached (stats) to identify reflectors that could be
//! abused for volumetric DDoS.
//!
//! FOR AUTHORIZED SECURITY TESTING ONLY.

use anyhow::{anyhow, Result};
use colored::*;
use std::net::{IpAddr, SocketAddr};
use tokio::time::{timeout, Duration};

use crate::utils::{
    cfg_prompt_default, cfg_prompt_yes_no,
};
use crate::modules::creds::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};

// ============================================================================
// MODULE INFO
// ============================================================================

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "Amplification Scanner".to_string(),
        description: "Scans for UDP amplification vulnerabilities (DNS open resolver, NTP monlist, SSDP M-SEARCH, Memcached stats). Identifies reflectors that could be abused for volumetric DDoS attacks.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://www.us-cert.gov/ncas/alerts/TA14-017A".to_string(),
            "https://www.cloudflare.com/learning/ddos/udp-amplification-attack/".to_string(),
        ],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Excellent,
    }
}

// ============================================================================
// PROTOCOL PROBES
// ============================================================================

/// DNS ANY query for "google.com" — open resolvers respond with large records.
/// Amplification factor: ~28-54x (ANY queries on popular domains).
fn dns_probe() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(33);
    // Transaction ID
    pkt.extend_from_slice(&[0xAA, 0xBB]);
    // Flags: standard query, recursion desired
    pkt.extend_from_slice(&[0x01, 0x00]);
    // Questions: 1, Answers: 0, Authority: 0, Additional: 0
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // QNAME: google.com
    pkt.push(6); pkt.extend_from_slice(b"google");
    pkt.push(3); pkt.extend_from_slice(b"com");
    pkt.push(0); // root label
    // QTYPE: ANY (0x00FF), QCLASS: IN (0x0001)
    pkt.extend_from_slice(&[0x00, 0xFF, 0x00, 0x01]);
    pkt
}

/// NTP MON_GETLIST_1 — vulnerable servers return a list of monitored clients.
/// Amplification factor: ~556x.
const NTP_MONLIST_PROBE: [u8; 8] = [0x17, 0x00, 0x03, 0x2A, 0x00, 0x00, 0x00, 0x00];

/// SSDP M-SEARCH — UPnP devices respond with service descriptions.
/// Amplification factor: ~30x.
const SSDP_MSEARCH_PROBE: &[u8] = b"M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 2\r\n\
ST: ssdp:all\r\n\
\r\n";

/// Memcached UDP stats — exposed servers return megabytes of cache statistics.
/// Amplification factor: ~51,000x.
fn memcached_probe() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(15);
    // UDP binary header (request ID, sequence, total datagrams, reserved)
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);
    // "stats\r\n"
    pkt.extend_from_slice(b"stats\r\n");
    pkt
}

// ============================================================================
// PROTOCOL DETECTION
// ============================================================================

#[derive(Debug, Clone)]
struct ProbeResult {
    protocol: &'static str,
    port: u16,
    response_size: usize,
    amplification: f64,
    detail: String,
}

/// Check if a DNS response indicates an open resolver.
fn check_dns(buf: &[u8], n: usize, probe_len: usize) -> Option<ProbeResult> {
    if n < 12 { return None; }
    // Check QR bit (response) and RCODE (no error)
    let qr = (buf[2] >> 7) & 1;
    let rcode = buf[3] & 0x0F;
    if qr != 1 { return None; }
    let answer_count = u16::from_be_bytes([buf[6], buf[7]]);
    let rcode_str = match rcode {
        0 => "NOERROR",
        2 => "SERVFAIL",
        5 => "REFUSED",
        _ => "OTHER",
    };
    // Even SERVFAIL means the server accepted the query (open resolver)
    if rcode == 5 { return None; } // REFUSED = not open
    Some(ProbeResult {
        protocol: "DNS",
        port: 53,
        response_size: n,
        amplification: n as f64 / probe_len as f64,
        detail: format!("rcode={}, answers={}", rcode_str, answer_count),
    })
}

/// Check if an NTP response indicates monlist support.
fn check_ntp(buf: &[u8], n: usize) -> Option<ProbeResult> {
    if n < 8 { return None; }
    // NTP mode 7 response: first byte & 0x07 == 0x07, or response bit set
    let mode = buf[0] & 0x07;
    if mode != 7 && mode != 6 { return None; }
    Some(ProbeResult {
        protocol: "NTP",
        port: 123,
        response_size: n,
        amplification: n as f64 / NTP_MONLIST_PROBE.len() as f64,
        detail: format!("monlist response ({} bytes)", n),
    })
}

/// Check if an SSDP response indicates a UPnP device.
fn check_ssdp(buf: &[u8], n: usize) -> Option<ProbeResult> {
    if n < 10 { return None; }
    let response = String::from_utf8_lossy(&buf[..n]);
    if !response.contains("HTTP/1.1") && !response.contains("NOTIFY") {
        return None;
    }
    let server = response.lines()
        .find(|l| l.to_lowercase().starts_with("server:"))
        .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
        .unwrap_or_default();
    Some(ProbeResult {
        protocol: "SSDP",
        port: 1900,
        response_size: n,
        amplification: n as f64 / SSDP_MSEARCH_PROBE.len() as f64,
        detail: if server.is_empty() { "UPnP device".to_string() } else { format!("UPnP: {}", server) },
    })
}

/// Check if a Memcached response indicates an exposed instance.
fn check_memcached(buf: &[u8], n: usize, probe_len: usize) -> Option<ProbeResult> {
    if n < 8 { return None; }
    let response = String::from_utf8_lossy(&buf[..n]);
    if !response.contains("STAT") && !response.contains("END") {
        return None;
    }
    let stat_count = response.matches("STAT ").count();
    Some(ProbeResult {
        protocol: "Memcached",
        port: 11211,
        response_size: n,
        amplification: n as f64 / probe_len as f64,
        detail: format!("{} stats returned", stat_count),
    })
}

// ============================================================================
// PROBE ENGINE
// ============================================================================

/// Probe a single IP for all selected amplification protocols.
async fn probe_host(
    ip: IpAddr,
    protocols: &ProbeConfig,
    timeout_ms: u64,
) -> Vec<ProbeResult> {
    let mut results = Vec::new();
    let dur = Duration::from_millis(timeout_ms);

    if protocols.dns {
        if let Some(r) = probe_single(ip, 53, &dns_probe(), dur, |buf, n, plen| check_dns(buf, n, plen)).await {
            results.push(r);
        }
    }
    if protocols.ntp {
        if let Some(r) = probe_single(ip, 123, &NTP_MONLIST_PROBE, dur, |buf, n, _| check_ntp(buf, n)).await {
            results.push(r);
        }
    }
    if protocols.ssdp {
        if let Some(r) = probe_single(ip, 1900, SSDP_MSEARCH_PROBE, dur, |buf, n, _| check_ssdp(buf, n)).await {
            results.push(r);
        }
    }
    if protocols.memcached {
        let probe = memcached_probe();
        if let Some(r) = probe_single(ip, 11211, &probe, dur, |buf, n, plen| check_memcached(buf, n, plen)).await {
            results.push(r);
        }
    }

    results
}

/// Send a single UDP probe and check the response.
async fn probe_single(
    ip: IpAddr,
    port: u16,
    payload: &[u8],
    dur: Duration,
    check: impl Fn(&[u8], usize, usize) -> Option<ProbeResult>,
) -> Option<ProbeResult> {
    let sock = crate::utils::udp_bind(None).await.ok()?;
    let addr = SocketAddr::new(ip, port);
    sock.send_to(payload, addr).await.ok()?;

    let mut buf = [0u8; 4096];
    match timeout(dur, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) if n > 0 => check(&buf, n, payload.len()),
        _ => None,
    }
}

// ============================================================================
// CONFIGURATION
// ============================================================================

#[derive(Clone)]
struct ProbeConfig {
    dns: bool,
    ntp: bool,
    ssdp: bool,
    memcached: bool,
}

impl ProbeConfig {
    fn all() -> Self {
        Self { dns: true, ntp: true, ssdp: true, memcached: true }
    }

    fn enabled_names(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.dns { v.push("DNS"); }
        if self.ntp { v.push("NTP"); }
        if self.ssdp { v.push("SSDP"); }
        if self.memcached { v.push("Memcached"); }
        v
    }
}

fn display_banner() {
    crate::mprintln!("{}", "+=================================================================+".cyan());
    crate::mprintln!("{}", "|         UDP Amplification Vulnerability Scanner                 |".cyan());
    crate::mprintln!("{}", "|   DNS (53) | NTP (123) | SSDP (1900) | Memcached (11211)       |".cyan());
    crate::mprintln!("{}", "+=================================================================+".cyan());
    crate::mprintln!();
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

pub async fn run(target: &str) -> Result<()> {
    // --- Mass scan mode ---
    if is_mass_scan_target(target) {
        let protos_input = cfg_prompt_default(
            "protocols", "Protocols to scan (dns,ntp,ssdp,memcached,all)", "all"
        ).await?;
        let protocols = parse_protocols(&protos_input);

        return run_mass_scan(target, MassScanConfig {
            protocol_name: "Amplification",
            default_port: 0, // unused — we scan each protocol's port
            state_file: "amplification_mass_state.log",
            default_output: "amplification_mass_results.txt",
            default_concurrency: 500,
        }, move |ip: IpAddr, _port: u16| {
            let protos = protocols.clone();
            async move {
                let results = probe_host(ip, &protos, 3000).await;
                if results.is_empty() {
                    return None;
                }
                let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                let mut lines = Vec::new();
                for r in &results {
                    lines.push(format!(
                        "[{}] {}:{} {} vulnerable ({}B response, {:.1}x amplification, {})",
                        ts, ip, r.port, r.protocol, r.response_size, r.amplification, r.detail
                    ));
                    crate::mprintln!("\r{}", format!(
                        "[+] {}:{} {} — {:.1}x amplification ({} bytes, {})",
                        ip, r.port, r.protocol, r.amplification, r.response_size, r.detail
                    ).green().bold());
                }
                Some(lines.join("\n") + "\n")
            }
        }).await;
    }

    // --- Single/multi-target mode ---
    display_banner();

    let protos_input = cfg_prompt_default(
        "protocols", "Protocols to scan (dns,ntp,ssdp,memcached,all)", "all"
    ).await?;
    let protocols = parse_protocols(&protos_input);

    let timeout_ms: u64 = cfg_prompt_default(
        "timeout", "Probe timeout (ms)", "3000"
    ).await?.parse().unwrap_or(3000);

    let verbose = cfg_prompt_yes_no("verbose", "Verbose output?", false).await?;

    crate::mprintln!("[*] Protocols: {}", protocols.enabled_names().join(", ").cyan());
    crate::mprintln!("[*] Target: {}", target.yellow());
    crate::mprintln!("[*] Timeout: {}ms", timeout_ms);
    crate::mprintln!();

    // Resolve target IP
    let ip: IpAddr = target.parse().map_err(|_| {
        // Try DNS resolution
        use std::net::ToSocketAddrs;
        format!("{}:0", target).to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .map(|sa| sa.ip())
            .ok_or_else(|| anyhow!("Cannot resolve target: {}", target))
    }).or_else(|r: Result<IpAddr, _>| r)?;

    crate::mprintln!("[*] Scanning {}...", ip);
    crate::mprintln!();

    let results = probe_host(ip, &protocols, timeout_ms).await;

    if results.is_empty() {
        crate::mprintln!("{}", "[-] No amplification vulnerabilities found.".yellow());
    } else {
        crate::mprintln!("{}", format!(
            "[+] Found {} amplification vulnerability(ies):", results.len()
        ).green().bold());
        crate::mprintln!();

        crate::mprintln!("  {:<12} {:<8} {:<12} {:<14} {}",
            "Protocol".bold(), "Port".bold(), "Resp Size".bold(),
            "Amplification".bold(), "Details".bold());
        crate::mprintln!("  {}", "-".repeat(70).dimmed());

        for r in &results {
            let amp_color = if r.amplification > 100.0 {
                format!("{:.1}x", r.amplification).red().bold().to_string()
            } else if r.amplification > 10.0 {
                format!("{:.1}x", r.amplification).yellow().to_string()
            } else {
                format!("{:.1}x", r.amplification).to_string()
            };

            crate::mprintln!("  {:<12} {:<8} {:<12} {:<14} {}",
                r.protocol.green(), r.port, format!("{} B", r.response_size),
                amp_color, r.detail);

            if verbose {
                crate::mprintln!("    {} Probe: {} bytes -> Response: {} bytes",
                    "->".dimmed(), probe_size(r.protocol), r.response_size);
            }
        }
        crate::mprintln!();

        // Risk summary
        let max_amp = results.iter().map(|r| r.amplification).fold(0.0_f64, f64::max);
        let risk = if max_amp > 500.0 { "CRITICAL".red().bold() }
            else if max_amp > 50.0 { "HIGH".red() }
            else if max_amp > 10.0 { "MEDIUM".yellow() }
            else { "LOW".green() };
        crate::mprintln!("[*] Risk level: {} (max amplification: {:.1}x)", risk, max_amp);

        // Recommendations
        crate::mprintln!();
        crate::mprintln!("{}", "[*] Recommendations:".cyan().bold());
        for r in &results {
            match r.protocol {
                "DNS" => crate::mprintln!("  - DNS: Restrict recursion to authorized clients (allow-recursion ACL)"),
                "NTP" => crate::mprintln!("  - NTP: Disable monlist (restrict noquery in ntp.conf)"),
                "SSDP" => crate::mprintln!("  - SSDP: Disable UPnP or block port 1900 at the firewall"),
                "Memcached" => crate::mprintln!("  - Memcached: Disable UDP listener (-U 0) or bind to localhost only"),
                _ => {}
            }
        }
    }

    crate::mprintln!();
    Ok(())
}

// ============================================================================
// HELPERS
// ============================================================================

fn parse_protocols(input: &str) -> ProbeConfig {
    let lower = input.to_lowercase();
    if lower.contains("all") {
        return ProbeConfig::all();
    }
    ProbeConfig {
        dns: lower.contains("dns"),
        ntp: lower.contains("ntp"),
        ssdp: lower.contains("ssdp"),
        memcached: lower.contains("memcache"),
    }
}

fn probe_size(protocol: &str) -> usize {
    match protocol {
        "DNS" => 33,
        "NTP" => 8,
        "SSDP" => SSDP_MSEARCH_PROBE.len(),
        "Memcached" => 15,
        _ => 0,
    }
}

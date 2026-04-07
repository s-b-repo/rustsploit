//! NetBIOS Name Service (NBNS) Scanner
//!
//! Sends NBNS name queries to port 137/UDP to discover Windows hosts,
//! extracting NetBIOS names, domain/workgroup, MAC addresses, and
//! service flags.
//!
//! For authorized penetration testing only.

use anyhow::{Result, Context};
use colored::*;
use std::time::Duration;
use tokio::time::timeout;
use crate::utils::{cfg_prompt_port, cfg_prompt_yes_no, cfg_prompt_output_file, cfg_prompt_int_range};
use crate::modules::creds::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "NetBIOS Name Service Scanner".into(),
        description: "Sends NBNS name queries to UDP port 137 to discover Windows hosts \
            on a network. Extracts NetBIOS computer names, domain/workgroup memberships, \
            MAC addresses, and service type flags. Useful for Windows network reconnaissance."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec![
            "https://www.rfc-editor.org/rfc/rfc1002".into(),
            "https://book.hacktricks.wiki/en/network-services-pentesting/137-138-139-pentesting-netbios.html".into(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

fn display_banner() {
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   NetBIOS Name Service (NBNS) Scanner                        ║".cyan());
    crate::mprintln!("{}", "║   Discover Windows hosts via NBNS queries (UDP 137)          ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

/// Build an NBNS wildcard name query packet.
/// Query name "*" encoded as CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
fn build_nbns_query() -> Vec<u8> {
    let txn_id: u16 = rand::random();

    let mut packet = Vec::with_capacity(50);

    // Transaction ID (2 bytes)
    packet.extend_from_slice(&txn_id.to_be_bytes());

    // Flags: 0x0000 (standard query, no recursion)
    packet.push(0x00);
    packet.push(0x00);

    // Questions: 1
    packet.push(0x00);
    packet.push(0x01);

    // Answer RRs: 0
    packet.push(0x00);
    packet.push(0x00);

    // Authority RRs: 0
    packet.push(0x00);
    packet.push(0x00);

    // Additional RRs: 0
    packet.push(0x00);
    packet.push(0x00);

    // Query name: encoded "*" = 0x20 length, then CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, then 0x00
    // NetBIOS first-level encoding: each byte -> 2 chars (high nibble + 'A', low nibble + 'A')
    // '*' = 0x2A -> high = 2 -> 'C', low = A -> 'K' -> "CK"
    // pad with 0x00 -> 'A','A' x 15 times
    packet.push(0x20); // Length of encoded name (32 bytes)
    // "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" (32 chars)
    packet.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    packet.push(0x00); // Name terminator

    // Query type: NBSTAT (0x0021)
    packet.push(0x00);
    packet.push(0x21);

    // Query class: IN (0x0001)
    packet.push(0x00);
    packet.push(0x01);

    packet
}

/// NetBIOS name entry type suffixes
fn nbns_suffix_name(suffix: u8) -> &'static str {
    match suffix {
        0x00 => "Workstation",
        0x03 => "Messenger",
        0x06 => "RAS Server",
        0x1B => "Domain Master Browser",
        0x1C => "Domain Controller",
        0x1D => "Master Browser",
        0x1E => "Browser Service Elections",
        0x1F => "NetDDE",
        0x20 => "File Server",
        0x21 => "RAS Client",
        0x22 => "MS Exchange Interchange",
        0x23 => "MS Exchange Store",
        0x24 => "MS Exchange Directory",
        0x2B => "Lotus Notes Server",
        0x30 => "Modem Sharing Server",
        0x43 => "SMS Client Remote Control",
        0x44 => "SMS Admin Remote Control",
        0x45 => "SMS Client Remote Chat",
        0x46 => "SMS Client Remote Transfer",
        0x4C => "DEC Pathworks TCP/IP",
        0x52 => "DEC Pathworks TCP/IP",
        0xBE => "Network Monitor Agent",
        0xBF => "Network Monitor Application",
        _ => "Unknown",
    }
}

#[derive(Debug, Clone)]
struct NbnsEntry {
    name: String,
    suffix: u8,
    is_group: bool,
}

#[derive(Debug, Clone)]
struct NbnsResult {
    host: String,
    entries: Vec<NbnsEntry>,
    mac_address: String,
}

impl std::fmt::Display for NbnsResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} | MAC: {}", self.host, self.mac_address)?;
        if let Some(name) = self.get_computer_name() {
            write!(f, " | Name: {}", name)?;
        }
        if let Some(domain) = self.get_domain() {
            write!(f, " | Domain: {}", domain)?;
        }
        Ok(())
    }
}

impl NbnsResult {
    fn get_computer_name(&self) -> Option<&str> {
        self.entries.iter()
            .find(|e| e.suffix == 0x00 && !e.is_group)
            .map(|e| e.name.as_str())
    }

    fn get_domain(&self) -> Option<&str> {
        self.entries.iter()
            .find(|e| e.suffix == 0x00 && e.is_group)
            .map(|e| e.name.as_str())
    }
}

/// Parse an NBNS response packet
fn parse_nbns_response(data: &[u8], host: &str) -> Option<NbnsResult> {
    // Minimum NBNS response: 12 (header) + question + answer
    if data.len() < 50 {
        return None;
    }

    // Check answer count > 0
    let answer_count = u16::from_be_bytes([data[6], data[7]]);
    if answer_count == 0 {
        return None;
    }

    // Skip header (12 bytes) + question section
    let mut offset: usize = 12;

    // Skip question name (0x00 terminator or 0xC0 compression pointer)
    while offset < data.len() {
        let b = data[offset];
        if b == 0x00 {
            offset = offset.checked_add(1)?;
            break;
        }
        if b & 0xC0 == 0xC0 {
            offset = offset.checked_add(2)?;
            break;
        }
        let label_len = b as usize;
        offset = offset.checked_add(1)?.checked_add(label_len)?;
    }

    // Skip QTYPE (2) + QCLASS (2)
    offset = offset.checked_add(4)?;
    if offset >= data.len() { return None; }

    // Skip answer name (compression pointer or labels)
    if data[offset] & 0xC0 == 0xC0 {
        offset = offset.checked_add(2)?;
    } else {
        while offset < data.len() && data[offset] != 0x00 {
            let label_len = data[offset] as usize;
            offset = offset.checked_add(1)?.checked_add(label_len)?;
        }
        offset = offset.checked_add(1)?;
    }

    // Skip TYPE (2) + CLASS (2) + TTL (4) = 8 bytes
    offset = offset.checked_add(8)?;
    if offset + 2 > data.len() { return None; }

    // RDLENGTH
    let rdlength = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset = offset.checked_add(2)?;

    if rdlength < 1 || offset.checked_add(rdlength)? > data.len() {
        return None;
    }

    // Number of names — cap to prevent DoS from malicious responses
    let num_names = std::cmp::min(data[offset] as usize, 50);
    offset = offset.checked_add(1)?;

    let mut entries = Vec::new();

    for _ in 0..num_names {
        // Each entry: 15 bytes name + 1 byte suffix + 2 bytes flags = 18 bytes
        if offset.checked_add(18)? > data.len() {
            break;
        }

        let name_bytes = &data[offset..offset + 15];
        let name = String::from_utf8_lossy(name_bytes).trim().to_string();
        let suffix = data[offset + 15];
        offset = offset.checked_add(16)?;

        let flags = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let is_group = flags & 0x8000 != 0;
        offset = offset.checked_add(2)?;

        entries.push(NbnsEntry {
            name,
            suffix,
            is_group,
        });
    }

    // MAC address: 6 bytes after all name entries
    let mac = if offset.checked_add(6).map_or(false, |end| end <= data.len()) {
        format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            data[offset], data[offset + 1], data[offset + 2],
            data[offset + 3], data[offset + 4], data[offset + 5])
    } else {
        "00:00:00:00:00:00".to_string()
    };

    Some(NbnsResult {
        host: host.to_string(),
        entries,
        mac_address: mac,
    })
}

/// Send NBNS query and parse response
async fn query_nbns(
    socket: &tokio::net::UdpSocket,
    addr: &str,
    timeout_dur: Duration,
) -> Result<Option<NbnsResult>> {
    let packet = build_nbns_query();

    socket.send_to(&packet, addr).await
        .context("Failed to send NBNS query")?;

    let mut buf = [0u8; 4096];
    match timeout(timeout_dur, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _src))) => {
            let host = addr.split(':').next().unwrap_or(addr);
            Ok(parse_nbns_response(&buf[..n], host))
        }
        Ok(Err(_)) => Ok(None),
        Err(_) => Ok(None), // Timeout
    }
}

pub async fn run(target: &str) -> Result<()> {
    if is_mass_scan_target(target) {
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "NBNS",
            default_port: 137,
            state_file: "nbns_scanner_mass_state.log",
            default_output: "nbns_scanner_mass_results.txt",
            default_concurrency: 500,
        }, move |ip, port| {
            async move {
                let sock = crate::utils::udp_bind(None).await.ok()?;
                let addr = format!("{}:{}", ip, port);
                let packet = build_nbns_query();
                sock.send_to(&packet, &addr).await.ok()?;
                let mut buf = [0u8; 1024];
                match tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await {
                    Ok(Ok((n, _))) if n > 56 => {
                        let host = ip.to_string();
                        if let Some(result) = parse_nbns_response(&buf[..n], &host) {
                            let name = result.get_computer_name().unwrap_or("?").to_string();
                            let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                            Some(format!("[{}] {}:{} NBNS name={} mac={}\n", ts, ip, port, name, result.mac_address))
                        } else {
                            let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                            Some(format!("[{}] {}:{} NBNS responded\n", ts, ip, port))
                        }
                    }
                    _ => None,
                }
            }
        }).await;
    }

    display_banner();

    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());

    let port = cfg_prompt_port("port", "NBNS port", 137).await?;
    let timeout_secs = cfg_prompt_int_range("timeout", "Query timeout (seconds)", 3, 1, 15).await? as u64;
    let retries = cfg_prompt_int_range("retries", "Number of retries", 2, 1, 5).await? as u32;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", false).await?;

    let timeout_dur = Duration::from_secs(timeout_secs);
    let addr = format!("{}:{}", target, port);

    let socket = crate::utils::udp_bind(None).await
        .context("Failed to bind UDP socket")?;

    crate::mprintln!();
    crate::mprintln!("{}", format!("[*] Querying {} ...", addr).bold());

    let mut result: Option<NbnsResult> = None;

    for attempt in 1..=retries {
        if retries > 1 {
            crate::mprintln!("{}", format!("  [*] Attempt {}/{}", attempt, retries).dimmed());
        }

        match query_nbns(&socket, &addr, timeout_dur).await {
            Ok(Some(r)) => {
                result = Some(r);
                break;
            }
            Ok(None) => {
                if attempt < retries {
                    crate::mprintln!("{}", "  [-] No response, retrying...".dimmed());
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
            Err(e) => {
                crate::mprintln!("{}", format!("  [!] Error: {}", e).yellow());
                if attempt < retries {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    // Display results
    crate::mprintln!();
    crate::mprintln!("{}", "=== NBNS Query Results ===".bold());
    crate::mprintln!("  Target: {}", addr);

    match &result {
        Some(r) => {
            if let Some(name) = r.get_computer_name() {
                crate::mprintln!("  {}", format!("Computer Name:  {}", name).green().bold());
            }
            if let Some(domain) = r.get_domain() {
                crate::mprintln!("  {}", format!("Domain/Group:   {}", domain).green());
            }
            crate::mprintln!("  {}", format!("MAC Address:    {}", r.mac_address).green());

            if r.mac_address == "00:00:00:00:00:00" {
                crate::mprintln!("  {}", "[*] Null MAC may indicate Samba/non-Windows NBNS".dimmed());
            }

            crate::mprintln!();
            crate::mprintln!("  {}", "NetBIOS Name Table:".bold());
            crate::mprintln!("  {:<20} {:<6} {:<8} {}", "Name", "Suffix", "Type", "Service");
            crate::mprintln!("  {}", "-".repeat(60));

            for entry in &r.entries {
                let type_str = if entry.is_group { "GROUP" } else { "UNIQUE" };
                let service = nbns_suffix_name(entry.suffix);
                let line = format!("  {:<20} 0x{:02X}   {:<8} {}",
                    entry.name, entry.suffix, type_str, service);

                if entry.suffix == 0x20 {
                    crate::mprintln!("{}", line.green()); // File server
                } else if entry.suffix == 0x1C || entry.suffix == 0x1B {
                    crate::mprintln!("{}", line.red().bold()); // Domain controller
                } else {
                    crate::mprintln!("{}", line);
                }
            }

            // Check for interesting services
            let has_file_server = r.entries.iter().any(|e| e.suffix == 0x20);
            let has_dc = r.entries.iter().any(|e| e.suffix == 0x1C || e.suffix == 0x1B);

            crate::mprintln!();
            if has_file_server {
                crate::mprintln!("{}", "[+] File sharing service detected (0x20)".green());
            }
            if has_dc {
                crate::mprintln!("{}", "[!] Domain Controller detected!".red().bold());
            }
        }
        None => {
            crate::mprintln!("  {}", "No response received.".dimmed());
            crate::mprintln!();
            crate::mprintln!("{}", "[-] Host did not respond to NBNS query.".yellow());
            crate::mprintln!("{}", "    Possible reasons: host down, filtered, or not running NetBIOS.".dimmed());
        }
    }

    if save_results {
        if let Some(r) = &result {
            let output_path = cfg_prompt_output_file("output_file", "Output file", "nbns_scan_results.txt").await?;
            let mut content = format!("NBNS Scan Results - {}\n\n", addr);
            content.push_str(&format!("MAC: {}\n", r.mac_address));
            if let Some(name) = r.get_computer_name() {
                content.push_str(&format!("Computer: {}\n", name));
            }
            if let Some(domain) = r.get_domain() {
                content.push_str(&format!("Domain: {}\n", domain));
            }
            content.push_str("\nName Table:\n");
            for entry in &r.entries {
                let type_str = if entry.is_group { "GROUP" } else { "UNIQUE" };
                content.push_str(&format!("  {} 0x{:02X} {} {}\n",
                    entry.name, entry.suffix, type_str, nbns_suffix_name(entry.suffix)));
            }
            {
                use std::io::Write;
                let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&output_path)
                    .with_context(|| format!("Failed to write results to {}", output_path))?;
                writeln!(f, "\n--- Scan at {} ---", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
                    .with_context(|| format!("Failed to write results to {}", output_path))?;
                f.write_all(content.as_bytes())
                    .with_context(|| format!("Failed to write results to {}", output_path))?;
            }
            crate::mprintln!("{}", format!("[+] Results saved to '{}'", output_path).green());
        }
    }

    Ok(())
}

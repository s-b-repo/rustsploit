//! SNMP Community String Scanner
//!
//! Tests SNMP v1/v2c community strings via UDP port 161.
//! Builds SNMP GET packets manually using BER/ASN.1 encoding.
//!
//! For authorized penetration testing only.

use anyhow::{Result, Context, anyhow};
use colored::*;
use std::time::Duration;
use tokio::time::timeout;
use crate::utils::{cfg_prompt_default, cfg_prompt_port, cfg_prompt_yes_no, cfg_prompt_output_file, cfg_prompt_int_range};
use crate::modules::creds::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "SNMP Community String Scanner".into(),
        description: "Tests SNMP v1/v2c community strings against target devices. \
            Builds raw SNMP GET packets using BER/ASN.1 encoding to extract \
            sysDescr, sysName, and sysLocation from responding devices."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec![
            "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/".into(),
            "https://www.rfc-editor.org/rfc/rfc1157".into(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

const DEFAULT_COMMUNITIES: &[&str] = &[
    "public", "private", "community", "snmp", "monitor",
    "admin", "default", "read", "write", "test",
];

/// OID for sysDescr.0: 1.3.6.1.2.1.1.1.0
const OID_SYS_DESCR: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
/// OID for sysName.0: 1.3.6.1.2.1.1.5.0
const OID_SYS_NAME: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00];
/// OID for sysLocation.0: 1.3.6.1.2.1.1.6.0
const OID_SYS_LOCATION: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x06, 0x00];

fn display_banner() {
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   SNMP Community String Scanner                              ║".cyan());
    crate::mprintln!("{}", "║   Tests SNMP v1/v2c communities via raw UDP packets          ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

/// Encode a BER length field
fn ber_encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    } else {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

/// Build an SNMP v1/v2c GET request packet
fn build_snmp_get(community: &str, oid: &[u8], version: u8, request_id: u32) -> Vec<u8> {
    // Version: INTEGER (0 = v1, 1 = v2c)
    let version_tlv = vec![0x02, 0x01, version];

    // Community: OCTET STRING
    let community_bytes = community.as_bytes();
    let mut community_tlv = vec![0x04];
    community_tlv.extend(ber_encode_length(community_bytes.len()));
    community_tlv.extend_from_slice(community_bytes);

    // Request ID: INTEGER
    let rid_bytes = request_id.to_be_bytes();
    let request_id_tlv = vec![0x02, 0x04, rid_bytes[0], rid_bytes[1], rid_bytes[2], rid_bytes[3]];

    // Error status: INTEGER 0
    let error_status_tlv = vec![0x02, 0x01, 0x00];

    // Error index: INTEGER 0
    let error_index_tlv = vec![0x02, 0x01, 0x00];

    // OID: OBJECT IDENTIFIER
    let mut oid_tlv = vec![0x06];
    oid_tlv.extend(ber_encode_length(oid.len()));
    oid_tlv.extend_from_slice(oid);

    // Value: NULL
    let null_tlv = vec![0x05, 0x00];

    // VarBind: SEQUENCE { oid, null }
    let varbind_content_len = oid_tlv.len() + null_tlv.len();
    let mut varbind = vec![0x30];
    varbind.extend(ber_encode_length(varbind_content_len));
    varbind.extend(&oid_tlv);
    varbind.extend(&null_tlv);

    // VarBindList: SEQUENCE { varbind }
    let mut varbind_list = vec![0x30];
    varbind_list.extend(ber_encode_length(varbind.len()));
    varbind_list.extend(&varbind);

    // PDU: GetRequest (0xA0)
    let pdu_content_len = request_id_tlv.len() + error_status_tlv.len()
        + error_index_tlv.len() + varbind_list.len();
    let mut pdu = vec![0xA0];
    pdu.extend(ber_encode_length(pdu_content_len));
    pdu.extend(&request_id_tlv);
    pdu.extend(&error_status_tlv);
    pdu.extend(&error_index_tlv);
    pdu.extend(&varbind_list);

    // Message: SEQUENCE { version, community, pdu }
    let msg_content_len = version_tlv.len() + community_tlv.len() + pdu.len();
    let mut message = vec![0x30];
    message.extend(ber_encode_length(msg_content_len));
    message.extend(&version_tlv);
    message.extend(&community_tlv);
    message.extend(&pdu);

    message
}

/// Try to extract a string value from an SNMP GetResponse packet.
/// Searches for OCTET STRING (0x04) values in the varbind area.
fn extract_snmp_string_value(data: &[u8]) -> Option<String> {
    // Walk backwards through the packet looking for the last 0x04 (OCTET STRING)
    // which is typically the value in the varbind
    let mut i = 0;
    let mut last_string = None;

    while i < data.len().saturating_sub(2) {
        if data[i] == 0x04 {
            let (len, hdr_len) = parse_ber_length(&data[i + 1..])?;
            let start = i + 1 + hdr_len;
            let end = start + len;
            if end <= data.len() && len > 0 {
                let s = String::from_utf8_lossy(&data[start..end]).to_string();
                if !s.is_empty() {
                    last_string = Some(s);
                }
            }
        }
        i += 1;
    }

    last_string
}

/// Parse a BER length field, returning (length, number_of_header_bytes)
fn parse_ber_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    if data[0] < 0x80 {
        Some((data[0] as usize, 1))
    } else if data[0] == 0x81 && data.len() >= 2 {
        Some((data[1] as usize, 2))
    } else if data[0] == 0x82 && data.len() >= 3 {
        Some((((data[1] as usize) << 8) | data[2] as usize, 3))
    } else {
        None
    }
}

/// Check if response is a valid SNMP GetResponse (tag 0xA2)
fn is_valid_snmp_response(data: &[u8]) -> bool {
    // Must start with SEQUENCE (0x30) and contain GetResponse (0xA2)
    if data.len() < 10 || data[0] != 0x30 {
        return false;
    }
    // Search for GetResponse PDU tag
    data.windows(1).any(|w| w[0] == 0xA2)
}

/// Send SNMP GET and check for valid response
async fn test_community(
    socket: &tokio::net::UdpSocket,
    addr: &str,
    community: &str,
    oid: &[u8],
    version: u8,
    timeout_dur: Duration,
) -> Result<Option<String>> {
    let request_id = rand::random::<u32>();
    let packet = build_snmp_get(community, oid, version, request_id);

    socket.send_to(&packet, addr).await
        .context("Failed to send SNMP packet")?;

    let mut buf = [0u8; 4096];
    match timeout(timeout_dur, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _src))) => {
            let data = &buf[..n];
            if is_valid_snmp_response(data) {
                let value = extract_snmp_string_value(data)
                    .unwrap_or_else(|| "<no string value>".into());
                Ok(Some(value))
            } else {
                Ok(None)
            }
        }
        Ok(Err(_)) => Ok(None),
        Err(_) => Ok(None), // Timeout
    }
}

pub async fn run(target: &str) -> Result<()> {
    if is_mass_scan_target(target) {
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "SNMP",
            default_port: 161,
            state_file: "snmp_scanner_mass_state.log",
            default_output: "snmp_scanner_mass_results.txt",
            default_concurrency: 500,
        }, move |ip, port| {
            async move {
                let sock = crate::utils::udp_bind(None).await.ok()?;
                let addr = format!("{}:{}", ip, port);
                let packet = build_snmp_get("public", OID_SYS_DESCR, 0x00, rand::random());
                sock.send_to(&packet, &addr).await.ok()?;
                let mut buf = [0u8; 1024];
                match tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await {
                    Ok(Ok((n, _))) if is_valid_snmp_response(&buf[..n]) => {
                        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                        Some(format!("[{}] {}:{} SNMP community 'public' valid\n", ts, ip, port))
                    }
                    _ => None,
                }
            }
        }).await;
    }

    display_banner();

    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());

    let port = cfg_prompt_port("port", "SNMP port", 161).await?;
    let timeout_secs = cfg_prompt_int_range("timeout", "Timeout per community (seconds)", 3, 1, 15).await? as u64;
    let version_choice = cfg_prompt_default("snmp_version", "SNMP version (1/2c/both)", "both").await?;
    let custom_wordlist = cfg_prompt_default("wordlist", "Custom wordlist path (leave empty for built-in)", "").await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", false).await?;

    let timeout_dur = Duration::from_secs(timeout_secs);

    // Determine communities to test
    let communities: Vec<String> = if custom_wordlist.is_empty() {
        DEFAULT_COMMUNITIES.iter().map(|s| s.to_string()).collect()
    } else {
        // Cap wordlist at 10MB to prevent OOM
        let meta = std::fs::metadata(&custom_wordlist)
            .with_context(|| format!("Cannot stat wordlist: {}", custom_wordlist))?;
        if meta.len() > 10 * 1024 * 1024 {
            return Err(anyhow!("Wordlist too large ({:.1}MB, max 10MB)", meta.len() as f64 / (1024.0 * 1024.0)));
        }
        let content = std::fs::read_to_string(&custom_wordlist)
            .with_context(|| format!("Failed to read wordlist: {}", custom_wordlist))?;
        content.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    };

    // Determine versions to test
    let versions: Vec<(u8, &str)> = match version_choice.trim().to_lowercase().as_str() {
        "1" => vec![(0x00, "v1")],
        "2c" | "2" => vec![(0x01, "v2c")],
        _ => vec![(0x00, "v1"), (0x01, "v2c")],
    };

    let addr = format!("{}:{}", target, port);
    let socket = crate::utils::udp_bind(None).await
        .context("Failed to bind UDP socket")?;

    crate::mprintln!();
    crate::mprintln!("{}", format!("[*] Testing {} communities across {} version(s) against {}",
        communities.len(), versions.len(), addr).bold());

    let mut valid_communities = Vec::new();

    for (ver_byte, ver_name) in &versions {
        crate::mprintln!();
        crate::mprintln!("{}", format!("[*] Testing SNMP {} ...", ver_name).cyan());

        for community in &communities {
            crate::mprint!("  [*] Testing '{}' ... ", community);
            let _ = std::io::Write::flush(&mut std::io::stdout());

            match test_community(&socket, &addr, community, OID_SYS_DESCR, *ver_byte, timeout_dur).await {
                Ok(Some(sys_descr)) => {
                    crate::mprintln!("{}", "VALID!".green().bold());
                    crate::mprintln!("    {}", format!("[+] sysDescr: {}", sys_descr).green());

                    // Try to get sysName
                    if let Ok(Some(sys_name)) = test_community(&socket, &addr, community, OID_SYS_NAME, *ver_byte, timeout_dur).await {
                        crate::mprintln!("    {}", format!("[+] sysName: {}", sys_name).green());
                    }

                    // Try to get sysLocation
                    if let Ok(Some(sys_loc)) = test_community(&socket, &addr, community, OID_SYS_LOCATION, *ver_byte, timeout_dur).await {
                        crate::mprintln!("    {}", format!("[+] sysLocation: {}", sys_loc).green());
                    }

                    valid_communities.push(format!("{} ({}): {}", community, ver_name, sys_descr));
                }
                Ok(None) => {
                    crate::mprintln!("{}", "no response".dimmed());
                }
                Err(e) => {
                    crate::mprintln!("{}", format!("error: {}", e).red());
                }
            }
        }
    }

    // Summary
    crate::mprintln!();
    crate::mprintln!("{}", "=== Scan Summary ===".bold());
    crate::mprintln!("  Target:               {}:{}", target, port);
    crate::mprintln!("  Communities tested:    {}", communities.len() * versions.len());
    crate::mprintln!("  Valid communities:     {}", if valid_communities.is_empty() {
        "0".dimmed().to_string()
    } else {
        valid_communities.len().to_string().green().bold().to_string()
    });

    if !valid_communities.is_empty() {
        crate::mprintln!();
        crate::mprintln!("{}", "[!] Valid community strings found:".red().bold());
        for vc in &valid_communities {
            crate::mprintln!("    - {}", vc);
        }
    }

    if save_results && !valid_communities.is_empty() {
        let output_path = cfg_prompt_output_file("output_file", "Output file", "snmp_scan_results.txt").await?;
        let content = valid_communities.join("\n");
        std::fs::write(&output_path, format!("SNMP Scan Results - {}:{}\n\n{}", target, port, content))
            .with_context(|| format!("Failed to write results to {}", output_path))?;
        crate::mprintln!("{}", format!("[+] Results saved to '{}'", output_path).green());
    }

    Ok(())
}

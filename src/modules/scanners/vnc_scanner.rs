//! VNC Service Scanner
//!
//! Connects to VNC servers, extracts protocol version, and enumerates
//! supported security types. Detects servers with no authentication.
//!
//! For authorized penetration testing only.

use anyhow::{Result, Context, anyhow};
use colored::*;
use std::time::Duration;
use tokio::time::timeout;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::utils::{cfg_prompt_port, cfg_prompt_yes_no, cfg_prompt_output_file, cfg_prompt_int_range};
use crate::modules::creds::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "VNC Security Scanner".into(),
        description: "Scans VNC servers for protocol version and security type enumeration. \
            Identifies servers with 'None' authentication (no password required) and reports \
            all supported security mechanisms."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec![
            "https://www.rfc-editor.org/rfc/rfc6143".into(),
            "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-vnc.html".into(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

fn display_banner() {
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   VNC Security Scanner                                       ║".cyan());
    crate::mprintln!("{}", "║   Enumerate VNC versions and security types                  ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

/// Decode a VNC security type number into a human-readable name
fn security_type_name(t: u8) -> &'static str {
    match t {
        0 => "Invalid",
        1 => "None (NO AUTH!)",
        2 => "VNC Authentication",
        5 => "RA2",
        6 => "RA2ne",
        16 => "Tight",
        17 => "Ultra",
        18 => "TLS",
        19 => "VeNCrypt",
        20 => "GTK-VNC SASL",
        21 => "MD5 hash",
        22 => "Colin Dean xvp",
        30 => "Apple Remote Desktop",
        _ => "Unknown",
    }
}

/// Scan a single VNC target and return findings
async fn scan_vnc(
    target: &str,
    port: u16,
    timeout_dur: Duration,
) -> Result<VncResult> {
    let addr = format!("{}:{}", target, port);

    let mut stream = timeout(timeout_dur, tokio::net::TcpStream::connect(&addr))
        .await
        .context("Connection timed out")?
        .context("Failed to connect to VNC server")?;

    // Step 1: Read server RFB version string (12 bytes: "RFB XXX.YYY\n")
    let mut version_buf = [0u8; 12];
    let n = timeout(timeout_dur, stream.read(&mut version_buf))
        .await
        .context("Timed out reading VNC version")?
        .context("Failed to read VNC version")?;

    if n < 12 {
        return Err(anyhow!("Short read for VNC version ({} bytes)", n));
    }

    let server_version = String::from_utf8_lossy(&version_buf[..n]).trim().to_string();
    if !server_version.starts_with("RFB ") {
        return Err(anyhow!("Not a VNC server (got: {})", server_version));
    }

    // Step 2: Send back the same version
    stream.write_all(&version_buf[..n]).await
        .context("Failed to send VNC version")?;
    stream.flush().await?;

    // Step 3: Read security types
    // In RFB 3.3: server sends 4-byte security type
    // In RFB 3.7+: server sends count byte followed by type bytes
    let mut sec_buf = [0u8; 256];
    let sec_n = timeout(timeout_dur, stream.read(&mut sec_buf))
        .await
        .context("Timed out reading security types")?
        .context("Failed to read security types")?;

    if sec_n == 0 {
        return Err(anyhow!("Connection closed after version exchange"));
    }

    let mut security_types = Vec::new();
    let mut no_auth = false;
    let mut error_msg = None;

    // Detect RFB 3.3 vs 3.7+ format
    if server_version.contains("003.003") {
        // RFB 3.3: 4-byte big-endian security type
        if sec_n >= 4 {
            let sec_type = u32::from_be_bytes([sec_buf[0], sec_buf[1], sec_buf[2], sec_buf[3]]);
            if sec_type == 0 {
                // Error: read reason string (length + message)
                if sec_n > 8 {
                    let msg_len = std::cmp::min(
                        u32::from_be_bytes([sec_buf[4], sec_buf[5], sec_buf[6], sec_buf[7]]) as usize,
                        sec_n.saturating_sub(8),
                    );
                    error_msg = Some(String::from_utf8_lossy(&sec_buf[8..8 + msg_len]).to_string());
                }
            } else {
                let t = sec_type as u8;
                security_types.push(t);
                if t == 1 {
                    no_auth = true;
                }
            }
        }
    } else {
        // RFB 3.7+: first byte = count of security types
        let count = std::cmp::min(sec_buf[0] as usize, sec_n.saturating_sub(1));
        if sec_buf[0] == 0 {
            // Error follows: 4-byte length + string
            if sec_n >= 5 {
                let msg_len = std::cmp::min(
                    u32::from_be_bytes([sec_buf[1], sec_buf[2], sec_buf[3], sec_buf[4]]) as usize,
                    sec_n.saturating_sub(5),
                );
                error_msg = Some(String::from_utf8_lossy(&sec_buf[5..5 + msg_len]).to_string());
            }
        } else {
            for i in 0..count {
                let idx = i + 1;
                if idx < sec_n && idx < sec_buf.len() {
                    let t = sec_buf[idx];
                    security_types.push(t);
                    if t == 1 {
                        no_auth = true;
                    }
                }
            }
        }
    }

    Ok(VncResult {
        host: target.to_string(),
        port,
        version: server_version,
        security_types,
        no_auth,
        error_msg,
    })
}

#[derive(Debug, Clone)]
struct VncResult {
    host: String,
    port: u16,
    version: String,
    security_types: Vec<u8>,
    no_auth: bool,
    error_msg: Option<String>,
}

impl std::fmt::Display for VncResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{} | {} | Security: [{}]",
            self.host, self.port, self.version,
            self.security_types.iter()
                .map(|t| format!("{}({})", t, security_type_name(*t)))
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        if self.no_auth {
            write!(f, " | NO AUTH")?;
        }
        if let Some(ref err) = self.error_msg {
            write!(f, " | Error: {}", err)?;
        }
        Ok(())
    }
}

pub async fn run(target: &str) -> Result<()> {
    if is_mass_scan_target(target) {
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "VNC",
            default_port: 5900,
            state_file: "vnc_scanner_mass_state.log",
            default_output: "vnc_scanner_mass_results.txt",
            default_concurrency: 500,
        }, move |ip, port| {
            async move {
                if crate::utils::tcp_port_open(ip, port, Duration::from_secs(3)).await {
                    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                    Some(format!("[{}] {}:{} VNC open\n", ts, ip, port))
                } else {
                    None
                }
            }
        }).await;
    }

    display_banner();

    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());

    let port = cfg_prompt_port("port", "VNC port", 5900).await?;
    let timeout_secs = cfg_prompt_int_range("timeout", "Connection timeout (seconds)", 5, 1, 30).await? as u64;
    let scan_display_range = cfg_prompt_yes_no("scan_range", "Scan display range :0-:10 (ports 5900-5910)?", false).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", false).await?;

    let timeout_dur = Duration::from_secs(timeout_secs);

    let ports: Vec<u16> = if scan_display_range {
        (5900..=5910).collect()
    } else {
        vec![port]
    };

    let mut results = Vec::new();

    for p in &ports {
        let display_num = p - 5900;
        crate::mprintln!();
        crate::mprintln!("{}", format!("[*] Scanning {}:{} (display :{})", target, p, display_num).bold());

        match scan_vnc(target, *p, timeout_dur).await {
            Ok(result) => {
                if result.no_auth {
                    crate::mprintln!("{}", format!("[+] {} - NO AUTHENTICATION REQUIRED!", result).red().bold());
                } else if !result.security_types.is_empty() {
                    crate::mprintln!("{}", format!("[+] {}", result).green());
                } else if let Some(ref err) = result.error_msg {
                    crate::mprintln!("{}", format!("[!] Server error: {}", err).yellow());
                }

                // Print security type details
                for t in &result.security_types {
                    let name = security_type_name(*t);
                    let indicator = if *t == 1 { "[!!!]".red().bold() } else { "[*]".dimmed() };
                    crate::mprintln!("  {} Type {}: {}", indicator, t, name);
                }

                results.push(result);
            }
            Err(e) => {
                crate::mprintln!("{}", format!("[-] {}:{} - {}", target, p, e).dimmed());
            }
        }
    }

    // Summary
    crate::mprintln!();
    crate::mprintln!("{}", "=== Scan Summary ===".bold());
    crate::mprintln!("  Ports scanned:    {}", ports.len());
    crate::mprintln!("  VNC found:        {}", results.len().to_string().green());
    let no_auth_count = results.iter().filter(|r| r.no_auth).count();
    if no_auth_count > 0 {
        crate::mprintln!("  No-auth servers:  {}", no_auth_count.to_string().red().bold());
        crate::mprintln!();
        crate::mprintln!("{}", "[!] WARNING: VNC servers with no authentication allow full remote desktop access!".red().bold());
    }

    if save_results && !results.is_empty() {
        let output_path = cfg_prompt_output_file("output_file", "Output file", "vnc_scan_results.txt").await?;
        let content = results.iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&output_path, content)
            .with_context(|| format!("Failed to write results to {}", output_path))?;
        crate::mprintln!("{}", format!("[+] Results saved to '{}'", output_path).green());
    }

    Ok(())
}

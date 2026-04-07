//! Multi-Protocol Service Version Detection Scanner
//!
//! Connects to multiple ports concurrently and grabs banners/versions for
//! various network services in a single scan pass. Supports FTP, SSH, Telnet,
//! SMTP, POP3, IMAP, MySQL, PostgreSQL, Redis, MongoDB, Memcached, RDP, VNC,
//! and Elasticsearch.
//!
//! For authorized penetration testing only.

use anyhow::{anyhow, Context, Result};
use colored::*;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::utils::{cfg_prompt_default, cfg_prompt_yes_no, cfg_prompt_output_file, cfg_prompt_int_range};
use crate::modules::creds::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};
use crate::module_info::{ModuleInfo, ModuleRank};

/// Default ports to scan when the user accepts the default list.
const DEFAULT_PORTS: &str = "21,22,23,25,110,143,443,3306,3389,5432,5900,6379,9200,11211,27017";
const DEFAULT_CONCURRENCY: i64 = 20;
const DEFAULT_TIMEOUT_SECS: i64 = 5;

// ---------------------------------------------------------------------------
// Module metadata
// ---------------------------------------------------------------------------

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Multi-Protocol Service Version Scanner".to_string(),
        description: "Connects to common service ports and grabs banners/version \
                       strings using protocol-specific probes. Detects FTP, SSH, \
                       Telnet, SMTP, POP3, IMAP, MySQL, PostgreSQL, Redis, MongoDB, \
                       Memcached, RDP, VNC, and Elasticsearch."
            .to_string(),
        authors: vec!["rustsploit contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

// ---------------------------------------------------------------------------
// Service result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ServiceResult {
    port: u16,
    service: String,
    version: String,
    banner: String,
    notes: String,
}

impl ServiceResult {
    fn new(port: u16) -> Self {
        Self {
            port,
            service: String::new(),
            version: String::new(),
            banner: String::new(),
            notes: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run(target: &str) -> Result<()> {
    // Mass scan support: TCP connect to port 80, extract HTTP server header.
    if is_mass_scan_target(target) {
        return run_mass_scan(
            target,
            MassScanConfig {
                protocol_name: "ServiceScan",
                default_port: 80,
                state_file: "service_scanner_mass_state.log",
                default_output: "service_scanner_mass_results.txt",
                default_concurrency: 500,
            },
            move |ip: std::net::IpAddr, port: u16| async move {
                mass_scan_probe(&ip.to_string(), port).await
            },
        )
        .await;
    }

    display_banner();

    // --- Prompts ---
    let port_list_str = cfg_prompt_default(
        "ports",
        "Ports to scan (comma-separated)",
        DEFAULT_PORTS,
    )
    .await?;

    let ports = parse_port_list(&port_list_str)?;
    if ports.is_empty() {
        return Err(anyhow!("No valid ports specified"));
    }

    let concurrency = cfg_prompt_int_range(
        "concurrency",
        "Concurrency (simultaneous probes)",
        DEFAULT_CONCURRENCY,
        1,
        500,
    )
    .await? as usize;

    let timeout_secs = cfg_prompt_int_range(
        "timeout",
        "Connection timeout (seconds)",
        DEFAULT_TIMEOUT_SECS,
        1,
        60,
    )
    .await? as u64;

    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", false).await?;
    let output_file = if save_results {
        cfg_prompt_output_file("output_file", "Output filename", "service_scan_results.txt").await?
    } else {
        String::new()
    };

    // --- Run scan ---
    crate::mprintln!();
    crate::mprintln!(
        "{}",
        format!(
            "[*] Scanning {} ports on {} (concurrency={}, timeout={}s)",
            ports.len(),
            target,
            concurrency,
            timeout_secs
        )
        .cyan()
        .bold()
    );
    crate::mprintln!();

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
    let target_str = target.to_string();

    let mut handles = Vec::with_capacity(ports.len());
    for port in &ports {
        let permit = semaphore.clone().acquire_owned().await?;
        let tgt = target_str.clone();
        let p = *port;
        let to = timeout_secs;
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            probe_service(&tgt, p, to).await
        }));
    }

    let mut results: Vec<ServiceResult> = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(Some(r)) => results.push(r),
            Ok(None) => {}
            Err(_) => {}
        }
    }

    // Sort by port number for tidy output.
    results.sort_by_key(|r| r.port);

    // --- Display results table ---
    print_results_table(&results);

    // --- Save to file ---
    if save_results && !output_file.is_empty() {
        save_results_to_file(&results, &output_file, target)?;
        crate::mprintln!(
            "{}",
            format!("[*] Results saved to {}", output_file).cyan()
        );
    }

    crate::mprintln!(
        "\n{}",
        format!("[*] Scan complete: {} services detected on {}", results.len(), target)
            .green()
            .bold()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

fn display_banner() {
    crate::mprintln!(
        "{}",
        "╔═══════════════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Multi-Protocol Service Version Scanner                        ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Detect service versions across common network ports           ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚═══════════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

fn print_results_table(results: &[ServiceResult]) {
    if results.is_empty() {
        crate::mprintln!("{}", "[!] No services detected.".yellow());
        return;
    }

    // Column widths
    let w_port = 7;
    let w_svc = 16;
    let w_ver = 28;
    let w_banner = 40;
    let w_notes = 24;

    let separator = format!(
        "+{:-<w_port$}+{:-<w_svc$}+{:-<w_ver$}+{:-<w_banner$}+{:-<w_notes$}+",
        "", "", "", "", "",
        w_port = w_port + 2,
        w_svc = w_svc + 2,
        w_ver = w_ver + 2,
        w_banner = w_banner + 2,
        w_notes = w_notes + 2
    );

    crate::mprintln!("\n{}", "=== Service Detection Results ===".cyan().bold());
    crate::mprintln!("{}", separator);
    crate::mprintln!(
        "| {:<w_port$} | {:<w_svc$} | {:<w_ver$} | {:<w_banner$} | {:<w_notes$} |",
        "Port", "Service", "Version", "Banner", "Notes",
        w_port = w_port,
        w_svc = w_svc,
        w_ver = w_ver,
        w_banner = w_banner,
        w_notes = w_notes
    );
    crate::mprintln!("{}", separator);

    for r in results {
        let banner_display = truncate_display(&sanitize_banner(&r.banner), w_banner);
        let version_display = truncate_display(&r.version, w_ver);
        let notes_display = truncate_display(&r.notes, w_notes);

        crate::mprintln!(
            "| {:<w_port$} | {:<w_svc$} | {:<w_ver$} | {:<w_banner$} | {:<w_notes$} |",
            r.port.to_string().green(),
            r.service.yellow(),
            version_display,
            banner_display.dimmed(),
            notes_display,
            w_port = w_port,
            w_svc = w_svc,
            w_ver = w_ver,
            w_banner = w_banner,
            w_notes = w_notes
        );
    }

    crate::mprintln!("{}", separator);
}

fn truncate_display(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

/// Strip control characters and collapse whitespace for readable banner display.
fn sanitize_banner(raw: &str) -> String {
    raw.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn save_results_to_file(
    results: &[ServiceResult],
    path: &str,
    target: &str,
) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)
        .with_context(|| format!("Failed to create output file: {}", path))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));

    writeln!(f, "Service Version Scan Results for {}", target)?;
    writeln!(f, "Timestamp: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(f, "{}", "-".repeat(80))?;
    writeln!(f, "{:<8} {:<16} {:<30} {}", "Port", "Service", "Version", "Notes")?;
    writeln!(f, "{}", "-".repeat(80))?;

    for r in results {
        writeln!(
            f,
            "{:<8} {:<16} {:<30} {}",
            r.port, r.service, r.version, r.notes
        )?;
        if !r.banner.is_empty() {
            writeln!(f, "         Banner: {}", sanitize_banner(&r.banner))?;
        }
    }

    writeln!(f, "\n{} services detected.", results.len())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Port list parsing
// ---------------------------------------------------------------------------

fn parse_port_list(input: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for token in input.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if token.contains('-') {
            let parts: Vec<&str> = token.splitn(2, '-').collect();
            if parts.len() == 2 {
                let start: u16 = parts[0]
                    .trim()
                    .parse()
                    .with_context(|| format!("Invalid port range start: {}", parts[0]))?;
                let end: u16 = parts[1]
                    .trim()
                    .parse()
                    .with_context(|| format!("Invalid port range end: {}", parts[1]))?;
                if start > end {
                    return Err(anyhow!("Invalid port range: {}-{}", start, end));
                }
                for p in start..=end {
                    ports.push(p);
                }
            }
        } else {
            let p: u16 = token
                .parse()
                .with_context(|| format!("Invalid port number: {}", token))?;
            ports.push(p);
        }
    }
    // Deduplicate while preserving order.
    let mut seen = std::collections::HashSet::new();
    ports.retain(|p| seen.insert(*p));
    Ok(ports)
}

// ---------------------------------------------------------------------------
// Mass scan probe (HTTP server header extraction)
// ---------------------------------------------------------------------------

async fn mass_scan_probe(ip: &str, port: u16) -> Option<String> {
    let addr = format!("{}:{}", ip, port);
    let stream = timeout(Duration::from_secs(3), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;

    let mut stream = stream;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        ip
    );
    stream.write_all(request.as_bytes()).await.ok()?;

    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }

    let response = String::from_utf8_lossy(&buf[..n]);
    let server = extract_http_header(&response, "server").unwrap_or_default();
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    Some(format!(
        "[{}] {}:{} ServiceScan server={}\n",
        ts, ip, port, server
    ))
}

// ---------------------------------------------------------------------------
// Core probe dispatcher
// ---------------------------------------------------------------------------

async fn probe_service(target: &str, port: u16, timeout_secs: u64) -> Option<ServiceResult> {
    let addr = format!("{}:{}", target, port);
    let dur = Duration::from_secs(timeout_secs);

    let stream = match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let result = match port {
        21 => probe_ftp(stream, port, dur).await,
        22 => probe_ssh(stream, port, dur).await,
        23 => probe_telnet(stream, port, dur).await,
        25 => probe_smtp(stream, port, dur).await,
        110 => probe_pop3(stream, port, dur).await,
        143 => probe_imap(stream, port, dur).await,
        443 | 8443 => { drop(stream); probe_https(target, port, dur).await },
        3306 => probe_mysql(stream, port, dur).await,
        3389 => probe_rdp(stream, port, dur).await,
        5432 => probe_postgres(stream, port, dur).await,
        5900 => probe_vnc(stream, port, dur).await,
        6379 => probe_redis(stream, port, dur).await,
        9200 => probe_elasticsearch(stream, port, dur).await,
        11211 => probe_memcached(stream, port, dur).await,
        27017 => probe_mongodb(stream, port, dur).await,
        _ => probe_generic(stream, port, dur).await,
    };

    result
}

// ---------------------------------------------------------------------------
// Protocol-specific probes
// ---------------------------------------------------------------------------

/// FTP (port 21) -- read banner, detect server software, check anonymous.
async fn probe_ftp(mut stream: TcpStream, port: u16, dur: Duration) -> Option<ServiceResult> {
    let mut r = ServiceResult::new(port);
    r.service = "FTP".to_string();

    let mut buf = vec![0u8; 2048];
    let n = timeout(dur, stream.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return Some(r);
    }

    let banner = String::from_utf8_lossy(&buf[..n]).to_string();
    r.banner = banner.trim().to_string();

    // Detect version
    let lower = r.banner.to_lowercase();
    if lower.contains("proftpd") {
        r.version = extract_version_after(&r.banner, "ProFTPD");
    } else if lower.contains("vsftpd") {
        r.version = extract_version_after(&r.banner, "vsftpd");
    } else if lower.contains("pure-ftpd") {
        r.version = extract_version_after(&r.banner, "Pure-FTPd");
    } else if lower.contains("filezilla") {
        r.version = extract_version_after(&r.banner, "FileZilla");
    } else if lower.contains("microsoft ftp") {
        r.version = "Microsoft FTP Service".to_string();
    } else if lower.contains("wu-") {
        r.version = extract_version_after(&r.banner, "wu-");
    }

    // Check anonymous access — proper FTP handshake
    let anon_cmd = b"USER anonymous\r\n";
    if stream.write_all(anon_cmd).await.is_ok() {
        let mut anon_buf = vec![0u8; 512];
        if let Ok(Ok(an)) = timeout(dur, stream.read(&mut anon_buf)).await {
            if an > 0 {
                let resp = String::from_utf8_lossy(&anon_buf[..an]);
                if resp.starts_with("230") {
                    // 230 = Logged in without password
                    r.notes = "ANONYMOUS LOGIN ALLOWED (no password)".to_string();
                } else if resp.starts_with("331") {
                    // 331 = Password required — send anonymous email
                    if stream.write_all(b"PASS anonymous@\r\n").await.is_ok() {
                        let mut pass_buf = vec![0u8; 512];
                        if let Ok(Ok(pn)) = timeout(dur, stream.read(&mut pass_buf)).await {
                            if pn > 0 {
                                let pass_resp = String::from_utf8_lossy(&pass_buf[..pn]);
                                if pass_resp.starts_with("230") {
                                    r.notes = "ANONYMOUS LOGIN ALLOWED".to_string();
                                } else if pass_resp.starts_with("530") {
                                    r.notes = "Anonymous login denied".to_string();
                                }
                            }
                        }
                    }
                } else if resp.starts_with("530") {
                    r.notes = "Anonymous login denied".to_string();
                }
            }
        }
    }

    Some(r)
}

/// SSH (port 22) -- read banner line (e.g. SSH-2.0-OpenSSH_8.9).
async fn probe_ssh(mut stream: TcpStream, port: u16, dur: Duration) -> Option<ServiceResult> {
    let mut r = ServiceResult::new(port);
    r.service = "SSH".to_string();

    let mut buf = vec![0u8; 512];
    let n = timeout(dur, stream.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return Some(r);
    }

    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    r.banner = banner.clone();

    // SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
    if let Some(idx) = banner.find("SSH-") {
        let rest = &banner[idx..];
        r.version = rest.to_string();
        if let Some(sw) = rest.split_whitespace().next() {
            r.version = sw.to_string();
        }
    }

    Some(r)
}

/// Telnet (port 23) -- connect and read initial data.
async fn probe_telnet(mut stream: TcpStream, port: u16, dur: Duration) -> Option<ServiceResult> {
    let mut r = ServiceResult::new(port);
    r.service = "Telnet".to_string();

    let mut buf = vec![0u8; 2048];
    let n = timeout(dur, stream.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return Some(r);
    }

    // Telnet negotiation bytes (IAC commands) start with 0xFF. Strip them for
    // display but keep the readable portion.
    let text_start = buf[..n]
        .iter()
        .position(|&b| b != 0xFF && b.is_ascii_graphic() || b == b' ')
        .unwrap_or(n);

    let readable = String::from_utf8_lossy(&buf[text_start..n]).trim().to_string();
    r.banner = readable;

    if !r.banner.is_empty() {
        let lower = r.banner.to_lowercase();
        if lower.contains("linux") || lower.contains("ubuntu") || lower.contains("debian") {
            r.notes = "Linux-based device".to_string();
        } else if lower.contains("busybox") {
            r.notes = "BusyBox embedded".to_string();
        } else if lower.contains("mikrotik") {
            r.notes = "MikroTik router".to_string();
        }
    }

    Some(r)
}

/// SMTP (port 25) -- read banner, detect MTA software.
async fn probe_smtp(mut stream: TcpStream, port: u16, dur: Duration) -> Option<ServiceResult> {
    let mut r = ServiceResult::new(port);
    r.service = "SMTP".to_string();

    let mut buf = vec![0u8; 2048];
    let n = timeout(dur, stream.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return Some(r);
    }

    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    r.banner = banner.clone();

    let lower = banner.to_lowercase();
    if lower.contains("postfix") {
        r.version = "Postfix".to_string();
        r.version = extract_version_after(&banner, "Postfix");
        if r.version.is_empty() {
            r.version = "Postfix".to_string();
        }
    } else if lower.contains("exim") {
        r.version = extract_version_after(&banner, "Exim");
        if r.version.is_empty() {
            r.version = "Exim".to_string();
        }
    } else if lower.contains("sendmail") {
        r.version = extract_version_after(&banner, "Sendmail");
        if r.version.is_empty() {
            r.version = "Sendmail".to_string();
        }
    } else if lower.contains("microsoft") || lower.contains("exchange") {
        r.version = "Microsoft Exchange/SMTP".to_string();
    }

    if banner.starts_with("220") {
        r.notes = "Service ready".to_string();
    }

    Some(r)
}

/// POP3 (port 110) -- read +OK banner.
async fn probe_pop3(mut stream: TcpStream, port: u16, dur: Duration) -> Option<ServiceResult> {
    let mut r = ServiceResult::new(port);
    r.service = "POP3".to_string();

    let mut buf = vec![0u8; 1024];
    let n = timeout(dur, stream.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return Some(r);
    }

    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    r.banner = banner.clone();

    if banner.starts_with("+OK") {
        r.notes = "POP3 ready".to_string();
        let lower = banner.to_lowercase();
        if lower.contains("dovecot") {
            r.version = "Dovecot".to_string();
        } else if lower.contains("cyrus") {
            r.version = "Cyrus".to_string();
        } else if lower.contains("courier") {
            r.version = "Courier".to_string();
        }
    }

    Some(r)
}

/// IMAP (port 143) -- read * OK banner.
async fn probe_imap(mut stream: TcpStream, port: u16, dur: Duration) -> Option<ServiceResult> {
    let mut r = ServiceResult::new(port);
    r.service = "IMAP".to_string();

    let mut buf = vec![0u8; 1024];
    let n = timeout(dur, stream.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return Some(r);
    }

    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    r.banner = banner.clone();

    if banner.starts_with("* OK") {
        r.notes = "IMAP ready".to_string();
        let lower = banner.to_lowercase();
        if lower.contains("dovecot") {
            r.version = "Dovecot".to_string();
        } else if lower.contains("cyrus") {
            r.version = "Cyrus".to_string();
        } else if lower.contains("courier") {
            r.version = "Courier".to_string();
        }
    }

    Some(r)
}

/// HTTPS (port 443/8443) -- use reqwest to make an HTTPS request and extract server info.
async fn probe_https(target: &str, port: u16, dur: Duration) -> Option<ServiceResult> {
    let mut r = ServiceResult::new(port);
    r.service = "HTTPS".to_string();

    let url = format!("https://{}:{}/", target, port);
    let client = crate::utils::build_http_client(dur).ok()?;
    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status();
            let server = resp.headers().get("server")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let powered_by = resp.headers().get("x-powered-by")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            r.banner = format!("{}", status);
            if !server.is_empty() {
                r.version = server.clone();
                r.notes = format!("Server: {}", server);
            }
            if !powered_by.is_empty() {
                if r.notes.is_empty() {
                    r.notes = format!("X-Powered-By: {}", powered_by);
                } else {
                    r.notes = format!("{}, X-Powered-By: {}", r.notes, powered_by);
                }
            }
        }
        Err(_) => {
            r.notes = "TLS connection failed or timeout".to_string();
        }
    }
    Some(r)
}

/// MySQL (port 3306) -- read greeting packet, extract version string.
async fn probe_mysql(mut stream: TcpStream, port: u16, dur: Duration) -> Option<ServiceResult> {
    let mut r = ServiceResult::new(port);
    r.service = "MySQL".to_string();

    let mut buf = vec![0u8; 2048];
    let n = timeout(dur, stream.read(&mut buf)).await.ok()?.ok()?;
    if n < 5 {
        return Some(r);
    }

    // MySQL greeting packet layout:
    //   bytes 0-2: payload length (little-endian)
    //   byte  3  : sequence id
    //   byte  4  : protocol version (typically 10)
    //   byte  5+ : null-terminated version string
    let protocol_version = buf[4];
    r.notes = format!("Protocol v{}", protocol_version);

    // Extract null-terminated version string starting at byte 5.
    if n > 5 {
        let version_bytes = &buf[5..n];
        let version_end = version_bytes.iter().position(|&b| b == 0).unwrap_or(version_bytes.len());
        let version_str = String::from_utf8_lossy(&version_bytes[..version_end]).to_string();
        if !version_str.is_empty() {
            r.version = version_str.clone();
            r.banner = format!("MySQL {}", version_str);
            if version_str.to_lowercase().contains("mariadb") {
                r.service = "MariaDB".to_string();
            }
        }
    }

    Some(r)
}

/// PostgreSQL (port 5432) -- send SSLRequest, read response.
async fn probe_postgres(
    mut stream: TcpStream,
    port: u16,
    dur: Duration,
) -> Option<ServiceResult> {
    let mut r = ServiceResult::new(port);
    r.service = "PostgreSQL".to_string();

    // Send an SSLRequest message: length (8 bytes big-endian) + SSL request code.
    // This is a safe way to detect PostgreSQL -- it responds with 'N' (no SSL) or
    // 'S' (SSL supported) without requiring authentication.
    let ssl_request: [u8; 8] = [
        0x00, 0x00, 0x00, 0x08, // length = 8
        0x04, 0xd2, 0x16, 0x2f, // SSL request code = 80877103
    ];

    if stream.write_all(&ssl_request).await.is_err() {
        return Some(r);
    }

    let mut buf = vec![0u8; 1024];
    if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
        if n > 0 {
            match buf[0] {
                b'S' => {
                    r.notes = "SSL supported".to_string();
                    r.version = "PostgreSQL (SSL)".to_string();
                }
                b'N' => {
                    r.notes = "SSL not supported".to_string();
                    r.version = "PostgreSQL".to_string();
                }
                _ => {
                    r.banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                }
            }
        }
    }

    Some(r)
}

/// Redis (port 6379) -- send INFO, check for redis_version, detect auth.
async fn probe_redis(mut stream: TcpStream, port: u16, dur: Duration) -> Option<ServiceResult> {
    let mut r = ServiceResult::new(port);
    r.service = "Redis".to_string();

    if stream.write_all(b"INFO\r\n").await.is_err() {
        return Some(r);
    }

    let mut buf = vec![0u8; 4096];
    let n = match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return Some(r),
    };

    let response = String::from_utf8_lossy(&buf[..n]).to_string();

    if response.contains("NOAUTH") || response.contains("-ERR") {
        r.notes = "Authentication required".to_string();
        // Even with auth required, the error message often reveals the version.
        if response.contains("redis_version") {
            r.version = extract_redis_version(&response);
        }
        return Some(r);
    }

    if response.contains("redis_version") {
        r.version = extract_redis_version(&response);
        r.notes = "No authentication (open)".to_string();
    }

    r.banner = truncate_display(&sanitize_banner(&response), 120);
    Some(r)
}

/// MongoDB (port 27017) -- send isMaster command, read response.
async fn probe_mongodb(mut stream: TcpStream, port: u16, dur: Duration) -> Option<ServiceResult> {
    let mut r = ServiceResult::new(port);
    r.service = "MongoDB".to_string();

    // Minimal OP_MSG with isMaster: {isMaster: 1, $db: "admin"}
    // We use a lightweight OP_QUERY to the admin.$cmd collection.
    // OP_QUERY header (standard wire protocol v1):
    //   messageLength (4), requestID (4), responseTo (4), opCode=2004 (4),
    //   flags (4), fullCollectionName (null-terminated), numberToSkip (4),
    //   numberToReturn (4), query BSON document
    let is_master_bson: Vec<u8> = build_is_master_query();

    if stream.write_all(&is_master_bson).await.is_err() {
        return Some(r);
    }

    let mut buf = vec![0u8; 4096];
    if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
        if n > 0 {
            let data = &buf[..n];
            // Look for version string pattern in the BSON response.
            // MongoDB includes "version" : "x.y.z" in the isMaster reply.
            let text = String::from_utf8_lossy(data);
            if let Some(ver) = extract_bson_string_field(&text, "version") {
                r.version = ver;
            }
            r.banner = format!("MongoDB ({}B response)", n);
            r.notes = "Responded to isMaster".to_string();
        }
    }

    Some(r)
}

/// Memcached (port 11211) -- send "version\r\n", read VERSION response.
async fn probe_memcached(
    mut stream: TcpStream,
    port: u16,
    dur: Duration,
) -> Option<ServiceResult> {
    let mut r = ServiceResult::new(port);
    r.service = "Memcached".to_string();

    if stream.write_all(b"version\r\n").await.is_err() {
        return Some(r);
    }

    let mut buf = vec![0u8; 512];
    let n = match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return Some(r),
    };

    let response = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    r.banner = response.clone();

    // Expected: "VERSION x.y.z"
    if response.starts_with("VERSION") {
        let parts: Vec<&str> = response.splitn(2, ' ').collect();
        if parts.len() == 2 {
            r.version = parts[1].trim().to_string();
        }
    }

    Some(r)
}

/// RDP (port 3389) -- send X.224 Connection Request, check response.
async fn probe_rdp(mut stream: TcpStream, port: u16, dur: Duration) -> Option<ServiceResult> {
    let mut r = ServiceResult::new(port);
    r.service = "RDP".to_string();

    // X.224 Connection Request (CR) TPDU wrapped in a TPKT header.
    // TPKT: version=3, reserved=0, length=19
    // X.224 CR: length=14, CR code=0xE0, dst-ref=0, src-ref=0, class=0
    // Cookie: "Cookie: mstshash=test\r\n"
    let cookie = b"Cookie: mstshash=test\r\n";
    let x224_len: u8 = 6 + cookie.len() as u8; // CR header (6) + cookie
    let tpkt_len: u16 = 4 + 1 + x224_len as u16; // TPKT header (4) + x224 length byte + x224 payload

    let mut pkt = Vec::with_capacity(tpkt_len as usize);
    // TPKT header
    pkt.push(0x03); // version
    pkt.push(0x00); // reserved
    pkt.extend_from_slice(&tpkt_len.to_be_bytes()); // length
    // X.224 CR TPDU
    pkt.push(x224_len); // length indicator
    pkt.push(0xE0); // CR code
    pkt.extend_from_slice(&[0x00, 0x00]); // dst-ref
    pkt.extend_from_slice(&[0x00, 0x00]); // src-ref
    pkt.push(0x00); // class option
    pkt.extend_from_slice(cookie);

    if stream.write_all(&pkt).await.is_err() {
        return Some(r);
    }

    let mut buf = vec![0u8; 1024];
    if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
        if n >= 7 {
            // TPKT response: version=3, X.224 CC code=0xD0
            if buf[0] == 0x03 && buf[5] == 0xD0 {
                r.version = "RDP (X.224 CC confirmed)".to_string();
                r.notes = "RDP service confirmed".to_string();
            } else {
                r.notes = "Unexpected response to X.224 CR".to_string();
            }
        } else if n > 0 {
            r.notes = format!("Short response ({}B)", n);
        }
    }

    Some(r)
}

/// VNC (port 5900) -- read RFB protocol version string.
async fn probe_vnc(mut stream: TcpStream, port: u16, dur: Duration) -> Option<ServiceResult> {
    let mut r = ServiceResult::new(port);
    r.service = "VNC".to_string();

    let mut buf = vec![0u8; 256];
    let n = timeout(dur, stream.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return Some(r);
    }

    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    r.banner = banner.clone();

    // Expected: "RFB 003.008\n" (or 003.003, 003.007, etc.)
    if banner.starts_with("RFB ") {
        let parts: Vec<&str> = banner.splitn(2, ' ').collect();
        if parts.len() == 2 {
            r.version = format!("RFB {}", parts[1].trim());
        }
        r.notes = "VNC server".to_string();
    }

    Some(r)
}

/// Elasticsearch (port 9200) -- send HTTP GET /, parse JSON for version.
async fn probe_elasticsearch(
    mut stream: TcpStream,
    port: u16,
    dur: Duration,
) -> Option<ServiceResult> {
    let mut r = ServiceResult::new(port);
    r.service = "Elasticsearch".to_string();

    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if stream.write_all(request).await.is_err() {
        return Some(r);
    }

    let mut buf = vec![0u8; 8192];
    let n = match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return Some(r),
    };

    let response = String::from_utf8_lossy(&buf[..n]).to_string();

    // Extract the JSON body (after the blank line).
    if let Some(body_start) = response.find("\r\n\r\n") {
        let body = &response[body_start + 4..];

        // Extract "number" field from the version object.
        // We parse manually to avoid pulling in serde_json just for this probe.
        if let Some(ver) = extract_json_field(body, "number") {
            r.version = ver;
        }
        if let Some(name) = extract_json_field(body, "cluster_name") {
            r.notes = format!("cluster={}", name);
        }

        r.banner = truncate_display(body.trim(), 120);
    } else {
        // Maybe not HTTP -- store whatever we got.
        r.banner = truncate_display(&sanitize_banner(&response), 120);
    }

    Some(r)
}

/// Generic probe for unknown ports -- try reading a banner, then send an
/// HTTP GET as a fallback.
async fn probe_generic(mut stream: TcpStream, port: u16, dur: Duration) -> Option<ServiceResult> {
    let mut r = ServiceResult::new(port);
    r.service = "unknown".to_string();

    let mut buf = vec![0u8; 2048];

    // First, try a passive read (many services send banners on connect).
    let short_dur = Duration::from_secs(dur.as_secs().min(2));
    if let Ok(Ok(n)) = timeout(short_dur, stream.read(&mut buf)).await {
        if n > 0 {
            let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
            r.banner = banner.clone();
            detect_service_from_banner(&banner, &mut r);
            return Some(r);
        }
    }

    // Fallback: send an HTTP GET and see if we get an HTTP response.
    let http_req = format!(
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(http_req.as_bytes()).await.is_ok() {
        if let Ok(Ok(n)) = timeout(short_dur, stream.read(&mut buf)).await {
            if n > 0 {
                let resp = String::from_utf8_lossy(&buf[..n]).to_string();
                if resp.starts_with("HTTP/") {
                    r.service = "HTTP".to_string();
                    if let Some(server) = extract_http_header(&resp, "server") {
                        r.version = server;
                    }
                }
                r.banner = sanitize_banner(&resp);
                r.banner = truncate_display(&r.banner, 120);
                return Some(r);
            }
        }
    }

    // Port is open but no data -- still report it.
    r.notes = "Open, no banner".to_string();
    Some(r)
}

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

/// Try to detect a service from a banner string and update the ServiceResult.
fn detect_service_from_banner(banner: &str, r: &mut ServiceResult) {
    let lower = banner.to_lowercase();

    if lower.contains("ssh-") {
        r.service = "SSH".to_string();
        if let Some(idx) = banner.find("SSH-") {
            r.version = banner[idx..].split_whitespace().next().unwrap_or("").to_string();
        }
    } else if lower.starts_with("220") && (lower.contains("ftp") || lower.contains("ready")) {
        r.service = "FTP".to_string();
    } else if lower.starts_with("220") && lower.contains("smtp") {
        r.service = "SMTP".to_string();
    } else if lower.starts_with("+ok") {
        r.service = "POP3".to_string();
    } else if lower.starts_with("* ok") {
        r.service = "IMAP".to_string();
    } else if lower.starts_with("rfb ") {
        r.service = "VNC".to_string();
    } else if lower.starts_with("http/") {
        r.service = "HTTP".to_string();
    }
}

/// Extract a version string that follows a keyword (case-insensitive search,
/// preserving the original case). Returns the keyword + trailing
/// version-like characters (digits, dots, dashes, underscores).
fn extract_version_after(text: &str, keyword: &str) -> String {
    let lower = text.to_lowercase();
    let kw_lower = keyword.to_lowercase();
    if let Some(idx) = lower.find(&kw_lower) {
        let start = idx;
        let rest = &text[start..];
        // Take until whitespace or end.
        let token = rest
            .split(|c: char| c == '\r' || c == '\n')
            .next()
            .unwrap_or("")
            .trim();
        token.to_string()
    } else {
        String::new()
    }
}

/// Extract `redis_version:x.y.z` from an INFO response.
fn extract_redis_version(text: &str) -> String {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("redis_version:") {
            return trimmed
                .strip_prefix("redis_version:")
                .unwrap_or("")
                .trim()
                .to_string();
        }
    }
    String::new()
}

/// Extract an HTTP header value by name (case-insensitive).
fn extract_http_header(response: &str, header: &str) -> Option<String> {
    let header_lower = header.to_lowercase();
    for line in response.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with(&header_lower) && line.contains(':') {
            let value = line.splitn(2, ':').nth(1)?.trim().to_string();
            return Some(value);
        }
    }
    None
}

/// Minimal JSON field extractor -- finds `"key" : "value"` patterns.
/// Does not handle nested objects or escaped quotes; sufficient for simple
/// version responses from Elasticsearch and similar services.
fn extract_json_field(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let idx = json.find(&pattern)?;
    let after_key = &json[idx + pattern.len()..];
    // Skip whitespace and colon.
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let after_ws = after_colon.trim_start();
    if after_ws.starts_with('"') {
        let value_start = 1; // skip opening quote
        let value_end = after_ws[value_start..].find('"')?;
        Some(after_ws[value_start..value_start + value_end].to_string())
    } else {
        None
    }
}

/// Try to find a string field in raw BSON-like data. This is a best-effort
/// text search in the lossy UTF-8 representation of the response bytes.
fn extract_bson_string_field(text: &str, field: &str) -> Option<String> {
    // In the UTF-8 lossy view of BSON, string values appear after
    // their field names separated by null bytes. We look for readable
    // version-like patterns near the field name.
    let idx = text.find(field)?;
    let after = &text[idx + field.len()..];
    // Skip non-printable / null padding and look for a version pattern.
    let clean: String = after
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if clean.is_empty() || !clean.contains('.') {
        return None;
    }
    Some(clean)
}

/// Build a minimal MongoDB OP_QUERY message for `admin.$cmd` with the
/// document `{isMaster: 1}`.
fn build_is_master_query() -> Vec<u8> {
    // BSON document: { isMaster: 1 }
    //   int32  document size (including self) = 18
    //   0x10   type = int32
    //   "isMaster\0" name
    //   int32  value = 1
    //   0x00   document terminator
    let mut bson = Vec::new();
    let doc_body: Vec<u8> = {
        let mut d = Vec::new();
        d.push(0x10); // type: int32
        d.extend_from_slice(b"isMaster\0"); // field name
        d.extend_from_slice(&1i32.to_le_bytes()); // value
        d.push(0x00); // terminator
        d
    };
    let doc_size = (4 + doc_body.len()) as i32;
    bson.extend_from_slice(&doc_size.to_le_bytes());
    bson.extend_from_slice(&doc_body);

    let collection = b"admin.$cmd\0";

    // OP_QUERY wire message
    let mut msg = Vec::new();
    // We'll fill in messageLength at the end.
    let request_id: i32 = 1;
    let response_to: i32 = 0;
    let op_code: i32 = 2004; // OP_QUERY
    let flags: i32 = 0;
    let number_to_skip: i32 = 0;
    let number_to_return: i32 = 1;

    // placeholder for length
    msg.extend_from_slice(&[0u8; 4]);
    msg.extend_from_slice(&request_id.to_le_bytes());
    msg.extend_from_slice(&response_to.to_le_bytes());
    msg.extend_from_slice(&op_code.to_le_bytes());
    msg.extend_from_slice(&flags.to_le_bytes());
    msg.extend_from_slice(collection);
    msg.extend_from_slice(&number_to_skip.to_le_bytes());
    msg.extend_from_slice(&number_to_return.to_le_bytes());
    msg.extend_from_slice(&bson);

    let total_len = msg.len() as i32;
    msg[0..4].copy_from_slice(&total_len.to_le_bytes());

    msg
}

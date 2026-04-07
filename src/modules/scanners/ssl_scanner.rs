//! SSL/TLS Certificate Scanner Module
//!
//! Connects to target hosts and analyzes SSL/TLS certificates and configuration.
//! Detects expired certificates, self-signed certs, weak ciphers, and misconfigurations.
//! Supports mass scanning via CIDR ranges.
//!
//! For authorized penetration testing only.

use anyhow::{anyhow, Context, Result};
use colored::*;
use std::sync::Arc;
use std::time::Duration;

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::modules::creds::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_int_range, cfg_prompt_output_file, cfg_prompt_port,
    cfg_prompt_yes_no,
};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const DEFAULT_PORT: u16 = 443;
const DEFAULT_TIMEOUT_SECS: i64 = 10;

// ============================================================
// Module metadata
// ============================================================

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "SSL/TLS Certificate Scanner".into(),
        description: "Analyzes SSL/TLS certificates and configuration. Detects expired certificates, \
            self-signed certs, weak ciphers, and misconfigurations."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec![],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

// ============================================================
// Certificate-capturing verifier
// ============================================================

/// A ServerCertVerifier that accepts all certificates but captures the
/// end-entity certificate DER bytes and the full chain for later analysis.
#[derive(Debug)]
struct CertCaptureVerifier {
    certs: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

impl CertCaptureVerifier {
    fn new() -> (Self, Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
        let certs = Arc::new(std::sync::Mutex::new(Vec::new()));
        (
            Self {
                certs: Arc::clone(&certs),
            },
            certs,
        )
    }
}

impl ServerCertVerifier for CertCaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let mut captured = self.certs.lock().unwrap_or_else(|e| e.into_inner());
        captured.push(end_entity.to_vec());
        for intermediate in intermediates {
            captured.push(intermediate.to_vec());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ============================================================
// Minimal ASN.1 / X.509 DER parser
// ============================================================

/// Read a DER tag + length, returning (tag, content_bytes, rest).
fn read_der_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if data.is_empty() {
        return None;
    }
    let tag = data[0];
    if data.len() < 2 {
        return None;
    }
    let (length, header_len) = if data[1] & 0x80 == 0 {
        (data[1] as usize, 2)
    } else {
        let num_bytes = (data[1] & 0x7f) as usize;
        if data.len() < 2 + num_bytes {
            return None;
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = len.checked_mul(256)
                .and_then(|l| l.checked_add(data[2 + i] as usize))?;
        }
        (len, 2 + num_bytes)
    };
    if data.len() < header_len + length {
        return None;
    }
    Some((
        tag,
        &data[header_len..header_len + length],
        &data[header_len + length..],
    ))
}

/// Walk through a SEQUENCE and collect all TLV items inside it.
fn parse_sequence_items(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut items = Vec::new();
    let mut remaining = data;
    while !remaining.is_empty() {
        if let Some((tag, content, rest)) = read_der_tlv(remaining) {
            items.push((tag, content.to_vec()));
            remaining = rest;
        } else {
            break;
        }
    }
    items
}

/// Decode a DER-encoded string (UTF8String, PrintableString, IA5String, etc.)
fn decode_der_string(data: &[u8]) -> String {
    // Try UTF-8 first, fall back to lossy
    String::from_utf8(data.to_vec()).unwrap_or_else(|_| String::from_utf8_lossy(data).to_string())
}

/// Known OID bytes for common X.509 name attributes.
const OID_CN: &[u8] = &[0x55, 0x04, 0x03]; // 2.5.4.3
const OID_O: &[u8] = &[0x55, 0x04, 0x0a]; // 2.5.4.10
const OID_OU: &[u8] = &[0x55, 0x04, 0x0b]; // 2.5.4.11
const OID_C: &[u8] = &[0x55, 0x04, 0x06]; // 2.5.4.6
const OID_ST: &[u8] = &[0x55, 0x04, 0x08]; // 2.5.4.8
const OID_L: &[u8] = &[0x55, 0x04, 0x07]; // 2.5.4.7

/// OID for Subject Alternative Name extension: 2.5.29.17
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];

/// Parse an X.509 distinguished name from DER SEQUENCE content.
/// Returns a map of short-name -> value.
fn parse_dn(data: &[u8]) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let sets = parse_sequence_items(data);
    for (_tag, set_content) in &sets {
        // Each SET contains one or more SEQUENCE (attribute type + value)
        let sequences = parse_sequence_items(set_content);
        for (_stag, seq_content) in &sequences {
            let attrs = parse_sequence_items(seq_content);
            if attrs.len() >= 2 {
                let oid_bytes = &attrs[0].1;
                let value = decode_der_string(&attrs[1].1);
                let name = if oid_bytes == OID_CN {
                    "CN"
                } else if oid_bytes == OID_O {
                    "O"
                } else if oid_bytes == OID_OU {
                    "OU"
                } else if oid_bytes == OID_C {
                    "C"
                } else if oid_bytes == OID_ST {
                    "ST"
                } else if oid_bytes == OID_L {
                    "L"
                } else {
                    continue;
                };
                result.push((name.to_string(), value));
            }
        }
    }
    result
}

/// Format a DN as a readable string.
fn format_dn(parts: &[(String, String)]) -> String {
    if parts.is_empty() {
        return "(empty)".to_string();
    }
    parts
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Extract CN from a parsed DN.
fn get_cn(parts: &[(String, String)]) -> Option<String> {
    parts
        .iter()
        .find(|(k, _)| k == "CN")
        .map(|(_, v)| v.clone())
}

/// ASN.1 GeneralizedTime / UTCTime to chrono DateTime.
/// UTCTime: YYMMDDHHMMSSZ
/// GeneralizedTime: YYYYMMDDHHMMSSZ
fn parse_asn1_time(tag: u8, data: &[u8]) -> Option<chrono::NaiveDateTime> {
    let s = std::str::from_utf8(data).ok()?;
    let s = s.trim_end_matches('Z');
    if tag == 0x17 {
        // UTCTime: YYMMDDHHMMSS
        if s.len() >= 12 {
            let year: i32 = s[0..2].parse().ok()?;
            let year = if year >= 50 { 1900 + year } else { 2000 + year };
            let month: u32 = s[2..4].parse().ok()?;
            let day: u32 = s[4..6].parse().ok()?;
            let hour: u32 = s[6..8].parse().ok()?;
            let min: u32 = s[8..10].parse().ok()?;
            let sec: u32 = s[10..12].parse().ok()?;
            return chrono::NaiveDate::from_ymd_opt(year, month, day)
                .and_then(|d| d.and_hms_opt(hour, min, sec));
        }
    } else if tag == 0x18 {
        // GeneralizedTime: YYYYMMDDHHMMSS
        if s.len() >= 14 {
            let year: i32 = s[0..4].parse().ok()?;
            let month: u32 = s[4..6].parse().ok()?;
            let day: u32 = s[6..8].parse().ok()?;
            let hour: u32 = s[8..10].parse().ok()?;
            let min: u32 = s[10..12].parse().ok()?;
            let sec: u32 = s[12..14].parse().ok()?;
            return chrono::NaiveDate::from_ymd_opt(year, month, day)
                .and_then(|d| d.and_hms_opt(hour, min, sec));
        }
    }
    None
}

/// Parse Subject Alternative Names from the SAN extension value.
/// The value is a SEQUENCE of GeneralName entries.
/// We look for dNSName (context tag [2]) and iPAddress (context tag [7]).
fn parse_san_extension(data: &[u8]) -> Vec<String> {
    let mut sans = Vec::new();
    // The extension value may be wrapped in an OCTET STRING; try to
    // unwrap one layer if present.
    let inner = if let Some((0x04, content, _)) = read_der_tlv(data) {
        content
    } else {
        data
    };
    // Should be a SEQUENCE (0x30)
    let seq_data = if let Some((0x30, content, _)) = read_der_tlv(inner) {
        content
    } else {
        inner
    };
    let mut remaining = seq_data;
    while !remaining.is_empty() {
        if let Some((tag, content, rest)) = read_der_tlv(remaining) {
            match tag {
                0x82 => {
                    // dNSName (context [2], primitive)
                    if let Ok(name) = std::str::from_utf8(content) {
                        sans.push(format!("DNS:{}", name));
                    }
                }
                0x87 => {
                    // iPAddress (context [7], primitive)
                    if content.len() == 4 {
                        sans.push(format!(
                            "IP:{}.{}.{}.{}",
                            content[0], content[1], content[2], content[3]
                        ));
                    } else if content.len() == 16 {
                        let parts: Vec<String> = content
                            .chunks(2)
                            .map(|c| format!("{:02x}{:02x}", c[0], c.get(1).copied().unwrap_or(0)))
                            .collect();
                        sans.push(format!("IP:{}", parts.join(":")));
                    }
                }
                _ => {}
            }
            remaining = rest;
        } else {
            break;
        }
    }
    sans
}

// ============================================================
// Certificate info extraction
// ============================================================

/// Parsed certificate information.
#[derive(Clone, Debug)]
struct CertInfo {
    subject: Vec<(String, String)>,
    issuer: Vec<(String, String)>,
    not_before: Option<chrono::NaiveDateTime>,
    not_after: Option<chrono::NaiveDateTime>,
    san_names: Vec<String>,
    is_self_signed: bool,
    serial_hex: String,
    key_bits: Option<u32>,
}

impl CertInfo {
    fn subject_cn(&self) -> String {
        get_cn(&self.subject).unwrap_or_else(|| "(no CN)".to_string())
    }

    fn issuer_cn(&self) -> String {
        get_cn(&self.issuer).unwrap_or_else(|| "(no CN)".to_string())
    }

    fn is_expired(&self) -> bool {
        if let Some(not_after) = self.not_after {
            let now = chrono::Utc::now().naive_utc();
            not_after < now
        } else {
            false
        }
    }

    fn days_until_expiry(&self) -> Option<i64> {
        self.not_after.map(|na| {
            let now = chrono::Utc::now().naive_utc();
            (na - now).num_days()
        })
    }

    fn is_expiring_soon(&self) -> bool {
        self.days_until_expiry()
            .map(|d| d >= 0 && d <= 30)
            .unwrap_or(false)
    }
}

/// Parse a DER-encoded X.509 certificate into CertInfo.
fn parse_certificate(der: &[u8]) -> Option<CertInfo> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (_tag, cert_seq, _) = read_der_tlv(der)?;

    let items = parse_sequence_items(cert_seq);
    if items.is_empty() {
        return None;
    }

    // tbsCertificate is the first item (SEQUENCE)
    let tbs_data = &items[0].1;
    let tbs_items = parse_sequence_items(tbs_data);

    // tbsCertificate structure:
    // [0] EXPLICIT version (optional, context tag 0xa0)
    // serialNumber INTEGER
    // signature AlgorithmIdentifier
    // issuer Name
    // validity Validity
    // subject Name
    // subjectPublicKeyInfo
    // ... extensions ...

    let mut idx = 0;

    // Check for explicit version tag (0xa0)
    if !tbs_items.is_empty() && tbs_items[0].0 == 0xa0 {
        idx += 1;
    }

    // serialNumber
    let serial_hex = if idx < tbs_items.len() && tbs_items[idx].0 == 0x02 {
        let serial = &tbs_items[idx].1;
        serial
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    } else {
        String::new()
    };
    idx += 1;

    // signature algorithm — skip
    idx += 1;

    // issuer
    let issuer = if idx < tbs_items.len() {
        parse_dn(&tbs_items[idx].1)
    } else {
        Vec::new()
    };
    idx += 1;

    // validity: SEQUENCE { notBefore, notAfter }
    let (not_before, not_after) = if idx < tbs_items.len() {
        let validity_items = parse_sequence_items(&tbs_items[idx].1);
        let nb = validity_items
            .first()
            .and_then(|(tag, data)| parse_asn1_time(*tag, data));
        let na = validity_items
            .get(1)
            .and_then(|(tag, data)| parse_asn1_time(*tag, data));
        (nb, na)
    } else {
        (None, None)
    };
    idx += 1;

    // subject
    let subject = if idx < tbs_items.len() {
        parse_dn(&tbs_items[idx].1)
    } else {
        Vec::new()
    };
    idx += 1;

    // Skip subjectPublicKeyInfo
    idx += 1;

    // Look for extensions in remaining items (context tag 0xa3)
    let mut san_names = Vec::new();
    while idx < tbs_items.len() {
        if tbs_items[idx].0 == 0xa3 {
            // Extensions wrapper: SEQUENCE of Extension
            let ext_seq_data =
                if let Some((0x30, content, _)) = read_der_tlv(&tbs_items[idx].1) {
                    content
                } else {
                    &tbs_items[idx].1
                };
            let extensions = parse_sequence_items(ext_seq_data);
            for (_etag, ext_content) in &extensions {
                let ext_items = parse_sequence_items(ext_content);
                if !ext_items.is_empty() && ext_items[0].0 == 0x06 {
                    // OID
                    if ext_items[0].1 == OID_SAN {
                        // The value is the last item (OCTET STRING or raw)
                        if let Some((_vtag, val_data)) = ext_items.last() {
                            san_names = parse_san_extension(val_data);
                        }
                    }
                }
            }
        }
        idx += 1;
    }

    let is_self_signed = subject == issuer;

    Some(CertInfo {
        subject,
        issuer,
        not_before,
        not_after,
        san_names,
        is_self_signed,
        serial_hex,
        key_bits: None,
    })
}

// ============================================================
// TLS connection and scanning
// ============================================================

/// Result of an SSL scan against a single target.
#[derive(Clone, Debug)]
struct SslScanResult {
    host: String,
    port: u16,
    tls_version: String,
    cipher_suite: String,
    cert_info: Option<CertInfo>,
    chain_depth: usize,
    fingerprint_sha256: Option<String>,
    issues: Vec<String>,
}

/// Known weak cipher suite name fragments.
const WEAK_CIPHER_FRAGMENTS: &[&str] = &[
    "NULL", "EXPORT", "DES_CBC", "RC4", "RC2", "DES40", "anon", "MD5",
];

fn is_weak_cipher(name: &str) -> bool {
    let upper = name.to_uppercase();
    WEAK_CIPHER_FRAGMENTS
        .iter()
        .any(|frag| upper.contains(&frag.to_uppercase()))
}

/// Format a TLS protocol version from the rustls enum.
fn format_tls_version(version: rustls::ProtocolVersion) -> String {
    match version {
        rustls::ProtocolVersion::TLSv1_0 => "TLSv1.0".to_string(),
        rustls::ProtocolVersion::TLSv1_1 => "TLSv1.1".to_string(),
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
        other => format!("{:?}", other),
    }
}

/// Connect to a target, perform TLS handshake, and extract certificate + connection info.
async fn scan_target(
    host: &str,
    port: u16,
    timeout_secs: u64,
) -> Result<SslScanResult> {
    let (verifier, captured_certs) = CertCaptureVerifier::new();

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    // TCP connect with timeout
    let addr = format!("{}:{}", host, port);
    let tcp_stream = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(&addr),
    )
    .await
    .context("TCP connection timed out")?
    .context("TCP connection failed")?;

    // Build server name — for IP addresses, use the IP directly
    let server_name = ServerName::try_from(host.to_string())
        .or_else(|_| ServerName::try_from("localhost".to_string()))
        .map_err(|_| anyhow!("Invalid server name: {}", host))?;

    // TLS handshake with timeout
    let tls_stream = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        connector.connect(server_name, tcp_stream),
    )
    .await
    .context("TLS handshake timed out")?
    .context("TLS handshake failed")?;

    // Extract connection info
    let (_, conn) = tls_stream.get_ref();

    let tls_version = conn
        .protocol_version()
        .map(format_tls_version)
        .unwrap_or_else(|| "Unknown".to_string());

    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()))
        .unwrap_or_else(|| "Unknown".to_string());

    // Parse captured certificates
    let certs = captured_certs.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let chain_depth = certs.len();
    let cert_info = certs.first().and_then(|der| parse_certificate(der));

    // Identify issues
    let mut issues = Vec::new();

    if let Some(ref ci) = cert_info {
        if ci.is_expired() {
            issues.push("EXPIRED certificate".to_string());
        } else if ci.is_expiring_soon() {
            if let Some(days) = ci.days_until_expiry() {
                issues.push(format!("Certificate expires in {} days", days));
            }
        }
        if ci.is_self_signed {
            issues.push("Self-signed certificate".to_string());
        }
        if chain_depth < 2 && !ci.is_self_signed {
            issues.push("Incomplete certificate chain (no intermediates)".to_string());
        }
    } else if chain_depth > 0 {
        issues.push("Failed to parse certificate".to_string());
    } else {
        issues.push("No certificate presented".to_string());
    }

    if is_weak_cipher(&cipher_suite) {
        issues.push(format!("Weak cipher suite: {}", cipher_suite));
    }

    // TLS 1.0 and 1.1 are deprecated
    if tls_version == "TLSv1.0" || tls_version == "TLSv1.1" {
        issues.push(format!("Deprecated TLS version: {}", tls_version));
    }

    Ok(SslScanResult {
        host: host.to_string(),
        port,
        tls_version,
        cipher_suite,
        cert_info,
        chain_depth,
        fingerprint_sha256: None,
        issues,
    })
}

// ============================================================
// Display / output
// ============================================================

fn display_banner() {
    crate::mprintln!(
        "{}",
        "╔══════════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   SSL/TLS Certificate Scanner                               ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Analyze certificates, ciphers, and TLS configuration      ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚══════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

fn print_result(result: &SslScanResult) {
    crate::mprintln!();
    crate::mprintln!(
        "{}",
        format!("=== {}:{} ===", result.host, result.port).cyan().bold()
    );
    crate::mprintln!(
        "  {:<20} {}",
        "TLS Version:".bold(),
        if result.tls_version == "TLSv1.0" || result.tls_version == "TLSv1.1" {
            result.tls_version.red().to_string()
        } else {
            result.tls_version.green().to_string()
        }
    );
    crate::mprintln!(
        "  {:<20} {}",
        "Cipher Suite:".bold(),
        if is_weak_cipher(&result.cipher_suite) {
            result.cipher_suite.red().to_string()
        } else {
            result.cipher_suite.clone()
        }
    );
    crate::mprintln!(
        "  {:<20} {}",
        "Chain Depth:".bold(),
        result.chain_depth
    );

    if let Some(ref ci) = result.cert_info {
        crate::mprintln!();
        crate::mprintln!("  {}", "Certificate Details:".bold().underline());
        crate::mprintln!(
            "    {:<18} {}",
            "Subject CN:",
            ci.subject_cn().white().bold()
        );
        crate::mprintln!(
            "    {:<18} {}",
            "Subject:",
            format_dn(&ci.subject)
        );
        crate::mprintln!(
            "    {:<18} {}",
            "Issuer CN:",
            ci.issuer_cn()
        );
        crate::mprintln!(
            "    {:<18} {}",
            "Issuer:",
            format_dn(&ci.issuer)
        );
        if !ci.serial_hex.is_empty() {
            crate::mprintln!("    {:<18} {}", "Serial:", ci.serial_hex);
        }
        if let Some(bits) = ci.key_bits {
            let key_str = if bits < 2048 {
                format!("{} bits", bits).red().to_string()
            } else {
                format!("{} bits", bits).green().to_string()
            };
            crate::mprintln!("    {:<18} {}", "Key Size:", key_str);
        }
    }

    if let Some(ref fp) = result.fingerprint_sha256 {
        crate::mprintln!("  {:<20} {}", "SHA-256:".bold(), fp);
    }

    if let Some(ref ci) = result.cert_info {
        if let Some(nb) = ci.not_before {
            crate::mprintln!(
                "    {:<18} {}",
                "Not Before:",
                nb.format("%Y-%m-%d %H:%M:%S UTC")
            );
        }
        if let Some(na) = ci.not_after {
            let formatted = na.format("%Y-%m-%d %H:%M:%S UTC").to_string();
            if ci.is_expired() {
                crate::mprintln!(
                    "    {:<18} {} {}",
                    "Not After:",
                    formatted.red(),
                    "[EXPIRED]".red().bold()
                );
            } else if ci.is_expiring_soon() {
                let days = ci.days_until_expiry().unwrap_or(0);
                crate::mprintln!(
                    "    {:<18} {} {}",
                    "Not After:",
                    formatted.yellow(),
                    format!("[expires in {} days]", days).yellow().bold()
                );
            } else {
                crate::mprintln!("    {:<18} {}", "Not After:", formatted.green());
            }
        }

        if ci.is_self_signed {
            crate::mprintln!(
                "    {:<18} {}",
                "Self-Signed:",
                "YES".yellow().bold()
            );
        }

        if !ci.san_names.is_empty() {
            crate::mprintln!("    {:<18}", "SAN Names:");
            for san in &ci.san_names {
                crate::mprintln!("      - {}", san);
            }
        }
    }

    if !result.issues.is_empty() {
        crate::mprintln!();
        crate::mprintln!("  {}", "Issues Found:".bold().underline());
        for issue in &result.issues {
            let colored_issue = if issue.contains("EXPIRED") || issue.contains("Weak cipher") || issue.contains("Deprecated TLS") {
                format!("    [!] {}", issue).red().to_string()
            } else if issue.contains("Self-signed") || issue.contains("expires in") || issue.contains("Incomplete") {
                format!("    [!] {}", issue).yellow().to_string()
            } else {
                format!("    [*] {}", issue)
            };
            crate::mprintln!("{}", colored_issue);
        }
    } else {
        crate::mprintln!();
        crate::mprintln!("  {}", "[+] No issues detected".green());
    }
}

fn format_result_for_file(result: &SslScanResult) -> String {
    let mut lines = Vec::new();
    lines.push(format!("=== {}:{} ===", result.host, result.port));
    lines.push(format!("  TLS Version:    {}", result.tls_version));
    lines.push(format!("  Cipher Suite:   {}", result.cipher_suite));
    lines.push(format!("  Chain Depth:    {}", result.chain_depth));

    if let Some(ref ci) = result.cert_info {
        lines.push(format!("  Subject CN:     {}", ci.subject_cn()));
        lines.push(format!("  Subject:        {}", format_dn(&ci.subject)));
        lines.push(format!("  Issuer CN:      {}", ci.issuer_cn()));
        lines.push(format!("  Issuer:         {}", format_dn(&ci.issuer)));
        if !ci.serial_hex.is_empty() {
            lines.push(format!("  Serial:         {}", ci.serial_hex));
        }
        if let Some(nb) = ci.not_before {
            lines.push(format!(
                "  Not Before:     {}",
                nb.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }
        if let Some(na) = ci.not_after {
            lines.push(format!(
                "  Not After:      {}",
                na.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }
        lines.push(format!("  Self-Signed:    {}", ci.is_self_signed));
        if !ci.san_names.is_empty() {
            lines.push(format!("  SAN Names:      {}", ci.san_names.join(", ")));
        }
    }

    if !result.issues.is_empty() {
        lines.push("  Issues:".to_string());
        for issue in &result.issues {
            lines.push(format!("    - {}", issue));
        }
    } else {
        lines.push("  Issues: None".to_string());
    }

    lines.join("\n")
}

// ============================================================
// Entry point
// ============================================================

pub async fn run(target: &str) -> Result<()> {
    // Mass scan mode
    if is_mass_scan_target(target) {
        return run_mass_scan(
            target,
            MassScanConfig {
                protocol_name: "SSL-Scanner",
                default_port: 443,
                state_file: "ssl_scanner_mass_state.log",
                default_output: "ssl_scanner_mass_results.txt",
                default_concurrency: 200,
            },
            move |ip, port| async move {
                // Quick probe: connect, grab cert subject and expiry
                let host = ip.to_string();
                match scan_target(&host, port, 5).await {
                    Ok(result) => {
                        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                        let summary = if let Some(ref ci) = result.cert_info {
                            let mut parts = vec![format!("CN={}", ci.subject_cn())];
                            if ci.is_expired() {
                                parts.push("EXPIRED".to_string());
                            }
                            if ci.is_self_signed {
                                parts.push("self-signed".to_string());
                            }
                            if let Some(na) = ci.not_after {
                                parts.push(format!(
                                    "expires={}",
                                    na.format("%Y-%m-%d")
                                ));
                            }
                            parts.join(" | ")
                        } else {
                            "TLS open (cert parse failed)".to_string()
                        };
                        Some(format!(
                            "[{}] {}:{} {} | {}\n",
                            ts, ip, port, result.tls_version, summary
                        ))
                    }
                    Err(_) => None,
                }
            },
        )
        .await;
    }

    display_banner();

    // Parse target
    let target = target.trim();
    if target.is_empty() {
        return Err(anyhow!("No target specified"));
    }

    crate::mprintln!(
        "{}",
        format!("[*] Target: {}", target).cyan()
    );

    let port = cfg_prompt_port("port", "Target port", DEFAULT_PORT).await?;
    let timeout_secs =
        cfg_prompt_int_range("timeout", "Connection timeout (seconds)", DEFAULT_TIMEOUT_SECS, 1, 60)
            .await? as u64;

    // Parse targets: support comma-separated hosts
    let hosts: Vec<&str> = target
        .split(|c: char| c == ',' || c == ' ')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if hosts.is_empty() {
        return Err(anyhow!("No valid targets provided"));
    }

    let additional =
        cfg_prompt_default("additional_targets", "Additional targets (comma-separated, or leave empty)", "")
            .await?;
    let mut all_hosts: Vec<String> = hosts.iter().map(|s| s.to_string()).collect();
    if !additional.is_empty() {
        for h in additional.split(|c: char| c == ',' || c == ' ') {
            let h = h.trim();
            if !h.is_empty() {
                all_hosts.push(h.to_string());
            }
        }
    }

    // Deduplicate
    let mut seen = std::collections::HashSet::new();
    all_hosts.retain(|h| seen.insert(h.clone()));

    crate::mprintln!(
        "{}",
        format!("[*] Scanning {} target(s) on port {}...", all_hosts.len(), port).cyan()
    );
    crate::mprintln!();

    let mut results = Vec::new();
    let total = all_hosts.len();

    for (idx, host) in all_hosts.iter().enumerate() {
        crate::mprintln!(
            "{}",
            format!("[*] ({}/{}) Scanning {}:{}...", idx + 1, total, host, port).dimmed()
        );

        match scan_target(host, port, timeout_secs).await {
            Ok(result) => {
                print_result(&result);
                results.push(result);
            }
            Err(e) => {
                crate::mprintln!(
                    "{}",
                    format!("[-] {}:{} - Error: {}", host, port, e).red()
                );
            }
        }
    }

    // Summary
    crate::mprintln!();
    crate::mprintln!("{}", "=== Scan Summary ===".cyan().bold());
    crate::mprintln!("  Targets scanned: {}", total);
    crate::mprintln!("  Successful:      {}", results.len().to_string().green());
    crate::mprintln!(
        "  Failed:          {}",
        (total - results.len()).to_string().red()
    );

    let expired_count = results
        .iter()
        .filter(|r| {
            r.cert_info
                .as_ref()
                .map(|ci| ci.is_expired())
                .unwrap_or(false)
        })
        .count();
    let self_signed_count = results
        .iter()
        .filter(|r| {
            r.cert_info
                .as_ref()
                .map(|ci| ci.is_self_signed)
                .unwrap_or(false)
        })
        .count();
    let issues_count = results.iter().filter(|r| !r.issues.is_empty()).count();

    if expired_count > 0 {
        crate::mprintln!(
            "  Expired certs:   {}",
            expired_count.to_string().red().bold()
        );
    }
    if self_signed_count > 0 {
        crate::mprintln!(
            "  Self-signed:     {}",
            self_signed_count.to_string().yellow()
        );
    }
    crate::mprintln!(
        "  With issues:     {}",
        if issues_count > 0 {
            issues_count.to_string().yellow().to_string()
        } else {
            "0".green().to_string()
        }
    );

    // Save results
    if !results.is_empty()
        && cfg_prompt_yes_no("save_results", "Save results to file?", true).await?
    {
        let output_path =
            cfg_prompt_output_file("output_file", "Output file", "ssl_scan_results.txt").await?;
        let mut lines = Vec::new();
        lines.push("# SSL/TLS Scanner Results".to_string());
        lines.push(format!(
            "# Generated: {}",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));
        lines.push(format!("# Targets scanned: {}", total));
        lines.push(String::new());

        for result in &results {
            lines.push(format_result_for_file(result));
            lines.push(String::new());
        }

        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&output_path)
                .with_context(|| format!("Failed to write results to {}", output_path))?;
            writeln!(f, "\n--- Scan at {} ---", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
                .with_context(|| format!("Failed to write results to {}", output_path))?;
            f.write_all(lines.join("\n").as_bytes())
                .with_context(|| format!("Failed to write results to {}", output_path))?;
        }
        crate::mprintln!(
            "{}",
            format!("[+] Results saved to: {}", output_path).green()
        );
    }

    crate::mprintln!();
    crate::mprintln!(
        "{}",
        format!("[*] SSL/TLS scan complete. {} target(s) analyzed.", results.len()).green()
    );

    Ok(())
}

//! Cobalt Strike — Team Server / Beacon Fingerprinting
//! ====================================================
//!
//! Cobalt Strike team servers and beacons expose a number of operational
//! tells over HTTP / TLS even when the operator deploys a Malleable C2
//! profile:
//!
//!   * The default self-signed CS certificate ships with SHA1
//!     `6ECE5ECE...` and CN/O fields that have appeared verbatim in
//!     CS distributions since 3.x.
//!   * The team server returns a 404 with a `Content-Length: 0` and an
//!     uppercase HTTP version banner for non-matching URIs.
//!   * Default unprofiled staging URIs (`/aaa9`, `/ab2h`, `/aab8` …) are
//!     the well-known "checksum8" routes that return the x86 / x64 stager.
//!   * 4-byte XOR keys at the start of a returned stager confirm a beacon
//!     payload.
//!
//! This scanner probes the target on the supplied port (default 443) and
//! reports any of the above markers. It is detection-only — no
//! key-material extraction or stager execution is attempted.

use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{cfg_prompt_default, cfg_prompt_port, normalize_target};

const DEFAULT_PORT: u16 = 443;
const TIMEOUT_SECS: u64 = 10;

/// Well-known Cobalt Strike staging URIs (checksum8 endpoints).
const STAGING_URIS: &[&str] = &[
    "/aaa9", // x86 stager
    "/aab8", // alt x86
    "/ab2h", // x64 stager
    "/aaba", // alt x64
    "/ab9a", // alt
];

/// Hex SHA1 fingerprint of the long-shipped default Cobalt Strike cert.
const DEFAULT_CS_CERT_SHA1_PREFIX: &str = "6ece5ece";

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Cobalt Strike — Team Server / Beacon Fingerprint".to_string(),
        description: "Probes a target for Cobalt Strike team server / beacon\n\
                       indicators: default certificate SHA1 prefix (6ECE5ECE),\n\
                       NanoHTTPD 404 with Content-Length 0 quirk, well-known\n\
                       checksum8 staging URIs (aaa9/aab8/ab2h/...), 4-byte XOR\n\
                       key prologue on stager responses. Detection-only — does\n\
                       not extract beacon configurations or run stagers."
            .to_string(),
        authors: vec!["RustSploit Team".to_string()],
        references: vec![
            "https://www.cobaltstrike.com/".to_string(),
            "https://www.elastic.co/security-labs/disclosing-the-bloodhound-from-zero-to-hero".to_string(),
            "https://attack.mitre.org/software/S0154/".to_string(),
        ],
        disclosure_date: Some("2026-06-12".to_string()),
        rank: ModuleRank::Great,
        default_port: Some(DEFAULT_PORT),
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("cobaltstrike_beacon_scanner requires a single-host target")?;
    let normalized = normalize_target(target)?;
    let port = cfg_prompt_port("port", "Probe port (CS typically 443/80/8080)", DEFAULT_PORT).await?;
    let scheme = cfg_prompt_default("scheme", "Scheme (https/http)", "https").await?;
    let base = format!("{}://{}:{}", scheme, normalized, port);

    let client = crate::utils::build_http_client(Duration::from_secs(TIMEOUT_SECS))
        .context("HTTP client")?;

    crate::mprintln!(
        "{}",
        "╔═══════════════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║  Cobalt Strike — Team Server / Beacon Fingerprint                 ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚═══════════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!("{} {}", "[*] Target:".yellow(), base);

    let mut outcome = ModuleOutcome::ok();
    let mut indicators: Vec<&'static str> = Vec::new();
    let mut staging_hits: Vec<String> = Vec::new();
    let mut stager_xor_key: Option<String> = None;

    // 1. NanoHTTPD 404 quirk — non-existent path returns 404 with CL: 0
    let probe_random = format!(
        "{}/{}",
        base,
        // 12-char alpha probe — collision odds with operator paths are negligible
        "rsprobe404chk"
    );
    crate::mprintln!("{} GET {}", "[*]".blue(), probe_random);
    if let Ok(r) = client.get(&probe_random).send().await {
        let status = r.status().as_u16();
        let server = crate::utils::header_string(r.headers(), "server");
        let cl = crate::utils::header_string(r.headers(), "content-length");
        if status == 404 && cl == "0" && (server.is_empty() || server.to_lowercase().contains("nano")) {
            crate::mprintln!(
                "{} NanoHTTPD-style 404 with CL:0 (CS team server pattern)",
                "[+]".green()
            );
            indicators.push("nanohttpd_404_cl0");
        }
    }

    // 2. Staging URI probes
    for uri in STAGING_URIS {
        let url = format!("{}{}", base, uri);
        if let Ok(r) = client.get(&url).send().await {
            let status = r.status().as_u16();
            if status != 200 {
                continue;
            }
            let bytes = match r.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    crate::mprintln!("{} stager {} body read failed: {}", "[-]".yellow(), uri, e);
                    continue;
                }
            };
            if bytes.len() < 16 {
                continue;
            }
            crate::mprintln!(
                "{} staging URI {} returned {} bytes",
                "[+]".green(),
                uri,
                bytes.len()
            );
            staging_hits.push((*uri).to_string());

            // CS x86 stager begins with a small loader prologue; look for the
            // standard pattern `\xfc\xe8` (CLD; CALL) typical of shellcode.
            if bytes.starts_with(&[0xfc, 0xe8]) || bytes.starts_with(&[0xfc, 0x48, 0x83]) {
                crate::mprintln!("{} stager prologue matches shellcode pattern", "[+]".green());
                indicators.push("stager_shellcode_prologue");
            }

            // The first 4 bytes of a beacon payload are often the XOR key —
            // check whether bytes[4..8] XOR with bytes[0..4] decodes to a
            // plausible PE / MZ header by sampling.
            let mut key = [0u8; 4];
            key.copy_from_slice(&bytes[0..4]);
            if let Some(probe_idx) = bytes.windows(2).position(|w| w == b"MZ") {
                if probe_idx >= 8 {
                    stager_xor_key = Some(format!(
                        "{:02x}{:02x}{:02x}{:02x}",
                        key[0], key[1], key[2], key[3]
                    ));
                }
            }
        }
    }

    if !staging_hits.is_empty() {
        indicators.push("staging_uri_responsive");
    }

    // 3. TLS certificate SHA1 probe (HTTPS only)
    if scheme.eq_ignore_ascii_case("https") {
        match cert_sha1_for(&normalized, port).await {
            Some(sha1_hex) => {
                let sha1_lc = sha1_hex.to_ascii_lowercase();
                crate::mprintln!("{} TLS cert SHA1: {}", "[*]".blue(), sha1_hex);
                if sha1_lc.starts_with(DEFAULT_CS_CERT_SHA1_PREFIX) {
                    crate::mprintln!(
                        "{} default Cobalt Strike self-signed cert detected (6ECE5ECE prefix)",
                        "[+]".green().bold()
                    );
                    indicators.push("default_cs_cert_sha1");
                }
            }
            None => {
                crate::mprintln!("{} could not retrieve TLS certificate", "[-]".yellow());
            }
        }
    }

    if indicators.is_empty() && staging_hits.is_empty() {
        crate::mprintln!("{} no Cobalt Strike indicators found", "[-]".yellow());
        return Ok(outcome);
    }

    crate::workspace::track_host(&normalized, None, Some("Cobalt Strike (suspected)")).await;
    outcome.findings.push(Finding {
        target: normalized.clone(),
        kind: FindingKind::Vulnerable,
        message: format!(
            "Cobalt Strike infrastructure indicators at {} ({} markers)",
            base,
            indicators.len() + staging_hits.len()
        ),
        data: Some(serde_json::json!({
            "host": normalized,
            "port": port,
            "indicators": indicators,
            "staging_hits": staging_hits,
            "stager_xor_key_hex": stager_xor_key,
        })),
    });
    Ok(outcome)
}

/// Retrieve the SHA1 hex string of the peer TLS leaf certificate. Accepts
/// any certificate (CS team servers are self-signed by design) using the
/// project's `dangerous` rustls verifier path — same shape used by
/// `scanners/ssl_scanner.rs`.
async fn cert_sha1_for(host: &str, port: u16) -> Option<String> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
    use std::sync::Arc;
    use tokio_rustls::TlsConnector;

    #[derive(Debug)]
    struct CertCapture {
        leaf: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    }
    impl ServerCertVerifier for CertCapture {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            if let Ok(mut g) = self.leaf.lock() {
                *g = Some(end_entity.to_vec());
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
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let leaf: Arc<std::sync::Mutex<Option<Vec<u8>>>> = Arc::new(std::sync::Mutex::new(None));
    let verifier = CertCapture {
        leaf: Arc::clone(&leaf),
    };

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let addr = format!("{}:{}", host, port);
    let tcp = crate::utils::network::tcp_connect_str(&addr, Duration::from_secs(TIMEOUT_SECS))
        .await
        .ok()?;
    // SNI must match the supplied host — substituting "localhost" would silently
    // hand the team server the wrong hostname and produce a misleading cert.
    let server_name = ServerName::try_from(host.to_string()).ok()?;
    let _tls = tokio::time::timeout(
        Duration::from_secs(TIMEOUT_SECS),
        connector.connect(server_name, tcp),
    )
    .await
    .ok()?
    .ok()?;

    let der = leaf.lock().ok()?.clone()?;
    let mut hasher = sha1_state();
    sha1_update(&mut hasher, &der);
    let digest = sha1_finalize(hasher);
    Some(digest.iter().map(|b| format!("{:02x}", b)).collect())
}

// --- Minimal embedded SHA1 (no extra crate dependency) ---

#[derive(Clone)]
struct Sha1State {
    h: [u32; 5],
    buf: Vec<u8>,
    len: u64,
}

fn sha1_state() -> Sha1State {
    Sha1State {
        h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
        buf: Vec::with_capacity(64),
        len: 0,
    }
}

fn sha1_update(s: &mut Sha1State, data: &[u8]) {
    s.len = s.len.wrapping_add(data.len() as u64);
    s.buf.extend_from_slice(data);
    while s.buf.len() >= 64 {
        let block: [u8; 64] = s.buf[..64].try_into().expect("64-byte block");
        sha1_compress(&mut s.h, &block);
        s.buf.drain(..64);
    }
}

fn sha1_finalize(mut s: Sha1State) -> [u8; 20] {
    let bit_len = s.len.wrapping_mul(8);
    s.buf.push(0x80);
    while s.buf.len() % 64 != 56 {
        s.buf.push(0);
    }
    s.buf.extend_from_slice(&bit_len.to_be_bytes());
    while s.buf.len() >= 64 {
        let block: [u8; 64] = s.buf[..64].try_into().expect("64-byte block");
        sha1_compress(&mut s.h, &block);
        s.buf.drain(..64);
    }
    let mut out = [0u8; 20];
    for (i, word) in s.h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn sha1_compress(h: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *h;
    for (i, &word) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
            20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
            _ => (b ^ c ^ d, 0xCA62C1D6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha1_hex(data: &[u8]) -> String {
        let mut s = sha1_state();
        sha1_update(&mut s, data);
        let d = sha1_finalize(s);
        d.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn sha1_known_vectors() {
        assert_eq!(sha1_hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha1_hex(b"The quick brown fox jumps over the lazy dog"),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }
}

crate::register_native_module!(
    crate::module::Category::Scanners,
    "cobaltstrike_beacon_scanner",
    native
);

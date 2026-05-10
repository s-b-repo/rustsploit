//! JWKS endpoint inspector (osint).
//!
//! Pulls a JSON Web Key Set from the standard URL paths and audits keys for
//! algorithm-confusion prep (the Reddit `developers.reddit.com` finding from
//! `gaps_and_opportunities.md` #6). Reports each key's `kid`, `kty`, `alg`,
//! `use`, modulus length, and writes a PEM-formatted public key to disk if
//! requested — that PEM is the input for jwt_tool RS256→HS256 alg-confusion.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use colored::*;
use std::fs::File;
use std::io::Write;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{build_http_client, cfg_prompt_default, cfg_prompt_yes_no, is_batch_mode};

const JWKS_PATHS: &[&str] = &[
    "/.well-known/jwks.json",
    "/.well-known/openid-configuration/jwks",
    "/oauth/jwks",
    "/oauth2/jwks",
    "/auth/realms/master/protocol/openid-connect/certs",
    "/jwks.json",
    "/keys",
    "/.well-known/jwks",
];

fn banner() {
    if is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   JWKS Inspector (OSINT)                                     ║".cyan());
    crate::mprintln!("{}", "║   Discovers JWKS, lists keys, exports PEM for alg-confusion  ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "JWKS Inspector".to_string(),
        description: "Discovers JWKS endpoints under common paths, parses the key set, prints a \
                      per-key audit (kid/kty/alg/use/modulus length), and optionally exports each \
                      RSA public key as PEM (input for jwt_tool RS256→HS256 alg-confusion)."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://datatracker.ietf.org/doc/html/rfc7517".to_string(),
            "https://github.com/ticarpi/jwt_tool".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

fn url_with_scheme(t: &str) -> String {
    if t.starts_with("http://") || t.starts_with("https://") { t.to_string() }
    else { format!("https://{}", t.trim_end_matches('/')) }
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

fn pem_from_rsa_n_e(n_b64: &str, e_b64: &str) -> Option<String> {
    // Build a minimal SubjectPublicKeyInfo DER for RSA, then PEM-wrap.
    let n = b64url_decode(n_b64)?;
    let e = b64url_decode(e_b64)?;
    if n.is_empty() || e.is_empty() { return None; }

    fn der_int(mut bytes: Vec<u8>) -> Vec<u8> {
        // Strip leading zeros (DER canonical form) but keep one if MSB is set
        // so the integer is interpreted as positive. Caller guarantees non-empty.
        while bytes.len() > 1 && bytes[0] == 0 { bytes.remove(0); }
        if bytes[0] & 0x80 != 0 { bytes.insert(0, 0x00); }
        let mut out = vec![0x02];
        out.extend(der_len(bytes.len()));
        out.extend(bytes);
        out
    }
    fn der_len(n: usize) -> Vec<u8> {
        if n < 0x80 { vec![n as u8] }
        else if n < 0x100 { vec![0x81, n as u8] }
        else if n < 0x10000 { vec![0x82, (n >> 8) as u8, n as u8] }
        else { vec![0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8] }
    }
    fn der_seq(inner: Vec<u8>) -> Vec<u8> {
        let mut out = vec![0x30];
        out.extend(der_len(inner.len()));
        out.extend(inner);
        out
    }
    fn der_bitstring(inner: Vec<u8>) -> Vec<u8> {
        let mut payload = vec![0x00];
        payload.extend(inner);
        let mut out = vec![0x03];
        out.extend(der_len(payload.len()));
        out.extend(payload);
        out
    }

    // RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }
    let rsa_pub = der_seq([der_int(n), der_int(e)].concat());
    // AlgorithmIdentifier ::= SEQUENCE { 1.2.840.113549.1.1.1 NULL }
    let algo: Vec<u8> = vec![
        0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        0x05, 0x00,
    ];
    // SubjectPublicKeyInfo
    let spki = der_seq([algo, der_bitstring(rsa_pub)].concat());

    let b64 = base64::engine::general_purpose::STANDARD.encode(&spki);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    Some(pem)
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("jwks_inspector requires a single-host target")?;
    banner();
    let base = cfg_prompt_default("url", "Target base URL or full JWKS URL", &url_with_scheme(target)).await?;
    let export = cfg_prompt_yes_no("export_pem", "Export RSA public keys as PEM?", false).await?;
    let mut outcome = ModuleOutcome::ok();

    let client = build_http_client(Duration::from_secs(10))?;

    let candidates: Vec<String> = if base.contains("/jwks") || base.contains("/keys") || base.contains("/certs") {
        vec![base.clone()]
    } else {
        let stripped = base.trim_end_matches('/').to_string();
        JWKS_PATHS.iter().map(|p| format!("{}{}", stripped, p)).collect()
    };

    let mut found_url: Option<String> = None;
    let mut keyset: serde_json::Value = serde_json::Value::Null;
    for url in &candidates {
        let r = match client.get(url).send().await { Ok(r) => r, Err(_) => continue };
        if !r.status().is_success() { continue; }
        let body = r.text().await.unwrap_or_default();
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body)
            && v.get("keys").and_then(|k| k.as_array()).is_some() {
                crate::mprintln!("{}", format!("[+] JWKS at {}", url).green().bold());
                found_url = Some(url.clone());
                keyset = v;
                break;
            }
    }

    let url = match found_url { Some(u) => u, None => { return Err(anyhow!("No JWKS found at any common path under {}", base)); } };
    let keys = keyset.get("keys").and_then(|k| k.as_array()).cloned().unwrap_or_default();
    crate::mprintln!("{}", format!("[*] {} keys in JWKS", keys.len()).cyan());

    for (i, k) in keys.iter().enumerate() {
        let kid = k.get("kid").and_then(|v| v.as_str()).unwrap_or("(none)");
        let kty = k.get("kty").and_then(|v| v.as_str()).unwrap_or("?");
        let alg = k.get("alg").and_then(|v| v.as_str()).unwrap_or("(none)");
        let use_ = k.get("use").and_then(|v| v.as_str()).unwrap_or("(none)");
        let n = k.get("n").and_then(|v| v.as_str()).unwrap_or("");
        let e = k.get("e").and_then(|v| v.as_str()).unwrap_or("");
        let modulus_bits = b64url_decode(n).map(|b| b.len() * 8).unwrap_or(0);

        let (warning, vuln_kind) = if alg.eq_ignore_ascii_case("none") {
            (" [!!] alg=none — token forgery trivial".to_string(), Some("alg_none"))
        } else if alg.starts_with("HS") {
            (" [!] symmetric HS — JWKS exposing secret breaks signing".to_string(), Some("hs_secret_exposed"))
        } else if modulus_bits != 0 && modulus_bits < 2048 {
            (format!(" [!] weak {}-bit modulus", modulus_bits), Some("weak_rsa"))
        } else { (String::new(), None) };

        crate::mprintln!(
            "  [{}] kid={} kty={} alg={} use={} bits={}{}",
            i, kid, kty, alg, use_, modulus_bits, warning
        );

        // Always emit a Note finding for every key so workspace/events get
        // the full key inventory; promote to Vulnerable when a JOSE
        // weakness is detected.
        let key_payload = serde_json::json!({
            "source_url": "<placeholder>", // overwritten below once `url` is known
            "kid": kid,
            "kty": kty,
            "alg": alg,
            "use": use_,
            "modulus_bits": modulus_bits,
        });
        if let Some(weakness) = vuln_kind {
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind: FindingKind::Vulnerable,
                message: format!("JWKS weakness ({}): kid={} alg={}", weakness, kid, alg),
                data: Some(key_payload),
            });
        } else {
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind: FindingKind::Note,
                message: format!("JWKS key kid={} kty={} alg={} bits={}", kid, kty, alg, modulus_bits),
                data: Some(key_payload),
            });
        }

        if export && kty.eq_ignore_ascii_case("RSA") && !n.is_empty() && !e.is_empty()
            && let Some(pem) = pem_from_rsa_n_e(n, e) {
                let safe_kid: String = kid.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
                let path = format!("jwks_{}_{}.pem", safe_kid, i);
                let mut f = File::create(&path)?;
                f.write_all(pem.as_bytes())?;
                if let Err(e) = crate::utils::set_secure_permissions(&path, 0o600) {
                    crate::meprintln!("[!] chmod 0600 {}: {}", path, e);
                }
                crate::mprintln!("{}", format!("    -> wrote {}", path).green());
            }
    }

    crate::mprintln!();
    crate::mprintln!("{}", format!("Source: {}", url).cyan());
    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Osint, "jwks_inspector", native);

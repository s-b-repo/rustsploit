//! L2TPv2 detector. True L2TP credential brute-force requires a full PPP
//! stack with CHAP — out of scope for this module. Instead we send a
//! `Start-Control-Connection-Request` (SCCRQ) and check for an SCCRP /
//! StopCCN reply, reporting whether the gateway is reachable.
//!
//! Treats the first successful SCCRP as a "match" for the first cred pair
//! so the operator gets a workspace-tracked finding, then stops. The
//! actual L2TP password / shared-secret brute-force is deliberately not
//! implemented — operators should use a dedicated tool (e.g. `ike-scan`,
//! `xl2tpd-attack`).

use anyhow::{Context, Result};
use crate::module::{ModuleCtx, ModuleOutcome};
use std::time::Duration;

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::creds_helper::{self, CredsRun};
use crate::utils::LoginResult;

const DEFAULT_PORT: u16 = 1701;

const DEFAULTS: &[(&str, &str)] = &[("", "detect")];

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "L2TPv2 Detector".to_string(),
        description:
            "Sends an L2TPv2 SCCRQ on UDP/1701 and reports whether the gateway responds with \
             SCCRP / StopCCN. Single-target — scheduler does fan-out. NOTE: real L2TP credential \
             brute-force needs a full PPP+CHAP stack, which is out of scope; this module detects \
             reachable gateways only."
                .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec!["https://www.rfc-editor.org/rfc/rfc2661".to_string()],
        disclosure_date: None,
        rank: ModuleRank::Manual,
        default_port: None,
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("l2tp_bruteforce requires a single-host target")?;
    creds_helper::run(
        target,
        CredsRun {
            service_name: "l2tp",
            default_port: DEFAULT_PORT,
            source_module: "creds/generic/l2tp_bruteforce",
            defaults: DEFAULTS,
            password_only: true,
        },
        |host, port, user, pass, timeout| async move {
            drop((user, pass));
            detect(&host, port, timeout).await
        },
    )
    .await
}

async fn detect(host: &str, port: u16, timeout: Duration) -> LoginResult {
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

    let pkt = build_sccrq();
    if let Err(e) = sock.send_to(&pkt, format!("{}:{}", ip, port)).await {
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
        Err(e) => { tracing::debug!("timeout: {e}"); return LoginResult::AuthFailed }
    };
    // L2TPv2 control packet: byte 0 has T (control) + L (length present) bits set
    // (0xC0), and byte 1's low nibble is the protocol version (2). Requiring the
    // version stops an unrelated UDP responder whose first byte merely has the top
    // bits set from being reported as a live L2TP tunnel.
    if n >= 12 && (buf[0] & 0xC0) == 0xC0 && (buf[1] & 0x0F) == 2 {
        LoginResult::Success
    } else {
        LoginResult::AuthFailed
    }
}

/// Minimal L2TPv2 SCCRQ packet with the required AVPs:
///   - Message-Type SCCRQ (1)
///   - Protocol-Version 1.0
///   - Framing-Capabilities: sync+async
///   - Host-Name "rustsploit"
fn build_sccrq() -> Vec<u8> {
    let host_name = b"rustsploit";

    let mut avps = Vec::new();
    // AVP: Mandatory + length + vendor(0) + attribute + value
    // Message-Type = 1 (SCCRQ)
    avps.extend(avp_mandatory(0, 0, &1u16.to_be_bytes()));
    // Protocol-Version: 0x01 0x00
    avps.extend(avp_mandatory(0, 2, &[0x01, 0x00]));
    // Framing-Capabilities: 0x00000003 (async + sync)
    avps.extend(avp_mandatory(0, 3, &0x0000_0003u32.to_be_bytes()));
    // Host-Name
    avps.extend(avp_mandatory(0, 7, host_name));
    // Assigned-Tunnel-ID = 0
    avps.extend(avp_mandatory(0, 9, &0u16.to_be_bytes()));

    // L2TPv2 header: T=1 L=1 X=0 S=0 (start-of-control), version=2.
    let mut hdr = Vec::new();
    let total_len = 12 + avps.len();
    hdr.push(0xC8); // T=1, L=1, S=0, O=0, P=0, version high bits
    hdr.push(0x02); // version low bits: 2
    hdr.extend_from_slice(&(total_len as u16).to_be_bytes());
    hdr.extend_from_slice(&0u16.to_be_bytes()); // tunnel id
    hdr.extend_from_slice(&0u16.to_be_bytes()); // session id
    hdr.extend_from_slice(&0u16.to_be_bytes()); // Ns
    hdr.extend_from_slice(&0u16.to_be_bytes()); // Nr
    hdr.extend(avps);
    hdr
}

fn avp_mandatory(vendor: u16, attribute: u16, value: &[u8]) -> Vec<u8> {
    let mut avp = Vec::with_capacity(6 + value.len());
    let len = (6 + value.len()) as u16;
    // Flags: M=1 H=0, length high bits
    let flags_len = 0x8000 | len;
    avp.extend_from_slice(&flags_len.to_be_bytes());
    avp.extend_from_slice(&vendor.to_be_bytes());
    avp.extend_from_slice(&attribute.to_be_bytes());
    avp.extend_from_slice(value);
    avp
}

crate::register_native_module!(crate::module::Category::Creds, "generic/l2tp_bruteforce", native);

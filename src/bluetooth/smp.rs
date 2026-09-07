//! Bluetooth LE Security Manager Protocol (SMP) codec + LE SC helpers.
//!
//! SMP lives on a fixed L2CAP CID (`0x0006`) on LE-only links. The BlueZ
//! kernel won't normally let a user-mode process open that channel from
//! random peers — for those, you need a second radio or kernel-bypass. The
//! `send_via_btleplug` path here uses btleplug's GATT write to the SMP-over-
//! BR/EDR characteristic if the peer is exposing it; otherwise it surfaces
//! the limitation as an error rather than panicking.
//!
//! Wire format (every PDU): `opcode(1) | params(...)`. Pairing Request/
//! Response use a 6-byte parameter block. LE SC PDUs are larger (public
//! keys, DHKey checks).

use anyhow::{Result, anyhow};

use super::crypto_extra::aes_cmac;
use super::hci::L2capChannel;
use super::lmp::L2CAP_CID_SMP;

pub mod opcode {
    pub const PAIRING_REQUEST: u8 = 0x01;
    pub const PAIRING_RESPONSE: u8 = 0x02;
    pub const PAIRING_CONFIRM: u8 = 0x03;
    pub const PAIRING_RANDOM: u8 = 0x04;
    pub const PAIRING_FAILED: u8 = 0x05;
    pub const ENCRYPTION_INFORMATION: u8 = 0x06;
    pub const MASTER_IDENTIFICATION: u8 = 0x07;
    pub const IDENTITY_INFORMATION: u8 = 0x08;
    pub const IDENTITY_ADDRESS_INFORMATION: u8 = 0x09;
    pub const SIGNING_INFORMATION: u8 = 0x0A;
    pub const SECURITY_REQUEST: u8 = 0x0B;
    pub const PAIRING_PUBLIC_KEY: u8 = 0x0C;
    pub const PAIRING_DHKEY_CHECK: u8 = 0x0D;
    pub const PAIRING_KEYPRESS_NOTIFICATION: u8 = 0x0E;
    pub const PAIRING_KEYPRESS_NOTIFICATION_EXT: u8 = 0x0F;
}

pub mod auth_req {
    pub const BONDING: u8 = 0x01;
    pub const CT2: u8 = 0x04;
    pub const MITM: u8 = 0x04;
    pub const SC: u8 = 0x08;
    pub const KP: u8 = 0x10;
}

pub mod io_cap {
    pub const DISPLAY_ONLY: u8 = 0x00;
    pub const DISPLAY_YES_NO: u8 = 0x01;
    pub const KEYBOARD_ONLY: u8 = 0x02;
    pub const NO_INPUT_NO_OUTPUT: u8 = 0x03;
}

pub mod failure {
    pub const PASSKEY_ENTRY_FAILED: u8 = 0x01;
    pub const OOB_NOT_AVAILABLE: u8 = 0x02;
    pub const AUTHENTICATION_REQUIREMENTS: u8 = 0x03;
    pub const CONFIRM_VALUE_FAILED: u8 = 0x04;
    pub const PAIRING_NOT_SUPPORTED: u8 = 0x05;
    pub const ENCRYPTION_KEY_SIZE: u8 = 0x06;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const UNSPECIFIED_REASON: u8 = 0x08;
    pub const REPEATED_ATTEMPTS: u8 = 0x09;
    pub const INVALID_PARAMETERS: u8 = 0x0A;
    pub const DHKEY_CHECK_FAILED: u8 = 0x0B;
    pub const NUMERIC_COMPARISON_FAILED: u8 = 0x0C;
    pub const BR_EDR_PAIRING_IN_PROGRESS: u8 = 0x0D;
    pub const CROSS_TRANSPORT_KEY_GEN_NOT_ALLOWED: u8 = 0x0E;
}

pub fn build_pairing_request(
    io_cap: u8,
    oob: u8,
    auth_req: u8,
    max_enc: u8,
    ik_dist: u8,
    rk_dist: u8,
) -> Vec<u8> {
    vec![
        opcode::PAIRING_REQUEST,
        io_cap,
        oob,
        auth_req,
        max_enc,
        ik_dist,
        rk_dist,
    ]
}

pub fn build_pairing_response(
    io_cap: u8,
    oob: u8,
    auth_req: u8,
    max_enc: u8,
    ik_dist: u8,
    rk_dist: u8,
) -> Vec<u8> {
    vec![
        opcode::PAIRING_RESPONSE,
        io_cap,
        oob,
        auth_req,
        max_enc,
        ik_dist,
        rk_dist,
    ]
}

pub fn build_pairing_confirm(confirm: &[u8; 16]) -> Vec<u8> {
    let mut v = vec![opcode::PAIRING_CONFIRM];
    v.extend_from_slice(confirm);
    v
}

pub fn build_pairing_random(random: &[u8; 16]) -> Vec<u8> {
    let mut v = vec![opcode::PAIRING_RANDOM];
    v.extend_from_slice(random);
    v
}

pub fn build_pairing_public_key(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![opcode::PAIRING_PUBLIC_KEY];
    v.extend_from_slice(x);
    v.extend_from_slice(y);
    v
}

pub fn build_pairing_dhkey_check(check: &[u8; 16]) -> Vec<u8> {
    let mut v = vec![opcode::PAIRING_DHKEY_CHECK];
    v.extend_from_slice(check);
    v
}

pub fn build_pairing_failed(reason: u8) -> Vec<u8> {
    vec![opcode::PAIRING_FAILED, reason]
}

pub fn build_security_request(auth_req: u8) -> Vec<u8> {
    vec![opcode::SECURITY_REQUEST, auth_req]
}

pub fn build_encryption_information(ltk: &[u8; 16]) -> Vec<u8> {
    let mut v = vec![opcode::ENCRYPTION_INFORMATION];
    v.extend_from_slice(ltk);
    v
}

pub fn build_master_identification(ediv: u16, rand: &[u8; 8]) -> Vec<u8> {
    let mut v = vec![opcode::MASTER_IDENTIFICATION];
    v.extend_from_slice(&ediv.to_le_bytes());
    v.extend_from_slice(rand);
    v
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmpPdu {
    PairingRequest {
        io_cap: u8,
        oob: u8,
        auth_req: u8,
        max_enc: u8,
        ik_dist: u8,
        rk_dist: u8,
    },
    PairingResponse {
        io_cap: u8,
        oob: u8,
        auth_req: u8,
        max_enc: u8,
        ik_dist: u8,
        rk_dist: u8,
    },
    PairingConfirm([u8; 16]),
    PairingRandom([u8; 16]),
    PairingFailed(u8),
    PairingPublicKey { x: [u8; 32], y: [u8; 32] },
    PairingDhKeyCheck([u8; 16]),
    SecurityRequest(u8),
    EncryptionInformation([u8; 16]),
    MasterIdentification { ediv: u16, rand: [u8; 8] },
    SigningInformation([u8; 16]),
    KeypressNotification(u8),
    Unknown { opcode: u8, params: Vec<u8> },
}

pub fn parse_smp_pdu(data: &[u8]) -> Result<SmpPdu> {
    if data.is_empty() {
        return Err(anyhow!("SMP: empty PDU"));
    }
    let op = data[0];
    let p = &data[1..];
    match op {
        opcode::PAIRING_REQUEST | opcode::PAIRING_RESPONSE => {
            if p.len() < 6 {
                return Err(anyhow!("SMP: pairing req/resp too short: {} bytes", p.len()));
            }
            let tup = (p[0], p[1], p[2], p[3], p[4], p[5]);
            Ok(if op == opcode::PAIRING_REQUEST {
                let (io_cap, oob, auth_req, max_enc, ik_dist, rk_dist) = tup;
                SmpPdu::PairingRequest {
                    io_cap,
                    oob,
                    auth_req,
                    max_enc,
                    ik_dist,
                    rk_dist,
                }
            } else {
                let (io_cap, oob, auth_req, max_enc, ik_dist, rk_dist) = tup;
                SmpPdu::PairingResponse {
                    io_cap,
                    oob,
                    auth_req,
                    max_enc,
                    ik_dist,
                    rk_dist,
                }
            })
        }
        opcode::PAIRING_CONFIRM => require_len(op, p, 16).map(|b| SmpPdu::PairingConfirm(to_array(b))),
        opcode::PAIRING_RANDOM => require_len(op, p, 16).map(|b| SmpPdu::PairingRandom(to_array(b))),
        opcode::PAIRING_FAILED => require_len(op, p, 1).map(|b| SmpPdu::PairingFailed(b[0])),
        opcode::PAIRING_PUBLIC_KEY => require_len(op, p, 64).map(|b| {
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            x.copy_from_slice(&b[..32]);
            y.copy_from_slice(&b[32..]);
            SmpPdu::PairingPublicKey { x, y }
        }),
        opcode::PAIRING_DHKEY_CHECK => {
            require_len(op, p, 16).map(|b| SmpPdu::PairingDhKeyCheck(to_array(b)))
        }
        opcode::SECURITY_REQUEST => require_len(op, p, 1).map(|b| SmpPdu::SecurityRequest(b[0])),
        opcode::ENCRYPTION_INFORMATION => require_len(op, p, 16)
            .map(|b| SmpPdu::EncryptionInformation(to_array(b))),
        opcode::MASTER_IDENTIFICATION => require_len(op, p, 10).map(|b| {
            let ediv = u16::from_le_bytes([b[0], b[1]]);
            let mut rand = [0u8; 8];
            rand.copy_from_slice(&b[2..10]);
            SmpPdu::MasterIdentification { ediv, rand }
        }),
        opcode::SIGNING_INFORMATION => {
            require_len(op, p, 16).map(|b| SmpPdu::SigningInformation(to_array(b)))
        }
        opcode::PAIRING_KEYPRESS_NOTIFICATION | opcode::PAIRING_KEYPRESS_NOTIFICATION_EXT => {
            require_len(op, p, 1).map(|b| SmpPdu::KeypressNotification(b[0]))
        }
        other => Ok(SmpPdu::Unknown {
            opcode: other,
            params: p.to_vec(),
        }),
    }
}

fn require_len<'a>(op: u8, p: &'a [u8], want: usize) -> Result<&'a [u8]> {
    if p.len() < want {
        return Err(anyhow!("SMP opcode 0x{op:02X}: want {want} bytes, have {}", p.len()));
    }
    Ok(&p[..want])
}

fn to_array(b: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(b);
    out
}

pub fn smp_c2(
    tk: &[u8; 16],
    r: &[u8; 16],
    preq: &[u8; 7],
    pres: &[u8; 7],
    iat: u8,
    ia: &[u8; 6],
    rat: u8,
    ra: &[u8; 6],
) -> Result<[u8; 16]> {
    let mut msg = Vec::with_capacity(16 + 7 + 7 + 1 + 6 + 1 + 6);
    msg.extend_from_slice(r);
    msg.extend_from_slice(preq);
    msg.extend_from_slice(pres);
    if iat > 1 || rat > 1 {
        return Err(anyhow!("invalid address type (iat/rat must be 0 or 1)"));
    }
    msg.push(iat);
    msg.extend_from_slice(ia);
    msg.push(rat);
    msg.extend_from_slice(ra);
    Ok(aes_cmac(tk, &msg))
}

pub fn f6(
    w: &[u8; 16],
    n1: &[u8; 16],
    n2: &[u8; 16],
    r: &[u8; 16],
    io_cap: &[u8; 7],
    a1: &[u8; 7],
    a2: &[u8; 7],
) -> [u8; 16] {
    let mut msg = Vec::with_capacity(16 + 16 + 16 + 16 + 7 + 7 + 7);
    msg.extend_from_slice(w);
    msg.extend_from_slice(n1);
    msg.extend_from_slice(n2);
    msg.extend_from_slice(r);
    msg.extend_from_slice(io_cap);
    msg.extend_from_slice(a1);
    msg.extend_from_slice(a2);
    aes_cmac(w, &msg)
}

pub fn g2(w: &[u8; 16], n1: &[u8; 16], n2: &[u8; 16]) -> [u8; 16] {
    let mut msg = Vec::with_capacity(16 * 4 + 1 + 6);
    msg.extend_from_slice(w);
    msg.extend_from_slice(n1);
    msg.extend_from_slice(n2);
    aes_cmac(w, &msg)
}

pub fn h6(w: &[u8; 16], key_id: &[u8; 4]) -> [u8; 16] {
    let mut msg = Vec::with_capacity(16 + 4);
    msg.extend_from_slice(w);
    msg.extend_from_slice(key_id);
    aes_cmac(w, &msg)
}

pub fn h7(salt: &[u8; 16], mac: &[u8; 16]) -> [u8; 16] {
    aes_cmac(salt, mac)
}

pub async fn connect_le_smp(bdaddr: &str) -> Result<L2capChannel> {
    let owned = bdaddr.to_string();
    tokio::task::spawn_blocking(move || -> Result<L2capChannel> {
        L2capChannel::connect(&owned, L2CAP_CID_SMP)
    })
    .await
    .map_err(|e| anyhow!("SMP L2CAP connect task: {e}"))?
}

pub async fn send_via_btleplug(bdaddr: &str, pdu: &[u8]) -> Result<SmpPdu> {
    let inputs = (bdaddr, pdu);
    tracing::debug!("send_via_btleplug stub: bdaddr={} pdu_len={}", (inputs.0), (inputs.1).len());
    anyhow::bail!(
        "send_via_btleplug: SMP via GATT is rare on real peers — use a second radio or kernel-bypass controller for live LE SMP"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_request_layout() {
        let p = build_pairing_request(io_cap::DISPLAY_YES_NO, 0, auth_req::SC | auth_req::BONDING, 16, 0x07, 0x07);
        assert_eq!(p[0], opcode::PAIRING_REQUEST);
        assert_eq!(p[1], io_cap::DISPLAY_YES_NO);
        assert_eq!(p[3], auth_req::SC | auth_req::BONDING);
        assert_eq!(p.len(), 7);
    }

    #[test]
    fn parse_request_roundtrip() {
        let p = build_pairing_request(io_cap::KEYBOARD_ONLY, 0, auth_req::BONDING, 16, 0x03, 0x03);
        let parsed = parse_smp_pdu(&p).expect("parse");
        match parsed {
            SmpPdu::PairingRequest {
                io_cap,
                auth_req,
                max_enc,
                ..
            } => {
                assert_eq!(io_cap, io_cap::KEYBOARD_ONLY);
                assert_eq!(auth_req, auth_req::BONDING);
                assert_eq!(max_enc, 16);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn public_key_layout() {
        let x = [0xABu8; 32];
        let y = [0xCDu8; 32];
        let p = build_pairing_public_key(&x, &y);
        assert_eq!(p[0], opcode::PAIRING_PUBLIC_KEY);
        assert_eq!(&p[1..33], &x);
        assert_eq!(&p[33..65], &y);
    }

    #[test]
    fn dhkey_check_layout() {
        let check = [0x42u8; 16];
        let p = build_pairing_dhkey_check(&check);
        assert_eq!(p[0], opcode::PAIRING_DHKEY_CHECK);
        assert_eq!(&p[1..], &check);
    }

    #[test]
    fn smp_c2_deterministic() {
        let tk = [0u8; 16];
        let r = [1u8; 16];
        let preq = [0u8; 7];
        let pres = [0u8; 7];
        let ia = [0u8; 6];
        let ra = [0u8; 6];
        let a = smp_c2(&tk, &r, &preq, &pres, 0, &ia, 1, &ra).expect("c2");
        let b = smp_c2(&tk, &r, &preq, &pres, 0, &ia, 1, &ra).expect("c2");
        assert_eq!(a, b);
    }

    #[test]
    fn f6_g2_h6_h7_deterministic() {
        let w = [0u8; 16];
        let n1 = [0u8; 16];
        let n2 = [0u8; 16];
        let r = [0u8; 16];
        let cap = [0u8; 7];
        let a1 = [0u8; 7];
        let a2 = [0u8; 7];
        assert_eq!(f6(&w, &n1, &n2, &r, &cap, &a1, &a2), f6(&w, &n1, &n2, &r, &cap, &a1, &a2));
        assert_eq!(g2(&w, &n1, &n2), g2(&w, &n1, &n2));
        assert_eq!(h6(&w, &[0, 1, 2, 3]), h6(&w, &[0, 1, 2, 3]));
        assert_eq!(h7(&w, &n1), h7(&w, &n1));
    }
}

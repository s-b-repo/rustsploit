//! LMP and L2CAP packet codecs (pure Rust, offline-testable).
//!
//! These are the wire primitives used by the KNOB / BIAS / BLUFFS / BrakTooth
//! attack engines and the L2CAP probing modules. All parse functions return
//! `Result` and never panic on malformed input.
//!
//! - LMP (Link Manager Protocol) PDUs travel inside ACL data on the LM
//!   connection (dest CID 0x0001 on the controller side). Stock BlueZ stacks
//!   refuse to let applications inject them — the codecs exist so attack
//!   engines can build/parse them over an `HCI_CHANNEL_USER` controller.
//! - L2CAP signalling (CID 0x0001) and connection-oriented channels (dynamic
//!   PSMs) are what BlueFrag / BlueBorne / BrakTooth class attacks ride on.

use anyhow::{Result, anyhow};

// ---------------------------------------------------------------------------
// L2CAP
// ---------------------------------------------------------------------------

/// Well-known L2CAP channel identifiers.
pub const L2CAP_CID_SIGNALING: u16 = 0x0001;
/// LMP messages tunnel over the LM channel on the controller side.
pub const L2CAP_CID_LM: u16 = 0x0001;
/// Attribute protocol (BLE GATT) CID.
pub const L2CAP_CID_ATT: u16 = 0x0004;
/// Security Manager protocol (BLE SMP) CID.
pub const L2CAP_CID_SMP: u16 = 0x0006;

/// Signalling command codes (BR/EDR).
pub const L2CAP_CONN_REQ: u8 = 0x02;
pub const L2CAP_CONN_RESP: u8 = 0x03;
pub const L2CAP_CONFIG_REQ: u8 = 0x04;
pub const L2CAP_CONFIG_RESP: u8 = 0x05;
pub const L2CAP_DISCONN_REQ: u8 = 0x06;
pub const L2CAP_DISCONN_RESP: u8 = 0x07;
pub const L2CAP_ECHO_REQ: u8 = 0x08;
pub const L2CAP_ECHO_RESP: u8 = 0x09;
pub const L2CAP_INFO_REQ: u8 = 0x0A;
pub const L2CAP_INFO_RESP: u8 = 0x0B;

/// Connection response result codes.
pub const L2CAP_CONN_RESP_SUCCESS: u16 = 0x0000;
pub const L2CAP_CONN_RESP_PSM_NOT_SUPPORTED: u16 = 0x0002;
pub const L2CAP_CONN_RESP_SECURITY_BLOCK: u16 = 0x0003;
/// Connection response "no resources" — used to fingerprint stack behaviour.
pub const L2CAP_CONN_RESP_NO_RESOURCES: u16 = 0x0004;

/// A parsed Basic Mode L2CAP PDU: `len(2) | cid(2) | payload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2capPdu {
    pub cid: u16,
    pub payload: Vec<u8>,
}

/// Parse a Basic Mode L2CAP frame from an HCI ACL data payload.
pub fn parse_l2cap(frame: &[u8]) -> Result<L2capPdu> {
    if frame.len() < 4 {
        return Err(anyhow!("L2CAP frame too short: {} bytes", frame.len()));
    }
    let len = u16::from_le_bytes([frame[0], frame[1]]) as usize;
    let cid = u16::from_le_bytes([frame[2], frame[3]]);
    let total = 4usize
        .checked_add(len)
        .ok_or_else(|| anyhow!("L2CAP length overflow"))?;
    if frame.len() < total {
        return Err(anyhow!(
            "L2CAP frame truncated: header says {len}, got {}",
            frame.len() - 4
        ));
    }
    Ok(L2capPdu {
        cid,
        payload: frame[4..total].to_vec(),
    })
}

/// Build a Basic Mode L2CAP frame.
pub fn build_l2cap(cid: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(&cid.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Parse a BR/EDR signalling packet (CID 0x0001): sequence of
/// `code(1) | id(1) | len(2) | data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2capSignal {
    pub code: u8,
    pub id: u8,
    pub data: Vec<u8>,
}

pub fn parse_signaling(payload: &[u8]) -> Result<Vec<L2capSignal>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 4 <= payload.len() {
        let code = payload[off];
        let id = payload[off + 1];
        let len = u16::from_le_bytes([payload[off + 2], payload[off + 3]]) as usize;
        off += 4;
        if off + len > payload.len() {
            return Err(anyhow!("signaling PDU truncated at offset {off}"));
        }
        out.push(L2capSignal {
            code,
            id,
            data: payload[off..off + len].to_vec(),
        });
        off += len;
    }
    Ok(out)
}

/// Build a Connection Request signaling PDU payload.
pub fn build_conn_req(id: u8, psm: u16, source_cid: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(8);
    data.push(L2CAP_CONN_REQ);
    data.push(id);
    data.extend_from_slice(&4u16.to_le_bytes());
    data.extend_from_slice(&psm.to_le_bytes());
    data.extend_from_slice(&source_cid.to_le_bytes());
    data
}

/// Build an Information Request signaling PDU payload (extended features mask).
pub fn build_info_req(id: u8, info_type: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(6);
    data.push(L2CAP_INFO_REQ);
    data.push(id);
    data.extend_from_slice(&2u16.to_le_bytes());
    data.extend_from_slice(&info_type.to_le_bytes());
    data
}

/// Information request types.
pub const L2CAP_INFO_CONNLESS_MTU: u16 = 0x0001;
/// Extended features mask — bit 5 = ERTM, bit 6 = streaming, bit 3 = FCS.
pub const L2CAP_INFO_EXTENDED_FEATURES: u16 = 0x0002;

/// PSM values of interest for probing.
pub const PSM_SDP: u16 = 0x0001;
pub const PSM_RFCOMM: u16 = 0x0003;
pub const PSM_HID_CONTROL: u16 = 0x0011;
pub const PSM_HID_INTERRUPT: u16 = 0x0013;
pub const PSM_AVDTP: u16 = 0x0019;
pub const PSM_AVDTP_MEDIA: u16 = 0x001B;
pub const PSM_BNEP: u16 = 0x000F;
pub const PSM_L2CAP_DYNAMIC_START: u16 = 0x1001;
pub const PSM_A2MP: u16 = 0x0007;

// ---------------------------------------------------------------------------
// LMP
// ---------------------------------------------------------------------------

/// LMP PDU opcodes relevant to the KNOB/BIAS/BLUFFS engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum LmpOpcode {
    /// `LMP_encryption_key_size_req` (transaction, opcode 0x39<<1 | 0).
    EncryptionKeySizeReq = 0x72,
    /// `LMP_encryption_key_size_res` (0x3A<<1 | 1 → 0x75).
    EncryptionKeySizeRes = 0x75,
    /// `LMP_features_req_ext` — extended feature page 1 (BIAS/BLUFFS-relevant).
    FeaturesReqExt = 0x6B,
    /// `LMP_features_res_ext`.
    FeaturesResExt = 0x6E,
    /// `LMP_aes_cfb` (BT 5.2 LE Secure... legacy AES command).
    AesCfb = 0x7D,
    /// `LMP_accepted`.
    Accepted = 0x03,
    /// `LMP_not_accepted`.
    NotAccepted = 0x04,
    /// `LMP_detach`.
    Detach = 0x07,
    /// `LMP_host_connection_req`.
    HostConnectionReq = 0x0B,
    /// `LMP_setup_complete`.
    SetupComplete = 0x0F,
    Unknown(u16),
}

impl LmpOpcode {
    /// Decode the 15-bit opcode from the two-byte LMP header (`op1 | op2<<8`).
    pub fn from_header(op1: u8, op2: u8) -> Self {
        let raw = ((op2 as u16) << 8) | op1 as u16;
        match raw {
            0x72 => Self::EncryptionKeySizeReq,
            0x75 => Self::EncryptionKeySizeRes,
            0x6B => Self::FeaturesReqExt,
            0x6E => Self::FeaturesResExt,
            0x7D => Self::AesCfb,
            0x03 => Self::Accepted,
            0x04 => Self::NotAccepted,
            0x07 => Self::Detach,
            0x0B => Self::HostConnectionReq,
            0x0F => Self::SetupComplete,
            other => Self::Unknown(other),
        }
    }

    pub fn raw(self) -> u16 {
        match self {
            Self::EncryptionKeySizeReq => 0x72,
            Self::EncryptionKeySizeRes => 0x75,
            Self::FeaturesReqExt => 0x6B,
            Self::FeaturesResExt => 0x6E,
            Self::AesCfb => 0x7D,
            Self::Accepted => 0x03,
            Self::NotAccepted => 0x04,
            Self::Detach => 0x07,
            Self::HostConnectionReq => 0x0B,
            Self::SetupComplete => 0x0F,
            Self::Unknown(v) => v,
        }
    }
}

/// An LMP PDU: 15-bit opcode + up to 17 payload bytes
/// (`op1(1) | op2+tid(1) | payload`).
#[derive(Debug, Clone)]
pub struct LmpPdu {
    pub opcode: LmpOpcode,
    pub tid: u8,
    pub payload: Vec<u8>,
}

/// Parse an LMP PDU from an ACL payload sent on the LM channel.
pub fn parse_lmp(data: &[u8]) -> Result<LmpPdu> {
    if data.len() < 2 {
        return Err(anyhow!("LMP PDU too short: {} bytes", data.len()));
    }
    let op1 = data[0];
    let op2 = data[1];
    let tid = op2 & 0x01;
    // op2 carries opcode bits 8..14 plus the transaction id in bit 0.
    let op2_field = op2 & 0xFE;
    let opcode = LmpOpcode::from_header(op1, op2_field >> 1);
    Ok(LmpPdu {
        opcode,
        tid,
        payload: data.get(2..).unwrap_or(&[]).to_vec(),
    })
}

/// Build an LMP PDU: `op1 | (opcode>>1)<<1 | tid | payload`.
pub fn build_lmp(opcode: LmpOpcode, tid: u8, payload: &[u8]) -> Vec<u8> {
    let raw = opcode.raw();
    let op1 = (raw & 0xFF) as u8;
    let op2 = (((raw >> 8) as u8) << 1) | (tid & 0x01);
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(op1);
    out.push(op2);
    out.extend_from_slice(payload);
    out
}

/// `LMP_encryption_key_size_req` payload: single byte `key_size` (1..=16).
/// KNOB: requesting 1 byte downgrades the link key entropy for the session.
pub fn build_key_size_req(key_size: u8) -> Vec<u8> {
    build_lmp(LmpOpcode::EncryptionKeySizeReq, 0, &[key_size])
}

/// Parse the key size out of `LMP_encryption_key_size_res/req`.
pub fn parse_key_size(payload: &[u8]) -> Result<u8> {
    payload
        .first()
        .copied()
        .ok_or_else(|| anyhow!("key size PDU empty"))
}

/// `LMP_features_req_ext` payload: `features_page(1) | features(8)`.
pub fn build_features_ext_req(page: u8, features: [u8; 8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(9);
    payload.push(page);
    payload.extend_from_slice(&features);
    build_lmp(LmpOpcode::FeaturesReqExt, 0, &payload)
}

/// Parse an extended features response → (page, feature mask).
pub fn parse_features_ext(payload: &[u8]) -> Result<(u8, u64)> {
    if payload.len() < 9 {
        return Err(anyhow!(
            "extended features PDU too short: {} bytes",
            payload.len()
        ));
    }
    let page = payload[0];
    let mut mask = 0u64;
    for (i, b) in payload[1..9].iter().enumerate() {
        mask |= (*b as u64) << (8 * i);
    }
    Ok((page, mask))
}

/// LMP error codes used by `LMP_not_accepted` / `LMP_detach`.
pub const LMP_ERROR_UNSUPPORTED_LMP_PDU: u8 = 0x14;
/// "Encryption mode not acceptable" — a KNOB-patched stack rejects small keys.
pub const LMP_ERROR_ENCRYPTION_MODE_NOT_ACCEPTABLE: u8 = 0x25;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l2cap_roundtrip() {
        let payload = [1u8, 2, 3, 4, 5];
        let frame = build_l2cap(0x0040, &payload);
        let parsed = parse_l2cap(&frame).expect("parse");
        assert_eq!(parsed.cid, 0x0040);
        assert_eq!(parsed.payload, payload.to_vec());
    }

    #[test]
    fn l2cap_truncated_rejected() {
        let bad = [3u8, 0, 0x40, 0, 1, 2];
        assert!(parse_l2cap(&bad).is_err());
        let tiny = [1u8, 0, 0];
        assert!(parse_l2cap(&tiny).is_err());
    }

    #[test]
    fn signaling_parse() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&build_conn_req(0x07, PSM_RFCOMM, 0x0041));
        let pdus = parse_signaling(&payload).expect("parse");
        assert_eq!(pdus.len(), 1);
        assert_eq!(pdus[0].code, L2CAP_CONN_REQ);
        assert_eq!(pdus[0].id, 0x07);
    }
}

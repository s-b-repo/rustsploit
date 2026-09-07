//! BLE link-layer packet codecs (pure Rust, offline-testable).
//!
//! The SweynTooth / InjectaBLE engines build and parse these PDUs. Raw radio
//! injection needs an `HCI_LE_Transmit_Test`-capable or user-channel
//! controller; the codecs are kept independent so the engines work against
//! any driver that accepts them.

use anyhow::{Result, anyhow};

// ---------------------------------------------------------------------------
// Advertising channel PDU header (BLE 4.x, pre-extended)
// ---------------------------------------------------------------------------

/// PDU type field (bits 0..3 of the first header octet).
pub const ADV_TYPE_ADV_IND: u8 = 0x0;
pub const ADV_TYPE_ADV_DIRECT_IND: u8 = 0x1;
pub const ADV_TYPE_ADV_NONCONN_IND: u8 = 0x2;
pub const ADV_TYPE_SCAN_REQ: u8 = 0x3;
pub const ADV_TYPE_SCAN_RSP: u8 = 0x4;
pub const ADV_TYPE_CONNECT_IND: u8 = 0x5;
pub const ADV_TYPE_ADV_SCAN_IND: u8 = 0x6;
pub const ADV_TYPE_ADV_EXT_IND: u8 = 0x7;

/// An advertising-channel PDU header (`tx_add/rx_add` folded into `type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvHeader {
    pub pdu_type: u8,
    /// `TxAdd` — 1 = random address.
    pub tx_add: bool,
    /// `RxAdd` — 1 = random address.
    pub rx_add: bool,
    /// Payload length in bytes (6..=37 for legacy adverts).
    pub length: u8,
}

impl AdvHeader {
    /// Parse the 2-byte advertising header.
    pub fn parse(header: [u8; 2]) -> Self {
        Self {
            pdu_type: header[0] & 0x0F,
            tx_add: header[0] & 0x40 != 0,
            rx_add: header[0] & 0x80 != 0,
            length: header[1] & 0x3F,
        }
    }

    /// Encode into the 2-byte advertising header.
    pub fn encode(self) -> [u8; 2] {
        let mut b0 = self.pdu_type & 0x0F;
        if self.tx_add {
            b0 |= 0x40;
        }
        if self.rx_add {
            b0 |= 0x80;
        }
        [b0, self.length & 0x3F]
    }
}

/// Build a complete advertising PDU (header + payload).
pub fn build_adv_pdu(pdu_type: u8, tx_add: bool, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > 37 {
        return Err(anyhow!(
            "legacy advertising payload too long: {} bytes (max 37)",
            payload.len()
        ));
    }
    let header = AdvHeader {
        pdu_type,
        tx_add,
        rx_add: false,
        length: payload.len() as u8,
    };
    let hdr = header.encode();
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(hdr[0]);
    out.push(hdr[1]);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Parse an advertising PDU → (header, payload).
pub fn parse_adv_pdu(data: &[u8]) -> Result<(AdvHeader, &[u8])> {
    if data.len() < 2 {
        return Err(anyhow!("advertising PDU too short"));
    }
    let header = AdvHeader::parse([data[0], data[1]]);
    let len = header.length as usize;
    if data.len() < 2 + len {
        return Err(anyhow!(
            "advertising PDU truncated: header says {len}, got {}",
            data.len().saturating_sub(2)
        ));
    }
    Ok((header, &data[2..2 + len]))
}

// ---------------------------------------------------------------------------
// LL control PDUs (data channel, LLID = 0b11)
// ---------------------------------------------------------------------------

/// LL control opcode (first payload byte when LLID = 0b11).
pub const LL_CONN_UPDATE_IND: u8 = 0x00;
pub const LL_CHANNEL_MAP_IND: u8 = 0x01;
pub const LL_TERMINATE_IND: u8 = 0x02;
/// `LL_REJECT_IND` (4.x).
pub const LL_REJECT_IND: u8 = 0x0C;
/// `LL_PING_REQ` — the empty control PDU behind the SweynTooth Ping flood.
pub const LL_PING_REQ: u8 = 0x0D;
pub const LL_PING_RSP: u8 = 0x0E;
/// `LL_LENGTH_REQ` — Data Length Extension negotiation (SweynTooth DLE crashes).
pub const LL_LENGTH_REQ: u8 = 0x11;
pub const LL_LENGTH_RSP: u8 = 0x12;
/// `LL_UNKNOWN_RSP`.
pub const LL_UNKNOWN_RSP: u8 = 0x0E;
/// `LL_CONNECTION_PARAM_REQ` (4.2+).
pub const LL_CONN_PARAM_REQ: u8 = 0x0F;
pub const LL_CONN_PARAM_RSP: u8 = 0x13;
/// `LL_REJECT_EXT_IND`.
pub const LL_REJECT_EXT_IND: u8 = 0x14;

/// Build an LL control PDU payload: `opcode | payload`.
pub fn build_ll_control(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(opcode);
    out.extend_from_slice(payload);
    out
}

/// Build the empty `LL_PING_REQ`.
pub fn build_ping_req() -> Vec<u8> {
    build_ll_control(LL_PING_REQ, &[])
}

/// Build `LL_TERMINATE_IND` with an error code.
pub fn build_terminate_ind(error: u8) -> Vec<u8> {
    build_ll_control(LL_TERMINATE_IND, &[error])
}

/// Build `LL_LENGTH_REQ`: `max_rx_octets(2) | max_rx_time(2) |
/// max_tx_octets(2) | max_tx_time(2)`, little-endian.
pub fn build_length_req(
    max_rx_octets: u16,
    max_rx_time: u16,
    max_tx_octets: u16,
    max_tx_time: u16,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&max_rx_octets.to_le_bytes());
    payload.extend_from_slice(&max_rx_time.to_le_bytes());
    payload.extend_from_slice(&max_tx_octets.to_le_bytes());
    payload.extend_from_slice(&max_tx_time.to_le_bytes());
    build_ll_control(LL_LENGTH_REQ, &payload)
}

/// Parse `LL_LENGTH_REQ`/`LL_LENGTH_RSP` parameters.
pub fn parse_length(payload: &[u8]) -> Result<(u16, u16, u16, u16)> {
    if payload.len() < 8 {
        return Err(anyhow!(
            "LL_LENGTH PDU too short: {} bytes (need 8)",
            payload.len()
        ));
    }
    let rx_oct = u16::from_le_bytes([payload[0], payload[1]]);
    let rx_time = u16::from_le_bytes([payload[2], payload[3]]);
    let tx_oct = u16::from_le_bytes([payload[4], payload[5]]);
    let tx_time = u16::from_le_bytes([payload[6], payload[7]]);
    Ok((rx_oct, rx_time, tx_oct, tx_time))
}

/// Build `LL_UNKNOWN_RSP` echoing an unknown opcode.
pub fn build_unknown_rsp(opcode: u8) -> Vec<u8> {
    build_ll_control(LL_UNKNOWN_RSP, &[opcode])
}

/// Parse an LL control PDU → (opcode, rest).
pub fn parse_ll_control(payload: &[u8]) -> Result<(u8, &[u8])> {
    payload
        .split_first()
        .map(|(op, rest)| (*op, rest))
        .ok_or_else(|| anyhow!("LL control PDU empty"))
}

/// Data-channel header (2 bytes) with LLID field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataHeader {
    /// 0b01 = data start, 0b10 = data continuation, 0b11 = LL control.
    pub llid: u8,
    pub nesn: bool,
    pub sn: bool,
    pub md: bool,
    pub length: u8,
}

impl DataHeader {
    pub fn parse(header: [u8; 2]) -> Self {
        Self {
            llid: header[0] & 0x03,
            nesn: header[0] & 0x04 != 0,
            sn: header[0] & 0x08 != 0,
            md: header[0] & 0x10 != 0,
            length: header[1] & 0xFF,
        }
    }

    pub fn encode(self) -> [u8; 2] {
        let mut b0 = self.llid & 0x03;
        if self.nesn {
            b0 |= 0x04;
        }
        if self.sn {
            b0 |= 0x08;
        }
        if self.md {
            b0 |= 0x10;
        }
        [b0, self.length]
    }
}

/// InjectaBLE attack phases (from the paper) — encoded for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectablePhase {
    /// Phase 1: passive discovery of an existing connection.
    Discovery,
    /// Phase 2: access-address synchronisation with the target link.
    Synchronisation,
    /// Phase 3: active injection into the established connection.
    Injection,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adv_header_roundtrip() {
        let header = AdvHeader {
            pdu_type: ADV_TYPE_ADV_IND,
            tx_add: true,
            rx_add: false,
            length: 22,
        };
        let encoded = header.encode();
        let parsed = AdvHeader::parse(encoded);
        assert_eq!(header, parsed);
    }

    #[test]
    fn adv_pdu_roundtrip_and_bounds() {
        let payload = [0x02u8, 0x01, 0x06];
        let pdu = build_adv_pdu(ADV_TYPE_ADV_IND, true, &payload).expect("build");
        let (header, got) = parse_adv_pdu(&pdu).expect("parse");
        assert_eq!(header.pdu_type, ADV_TYPE_ADV_IND);
        assert!(header.tx_add);
        assert_eq!(got, payload);
        let long = [0u8; 38];
        assert!(build_adv_pdu(ADV_TYPE_ADV_IND, false, &long).is_err());
    }

    #[test]
    fn length_req_roundtrip() {
        let pdu = build_length_req(251, 2120, 251, 2120);
        assert_eq!(pdu[0], LL_LENGTH_REQ);
        let (rx_o, rx_t, tx_o, tx_t) = parse_length(&pdu[1..]).expect("parse");
        assert_eq!((rx_o, rx_t, tx_o, tx_t), (251, 2120, 251, 2120));
    }

    #[test]
    fn ping_req_is_one_byte() {
        assert_eq!(build_ping_req(), vec![LL_PING_REQ]);
        assert_eq!(LL_UNKNOWN_RSP, 0x0E);
    }
}

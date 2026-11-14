//! Bluetooth HID Profile (HIDP 1.1) transaction codec.
//!
//! The framework could already talk to BLE HID-over-GATT, but the CLASSIC
//! HID transport was missing entirely: the L2CAP PSMs were listed in the
//! probe table and nothing spoke the protocol. Classic HID is still the
//! transport behind many enterprise keyboards, industrial scanners and
//! presentation remotes.
//!
//! HIDP runs over two L2CAP channels:
//!   - PSM 0x0011 — control channel: SET/GET_PROTOCOL, suspend/resume
//!   - PSM 0x0013 — interrupt channel: SET_REPORT / GET_REPORT
//!
//! Wire format (HIDP 1.1, §7.2): every transaction is
//! `type(1) | param_len(2, big-endian) | params`.
//!
//! This module is a pure codec — no I/O — so it is unit-testable.

use anyhow::{Result, anyhow};

/// L2CAP PSM for the HID control channel.
pub const PSM_HID_CONTROL: u16 = 0x0011;
/// L2CAP PSM for the HID interrupt channel.
pub const PSM_HID_INTERRUPT: u16 = 0x0013;

/// HID transaction types.
pub const HID_TRANSACTION_SET_REPORT: u8 = 0x01;
pub const HID_TRANSACTION_GET_REPORT: u8 = 0x02;
pub const HID_TRANSACTION_SET_PROTOCOL: u8 = 0x04;
pub const HID_TRANSACTION_GET_PROTOCOL: u8 = 0x05;
pub const HID_TRANSACTION_SUSPEND: u8 = 0x06;
pub const HID_TRANSACTION_RESUME: u8 = 0x07;

/// HID report types.
pub const HID_REPORT_TYPE_INPUT: u8 = 0x01;
pub const HID_REPORT_TYPE_OUTPUT: u8 = 0x02;
pub const HID_REPORT_TYPE_FEATURE: u8 = 0x03;

/// Protocol modes, as reported by GET_PROTOCOL.
pub const HID_PROTOCOL_BOOT: u8 = 0x00;
pub const HID_PROTOCOL_REPORT: u8 = 0x01;

/// A decoded HIDP transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HidTransaction {
    pub transaction_type: u8,
    pub params: Vec<u8>,
}

/// Build the transaction header for a HIDP transaction.
fn with_header(transaction_type: u8, params: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + params.len());
    out.push(transaction_type);
    out.extend_from_slice(&(params.len() as u16).to_be_bytes());
    out.extend_from_slice(params);
    out
}

/// Build a `GET_PROTOCOL` transaction.
///
/// Sent on the control channel to discover whether the peer is in boot mode
/// or report mode — and, on some stacks, whether it will answer at all.
pub fn build_get_protocol() -> Vec<u8> {
    with_header(HID_TRANSACTION_GET_PROTOCOL, &[])
}

/// Build a `SET_PROTOCOL` transaction.
pub fn build_set_protocol(mode: u8) -> Vec<u8> {
    with_header(HID_TRANSACTION_SET_PROTOCOL, &[mode])
}

/// Build a `GET_REPORT` transaction for a report type and report id.
pub fn build_get_report(report_type: u8, report_id: u8) -> Vec<u8> {
    with_header(HID_TRANSACTION_GET_REPORT, &[report_type, report_id])
}

/// Build a `SET_REPORT` transaction carrying a report payload.
///
/// This is the write path: injecting keystrokes at a classic HID keyboard
/// means sending an input report on the interrupt channel.
pub fn build_set_report(report_type: u8, report_id: u8, data: &[u8]) -> Vec<u8> {
    let mut params = Vec::with_capacity(2 + data.len());
    params.push(report_type);
    params.push(report_id);
    params.extend_from_slice(data);
    with_header(HID_TRANSACTION_SET_REPORT, &params)
}

/// Build a `SUSPEND` transaction.
pub fn build_suspend() -> Vec<u8> {
    with_header(HID_TRANSACTION_SUSPEND, &[])
}

/// Parse a HIDP transaction.
pub fn parse_transaction(pdu: &[u8]) -> Result<HidTransaction> {
    if pdu.len() < 3 {
        return Err(anyhow!("HIDP transaction too short: {} bytes", pdu.len()));
    }
    let param_len = u16::from_be_bytes([pdu[1], pdu[2]]) as usize;
    let params = pdu
        .get(3..3 + param_len)
        .ok_or_else(|| anyhow!("HIDP transaction params truncated (want {param_len})"))?;
    Ok(HidTransaction {
        transaction_type: pdu[0],
        params: params.to_vec(),
    })
}

/// Extract the protocol mode from a `GET_PROTOCOL` response.
///
/// The response params are `status(1) | mode(1)`. A status of 0 means the
/// peer answered; anything else is an HIDP error.
pub fn parse_get_protocol_response(pdu: &[u8]) -> Result<u8> {
    let tx = parse_transaction(pdu)?;
    if tx.transaction_type != HID_TRANSACTION_GET_PROTOCOL {
        return Err(anyhow!(
            "not a GET_PROTOCOL response (type 0x{:02X})",
            tx.transaction_type
        ));
    }
    if tx.params.len() < 2 {
        return Err(anyhow!("GET_PROTOCOL response too short"));
    }
    if tx.params[0] != 0 {
        return Err(anyhow!(
            "GET_PROTOCOL failed with HIDP status 0x{:02X}",
            tx.params[0]
        ));
    }
    Ok(tx.params[1])
}

/// Extract the report payload from a `GET_REPORT` response.
///
/// The response params are `status(1) | report_type(1) | report_id(1) | data`.
pub fn parse_get_report_response(pdu: &[u8]) -> Result<(u8, u8, Vec<u8>)> {
    let tx = parse_transaction(pdu)?;
    if tx.transaction_type != HID_TRANSACTION_GET_REPORT {
        return Err(anyhow!(
            "not a GET_REPORT response (type 0x{:02X})",
            tx.transaction_type
        ));
    }
    if tx.params.len() < 3 {
        return Err(anyhow!("GET_REPORT response too short"));
    }
    if tx.params[0] != 0 {
        return Err(anyhow!(
            "GET_REPORT failed with HIDP status 0x{:02X}",
            tx.params[0]
        ));
    }
    Ok((tx.params[1], tx.params[2], tx.params[3..].to_vec()))
}

/// A human-readable name for a protocol mode.
pub fn protocol_name(mode: u8) -> &'static str {
    match mode {
        HID_PROTOCOL_BOOT => "boot",
        HID_PROTOCOL_REPORT => "report",
        _ => "reserved",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_protocol_has_an_empty_parameter_block() {
        let pdu = build_get_protocol();
        assert_eq!(pdu, vec![HID_TRANSACTION_GET_PROTOCOL, 0x00, 0x00]);
    }

    #[test]
    fn transaction_round_trips() {
        let pdu = build_set_report(HID_REPORT_TYPE_OUTPUT, 0x02, &[0xAA, 0xBB]);
        let tx = parse_transaction(&pdu).expect("should parse");
        assert_eq!(tx.transaction_type, HID_TRANSACTION_SET_REPORT);
        assert_eq!(tx.params, vec![HID_REPORT_TYPE_OUTPUT, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn get_protocol_response_is_parsed() {
        // type(1)=0x05 param_len(2)=0x0002 status(1)=0 mode(1)=1
        let pdu = vec![
            HID_TRANSACTION_GET_PROTOCOL,
            0x00,
            0x02,
            0x00,
            HID_PROTOCOL_REPORT,
        ];
        assert_eq!(
            parse_get_protocol_response(&pdu).unwrap_or(0),
            HID_PROTOCOL_REPORT
        );
        assert_eq!(protocol_name(HID_PROTOCOL_REPORT), "report");
    }

    #[test]
    fn get_protocol_error_status_is_reported() {
        let pdu = vec![HID_TRANSACTION_GET_PROTOCOL, 0x00, 0x02, 0x01, 0x00];
        assert!(parse_get_protocol_response(&pdu).is_err());
    }

    #[test]
    fn get_report_response_yields_the_payload() {
        let pdu = vec![
            HID_TRANSACTION_GET_REPORT,
            0x00,
            0x05,
            0x00,
            HID_REPORT_TYPE_FEATURE,
            0x03,
            0xDE,
            0xAD,
        ];
        let (rtype, rid, data) = parse_get_report_response(&pdu).expect("should parse");
        assert_eq!(rtype, HID_REPORT_TYPE_FEATURE);
        assert_eq!(rid, 0x03);
        assert_eq!(data, vec![0xDE, 0xAD]);
    }

    #[test]
    fn truncated_transaction_is_an_error_not_a_panic() {
        assert!(parse_transaction(&[0x01, 0x00]).is_err());
        assert!(parse_transaction(&[0x01, 0x00, 0x05, 0x01]).is_err());
    }
}

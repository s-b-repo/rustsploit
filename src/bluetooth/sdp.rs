//! Minimal SDP client over L2CAP PSM 1 (Linux).
//!
//! Implements the SDP `ServiceSearchAttribute` transaction natively — no
//! `sdptool` dependency — so `classic_scan` can enumerate service records
//! (SPP/A2DP/HID/...) directly from the target.

use std::time::Duration;

use anyhow::{Result, anyhow};

use super::hci::BdAddr;

const BTPROTO_L2CAP: i32 = 0;
const PSM_SDP: u16 = 0x0001;

/// Attribute IDs of interest.
pub const ATTR_SERVICE_CLASS_ID_LIST: u16 = 0x0001;
pub const ATTR_PROTOCOL_DESCRIPTOR_LIST: u16 = 0x0004;

/// SDP data element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdpData {
    Nil,
    U8(u8),
    U16(u16),
    U32(u32),
    U128(u128),
    Str(Vec<u8>),
    Uuid(u128),
    Seq(Vec<SdpData>),
}

impl SdpData {
    /// Collect UUIDs from a service-class list.
    pub fn uuids(&self) -> Vec<u128> {
        match self {
            SdpData::Seq(items) => items
                .iter()
                .filter_map(|i| match i {
                    SdpData::Uuid(u) => Some(*u),
                    _ => None,
                })
                .collect(),
            SdpData::Uuid(u) => vec![*u],
            _ => Vec::new(),
        }
    }

    /// Extract the RFCOMM channel from a protocol-descriptor list.
    pub fn rfcomm_channel(&self) -> Option<u8> {
        // [[L2CAP(0x0100)], [RFCOMM(0x0003), channel]]
        if let SdpData::Seq(protocols) = self {
            for protocol in protocols {
                if let SdpData::Seq(stack) = protocol {
                    for (i, elem) in stack.iter().enumerate() {
                        if matches!(elem, SdpData::Uuid(0x0003)) {
                            return stack.get(i + 1).and_then(|ch| match ch {
                                SdpData::U8(c) => Some(*c),
                                _ => None,
                            });
                        }
                    }
                }
            }
        }
        None
    }

    /// True when the record advertises the HID profile.
    pub fn is_hid(&self) -> bool {
        self.uuids()
            .iter()
            .any(|u| *u == 0x1124 || *u == 0x111E || *u == 0x111F)
    }

    /// True when the record advertises A2DP sink/source.
    pub fn is_a2dp(&self) -> bool {
        self.uuids().iter().any(|u| *u == 0x110B || *u == 0x110C)
    }

    /// True when the record advertises HFP/HSP.
    pub fn is_handsfree(&self) -> bool {
        self.uuids()
            .iter()
            .any(|u| *u == 0x111E || *u == 0x1108 || *u == 0x1203)
    }
}

/// Human-readable label for well-known profile UUIDs.
pub fn profile_name(u: u128) -> String {
    match u {
        0x1101 => "SPP (Serial Port)".into(),
        0x1108 => "HSP Headset".into(),
        0x110B => "A2DP Sink".into(),
        0x110C => "A2DP Source".into(),
        0x110E => "AVRCP".into(),
        0x111E => "HID Device".into(),
        0x111F => "HID Pointing".into(),
        0x1124 => "HID Device Class".into(),
        0x1112 => "Headset Audio Gateway".into(),
        0x1203 => "PANU".into(),
        other => format!("0x{other:04X}"),
    }
}

/// One parsed SDP service record.
#[derive(Debug, Clone, Default)]
pub struct SdpRecord {
    pub uuids: Vec<u128>,
    pub rfcomm_channel: Option<u8>,
    pub hid: bool,
    pub a2dp: bool,
    pub handsfree: bool,
}

/// An L2CAP socket connection to the SDP server of a target.
pub struct SdpClient {
    fd: i32,
}

impl SdpClient {
    /// Connect the L2CAP PSM 1 (SDP) channel to `bdaddr` (display order).
    pub fn connect(bdaddr_display: &str) -> Result<Self> {
        let addr = super::parse_mac(bdaddr_display)?;
        // sockaddr_l2 wants the address LSB-first.
        let mut reverse = addr;
        reverse.reverse();
        let fd = unsafe {
            libc::socket(
                libc::AF_BLUETOOTH,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                BTPROTO_L2CAP,
            )
        };
        if fd < 0 {
            return Err(anyhow!(
                "opening L2CAP socket failed (need root or CAP_NET_RAW): {}",
                std::io::Error::last_os_error()
            ));
        }
        // sockaddr_l2: family(2) psm(2, big-endian) bdaddr(6) cid(2) bdaddr_type(1)
        let mut sa = [0u8; 15];
        sa[0] = libc::AF_BLUETOOTH as u8;
        sa[2] = (PSM_SDP >> 8) as u8;
        sa[3] = (PSM_SDP & 0xFF) as u8;
        for (i, b) in reverse.iter().enumerate() {
            sa[4 + i] = *b;
        }
        let rc =
            unsafe { libc::connect(fd, sa.as_ptr() as *const libc::sockaddr, sa.len() as u32) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(anyhow!(
                "L2CAP connect to {bdaddr_display} PSM 1 (SDP): {err}"
            ));
        }
        Ok(Self { fd })
    }

    /// Run a full `ServiceSearchAttribute` for the public browse root and
    /// parse every returned record.
    pub fn browse(&mut self, timeout: Duration) -> Result<Vec<SdpRecord>> {
        let req = build_service_search_attribute_request();
        self.send_pdu(&req)?;
        let resp = self.recv_pdu(timeout)?;
        parse_sdp_response(&resp)
    }

    fn send_pdu(&mut self, pdu: &[u8]) -> Result<()> {
        let mut off = 0usize;
        while off < pdu.len() {
            let n = unsafe {
                libc::write(
                    self.fd,
                    pdu[off..].as_ptr() as *const libc::c_void,
                    pdu.len() - off,
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(anyhow!("writing SDP PDU: {err}"));
            }
            off += n as usize;
        }
        Ok(())
    }

    fn recv_pdu(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        // PDU header: PduId(1) TransactionId(2) ParamLength(2).
        let mut header = [0u8; 5];
        read_exact_timeout(self.fd, &mut header, timeout)?;
        let param_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0u8; param_len];
        read_exact_timeout(self.fd, &mut body, timeout)?;
        let mut full = header.to_vec();
        full.extend_from_slice(&body);
        Ok(full)
    }
}

impl Drop for SdpClient {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl std::fmt::Debug for SdpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SdpClient").field("fd", &self.fd).finish()
    }
}

fn read_exact_timeout(fd: i32, buf: &mut [u8], timeout: Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    let mut got = 0usize;
    while got < buf.len() {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .ok_or_else(|| anyhow!("SDP response timeout"))?;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, remaining.as_millis() as i32) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(anyhow!("polling SDP socket: {err}"));
        }
        if rc == 0 {
            return Err(anyhow!("SDP poll timeout"));
        }
        let n = unsafe {
            libc::read(
                fd,
                buf[got..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - got,
            )
        };
        if n < 0 {
            return Err(anyhow!(
                "reading SDP socket: {}",
                std::io::Error::last_os_error()
            ));
        }
        if n == 0 {
            return Err(anyhow!("SDP connection closed"));
        }
        got += n as usize;
    }
    Ok(())
}

/// Build a `ServiceSearchAttribute` request against the public browse group,
/// asking for the service-class list + protocol descriptor list.
pub fn build_service_search_attribute_request() -> Vec<u8> {
    // PDU: PduId=0x06 | TID(2) | ParamLen(2) | params...
    let mut params: Vec<u8> = Vec::new();
    // ServiceSearchPattern: one UUID128 → PublicBrowseRoot (0x1002).
    params.push(0x06); // size index: 128-bit UUID
    params.extend_from_slice(&uuid128_bytes(0x0000_1002));
    params.extend_from_slice(&1u16.to_be_bytes()); // MaxServiceRecordCount
    // AttributeIDList: a single 32-bit range covering 0x0000..=0xFFFF.
    params.push(0x0A); // 32-bit range element
    params.extend_from_slice(&0x0000u16.to_be_bytes());
    params.extend_from_slice(&0xFFFFu16.to_be_bytes());
    params.extend_from_slice(&u16::MAX.to_be_bytes()); // MaximumAttributeByteCount

    let mut pdu = Vec::with_capacity(5 + params.len());
    pdu.push(0x06); // SDP_ServiceSearchAttributeResponse request PDU id
    pdu.extend_from_slice(&0x0001u16.to_be_bytes()); // transaction id
    pdu.extend_from_slice(&(params.len() as u16).to_be_bytes());
    pdu.extend_from_slice(&params);
    pdu
}

fn uuid128_bytes(short: u16) -> [u8; 16] {
    let full = ((short as u128) << 96) | 0x0000_1000_8000_0080_5f9b_34fb;
    full.to_be_bytes()
}

/// Parse a `ServiceSearchAttributeResponse` PDU into records.
pub fn parse_sdp_response(pdu: &[u8]) -> Result<Vec<SdpRecord>> {
    if pdu.len() < 7 {
        return Err(anyhow!("SDP response too short: {} bytes", pdu.len()));
    }
    let param_len = u16::from_be_bytes([pdu[3], pdu[4]]) as usize;
    let params = pdu
        .get(5..5 + param_len)
        .ok_or_else(|| anyhow!("SDP response params truncated"))?;
    if params.len() < 3 {
        return Err(anyhow!("SDP response missing counts"));
    }
    // AttributeLists: data element seq of record seqs. Continuation state
    // (last byte) is honoured as "no continuation" only — multi-PDU responses
    // are re-issued by the caller with the same socket if needed.
    let list_len = u16::from_be_bytes([params[0], params[1]]) as usize;
    let list = params
        .get(2..2 + list_len)
        .ok_or_else(|| anyhow!("SDP attribute list truncated"))?;

    let parsed = parse_data_element(list)?;
    let mut records = Vec::new();
    if let SdpData::Seq(record_elems) = parsed {
        for elem in record_elems {
            if let SdpData::Seq(attrs) = elem {
                let mut record = SdpRecord::default();
                let mut i = 0usize;
                while i + 1 < attrs.len() {
                    let attr_id = match &attrs[i] {
                        SdpData::U16(v) => *v,
                        _ => {
                            i += 2;
                            continue;
                        }
                    };
                    let value = &attrs[i + 1];
                    match attr_id {
                        ATTR_SERVICE_CLASS_ID_LIST => record.uuids.extend(value.uuids()),
                        ATTR_PROTOCOL_DESCRIPTOR_LIST => {
                            record.rfcomm_channel = value.rfcomm_channel()
                        }
                        _ => {}
                    }
                    i += 2;
                }
                record.hid = record
                    .uuids
                    .iter()
                    .any(|u| *u == 0x1124 || *u == 0x111E || *u == 0x111F);
                record.a2dp = record.uuids.iter().any(|u| *u == 0x110B || *u == 0x110C);
                record.handsfree = record
                    .uuids
                    .iter()
                    .any(|u| *u == 0x1108 || *u == 0x1112 || *u == 0x1203 || *u == 0x111E);
                if !record.uuids.is_empty() {
                    records.push(record);
                }
            }
        }
    }
    Ok(records)
}

/// Parse one SDP data element (header byte: size descriptor + type).
pub fn parse_data_element(data: &[u8]) -> Result<SdpData> {
    let (&header, rest) = data
        .split_first()
        .ok_or_else(|| anyhow!("empty data element"))?;
    let type_index = header >> 3;
    let size_index = header & 0x07;
    let (len, consumed) = match size_index {
        0 => (0usize, 0usize),
        1 => (1, 0),
        2 => (2, 0),
        3 => (4, 0),
        4 => (8, 0),
        5 => (16, 0),
        6 => {
            let n = *rest
                .first()
                .ok_or_else(|| anyhow!("SDP size byte missing"))? as usize;
            (n, 1)
        }
        7 => {
            if rest.len() < 2 {
                return Err(anyhow!("SDP 16-bit size truncated"));
            }
            let n = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            (n, 2)
        }
        other => return Err(anyhow!("invalid SDP size descriptor {other}")),
    };
    let body = rest.get(consumed..consumed + len).ok_or_else(|| {
        anyhow!(
            "SDP element truncated: need {len}, have {}",
            rest.len().saturating_sub(consumed)
        )
    })?;

    Ok(match type_index {
        0 => SdpData::Nil,
        1 => SdpData::U128(read_be_u128(body)?),
        2 => match len {
            1 => SdpData::U8(*body.first().unwrap_or(&0)),
            2 => SdpData::U16(read_be_u16(body)?),
            4 => SdpData::U32(read_be_u32(body)?),
            16 => SdpData::U128(read_be_u128(body)?),
            _ => SdpData::U32(read_be_u32(body)?),
        },
        3 => SdpData::Uuid(match len {
            2 => u128::from(read_be_u16(body)?),
            4 => u128::from(read_be_u32(body)?),
            _ => read_be_u128(body)?,
        }),
        4 => SdpData::Str(body.to_vec()),
        5 => SdpData::Nil,
        6 => {
            let mut items = Vec::new();
            let mut off = 0usize;
            while off < body.len() {
                let elem = parse_data_element(&body[off..])?;
                let used = element_size(&body[off..])?;
                items.push(elem);
                off += used;
            }
            SdpData::Seq(items)
        }
        other => return Err(anyhow!("invalid SDP type descriptor {other}")),
    })
}

/// Total encoded size (header + payload) of the element starting at `data`.
pub fn element_size(data: &[u8]) -> Result<usize> {
    let (&header, rest) = data.split_first().ok_or_else(|| anyhow!("empty element"))?;
    let size_index = header & 0x07;
    let (len, extra) = match size_index {
        0 => (0usize, 0usize),
        1 => (1, 0),
        2 => (2, 0),
        3 => (4, 0),
        4 => (8, 0),
        5 => (16, 0),
        6 => {
            let n = *rest.first().ok_or_else(|| anyhow!("size byte missing"))? as usize;
            (n, 1)
        }
        7 => {
            if rest.len() < 2 {
                return Err(anyhow!("16-bit size truncated"));
            }
            (u16::from_be_bytes([rest[0], rest[1]]) as usize, 2)
        }
        other => return Err(anyhow!("invalid size descriptor {other}")),
    };
    Ok(1 + extra + len)
}

fn read_be_u16(b: &[u8]) -> Result<u16> {
    if b.len() < 2 {
        return Err(anyhow!("u16 truncated"));
    }
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn read_be_u32(b: &[u8]) -> Result<u32> {
    if b.len() < 4 {
        return Err(anyhow!("u32 truncated"));
    }
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_be_u128(b: &[u8]) -> Result<u128> {
    if b.len() < 16 {
        return Err(anyhow!("u128 truncated"));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&b[..16]);
    Ok(u128::from_be_bytes(out))
}

/// Unused in hot paths but exported for probe modules building raw SDP.
pub fn bdaddr_for_socket(mac_display: &str) -> Result<BdAddr> {
    let mut addr = super::parse_mac(mac_display)?;
    addr.reverse();
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_u16_element() {
        // header: u16 type, fixed size 2 → 0x22, then 0x01 0x02
        let data = [0x22u8, 0x01, 0x02];
        let parsed = parse_data_element(&data).expect("parse");
        assert_eq!(parsed, SdpData::U16(0x0102));
        assert_eq!(element_size(&data).expect("size"), 3);
    }

    #[test]
    fn parses_seq_of_uuids() {
        // Seq (size index 6 → 1 extra byte) with two 16-bit UUIDs
        let mut data = vec![0x36u8, 0x06];
        data.extend_from_slice(&[0x19, 0x01, 0x01]); // u16 uuid 0x0101
        data.extend_from_slice(&[0x19, 0x03, 0x00]); // u16 uuid 0x0300 (RFCOMM)
        let parsed = parse_data_element(&data).expect("parse");
        let uuids = parsed.uuids();
        assert_eq!(uuids, vec![0x0101, 0x0003]);
    }

    #[test]
    fn rfcomm_channel_extraction() {
        // [[L2CAP uuid, PSM], [RFCOMM uuid, channel 5]]
        let mut seq = Vec::new();
        // inner: L2CAP stack
        let mut stack1 = vec![0x36u8, 0x04];
        stack1.extend_from_slice(&[0x19, 0x01, 0x00]); // L2CAP
        stack1.extend_from_slice(&[0x09, 0x00, 0x0F]); // PSM 15
        let mut stack2 = vec![0x36u8, 0x04];
        stack2.extend_from_slice(&[0x19, 0x03, 0x00]); // RFCOMM
        stack2.extend_from_slice(&[0x08, 0x05]); // channel 5
        for stack in [stack1, stack2] {
            seq.extend_from_slice(&stack);
        }
        let mut outer = vec![0x36u8];
        outer.push(seq.len() as u8);
        outer.extend_from_slice(&seq);
        let parsed = parse_data_element(&outer).expect("parse");
        assert_eq!(parsed.rfcomm_channel(), Some(5));
    }

    #[test]
    fn request_is_wellformed() {
        let req = build_service_search_attribute_request();
        assert_eq!(req[0], 0x06);
        assert_eq!(&req[5..7], &[0x06, 0x00]); // uuid128 size index
    }
}

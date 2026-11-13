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
    U64(u64),
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
///
/// The parameter block is encoded with the specification's data elements:
///   ServiceSearchPattern      — a sequence holding one 128-bit UUID
///   MaxServiceRecordCount     — u16, big-endian
///   AttributeIDList           — a sequence holding one 32-bit attribute range
///   MaximumAttributeByteCount — u16, big-endian
pub fn build_service_search_attribute_request() -> Vec<u8> {
    let mut params: Vec<u8> = Vec::new();

    // ServiceSearchPattern: a sequence holding one 128-bit UUID.
    let mut pattern = Vec::new();
    pattern.push((13 << 3) | 0); // UUID, 16 octets, fixed size
    pattern.extend_from_slice(&uuid128_bytes(0x0000_1002)); // PublicBrowseRoot
    params.push((16 << 3) | 6); // sequence, 1-byte length
    params.push(pattern.len() as u8);
    params.extend_from_slice(&pattern);

    // MaxServiceRecordCount: u16, big-endian, fixed size.
    params.push((2 << 3) | 0);
    params.extend_from_slice(&1u16.to_be_bytes());

    // AttributeIDList: a sequence holding one 32-bit attribute range.
    let mut ranges = Vec::new();
    ranges.push((4 << 3) | 0); // u32, fixed size
    ranges.extend_from_slice(&0x0000u32.to_be_bytes()); // start
    ranges.extend_from_slice(&0xFFFFu32.to_be_bytes()); // end
    params.push((16 << 3) | 6); // sequence, 1-byte length
    params.push(ranges.len() as u8);
    params.extend_from_slice(&ranges);

    // MaximumAttributeByteCount: u16, big-endian, fixed size.
    params.push((2 << 3) | 0);
    params.extend_from_slice(&u16::MAX.to_be_bytes());

    let mut pdu = Vec::with_capacity(5 + params.len());
    pdu.push(0x04); // SDP_ServiceSearchAttributeRequest pdu id
    pdu.extend_from_slice(&0x0001u16.to_be_bytes()); // transaction id
    pdu.extend_from_slice(&(params.len() as u16).to_be_bytes());
    pdu.extend_from_slice(&params);
    pdu
}

/// Build a `ServiceSearchAttribute` request that carries a continuation
/// state.
///
/// The peer returns a continuation token when its record set does not fit
/// in one PDU; re-issuing the query with that token yields the next batch.
/// Without this the tail of a large service list was never retrieved.
pub fn build_service_search_attribute_request_continued(continuation: &[u8]) -> Vec<u8> {
    let mut pdu = build_service_search_attribute_request();
    // Strip the trailing PDU framing and re-lay the params with the
    // continuation state appended.
    let param_len = u16::from_be_bytes([pdu[3], pdu[4]]) as usize;
    let mut params = pdu[5..5 + param_len].to_vec();

    if continuation.is_empty() {
        // Nil continuation state (type 0, size index 0).
        params.push(0x00);
    } else if continuation.len() == 2 {
        // A u16 continuation offset: type 2 (u16), fixed size → size index 0.
        params.push((2 << 3) | 0);
        params.extend_from_slice(continuation);
    } else {
        // A byte sequence: type 14 (text string), 2-byte length → size index 2.
        params.push((14 << 3) | 2);
        params.extend_from_slice(&(continuation.len() as u16).to_be_bytes());
        params.extend_from_slice(continuation);
    }

    pdu.truncate(5);
    pdu[3..5].copy_from_slice(&(params.len() as u16).to_be_bytes());
    pdu.extend_from_slice(&params);
    pdu
}

fn uuid128_bytes(short: u16) -> [u8; 16] {
    let full = ((short as u128) << 96) | 0x0000_1000_8000_0080_5f9b_34fb;
    full.to_be_bytes()
}

/// Parse a `ServiceSearchAttributeResponse` PDU into records.
///
/// The response carries a continuation state: when the peer's record set is
/// larger than one PDU, it returns a partial list plus a continuation
/// token, and the client MUST re-issue the query with that token to get the
/// rest. The previous implementation treated every response as complete, so
/// a peer with more records than fit in one PDU silently lost the tail —
/// the scan reported fewer services than the device actually publishes.
///
/// Use [`parse_sdp_response_full`] when the continuation state is needed.
pub fn parse_sdp_response(pdu: &[u8]) -> Result<Vec<SdpRecord>> {
    let (records, _continuation) = parse_sdp_response_full(pdu)?;
    Ok(records)
}

/// Parse a `ServiceSearchAttributeResponse`, returning the records and the
/// continuation state (empty when the peer sent everything).
pub fn parse_sdp_response_full(pdu: &[u8]) -> Result<(Vec<SdpRecord>, Vec<u8>)> {
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

    // Spec layout: the params are `AttributeLists` — a data element — with
    // an optional `ContinuationState` data element after it.
    let (lists_element, consumed) = split_data_element(params)?;
    let lists = parse_data_element(lists_element)?;

    let mut records = Vec::new();
    if let SdpData::Seq(record_elems) = &lists {
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

    // The continuation state is the next data element, if there is one.
    let mut continuation = Vec::new();
    if let Some(rest) = params.get(consumed..)
        && !rest.is_empty()
    {
        let (cont_element, _consumed) = split_data_element(rest)?;
        let (cont_len, cont_header_len) = element_payload_len(cont_element)?;
        if let Some(body) = cont_element.get(1 + cont_header_len..1 + cont_header_len + cont_len) {
            continuation = body.to_vec();
        }
    }

    Ok((records, continuation))
}

/// The payload length and header length of the element at the front of `data`.
///
/// With size index 0 the payload length comes from the type's own size; every
/// other size index carries an explicit length field.
fn element_payload_len(data: &[u8]) -> Result<(usize, usize)> {
    let (&header, _rest) = data
        .split_first()
        .ok_or_else(|| anyhow!("empty data element"))?;
    let type_index = (header >> 3) & 0x1F;
    let size_index = header & 0x07;
    let (extent_len, header_len) = data_element_extent(data)?;
    let len = if size_index == 0 {
        match fixed_type_len(type_index) {
            Some(n) => n,
            None => return Err(anyhow!("invalid SDP type index {type_index}")),
        }
    } else {
        extent_len
    };
    Ok((len, header_len))
}

/// Split one data element off the front of `data`.
///
/// Returns the element (header included) and how many bytes of `data` it
/// consumed.
fn split_data_element(data: &[u8]) -> Result<(&[u8], usize)> {
    let (len, header_len) = element_payload_len(data)?;
    let total = 1 + header_len + len;
    let element = data.get(..total).ok_or_else(|| {
        anyhow!(
            "SDP element truncated: need {total} bytes, have {}",
            data.len()
        )
    })?;
    Ok((element, total))
}

/// The length of the data element's payload and of its length field.
///
/// The header byte is `type_index(5) | size_index(3)`: the type descriptor
/// occupies the UPPER five bits and the size descriptor the lower three.
///
/// Size index (Core Specification, Vol 3, Part A, Table 1.1):
///   0   no length field — the length comes from the type's own size
///   1   1 octet of length
///   2   2 octets of length
///   3   4 octets of length
///   4   8 octets of length
///   5   16 octets of length
///   6   1 octet of length (alternative encoding)
///   7   2 octets of length (alternative encoding)
fn data_element_extent(data: &[u8]) -> Result<(usize, usize)> {
    let (&header, rest) = data
        .split_first()
        .ok_or_else(|| anyhow!("empty data element"))?;
    let size_index = header & 0x07;
    let (len, header_len) = match size_index {
        0 => (0usize, 0usize),
        1 | 6 => {
            let n = *rest
                .first()
                .ok_or_else(|| anyhow!("SDP size byte missing"))? as usize;
            (n, 1)
        }
        2 | 7 => {
            if rest.len() < 2 {
                return Err(anyhow!("SDP 16-bit size truncated"));
            }
            (u16::from_be_bytes([rest[0], rest[1]]) as usize, 2)
        }
        3 => {
            if rest.len() < 4 {
                return Err(anyhow!("SDP 32-bit size truncated"));
            }
            (
                u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize,
                4,
            )
        }
        4 => {
            if rest.len() < 8 {
                return Err(anyhow!("SDP 64-bit size truncated"));
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&rest[..8]);
            (u64::from_be_bytes(b) as usize, 8)
        }
        5 => {
            if rest.len() < 16 {
                return Err(anyhow!("SDP 128-bit size truncated"));
            }
            let mut b = [0u8; 16];
            b.copy_from_slice(&rest[..16]);
            (u128::from_be_bytes(b) as usize, 16)
        }
        other => return Err(anyhow!("invalid SDP size index {other}")),
    };
    Ok((len, header_len))
}

/// The natural payload length of a fixed-size type, when the size index is 0.
///
/// Type index (Core Specification, Vol 3, Part A, Table 1.2).
fn fixed_type_len(type_index: u8) -> Option<usize> {
    match type_index {
        0 => Some(0),   // Nil
        1 => Some(1),   // Unsigned integer, 1 octet
        2 => Some(2),   // Unsigned integer, 2 octets
        3 => Some(4),   // Unsigned integer, 4 octets
        4 => Some(8),   // Unsigned integer, 8 octets
        5 => Some(16),  // Unsigned integer, 16 octets
        6 => Some(1),   // Signed integer, 1 octet
        7 => Some(2),   // Signed integer, 2 octets
        8 => Some(4),   // Signed integer, 4 octets
        9 => Some(8),   // Signed integer, 8 octets
        10 => Some(16), // Signed integer, 16 octets
        11 => Some(2),  // UUID, 2 octets
        12 => Some(4),  // UUID, 4 octets
        13 => Some(16), // UUID, 16 octets
        14 => Some(0),  // Text string — length always explicit
        15 => Some(1),  // Boolean, 1 octet
        16 => Some(0),  // Sequence — length always explicit
        17 => Some(0),  // Alternative — length always explicit
        18 => Some(0),  // URL — length always explicit
        _ => None,
    }
}

/// Parse one SDP data element.
///
/// The header byte is `type_index(5) | size_index(3)`. The type table is the
/// one from Core Specification Vol 3, Part A, Table 1.2; the size table is
/// Table 1.1.
///
/// The type TABLE is what was wrong: type 1 was read as a 128-bit integer,
/// type 4 as a text string and type 6 as a sequence. Every real SDP response
/// therefore decoded into the wrong shape, and the three unit tests that
/// exercised the decoder were failing on `main`.
pub fn parse_data_element(data: &[u8]) -> Result<SdpData> {
    let (&header, rest) = data
        .split_first()
        .ok_or_else(|| anyhow!("empty data element"))?;
    let type_index = (header >> 3) & 0x1F;

    let (len, header_len) = element_payload_len(data)?;

    let body = rest.get(header_len..header_len + len).ok_or_else(|| {
        anyhow!(
            "SDP element truncated: need {len}, have {}",
            rest.len().saturating_sub(header_len)
        )
    })?;

    Ok(match type_index {
        0 => SdpData::Nil,
        1 => SdpData::U8(body.first().copied().unwrap_or(0)),
        2 => SdpData::U16(read_be_u16(body)?),
        3 => SdpData::U32(read_be_u32(body)?),
        4 => SdpData::U64(read_be_u64(body)?),
        5 => SdpData::U128(read_be_u128(body)?),
        // Signed integers are decoded as their unsigned counterpart: the
        // framework only ever compares them against small positive values.
        6..=10 => match len {
            1 => SdpData::U8(body.first().copied().unwrap_or(0)),
            2 => SdpData::U16(read_be_u16(body)?),
            4 => SdpData::U32(read_be_u32(body)?),
            8 => SdpData::U64(read_be_u64(body)?),
            _ => SdpData::U128(read_be_u128(body)?),
        },
        11..=13 => SdpData::Uuid(match len {
            2 => u128::from(read_be_u16(body)?),
            4 => u128::from(read_be_u32(body)?),
            _ => read_be_u128(body)?,
        }),
        14 => SdpData::Str(body.to_vec()),
        15 => SdpData::U8(body.first().copied().unwrap_or(0)),
        16 | 17 => {
            // Sequence and Alternative are both encoded as a list of
            // elements. An Alternative holds one or two sequences.
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
        18 => SdpData::Str(body.to_vec()),
        other => return Err(anyhow!("invalid SDP type index {other}")),
    })
}

/// Total encoded size (header + payload) of the element starting at `data`.
pub fn element_size(data: &[u8]) -> Result<usize> {
    if data.is_empty() {
        return Err(anyhow!("empty element"));
    }
    let (len, header_len) = element_payload_len(data)?;
    Ok(1 + header_len + len)
}

fn read_be_u16(b: &[u8]) -> Result<u16> {
    if b.len() < 2 {
        return Err(anyhow!("u16 truncated"));
    }
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn read_be_u64(b: &[u8]) -> Result<u64> {
    if b.len() < 8 {
        return Err(anyhow!("need 8 bytes for a u64, have {}", b.len()));
    }
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[..8]);
    Ok(u64::from_be_bytes(v))
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

    /// Header byte for a fixed-size type: `type_index << 3`.
    const fn hdr(type_index: u8) -> u8 {
        type_index << 3
    }

    #[test]
    fn parses_u16_element() {
        // u16 is type index 2 with a fixed 2-octet size → header 0x10.
        let data = [hdr(2), 0x01, 0x02];
        let parsed = parse_data_element(&data).expect("parse");
        assert_eq!(parsed, SdpData::U16(0x0102));
        assert_eq!(element_size(&data).expect("size"), 3);
    }

    #[test]
    fn parses_u8_element() {
        // u8 is type index 1 → header 0x08.
        let data = [hdr(1), 0x07];
        assert_eq!(parse_data_element(&data).expect("parse"), SdpData::U8(7));
        assert_eq!(element_size(&data).expect("size"), 2);
    }

    #[test]
    fn parses_u32_element() {
        // u32 is type index 3 → header 0x18.
        let data = [hdr(3), 0x00, 0x01, 0x00, 0x00];
        assert_eq!(
            parse_data_element(&data).expect("parse"),
            SdpData::U32(0x00010000)
        );
    }

    #[test]
    fn parses_16bit_uuid() {
        // UUID, 2 octets → type index 11 → header 0x58.
        let data = [hdr(11), 0x01, 0x01];
        assert_eq!(
            parse_data_element(&data).expect("parse"),
            SdpData::Uuid(0x0101)
        );
    }

    #[test]
    fn parses_seq_of_uuids() {
        // Sequence (type 16, size index 6 → 1-byte length) with two
        // 16-bit UUIDs.
        let mut data = vec![hdr(16) | 6];
        data.push(6);
        data.extend_from_slice(&[hdr(11), 0x01, 0x01]); // uuid 0x0101
        data.extend_from_slice(&[hdr(11), 0x00, 0x03]); // uuid 0x0003 (RFCOMM)
        let parsed = parse_data_element(&data).expect("parse");
        let uuids = parsed.uuids();
        assert_eq!(uuids, vec![0x0101, 0x0003]);
    }

    #[test]
    fn rfcomm_channel_extraction() {
        // [[L2CAP uuid, PSM], [RFCOMM uuid, channel 5]]
        let mut seq = Vec::new();
        // inner: L2CAP stack — a sequence of (uuid, u16)
        let mut stack1 = vec![hdr(16) | 6, 6];
        stack1.extend_from_slice(&[hdr(11), 0x01, 0x00]); // L2CAP
        stack1.extend_from_slice(&[hdr(2), 0x00, 0x0F]); // PSM 15
        // inner: RFCOMM stack
        let mut stack2 = vec![hdr(16) | 6, 5];
        stack2.extend_from_slice(&[hdr(11), 0x00, 0x03]); // RFCOMM
        stack2.extend_from_slice(&[hdr(1), 0x05]); // channel 5
        for stack in [stack1, stack2] {
            seq.extend_from_slice(&stack);
        }
        let mut outer = vec![hdr(16) | 6];
        outer.push(seq.len() as u8);
        outer.extend_from_slice(&seq);
        let parsed = parse_data_element(&outer).expect("parse");
        assert_eq!(parsed.rfcomm_channel(), Some(5));
    }

    #[test]
    fn request_is_wellformed() {
        let req = build_service_search_attribute_request();
        // PDU id 0x04 = ServiceSearchAttributeRequest.
        assert_eq!(req[0], 0x04);
        // The first parameter is a sequence (type 16) with a 1-byte length.
        assert_eq!(req[5], hdr(16) | 6);
        // Inside it, a 128-bit UUID (type 13).
        assert_eq!(req[7], hdr(13));
    }

    /// Build a spec-shaped `ServiceSearchAttributeResponse` carrying one
    /// service record and an optional continuation state.
    fn build_response(records: &[u16], continuation: Option<&[u8]>) -> Vec<u8> {
        // AttributeLists: a sequence of sequences.
        let mut lists_content = Vec::new();
        for uuid in records {
            // One record: a sequence of (attr_id u16, attr_value).
            let mut record_content = Vec::new();
            // AttributeID = 0x0001 (service class id list), value = a
            // sequence holding one 16-bit uuid.
            record_content.extend_from_slice(&[hdr(2), 0x00, 0x01]); // attr id
            // The uuid sequence holds one 16-bit uuid → a 3-byte body.
            let mut uuid_seq = vec![hdr(16) | 6, 3];
            uuid_seq.extend_from_slice(&[hdr(11), (uuid >> 8) as u8, (uuid & 0xFF) as u8]);
            record_content.extend_from_slice(&uuid_seq);
            let mut record = vec![hdr(16) | 6, record_content.len() as u8];
            record.extend_from_slice(&record_content);
            lists_content.extend_from_slice(&record);
        }
        // The lists sequence — a 2-byte length, so size index 7.
        let mut lists = vec![hdr(16) | 7];
        lists.extend_from_slice(&(lists_content.len() as u16).to_be_bytes());
        lists.extend_from_slice(&lists_content);

        let mut params = lists;
        if let Some(cont) = continuation {
            // Continuation state: a u16 data element.
            params.push(hdr(2));
            params.extend_from_slice(cont);
        }

        let mut pdu = vec![0x07u8, 0x00, 0x01];
        pdu.extend_from_slice(&(params.len() as u16).to_be_bytes());
        pdu.extend_from_slice(&params);
        pdu
    }

    #[test]
    fn response_records_are_parsed() {
        let pdu = build_response(&[0x1101, 0x110B], None);
        let records = parse_sdp_response(&pdu).expect("should parse");
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|r| r.uuids.contains(&0x1101)));
        assert!(records.iter().any(|r| r.a2dp));
    }

    #[test]
    fn continuation_state_is_reported() {
        // A peer with more records than fit in one PDU returns a token.
        let pdu = build_response(&[0x1101], Some(&[0x00, 0x40]));
        let (records, continuation) = parse_sdp_response_full(&pdu).expect("should parse");
        assert_eq!(records.len(), 1);
        assert_eq!(continuation, vec![0x00, 0x40]);

        // And the token can be put back into the next request.
        let req = build_service_search_attribute_request_continued(&continuation);
        assert_eq!(req[0], 0x04);
        // The continuation state is the last data element.
        let param_len = u16::from_be_bytes([req[3], req[4]]) as usize;
        assert_eq!(
            &req[5 + param_len - 3..5 + param_len],
            &[hdr(2), 0x00, 0x40]
        );
    }

    #[test]
    fn no_continuation_state_yields_an_empty_token() {
        let pdu = build_response(&[0x1101], None);
        let (_records, continuation) = parse_sdp_response_full(&pdu).expect("should parse");
        assert!(continuation.is_empty());
    }
}

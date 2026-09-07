//! btsnoop capture parsing (Android HCI snoop / `btmon -w` format).
//!
//! The BLUFFS / InjectaBLE analyzers and the LE legacy-pairing TK cracker all
//! consume captures in this format: header `btsnoop\0` + version + datalink,
//! then records `original_len | included_len | flags | drops | timestamp` +
//! packet. Datalink 1002 = HCI UART (H4), 1005 = Android internal — both put
//! HCI packets (0x02 ACL out, 0x04 event) in the record payload.

use anyhow::{Result, anyhow};

/// Datalink: HCI UART (H4).
pub const DATALINK_H4: u32 = 1002;
/// Datalink: Android internal logger.
pub const DATALINK_ANDROID: u32 = 1005;

/// HCI packet types as carried in H4 captures.
pub const HCI_ACL_PKT: u8 = 0x02;
pub const HCI_EVENT_PKT: u8 = 0x04;

/// One decoded capture record.
#[derive(Debug, Clone)]
pub struct BtsnoopRecord {
    /// Flags bit0: 0 = host→controller, 1 = controller→host.
    pub sent_by_host: bool,
    pub timestamp_us: u64,
    pub packet_type: u8,
    /// ACL handle (0 for events).
    pub conn_handle: u16,
    pub payload: Vec<u8>,
}

/// Parse a full btsnoop file into records.
pub fn parse(data: &[u8]) -> Result<Vec<BtsnoopRecord>> {
    if data.len() < 16 || &data[0..8] != b"btsnoop\0" {
        return Err(anyhow!("not a btsnoop file (missing magic)"));
    }
    let version = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    if version != 1 {
        return Err(anyhow!("unsupported btsnoop version {version}"));
    }
    let mut records = Vec::new();
    let mut off = 16usize;
    while off + 24 <= data.len() {
        let included = u32::from_be_bytes(data[off + 4..off + 8].try_into()?) as usize;
        let flags = u32::from_be_bytes(data[off + 8..off + 12].try_into()?);
        let timestamp = u64::from_be_bytes(data[off + 16..off + 24].try_into()?);
        off += 24;
        if included == 0 || off + included > data.len() {
            break;
        }
        let pkt = &data[off..off + included];
        off += included;
        let (packet_type, conn_handle, payload) = match pkt.first() {
            Some(&HCI_EVENT_PKT) => (HCI_EVENT_PKT, 0u16, pkt.get(1..).unwrap_or(&[]).to_vec()),
            Some(&HCI_ACL_PKT) => {
                if pkt.len() < 5 {
                    continue;
                }
                let handle_flags = u16::from_le_bytes([pkt[1], pkt[2]]);
                let len = u16::from_le_bytes([pkt[3], pkt[4]]) as usize;
                (
                    HCI_ACL_PKT,
                    handle_flags & 0x0FFF,
                    pkt.get(5..5 + len).unwrap_or(&[]).to_vec(),
                )
            }
            _ => continue,
        };
        records.push(BtsnoopRecord {
            sent_by_host: flags & 0x01 == 0,
            timestamp_us: timestamp,
            packet_type,
            conn_handle,
            payload,
        });
    }
    Ok(records)
}

/// L2CAP-signalling extract: every ACL record whose L2CAP CID is 0x0001,
/// decoded as (sent_by_host, handle, code, id, data).
#[derive(Debug, Clone)]
pub struct SignalingPdu {
    pub sent_by_host: bool,
    pub handle: u16,
    pub code: u8,
    pub id: u8,
    pub data: Vec<u8>,
    pub timestamp_us: u64,
}

/// Extract L2CAP signalling PDUs from parsed records.
pub fn extract_signaling(records: &[BtsnoopRecord]) -> Vec<SignalingPdu> {
    let mut out = Vec::new();
    for r in records {
        if r.packet_type != HCI_ACL_PKT || r.payload.len() < 4 {
            continue;
        }
        let len = u16::from_le_bytes([r.payload[0], r.payload[1]]) as usize;
        let cid = u16::from_le_bytes([r.payload[2], r.payload[3]]);
        if cid != 0x0001 {
            continue;
        }
        let sig = match r.payload.get(4..4 + len) {
            Some(s) => s,
            None => continue,
        };
        if sig.len() < 4 {
            continue;
        }
        let code = sig[0];
        let id = sig[1];
        let dlen = u16::from_le_bytes([sig[2], sig[3]]) as usize;
        let data = sig.get(4..4 + dlen).unwrap_or(&[]).to_vec();
        out.push(SignalingPdu {
            sent_by_host: r.sent_by_host,
            handle: r.conn_handle,
            code,
            id,
            data,
            timestamp_us: r.timestamp_us,
        });
    }
    out
}

/// SMP extract: every ACL record on the Security Manager CID (0x0006),
/// decoded as (sent_by_host, opcode, data). LE legacy pairing captures carry
/// `Pairing Confirm` (0x03) and `Pairing Random` (0x04) here.
#[derive(Debug, Clone)]
pub struct SmpPdu {
    pub sent_by_host: bool,
    pub opcode: u8,
    pub data: Vec<u8>,
}

pub const SMP_PAIRING_CONFIRM: u8 = 0x03;
pub const SMP_PAIRING_RANDOM: u8 = 0x04;

pub fn extract_smp(records: &[BtsnoopRecord]) -> Vec<SmpPdu> {
    let mut out = Vec::new();
    for r in records {
        if r.packet_type != HCI_ACL_PKT || r.payload.len() < 5 {
            continue;
        }
        let len = u16::from_le_bytes([r.payload[0], r.payload[1]]) as usize;
        let cid = u16::from_le_bytes([r.payload[2], r.payload[3]]);
        if cid != 0x0006 {
            continue;
        }
        if let Some(body) = r.payload.get(4..4 + len)
            && let Some(&opcode) = body.first()
        {
            out.push(SmpPdu {
                sent_by_host: r.sent_by_host,
                opcode,
                data: body.get(1..).unwrap_or(&[]).to_vec(),
            });
        }
    }
    out
}

/// SMP address quadruple extracted from a `LE_Connection_Complete` event.
/// `iat`/`rat`: 0 = public address, 1 = random. `ia`/`ra` are 6-byte addresses
/// in **display order** (most-significant octet first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmpAddresses {
    pub iat: u8,
    pub ia: [u8; 6],
    pub rat: u8,
    pub ra: [u8; 6],
}

/// Walk the records for the first `LE_Connection_Complete` event
/// (event 0x3E, subevent 0x01) and extract the initiator/responder address
/// quadruple the SMP `c1` confirm generator needs. The event payload (after
/// the 2-byte subevent code at bytes 1-2) carries:
///   status(1) + handle(2) + role(1: 0=master, 1=slave)
///   + peer_bdaddr_type(1: 0=public, 1=random) + peer_bdaddr(6)
///   + local_rpa(6) + peer_rpa(6)
/// We treat the capture's viewpoint as the responder (`ra`) — the local
/// device is implicitly on the radio that wrote the capture. The btsnoop
/// file header does not carry a `local_bdaddr` field (btsnoop v1 is just a
/// 16-byte magic+version+datalink header), so `ra` defaults to all-zero
/// when the local address cannot be determined; the cracker falls back to
/// the zero-path on that case.
pub fn extract_smp_addresses(records: &[BtsnoopRecord]) -> Result<SmpAddresses> {
    for r in records {
        if r.packet_type != HCI_EVENT_PKT || r.payload.len() < 4 {
            continue;
        }
        if r.payload[0] != 0x3E || r.payload[1] != 0x01 {
            continue;
        }
        // The 2-byte subevent code occupies bytes 1-2 of the event params;
        // payload of the LE_Meta_Event is in `r.payload[2..]`.
        let p = &r.payload[2..];
        if p.len() < 22 {
            continue;
        }
        let status = p[0];
        if status != 0 {
            continue;
        }
let role = p[3];
        let peer_addr_type = p[4];
        let mut peer_addr = [0u8; 6];
        peer_addr.copy_from_slice(&p[5..11]);
        // btsnoop v1 has no local-bdaddr in the header — leave ra as zero
        // rather than fabricate one.
        let local_addr = [0u8; 6];
        let (iat, ia, rat, ra) = if role == 0 {
            // Capture belongs to the master: ia = peer_addr, ra = local.
            (peer_addr_type & 0x01, peer_addr, 0u8, local_addr)
        } else {
            // Capture belongs to the slave: ra = peer_addr, ia = local.
            (0u8, local_addr, peer_addr_type & 0x01, peer_addr)
        };
        return Ok(SmpAddresses { iat, ia, rat, ra });
    }
    Err(anyhow!(
        "no LE_Connection_Complete in capture — cannot recover SMP addresses"
    ))
}

/// Extract HCI `Encryption Change` (event 0x08) results:
/// (handle, enabled, key_size).
pub fn extract_encryption_changes(records: &[BtsnoopRecord]) -> Vec<(u16, bool, u8)> {
    let mut out = Vec::new();
    for r in records {
        if r.packet_type != HCI_EVENT_PKT || r.payload.is_empty() || r.payload[0] != 0x08 {
            continue;
        }
        let p = &r.payload[1..];
        if p.len() >= 4 {
            let handle = u16::from_le_bytes([p[1], p[2]]);
            out.push((handle, p[0] == 0x01, p[3]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_capture() {
        let mut data = Vec::new();
        data.extend_from_slice(b"btsnoop\0");
        data.extend_from_slice(&1u32.to_be_bytes()); // version
        data.extend_from_slice(&DATALINK_H4.to_be_bytes());
        // One ACL record: handle 0x000B, 4-byte L2CAP header + 4-byte signal.
        let mut pkt = vec![HCI_ACL_PKT];
        pkt.extend_from_slice(&0x000Bu16.to_le_bytes()); // handle+flags
        let mut l2 = vec![4u8, 0, 0x01, 0x00, 0x02, 0x07, 4, 0, 0x03, 0x00, 0x11, 0x00];
        pkt.append(&mut l2);
        data.extend_from_slice(&(pkt.len() as u32).to_be_bytes());
        data.extend_from_slice(&(pkt.len() as u32).to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes()); // flags: host→ctrl
        data.extend_from_slice(&0u32.to_be_bytes()); // drops
        data.extend_from_slice(&0u64.to_be_bytes()); // timestamp
        data.extend_from_slice(&pkt);

        let records = parse(&data).expect("parse");
        assert_eq!(records.len(), 1);
        assert!(records[0].sent_by_host);
        assert_eq!(records[0].conn_handle, 0x000B);
        let sig = extract_signaling(&records);
        assert_eq!(sig.len(), 1);
        assert_eq!(sig[0].code, 0x02);
        assert_eq!(sig[0].data, vec![0x03, 0x00, 0x11, 0x00]);
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(parse(b"nope").is_err());
    }
}

//! BNEP 1.0 (Bluetooth Network Encapsulation Protocol) over L2CAP PSM 0x000F.
//!
//! BNEP carries Ethernet frames on top of L2CAP. Before any data flow both
//! sides exchange a setup message (with UUID-sized service handles) and
//! optionally a filter net type set. This module owns:
//!
//! - General Ethernet / No Ethernet type encoders.
//! - Setup Connection Request/Response (2-byte and 16-byte UUID variants).
//! - Filter set / add / delete control commands.
//! - Connect / Connect Response (used by personal-area networking).
//!
//! All packet builders are pure (no I/O); the async helpers take a
//! `&mut L2capChannel` and run the blocking I/O on `spawn_blocking`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::sync::Mutex;
use tokio::task;

use super::hci::L2capChannel;
use super::lmp::PSM_BNEP;

pub const BNEP_TYPE_GENERAL_ETHERNET: u8 = 0x01;
pub const BNEP_TYPE_NO_ETHERNET: u8 = 0x02;
pub const BNEP_TYPE_COMPRESSED_ETHERNET: u8 = 0x03;
pub const BNEP_TYPE_COMPRESSED_EUREL: u8 = 0x04;
pub const BNEP_TYPE_SOURCE_ADDR_EXT: u8 = 0x05;
pub const BNEP_TYPE_DEST_ADDR_EXT: u8 = 0x06;

pub const BNEP_CMD_NOT_UNDERSTOOD: u8 = 0x00;
pub const BNEP_CMD_SETUP_REQ: u8 = 0x01;
pub const BNEP_CMD_SETUP_RESP: u8 = 0x02;
pub const BNEP_CMD_FILTER_NET_TYPE_SET: u8 = 0x03;
pub const BNEP_CMD_FILTER_NET_TYPE_RESP: u8 = 0x04;
pub const BNEP_CMD_FILTER_ADD_REQ: u8 = 0x05;
pub const BNEP_CMD_FILTER_ADD_RESP: u8 = 0x06;
pub const BNEP_CMD_FILTER_DELETE_REQ: u8 = 0x07;
pub const BNEP_CMD_FILTER_DELETE_RESP: u8 = 0x08;
pub const BNEP_CMD_CONNECT_REQ: u8 = 0x09;
pub const BNEP_CMD_CONNECT_RESP: u8 = 0x0A;

pub const BNEP_SETUP_SUCCESS: u16 = 0x0000;
pub const BNEP_SETUP_INVALID_DEST_UUID: u16 = 0x0001;
pub const BNEP_SETUP_INVALID_SRC_UUID: u16 = 0x0002;
pub const BNEP_SETUP_UUID16_NOT_SUPPORTED: u16 = 0x0003;
pub const BNEP_SETUP_UUID32_NOT_SUPPORTED: u16 = 0x0004;
pub const BNEP_SETUP_UUID128_NOT_SUPPORTED: u16 = 0x0005;

pub const BNEP_SERVICE_PANU: u16 = 0x1115;
pub const BNEP_SERVICE_NAP: u16 = 0x1116;
pub const BNEP_SERVICE_GN: u16 = 0x1117;

pub fn build_ethernet_packet(frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + frame.len());
    out.push(BNEP_TYPE_GENERAL_ETHERNET);
    out.extend_from_slice(frame);
    out
}

pub fn build_no_ethernet_packet(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(BNEP_TYPE_NO_ETHERNET);
    out.extend_from_slice(payload);
    out
}

pub fn build_setup_request_2byte(src_uuid: u16, dst_uuid: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(7);
    out.push(BNEP_CMD_SETUP_REQ);
    out.push(0x01); // UUID size = 2 bytes
    out.extend_from_slice(&dst_uuid.to_be_bytes());
    out.extend_from_slice(&src_uuid.to_be_bytes());
    out
}

pub fn build_setup_request_4byte(src_uuid: u32, dst_uuid: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(11);
    out.push(BNEP_CMD_SETUP_REQ);
    out.push(0x02); // UUID size = 4 bytes
    out.extend_from_slice(&dst_uuid.to_be_bytes());
    out.extend_from_slice(&src_uuid.to_be_bytes());
    out
}

pub fn build_setup_request_16byte(src_uuid: &[u8; 16], dst_uuid: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(35);
    out.push(BNEP_CMD_SETUP_REQ);
    out.push(0x10); // UUID size = 16 bytes
    out.extend_from_slice(dst_uuid);
    out.extend_from_slice(src_uuid);
    out
}

pub fn build_setup_response_2byte(src_uuid: u16, dst_uuid: u16, code: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    out.push(BNEP_CMD_SETUP_RESP);
    out.push(0x01);
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&dst_uuid.to_be_bytes());
    out.extend_from_slice(&src_uuid.to_be_bytes());
    out
}

pub fn build_filter_net_type_set(cnt: u16, types: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + types.len());
    out.push(BNEP_CMD_FILTER_NET_TYPE_SET);
    out.extend_from_slice(&cnt.to_be_bytes());
    out.extend_from_slice(types);
    out
}

pub fn build_filter_net_type_response(cnt: u16, types: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + types.len());
    out.push(BNEP_CMD_FILTER_NET_TYPE_RESP);
    out.extend_from_slice(&cnt.to_be_bytes());
    out.extend_from_slice(types);
    out
}

pub fn build_filter_add(dst_mac: &[u8; 6]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    out.push(BNEP_CMD_FILTER_ADD_REQ);
    out.extend_from_slice(dst_mac);
    out
}

pub fn build_filter_delete(dst_mac: &[u8; 6]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    out.push(BNEP_CMD_FILTER_DELETE_REQ);
    out.extend_from_slice(dst_mac);
    out
}

pub fn build_connect_request(src_uuid_size: u8, src_uuid: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + src_uuid.len());
    out.push(BNEP_CMD_CONNECT_REQ);
    out.push(src_uuid_size);
    out.extend_from_slice(src_uuid);
    out
}

pub fn build_connect_response(src_uuid_size: u8, src_uuid: &[u8], code: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + src_uuid.len());
    out.push(BNEP_CMD_CONNECT_RESP);
    out.push(src_uuid_size);
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(src_uuid);
    out
}

pub fn build_command_not_understood(command: u8) -> Vec<u8> {
    vec![BNEP_CMD_NOT_UNDERSTOOD, command]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BnepControl {
    Setup {
        uuid_size: u8,
        dst: Vec<u8>,
        src: Vec<u8>,
    },
    SetupResponse {
        uuid_size: u8,
        code: u16,
        dst: Vec<u8>,
        src: Vec<u8>,
    },
    FilterNetTypeSet {
        count: u16,
        types: Vec<u8>,
    },
    FilterNetTypeResponse {
        count: u16,
        types: Vec<u8>,
    },
    FilterAdd([u8; 6]),
    FilterDelete([u8; 6]),
    Connect {
        uuid_size: u8,
        src: Vec<u8>,
    },
    ConnectResponse {
        uuid_size: u8,
        code: u16,
        src: Vec<u8>,
    },
    NotUnderstood(u8),
}

pub fn parse_control(data: &[u8]) -> Result<BnepControl> {
    if data.is_empty() {
        return Err(anyhow!("BNEP: empty control packet"));
    }
    match data[0] {
        BNEP_CMD_NOT_UNDERSTOOD => {
            let cmd = *data.get(1).ok_or_else(|| anyhow!("BNEP: not-understood truncated"))?;
            Ok(BnepControl::NotUnderstood(cmd))
        }
        BNEP_CMD_SETUP_REQ => {
            let size = *data.get(1).ok_or_else(|| anyhow!("BNEP: setup-req missing size"))? as usize;
            let body = &data[2..];
            if body.len() < size * 2 {
                return Err(anyhow!("BNEP: setup-req truncated"));
            }
            let dst = body[..size].to_vec();
            let src = body[size..size * 2].to_vec();
            Ok(BnepControl::Setup {
                uuid_size: size as u8,
                dst,
                src,
            })
        }
        BNEP_CMD_SETUP_RESP => {
            let size = *data.get(1).ok_or_else(|| anyhow!("BNEP: setup-resp missing size"))? as usize;
            let body = &data[2..];
            if body.len() < 2 + size * 2 {
                return Err(anyhow!("BNEP: setup-resp truncated"));
            }
            let code = u16::from_be_bytes([body[0], body[1]]);
            let dst = body[2..2 + size].to_vec();
            let src = body[2 + size..2 + size * 2].to_vec();
            Ok(BnepControl::SetupResponse {
                uuid_size: size as u8,
                code,
                dst,
                src,
            })
        }
        BNEP_CMD_FILTER_NET_TYPE_SET => {
            let count = u16::from_be_bytes([data[1], data[2]]);
            let types = data.get(3..).unwrap_or(&[]).to_vec();
            Ok(BnepControl::FilterNetTypeSet { count, types })
        }
        BNEP_CMD_FILTER_NET_TYPE_RESP => {
            let count = u16::from_be_bytes([data[1], data[2]]);
            let types = data.get(3..).unwrap_or(&[]).to_vec();
            Ok(BnepControl::FilterNetTypeResponse { count, types })
        }
        BNEP_CMD_FILTER_ADD_REQ | BNEP_CMD_FILTER_DELETE_REQ => {
            if data.len() < 7 {
                return Err(anyhow!("BNEP: filter-add/delete truncated"));
            }
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&data[1..7]);
            Ok(if data[0] == BNEP_CMD_FILTER_ADD_REQ {
                BnepControl::FilterAdd(mac)
            } else {
                BnepControl::FilterDelete(mac)
            })
        }
        BNEP_CMD_CONNECT_REQ => {
            let size = *data.get(1).ok_or_else(|| anyhow!("BNEP: connect-req size missing"))? as usize;
            let src = data.get(2..2 + size).unwrap_or(&[]).to_vec();
            Ok(BnepControl::Connect {
                uuid_size: size as u8,
                src,
            })
        }
        BNEP_CMD_CONNECT_RESP => {
            let size = *data.get(1).ok_or_else(|| anyhow!("BNEP: connect-resp size missing"))? as usize;
            if data.len() < 4 + size {
                return Err(anyhow!("BNEP: connect-resp truncated"));
            }
            let code = u16::from_be_bytes([data[2], data[3]]);
            let src = data[4..4 + size].to_vec();
            Ok(BnepControl::ConnectResponse {
                uuid_size: size as u8,
                code,
                src,
            })
        }
        other => Err(anyhow!("BNEP: unknown control command 0x{other:02X}")),
    }
}

pub async fn setup_connection(channel: Arc<Mutex<L2capChannel>>, src_uuid: u16, dst_uuid: u16) -> Result<()> {
    let req = build_setup_request_2byte(src_uuid, dst_uuid);
    let result = task::spawn_blocking(move || -> Result<u16> {
        let channel = channel.blocking_lock();
        let mut guard = channel;
        send_exact(&mut guard, &req)?;
        let mut buf = [0u8; 64];
        let n = guard.recv(&mut buf, Duration::from_secs(5))?;
        if n < 4 {
            return Err(anyhow!("BNEP: setup response truncated: {n} bytes"));
        }
        let parsed = parse_control(&buf[..n])?;
        match parsed {
            BnepControl::SetupResponse { code, .. } => Ok(code),
            other => Err(anyhow!("BNEP: expected setup-response, got {other:?}")),
        }
    })
    .await
    .map_err(|e| anyhow!("BNEP setup task: {e}"))??;

    if result != BNEP_SETUP_SUCCESS {
        anyhow::bail!("BNEP setup refused: code 0x{result:04X}");
    }
    Ok(())
}

pub async fn send_ethernet_frame(channel: Arc<Mutex<L2capChannel>>, frame: &[u8]) -> Result<()> {
    let pkt = build_ethernet_packet(frame);
    let payload = pkt.clone();
    task::spawn_blocking(move || -> Result<()> {
        let channel = channel.blocking_lock();
        let mut guard = channel;
        send_exact(&mut guard, &payload)
    })
    .await
    .map_err(|e| anyhow!("BNEP ethernet send task: {e}"))?
}

fn send_exact(channel: &mut L2capChannel, data: &[u8]) -> Result<()> {
    let mut off = 0usize;
    while off < data.len() {
        let n = channel.send(&data[off..])?;
        off += n;
    }
    Ok(())
}

pub async fn connect_bnep(bdaddr: &str) -> Result<Arc<Mutex<L2capChannel>>> {
    let bdaddr_owned = bdaddr.to_string();
    let channel = task::spawn_blocking(move || -> Result<L2capChannel> {
        L2capChannel::connect(&bdaddr_owned, PSM_BNEP)
    })
    .await
    .map_err(|e| anyhow!("BNEP L2CAP connect task: {e}"))??;
    let arc = Arc::new(Mutex::new(channel));
    setup_connection(arc.clone(), BNEP_SERVICE_PANU, BNEP_SERVICE_NAP).await?;
    Ok(arc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_req_roundtrip() {
        let req = build_setup_request_2byte(BNEP_SERVICE_PANU, BNEP_SERVICE_NAP);
        let parsed = parse_control(&req).expect("parse");
        match parsed {
            BnepControl::Setup {
                uuid_size,
                dst,
                src,
            } => {
                assert_eq!(uuid_size, 2);
                assert_eq!(dst, BNEP_SERVICE_NAP.to_be_bytes());
                assert_eq!(src, BNEP_SERVICE_PANU.to_be_bytes());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn setup_resp_success() {
        let resp = build_setup_response_2byte(BNEP_SERVICE_PANU, BNEP_SERVICE_NAP, BNEP_SETUP_SUCCESS);
        let parsed = parse_control(&resp).expect("parse");
        match parsed {
            BnepControl::SetupResponse { code, .. } => assert_eq!(code, BNEP_SETUP_SUCCESS),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn ethernet_packet_has_type_prefix() {
        let pkt = build_ethernet_packet(&[0xAA; 14]);
        assert_eq!(pkt[0], BNEP_TYPE_GENERAL_ETHERNET);
        assert_eq!(&pkt[1..], &[0xAA; 14]);
    }

    #[test]
    fn filter_set_roundtrip() {
        let req = build_filter_net_type_set(2, &[0x08, 0x00]);
        let parsed = parse_control(&req).expect("parse");
        match parsed {
            BnepControl::FilterNetTypeSet { count, types } => {
                assert_eq!(count, 2);
                assert_eq!(types, vec![0x08, 0x00]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn not_understood_roundtrip() {
        let p = build_command_not_understood(0x55);
        match parse_control(&p).expect("parse") {
            BnepControl::NotUnderstood(c) => assert_eq!(c, 0x55),
            _ => panic!("wrong variant"),
        }
    }
}

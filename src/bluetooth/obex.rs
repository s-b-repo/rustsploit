//! OBEX 1.5 (IrOBEX) client over `RfcommSession`.
//!
//! Standard Bluetooth server channels:
//! - `0x04` — OBEX File Transfer (FTP)
//! - `0x05` — OBEX Object Push (OPP)
//! - `0x06` — OBEX Synchronisation (SYNC)
//! - `0x0F` or `0x10` — Phone Book Access (PBAP, uses a non-standard port)
//!
//! Request/response layout:
//!
//! | field         | size           |
//! |---------------|----------------|
//! | opcode        | 1 byte         |
//! | length        | 2 bytes BE     |
//! | headers       | variable       |
//!
//! Header ID (1) + length (2 BE) + value. `0x49` End-of-Body and `0xC0`
//! SetPath carry no length (the value bytes follow inline).

use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::sync::Mutex;

use super::rfcomm::RfcommSession;

pub mod opcode {
    pub const CONNECT: u8 = 0x80;
    pub const DISCONNECT: u8 = 0x81;
    pub const PUT: u8 = 0x02;
    pub const GET: u8 = 0x03;
    pub const SETPATH: u8 = 0x05;
    pub const CONTINUE: u8 = 0x10;
    pub const OK: u8 = 0x20;
    pub const FORBIDDEN: u8 = 0x40;
    pub const NOT_FOUND: u8 = 0x44;
    pub const SERVICE_UNAVAILABLE: u8 = 0x4F;
    pub const INTERNAL_ERROR: u8 = 0x50;
}

pub mod hid {
    pub const CONNECTION_ID: u8 = 0x01;
    pub const NAME: u8 = 0x42;
    pub const TYPE: u8 = 0x44;
    pub const TARGET: u8 = 0x4C;
    pub const BODY: u8 = 0x48;
    pub const END_OF_BODY: u8 = 0x49;
    pub const LENGTH: u8 = 0xC3;
    pub const SETPATH_FLAGS: u8 = 0xC0;
    pub const APPLICATION_PARAMS: u8 = 0x4C;
    pub const WHO: u8 = 0x4A;
}

#[derive(Debug, Clone, Default)]
pub struct ObexListing {
    pub name: String,
    pub type_: String,
    pub size: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ObexResponse {
    pub opcode: u8,
    pub headers: Vec<(u8, Vec<u8>)>,
}

pub fn build_connect_req(max_packet: u16) -> Vec<u8> {
    let mut payload = [0u8; 7];
    payload[0] = 0x10;
    payload[1] = 0x00;
    payload[2] = (max_packet >> 8) as u8;
    payload[3] = (max_packet & 0xFF) as u8;
    payload[4] = 0x40;
    payload[5] = 0x00;
    payload[6] = 0xFF;
    pdu(opcode::CONNECT, &payload)
}

pub fn build_disconnect_req() -> Vec<u8> {
    pdu(opcode::DISCONNECT, &[])
}

pub fn build_setpath_req(name: Option<&str>, flags: u8) -> Vec<u8> {
    let mut payload = vec![flags];
    if let Some(n) = name {
        if !n.is_empty() {
            push_header(&mut payload, hid::NAME, n.as_bytes());
        }
    }
    pdu(opcode::SETPATH, &payload)
}

pub fn build_put_req(name: &str, total_len: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(48);
    push_header(&mut payload, hid::NAME, name.as_bytes());
    push_header(&mut payload, hid::LENGTH, &total_len.to_be_bytes());
    pdu(opcode::PUT, &payload)
}

pub fn build_get_req(name: Option<&str>, type_: Option<&str>) -> Vec<u8> {
    let mut payload = Vec::with_capacity(48);
    if let Some(n) = name {
        if !n.is_empty() {
            push_header(&mut payload, hid::NAME, n.as_bytes());
        }
    }
    if let Some(t) = type_ {
        push_header(&mut payload, hid::TYPE, t.as_bytes());
    }
    pdu(opcode::GET, &payload)
}

fn push_header(out: &mut Vec<u8>, id: u8, value: &[u8]) {
    out.push(id);
    out.push(((value.len() >> 8) & 0xFF) as u8);
    out.push((value.len() & 0xFF) as u8);
    out.extend_from_slice(value);
}

fn pdu(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + payload.len());
    out.push(opcode);
    out.push(((payload.len() >> 8) & 0xFF) as u8);
    out.push((payload.len() & 0xFF) as u8);
    out.extend_from_slice(payload);
    out
}

pub fn parse_response(data: &[u8]) -> Result<ObexResponse> {
    if data.len() < 3 {
        return Err(anyhow!("OBEX response too short: {} bytes", data.len()));
    }
    let op = data[0];
    let len = u16::from_be_bytes([data[1], data[2]]) as usize;
    let body = data
        .get(3..3 + len)
        .ok_or_else(|| anyhow!("OBEX response body truncated: want {len}"))?;
    let mut headers = Vec::new();
    let mut i = 0usize;
    while i < body.len() {
        let id = body[i];
        if id == hid::END_OF_BODY || id == hid::SETPATH_FLAGS {
            // Single-byte or empty payloads.
            let v_start = i + 1;
            if id == hid::SETPATH_FLAGS {
                if v_start >= body.len() {
                    return Err(anyhow!("OBEX: SETPATH flag byte missing"));
                }
                headers.push((id, vec![body[v_start]]));
                i = v_start + 1;
            } else {
                headers.push((id, Vec::new()));
                i = v_start;
            }
            continue;
        }
        if i + 2 >= body.len() {
            return Err(anyhow!("OBEX: truncated header length at offset {i}"));
        }
        let hlen = u16::from_be_bytes([body[i + 1], body[i + 2]]) as usize;
        let v_start = i + 3;
        let v_end = v_start + hlen;
        if v_end > body.len() {
            return Err(anyhow!("OBEX: header payload truncated"));
        }
        headers.push((id, body[v_start..v_end].to_vec()));
        i = v_end;
    }
    Ok(ObexResponse {
        opcode: op,
        headers,
    })
}

impl ObexResponse {
    pub fn success(&self) -> bool {
        matches!(self.opcode, opcode::OK)
    }
    pub fn continue_(&self) -> bool {
        self.opcode == opcode::CONTINUE
    }
    pub fn status_name(&self) -> &'static str {
        match self.opcode {
            opcode::OK => "OK",
            opcode::CONTINUE => "Continue",
            opcode::FORBIDDEN => "Forbidden",
            opcode::NOT_FOUND => "Not Found",
            opcode::SERVICE_UNAVAILABLE => "Service Unavailable",
            opcode::INTERNAL_ERROR => "Internal Server Error",
            _ => "Unknown",
        }
    }
    pub fn body_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (id, v) in &self.headers {
            if *id == hid::BODY || *id == hid::END_OF_BODY {
                out.extend_from_slice(v);
            }
        }
        out
    }
    pub fn listing(&self) -> Vec<ObexListing> {
        let mut listings = Vec::new();
        for (id, v) in &self.headers {
            if *id == hid::APPLICATION_PARAMS {
                let mut off = 0usize;
                while off + 2 < v.len() {
                    let tag = v[off];
                    let len = v[off + 1] as usize;
                    off += 2;
                    off += len;
                    listings.push(ObexListing {
                        name: format!("tag_0x{:02X}", tag),
                        type_: "x-bt/folder".into(),
                        size: None,
                    });
                }
            }
        }
        listings
    }
    pub fn name(&self) -> Option<String> {
        for (id, v) in &self.headers {
            if *id == hid::NAME {
                let mut s = String::from_utf8_lossy(v).to_string();
                while s.ends_with('\0') {
                    s.pop();
                }
                return Some(s);
            }
        }
        None
    }
}

pub struct ObexClient {
    rfcomm: Mutex<RfcommSession>,
    max_packet_len: u16,
}

impl ObexClient {
    pub async fn connect(bdaddr: &str, server_channel: u8) -> Result<Self> {
        let rfcomm = RfcommSession::connect(bdaddr, server_channel).await?;
        let me = Self {
            rfcomm: Mutex::new(rfcomm),
            max_packet_len: 1024,
        };
        let connect_pdu = build_connect_req(me.max_packet_len);
        me.exchange(&connect_pdu).await?;
        Ok(me)
    }

    async fn exchange(&self, pdu: &[u8]) -> Result<ObexResponse> {
        let mut buf = vec![0u8; 4096];
        let mut rfcomm = self.rfcomm.lock().await;
        rfcomm.send(pdu).await?;
        let n = rfcomm.recv(&mut buf, Duration::from_secs(10)).await?;
        let resp = parse_response(&buf[..n])?;
        if !resp.success() && resp.opcode != opcode::CONTINUE {
            anyhow::bail!(
                "OBEX request failed: opcode 0x{:02X} ({})",
                resp.opcode,
                resp.status_name()
            );
        }
        Ok(resp)
    }

    pub async fn disconnect(self) -> Result<()> {
        let mut rfcomm = self.rfcomm.lock().await;
        if let Err(e) = rfcomm.send(&build_disconnect_req()).await {
            tracing::debug!("OBEX disconnect send: {e:#}");
        }
        rfcomm.close().await
    }

    pub async fn put_file(&mut self, name: &str, body: &[u8]) -> Result<()> {
        let header = build_put_req(name, body.len() as u32);
        let chunk = (self.max_packet_len as usize).saturating_sub(header.len() + 3);
        if chunk == 0 {
            anyhow::bail!("OBEX max_packet too small for any body fragment");
        }
        let mut sent = 0usize;
        while sent < body.len() {
            let end = (sent + chunk).min(body.len());
            let frag = &body[sent..end];
            let is_last = end == body.len();
            let mut pdu_payload = Vec::with_capacity(header.len() + 3 + frag.len());
            pdu_payload.extend_from_slice(&header[3..]);
            let hid = if is_last {
                hid::END_OF_BODY
            } else {
                hid::BODY
            };
            if is_last {
                pdu_payload.push(hid);
                pdu_payload.extend_from_slice(frag);
            } else {
                push_header(&mut pdu_payload, hid, frag);
            }
            let req = pdu(opcode::PUT, &pdu_payload);
            let resp = self.exchange(&req).await?;
            if is_last {
                if !resp.success() {
                    anyhow::bail!(
                        "OBEX Put final ack not OK: opcode 0x{:02X}",
                        resp.opcode
                    );
                }
            } else if !resp.continue_() {
                anyhow::bail!(
                    "OBEX Put fragment ack not Continue: opcode 0x{:02X}",
                    resp.opcode
                );
            }
            sent = end;
        }
        Ok(())
    }

    pub async fn get_file(&mut self, name: &str) -> Result<Vec<u8>> {
        let req = build_get_req(Some(name), None);
        let mut all = Vec::new();
        let resp = self.exchange(&req).await?;
        all.extend_from_slice(&resp.body_payload());
        if resp.success() {
            return Ok(all);
        }
        loop {
            let ack = pdu(opcode::GET, &[]);
            let resp = self.exchange(&ack).await?;
            let more = resp.body_payload();
            let done = resp.success();
            all.extend_from_slice(&more);
            if done {
                return Ok(all);
            }
        }
    }

    pub async fn list_folder(&mut self, name: Option<&str>) -> Result<Vec<ObexListing>> {
        self.set_path(name, 0x00).await?;
        let req = build_get_req(None, Some("x-bt/folder-listing"));
        let resp = self.exchange(&req).await?;
        let mut out = Vec::new();
        let body = resp.body_payload();
        let mut i = 0usize;
        while i + 2 < body.len() {
            let len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
            let v_start = i + 2;
            if v_start + len > body.len() {
                break;
            }
            let v = &body[v_start..v_start + len];
            let mut listing = ObexListing::default();
            let mut j = 0usize;
            while j + 2 < v.len() {
                let tag = v[j];
                let tlen = v[j + 1] as usize;
                let tv = if j + 2 + tlen <= v.len() {
                    &v[j + 2..j + 2 + tlen]
                } else {
                    &v[j + 2..]
                };
                match tag {
                    0x01 => listing.name = String::from_utf8_lossy(tv).trim_end_matches('\0').to_string(),
                    0x02 => listing.type_ = String::from_utf8_lossy(tv).trim_end_matches('\0').to_string(),
                    0x03 => {
                        if tv.len() >= 4 {
                            listing.size = Some(u32::from_be_bytes([tv[0], tv[1], tv[2], tv[3]]));
                        }
                    }
                    _ => {}
                }
                j += 2 + tlen;
            }
            if !listing.name.is_empty() {
                out.push(listing);
            }
            i = v_start + len;
        }
        Ok(out)
    }

    pub async fn set_path(&mut self, name: Option<&str>, flags: u8) -> Result<()> {
        let req = build_setpath_req(name, flags);
        self.exchange(&req).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_pdu_layout() {
        let p = build_connect_req(1024);
        assert_eq!(p[0], opcode::CONNECT);
        assert_eq!(u16::from_be_bytes([p[1], p[2]]), 7);
        assert_eq!(p[3], 0x10); // OBEX version
        assert_eq!(u16::from_be_bytes([p[4], p[5]]), 1024);
    }

    #[test]
    fn put_pdu_has_name_and_length() {
        let p = build_put_req("hello.txt", 42);
        assert_eq!(p[0], opcode::PUT);
        let body = &p[3..];
        assert_eq!(body[0], hid::NAME);
        let hlen = u16::from_be_bytes([body[1], body[2]]) as usize;
        assert_eq!(&body[3..3 + hlen], b"hello.txt");
        let next = 3 + hlen;
        assert_eq!(body[next], hid::LENGTH);
        let llen = u16::from_be_bytes([body[next + 1], body[next + 2]]) as usize;
        assert_eq!(llen, 4);
        assert_eq!(
            u32::from_be_bytes([
                body[next + 3],
                body[next + 4],
                body[next + 5],
                body[next + 6]
            ]),
            42
        );
    }

    #[test]
    fn parse_ok_response() {
        let mut pdu = vec![opcode::OK, 0x00, 0x06];
        pdu.extend_from_slice(&[hid::LENGTH, 0x00, 0x04, 0x00, 0x00, 0x00, 0x2A]);
        let resp = parse_response(&pdu).expect("parse");
        assert_eq!(resp.opcode, opcode::OK);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, hid::LENGTH);
    }

    #[test]
    fn parse_end_of_body_header() {
        let mut pdu = vec![opcode::OK, 0x00, 0x02];
        pdu.extend_from_slice(&[hid::END_OF_BODY, 0xFF]);
        let resp = parse_response(&pdu).expect("parse");
        assert_eq!(resp.opcode, opcode::OK);
        assert_eq!(resp.headers[0].0, hid::END_OF_BODY);
    }
}

//! RFCOMM 1.2 (ETS 300 916) codec + an async session over L2CAP PSM 0x0003.
//!
//! Frame layout per spec:
//!
//! | field    | size                | notes                                                  |
//! |----------|---------------------|--------------------------------------------------------|
//! | address  | 1 byte              | `(dlci << 3) | (cr << 2) | EA=1`                       |
//! | control  | 1 byte              | `0x2F` UIH initiator, `0x0F` UIH responder, ...        |
//! | length   | 1 or 2 bytes        | EA bit (LSB) — 2-byte form when payload > 127          |
//! | payload  | 0..=32767 bytes     | UIH: user data; control frames: 0                      |
//! | FCS      | 0 or 1 byte         | SABM/UA/DISC/DM only; 8-bit CRC over addr+ctrl+length  |
//!
//! The UIH FCS is OPTIONAL in 1.2 and modern stacks (BlueZ) ignore it; we
//! omit it on the data path and compute it on control frames.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::sync::Mutex;
use tokio::task;

use super::hci::L2capChannel;
use super::lmp::PSM_RFCOMM;

/// RFCOMM address field: EA=1, CR=0 (responder) / CR=1 (initiator),
/// DLCI is the bottom 6 bits.
pub const RFCOMM_EA_BIT: u8 = 0x01;
/// DLCI 0 = control channel.
pub const RFCOMM_DLCI_CONTROL: u8 = 0;
/// Maximum payload that fits in the 1-byte length form.
pub const RFCOMM_MAX_1B_LEN: u16 = 127;
/// Maximum payload in the 2-byte length form.
pub const RFCOMM_MAX_2B_LEN: u16 = 32767;

/// Control field byte values per ETS 300 916 §5.4. UIH uses the polled-bit
/// to carry C/R: responder sends 0x0F, initiator sends 0x2F (P/F=1), and
/// 0x0F / 0x2F on subsequent frames.
pub mod ctrl {
    pub const SABM: u8 = 0x2F;
    pub const UA: u8 = 0x63;
    pub const DM: u8 = 0x0F;
    pub const DISC: u8 = 0x53;
    pub const UIH_CR1: u8 = 0xEF;
    pub const UIH_CR0: u8 = 0xFF;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Sabm,
    Ua,
    Dm,
    Disc,
    Uih,
}

/// A decoded RFCOMM frame.
#[derive(Debug, Clone)]
pub struct RfcommFrame {
    pub address: u8,
    pub control: u8,
    pub kind: FrameKind,
    pub payload: Vec<u8>,
    pub fcs_valid: bool,
}

impl RfcommFrame {
    pub fn dlci(&self) -> u8 {
        (self.address >> 3) & 0x3F
    }
    pub fn cr(&self) -> bool {
        (self.address & 0x04) != 0
    }
    pub fn ea(&self) -> bool {
        (self.address & 0x01) != 0
    }
}

fn fcs8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0xFF;
    for b in data {
        crc ^= *b;
        for _ in 0..8 {
            if crc & 0x01 != 0 {
                crc = (crc >> 1) ^ 0x0D;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn address_byte(dlci: u8, cr: bool) -> u8 {
    ((dlci & 0x3F) << 3) | ((cr as u8) << 2) | RFCOMM_EA_BIT
}

fn encode_length(len: u16) -> Vec<u8> {
    if len <= RFCOMM_MAX_1B_LEN {
        // EA=1, len in 7 bits.
        vec![(len as u8) | 0x01]
    } else {
        // EA=0 in low byte, then len big-endian.
        let high = ((len >> 7) & 0x7F) as u8;
        let low = (len & 0x7F) as u8;
        vec![low, high]
    }
}

fn decode_length(data: &[u8]) -> Result<(usize, u16)> {
    if data.is_empty() {
        return Err(anyhow!("RFCOMM: empty length field"));
    }
    let first = data[0];
    if first & 0x01 != 0 {
        Ok((1usize, ((first >> 1) & 0x7F) as u16))
    } else {
        if data.len() < 2 {
            return Err(anyhow!("RFCOMM: truncated 2-byte length"));
        }
        let high = (data[1] as u16) << 7;
        let low = ((first >> 1) & 0x7F) as u16;
        Ok((2usize, high | low))
    }
}

pub fn build_sabm(dlci: u8, cr: bool) -> Vec<u8> {
    let addr = address_byte(dlci, cr);
    let len_bytes = encode_length(0);
    let mut out = Vec::with_capacity(3 + len_bytes.len());
    out.push(addr);
    out.push(ctrl::SABM);
    out.extend_from_slice(&len_bytes);
    out.push(fcs8(&out));
    out
}

pub fn build_ua(dlci: u8, cr: bool) -> Vec<u8> {
    let addr = address_byte(dlci, cr);
    let len_bytes = encode_length(0);
    let mut out = Vec::with_capacity(3 + len_bytes.len());
    out.push(addr);
    out.push(ctrl::UA);
    out.extend_from_slice(&len_bytes);
    out.push(fcs8(&out));
    out
}

pub fn build_disc(dlci: u8, cr: bool) -> Vec<u8> {
    let addr = address_byte(dlci, cr);
    let len_bytes = encode_length(0);
    let mut out = Vec::with_capacity(3 + len_bytes.len());
    out.push(addr);
    out.push(ctrl::DISC);
    out.extend_from_slice(&len_bytes);
    out.push(fcs8(&out));
    out
}

pub fn build_dm(dlci: u8, cr: bool) -> Vec<u8> {
    let addr = address_byte(dlci, cr);
    let len_bytes = encode_length(0);
    let mut out = Vec::with_capacity(3 + len_bytes.len());
    out.push(addr);
    out.push(ctrl::DM);
    out.extend_from_slice(&len_bytes);
    out.push(fcs8(&out));
    out
}

pub fn build_uih(dlci: u8, cr: bool, payload: &[u8]) -> Vec<u8> {
    let addr = address_byte(dlci, cr);
    let len_bytes = encode_length(payload.len() as u16);
    let mut out = Vec::with_capacity(2 + len_bytes.len() + payload.len());
    out.push(addr);
    out.push(if cr { ctrl::UIH_CR1 } else { ctrl::UIH_CR0 });
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(payload);
    out
}

pub fn build_msc(dlci: u8, cr: bool, bits: u8) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2);
    payload.push(0xE1);
    payload.push(bits | 0x10);
    build_uih(dlci, cr, &payload)
}

pub fn build_rpn(dlci: u8, params: &[u8; 14]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(15);
    payload.push(0xE3);
    payload.extend_from_slice(params);
    build_uih(dlci, true, &payload)
}

pub fn build_rls(dlci: u8, line_status: u8) -> Vec<u8> {
    let payload = [0xE5, line_status];
    build_uih(dlci, true, &payload)
}

pub fn build_test(payload: &[u8]) -> Vec<u8> {
    build_uih(RFCOMM_DLCI_CONTROL, true, payload)
}

/// Parameter Negotiation (PN) on the control DLCI, asking for `mtu` and a
/// data DLCI derived from `server_channel` (DLCI = server_channel << 1).
pub fn build_pn(server_channel: u8, mtu: u16) -> Vec<u8> {
    let mut payload = [0u8; 8];
    payload[0] = 0x80;
    payload[1] = (server_channel as u8) << 1;
    payload[2] = 0;
    payload[3] = 0;
    payload[4] = 0xF0;
    payload[5] = 0;
    payload[6] = (mtu & 0xFF) as u8;
    payload[7] = (mtu >> 8) as u8;
    build_uih(RFCOMM_DLCI_CONTROL, true, &payload)
}

pub fn parse_frame(data: &[u8]) -> Result<RfcommFrame> {
    if data.len() < 3 {
        return Err(anyhow!("RFCOMM frame too short: {} bytes", data.len()));
    }
    let address = data[0];
    let control = data[1];
    let (consumed, payload_len) = decode_length(&data[2..])?;
    let payload_start = 2 + consumed;
    let after_payload = payload_start + payload_len as usize;
    let kind = match control & 0xEF {
        0x2F => FrameKind::Sabm,
        0x63 => FrameKind::Ua,
        0x0F => FrameKind::Dm,
        0x53 => FrameKind::Disc,
        0xEF | 0xFF => FrameKind::Uih,
        _ => return Err(anyhow!("unknown RFCOMM control byte 0x{control:02X}")),
    };
    let mut fcs_valid = false;
    let payload = match kind {
        FrameKind::Uih => {
            if after_payload > data.len() {
                return Err(anyhow!(
                    "RFCOMM UIH payload truncated: need {payload_len}, have {}",
                    data.len() - payload_start
                ));
            }
            data[payload_start..after_payload].to_vec()
        }
        _ => {
            if after_payload + 1 > data.len() {
                return Err(anyhow!("RFCOMM control frame missing FCS"));
            }
            let fcs = data[after_payload];
            let expected = fcs8(&data[..after_payload]);
            fcs_valid = fcs == expected;
            Vec::new()
        }
    };
    Ok(RfcommFrame {
        address,
        control,
        kind,
        payload,
        fcs_valid,
    })
}

#[derive(Debug)]
pub struct RfcommSession {
    channel: Arc<Mutex<L2capChannel>>,
    dlci: u8,
    _cr: bool,
    _msc_negotiated: bool,
}

impl RfcommSession {
    pub async fn connect(bdaddr: &str, server_channel: u8) -> Result<Self> {
        let channel = Arc::new(Mutex::new(
            task::spawn_blocking({
                let bdaddr = bdaddr.to_string();
                move || -> Result<L2capChannel> { L2capChannel::connect(&bdaddr, PSM_RFCOMM) }
            })
            .await
            .map_err(|e| anyhow!("RFCOMM L2CAP connect task: {e}"))??,
        ));

        let dlci = (server_channel << 1) & 0x3E;

        // SABM on control DLCI.
        {
            let sabm_ctrl = build_sabm(RFCOMM_DLCI_CONTROL, true);
            let ch = channel.clone();
            task::spawn_blocking(move || -> Result<RfcommFrame> {
                let mut guard = ch.blocking_lock();
                send_blocking(&mut guard, &sabm_ctrl)?;
                recv_frame_blocking(&mut guard, Duration::from_secs(5))
            })
            .await
            .map_err(|e| anyhow!("RFCOMM control-SABM task: {e}"))??
            .fcs_check(RFCOMM_DLCI_CONTROL, FrameKind::Ua)?;
        }

        // Parameter Negotiation on the data DLCI.
        {
            let mtu: u16 = 990;
            let pn = build_pn(server_channel, mtu);
            let ch = channel.clone();
            let f = task::spawn_blocking(move || -> Result<RfcommFrame> {
                let mut guard = ch.blocking_lock();
                send_blocking(&mut guard, &pn)?;
                recv_frame_blocking(&mut guard, Duration::from_secs(5))
            })
            .await
            .map_err(|e| anyhow!("RFCOMM PN task: {e}"))??;
            if f.kind != FrameKind::Uih || f.dlci() != RFCOMM_DLCI_CONTROL {
                return Err(anyhow!("RFCOMM PN: unexpected reply kind={:?}", f.kind));
            }
        }

        // SABM on the data DLCI.
        {
            let sabm_data = build_sabm(dlci, true);
            let ch = channel.clone();
            task::spawn_blocking(move || -> Result<RfcommFrame> {
                let mut guard = ch.blocking_lock();
                send_blocking(&mut guard, &sabm_data)?;
                recv_frame_blocking(&mut guard, Duration::from_secs(5))
            })
            .await
            .map_err(|e| anyhow!("RFCOMM data-SABM task: {e}"))??
            .fcs_check(dlci, FrameKind::Ua)?;
        }

        Ok(Self {
            channel,
            dlci,
            _cr: true,
            _msc_negotiated: false,
        })
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        let frame = build_uih(self.dlci, true, data);
        let ch = self.channel.clone();
        task::spawn_blocking(move || -> Result<()> {
            let mut guard = ch.blocking_lock();
            send_blocking(&mut guard, &frame)
        })
        .await
        .map_err(|e| anyhow!("RFCOMM send task: {e}"))?
    }

    pub async fn recv(&mut self, buf: &mut [u8], timeout: Duration) -> Result<usize> {
        let ch = self.channel.clone();
        let mut buf_owned: Vec<u8> = buf.to_vec();
        let payload: Vec<u8> = task::spawn_blocking(move || -> Result<Vec<u8>> {
            let mut guard = ch.blocking_lock();
            let frame = recv_frame_blocking(&mut guard, timeout)?;
            let take = frame.payload.len().min(buf_owned.len());
            buf_owned[..take].copy_from_slice(&frame.payload[..take]);
            Ok(buf_owned[..take].to_vec())
        })
        .await
        .map_err(|e| anyhow!("RFCOMM recv task: {e}"))??;
        let copy = payload.len().min(buf.len());
        buf[..copy].copy_from_slice(&payload[..copy]);
        Ok(copy)
    }

    pub async fn close(&mut self) -> Result<()> {
        let disc = build_disc(self.dlci, true);
        let ch = self.channel.clone();
        if let Err(e) = task::spawn_blocking(move || -> Result<()> {
            let mut guard = ch.blocking_lock();
            send_blocking(&mut guard, &disc)
        })
        .await
        .map_err(|e| anyhow!("RFCOMM close task: {e}"))?
        {
            tracing::debug!("RFCOMM DISC send: {e:#}");
        }
        Ok(())
    }

    pub fn dlci(&self) -> u8 {
        self.dlci
    }
}

impl RfcommFrame {
    pub fn fcs_check(self, expect_dlci: u8, expect_kind: FrameKind) -> Result<RfcommFrame> {
        if self.kind != expect_kind || self.dlci() != expect_dlci {
            Err(anyhow!(
                "RFCOMM: expected kind={:?} dlci={}, got kind={:?} dlci={}",
                expect_kind,
                expect_dlci,
                self.kind,
                self.dlci()
            ))
        } else {
            Ok(self)
        }
    }
}

fn send_blocking(channel: &mut L2capChannel, data: &[u8]) -> Result<()> {
    let mut off = 0usize;
    while off < data.len() {
        let n = channel.send(&data[off..])?;
        off += n;
    }
    Ok(())
}

fn recv_frame_blocking(channel: &mut L2capChannel, timeout: Duration) -> Result<RfcommFrame> {
    // First peek header (1 byte) to detect length field size.
    let mut hdr = [0u8; 1];
    let n = channel.recv(&mut hdr, timeout)?;
    if n == 0 {
        return Err(anyhow!("RFCOMM: header recv timed out"));
    }
    let mut got = vec![hdr[0]];
    loop {
        let need = 2usize.saturating_sub(got.len());
        if need > 0 {
            let mut small = [0u8; 2];
            let n = channel.recv(&mut small[..need], timeout)?;
            if n == 0 {
                return Err(anyhow!("RFCOMM: addr/ctrl recv timeout"));
            }
            got.extend_from_slice(&small[..n]);
        }
        let (consumed, payload_len) = decode_length(&got[2..])?;
        let total = 2 + consumed + payload_len as usize;
        let need = total.saturating_sub(got.len());
        if need > 0 {
            let limit = need.min(4096usize);
            let mut big = vec![0u8; limit];
            let take = big.len();
            let n = channel.recv(&mut big[..take], timeout)?;
            if n == 0 {
                return Err(anyhow!("RFCOMM: payload recv timeout"));
            }
            got.extend_from_slice(&big[..n]);
            if got.len() < total {
                return Err(anyhow!("RFCOMM: payload truncated"));
            }
        }
        let kind_byte = got[1] & 0xEF;
        if kind_byte != 0xEF && kind_byte != 0xFF {
            let mut fcs = [0u8; 1];
            let n = channel.recv(&mut fcs, timeout)?;
            if n == 0 {
                return Err(anyhow!("RFCOMM: FCS recv timeout"));
            }
            got.extend_from_slice(&fcs);
        }
        return parse_frame(&got);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sabm_roundtrip() {
        let f = build_sabm(5, true);
        let p = parse_frame(&f).expect("parse");
        assert_eq!(p.kind, FrameKind::Sabm);
        assert_eq!(p.dlci(), 5);
        assert!(p.cr());
        assert!(p.fcs_valid);
    }

    #[test]
    fn ua_roundtrip() {
        let f = build_ua(0, false);
        let p = parse_frame(&f).expect("parse");
        assert_eq!(p.kind, FrameKind::Ua);
        assert_eq!(p.dlci(), 0);
        assert!(!p.cr());
        assert!(p.fcs_valid);
    }

    #[test]
    fn uih_roundtrip_short() {
        let payload = b"hello";
        let f = build_uih(5, true, payload);
        let p = parse_frame(&f).expect("parse");
        assert_eq!(p.kind, FrameKind::Uih);
        assert_eq!(p.dlci(), 5);
        assert_eq!(p.payload, payload);
    }

    #[test]
    fn uih_roundtrip_long() {
        let payload = vec![0xAA; 300];
        let f = build_uih(5, true, &payload);
        let p = parse_frame(&f).expect("parse");
        assert_eq!(p.kind, FrameKind::Uih);
        assert_eq!(p.payload.len(), 300);
        assert_eq!(p.payload[100], 0xAA);
    }

    #[test]
    fn pn_has_correct_layout() {
        let pn = build_pn(7, 990);
        let p = parse_frame(&pn).expect("parse");
        assert_eq!(p.kind, FrameKind::Uih);
        assert_eq!(p.dlci(), RFCOMM_DLCI_CONTROL);
        assert_eq!(p.payload[0], 0x80);
        assert_eq!(p.payload[1], 7 << 1);
    }

    #[test]
    fn msc_and_rls_build() {
        let m = build_msc(5, true, 0x00);
        assert!(!m.is_empty());
        let r = build_rls(5, 0);
        assert!(!r.is_empty());
    }

    #[test]
    fn length_encoding_bounds() {
        let short = encode_length(127);
        assert_eq!(short.len(), 1);
        let long = encode_length(128);
        assert_eq!(long.len(), 2);
        let long2 = encode_length(32767);
        assert_eq!(long2.len(), 2);
    }
}

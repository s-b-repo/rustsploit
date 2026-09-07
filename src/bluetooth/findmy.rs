//! Apple Find My offline-finder advertisement builder (pure, no I/O).
//!
//! Apple Company ID = 0x004C. Subtypes 0x10 and 0x12 carry the offline-
//! finder payload with a 22-byte body that includes a 28-bit public-key
//! prefix + status hints. Real Find My advertisements rotate the public
//! key every 15 minutes — these builders let exploit modules forge one
//! without owning the rotation schedule (useful for clone/spoof probes).

use anyhow::{Result, anyhow};
use rand::RngExt;

pub const APPLE_COMPANY_ID: u16 = 0x004C;
pub const FINDMY_SUBTYPE_NEAR_OWNER: u8 = 0x10;
pub const FINDMY_SUBTYPE_SEPARATED: u8 = 0x12;

pub mod status {
    pub const BATTERY_HIGH_NIBBLE_FOLLOWS: u8 = 0x01;
    pub const SOUND_PLAYING: u8 = 0x20;
    pub const MOVING: u8 = 0x40;
    pub const PRIMARY_TRACKER: u8 = 0x80;
}

#[derive(Debug, Clone)]
pub struct FindMyStatus {
    pub battery_level: u8,
    pub sound_playing: bool,
    pub moving: bool,
    pub primary_tracker: bool,
    pub battery_high_nibble: bool,
}

impl FindMyStatus {
    pub fn byte(&self) -> u8 {
        let mut b = (self.battery_level & 0x0F) << 1;
        if self.battery_high_nibble {
            b |= status::BATTERY_HIGH_NIBBLE_FOLLOWS;
        }
        if self.sound_playing {
            b |= status::SOUND_PLAYING;
        }
        if self.moving {
            b |= status::MOVING;
        }
        if self.primary_tracker {
            b |= status::PRIMARY_TRACKER;
        }
        b
    }
}

/// 25-byte manufacturer-specific payload (subtype + status + 22-byte body).
pub fn build_findmy_advertisement(subtype: u8, status_byte: u8, payload_prefix: &[u8; 22]) -> [u8; 25] {
    let mut out = [0u8; 25];
    out[0] = subtype;
    out[1] = status_byte;
    out[2..25].copy_from_slice(payload_prefix);
    out
}

/// Wrap the 25-byte payload into a full BLE advertisement data block:
/// Flags(0x06) + Manufacturer Data(0xFF, length 27 = 25 payload + 2 cid).
pub fn build_findmy_adv_data(subtype: u8, status_byte: u8, payload_prefix: &[u8; 22]) -> Vec<u8> {
    let mut out = Vec::with_capacity(31);
    out.extend_from_slice(&[0x02, 0x01, 0x06]);
    out.push(0x03);
    out.push(0xFF);
    out.push(APPLE_COMPANY_ID as u8);
    out.push((APPLE_COMPANY_ID >> 8) as u8);
    let mfr = build_findmy_advertisement(subtype, status_byte, payload_prefix);
    out.extend_from_slice(&mfr);
    if out.len() > 31 {
        return out[..31].to_vec();
    }
    out
}

pub fn build_airtag_clone_advertisement() -> [u8; 25] {
    let mut prefix = [0u8; 22];
    rand::rng().fill(&mut prefix[..]);
    let status = FindMyStatus {
        battery_level: 7,
        sound_playing: false,
        moving: false,
        primary_tracker: true,
        battery_high_nibble: false,
    };
    build_findmy_advertisement(FINDMY_SUBTYPE_NEAR_OWNER, status.byte(), &prefix)
}

pub fn parse_findmy_advertisement(payload: &[u8]) -> Result<(u8, u8, [u8; 22])> {
    if payload.len() < 24 {
        return Err(anyhow!("Find My payload too short: {} bytes", payload.len()));
    }
    let subtype = payload[0];
    let status_byte = payload[1];
    let mut body = [0u8; 22];
    body.copy_from_slice(&payload[2..24]);
    Ok((subtype, status_byte, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_byte_layout() {
        let s = FindMyStatus {
            battery_level: 5,
            sound_playing: true,
            moving: false,
            primary_tracker: true,
            battery_high_nibble: false,
        };
        let b = s.byte();
        assert_eq!(b & 0x0E, 5 << 1);
        assert_ne!(b & status::SOUND_PLAYING, 0);
        assert_ne!(b & status::PRIMARY_TRACKER, 0);
        assert_eq!(b & status::MOVING, 0);
    }

    #[test]
    fn adv_data_layout() {
        let prefix = [0xAB; 22];
        let adv = build_findmy_adv_data(FINDMY_SUBTYPE_NEAR_OWNER, 0x80, &prefix);
        assert_eq!(adv[0], 0x02);
        assert_eq!(adv[1], 0x01);
        assert_eq!(adv[2], 0x06);
        let mfr_len = adv[3] as usize;
        assert!(mfr_len >= 25);
        assert_eq!(adv[4], 0xFF);
        let cid = u16::from_le_bytes([adv[5], adv[6]]);
        assert_eq!(cid, APPLE_COMPANY_ID);
        assert_eq!(adv[7], FINDMY_SUBTYPE_NEAR_OWNER);
        assert_eq!(adv[8], 0x80);
    }

    #[test]
    fn roundtrip_parse() {
        let prefix = [0x33u8; 22];
        let mfr = build_findmy_advertisement(FINDMY_SUBTYPE_SEPARATED, 0x42, &prefix);
        let (sub, st, body) = parse_findmy_advertisement(&mfr).expect("parse");
        assert_eq!(sub, FINDMY_SUBTYPE_SEPARATED);
        assert_eq!(st, 0x42);
        assert_eq!(body, prefix);
    }

    #[test]
    fn airtag_clone_advertisement_is_wellformed() {
        let m = build_airtag_clone_advertisement();
        let (sub, st, body) = parse_findmy_advertisement(&m).expect("parse");
        assert!(sub == FINDMY_SUBTYPE_NEAR_OWNER || sub == FINDMY_SUBTYPE_SEPARATED);
        assert!(st != 0);
        assert_eq!(body.len(), 22);
    }
}

//! Shared Bluetooth core for rustsploit.
//!
//! Every Bluetooth module (BLE and Classic) is built on this layer:
//!
//! - [`adapter`] — local radio enumeration / selection / power.
//! - [`discovery`] — unified BLE advert capture + classification (Fast Pair,
//!   Find My, iBeacon/Eddystone, Mesh Proxy, HID-over-GATT) and Classic
//!   inquiry through BlueZ.
//! - [`gatt_client`] — btleplug GATT plumbing (connect/retry/read/write/notify).
//! - [`fastpair`] — Google Fast Pair protocol + crypto + model database.
//! - [`classic`] — BR/EDR device discovery, pairing and transport via BlueZ D-Bus.
//! - [`hci`] — raw HCI sockets: inquiry, connection setup, encryption-key-size,
//!   plus the `L2capChannel` used by every higher codec below.
//! - [`sdp`] — minimal SDP ServiceSearchAttribute client over L2CAP PSM 1.
//! - [`lmp`] — LMP/L2CAP packet codecs (pure, offline-testable).
//! - [`ll`] — BLE link-layer packet codecs (pure, offline-testable).
//! - [`inventory`] — persistent device store under `~/.rustsploit/`.
//! - [`matrix`] — device-class → attack-path matrix used by `blueforge`.
//!
//! Protocol-stack codecs used by exploit modules:
//!
//! - [`rfcomm`] — RFCOMM 1.2 (ETS 300 916) UIH frame codec + async session.
//! - [`obex`] — OBEX 1.5 client over RFCOMM.
//! - [`bnep`] — BNEP 1.0 codec (used by BlueBorne-class exploits).
//! - [`avdtp`] — AVDTP 1.3 signaling + SBC codec catalog.
//! - [`hfp`] — Hands-Free Profile AT-command client over RFCOMM.
//! - [`smp`] — BLE Security Manager PDU codec + LE SC confirmation helpers
//!   (`smp_c2`, `f6`, `g2`, `h6`, `h7`).
//! - [`findmy`] — Apple Find My offline-finder advertisement builder.
//! - [`airoha`] — Airoha / MediaTek vendor HCI command helpers
//!   (CVE-2024-47875 / CVE-2024-21743 surface).
//!
//! Everything here is feature-gated behind `bluetooth` (btleplug). Classic and
//! HCI paths additionally require Linux (AF_BLUETOOTH) and root/CAP_NET_RAW.

#[cfg(feature = "bluetooth")]
pub mod adapter;
#[cfg(feature = "bluetooth")]
pub mod airoha;
#[cfg(feature = "bluetooth")]
pub mod avdtp;
#[cfg(feature = "bluetooth")]
pub mod bnep;
#[cfg(feature = "bluetooth")]
pub mod btsnoop;
#[cfg(feature = "bluetooth")]
pub mod classic;
#[cfg(feature = "bluetooth")]
pub mod crypto_extra;
#[cfg(feature = "bluetooth")]
pub mod discovery;
#[cfg(feature = "bluetooth")]
pub mod fastpair;
#[cfg(feature = "bluetooth")]
pub mod findmy;
#[cfg(feature = "bluetooth")]
pub mod gatt_client;
#[cfg(all(feature = "bluetooth", target_os = "linux"))]
pub mod hci;
#[cfg(feature = "bluetooth")]
pub mod hfp;
#[cfg(feature = "bluetooth")]
pub mod inventory;
#[cfg(feature = "bluetooth")]
pub mod ll;
#[cfg(feature = "bluetooth")]
pub mod lmp;
#[cfg(feature = "bluetooth")]
pub mod matrix;
#[cfg(feature = "bluetooth")]
pub mod obex;
#[cfg(feature = "bluetooth")]
pub mod rfcomm;
#[cfg(all(feature = "bluetooth", target_os = "linux"))]
pub mod sdp;
#[cfg(feature = "bluetooth")]
pub mod smp;

#[cfg(feature = "bluetooth")]
use anyhow::Result;

/// A Bluetooth device observed during discovery (either transport).
#[cfg(feature = "bluetooth")]
#[derive(Debug, Clone, Default)]
pub struct BtDevice {
    /// `AA:BB:CC:DD:EE:FF`.
    pub mac: String,
    pub name: String,
    /// Last seen RSSI, dBm.
    pub rssi: Option<i16>,
    /// BR/EDR + BLE: device came from a Classic inquiry.
    pub classic: bool,
    /// BLE: came from an advert scan.
    pub le: bool,
    /// 24-bit Class of Device (Classic) if known.
    pub class_of_device: Option<u32>,
    /// Fast Pair model ID if the advert carried one.
    pub fastpair_model_id: Option<u32>,
    /// Advertising state relative to Fast Pair pairing mode.
    pub fastpair_pairing_mode: bool,
    pub fastpair_steady_state: bool,
    /// Advertised 128-bit service UUIDs (BLE) or SDP UUIDs (Classic).
    pub uuids: Vec<String>,
    /// Manufacturer-specific data, keyed by company ID.
    pub manufacturer_data: Vec<(u16, Vec<u8>)>,
}

#[cfg(feature = "bluetooth")]
impl BtDevice {
    /// Human-readable transport string.
    pub fn transport(&self) -> &'static str {
        match (self.classic, self.le) {
            (true, true) => "BR/EDR+BLE",
            (true, false) => "BR/EDR",
            (false, true) => "BLE",
            (false, false) => "?",
        }
    }

    /// Coarse device class from the 24-bit Class of Device
    /// (major service class bits, Bluetooth Assigned Numbers).
    pub fn device_class(&self) -> Option<&'static str> {
        let cod = self.class_of_device?;
        let major = (cod >> 8) & 0x1F;
        Some(match major {
            0x01 => "computer",
            0x02 => "phone",
            0x03 => "lan/network-access",
            0x04 => "audio/video",
            0x05 => "peripheral (HID)",
            0x06 => "imaging",
            0x07 => "wearable",
            0x08 => "toy",
            0x09 => "health",
            0x1F => "uncategorized",
            _ => "unknown",
        })
    }

    /// Classification hints used by the attack matrix.
    pub fn classes(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.fastpair_model_id.is_some() {
            out.push("fastpair");
        }
        if self.uuids.iter().any(|u| {
            let lower = u.to_ascii_lowercase();
            lower.starts_with("00001812") || lower.starts_with("1812")
        }) {
            out.push("hid");
        }
        if self.uuids.iter().any(|u| {
            let lower = u.to_ascii_lowercase();
            lower.starts_with("00001800") || lower.starts_with("1800")
        }) {
            out.push("gatt-server");
        }
        if self.uuids.iter().any(|u| {
            let lower = u.to_ascii_lowercase();
            lower.starts_with("00001827") || lower.starts_with("1827")
        }) {
            out.push("mesh");
        }
        if self.uuids.iter().any(|u| {
            let lower = u.to_ascii_lowercase();
            lower.starts_with("apple-findmy")
        }) {
            out.push("findmy-target");
        }
        if let Some(c) = self.device_class() {
            match c {
                "audio/video" => {
                    out.push("a2dp");
                    out.push("a2dp-sink");
                }
                "peripheral (HID)" => out.push("hid"),
                "phone" | "computer" => out.push("classic-computing"),
                _ => {}
            }
        }
        if self.classic {
            out.push("classic");
            // Mark OBEX-reachable when OBEX push / file-transfer / phonebook
            // access SDP UUIDs are visible. The actual probe lives in
            // `bluebug_obex` / `bluesnarf_obex`.
            if self.uuids.iter().any(|u| {
                let l = u.to_ascii_lowercase();
                l.starts_with("1105") || l.starts_with("1106") || l.starts_with("1130")
            }) {
                out.push("obex-paired");
            }
            // Hands-Free / Headset profile UUIDs.
            if self.uuids.iter().any(|u| {
                let l = u.to_ascii_lowercase();
                l.starts_with("111e") || l.starts_with("1108") || l.starts_with("1203")
            }) {
                out.push("handsfree");
            }
        }
        if self.le {
            out.push("le");
            if self.fastpair_pairing_mode || self.fastpair_steady_state {
                out.push("le-pairing-mode-observed");
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// Parse `AA:BB:CC:DD:EE:FF` (also `-` separated) into 6 bytes.
#[cfg(feature = "bluetooth")]
pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 {
        anyhow::bail!("malformed MAC address: {s}");
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16)
            .map_err(|e| anyhow::anyhow!("bad MAC octet '{p}' in {s}: {e}"))?;
    }
    Ok(out)
}

/// Format 6 bytes as `AA:BB:CC:DD:EE:FF`.
#[cfg(feature = "bluetooth")]
pub fn mac_to_string(bytes: &[u8; 6]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}:"))
        .collect::<String>()
        .trim_end_matches(':')
        .to_string()
}

/// Loosely validate a Bluetooth MAC (`AA:BB:CC:DD:EE:FF`, also `-` separated).
#[cfg(feature = "bluetooth")]
pub fn is_mac_addr(s: &str) -> bool {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[cfg(feature = "bluetooth")]
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Unified target-MAC resolution for radio modules: a MAC-shaped `ctx.target`
/// beats the `target_mac` global. `None` = operate on whatever is in range.
#[cfg(feature = "bluetooth")]
pub(crate) fn resolve_target_mac(ctx: &crate::module::ModuleCtx) -> Option<String> {
    ctx.target
        .as_single()
        .map(str::trim)
        .filter(|s| is_mac_addr(s))
        .map(str::to_string)
        .or_else(|| {
            crate::tenant::resolve()
                .global_options()
                .try_get("target_mac")
                .map(|s| s.trim().to_string())
                .filter(|s| is_mac_addr(s))
        })
}

/// Common banner helper for Bluetooth interactive modules.
#[cfg(feature = "bluetooth")]
pub(crate) fn banner(title: &str, subtitle: &str) {
    if crate::utils::is_batch_mode() {
        return;
    }
    crate::mprintln!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗"
    );
    crate::mprintln!("║   {title}");
    crate::mprintln!("║   {subtitle}");
    crate::mprintln!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝"
    );
}

/// Refuse scheduler fan-out for radio modules — the local Bluetooth radio is
/// not a per-host resource. Prints guidance at most once per process.
#[cfg(feature = "bluetooth")]
pub(crate) fn warn_no_fanout_once(module: &str) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        crate::meprintln!(
            "[!] {module} drives the LOCAL Bluetooth radio and does not fan out per network host. \
             Mass-scan targets are ignored — run the module with no target for an interactive session."
        );
    }
}

#[cfg(all(test, feature = "bluetooth"))]
mod tests {
    use super::*;

    #[test]
    fn mac_roundtrip() {
        let m = "AA:BB:CC:DD:EE:FF";
        assert!(is_mac_addr(m));
        assert_eq!(mac_to_string(&parse_mac(m).expect("parse")), m);
        assert!(is_mac_addr("AA-BB-CC-DD-EE-FF"));
        assert!(!is_mac_addr("AA:BB:CC"));
        assert!(!is_mac_addr("AA:BB:CC:DD:EE:GG"));
    }
}

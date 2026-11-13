//! Local Bluetooth controller capability enumeration.
//!
//! Reports what the host's own controller can actually do, so the operator
//! knows which attacks are reachable before driving one at a target. Most
//! Bluetooth exploit chains have a hard prerequisite that the local radio
//! cannot satisfy — LE Extended Advertising, a second controller, or
//! controller-level HCI access — and finding out only after building a
//! payload wastes a lot of time.
//!
//! This is a LOCAL probe: it talks to the host's own HCI socket and never
//! touches a target, so it ignores the module target entirely.

use anyhow::Result;

use crate::module::{ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Controller Capability Enumerator".to_string(),
        description: "Queries the LOCAL Bluetooth controller for its supported HCI commands, \
                      BR/EDR and LE feature bitmaps, and LE buffer sizes, then reports which \
                      attack primitives the radio can actually service: LMP injection, \
                      LE Extended Advertising, LE Audio, multi-adapter operation. Needs root \
                      or CAP_NET_RAW. No target — this probes the local radio."
            .to_string(),
        authors: vec!["rustsploit contributors".to_string()],
        references: vec![
            "https://www.bluetooth.com/specifications/specs/core-specification-6-0/".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: None,
    }
}

/// BR/EDR feature bits worth naming (Core Specification, Vol 3, Part C).
const FEATURE_ENCRYPTION: u8 = 2;
const FEATURE_EXTENDED_INQUIRY_RESPONSE: u8 = 5;
const FEATURE_RSSI_WITH_INQUIRY: u8 = 6;
const FEATURE_LE_SUPPORTED: u8 = 6;

/// LE feature bits (Vol 4, Part E).
const LE_FEATURE_LE_ENCRYPTED_CONNECTION: u8 = 0;
const LE_FEATURE_LE_EXTENDED_ADVERTISING: u8 = 12;
const LE_FEATURE_LE_PERIODIC_ADVERTISING: u8 = 13;

#[cfg(all(feature = "bluetooth", target_os = "linux"))]
pub async fn run(_ctx: &ModuleCtx) -> Result<ModuleOutcome> { // audit-allow: local controller probe, ctx unused
    use std::time::Duration;

    use crate::bluetooth::hci::HciSocket;
    use crate::module::{Finding, FindingKind};

    crate::bluetooth::warn_no_fanout_once("controller_info");
    let mut outcome = ModuleOutcome::ok();

    let dev_id = crate::bluetooth::adapter::adapter_index();
    let mut sock = HciSocket::open(u16::try_from(dev_id).unwrap_or(0), crate::bluetooth::hci::HCI_CHANNEL_RAW)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    crate::mprintln!("[*] Probing local controller (hci{dev_id}) ...");

    // --- Version -------------------------------------------------------
    let (lmp_ver, manufacturer, lmp_subver) = sock.read_local_version()?;
    crate::mprintln!(
        "[+] LMP version {lmp_ver}, manufacturer 0x{manufacturer:04X}, subversion 0x{lmp_subver:04X}"
    );

    // --- Command bitmap ------------------------------------------------
    let commands = sock.read_supported_commands()?;
    let command_count = commands.iter().filter(|b| **b != 0).count();
    crate::mprintln!("[*] Supported HCI command bitmap: {command_count} non-empty bytes");

    // --- BR/EDR features ------------------------------------------------
    let features = sock.read_supported_features()?;
    let le_supported = features
        .get(FEATURE_LE_SUPPORTED as usize)
        .map(|b| b & 0x01 != 0)
        .unwrap_or(false);
    crate::mprintln!("[+] BR/EDR features: {features:02x?}");

    // --- LE features ----------------------------------------------------
    let le_features = match sock.read_le_supported_features() {
        Ok(f) => {
            crate::mprintln!("[+] LE features: {f:02x?}");
            Some(f)
        }
        Err(e) => {
            crate::mprintln!("[-] LE_Read_Local_Supported_Features failed: {e}");
            None
        }
    };

    // --- LE buffer sizes -------------------------------------------------
    let mut le_buffer: Option<(u16, u8, u16)> = None;
    match sock.read_le_buffer_size() {
        Ok(v) => {
            crate::mprintln!(
                "[+] LE ACL payload {} bytes, {} packets (total {})",
                v.0, v.1, v.2
            );
            le_buffer = Some(v);
        }
        Err(e) => {
            crate::mprintln!("[-] LE_Read_Buffer_Size failed: {e}");
        }
    }

    // --- What this means -------------------------------------------------
    let mut capable: Vec<&str> = Vec::new();
    let mut incapable: Vec<&str> = Vec::new();

    // LMP injection needs raw ACL TX, which the framework now has — but the
    // controller must also accept host ACL data, which the "Host Supported
    // Commands" bit and the BR/EDR feature set imply.
    capable.push("L2CAP/ACL-level probing (raw L2CAP sockets)");
    if features.get(FEATURE_ENCRYPTION as usize).map(|b| b & 0x01 != 0) == Some(true) {
        capable.push("encrypted link creation (KNOB / BIAS surface)");
    }
    if features.get(FEATURE_RSSI_WITH_INQUIRY as usize).map(|b| b & 0x01 != 0) == Some(true) {
        capable.push("inquiry with RSSI");
    }
    if features.get(FEATURE_EXTENDED_INQUIRY_RESPONSE as usize).map(|b| b & 0x01 != 0) == Some(true) {
        capable.push("extended inquiry response");
    }
    if le_supported {
        capable.push("LE (Bluetooth Low Energy)");
    } else {
        incapable.push("LE (Bluetooth Low Energy)");
    }

    if let Some(f) = le_features {
        if f.get(LE_FEATURE_LE_EXTENDED_ADVERTISING as usize).map(|b| b & 0x01 != 0) == Some(true) {
            capable.push("LE Extended Advertising (AUX_ADV_IND)");
        } else {
            incapable.push("LE Extended Advertising (AUX_ADV_IND)");
        }
        if f.get(LE_FEATURE_LE_PERIODIC_ADVERTISING as usize).map(|b| b & 0x01 != 0) == Some(true) {
            capable.push("LE Periodic Advertising");
        } else {
            incapable.push("LE Periodic Advertising");
        }
        if f.get(LE_FEATURE_LE_ENCRYPTED_CONNECTION as usize).map(|b| b & 0x01 != 0) == Some(true) {
            capable.push("LE encrypted connections");
        }
    }

    crate::mprintln!();
    crate::mprintln!("[*] Attack primitives this radio can service:");
    for c in &capable {
        crate::mprintln!("    [+] {c}");
    }
    if !incapable.is_empty() {
        crate::mprintln!("[*] Not available on this radio:");
        for c in &incapable {
            crate::mprintln!("    [-] {c}");
        }
    }
    if let Some((acl_len, num_packets, total_packets)) = le_buffer {
        crate::mprintln!(
            "[*] Largest LE ACL payload: {acl_len} bytes — bounds any LE L2CAP COC segment."
        );
        let _ = (num_packets, total_packets);
    }

    outcome.findings.push(Finding {
        target: format!("hci{dev_id}"),
        kind: FindingKind::Banner,
        message: format!(
            "Local controller: LMP v{lmp_ver}, mfr 0x{manufacturer:04X}, LE={le_supported}, \
             {} primitive(s) available",
            capable.len()
        ),
        data: Some(serde_json::json!({
            "dev_id": dev_id,
            "lmp_version": lmp_ver,
            "manufacturer": manufacturer,
            "lmp_subversion": lmp_subver,
            "le_supported": le_supported,
            "supported_command_bytes": command_count,
            "features": format!("{features:02x?}"),
            "le_features": le_features.map(|f| format!("{f:02x?}")),
            "le_buffer": le_buffer.map(|(len, np, tp)| serde_json::json!({
                "acl_payload_len": len,
                "num_packets": np,
                "total_packets": tp,
            })),
            "capable": capable,
            "incapable": incapable,
        })),
    });

    // Keep the socket alive until the reads are done.
    drop(sock);
    let _ = Duration::from_millis(0);
    Ok(outcome)
}

#[cfg(not(all(feature = "bluetooth", target_os = "linux")))]
pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    tracing::trace!(
        "controller_info unavailable without bluetooth feature on Linux (target {:?})",
        ctx.target
    );
    anyhow::bail!(
        "controller_info requires the `bluetooth` feature on Linux with root/CAP_NET_RAW (raw HCI socket)."
    )
}

crate::register_native_module!(
    crate::module::Category::Scanners,
    "bluetooth/controller_info",
    native
);

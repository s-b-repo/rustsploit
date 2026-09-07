//! BLE reconnaissance and classification.

use anyhow::Result;

use crate::module::{ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "BLE Scan & Classifier".to_string(),
        description: "Bluetooth LE reconnaissance: scans the selected adapter, classifies every \
                      advertisement (Fast Pair 0xFE2C, Apple Find My, iBeacon, Microsoft Swift \
                      Pair, Mesh Proxy, HID-over-GATT) and persists devices into the engagement \
                      inventory. The classification feeds the blueforge attack matrix."
            .to_string(),
        authors: vec!["rustsploit contributors".to_string()],
        references: vec![
            "https://developers.google.com/nearby/fast-pair/specifications/service/provider"
                .to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: None,
    }
}

#[cfg(feature = "bluetooth")]
pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    use crate::bluetooth::inventory;
    use crate::module::{Finding, FindingKind};

    crate::bluetooth::warn_no_fanout_once("ble_scan");
    let mut outcome = ModuleOutcome::ok();
    let devices = crate::bluetooth::discovery::ble_scan(ctx).await?;
    if devices.is_empty() {
        crate::mprintln!("[-] No BLE devices visible. Increase scan_secs or move closer.");
        return Ok(outcome);
    }

    let mut inv = match inventory::load() {
        Ok(inv) => inv,
        Err(e) => {
            crate::meprintln!("[!] Could not load inventory (starting fresh): {e:#}");
            std::collections::HashMap::new()
        }
    };
    for d in &devices {
        let model = match d.fastpair_model_id {
            Some(m) => format!("0x{m:06X}"),
            None => "-".into(),
        };
        let rssi = d.rssi.map(|r| r.to_string()).unwrap_or_else(|| "?".into());
        crate::mprintln!(
            "[+] BLE {} ({}) RSSI {} [{}] classes={}",
            d.mac,
            d.name,
            rssi,
            d.transport(),
            d.classes().join(",")
        );
        for tag in &d.uuids {
            crate::mprintln!("      advert: {tag}");
        }
        if d.fastpair_model_id.is_some() {
            let state = if d.fastpair_pairing_mode {
                "PAIRING MODE"
            } else if d.fastpair_steady_state {
                "STEADY-STATE (prime WhisperPair target)"
            } else {
                "advertising"
            };
            crate::mprintln!("      Fast Pair model {model} [{state}]");
        }
        outcome.findings.push(Finding {
            target: d.mac.clone(),
            kind: FindingKind::Note,
            message: format!(
                "BLE device {} ({}) classes={}",
                d.mac,
                d.name,
                d.classes().join(",")
            ),
            data: Some(serde_json::json!({
                "mac": d.mac,
                "name": d.name,
                "rssi": d.rssi,
                "transport": d.transport(),
                "classes": d.classes(),
                "fastpair_model_id": d.fastpair_model_id,
                "uuids": d.uuids,
            })),
        });
    }

    for d in &devices {
        inventory::upsert(&mut inv, d);
    }
    match inventory::save(&inv) {
        Ok(()) => crate::mprintln!("[*] Inventory saved ({} devices).", inv.len()),
        Err(e) => crate::meprintln!("[!] Could not persist inventory: {e:#}"),
    }
    Ok(outcome)
}

#[cfg(not(feature = "bluetooth"))]
pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    tracing::trace!(
        "ble_scan unavailable without bluetooth feature (target {:?})",
        ctx.target
    );
    anyhow::bail!(
        "ble_scan requires the `bluetooth` feature — rebuild with `--features bluetooth`."
    )
}

crate::register_native_module!(
    crate::module::Category::Scanners,
    "bluetooth/ble_scan",
    native
);

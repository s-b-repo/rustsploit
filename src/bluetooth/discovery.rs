//! Unified Bluetooth discovery: BLE advert capture through btleplug plus
//! Classic inquiry through BlueZ (see [`crate::bluetooth::classic`]).
//!
//! The advert classifier recognises the ecosystems relevant to the attack
//! matrix: Google Fast Pair (0xFE2C service data), Apple Find My (0x004C
//! continuity beacons), iBeacon, Microsoft Swift Pair, Bluetooth Mesh Proxy
//! (0x1827) and HID-over-GATT (0x1812).

use std::time::Duration;

use anyhow::Result;
use btleplug::api::{Central, Peripheral as _, ScanFilter};

use super::{BtDevice, adapter};

/// Google Fast Pair service `0xFE2C`.
pub const FAST_PAIR_SERVICE_U16: u16 = 0xFE2C;
/// Bluetooth Mesh Proxy service `0x1827`.
pub const MESH_PROXY_SERVICE_U16: u16 = 0x1827;
/// HID-over-GATT service `0x1812`.
pub const HID_SERVICE_U16: u16 = 0x1812;
/// Apple, Inc. manufacturer ID.
pub const APPLE_COMPANY_ID: u16 = 0x004C;
/// Microsoft manufacturer ID (Swift Pair).
pub const MICROSOFT_COMPANY_ID: u16 = 0x0006;

/// Canonical 128-bit UUID for a Bluetooth SIG 16-bit service UUID.
pub fn svc_uuid(short: u16) -> uuid::Uuid {
    let base: u128 = 0x0000_1000_8000_0080_5f9b_34fb;
    uuid::Uuid::from_u128(((short as u128) << 96) | base)
}

/// Scan the selected adapter for `scan_secs` (setg) and classify every
/// peripheral in range. No service filter is applied: BlueZ service-filtered
/// scans drop devices whose UUID appears only in service *data*, so match in
/// software instead.
pub async fn ble_scan(ctx: &crate::module::ModuleCtx) -> Result<Vec<BtDevice>> {
    use btleplug::api::Manager as _;

    let manager = btleplug::platform::Manager::new()
        .await
        .map_err(|e| anyhow::anyhow!("btleplug manager init failed: {e}"))?;
    let adapters = manager
        .adapters()
        .await
        .map_err(|e| anyhow::anyhow!("listing Bluetooth adapters failed: {e}"))?;
    if adapters.is_empty() {
        anyhow::bail!("no BLE adapters found — power a controller with 'bluetoothctl power on'");
    }
    let idx = adapter::adapter_index();
    let central = adapters
        .into_iter()
        .nth(idx)
        .ok_or_else(|| anyhow::anyhow!("adapter index {idx} out of range"))?;

    let scan_secs = adapter::scan_duration().await;
    let target = super::resolve_target_mac(ctx);

    central
        .start_scan(ScanFilter::default())
        .await
        .map_err(|e| anyhow::anyhow!("starting BLE scan failed: {e}"))?;
    match &target {
        Some(m) => {
            crate::mprintln!("[*] Scanning {scan_secs}s for Bluetooth devices (target {m}) ...")
        }
        None => {
            crate::mprintln!("[*] Scanning {scan_secs}s for Bluetooth devices (all in range) ...")
        }
    }

    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(scan_secs)) => {}
        _ = ctx.cancel.cancelled() => {
            crate::meprintln!("[!] Scan cancelled before the window elapsed.");
        }
    }

    let peripherals = central
        .peripherals()
        .await
        .map_err(|e| anyhow::anyhow!("listing discovered peripherals failed: {e}"))?;
    if let Err(e) = central.stop_scan().await {
        tracing::debug!("stop_scan failed: {e:#}");
    }

    let mut found = Vec::new();
    for p in peripherals {
        let props = match p.properties().await {
            Ok(Some(props)) => props,
            Ok(None) => continue,
            Err(e) => {
                tracing::debug!("reading peripheral properties: {e:#}");
                continue;
            }
        };
        let mac = props.address.to_string();
        if let Some(want) = target.as_deref()
            && !mac.eq_ignore_ascii_case(want)
        {
            continue;
        }
        let mut dev = classify_advert(&mac, &props);
        dev.le = true;
        found.push(dev);
    }
    Ok(found)
}

/// Classify one advertisement set into a [`BtDevice`].
fn classify_advert(mac: &str, props: &btleplug::api::PeripheralProperties) -> BtDevice {
    let fp_svc = svc_uuid(FAST_PAIR_SERVICE_U16);
    let mut dev = BtDevice {
        mac: mac.to_string(),
        name: props
            .local_name
            .clone()
            .unwrap_or_else(|| "(unknown)".into()),
        rssi: props.rssi,
        ..Default::default()
    };

    // Fast Pair service data: 3-byte model ID (pairing mode) or 16-byte
    // account-key filter (steady state).
    if let Some(data) = props.service_data.get(&fp_svc) {
        if let Some(mid) = crate::bluetooth::fastpair::db::model_id_from_service_data(data) {
            dev.fastpair_model_id = Some(mid);
            dev.fastpair_pairing_mode = true;
        } else if crate::bluetooth::fastpair::db::is_account_key_filter(data) {
            dev.fastpair_steady_state = true;
        }
    }

    for (company, data) in &props.manufacturer_data {
        match *company {
            APPLE_COMPANY_ID => {
                if let Some(first) = data.first() {
                    match first {
                        0x10 => dev.uuids.push("apple-findmy".to_string()),
                        0x02 => dev.uuids.push("ibeacon".to_string()),
                        _ => dev.uuids.push("apple-continuity".to_string()),
                    }
                }
            }
            MICROSOFT_COMPANY_ID => {
                dev.uuids.push("microsoft-swift-pair".to_string());
            }
            _ => {}
        }
        dev.manufacturer_data.push((*company, data.clone()));
    }

    dev.uuids.sort();
    dev.uuids.dedup();
    dev
}

/// Merge a freshly-scanned device into an existing list (by MAC), preferring
/// the richer record.
pub fn merge(existing: &mut Vec<BtDevice>, incoming: Vec<BtDevice>) {
    for dev in incoming {
        match existing
            .iter_mut()
            .find(|d| d.mac.eq_ignore_ascii_case(&dev.mac))
        {
            Some(existing) => {
                if dev.classic {
                    existing.classic = true;
                    existing.class_of_device = existing.class_of_device.or(dev.class_of_device);
                }
                if dev.le {
                    existing.le = true;
                }
                if dev.fastpair_model_id.is_some() && existing.fastpair_model_id.is_none() {
                    existing.fastpair_model_id = dev.fastpair_model_id;
                    existing.fastpair_pairing_mode = dev.fastpair_pairing_mode;
                    existing.fastpair_steady_state = dev.fastpair_steady_state;
                }
                if existing.rssi.is_none() {
                    existing.rssi = dev.rssi;
                }
                for u in dev.uuids {
                    if !existing.uuids.contains(&u) {
                        existing.uuids.push(u);
                    }
                }
                if dev.name != "(unknown)" {
                    existing.name = dev.name;
                }
            }
            None => existing.push(dev),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_constants() {
        assert_eq!(FAST_PAIR_SERVICE_U16, 0xFE2C);
        assert_eq!(MESH_PROXY_SERVICE_U16, 0x1827);
        assert_eq!(HID_SERVICE_U16, 0x1812);
        assert_eq!(APPLE_COMPANY_ID, 0x004C);
    }

    #[test]
    fn svc_uuid_is_canonical() {
        let u = svc_uuid(0xFE2C);
        assert_eq!(u.to_string(), "0000fe2c-0000-1000-8000-00805f9b34fb");
    }
}

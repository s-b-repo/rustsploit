//! Local Bluetooth adapter enumeration, selection and power control.
//!
//! BLE adapters are enumerated through btleplug; the operator picks one with
//! `setg adapter <n>` (alias `wpair_adapter`). This is the single source of
//! truth shared by every radio module.

use anyhow::{Result, anyhow};

/// Open the selected local BLE adapter (btleplug/BlueZ).
pub async fn open_adapter() -> Result<btleplug::platform::Adapter> {
    use btleplug::api::Manager as _;
    let manager = btleplug::platform::Manager::new()
        .await
        .map_err(|e| anyhow!("btleplug manager init failed: {e}"))?;
    let adapters = manager
        .adapters()
        .await
        .map_err(|e| anyhow!("listing Bluetooth adapters failed: {e}"))?;
    let count = adapters.len();
    if count == 0 {
        anyhow::bail!(
            "No Bluetooth adapters found. Ensure a BLE controller is present and powered on \
             ('bluetoothctl power on'), and that you have permission (root or CAP_NET_RAW)."
        );
    }
    let idx = adapter_index();
    if idx >= count {
        anyhow::bail!(
            "Adapter index {idx} out of range — {count} present. Pick one with 'setg adapter <n>'."
        );
    }
    adapters
        .into_iter()
        .nth(idx)
        .ok_or_else(|| anyhow!("adapter {idx} disappeared during enumeration"))
}

/// Selected adapter index from global options (`adapter` or `wpair_adapter`).
pub fn adapter_index() -> usize {
    let raw = crate::tenant::resolve()
        .global_options()
        .try_get("adapter")
        .or_else(|| {
            crate::tenant::resolve()
                .global_options()
                .try_get("wpair_adapter")
        });
    let Some(raw) = raw else {
        return 0;
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return 0;
    }
    match raw.parse::<usize>() {
        Ok(n) => n,
        Err(e) => {
            crate::meprintln!("[!] invalid adapter '{raw}' ({e}) — using 0.");
            0
        }
    }
}

/// Operator-configured BLE scan window in seconds (`setg scan_secs <s>`).
pub async fn scan_duration() -> u64 {
    let Some(raw) = crate::tenant::resolve()
        .global_options()
        .get("scan_secs")
        .await
    else {
        return 15;
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return 15;
    }
    match raw.parse::<u64>() {
        Ok(n) => n.clamp(3, 300),
        Err(e) => {
            crate::meprintln!("[!] invalid scan_secs '{raw}' ({e}) — using 15.");
            15
        }
    }
}

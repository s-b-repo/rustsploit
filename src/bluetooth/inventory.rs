//! Persistent Bluetooth device inventory.
//!
//! Stores discovered devices as JSON under `~/.rustsploit/bluetooth_inventory.json`
//! so engagements accumulate a device database across sessions. Every device
//! record carries the classification hints the attack matrix keys off.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use super::BtDevice;

/// A stored inventory entry (device + bookkeeping).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InventoryEntry {
    pub mac: String,
    pub name: String,
    pub rssi: Option<i16>,
    pub classic: bool,
    pub le: bool,
    pub class_of_device: Option<u32>,
    pub fastpair_model_id: Option<u32>,
    pub uuids: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
    /// Modules that have been run against this device.
    pub attacks_attempted: Vec<String>,
}

impl From<&BtDevice> for InventoryEntry {
    fn from(d: &BtDevice) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        InventoryEntry {
            mac: d.mac.clone(),
            name: d.name.clone(),
            rssi: d.rssi,
            classic: d.classic,
            le: d.le,
            class_of_device: d.class_of_device,
            fastpair_model_id: d.fastpair_model_id,
            uuids: d.uuids.clone(),
            first_seen: now.clone(),
            last_seen: now,
            attacks_attempted: Vec::new(),
        }
    }
}

impl From<&InventoryEntry> for BtDevice {
    fn from(e: &InventoryEntry) -> Self {
        BtDevice {
            mac: e.mac.clone(),
            name: e.name.clone(),
            rssi: e.rssi,
            classic: e.classic,
            le: e.le,
            class_of_device: e.class_of_device,
            fastpair_model_id: e.fastpair_model_id,
            fastpair_pairing_mode: false,
            fastpair_steady_state: false,
            uuids: e.uuids.clone(),
            manufacturer_data: Vec::new(),
        }
    }
}

/// Inventory file location: `$RUSTSPLOIT_HOME` or `~/.rustsploit/`.
pub fn inventory_path() -> Result<std::path::PathBuf> {
    let base = match std::env::var("RUSTSPLOIT_HOME") {
        Ok(h) if !h.trim().is_empty() => h,
        _ => {
            let home =
                std::env::var("HOME").map_err(|e| anyhow::anyhow!("resolving $HOME: {e}"))?;
            format!("{home}/.rustsploit")
        }
    };
    Ok(PathBuf::from(base).join("bluetooth_inventory.json"))
}

/// Load the whole inventory.
pub fn load() -> Result<HashMap<String, InventoryEntry>> {
    let path = inventory_path()?;
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

/// Persist the whole inventory atomically.
pub fn save(entries: &HashMap<String, InventoryEntry>) -> Result<()> {
    let path = inventory_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(entries).context("serialising inventory")?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("renaming into {}", path.display()))
}

/// Upsert one scanned device; preserves `first_seen` and attack history.
pub fn upsert(entries: &mut HashMap<String, InventoryEntry>, dev: &BtDevice) {
    let key = dev.mac.to_ascii_uppercase();
    match entries.get_mut(&key) {
        Some(existing) => {
            if dev.name != "(unknown)" {
                existing.name = dev.name.clone();
            }
            existing.rssi = existing.rssi.or(dev.rssi);
            existing.classic |= dev.classic;
            existing.le |= dev.le;
            existing.class_of_device = existing.class_of_device.or(dev.class_of_device);
            if existing.fastpair_model_id.is_none() {
                existing.fastpair_model_id = dev.fastpair_model_id;
            }
            for u in &dev.uuids {
                if !existing.uuids.contains(u) {
                    existing.uuids.push(u.clone());
                }
            }
            existing.last_seen = chrono::Utc::now().to_rfc3339();
        }
        None => {
            let entry = InventoryEntry::from(dev);
            entries.insert(key, entry);
        }
    }
}

/// Record that an attack module ran against a device.
pub fn record_attack(entries: &mut HashMap<String, InventoryEntry>, mac: &str, module: &str) {
    let key = mac.to_ascii_uppercase();
    if let Some(entry) = entries.get_mut(&key)
        && !entry.attacks_attempted.iter().any(|a| a == module)
    {
        entry.attacks_attempted.push(module.to_string());
    }
}

/// Record a Fast Pair account key planted on a target BDADDR. The follow-up
/// `classic_pin` / `wpair` modules read this on a later engagement to test
/// the planted key first before going to dictionary. Stored as a hex string
/// in `account_keys` keyed by MAC, alongside the existing inventory entries.
pub fn record_account_key(mac: &str, key: &[u8; 16]) -> Result<()> {
    let mut entries = load()?;
    let key_map_key = mac.to_ascii_uppercase();
    let hex_key: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let mut entry = match entries.remove(&key_map_key) {
        Some(e) => e,
        None => InventoryEntry::default(),
    };
    entry.mac = key_map_key.clone();
    entry.last_seen = chrono::Utc::now().to_rfc3339();
    entries.insert(entry.mac.clone(), entry);
    save(&entries)?;
    persist_account_key_sidecar(&key_map_key, &hex_key)?;
    crate::mprintln!(
        "[*] Account key for {} persisted to inventory sidecar.",
        mac
    );
    Ok(())
}

fn account_key_sidecar_path() -> Result<std::path::PathBuf> {
    let base = inventory_path()?;
    Ok(base.with_extension("account_keys.json"))
}

fn persist_account_key_sidecar(mac: &str, hex_key: &str) -> Result<()> {
    let mut map: std::collections::HashMap<String, String> = {
        let path = account_key_sidecar_path()?;
        if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            serde_json::from_str(&raw)
                .with_context(|| format!("parsing {}", path.display()))?
        } else {
            std::collections::HashMap::new()
        }
    };
    map.insert(mac.to_string(), hex_key.to_string());
    let path = account_key_sidecar_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(&map).context("serialising account-key sidecar")?;
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))
}

/// Look up a planted account key for `mac` (returns hex).
pub fn lookup_account_key(mac: &str) -> Result<Option<String>> {
    let path = account_key_sidecar_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    let map: std::collections::HashMap<String, String> = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {}", path.display()))?;
    Ok(map.get(&mac.to_ascii_uppercase()).cloned())
}

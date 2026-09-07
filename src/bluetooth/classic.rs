//! BR/EDR (Classic) device discovery, pairing and transport via BlueZ D-Bus.
//!
//! Discovery reads the ObjectManager snapshot after `Adapter1.StartDiscovery`
//! — no per-device property round-trips. Pairing/connecting drive
//! `Device1.Pair`/`Device1.Connect` with explicit cancellation. Linux-only in
//! practice (BlueZ), but the code compiles everywhere and fails gracefully.

use std::time::Duration;

use anyhow::{Result, anyhow};
use zbus::zvariant::OwnedValue;

use super::BtDevice;

/// BlueZ D-Bus well-known name and paths.
pub const BLUEZ_SERVICE: &str = "org.bluez";
pub const OBJECT_MANAGER_PATH: &str = "/";

/// One BlueZ `Device1` object from an ObjectManager snapshot.
#[derive(Debug, Clone, Default)]
pub struct BluezDevice {
    pub object_path: String,
    pub mac: String,
    pub name: String,
    pub alias: String,
    pub class_of_device: Option<u32>,
    pub rssi: Option<i16>,
    pub paired: bool,
    pub connected: bool,
    pub legacy_pairing: Option<bool>,
    pub uuids: Vec<String>,
}

impl From<BluezDevice> for BtDevice {
    fn from(d: BluezDevice) -> Self {
        BtDevice {
            mac: d.mac,
            name: if d.name.is_empty() { d.alias } else { d.name },
            rssi: d.rssi,
            classic: true,
            le: false,
            class_of_device: d.class_of_device,
            fastpair_model_id: None,
            fastpair_pairing_mode: false,
            fastpair_steady_state: false,
            uuids: d.uuids,
            manufacturer_data: Vec::new(),
        }
    }
}

/// Extract a property out of an ObjectManager interface map.
fn prop_str<'v>(
    iface: &std::collections::HashMap<String, OwnedValue>,
    key: &str,
) -> Option<String> {
    iface
        .get(key)
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| <String as TryFrom<OwnedValue>>::try_from(v).ok())
}

fn prop_u32(iface: &std::collections::HashMap<String, OwnedValue>, key: &str) -> Option<u32> {
    iface
        .get(key)
        .and_then(|v| <u32 as TryFrom<OwnedValue>>::try_from(v.try_clone().ok()?).ok())
}

fn prop_i16(iface: &std::collections::HashMap<String, OwnedValue>, key: &str) -> Option<i16> {
    iface
        .get(key)
        .and_then(|v| <i16 as TryFrom<OwnedValue>>::try_from(v.try_clone().ok()?).ok())
}

fn prop_bool(iface: &std::collections::HashMap<String, OwnedValue>, key: &str) -> Option<bool> {
    iface
        .get(key)
        .and_then(|v| <bool as TryFrom<OwnedValue>>::try_from(v.try_clone().ok()?).ok())
}

fn prop_str_array(iface: &std::collections::HashMap<String, OwnedValue>, key: &str) -> Vec<String> {
    iface
        .get(key)
        .and_then(|v| <Vec<String> as TryFrom<OwnedValue>>::try_from(v.try_clone().ok()?).ok())
        .unwrap_or_else(Vec::new)
}

/// Snapshot every BlueZ object the daemon currently knows about, flattened to
/// `(object_path, interface_name, properties)`.
pub async fn managed_objects(
    conn: &zbus::Connection,
) -> Result<
    Vec<(
        String,
        String,
        std::collections::HashMap<String, OwnedValue>,
    )>,
> {
    use zbus::zvariant::OwnedObjectPath;
    let om = zbus::Proxy::new(
        conn,
        BLUEZ_SERVICE,
        OBJECT_MANAGER_PATH,
        "org.freedesktop.DBus.ObjectManager",
    )
    .await
    .map_err(|e| anyhow!("BlueZ ObjectManager proxy: {e} — is the bluetooth service running?"))?;
    let reply: std::collections::HashMap<
        OwnedObjectPath,
        std::collections::HashMap<String, std::collections::HashMap<String, OwnedValue>>,
    > = om
        .call("GetManagedObjects", &())
        .await
        .map_err(|e| anyhow!("GetManagedObjects failed: {e}"))?;

    let mut out = Vec::new();
    for (path, interfaces) in reply {
        for (iface, props) in interfaces {
            out.push((path.to_string(), iface, props));
        }
    }
    Ok(out)
}

/// Enumerate BlueZ `Device1` objects from an ObjectManager snapshot.
pub async fn list_devices(conn: &zbus::Connection) -> Result<Vec<BluezDevice>> {
    let objects = managed_objects(conn).await?;
    let mut out = Vec::new();
    for (path, iface, props) in objects {
        if iface != "org.bluez.Device1" {
            continue;
        }
        out.push(BluezDevice {
            object_path: path,
            mac: prop_str(&props, "Address").unwrap_or_else(String::new),
            name: prop_str(&props, "Name").unwrap_or_else(String::new),
            alias: prop_str(&props, "Alias").unwrap_or_else(String::new),
            class_of_device: prop_u32(&props, "Class"),
            rssi: prop_i16(&props, "RSSI"),
            paired: prop_bool(&props, "Paired").unwrap_or(false),
            connected: prop_bool(&props, "Connected").unwrap_or(false),
            legacy_pairing: prop_bool(&props, "LegacyPairing"),
            uuids: prop_str_array(&props, "UUIDs"),
        });
    }
    Ok(out)
}

/// Open a system-bus connection (the only bus BlueZ lives on).
pub async fn connect_system_bus() -> Result<zbus::Connection> {
    zbus::Connection::system()
        .await
        .map_err(|e| anyhow!("connecting to the system D-Bus: {e}"))
}

/// Start Classic discovery on the default adapter.
pub async fn start_discovery(conn: &zbus::Connection) -> Result<()> {
    let adapter = default_adapter_path(conn).await?;
    let proxy = zbus::Proxy::new(conn, BLUEZ_SERVICE, adapter, "org.bluez.Adapter1")
        .await
        .map_err(|e| anyhow!("Adapter1 proxy: {e}"))?;
    proxy
        .call("StartDiscovery", &())
        .await
        .map_err(|e| anyhow!("StartDiscovery: {e}"))
}

/// Stop discovery on the default adapter (errors logged, not fatal).
pub async fn stop_discovery(conn: &zbus::Connection) {
    let adapter = match default_adapter_path(conn).await {
        Ok(a) => a,
        Err(e) => {
            tracing::debug!("no adapter for StopDiscovery: {e:#}");
            return;
        }
    };
    match zbus::Proxy::new(conn, BLUEZ_SERVICE, adapter, "org.bluez.Adapter1").await {
        Ok(proxy) => {
            if let Err(e) = proxy.call::<_, _, ()>("StopDiscovery", &()).await {
                tracing::debug!("StopDiscovery failed: {e:#}");
            }
        }
        Err(e) => tracing::debug!("Adapter1 proxy for StopDiscovery: {e:#}"),
    }
}

/// Find the first `Adapter1` object path (`/org/bluez/hciX`).
pub async fn default_adapter_path(conn: &zbus::Connection) -> Result<String> {
    let objects = managed_objects(conn).await?;
    for (path, iface, _props) in objects {
        if iface == "org.bluez.Adapter1" {
            return Ok(path);
        }
    }
    Err(anyhow!(
        "no org.bluez.Adapter1 present — is a Classic controller available?"
    ))
}

/// Pair with a device (blocks until the BlueZ agent finishes; a PIN/passkey
/// agent must be registered for legacy devices — see `creds/bluetooth/classic_pin`).
pub async fn pair(conn: &zbus::Connection, mac: &str) -> Result<()> {
    let path = device_path_for(conn, mac).await?;
    let proxy = zbus::Proxy::new(conn, BLUEZ_SERVICE, path, "org.bluez.Device1")
        .await
        .map_err(|e| anyhow!("Device1 proxy: {e}"))?;
    proxy
        .call::<_, _, ()>("Pair", &())
        .await
        .map_err(|e| anyhow!("Pair {mac}: {e}"))
}

/// Connect all profiles of a device.
pub async fn connect_device(conn: &zbus::Connection, mac: &str) -> Result<()> {
    let path = device_path_for(conn, mac).await?;
    let proxy = zbus::Proxy::new(conn, BLUEZ_SERVICE, path, "org.bluez.Device1")
        .await
        .map_err(|e| anyhow!("Device1 proxy: {e}"))?;
    proxy
        .call::<_, _, ()>("Connect", &())
        .await
        .map_err(|e| anyhow!("Connect {mac}: {e}"))
}

/// Remove pairing/bonding info for a device.
pub async fn remove_device(conn: &zbus::Connection, mac: &str) -> Result<()> {
    let path = device_path_for(conn, mac).await?;
    let parent = path
        .rsplit_once('/')
        .map(|(p, _)| p.to_string())
        .ok_or_else(|| anyhow!("malformed device path {path}"))?;
    let adapter = zbus::Proxy::new(conn, BLUEZ_SERVICE, parent, "org.bluez.Adapter1")
        .await
        .map_err(|e| anyhow!("Adapter1 proxy: {e}"))?;
    adapter
        .call(
            "RemoveDevice",
            &(zbus::zvariant::ObjectPath::try_from(path)?),
        )
        .await
        .map_err(|e| anyhow!("RemoveDevice {mac}: {e}"))
}

/// Resolve (or scan for) the BlueZ object path of a device by MAC.
pub async fn device_path_for(conn: &zbus::Connection, mac: &str) -> Result<String> {
    let want = mac.to_ascii_uppercase().replace('-', ":");
    let devices = list_devices(conn).await?;
    if let Some(d) = devices.iter().find(|d| d.mac.eq_ignore_ascii_case(&want)) {
        return Ok(d.object_path.clone());
    }
    // Not known yet: start discovery briefly and re-snapshot.
    if start_discovery(conn).await.is_ok() {
        tokio::time::sleep(Duration::from_secs(6)).await;
        match list_devices(conn).await {
            Ok(devices) => {
                if let Some(d) = devices.iter().find(|d| d.mac.eq_ignore_ascii_case(&want)) {
                    let p = d.object_path.clone();
                    stop_discovery(conn).await;
                    return Ok(p);
                }
            }
            Err(e) => tracing::debug!("device_path_for: re-snapshot after discovery failed: {e:#}"),
        }
        stop_discovery(conn).await;
    }
    Err(anyhow!(
        "device {mac} unknown to BlueZ — run a discovery first or pair manually once"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bluez_constants() {
        assert_eq!(BLUEZ_SERVICE, "org.bluez");
        assert_eq!(OBJECT_MANAGER_PATH, "/");
    }
}

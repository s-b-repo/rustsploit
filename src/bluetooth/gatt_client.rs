//! btleplug GATT plumbing shared by every BLE module: connect with retry and
//! per-attempt timeout, characteristic lookup, read/write, and the
//! write-then-await-notification pattern used by Fast Pair request/response.

use std::time::Duration;

use anyhow::{Result, anyhow};
use btleplug::api::{Central, Characteristic, Peripheral as _, WriteType};
use btleplug::platform::{Adapter, Peripheral};
use futures::StreamExt;
use uuid::Uuid;

/// Connect to a discovered peripheral by MAC, with retry/backoff and a
/// per-attempt timeout — BLE links are flaky, so a single attempt is not
/// production-grade. The caller must have scanned first.
pub async fn connect(central: &Adapter, mac: &str) -> Result<Peripheral> {
    let attempts = retry_count().await;
    let backoff_ms = retry_backoff_ms().await;
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=attempts {
        match connect_once(central, mac).await {
            Ok(p) => return Ok(p),
            Err(e) => {
                tracing::debug!("ble connect attempt {attempt}/{attempts} to {mac}: {e:#}");
                last_err = Some(e);
                if attempt < attempts {
                    tokio::time::sleep(Duration::from_millis(backoff_ms * attempt as u64)).await;
                }
            }
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Err(anyhow!("could not connect to {mac}")),
    }
}

async fn retry_count() -> u32 {
    crate::tenant::resolve()
        .global_options()
        .get("wpair_retries")
        .await
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(3)
}

async fn retry_backoff_ms() -> u64 {
    crate::tenant::resolve()
        .global_options()
        .get("wpair_retry_ms")
        .await
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(400)
}

/// One connect attempt: locate the peripheral, connect (bounded by a timeout),
/// and run service discovery.
async fn connect_once(central: &Adapter, mac: &str) -> Result<Peripheral> {
    let peripherals = central
        .peripherals()
        .await
        .map_err(|e| anyhow!("listing discovered peripherals: {e}"))?;
    for p in peripherals {
        let addr = match p.properties().await {
            Ok(Some(props)) => props.address.to_string(),
            Ok(None) => continue,
            Err(e) => {
                tracing::debug!("reading peripheral properties: {e:#}");
                continue;
            }
        };
        if !addr.eq_ignore_ascii_case(mac) {
            continue;
        }
        let already_connected = match p.is_connected().await {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(
                    "is_connected check on {mac} failed, assuming not connected: {e:#}"
                );
                false
            }
        };
        if !already_connected {
            tokio::time::timeout(Duration::from_secs(10), p.connect())
                .await
                .map_err(|e| anyhow!("connect to {mac} timed out after 10s: {e}"))?
                .map_err(|e| anyhow!("connecting to {mac}: {e}"))?;
        }
        p.discover_services()
            .await
            .map_err(|e| anyhow!("discovering services on {mac}: {e}"))?;
        return Ok(p);
    }
    Err(anyhow!(
        "device {mac} not found among discovered peripherals — run `scan` first"
    ))
}

/// Find a characteristic by UUID on a connected peripheral.
pub fn find_characteristic(p: &Peripheral, uuid: Uuid) -> Result<Characteristic> {
    p.characteristics()
        .into_iter()
        .find(|c| c.uuid == uuid)
        .ok_or_else(|| anyhow!("characteristic {uuid} not found"))
}

/// Write bytes to a characteristic (with or without response).
pub async fn write(p: &Peripheral, uuid: Uuid, data: &[u8], with_response: bool) -> Result<()> {
    let ch = find_characteristic(p, uuid)?;
    let write_type = if with_response {
        WriteType::WithResponse
    } else {
        WriteType::WithoutResponse
    };
    p.write(&ch, data, write_type)
        .await
        .map_err(|e| anyhow!("writing {} bytes to {uuid}: {e}", data.len()))
}

/// Read a characteristic's value.
pub async fn read(p: &Peripheral, uuid: Uuid) -> Result<Vec<u8>> {
    let ch = find_characteristic(p, uuid)?;
    p.read(&ch)
        .await
        .map_err(|e| anyhow!("reading {uuid}: {e}"))
}

/// Write a request and await one notification on `notify_uuid`, bounded by
/// `timeout`. `Ok(None)` = no response arrived in time (the device rejected
/// or ignored the write).
pub async fn write_and_await(
    p: &Peripheral,
    write_uuid: Uuid,
    data: &[u8],
    notify_uuid: Uuid,
    timeout: Duration,
) -> Result<Option<Vec<u8>>> {
    let notify_ch = find_characteristic(p, notify_uuid)?;
    p.subscribe(&notify_ch)
        .await
        .map_err(|e| anyhow!("subscribing to {notify_uuid}: {e}"))?;
    let mut stream = p
        .notifications()
        .await
        .map_err(|e| anyhow!("opening notification stream: {e}"))?;

    write(p, write_uuid, data, true).await?;

    let wait = async {
        while let Some(n) = stream.next().await {
            if n.uuid == notify_uuid {
                return Some(n.value);
            }
        }
        None
    };
    match tokio::time::timeout(timeout, wait).await {
        Ok(value) => Ok(value),
        // The only `Err` is `tokio::time::error::Elapsed` (the deadline passed),
        // which is a valid "no response in time" outcome, not an operation error.
        Err(e) => {
            tracing::debug!("GATT characteristic read timed out: {e:#}");
            Ok(None)
        }
    }
}

/// Best-effort disconnect — errors are non-fatal (the device may already be gone).
pub async fn disconnect(p: &Peripheral) {
    if let Err(e) = p.disconnect().await {
        tracing::debug!("ble disconnect failed: {e:#}");
    }
}

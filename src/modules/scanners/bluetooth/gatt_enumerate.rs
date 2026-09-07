//! GATT surface enumeration for a BLE target.

use anyhow::Result;

use crate::module::{ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "GATT Enumerator".to_string(),
        description: "Connects to a BLE target and dumps its full GATT surface: services, \
                      characteristics, properties and handles. Performs safe reads of every \
                      readable characteristic and flags writable ones — the write surface is \
                      what BLESA/whisper-class exploits abuse. Set a target MAC via \
                      `use module` + target, or `setg target_mac`."
            .to_string(),
        authors: vec!["rustsploit contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: None,
    }
}

#[cfg(feature = "bluetooth")]
pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    use btleplug::api::{CharPropFlags, Peripheral as _};

    use crate::bluetooth::{adapter, gatt_client, resolve_target_mac};
    use crate::module::{Finding, FindingKind};

    crate::bluetooth::warn_no_fanout_once("gatt_enumerate");
    let mut outcome = ModuleOutcome::ok();

    let target = match resolve_target_mac(ctx) {
        Some(t) => t,
        None => {
            // Discover and auto-select the single visible device, else fail.
            let devices = crate::bluetooth::discovery::ble_scan(ctx).await?;
            if devices.len() == 1 {
                let mac = devices[0].mac.clone();
                crate::mprintln!("[*] Auto-selected the only visible device: {mac}");
                mac
            } else {
                anyhow::bail!(
                    "no target — 'setg target_mac <MAC>' or ensure exactly one device is in range"
                );
            }
        }
    };

    let central = adapter::open_adapter().await?;
    let p = gatt_client::connect(&central, &target).await?;

    let services = p.services();
    if services.is_empty() {
        crate::mprintln!("[-] No services discovered on {target}.");
        gatt_client::disconnect(&p).await;
        return Ok(outcome);
    }

    let mut writable: Vec<String> = Vec::new();
    let mut read_values: Vec<(String, Vec<u8>)> = Vec::new();

    for svc in &services {
        crate::mprintln!("[*] Service {} (primary={})", svc.uuid, svc.primary);
        for ch in p
            .characteristics()
            .iter()
            .filter(|c| c.service_uuid == svc.uuid)
        {
            let mut props = Vec::new();
            let pset = ch.properties;
            if pset.contains(CharPropFlags::READ) {
                props.push("read");
            }
            if pset.intersects(CharPropFlags::WRITE | CharPropFlags::WRITE_WITHOUT_RESPONSE) {
                props.push("write");
            }
            if pset.contains(CharPropFlags::NOTIFY) {
                props.push("notify");
            }
            if pset.contains(CharPropFlags::INDICATE) {
                props.push("indicate");
            }
            crate::mprintln!("    {} [{}]", ch.uuid, props.join(","));
            if pset.intersects(CharPropFlags::WRITE | CharPropFlags::WRITE_WITHOUT_RESPONSE) {
                writable.push(ch.uuid.to_string());
            }
            if pset.contains(CharPropFlags::READ) {
                // Safe bounded read — never write, only observe.
                match gatt_client::read(&p, ch.uuid).await {
                    Ok(val) => {
                        let shown: String =
                            val.iter().take(24).map(|b| format!("{b:02x}")).collect();
                        crate::mprintln!("      value: {shown}{} bytes", val.len());
                        read_values.push((ch.uuid.to_string(), val));
                    }
                    Err(e) => tracing::debug!("read {} on {target}: {e:#}", ch.uuid),
                }
            }
        }
    }

    gatt_client::disconnect(&p).await;

    crate::mprintln!(
        "[*] {target}: {} services, {} writable characteristics",
        services.len(),
        writable.len()
    );
    if !writable.is_empty() {
        crate::mprintln!("[!] Writable surface present — reconnect-write probes (BLESA) apply.");
    }
    outcome.findings.push(Finding {
        target: target.clone(),
        kind: FindingKind::Note,
        message: format!(
            "GATT surface: {} services, {} writable chars on {target}",
            services.len(),
            writable.len()
        ),
        data: Some(serde_json::json!({
            "mac": target,
            "services": services.iter().map(|s| s.uuid.to_string()).collect::<Vec<_>>(),
            "writable": writable,
            "read_values": read_values.iter().map(|(u, v)| serde_json::json!({
                "uuid": u,
                "value_hex": crate::bluetooth::hex(v),
            })).collect::<Vec<_>>(),
        })),
    });
    Ok(outcome)
}

#[cfg(not(feature = "bluetooth"))]
pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    tracing::trace!(
        "gatt_enumerate unavailable without bluetooth feature (target {:?})",
        ctx.target
    );
    anyhow::bail!(
        "gatt_enumerate requires the `bluetooth` feature — rebuild with `--features bluetooth`."
    )
}

crate::register_native_module!(
    crate::module::Category::Scanners,
    "bluetooth/gatt_enumerate",
    native
);

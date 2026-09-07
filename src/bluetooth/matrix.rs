//! Attack matrix: device classification → applicable modules.
//!
//! `blueforge` consults this to drive the per-device attack sequence. Every
//! entry maps a class tag (see `BtDevice::classes()`) to the module paths
//! that apply, in recommended order (recon → probes → exploits).

/// One matrix row: class tag + ordered module recommendations.
#[derive(Debug, Clone)]
pub struct MatrixRow {
    pub class_tag: &'static str,
    /// Module paths in execution order.
    pub modules: &'static [&'static str],
    /// Short rationale surfaced in the REPL.
    pub rationale: &'static str,
}

/// The full attack matrix.
pub const MATRIX: &[MatrixRow] = &[
    MatrixRow {
        class_tag: "fastpair",
        modules: &[
            "scanners/bluetooth/ble_scan",
            "scanners/bluetooth/gatt_enumerate",
            "exploits/bluetooth/wpair",
        ],
        rationale: "Fast Pair provider — WhisperPair KBP bypass chain applies",
    },
    MatrixRow {
        class_tag: "hid",
        modules: &[
            "scanners/bluetooth/ble_scan",
            "exploits/bluetooth/hid_injection",
            "exploits/bluetooth/mode_confusion",
        ],
        rationale: "HID device — unauthenticated-pairing keystroke injection (CVE-2023-45866)",
    },
    MatrixRow {
        class_tag: "hid-auto-pair-attempt",
        modules: &[
            "scanners/bluetooth/ble_scan",
            "exploits/bluetooth/hid_gatt_server",
        ],
        rationale: "HID-over-GATT auto-pair attempt — fake keyboard injection",
    },
    MatrixRow {
        class_tag: "a2dp",
        modules: &[
            "scanners/bluetooth/classic_scan",
            "exploits/bluetooth/l2cap_probe",
            "exploits/bluetooth/knob_probe",
        ],
        rationale: "Audio device — L2CAP/AVDTP surface + KNOB entropy check",
    },
    MatrixRow {
        class_tag: "a2dp-sink",
        modules: &[
            "scanners/bluetooth/classic_scan",
            "exploits/bluetooth/avdtp_hijack",
        ],
        rationale: "A2DP sink (headphones/speaker) — AVDTP signalling hijack",
    },
    MatrixRow {
        class_tag: "handsfree",
        modules: &[
            "scanners/bluetooth/classic_scan",
            "exploits/bluetooth/carwhisperer",
        ],
        rationale: "Hands-Free Profile — microphone/audio injection via AT commands",
    },
    MatrixRow {
        class_tag: "obex-paired",
        modules: &[
            "exploits/bluetooth/bluebug_obex",
            "exploits/bluetooth/bluesnarf_obex",
        ],
        rationale: "Paired OBEX target — file-system / contact theft path",
    },
    MatrixRow {
        class_tag: "classic",
        modules: &[
            "scanners/bluetooth/classic_scan",
            "exploits/bluetooth/l2cap_probe",
            "exploits/bluetooth/knob_probe",
            "exploits/bluetooth/ctkd_probe",
            "exploits/bluetooth/bias",
            "exploits/bluetooth/bluffs",
        ],
        rationale: "Classic BR/EDR — full LMP/auth attack suite",
    },
    MatrixRow {
        class_tag: "classic-bnep-reachable",
        modules: &["exploits/bluetooth/blueborne_full"],
        rationale: "BNEP reachable — BlueBorne full RCE/DoS class",
    },
    MatrixRow {
        class_tag: "le",
        modules: &[
            "scanners/bluetooth/gatt_enumerate",
            "exploits/bluetooth/ble_reconn_spoof",
            "exploits/bluetooth/sweyntooth",
            "exploits/bluetooth/injectable",
            "exploits/bluetooth/invalid_curve",
        ],
        rationale: "BLE device — reconnect spoofing, LL fuzzing, SMP curve checks",
    },
    MatrixRow {
        class_tag: "le-pairing-mode-observed",
        modules: &["exploits/bluetooth/smp_invalid_curve"],
        rationale: "LE pairing-mode observed — SMP invalid-curve probe (LE Secure Connections)",
    },
    MatrixRow {
        class_tag: "classic-computing",
        modules: &[
            "scanners/bluetooth/classic_scan",
            "exploits/bluetooth/blueborne_l2cap",
            "exploits/bluetooth/bluefrag",
            "exploits/bluetooth/bleedingtooth",
        ],
        rationale: "Computing device — stack-specific RCE/DoS probes (BlueBorne/BlueFrag/BlueZ)",
    },
    MatrixRow {
        class_tag: "l2cap-config-anomaly",
        modules: &["exploits/bluetooth/bleedingtooth_full"],
        rationale: "L2CAP config-response anomaly — BleedingTooth RCE class",
    },
    MatrixRow {
        class_tag: "gatt-server",
        modules: &[
            "scanners/bluetooth/gatt_enumerate",
            "exploits/bluetooth/bleedingbit",
        ],
        rationale: "GATT server — BleedingBit advert/OTA fingerprinting",
    },
    MatrixRow {
        class_tag: "mesh",
        modules: &[
            "scanners/bluetooth/ble_scan",
            "exploits/bluetooth/mesh_authvalue",
        ],
        rationale: "Mesh proxy — AuthValue/provisioning probing",
    },
    MatrixRow {
        class_tag: "findmy-target",
        modules: &["exploits/bluetooth/findmy_clone"],
        rationale: "Apple Find My detected — Find My clone / token replay",
    },
    MatrixRow {
        class_tag: "airoha-detected",
        modules: &["exploits/bluetooth/airoha_rce"],
        rationale: "Airoha / MediaTek vendor detected — RCE primitives (CVE-2024-47875/-21743)",
    },
];

/// Recommend modules for a device's class tags (deduplicated, ordered).
pub fn recommend(classes: &[&str]) -> (Vec<&'static str>, Vec<&'static str>) {
    let mut modules: Vec<&'static str> = Vec::new();
    let mut rationale: Vec<&'static str> = Vec::new();
    for row in MATRIX {
        if classes.contains(&row.class_tag) {
            for m in row.modules {
                if !modules.contains(m) {
                    modules.push(m);
                }
            }
            rationale.push(row.rationale);
        }
    }
    (modules, rationale)
}

/// All module paths mentioned by the matrix.
pub fn all_modules() -> Vec<&'static str> {
    let mut out = Vec::new();
    for row in MATRIX {
        for m in row.modules {
            if !out.contains(m) {
                out.push(m);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fastpair_chain_recommended() {
        let (mods, rationale) = recommend(&["fastpair"]);
        assert!(mods.contains(&"exploits/bluetooth/wpair"));
        assert_eq!(mods.first(), Some(&"scanners/bluetooth/ble_scan"));
        assert!(!rationale.is_empty());
    }

    #[test]
    fn no_duplicate_modules() {
        let mods = all_modules();
        for (i, m) in mods.iter().enumerate() {
            assert!(!mods[..i].contains(m), "duplicate {m}");
        }
    }

    #[test]
    fn unknown_class_is_empty() {
        let (mods, _) = recommend(&["nonexistent"]);
        assert!(mods.is_empty());
    }
}

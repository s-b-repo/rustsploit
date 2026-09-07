# Bluetooth Framework

Rustsploit's Bluetooth stack: one binary (`rustsploit`) exposing ~26 Bluetooth
modules — 3 scanners, 21 exploits, 2 credential modules — through its four
interfaces (interactive shell, CLI runner, PQ-encrypted REST/WebSocket API,
MCP server), all converging on the same `commands::run_module` → `scheduler::run`
dispatch path. Everything below is compiled behind the **`bluetooth` feature**
(on by default; `cargo build --no-default-features` drops it, e.g. for
headless builds without `libdbus-1-dev`).

> ⚠️ **Ethics & legal**: Bluetooth modules are for **authorized testing only** —
> obtain explicit written permission before touching hardware you do not own.
> The active crash/fuzz modes called out in the [Ethics](#ethics--legal) section
> below are destructive and may permanently disrupt the target device.

---

## Hardware tiers

Not every module needs the same hardware. Three tiers, in decreasing order of
capability:

| Tier | What it uses | Requirements | Modules |
|------|-------------|--------------|---------|
| **BLE scan / GATT** | `btleplug` (BlueZ backend) | Any BLE-capable adapter; no root needed beyond what BlueZ requires | `ble_scan`, `gatt_enumerate`, `ble_reconn_spoof`, `wpair`, `invalid_curve` (FP path), `mesh_authvalue` |
| **Raw HCI / L2CAP** | `AF_BLUETOOTH`/`BTPROTO_HCI` sockets + L2CAP sockets (Linux only) | Linux, root or `CAP_NET_RAW`, a BR/EDR-capable adapter. **BlueZ should release the controller** (stop the service or dedicate an adapter) for user-channel / exclusive use | `classic_scan` (raw inquiry + SDP), `l2cap_probe`, `knob_probe`, `bias` (live), `mode_confusion`, `passkey_impersonation`, `classic_pin`, `hid_injection`, `fp_rogue_beacon`, `blueborne_l2cap`, `bluefrag`, `bleedingtooth`, `braktooth` (L2CAP fuzzer), `sweyntooth` (DTM) |
| **Capture analysis** | btsnoop files on disk | No radio at all — offline | `bias` (capture mode), `bluffs`, `injectable`, `le_legacy_crack`, `mesh_authvalue` (wordlist phase) |

Caveats from the code:

- When BlueZ owns the controller, raw-HCI modules can interfere with it.
  `fp_rogue_beacon`'s notes say it plainly: stop the BlueZ service or dedicate
  an adapter (`setg adapter <n>`) for exclusive user-channel use.
- Air-level LMP injection (full BrakTooth LMP fuzzing, true InjectaBLE
  injection, the BIAS/BLUFFS active MITM relay, SweynTooth over-the-air) needs
  a vendor-capable or SweynTooth-capable radio (nRF52/ESP32 class); the
  Rustsploit engines natively generate the corpora and run the L2CAP-side
  attacks.

---

## Architecture — `src/bluetooth/` core layer

Every Bluetooth module is built on this layer:

| File | Responsibility |
|------|----------------|
| `mod.rs` | Shared core: `BtDevice` model + classification helpers, `resolve_target_mac` (reads `setg target_mac`), re-exports of the submodules |
| `adapter.rs` | Local adapter enumeration/selection/power via btleplug; consumes `adapter` (alias `wpair_adapter`) and `scan_secs` global options |
| `discovery.rs` | Unified discovery (BLE adverts + Classic inquiry) and the advert classifier: Google Fast Pair (0xFE2C), Apple Find My, iBeacon, Microsoft Swift Pair, Mesh Proxy, HID-over-GATT; `merge` de-duplication |
| `gatt_client.rs` | btleplug GATT plumbing: connect with retry + per-attempt timeout (`wpair_retries`/`wpair_retry_ms`), characteristic lookup, read/write, write-then-await-notification for Fast Pair request/response |
| `fastpair/mod.rs` | Umbrella for the Google Fast Pair (service 0xFE2C) primitives shared by wpair, the rogue beacon and the invalid-curve probe |
| `fastpair/crypto.rs` | Fast Pair Key-Based Pairing crypto (CVE-2025-36911 / WhisperPair, KU Leuven COSIC): secp256r1 ECDH, AES-128-ECB, HMAC, AES-CTR |
| `fastpair/db.rs` | Model-ID → device database (KU Leuven COSIC WhisperPair dataset, ~2,900 models embedded at compile time), Anti-Spoofing key resolution (global option / metadata URL / local cache at `~/.rustsploit/wpair_keys`) |
| `fastpair/protocol.rs` | Key-Based Pairing message construction: 16-byte request block `[type][flags][addr 6B][salt 8B]`, verified against the Fast Pair spec and public reference PoCs |
| `classic.rs` | BR/EDR discovery, pairing and transport over BlueZ D-Bus (`Adapter1.StartDiscovery`, `Device1.Pair`/`Connect` with explicit cancellation); object-path resolution |
| `hci.rs` | Raw HCI socket (Linux, root/CAP_NET_RAW): classic inquiry, connection creation, remote name, `HCI_Read_Encryption_Key_Size` (KNOB), event parsing, `L2capChannel` |
| `sdp.rs` | Minimal native SDP client over L2CAP PSM 1 — `ServiceSearchAttribute` transaction, no `sdptool` dependency |
| `lmp.rs` | LMP and L2CAP wire codecs (pure Rust, offline-testable; parse functions never panic on malformed input) — used by KNOB/BIAS/BLUFFS/BrakTooth and the L2CAP probes |
| `ll.rs` | BLE link-layer packet codecs (advert PDUs, LL control) used by the SweynTooth/InjectaBLE engines; offline-testable |
| `btsnoop.rs` | btsnoop capture parser (Android HCI snoop / `btmon -w`): header + records; also extracts SMP Pairing Confirm/Random PDUs |
| `crypto_extra.rs` | Shared crypto: AES-CMAC (RFC 4493 over the `aes` crate), `s1`/`ah`, and the SMP `c1` confirm generator for the TK cracker |
| `inventory.rs` | Persistent device inventory — JSON under `~/.rustsploit/bluetooth_inventory.json`; every record carries the classification hints the attack matrix keys off |
| `matrix.rs` | Attack matrix: device class tag → ordered module recommendations (recon → probes → exploits); consumed by `blueforge` |

---

## Module catalog

### Scanners (`Category::Scanners`)

| Path | Name | Summary |
|------|------|---------|
| `scanners/bluetooth/ble_scan` | BLE Scan & Classifier | LE reconnaissance: scans the selected adapter, classifies every advertisement (Fast Pair 0xFE2C, Apple Find My, iBeacon, Microsoft Swift Pair, Mesh Proxy, HID-over-GATT) and persists devices into the engagement inventory. Classification feeds the blueforge attack matrix. |
| `scanners/bluetooth/gatt_enumerate` | GATT Enumerator | Connects to a BLE target and dumps its full GATT surface: services, characteristics, properties and handles. Performs safe bounded reads of every readable characteristic and flags writable ones — the write surface BLESA/whisper-class exploits abuse. |
| `scanners/bluetooth/classic_scan` | Classic (BR/EDR) Scanner + SDP | Runs a BlueZ discovery window (D-Bus) and/or raw HCI inquiry, resolves friendly names, optionally browses each target's SDP records natively over L2CAP PSM 1 (SPP/A2DP/HID/…). Feeds the classic attack chain (KNOB/BIAS/BLUFFS/L2CAP). Requires Linux + BR/EDR adapter; SDP browsing needs root. |

### Exploits (`Category::Exploits`)

| Path | Name | CVE(s) | Summary |
|------|------|--------|---------|
| `exploits/bluetooth/blueforge` | Blueforge — Bluetooth Framework Umbrella | — | Interactive umbrella console: unified discovery (BLE + Classic), persistent inventory, classification, and the attack matrix driving every Bluetooth module against each target. REPL commands: `scan`, `list`, `info <mac>`, `select <mac>`, `matrix`, `run <module>`, `clear`, `help`. |
| `exploits/bluetooth/wpair` | WPair — Fast Pair Exploit (WhisperPair) | CVE-2025-36911 | Interactive Fast Pair pairing-mode-bypass: discovers Fast Pair accessories (0xFE2C), performs the secp256r1 ECDH Key-Based Pairing handshake against the Anti-Spoofing key to force-pair out of pairing mode, with nonce-replay and invalid-curve conformance tests. Commands: `scan`, `info`, `exploit`, `exploitall`, `testall`, `nonce`, `curve`, `pair`, `rename`, `switch`, `harvest`. |
| `exploits/bluetooth/knob_probe` | KNOB — Key Entropy Probe | CVE-2019-9506 | Completes a Classic ACL connection and reads negotiated link-key entropy via `HCI_Read_Encryption_Key_Size`. Links pairing with key sizes below 7 bytes accept the KNOB LMP entropy downgrade — an active MITM can brute-force the key. Requires Linux + root. |
| `exploits/bluetooth/bias` | BIAS — Impersonation Analysis | CVE-2020-10135 | Live mode (raw HCI, root): authenticates and classifies the resulting link-key type — unauthenticated keys where authenticated bonds are expected indicate BIAS exposure. Capture mode (`setg bt_capture=…`): parses an HCI snoop log for link-key/encryption downgrades. Detection plane; full MITM needs a second radio. |
| `exploits/bluetooth/bluffs` | BLUFFS — Session Key Analysis | CVE-2023-24023 | Analyzes btsnoop captures for reused L2CAP signalling nonces, missing connection-id binding, and key-agreement without MITM protection. Feeds the offline portion of BLUFFS; the active relay requires a second radio. |
| `exploits/bluetooth/ctkd_probe` | BLURtooth — CTKD Probe | CVE-2020-15802 | Cross-Transport Key Derivation exposure: enumerates a dual-mode device's transports, pairing state and profile surface via BlueZ and reports whether both transports are bonded with weaker-transport indicators (key overwrite via the weaker transport). |
| `exploits/bluetooth/ble_reconn_spoof` | BLESA — Reconnection Spoofing Probe | CVE-2020-9770 | Tests whether a BLE device accepts unauthenticated writes after reconnection (BLESA: reconnected clients fail to re-verify the server, servers fail to enforce security levels). Probes writable characteristics without bonding and watches advertising for reconnection windows. |
| `exploits/bluetooth/invalid_curve` | Invalid Curve Probe — CVE-2018-5383 class | CVE-2018-5383 | Point-validation weakness: sends an off-curve ephemeral public key inside the Fast Pair Key-Based Pairing payload (acceptance = no ECDH point validation) and generates malformed SMP Pairing Public Key PDUs for offline curve-membership verification. Shares the engine behind wpair §4.5. |
| `exploits/bluetooth/bleedingbit` | BleedingBit — TI CC2640 Probe | CVE-2018-7080, CVE-2018-16986 | Detects TI OTA service adverts (unauthenticated OTA code load) on CC2640-series radios (LED fixtures, medical devices); can flood crafted TI vendor adverts (RCE via advert length overflow) — opt-in via `bleedingbit_flood=1`. |
| `exploits/bluetooth/blueborne_l2cap` | BlueBorne BNEP Probe | CVE-2017-0781, CVE-2017-0785 | Phase 1 fingerprints BNEP reachability; Phase 2 (`blueborne_payload=1`) sends a crafted BNEP Setup Connection Request with oversized UUID/extension lengths — vulnerable stacks (Android 4.4.4–7.0, ancient Linux) crash or drop the link. **Active crash PoC — destructive.** |
| `exploits/bluetooth/bluefrag` | BlueFrag — Android L2CAP PoC | CVE-2020-0022 | L2CAP first-fragment length confusion on Android 8.x/9.x: a Basic Mode frame whose declared length exceeds the first ACL fragment triggers an out-of-bounds write — remote crash on most builds, RCE-class on 8.0–8.1. Active PoC via `bluefrag_payload=1`. **Payload mode is destructive.** |
| `exploits/bluetooth/bleedingtooth` | BleedingTooth — BlueZ Probe | CVE-2020-12351, CVE-2020-12352, CVE-2020-24490 | Probes Linux BlueZ for type confusion via L2CAP config (remote kernel DoS), A2MP info leak, and extended-advertising HCI event overflow; sends a malformed Configuration Request with a zero-length MTU option and observes the link. |
| `exploits/bluetooth/injectable` | InjectaBLE — Connection Injection Analysis | CVE-2021-31615 | btsnoop analysis: reconstructs LE connection establishment, measures the CONNECT_IND → encryption-setup window and flags connections whose early state accepts injected LL control traffic. Active injection needs a real-time LL-capable radio; corpus + indicators are exported. |
| `exploits/bluetooth/mode_confusion` | Pairing Method Downgrade Probe | CVE-2020-10134, CVE-2020-25836/-25837 | Drives the SSP pairing exchange with NoInputNoOutput IO capability and MITM protection off; devices completing Just-Works or legacy PIN pairing where a protected method was expected are exposed to pairing-mode confusion / downgrade impersonation. |
| `exploits/bluetooth/passkey_impersonation` | Passkey Entry Impersonation Probe | CVE-2021-37577 | Exercises the BR/EDR passkey-entry path: opens an ACL link, answers the IO-capability exchange keyboard-only and replies to the passkey request with the dictionary value (`bt_passkey`). Single-guessable passkeys = passkey-entry impersonation exposure. |
| `exploits/bluetooth/mesh_authvalue` | Mesh AuthValue Probe | CVE-2020-26559 | Scans for Mesh Proxy / unprovisioned-device beacons (0x1828/0x182C, AD type 0x2B), extracts device UUIDs + OOB info, then runs an offline confirmation-value dictionary attack against a capture's provisioning random/confirm pair. Weak/absent AuthValues let an attacker complete provisioning. |
| `exploits/bluetooth/hid_injection` | Bluetooth HID Injection | CVE-2023-45866 | Emulates a Bluetooth keyboard against hosts that accept unauthenticated HID pairing and auto-trust input devices: advertises HID-over-GATT (0x1812) via raw HCI and injects keystrokes through `uhid` once a host subscribes. Fixed benign `RUSTSPLOIT` marker payload. Test your own hosts only. |
| `exploits/bluetooth/l2cap_probe` | L2CAP Surface Probe | — | Enumerates reachable L2CAP PSms on a Classic target (SDP, RFCOMM, HID, AVDTP, BNEP + dynamic range) and fingerprints the stack from accept/refuse/security-block behaviour — the entry surface for BlueBorne/BlueFrag-class attacks. |
| `exploits/bluetooth/braktooth` | BrakTooth — LMP/L2CAP Fuzzer | — (BrakTooth toolkit) | Generates the BrakTooth LMP fuzz corpus (host-connection floods, malformed extended-features, AES-CFB, truncated PDUs) and drives an L2CAP signalling fuzzer against reachable PSMs. Air-level LMP injection needs a vendor-capable controller. **Fuzzing is destructive.** |
| `exploits/bluetooth/sweyntooth` | SweynTooth — BLE LL DoS Engine | — | Generates the SweynTooth LL control corpus (LL_PING floods, malformed DLE negotiation, degenerate connection-update, all-zero channel-map PDUs) for export to nRF52/ESP32-class radios. DTM mode (`sweyntooth_dtm=1`, root) exercises the **local** controller directly. |
| `exploits/bluetooth/fp_rogue_beacon` | Fast Pair Rogue Beacon | — | Advertises a spoofed Google Fast Pair provider (0xFE2C) with an operator-chosen model ID (pairing-mode or SteadyState/account-key-filter form) and counts any Seeker that connects to the lure. For lure research, client fingerprinting and pairing DoS. |

### Credentials (`Category::Creds`)

| Path | Name | Summary |
|------|------|---------|
| `creds/bluetooth/classic_pin` | Classic Legacy PIN Bruteforce | Dictionary attack on Classic legacy pairing: opens an ACL link, answers each `PIN_Code_Request` with the next candidate from `pin_wordlist` (default: 4–6 digit PINs such as `0000`/`1234`) and watches for `Link_Key_Notification` vs `Authentication_Failure`. Requires Linux + root. |
| `creds/bluetooth/le_legacy_crack` | LE Legacy Pairing TK Cracker | Offline dictionary attack on the LE legacy-pairing Temporal Key: parses a btsnoop capture, extracts SMP Pairing Confirm/Random + Pres/Preq/address bytes and recomputes `c1 = AES-CMAC(TK, …)` for every candidate TK (6-digit passkeys by default, `tk_wordlist` for custom lists). Pure offline crypto — no radio. |

---

## Global options (`setg`)

Bluetooth reads its inputs through the global options with the fixed
precedence `custom_prompts` → run-context target → global options → stdin.
All keys below live in the free-form `setg` store persisted to
`~/.rustsploit/global_options.json`.

| Key | Consumer(s) | Example | Notes |
|-----|-------------|---------|-------|
| `adapter` | every btleplug/HCI radio module (via `adapter::adapter_index`) | `setg adapter 1` | 0-based index; alias `wpair_adapter`; default 0 |
| `scan_secs` | `ble_scan`, `classic_scan`, blueforge scans | `setg scan_secs 30` | default 15, clamped 3–300 |
| `target_mac` | all targeted modules (via `resolve_target_mac`) | `setg target_mac AA:BB:CC:DD:EE:FF` | also settable per-run via `set target` |
| `model_id` | `wpair` | `setg model_id 0x0582FD` | hex by convention; bare hex/decimal accepted; malformed values are warned, never ignored silently |
| `antispoofing_key` | `wpair` (via `fastpair/db`) | `setg antispoofing_key <base64>` | overrides DB/metadata lookup of the provider's Anti-Spoofing public key |
| `gfp_metadata_url` | `wpair` (via `fastpair/db`) | `setg gfp_metadata_url https://…/?ids={}` | metadata-fetch template for model-ID → key resolution |
| `gfp_api_key` | `wpair` (via `fastpair/db`) | `setg gfp_api_key <key>` | API key for the metadata endpoint |
| `wpair_retries` | every btleplug GATT connect (via `gatt_client`) | `setg wpair_retries 5` | default 3 |
| `wpair_retry_ms` | every btleplug GATT connect (via `gatt_client`) | `setg wpair_retry_ms 800` | default 400 |
| `wpair_harvest_delay_ms` | `wpair` (harvest step) | `setg wpair_harvest_delay_ms 500` | delay between harvest writes |
| `rogue_model_id` | `fp_rogue_beacon` | `setg rogue_model_id 0x00070E` | 3-byte model ID advertised by the lure |
| `rogue_steady` | `fp_rogue_beacon` | `setg rogue_steady 1` | SteadyState (account-key filter) advert form |
| `bleedingbit_flood` | `bleedingbit` | `setg bleedingbit_flood 1` | enables the CVE-2018-16986 crafted-advert flood (active/destructive) |
| `blueborne_payload` | `blueborne_l2cap` | `setg blueborne_payload 1` | enables Phase 2 malformed BNEP payload (active crash PoC) |
| `bluefrag_payload` | `bluefrag` | `setg bluefrag_payload 1` | enables the active OOB-write PoC frame |
| `bt_capture` | `bias` (capture mode), `bluffs`, `injectable`, `le_legacy_crack` | `setg bt_capture /tmp/hci_snoop.btsnoop` | path to a btsnoop/`btmon -w` capture |
| `bt_passkey` | `passkey_impersonation` | `setg bt_passkey 123456` | passkey guessed during entry; default `123456` |
| `pin_wordlist` | `classic_pin` | `setg pin_wordlist /usr/share/wordlists/pins.txt` | default: built-in 4–6 digit list |
| `tk_wordlist` | `le_legacy_crack` | `setg tk_wordlist /usr/share/wordlists/tks.txt` | default: 6-digit passkey space |
| `mesh_capture` | `mesh_authvalue` | `setg mesh_capture /tmp/provision.btsnoop` | capture holding provisioning random/confirm pair |
| `mesh_authwordlist` | `mesh_authvalue` | `setg mesh_authwordlist /tmp/authvalues.txt` | AuthValue candidate list |
| `sdp_browse` | `classic_scan` | `setg sdp_browse 1` | enables native SDP browsing (root) |
| `sweyntooth_dtm` | `sweyntooth` | `setg sweyntooth_dtm 1` | DTM mode against the local controller (root) |

---

## Quick starts

### 1) Blueforge umbrella session (recommended entry point)

```
setg adapter 0
setg scan_secs 30
use exploits/bluetooth/blueforge
run                      # enters the REPL
scan                     # unified BLE + Classic discovery, inventory + classification
list                     # known devices
info AA:BB:CC:DD:EE:FF   # per-device class tags + inventory record
select AA:BB:CC:DD:EE:FF
matrix                   # recommended module order for the selected device
run exploits/bluetooth/knob_probe
```

### 2) WPair (Fast Pair / WhisperPair) session

```
use exploits/bluetooth/wpair
run                       # interactive REPL
scan                      # discover Fast Pair providers (0xFE2C)
info <mac>                # model lookup via the COSIC dataset
exploit <mac>             # Key-Based Pairing handshake vs Anti-Spoofing key
nonce                     # nonce-reuse / replay conformance test
curve                     # invalid-curve (point validation) conformance test
harvest                   # post-pairing harvest (see wpair_harvest_delay_ms)
```

Key options: `model_id`, `antispoofing_key`, `gfp_metadata_url`, `gfp_api_key`.

### 3) Classic chain (recon → surface → entropy)

```
use scanners/bluetooth/classic_scan
setg sdp_browse 1
run -t AA:BB:CC:DD:EE:FF          # discovery + names + SDP records (root)

use exploits/bluetooth/l2cap_probe
run -t AA:BB:CC:DD:EE:FF          # reachable PSms + stack fingerprint

use exploits/bluetooth/knob_probe
run -t AA:BB:CC:DD:EE:FF          # HCI_Read_Encryption_Key_Size; key < 7 bytes = KNOB exposure
```

Follow-ups: `bias` (live link-key classification), `mode_confusion`, `passkey_impersonation`,
`ctkd_probe`.

### 4) Offline capture analysis (no radio)

Grab an HCI snoop capture (Android developer options → Bluetooth HCI snoop
log, or `btmon -w`), then:

```
setg bt_capture /path/to/capture.btsnoop
use exploits/bluetooth/bias ; run            # link-key / encryption downgrade indicators
use exploits/bluetooth/bluffs                # session-key negotiation weaknesses (CVE-2023-24023)
use exploits/bluetooth/injectable            # InjectaBLE injectability window (CVE-2021-31615)
use creds/bluetooth/le_legacy_crack          # offline TK dictionary attack (c1 recomputation)
```

---

## Ethics & legal

Rustsploit is intended for **authorized security testing and research only**.
Always obtain explicit written permission before targeting any system or
device you do not own.

Some Bluetooth modules are **destructive by design** — they send malformed
traffic that crashes or permanently disrupts the target. These must only ever
run against devices you own or are explicitly authorized to test:

- `exploits/bluetooth/blueborne_l2cap` with `blueborne_payload=1` (crash PoC)
- `exploits/bluetooth/bluefrag` with `bluefrag_payload=1` (OOB-write PoC — RCE-class payload on some builds)
- `exploits/bluetooth/braktooth` fuzzing (LMP/L2CAP storm)
- `sweyntooth` DTM mode (`sweyntooth_dtm=1`)

Active third-party-device effects also apply to `bleedingbit` with
`bleedingbit_flood=1` and `hid_injection` (keystroke injection — test your own
hosts only). Passive scanners and offline capture analyzers are non-destructive.

**No liability**: the authors accept no responsibility for misuse or damage.
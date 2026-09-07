rustsploit 0.5.1 — Changelog
============================

This release addresses every item from todo.txt and bugs.txt, plus
extensive audit-driven hardening against BAD_PATTERNS.md violations.

Framework — Scheduler (src/scheduler.rs)
-----------------------------------------

- random scan max_random_hosts now auto-bumps to full public IPv4 count
  when the operator hasn't explicitly set a non-default value. Previously
  the 10k factory default was used unless the key was completely absent
  from global_options; a persisted 10k from a prior session would also
  block the auto-bump. Now both paths resolve correctly.

- Live per-IP hit reporting during mass scans. Every finding (vulnerability,
  credential, open port, banner, note) is printed immediately as it's
  discovered by a spawned task — the operator sees results in real time
  instead of only at the final summary. Implemented via new
  record_and_report() method on ScanStats; all four fan-out paths
  (fanout_cidr, fanout_file, fanout_random, fanout_sequential) updated.

- setg block_internal toggle. Operators can now disable RFC1918/bogon/
  Cloudflare exclusions with `setg block_internal off`. Only changeable
  from the interactive shell (not API/MCP/scripts). Default: on (safe).

- Error swallowing eliminated. The live-hit match arm now explicitly
  handles all five FindingKind variants (Vulnerable, Credential, OpenPort,
  Banner, Note) instead of a catch-all `_` arm.

io_uring — Universal stream-connect (src/utils/uring_connect.rs, src/utils/network.rs)
--------------------------------------------------------------------------------------

- io_uring connect service upgraded from port-probe-only to full TCP stream
  connect. Every module's `tcp_connect_addr` / `tcp_connect_str` path now
  routes through the dedicated io_uring ring thread pool when the feature
  is enabled and no source port is configured.

- `!Send` bridge: tokio_uring::net::TcpStream can't cross threads, so the
  ring thread dup(2)s the connected fd, drops the uring stream, and returns
  a std::net::TcpStream (Send). The main runtime wraps it in tokio TcpStream.

- Ring count capped at 16 by default (peak benchmark throughput) to prevent
  oversubscription on many-core boxes. Overridable via RUSTSPLOIT_URING_RINGS.

- Self-healing: if the ring service is unavailable, every caller falls back
  to the standard tokio epoll connect path. No single point of failure.

- All 380+ modules benefit automatically — scanners, exploits, and cred
  modules all use the framework TCP wrappers.

Credential Modules — setg port honored (src/utils/creds_helper.rs)
------------------------------------------------------------------

- creds_helper::run() now reads the global `setg port` option and uses
  it as the default port instead of falling back to each module's
  hardcoded default. Fixes `setg port 2323; use creds/generic/telnet_bruteforce; run`
  silently probing port 23. All 32 cred modules benefit automatically.

Bluetooth — WPair command parsing (src/modules/exploits/bluetooth/wpair/mod.rs)
-------------------------------------------------------------------------------

- Commands typed with trailing/leading quotes (`scan'`, `"scan"`) now
  resolve correctly. The REPL strips surrounding single and double quotes
  from the command token before matching.

RTSP Bruteforce — Response parsing (src/modules/creds/generic/rtsp_bruteforce.rs)
----------------------------------------------------------------------------------

- Response line splitting now uses text.lines().next() instead of
  split("\r\n"). Some RTSP servers (especially cheap/embedded cameras)
  only send \n line endings, causing the old parser to treat the entire
  response as one line and fail to extract the status code. All 9
  credential attempts were misclassified as "Error" instead of proper
  "AuthFailed" for 404 responses.

Service Scanner — Batch mode output (src/modules/scanners/service_scanner.rs)
------------------------------------------------------------------------------

- The per-host "Scanning X ports on <target>..." message was missing its
  is_batch_mode() guard. During mass scans this line was printed once
  per host, flooding the console. Now suppressed in batch mode, consistent
  with the other five per-host messages already guarded.

New Module — Metasploit Pro CVE-2017-5242 (src/modules/exploits/frameworks/metasploit_pro/)
--------------------------------------------------------------------------------------------

- exploits/frameworks/metasploit_pro/cve_2017_5242_file_read — exploits
  the CVE-2017-5242 path-traversal vulnerability in Metasploit Pro 4.x
  (confirmed on 4.14.1, default port 3790 HTTPS). Three modes:
  1. Vulnerability check (probe endpoints for traversal support)
  2. Read a single user-specified file
  3. Run a predefined list of 25 high-value files (/etc/passwd,
     /etc/shadow, Metasploit config YAMLs, SSH keys, etc.)
  Uses reqwest with dangerous-TLS for self-signed MSF Pro certs.
  Honors prompt_only and batch_mode. Findings saved to loot/workspace.

Tommy Guide — New pages (src/tommy.rs)
--------------------------------------

- Page 17: Mass scanning — covers all five target types (0.0.0.0, CIDR,
  random, file, comma-separated), key global options, live feedback,
  and auto-save locations.

- Page 18: Exclusions & block_internal — RFC1918 defaults, toggle,
  custom exclusion lists, advisory format.

  Total pages: 22 (up from 20).

DoS Module Hardening (src/modules/exploits/dos/ — 17 modules)
--------------------------------------------------------------

- Full audit against docs/BAD_PATTERNS.md and docs/Exploit-Modules-Guide.md.
  20 bugs found, 11 fixed (all critical + moderate), 5 low-priority documented.

- prompt_only guards added to 8 modules: http_flood, slowloris, rudy,
  tcp_connection_flood, connection_exhaustion_flood, http2_rapidreset,
  apachebrpc_overflow, px4_uav_dos. Prevents DOS attacks launching during
  the scheduler's prompt-harvest dry run against placeholder targets.

- batch_mode guards added to apachebrpc_overflow, px4_uav_dos. All 17 DoS
  modules now bail with a descriptive error in mass-scan mode (DoS is
  inherently single-target).

- http2_rapidreset: removed early is_blocked_target bypass that rendered
  assert_dos_target_authorized dead code. Authorization flow now consistent
  with all other attack-only DoS modules.

- apachebrpc_overflow: attack loop now checks ctx.cancel on each iteration,
  matching cancellation discipline of all other DoS modules.

- BAD_PATTERNS violations fixed in telnet_iac_flood (A4 .unwrap_or →
  match), tcp_connection_flood (A5 .unwrap_or_else → match, D1 [0] →
  .first().context()), rudy (D2 &[..] → .get(), E1 as usize →
  try_from), px4_uav_dos (D2 &buf[10..] → .get_mut()).

- Self-healing: all DoS modules route through tcp_connect_addr → io_uring
  (when feature on, no source port). assert_dos_target_authorized checks
  every resolved IP, not just the literal target string.

Audit-Driven Hardening (per docs/BAD_PATTERNS.md and Project Docs)
------------------------------------------------------------------

Panicking error handling fixed (Section A):

  - fortios_sslvpn_heapoverflow (src/modules/exploits/network_infra/fortinet/):
    .unwrap() calls on rfind/find replaced with match-based port detection.

  - ldap_anon_spray (src/modules/exploits/windows/):
    .last().unwrap() on tmp vec replaced with .last().copied().unwrap_or(0).
    read_resp.unwrap() replaced with read_resp.map_or(true, |r| r.is_err()).

  - h3c_redfish_config_dump (src/modules/exploits/frameworks/h3c_bmc/):
    Three .parse().unwrap() on HeaderValue replaced with .parse().context(..)?

Error swallowing fixed (Section B):

  - cookie_dos (snare), tapestry_fileread (webapps), php_unrestricted_upload_rce:
    Multiple Err(_) => {} anonymous drops replaced with tracing::debug! or
    proper error propagation per BAD_PATTERNS.md B1.

  - Codebase-wide error-handling hardening: 45+ sites across 25+ files fixed.
    All `Err(_) => continue/{}`, `let _ = <Result>`, `Err(_timeout)`, and
    `Err(_ident)` patterns replaced with explicit error binding and
    `tracing::debug!` logging. Every error now self-documents what failed.

  - Critical error-swallowing bugs fixed:
    * proxy_bruteforce: credentials literally never sent (`***` not `{}`)
    * cowrie modules: `std::thread::sleep` → `tokio::time::sleep` (F1)
    * git_exposure_rce, mantisbt_exec: `.unwrap_or_default()` HTTP body
      → `match` with `tracing::warn!`
    * avtech_camera: poisoned Mutex recovery via `into_inner()`
    * langflow_rce: UB pointer cast replaced with safe self-hash
    * m365_activesync_spray: semaphore `.ok()?` → logged error
    * ssh_spray: `.parse().unwrap_or()` port swallow → logged warning

  - Framework-bypassing connects fixed:
    * ldap_anon_spray: 4× raw `TcpStream::connect` → `tcp_connect_str`
    * routeros_jailbreak: raw connect + `.ok()?.ok()?` → `tcp_connect_str`
    * ZTE ZXV10: raw `Client::builder()` → `build_http_client_with`
    * camxploit: raw `Client::builder()` → `build_http_client`

  - Lint suppression removed: 3 `#[allow(unused_imports)]` in ldap_anon_spray

Module conventions enforced (per docs/Module-Development.md, Exploit-Modules-Guide.md):

  - All new and fixed modules use native shape (run(ctx) -> Result<ModuleOutcome>)
  - prompt_only guard present where cfg_prompt_* is called before network work
  - is_batch_mode() guards on per-host display output
  - Framework network wrappers used (no raw TcpStream::connect)
  - Target-specific filenames for output files
  - Findings routed through ModuleOutcome rather than direct cred_store calls

Verification
------------

All changes pass `cargo check` with zero new warnings.
BAD_PATTERNS audit on modules reduced from 110 Section-A hits to 0 critical unwrap/expect.

================================================================================
v0.5.1 (2026-09-07) — Bluetooth expansion + framework module audit
================================================================================

This patch-level release lands the full Bluetooth exploitation expansion
(BT-1 through BT-4) and a framework-wide module audit that fixed 128 modules
across all categories. Build clean, 0 errors, 0 warnings, 0 new strict
BAD_PATTERNS violations. 468 → 477 registered modules (25 → 35 Bluetooth).

------------------------------------------------------------------
Framework module audit (128 modules touched)
------------------------------------------------------------------

A scan of every non-bluetooth module under `src/modules/{exploits,scanners,
creds,osint,post,plugins}` was performed, 128 files were touched, and every
flagged issue was resolved in place. Highlights:

* **Banned-pattern sweep** — every B (silent error swallowing), L (crypto),
  M (injection), N (UB) violation in the touched scope is gone. The strict
  audit reports 0 critical hits on the changed files. The remaining
  pre-existing hits across the whole tree are indexed-indexing, as-casts
  in protocol parsers, and test-only expects (all allowed per CLAUDE.md).
* **`get_or<T>()` Display bound** (`src/module.rs`) — the option-resolver
  no longer silently drops parse errors when `T::Err` lacks Display. Now
  the offending value, expected type, and parse error are all surfaced
  via `tracing::warn!`.
* **Jenkins CVE-ID rename** — `jenkins_args4j_rce_cve_2024_24549` →
  `jenkins_args4j_rce_cve_2024_23897` (the real CVE; the 24549 ID was a
  duplicate). Module file, `mod.rs`, and the vuln_checker mapping all
  updated in lockstep.
* **Module-path renames and tidies** — `module.rs` and `inventory.rs` got
  a Display-bounded error path; `wpair/mod.rs` got a sane B/L pass.
* **Catalog regen** — `docs/Module-Catalog.md` regenerated from the live
  `inventory` registry (468 entries).

------------------------------------------------------------------
Bluetooth (BT-1: foundational codecs — 2,804 LOC, `src/bluetooth/`)
------------------------------------------------------------------

Eight new protocol-stack codecs land on top of the existing `L2capChannel`
and `HciSocket` primitives. Every codec is `#[cfg(feature = "bluetooth")]`-
gated and offline-testable where possible.

| File                | LOC | Purpose                                                                |
|---------------------|-----|------------------------------------------------------------------------|
| `rfcomm.rs`         | 532 | RFCOMM 1.2 UIH/SABM/UA/DISC/PN/MSC/RPN/RLS codec + async `RfcommSession` |
| `obex.rs`           | 446 | OBEX 1.5 client (Connect/Put/Get/SetPath/Listing) over RFCOMM          |
| `bnep.rs`           | 397 | BNEP control + General-Ethernet encapsulation (Setup/Filter/Network)  |
| `avdtp.rs`          | 561 | AVDTP signaling + SBC codec negotiation, media-channel open           |
| `hfp.rs`            | 137 | HFP AT-command set (BRSF/CIND/CHLD/VGS/VGM/NREC/DTMF) over RFCOMM     |
| `smp.rs`            | 424 | BLE SMP + LE SC crypto (`smp_c2`, `f6`, `g2`, `h6`, `h7`) + L2CAP CID 0x0006 transport |
| `findmy.rs`         | 155 | Apple Find My advertisement encoder (Near-Owner / Separated)           |
| `airoha.rs`         | 152 | Airoha AR3011/MTK vendor HCI helpers (CVE-2024-47875 / -21743 trigger) |

LE SC crypto additions live alongside the existing `smp_c1` in
`crypto_extra.rs`; the 8-bit PSM constant `PSM_A2MP = 0x0007` was added to
`lmp.rs` for the BleedingTooth A2MP probe.

------------------------------------------------------------------
Bluetooth (BT-2: new exploit modules — 10 modules, 1,750 LOC)
------------------------------------------------------------------

| Module                       | Family / CVE                                       | Codec used              |
|------------------------------|----------------------------------------------------|-------------------------|
| `bluebug_obex`               | OBEX-FTP PUT (BlueBug class)                       | `obex` over `rfcomm`    |
| `bluesnarf_obex`             | OBEX-FTP / PBAP exfil (BlueSnarf class)            | `obex` over `rfcomm`    |
| `carwhisperer`               | HFP audio injection (CVE-2017-0785 secondary)      | `hfp` over `rfcomm`     |
| `avdtp_hijack`               | A2DP signaling hijack + media L2CAP                | `avdtp`                 |
| `findmy_clone`               | Rogue Apple Find My advertiser (AirTag clone)      | `findmy` + raw HCI      |
| `airoha_rce`                 | Airoha AR3011 / MTK vendor-diag RCE                | `airoha`                |
| `smp_invalid_curve`          | LE SC off-curve point probe (CVE-2018-5383 class)   | `smp` + `p256`          |
| `blueborne_full`             | 4-vector BlueBorne BNEP (CVE-2017-0781/-0784)      | `bnep`                  |
| `bleedingtooth_full`         | All three BleedingTooth CVEs (12351/-12352/-24490) | L2CAP + raw HCI         |
| `hid_gatt_server`            | HID-over-GATT with real Report Map (CVE-2023-45866) | uhid + raw HCI         |

------------------------------------------------------------------
Bluetooth (BT-3: bug fixes + cross-module integration — 9 tasks)
------------------------------------------------------------------

* **`le_legacy_crack` real addresses** — added `btsnoop::extract_smp_addresses`
  to pull the actual iat/ia/rat/ra out of `LE_Connection_Complete` events
  instead of using zero placeholders. The previous `&[0u8; 6]` addresses
  made the c1 brute-force effectively never succeed.
* **`ctkd_probe` active overwrite** — removed the dead `setg blur_pair_le=1`
  reference, added an actual active BLURtooth (CVE-2020-15802) probe path
  via BlueZ D-Bus that re-reads the BR/EDR link key after a fresh LE
  pairing and reports the overwrite.
* **`invalid_curve` description trimmed** — the old description overclaimed
  the LE SC SMP path; the new `smp_invalid_curve` module owns that now.
* **`mesh_authvalue` AD 0x2B parser** — implemented the missing Mesh
  Beacon (unprovisioned-device, AD type 0x2B) decoder. Captures device
  UUIDs and OOB info from mesh-beacon adverts.
* **Sweyntooth + Braktooth CVE mapping** — every corpus entry now carries
  the CVE-YYYY-NNNN it covers (CVE-2019-16336/-17061/-17519/-17520;
  CVE-2020-35500; CVE-2021-28135/-28136/-28138/-28139/-31717).
* **BlueFrag second-stage** — added the operator-driven stage-2 RCE
  payload path (`setg bluefrag_stage2`) that writes a hex-decoded
  continuation frame after the first-stage length-mismatch primitive.
* **`mode_confusion` AES-CCM downgrade** — added Phase 2 of the probe
  to detect the CVE-2022-25836 / -25837 BR/EDR AES-CCM downgrade.
* **Matrix expansion** — `src/bluetooth/matrix.rs` gained 10 new
  `MatrixRow` entries; `BtDevice::classes()` extended with OBEX / HFP /
  A2DP-sink / mesh / findmy tags so `blueforge` recommends the right
  follow-up after each finding.
* **`wpair` planted key → `inventory` sidecar → `classic_pin`** — the
  account key wpair plants on a successful exploit is now persisted to
  `inventory::record_account_key`. `classic_pin` consults the sidecar
  via `setg pin_candidate <hex>` to pre-seed the dictionary.

------------------------------------------------------------------
Bluetooth (BT-4: final fixes)
------------------------------------------------------------------

* Wrapped three pre-existing `std::fs::read_to_string` calls inside async
  fns in `tokio::task::spawn_blocking` so the runtime never blocks on
  disk I/O: `mesh_authvalue`, `le_legacy_crack`, `classic_pin`. Fixed a
  `&str → String` clone mismatch in `classic_pin::run`.
* The audit's F-pattern still flags the 7 sites, but every flagged
  call is now either in a sync fn (3 in `inventory.rs`) or already
  wrapped in `spawn_blocking` (1 in `wpair` pre-existing, 3 from this
  patch). The regex can't see through the closure boundary; the actual
  rule is satisfied.

------------------------------------------------------------------
Stats
------------------------------------------------------------------

* Modules: 468 → 477 registered (468 base + 9 new BT-2; one BT-2 module
  shares a path with a pre-existing scanner).
* Bluetooth: 25 → 35 cataloged (20 → 30 exploits, 3 scanners unchanged,
  2 creds unchanged).
* New framework code: ~3,100 LOC across 8 codec files.
* New exploit code: ~1,750 LOC across 10 exploit modules.
* Bug fixes + integration: ~500 LOC across 11 files.
* Build: `cargo build --bin rustsploit` → clean (0 errors, 0 warnings).
  Use `CARGO_BUILD_JOBS=2` on ≤ 8 GiB boxes to avoid OOM during link.
* Strict audit on the 34 BT-touched files: 0 new violations of B / C / L
  / M / N. The A / D / E / F hits are test-only, protocol-parser indexing,
  numeric casts, and audit false-positives of the same shape used in
  every existing codec (`sdp.rs`, `lmp.rs`, `ll.rs`).
* `check-docs`: clean (108 links resolve, no banned tokens, full coverage).


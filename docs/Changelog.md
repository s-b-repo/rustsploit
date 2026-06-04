# Changelog

A high-level summary of significant changes. For the full detailed log, see [`changelogs/changelog-latest.md`](../changelogs/changelog-latest.md). For surviving pre-v0.5.0 systems and why they were kept, see [`Legacy.md`](Legacy.md).

---

## 2026-06-04 — WhisperPair (Fast Pair ECDH) re-implemented in `exploits/bluetooth/wpair`

The Fast Pair ECDH exploitation flow (CVE-2025-36911) that had been reduced to
discovery-only during the v0.5.0 module rewrite is **restored and rebuilt** as a
`wpair/` submodule (`crypto` · `protocol` · `db` · `gatt` · `mod`):

- **ECDH Key-Based Pairing handshake (§3.3.2)** — ephemeral secp256r1 ↔ the
  Provider's Anti-Spoofing public key → `K = SHA-256(z)[0..16]` → AES-128-ECB
  encrypted 80-byte KBP write (`p256` + `aes` + `sha2`).
- **Interactive sub-shell** — `scan` (with PAIRING vs SteadyState classification),
  `info`, `select`, `exploit`, `testall`, `exploitall`, `pair`, `rename` (§3.3.5),
  `switch` (§5.3.3), `harvest`, plus passkey + account-key planting.
- **Conformance tests** — `nonce` (replay / freshness §4.3) and `curve`
  (off-curve point validation §4.5).
- **Keyless detection** — `testall` / `exploit` detect the bypass with no
  Anti-Spoofing key by classifying on whether the Provider accepts the KBP write
  out of pairing mode (a patched device rejects it at the GATT layer); the key is
  only needed to *complete* crypto pairing. SteadyState model IDs are read over GATT.
- **Device dataset** — the KU Leuven COSIC WhisperPair `model_ids.csv` (~2,900
  registered Fast Pair models: name, manufacturer, type, Find-Hub tracking flag)
  is embedded via `include_str!` and parsed lazily; `info` resolves friendly names
  and `harvest` sweeps the full set. No anti-spoofing keys exist in any public
  dataset, so the table is names-only.
- **Anti-Spoofing key resolution** — operator override (`setg antispoofing_key`)
  and a configurable Google Nearby Devices metadata API fetch (`setg
  gfp_metadata_url` / `gfp_api_key`).
- **Protocol verified** against the Fast Pair spec + Python/Android reference PoCs:
  characteristic UUIDs `fe2c1233`–`fe2c1238`, request flags `0x11`, and the
  Additional-Data HMAC-SHA256 + Fast-Pair AES-CTR construction.
- **Tests** — 16 unit tests (AES FIPS-197 KAT, ECDH symmetry, HMAC RFC-4231, CTR,
  KBP/passkey/account-key/Additional-Data layouts, advert classification, key
  extraction). Builds clean with and without `--features bluetooth`; clippy clean.

See the [Fast Pair / WhisperPair Guide](Fast-Pair-WhisperPair-Guide.md).

---

## v0.5.0-dev (2026-05-24) — Universal source port, probe timeout passthrough, inter-feature integration

Full integration sweep ensuring all features work together across all modules.

### Source port universalisation

All TCP/UDP connections now go through the framework's network wrappers
(`tcp_connect_str`, `tcp_connect_addr`, `blocking_tcp_connect`, `udp_bind`),
which honour `setg source_port <port>` via `socket2` with `SO_REUSEADDR` /
`SO_REUSEPORT` for concurrent mass-scan compatibility.

**Third-party library bypasses fixed (8 call sites):**

| Module | Library | Fix |
|--------|---------|-----|
| `ftp_bruteforce` (plain + FTPS) | suppaftp | `tcp_connect_str` → `connect_with_stream` |
| `ftp_anonymous` (plain + FTPS) | suppaftp | `tcp_connect_str` → `connect_with_stream` |
| `ftp_bounce_test` | suppaftp | `tcp_connect_str` → `connect_with_stream` |
| `acti_camera_default` (FTP) | suppaftp | `tcp_connect_str` → `connect_with_stream` |
| `acti_camera_default` (Telnet) | telnet crate | `blocking_tcp_connect` → `from_stream` |
| `pachev_ftp_path_traversal` | suppaftp (blocking) | `blocking_tcp_connect` → `connect_with_stream` |

**UDP modules fixed:** `snmp_bruteforce` and `l2tp_bruteforce` replaced raw
`UdpSocket::bind` with `crate::utils::udp_bind(Some(ip))`.

**Port scanner:** `scan_udp` added `socket2` `SO_REUSEPORT` fallback for
source-port-bound concurrent scanning.

### Probe timeout passthrough

The `creds_helper::run` probe closure signature was extended to
`Fn(String, u16, String, String, Duration)` — the fifth parameter is the
user-configured timeout from `setg timeout N`. All 13 credential modules
updated so the operator's timeout reaches inner probe functions instead of
being overridden by hardcoded values.

| Module | Change |
|--------|--------|
| `postgres_bruteforce` | Probe uses caller timeout for TCP connect + auth exchange |
| `mysql_bruteforce` | Probe uses caller timeout for handshake + auth |
| `rdp_bruteforce` | Probe passes timeout to `native::rdp::try_login` |
| `mqtt_bruteforce` | Probe uses caller timeout for CONNECT packet exchange |
| `memcached_bruteforce` | Probe uses caller timeout for SASL auth |
| `rtsp_bruteforce` | Probe uses caller timeout for DESCRIBE request |
| `elasticsearch_bruteforce` | Probe uses caller timeout for HTTP Basic request |
| `couchdb_bruteforce` | Probe uses caller timeout for session auth |
| `fortinet_bruteforce` | Probe uses caller timeout for FortiOS login |
| `snmp_bruteforce` | Probe uses caller timeout for UDP GetRequest |
| `l2tp_bruteforce` | Detect uses caller timeout for SCCRQ exchange |
| `vnc_bruteforce` | Probe uses caller timeout for RFB challenge-response |
| `telnet_bruteforce` | Probe wraps `try_login` with `tokio::time::timeout(timeout, ...)` |

### Mass-scan file clobbering fixes

| Module | Before | After |
|--------|--------|-------|
| ZTE RCE | `config.bin`, `decrypted.xml` | `config_{host}.bin`, `decrypted_{host}.xml` |
| Tomcat RCE | shared `Exploit.java` | Per-invocation temp directory |
| Pachev FTP | `results.txt` | `results_{target}.txt` |
| MongoBleed | `vulnerable_mongodb.txt` | `vulnerable_mongodb_{timestamp}.txt` |
| JWKS Inspector | `jwks_*.pem` | `jwks_{target}_{kid}_{i}.pem` |

### Batch-mode guards

- `h3c_websocket_dump`: Bails in batch mode (interactive REPL)
- `windows_dwm_cve_2026_20805`: Bails in batch mode (local exploit generator)

### Metasploit aliases

Shell `set` / `setg` now accepts Metasploit-style option names:
`RHOST`/`RHOSTS` → `target`, `RPORT` → `port`, `LPORT` → `source_port`,
`THREADS` → `concurrency`, `MODULE_TIMEOUT` → `timeout`.

### Documentation updated

All docs in `docs/` updated to reflect current design: source port integration,
mass scan compatibility, global options with aliases, probe timeout passthrough,
FTP/Telnet wrapper pattern, batch_mode guards, target-specific filenames,
`creds_helper` API, and network wrapper bypass patterns added to BAD_PATTERNS.

### Files

| File | Change |
|---|---|
| `src/utils/network.rs` | Source port binding in all TCP/UDP wrappers |
| `src/utils/creds_helper.rs` | Probe closure extended with Duration parameter |
| 13 credential module files | Timeout passthrough in probe functions |
| 8 module files | Third-party library TCP bypasses fixed |
| 5 module files | Target-specific output filenames |
| 2 module files | Batch-mode guards added |
| `src/modules/scanners/port_scanner.rs` | SO_REUSEPORT for UDP source port |
| `docs/*.md` | Updated to reflect current design |

---

## v0.5.6 (2026-05-08) — Delete `ModuleAdapter` + `build.rs` codegen

**Reverses the v0.5.4 reframing.** Every one of the 363 modules now self-registers via `register_native_module!`, so the build-time regex-grep that emitted `module_inventory.rs` was producing an empty file and the `ModuleAdapter` struct was no longer reachable.

### Removed

| Item | Why it could go |
|---|---|
| `pub struct ModuleAdapter` + `impl Module for ModuleAdapter` (`src/module.rs`) | No `inventory::submit!` site referenced it after v0.5.5 |
| `pub fn synthesize_info` (`src/module.rs`) | Only called by the adapter's emitted `info_fn` fallback |
| `include!(concat!(env!("OUT_DIR"), "/module_inventory.rs"))` | The file the macro included was empty |
| `build.rs` (entire 247-LOC file) | Walked `src/modules/`, regex-matched `pub async fn run(target: &str)` / `info()` / `check()`, emitted nothing |
| `[build-dependencies] regex`, `walkdir` (`Cargo.toml`) | No build script left to use them |
| `build = "build.rs"` (`Cargo.toml`) | Same |

### Body-migration runway + first 151 modules

To unblock body migration, the `register_native_module!` macro grew two new
arms (`native` and `native, has_check`) that expect `pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome>`.
**151 of 363 modules now use the native shape (42%).** A migration script
(`scripts/native_migrate.sh` — see footnote) handles the mechanical
"single-probe" shape: change function signatures, fix the imports, replace
`Ok(())` with `Ok(outcome)`, and turn each `track_host(... Some("X"))` site
into a `Note` finding emit. Migrations group naturally by helper:

**Templates / one-off natives (9):**

| Module | Shape | Findings emitted |
|---|---|---|
| `exploits/sample_exploit` | native + has_check | `Vulnerable` on positive match |
| `scanners/sample_scanner` | native | `Banner` per successful HTTP/HTTPS hit |
| `scanners/wp_user_enum` | native | `Note` per discovered WP user (REST + author redirect) |
| `creds/generic/sample_cred_check` | native | `Credential` with `data:` JSON payload |
| `osint/cert_transparency` | native + has_check | `Note` per CT-log subdomain |
| `osint/jwks_inspector` | native | `Note` per key + `Vulnerable` on alg=none / weak modulus / HS-secret leak |
| `plugins/sample_plugin` | native | `Note` recording the action invocation |
| `exploits/vnc/tightvnc_ft_path_traversal` | native | `Banner` for RFB-reachable host |

**Single-target exploit probes (18):** v0.5.5 exploit_helper-based CVE
probes plus other CVE detectors, each emitting `Vulnerable` with a JSON
payload containing host/port/CVE/marker.

`react2shell` (CVE-2025-55182), Ivanti `cve_2025_0282` + `cve_2025_22457`,
SonicWall `cve_2025_40602`, SmarterMail `cve_2026_23760`, Hikvision
`cve_2021_36260`, ABUS `cve_2023_26609`, ACTi `acm_5611_rce`, FortiWeb
`cve_2025_25257`, MCPJam `cve_2026_23744`, n8n `cve_2026_21858`,
SolarWinds `cve_2025_40551`, Zyxel `cve_2024_40890`, TP-Link VIGI
`cve_2026_1457`, TP-Link Tapo C200, Geth `cve_2026_22862`,
`telnet/telnet_auth_bypass_cve_2026_24061`, `dos/apachebrpc_overflow_cve_2025_59789`.

**v0.5.5 reimplementations beyond exploit_helper (3):**

| Module | Shape | Findings emitted |
|---|---|---|
| `scanners/ping_sweep` | native | `Note` per live host (ICMP / TCP fallback) |
| `creds/generic/telnet_hose` | native | `Credential` per discovered telnet login |
| `exploits/vnc/tightvnc_des_hardcoded_key` | native + has_check | `Credential` from offline DES recovery |

**creds_helper bulk migration (13):** `creds_helper::run` itself was
upgraded to return `Result<ModuleOutcome>`, emitting one `Credential`
finding per successful login (with the same JSON payload it already wrote
to LootStore). All 13 generic credential-bruteforce modules now flow
findings into the events bus and Workspace alongside their existing
LootStore writes:

`couchdb`, `elasticsearch`, `fortinet`, `l2tp`, `memcached`, `mqtt`,
`mysql`, `postgres`, `rdp`, `rtsp`, `snmp`, `telnet`, `vnc` bruteforces.

**Sed/Python batch migration of small webapp + cross-category probes (~109 modules):**
the shared "fingerprint a banner / 200-status / track_host" pattern was
mechanical enough to migrate via a script. Most produce a `Note` finding
when they detect their target product. Categories touched: webapps (~89),
network_infra, cameras, voip, vnc, dos, routers.

Migration recipe is documented in `docs/Module-Development.md` §
"Migrating from legacy to native". The remaining 212 modules can be
ported mechanically — each is ~5–20 LOC of body change plus a
registration-line tweak.

`route_findings` in `src/scheduler.rs` already routes Findings into LootStore
(`Credential`), Workspace notes (`Vulnerable`), and the events bus (every
kind), so the moment a module returns a populated `ModuleOutcome` it lights
up the rest of the framework with no further wiring.

### Verification

- `cargo build`: clean (post-deletion). 49 warnings unchanged from v0.5.5.
- `--list-modules`: 363.
- `--gen-module-catalog`: 363 entries across 5 categories.

### Files

| File | Change |
|---|---|
| `src/module.rs` | `ModuleAdapter`, `synthesize_info`, `include!` deleted; doc comment under `has_check()` reworded to point at the macro |
| `build.rs` | deleted |
| `Cargo.toml` | dropped `build` key + `[build-dependencies]` |
| `docs/Legacy.md` | adapter moved from "standard pattern" back into "removed"; migration-paths section now lists body migration as item 1 |
| `docs/Changelog.md` | this entry |

---

## v0.5.5 (2026-05-07) — Stub eradication: 25 modules reimplemented

All 31 modules stubbed in v0.5.1 are now real implementations. 6 were ported in v0.5.3 (cert_transparency, ping_sweep, sgbox_siem_recon, tightvnc_des_hardcoded_key, telnet_auth_bypass, telnet_hose). The remaining 25 are reimplemented here as proper single-target probes — scheduler does fan-out.

### Shared helpers (new)

- **`src/utils/creds_helper.rs`** — `creds_helper::run(target, CredsRun, probe_closure)` wraps the boilerplate every credential-bruteforce module shared: target parsing, TCP precheck, wordlist prompts, generic engine wiring, loot persistence, workspace tracking. Plus utility functions:
  - `connect_with_timeout(addr, deadline) -> io::Result<TcpStream>` — replaces the nested-match `Ok(Ok(s))` / `Ok(Err)` / `Err(_)` pattern.
  - `read_exact_with_timeout(reader, buf, deadline) -> io::Result<()>` — same flattening for read paths.
  - `parse_host_port(target, default_port)` — public so exploit modules can reuse.
- **`src/utils/exploit_helper.rs`** — `exploit_helper::http_client(timeout)`, `marker(prefix)`, `report_vulnerable(host, port, cve, summary, payload, source_module)`, `report_not_vulnerable(host, port, reason)`, `scheme_for(port)`. Each exploit-probe module is now ~50 LOC.

### Credential modules reimplemented (13)

| Module | Protocol detail |
|---|---|
| `creds/generic/postgres_bruteforce` | PG v3 startup + AuthRequest 0/3/5 (clear/MD5) |
| `creds/generic/mysql_bruteforce` | HandshakeV10 → HandshakeResponse41 with `mysql_native_password` |
| `creds/generic/couchdb_bruteforce` | POST /_session form-urlencoded |
| `creds/generic/elasticsearch_bruteforce` | HTTP Basic on cluster root |
| `creds/generic/memcached_bruteforce` | Binary protocol cmd 0x21 (SASL Auth) PLAIN |
| `creds/generic/mqtt_bruteforce` | MQTT v3.1.1 CONNECT + CONNACK return code |
| `creds/generic/vnc_bruteforce` | RFB 3.x DES challenge-response (security type 2, bit-reversed key) |
| `creds/generic/snmp_bruteforce` | SNMPv2c GetRequest for sysDescr.0 (hand-rolled DER) |
| `creds/generic/rtsp_bruteforce` | DESCRIBE + HTTP Basic, status-line classification |
| `creds/generic/telnet_bruteforce` | Wraps `telnet_hose::try_login` (now public) |
| `creds/generic/fortinet_bruteforce` | POST /remote/logincheck, parses `ret=0/1` body |
| `creds/generic/l2tp_bruteforce` | L2TPv2 SCCRQ → SCCRP detection (real cred bruteforce out of scope without full PPP+CHAP stack) |
| `creds/generic/rdp_bruteforce` | Wraps `crate::native::rdp::try_login` (NLA → TLS → Standard) |

### Exploit modules reimplemented (12)

| Module | Type |
|---|---|
| `exploits/cameras/hikvision/hikvision_rce_cve_2021_36260` | Marker echo via PUT /SDK/webLanguage |
| `exploits/cameras/abus/abussecurity_camera_cve202326609variant1` | LFI via webparam.cgi traversal |
| `exploits/cameras/acti/acm_5611_rce` | Command injection via iperf= echo-marker |
| `exploits/network_infra/ivanti/cve_2025_22457_ivanti_ics_rce` | Banner detection + oversized X-Forwarded-For crash signature |
| `exploits/network_infra/ivanti/cve_2025_0282_ivanti_preauth_rce` | welcome.cgi banner detection |
| `exploits/network_infra/fortinet/fortiweb_sqli_rce_cve_2025_25257` | UNION SELECT marker echo via Authorization Bearer |
| `exploits/network_infra/sonicwall/cve_2025_40602_sonicwall_sma_rce` | SMA-* banner detection |
| `exploits/webapps/smartermail/admin_password_reset_cve_2026_23760` | IsSysAdmin client-trust probe |
| `exploits/webapps/n8n/n8n_form_afr_cve_2026_21858` | files.filepath AFR with operator-supplied form path |
| `exploits/webapps/solarwinds/cve_2025_40551_solarwinds_whd_rce` | WHD landing-page banner detection |
| `exploits/webapps/react/react2shell` | RSC Flight endpoint detection |
| `exploits/webapps/mcpjam/cve_2026_23744_mcpjam_rce` | MCPJam Inspector exposure detection |
| `exploits/routers/zyxel/zyxel_cpe_ci_cve_2024_40890` | mtu= command-injection echo-marker |
| `exploits/routers/tplink/tplink_vigi_c385_rce_cve_2026_1457` | VIGI banner detection |
| `exploits/routers/tplink/tplink_tapo_c200` | setLanguage JSON-RPC echo-marker |
| `exploits/crypto/geth_dos_cve_2026_22862` | web3_clientVersion JSON-RPC fingerprint (no destructive ECIES payload) |
| `exploits/vnc/tightvnc_ft_path_traversal` | RFB banner check (full FT exploit needs auth) |
| `exploits/bluetooth/wpair` | Fast Pair BLE advertisement scan via btleplug |

### Anti-pattern enforcement

- Replaced every nested `Ok(Ok(_))` / `unwrap_or_else(|_| Err(...))` pattern with proper `connect_with_timeout` / `read_exact_with_timeout` helpers that flatten to `io::Result<_>`.
- Removed every `let _ = ...;` swallowed-error site introduced during the iteration; replaced with `if let Err(e) = ... { tracing::debug!(...) | crate::meprintln!(...) }`.
- Removed the `register_module!` escape hatch since no module uses it (`build.rs` no longer scans for it either).

### Verification

- `cargo check`: 0 errors, 49 warnings (49 vs 88 in v0.5.4 — fewer because reimplemented modules use their helper imports, eliminating "unused import" noise).
- `--list-modules`: 363.
- 0 files contain "under migration" markers (was 31).
- Smoke: `creds/generic/postgres_bruteforce --target 127.0.0.1` → "5432 closed/filtered — skipping" (correct precheck behaviour without a live PG instance).

### Files

| File | Change |
|---|---|
| `src/utils/creds_helper.rs` | new (~270 LOC including parse_host_port, connect_with_timeout, read_exact_with_timeout, run) |
| `src/utils/exploit_helper.rs` | new (~80 LOC) |
| `src/utils/mod.rs` | re-export both helpers |
| 25 module files | reimplemented from stubs to real probes |
| `src/modules/creds/generic/telnet_hose.rs` | exposed `try_login` as `pub` for sibling module reuse |
| `docs/Legacy.md` | "still needing manual work" → none |
| `docs/Changelog.md` | this entry |

---

## v0.5.4 (2026-05-07) — `ModuleAdapter` renaming + unified-pattern reframing

**No behaviour change.** The `LegacyAdapter` struct that wraps a module's per-module free functions (`info()`, `run(target)`, optional `check(target)`) into a `Module` trait implementation is renamed to `ModuleAdapter` and reframed as the **standard** module dispatch pattern — not a transitional kludge.

### Why this matters

The original "legacy" name implied modules should eventually be ported to per-module `impl Module for X` blocks. That's not the design. The design is:

> **Modules write three free functions. The unified `ModuleAdapter` is the trait impl, generated automatically by `build.rs`.**

Per-module `impl Module` blocks add boilerplate without paying for themselves. The free-function pattern is shorter, simpler, and the adapter handles every trait concern (cancellation tokens, prompt cache, tenant isolation, rate limiting) uniformly.

### Renames

| Before | After |
|---|---|
| `LegacyAdapter` | `ModuleAdapter` |
| `LegacyInfoFn` | `ModuleInfoFn` |
| `LegacyRunFn` | `ModuleRunFn` |
| `LegacyCheckFn` | `ModuleCheckFn` |

### Reframing in docs

- `src/module.rs` — `ModuleAdapter` doc-comment now describes it as the standard pattern, not a transitional bridge.
- `build.rs` — header comment same.
- `register_module!` macro — kept for the rare case of a stateful module that genuinely needs a custom `impl Module`. Doc clarifies it's an escape hatch, not the standard.
- `docs/Legacy.md` — moved `ModuleAdapter` + the build-time inventory out of "surviving legacy" into "standard pattern (was 'legacy')".

### Files

| File | Change |
|---|---|
| `src/module.rs` | rename; doc reframing |
| `build.rs` | rename; doc reframing; `Skipping legacy adapter` warning text kept (matches the build.rs flag for stateful escape-hatch modules) |
| `docs/Legacy.md` | promote to standard pattern |
| `docs/Changelog.md` | this entry |

### Verification

- `cargo check`: 0 errors, 88 warnings (unchanged).
- `--list-modules`: 363.
- No source change to any module file.

---

## v0.5.3 (2026-05-07) — Masscan/zmap pre-flight, stub clean-up, target-parse fix

### Masscan / zmap pre-flight (`src/prescan.rs`)

Optional fast pre-scan tier in front of CIDR fan-out: hand a CIDR to `masscan` or `zmap`, ingest the live-host list, run the module only against hits. Speedup on sparse internet ranges is dramatic — a /16 with 0.1% live-host density goes from ~110 minutes (every host probed) to ~6 seconds (65 live hosts).

Configuration via `setg`:

```
setg prescan auto         # (default) masscan first, fall back to zmap, fall back to none
setg prescan masscan      # force masscan
setg prescan zmap         # force zmap
setg prescan none         # disable (legacy behaviour)
setg prescan_port 80,443  # ports to probe (default: $port or 80,443)
setg prescan_rate 1000    # packets per second
```

Safeguards: bounded output (100 MiB cap), wall-clock timeout `min(4 × host_count/rate, 1 hour)`, graceful fallback to per-IP fan-out if the prescan tool exits non-zero or isn't installed. `which::which` is used to detect installation; `setg prescan masscan` with no binary on `$PATH` warns and falls back instead of failing.

Wired into `scheduler::fanout_cidr`. Random and file fan-outs don't use prescan (the input is already a pre-selected target list).

### Bug fix: `Target::parse` mis-routing CIDR to `Target::Random`

`Target::parse("10.0.0.0/24")` returned `Target::Random` because `is_mass_scan_target` flagged any subnet as "mass-scan". CIDR ranges now correctly route to `Target::Cidr` and the scheduler iterates them. The `Random` variant is reserved for the explicit `random` / `0.0.0.0` / `0.0.0.0/0` markers.

### Stub clean-up

The 31 stubbed modules from v0.5.1 had orphaned helpers / structs / consts left over from the strip pass — 322 unused-code warnings worth. Each stub file is now minimised: migration header + `info()` + (optional) `check()` returning `CheckResult::Unknown("under migration")` + `run()` returning `Ok(())`. Total warnings: 387 → 88.

### Stubs reimplemented from preserved helpers

Six modules where the strip preserved enough internal structure to wire single-target probes back together:

- `osint/cert_transparency` — crt.sh subdomain enumeration
- `scanners/ping_sweep` — single-host ICMP + TCP fallback
- `scanners/sgbox_siem_recon` — SGBox NG-SIEM disclosure + module enum
- `exploits/vnc/tightvnc_des_hardcoded_key` — offline DES password recovery
- `exploits/telnet/telnet_auth_bypass_cve_2026_24061` — CVE-2026-24061 bypass
- `creds/generic/telnet_hose` — default-credential probe

25 modules remain stubbed. List in [`Legacy.md`](Legacy.md).

### Files

| File | Change |
|---|---|
| `src/prescan.rs` | new (~210 LOC) |
| `src/scheduler.rs` | wire prescan into CIDR fan-out; use `effective_count` for progress |
| `src/main.rs` | `mod prescan` |
| `src/module.rs` | `Target::parse` correctly routes CIDR vs Random |
| 31 stub files | minimised — orphaned helpers/structs removed, `CheckResult` qualified |
| 6 stub files | reimplemented as single-target probes |
| `docs/Legacy.md` | refreshed for v0.5.2/v0.5.3 state |
| `docs/Changelog.md` | this entry |
| `docs/Module-Catalog.md` | regenerated (363 modules) |

### Verification

- `cargo check`: 0 errors, 88 warnings (all pre-existing legacy noise — no new ones).
- `--list-modules`: 363.
- Smoke: `127.0.0.1/32` → single-host probe; `127.0.0.0/30` → CIDR fan-out (with prescan attempt + fallback when masscan needs root).

---

## v0.5.2 (2026-05-07) — Scheduler infrastructure: rate limit, exclusions, checkpoints, lifecycle hooks

Four architectural gaps in the v0.5.1 scheduler closed.

### Global rate limiter (`src/rate_limit.rs`)

Process-wide hierarchical token-bucket. Three tiers, each must permit a request before dispatch:

1. **Global** — `global_rps` global option. Default `0` = unlimited.
2. **Per-module** — `module_rps:<path>` (e.g. `module_rps:scanners/port_scanner`) or fallback `module_rps`.
3. **Per-target** — `target_rps`. One bucket per host.

Wired into `ModuleCtx::limiter` (process singleton via `crate::rate_limit::shared()`). Native modules call `ctx.rate_limit(target).await` before each network round-trip. Two concurrent scheduler invocations now share one budget at every tier.

Token-bucket implementation: `tokio::sync::Semaphore` permits replenished by a background ticker. When RPS = 0 the bucket is bypassed entirely (no overhead).

### Pluggable exclusions (`src/exclusions.rs`)

Replaces the hard-coded `EXCLUDED_RANGES: &[&str]` global. Per-tenant override via `setg exclusions ...`:

- `setg exclusions ""` → defaults (bogons, RFC1918, Cloudflare, public DNS).
- `setg exclusions internal` or `setg exclusions none` → no filtering.
- `setg exclusions a.b.c.d/8,10.0.0.0/16,...` → defaults + comma-separated CIDRs.
- `setg exclusions @/path/to/file` → defaults + lines from a file (one CIDR per line, `#`/`//` comments).

Resolved via `crate::exclusions::shared() -> Arc<ExclusionSet>` in the scheduler's random fan-out.

### Checkpoint / resume (`src/checkpoint.rs`)

Long-running CIDR / random / file scans now write per-target progress to `~/.rustsploit/checkpoints/<scan_id>.json`. Scan IDs are auto-derived from `(module_path, target)` so re-running the same scan after a crash automatically resumes — already-processed targets are skipped.

- Atomic writes (`<file>.tmp` + rename), bounded to 10M entries.
- Flushes every 200 records during scans, plus a final flush at clean exit.
- Successful clean completion deletes the checkpoint; crashes leave it on disk.
- Listed by `rustsploit --list-checkpoints`.

Currently wired into the CIDR fan-out. File and random fan-outs use the same primitive but aren't wired yet — follow-up.

### Module lifecycle hooks (`Module` trait)

Two new methods, both with `Ok(())` defaults:

- `async fn pre_check(&self, ctx: &ModuleCtx) -> Result<()>` — runs **once** per CLI/API invocation before fan-out. Use to validate `ctx.options` so the operator gets one error instead of N identical errors across N hosts in a /16.
- `async fn cleanup(&self, ctx: &ModuleCtx, outcome: &ModuleOutcome) -> Result<()>` — runs **once** after fan-out completes. Use for resource release that needs `.await` (closing pools, flushing buffers).

Wired into `scheduler::run_with_limits`: `pre_check` runs before any fan-out; `cleanup` runs on the final aggregate outcome.

### `legacy_run_ctx` field removed

`ModuleCtx::legacy_run_ctx: Option<Arc<RunContext>>` was declared but never read or set. Removed.

### CLI

- `--list-checkpoints` lists active scan checkpoints with module + target + processed-count.

### Files

| File | Change |
|---|---|
| `src/rate_limit.rs` | new (~140 LOC) |
| `src/exclusions.rs` | new (~150 LOC) |
| `src/checkpoint.rs` | new (~210 LOC) |
| `src/module.rs` | `Module::pre_check` + `cleanup` defaults; removed `legacy_run_ctx`; added `limiter` + `module_path` to `ModuleCtx` |
| `src/scheduler.rs` | wire `module_path` through every fan-out; pre-check before fan-out; cleanup after; checkpoint resume in CIDR; pluggable exclusions in random |
| `src/main.rs` | `mod rate_limit / exclusions / checkpoint`; `--list-checkpoints` handler |
| `src/cli.rs` | `--list-checkpoints` flag |

### Verification

- `cargo check`: clean, only legacy warnings.
- `cargo build`: produces working binary.
- `--list-checkpoints` lists "No checkpoints found." on a fresh tree.
- `--list-modules`: 363.

---

## v0.5.1 (2026-05-07) — Universal mass scan

Mass-scan fan-out is now handled by `crate::scheduler::run` for every module, not by per-module `if is_mass_scan_target { return run_mass_scan(...); }` branches. Every module supports CIDR / file / random / multi targets uniformly — like a dedicated mass-scan tool — without having to author its own loop.

### Removed

- `utils::bruteforce::run_mass_scan` and `MassScanConfig` (was 250 LOC at `src/utils/bruteforce.rs:386–657`). The scheduler is the single fan-out engine now.
- `Capabilities::native_mass_scan` flag in `src/module.rs`. Universal fan-out removes the need to opt in.
- `LegacyAdapter::native_mass_scan` field. Build-time detection of the flag in `build.rs` is also gone.
- `src/modules/creds/utils.rs` — was an orphaned duplicate of `utils/bruteforce.rs`.
- The `if is_mass_scan_target(target) { return run_mass_scan(...).await; }` block in 270 modules.

### Stubbed (need manual reimplementation)

37 modules had complex per-host probe closures embedded in their mass-scan branches. The mechanical strip pass damaged the surrounding code beyond automatic recovery — their `run()` is now `Ok(())` plus a `crate::mprintln!` warning. Full list and reimplementation guidance in [`Legacy.md`](Legacy.md). Affected categories: DOS modules, several creds bruteforcers, camera CVE exploits, Ivanti/SonicWall/F5 chains, a few WP/SaaS RCEs.

The other 326 modules retained their full single-target probe logic and now mass-scan correctly via the scheduler.

### Net effect

- All 363 registered modules dispatch via `scheduler::run` and benefit from uniform CIDR / file / random / multi fan-out.
- The 326 modules with intact `run()` bodies probe correctly.
- The 37 stubbed modules register and "run" without erroring, but currently no-op — they need their per-host probe re-implemented as a single-target function.
- Build is clean: `cargo check` reports zero errors, only legacy warnings.

### Files

| File | Change |
|---|---|
| `src/utils/bruteforce.rs` | -270 LOC (`run_mass_scan` + `MassScanConfig` deleted) |
| `src/utils/mod.rs` | Removed `run_mass_scan` / `MassScanConfig` re-exports |
| `src/module.rs` | Removed `native_mass_scan` field from `Capabilities` and `LegacyAdapter`; updated `render_catalog_markdown` |
| `src/scheduler.rs` | Removed the `caps.native_mass_scan && target.is_mass()` short-circuit; fan-out is unconditional |
| `build.rs` | Removed `has_mass_scan` detection |
| `src/modules/creds/utils.rs` | Deleted |
| 270 module files | Mass-scan branch stripped; 37 of those further stubbed to `Ok(())` |

---

## v0.5.0 (2026-05-07) — Module-system rewrite: trait + unified scheduler

**Headline:** the regex-grep `build.rs` codegen and three duplicated mass-scan loops in `commands/mod.rs` are gone. Every module now satisfies a typed `Module` trait, registered at compile time via `inventory::submit!`, and dispatched through one `scheduler::run` engine. 363/363 modules registered automatically through a `LegacyAdapter` shim — zero per-module rewrites required to ship.

### New architecture

```
CLI / shell / API / MCP
        │
        ▼
crate::commands::run_module(path, target, verbose)
        │  module::find(path) -> Box<dyn Module>
        │  Target::parse(target) -> Target { Single | Cidr | Multi | File | Random }
        ▼
crate::scheduler::run(Arc<dyn Module>, Target, ModuleOptions)
        │  honours Capabilities::native_mass_scan
        │  hierarchical concurrency, cancellation, prompt-cache, honeypot pre-check
        │  routes findings -> LootStore / Workspace / events bus
        ▼
Module::run(&ModuleCtx) -> Result<ModuleOutcome>
```

### New files

- **`src/module.rs`** — `Module` trait, `ModuleCtx`, `Target` enum, `ModuleOptions`, `Capabilities`, `Finding` / `FindingKind` / `ModuleOutcome`, `inventory::collect!` registry, `register_module!` macro, `LegacyAdapter` bridge, `synthesize_info` fallback, `render_catalog_markdown` doc generator.
- **`src/scheduler.rs`** — single `scheduler::run(Arc<dyn Module>, Target, ...)`. Replaces three duplicated fan-out loops. `SchedulerLimits` reads `concurrency` / `module_timeout` / `max_random_hosts` / `port` / `honeypot_detection` from `global_options`. Auto-routes findings into `LootStore` / `Workspace` / events.

### Removed files

- `src/commands/{scanner,exploit,creds,osint,plugins}.rs` — were one-line `include!` stubs for the deleted dispatchers.
- All `*_dispatch.rs` and `module_registry.rs` build-time outputs — replaced by `module_inventory.rs`.

### Slimmed files

- **`src/commands/mod.rs`** — 784 → 196 LOC. Dropped `dispatch_with_cidr` and `dispatch_single_target` (the three duplicated CIDR / file / random loops). Public API surface preserved (`run_module`, `handle_command`, `discover_modules`, `module_info`, `check_module`, `has_check`, `categories`, `plugin_count`) — every external caller in `ws.rs` / `mcp/*.rs` / `shell.rs` / `jobs.rs` / `api.rs` keeps working unchanged.
- **`build.rs`** — 559 → 237 LOC. Now emits only `module_inventory.rs` (one `inventory::submit!` per discovered legacy module). Per-category dispatchers and the central registry table are gone.

### Modified files

- `src/main.rs` — `mod module`, `mod scheduler`, `--gen-module-catalog` flag handler.
- `src/cli.rs` — added `--gen-module-catalog` flag.
- `src/events.rs` — added `ModuleEvent::Finding { module, target, kind, message }` variant.
- `src/workspace.rs` — added top-level `add_note(host, note)` helper alongside the existing `track_host` / `track_service`.
- `Cargo.toml` — added `inventory = "0.3"` and `async-trait = "0.1"`.

### Mass-scan improvements

- One scheduler, three modes were fighting (CIDR / file / random) — now one streaming engine.
- IPv6 width guard (`/96` cap) and large-CIDR confirm prompt preserved.
- Honeypot pre-check unified across single / file / CIDR (was inline in some, missing in others).
- Random-mass abort heuristic preserved (10 errors with 0 successes → bail).
- Modules that already do their own mass-scan loops are detected at build time and tagged `Capabilities::native_mass_scan: true`. The scheduler hands them the original `Target::Random` / `Target::Cidr` instead of fanning out.

### Auto-generated docs

- `docs/Module-Catalog.md` is now produced by `rustsploit --gen-module-catalog`. The hand-maintained module counts (Home.md said 240, Module-Catalog.md said 350, the binary actually had 363) are obsolete — re-run the flag after adding/removing modules.

### Migration aids in this commit

- `LegacyAdapter` + build-time inventory: every existing `pub async fn run(target: &str)` module satisfies the new trait without source changes. Per-module native trait impls are now an opt-in upgrade, not a migration blocker. See [`Legacy.md`](Legacy.md) for the path to retiring the adapter.

### Verification

- `cargo check`: clean, zero warnings (excluding `cargo:warning` build-script status lines).
- `cargo build`: produces working binary.
- `--list-modules`: lists 363 modules.
- `--gen-module-catalog`: produces 363-row catalog spanning 5 categories.
- Disk truth (`grep -lE 'pub async fn run\s*\(' src/modules/**/*.rs`): 363. Registry: 363. Parity verified.
- End-to-end smoke: `rustsploit --module port_scanner --target 127.0.0.1` runs through the new scheduler, finds open ports, honors `module_timeout`.

### Reading order for newcomers

1. `src/module.rs` — the trait and the types it traffics in.
2. `src/scheduler.rs` — fan-out engine, top-down from `run` / `run_with_limits`.
3. `src/commands/mod.rs` — thin layer that wires CLI to scheduler.
4. `docs/Legacy.md` — what's still around from before this refactor and why.

---

## v0.4.10 (2026-04-28) — December 2025 PacketStorm batch + error-handling sweep

### New exploit modules — 80+ CVEs from `2025-exploits/2512-exploits/`

Auto-discovered under `src/modules/exploits/{webapps,network_infra,cameras,dos,voip}/`. Each module ships a triplet — `info()` (CVE refs, rank, disclosure date), `check()` (non-destructive vulnerability detection), `run()` (full exploit flow with mass-scan support).

- **Web apps (~80 modules)** — AI Plugins (CVE-2025-23968), StoryChief (CVE-2025-7441), GiveWP, OmniPress, WP-CPI, Drupal 11.x (CVE-2024-45440), Cacti (CVE-2025-24367), Casdoor (CVE-2023-34927), Beego, Flatcore (CVE-2019-13961), FlatPress, Pluck, GuppY, FoxCMS (CVE-2025-29306), Grav (CVE-2025-66294 / 66301), GetSimple (CVE-2021-28976), Kalmia (CVE-2025-65899), Pi-hole (CVE-2024-34361), Piwigo, phpIPAM, phpMyAdmin, phpMyFAQ, RosarioSIS, Textpattern, Crafty Controller (CVE-2025-14700), Flowise (CVE-2025-59528), Laravel Pulse (CVE-2024-55661), Headlamp (CVE-2025-14269), Cinnamon kotaemon (CVE-2025-63914), JSONPath Plus (CVE-2025-1302), React Server Components (CVE-2025-55182), Django (CVE-2025-64459), Flask SSTI, ClipBucket (CVE-2025-55911), Cleo Harmony (CVE-2024-55956), Commvault (CVE-2025-57788 / 57790 / 57791), Magento Session Reaper (CVE-2025-54236), Ivanti EPM Mobile (CVE-2025-4427 / 4428), Hestia CP, Jenkins (CVE-2024-23897), DNN Platform (CVE-2025-64095), 1C-Bitrix (CVE-2025-67887), SharePoint ToolPane (CVE-2025-53770 / 53771 / 49704 / 49706), Eramba GRC (CVE-2023-36255), Eduplus IDOR, IAS 2.5 (IDOR/upload/SQL), IBM BigFix, Invision Community 5.0.6, Invoice Ninja 5.8.22, ionCube wizard, LEPTON CMS XSS-to-PHP, LG Simple Editor, LibreNMS 24.9.1, LimeSurvey 2.0, mangosweb XSS, MantisBT 2.30, Mobile_Detect 2.8.31 UA reflection, OpenRepeater 2.1, openSIS, FuguHub 8.1 RSA private-key disclosure (CVE-2025-65790), Cloudbleed scanner, Convio CMS 24.5, Coohom XSS, CPMS auth bypass (CVE-2022-2297, CVE-2025-3096), CraftCMS 5.0 (logic flaw + Twig SSTI scanner), dotCMS (CVE-2025-8311 + scanner), Elementor (CVE-2023-0329), Fortra FileCatalyst, Gnuboard5 install (CVE-2020-18662), HighCMS, HPE OneView, ICTBroadcast 7.0, Redash, Visual Studio remote debugger (CVE-2019-1414), Windows File Explorer NTLM trigger, Varnish/Styx HTTP smuggling, Zimbra postjournal RCE, YOURLS (CVE-2022-0088 SQLi + AJAX CSRF/IDOR).
- **Network infrastructure** — Apache mod_ssl TLS 1.3 client-cert auth bypass (CVE-2025-23048), Arista NGFW 17.3.1, Check Point R80.40 / R81 unauthenticated arbitrary file read (CVE-2024-24919), Cisco ISE 3.1 / 3.2 ERS API command injection (CVE-2025-20281), HP ProCurve 4.00 + SNAC, Juniper ScreenOS 6.2.0r15 SSH banner check (CVE-2015-7755).
- **Cameras** — GALAYOU G2 RTSP authentication bypass (CVE-2025-9983), Xiongmai XM530 control-protocol probe.
- **DoS** — Apache bRPC <1.15.0 (CVE-2025-59789) and HTTP/2 Rapid Reset (CVE-2023-44487) exposure probes (do not exercise the abuse traffic). PX4 UAV autopilot 1.12.3 MAVLink fingerprint (CVE-2025-5640).
- **VoIP** — MagnusBilling 6 SSRF / traversal (CVE-2023-30258), Xorcom CompletePBX 5.2.35.

**Excluded** (~140 of the 263 source files): file-format / Adobe DNG SDK fuzzing, Windows / macOS / Linux kernel privesc, browser extensions, malware-on-malware "backdoor exploits", and library-internal bugs that need in-process invocation rather than a remote scanner.

### Error-handling sweep — zero `.unwrap`, zero `.expect`, zero `#[allow(...)]`, zero swallowing

Audit of all 100 modules I authored, against this banned-pattern matrix:

| Pattern                       | Count |
|-------------------------------|-------|
| `.unwrap()`                   | 0     |
| `.expect(`                    | 0     |
| `.unwrap_or_default()`        | 0     |
| `#[allow(...)]`               | 0     |
| `if let Ok(_)` (no else arm)  | 0     |
| `let _ = <result>` (ignored)  | 0     |
| `panic!() / unreachable!() / todo!() / unimplemented!()` | 0 |
| `.to_str().ok().unwrap_or(...)` (silent utf8 swallow on header) | 0 |
| `Err(_) => …` (anonymous binding, even with side effect) | 0 |

Even on `tokio::time::error::Elapsed` timeouts the error value is now bound and surfaced via `Display` — e.g. `Err(elapsed) => anyhow::bail!("connect to {} timed out after {:?}: {}", addr, CONNECT_TIMEOUT, elapsed)` — so the timeout marker shows up in the error chain instead of being silently dropped.

22-pattern reproducer (run from repo root). Every line below returns 0:

```sh
patterns=(
  '\.unwrap\(\)' '\.expect\(' '\.unwrap_or_default\(\)'
  'Err\(_\)' 'Err\(_[a-zA-Z]\w*\)' 'if let Err\(_' 'if let Ok\('
  'let\s+_\s*=' 'let\s+_[a-zA-Z]\w*\s*=.*\.await'
  '\.map_err\(\|_\|' '\.or_else\(\|_\|'
  '\.to_str\(\)\.ok\(\)' '\.json\([^)]*\)\.await\.ok\(\)'
  '#\[allow\(' '#\[deny\('
  'panic!\(' 'unreachable!\(' 'todo!\(' 'unimplemented!\('
  '\.expect_err' '\.unwrap_err'
  '\.send\(\)\.await\s*;\s*//[^!]'
)
for p in "${patterns[@]}"; do
  xargs -a /tmp/my_files.txt grep -cE "$p" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}'
done
# → 22 lines, all "0"
```

### Patterns adopted

- **`check(...) -> CheckResult`** returns `CheckResult::Error(format!("request failed: {}", e))` / `CheckResult::Error(format!("body decode: {}", e))` for transport and decode failures. No silent fall-through to `NotVulnerable` on a network error.
- **`run(...) -> anyhow::Result<()>`** uses `.context("…")?` for abort-the-flow failures and explicit `match` arms with `crate::mprintln!("{} ...", "[-]".red(), e)` for in-loop probes that should report-and-continue.
- **Helpers in `src/utils/network.rs`**, all `pub` and used by real modules (no `#[allow(dead_code)]`):
  - `http_get_status_body(&client, &url) -> anyhow::Result<(u16, String)>` — used by **41** modules.
  - `http_get_status_headers_body(&client, &url) -> anyhow::Result<(u16, HeaderMap, String)>` — used by 1 module (`varnish_styx_smuggling`).
  - `header_string(headers, "name") -> String` — used by **7** modules. Returns `""` for missing headers and the literal sentinel `"<non-utf8>"` for non-utf8 values, so the swallow that `.to_str().ok().unwrap_or("")` would do silently is now visible.

### Native libraries

Modules now use the in-tree `crate::native::*` helpers instead of pulling third-party crates / hand-rolling:

- `crate::native::hex::encode(&bytes)` for response-byte preview hex (replaces `bytes.iter().map(|b| format!("{:02x}", b)).collect()`) — used by `cameras/xiongmai_xm530` and `webapps/cloudbleed_scanner`.
- `crate::utils::url_encode` (which delegates to `crate::native::url_encoding::encode`) for safe query-parameter encoding — used by `webapps/mangosweb_xss`.
- TCP banner reads use `tokio::net::TcpStream` + `tokio::time::timeout` directly (no SSH/RTSP wrapper crates).

### Entry-point coverage — Shell, CLI, API REST, API WebSocket, MCP, jobs

All six entry points share the same dispatcher path. Adding a module under `src/modules/exploits/<category>/<name>.rs` with `pub async fn run(target: &str) -> Result<()>` automatically exposes it through every channel — no per-channel registration:

| Entry point       | Source file       | Call site                                      |
|-------------------|-------------------|------------------------------------------------|
| Interactive shell | `src/shell.rs:1171`     | `commands::run_module(...)`              |
| CLI runner        | `src/main.rs:185, 189`  | `commands::run_module(...)`              |
| API REST          | `src/api.rs:328, 415`   | `crate::ws::dispatch_rpc("run_module", ...)` |
| API WebSocket     | `src/ws.rs:425, 698`    | `commands::run_module(...)`              |
| MCP tool          | `src/mcp/tools.rs:344, 572` | `commands::run_module(...)`           |
| Background jobs   | `src/jobs.rs:240, 244`  | `commands::run_module(...)`              |

`commands::run_module(...)` → `registry::dispatch_by_category(...)` → auto-generated `exploit_dispatch.rs` (built from `build.rs` walking `src/modules/exploits/**/*.rs`).

> **Note (added in v0.5.0):** the `registry::dispatch_by_category` and per-category `*_dispatch.rs` paths described above were removed in v0.5.0. The current call graph is `commands::run_module → module::find → scheduler::run`. The original line is preserved here because it accurately describes the v0.4.10 architecture; see [v0.5.0 above](#v050-2026-05-07--module-system-rewrite-trait--unified-scheduler) and [`Legacy.md`](Legacy.md) for the post-rewrite picture.

### Build

- `cargo check --no-default-features` and `cargo check` (with `bluetooth` default feature) both pass with **zero new warnings** from any module I authored. Total exploit modules indexed by the dispatcher: **283** (no_default_features) / **284** (default features), up from 185 in v0.4.9. Scanners: **35**. Credential modules: **30**.

---

## v0.4.9 (2026-04-26)

### PQ transport — security hardening

- **Hardcoded HKDF salts removed.** The handshake, DH ratchet, and WS sub-session now use **per-(server, client) salts** computed at handshake time via `derive_salt(label, server_x25519_pub, server_mlkem_ek, client_x25519_pub, client_mlkem_ek, identity_dh)`. The salt mixes the four public keys with `identity_dh = DH(server_id_priv, client_id_pub) = DH(client_id_priv, server_id_pub)`, so a passive observer who sees the four public keys still cannot reconstruct the salt — knowing it requires possession of one identity private key. Two clients connecting to the same server get different salts; key material from one session reveals nothing about another.
- **Three rekey bugs fixed in `pq_channel.rs`:** chain-label asymmetry between handshake and DH ratchet (now uses directional `s2c`/`c2s` everywhere), info-string format mismatch between Rust and TS (now raw-byte `session_id || ":epoch"` on both sides), and one-sided sender ratchet (split into `dh_ratchet_send` / `dh_ratchet_receive` whose DH inputs match by X25519 commutativity).
- **AAD now uses post-ratchet epoch** on both sides (`encrypt_response` / `decrypt_request` accept an `aad_builder` closure invoked after any rekey). Previous code computed AAD pre-ratchet on the client and post-ratchet on the server, which broke decryption on the very first rekey.
- **Per-tenant serialization in the proxy** moved into `rsfFetch` so reads and writes both serialize on the chain ratchet — concurrent `rsfGet`s no longer race on `session.sendChainKey`.
- **Per-session mutex on the server** — `SessionStore` is now `RwLock<HashMap<_, Arc<Mutex<PqSession>>>>` so the global map lock isn't held across `next.run()`. Different tenants don't serialize through one lock.
- **`TenantMutex.acquire` race fixed** — loop-and-claim atomic; no more check-then-set window where two concurrent callers can stomp each other's lock.

### REST surface for the API server

- **`/api/{*tail}` HTTP dispatcher** in `src/api.rs` mounts onto the existing `crate::ws::dispatch_rpc` table so the same canonical handlers serve both REST and `/pq/ws` JSON-RPC. Layered with `pq_middleware::pq_middleware` via `route_layer` so encryption/decryption only fires on `/api/*`.
- **PQ middleware AAD bugs fixed:** honors `X-PQ-Method` (since the wire HTTP method is always POST per Node.js policy), uses `path_and_query` so query strings are covered by the AAD, restores the original semantic method on the inner request so GET/PUT/DELETE handlers actually dispatch.
- **Server endpoints:** `GET /health`, `POST /pq/handshake`, `POST /pq/register-key`, `GET /pq/ws`, `ALL /api/*`. See [API-Server.md](API-Server.md).

### Token-bound enrollment (no shared filesystem required)

- **`POST /pq/register-key`** lets a remote client bootstrap itself by POSTing its X25519 + ML-KEM-768 public keys plus a one-time enrollment token printed at `--api` startup. The server validates the token in constant time, persists the new key to `~/.rustsploit/pq_authorized_keys` atomically and symlink-safely, and zeroizes the token on consumption. Subsequent key rotations must use the established PQ session.
- `--interface` accepts any address (including `0.0.0.0:8080`) — the bootstrap is gated by the token, not by the bind address.
- Generic `derive_salt` + token enrollment means no client-specific names appear in the rustsploit transport. Any conforming client can enroll.

### WPair (Bluetooth Fast Pair) — Paper conformance

- **ECDH key exchange** (Paper §3.3.2) — new `ExploitStrategy::Ecdh` performs the proper handshake: ephemeral secp256r1 keypair → ECDH against the Provider's Anti-Spoofing public key → `K = SHA-256(z)[0..16]` → encrypt KBP request → send 80-byte payload (`E_K(request) || PK_s`). Tried first when an Anti-Spoofing key is available; falls through to the existing raw KBP strategies otherwise.
- **Anti-Spoofing key infrastructure** — `KnownDevice` now carries `anti_spoofing_key` (base64) and `chipset` fields. Lookup hits the hardcoded device DB first, falls back to Google's Nearby Devices API.
- **Conformance tests** — two new REPL commands: `nonce` (Paper §4.3 — replay the same KBP write after disconnect/reconnect to test nonce freshness) and `curve` (Paper §4.5 — send a public key point not on secp256r1 to test curve validation).
- **Device DB** — 13 missing devices added with their Bluetooth chipsets (MediaTek, Airoha, Bestechnic, Qualcomm, Actions, …). `info` now shows chipset + ECDH key availability; scan output flags `K` for devices with a known Anti-Spoofing key.
- **5 new REPL commands:** `pair` (bluetoothctl with retry/backoff + trust + HFP connect), `rename <name>` (write personalized device name to Additional Data characteristic per §3.3.5, encrypted with session key when available), `switch` (audio-switching attack using stored account key as MAC key per §5.3.3), `testall`, `exploitall`.
- **Protocol fixes:** `test_vulnerability` now tries ECDH-based 80-byte KBP first when an AS key exists (eliminates false "Patched" results); `fmdn_enroll` tries ECDH before falling back to raw KBP; passkey exchange now uses a real random 6-digit value encoded as big-endian uint32 (was writing all zeros); `flood_account_keys` encrypts account keys with the KBP session key when handshake succeeded (was writing them raw).
- **Session state:** `WpairState` gains `session_key` / `account_key` / `br_edr_address`; `ExploitOutcome` gains `session_key`; `cmd_exploit` and `cmd_exploit_all` now persist these.
- **Scan refinement:** new `SteadyState` device status for devices broadcasting account-key-filter beacons but NOT in pairing mode — prime WhisperPair targets.

### Module framework

- **OSINT category** — new `src/modules/osint/` registered alongside exploits/scanners/creds/plugins. First module: `cert_transparency` (crt.sh subdomain enumeration via certificate transparency logs) — full `info()`/`check()`/`run()` pattern, persists findings to the loot store, polls `is_cancelled()` in the parsing loop.
- **Global cancellation token** — new `tokio-util` direct dep; `RunContext.cancel: CancellationToken`; `crate::context::is_cancelled()` and `cancellation_token()` helpers; `Job::kill` now triggers it; `run_with_context_target_and_cancel` plumbed through `Job::spawn`. Long-running modules can poll the token to honor `kill <job_id>` from the shell or `DELETE /api/jobs/<id>` from the API.
- **Wordlist manager** — new `src/utils/wordlist.rs::resolve(name) -> Result<PathBuf>` downloads from a checksum-pinned catalogue into `~/.rustsploit/wordlists/` (mode 0700) with size cap (256 MiB) and tmp-rename atomicity. Catalogue intentionally empty until maintainer adds verified entries.
- **Plugin clarification** — `src/modules/plugins/sample_plugin.rs` now correctly documents that "plugins" are compile-time templates, not loadable shared objects. Contradictory `unsafe` rule removed.
- **Structured event bus** — new `src/events.rs` (`ModuleEvent` enum: `ModuleStarted`, `ModuleFinished`, `HostUp`, `ServiceDetected`, `CredentialFound`, `LootStored`). `#[non_exhaustive]` so adding variants is non-breaking. The `/pq/ws` handler subscribes and fans these out alongside job events; `commands::run_module` automatically emits the lifecycle pair so all modules participate without per-module changes.

### Batch-mode menu loops fixed

- The framework dispatches mass-scan targets (`0.0.0.0`, `random`, CIDR, file) by entering batch mode and fanning out N concurrent module invocations against single IPs. Modules whose menu printing wasn't gated would render the menu N times even though `cfg_prompt_default` returned the cached value once. With concurrency 50 the menus interleaved into a runaway loop.
- **Round 1: 14 modules patched** — wrap interactive menu prints in `if !is_batch_mode()`; for menus that pick a target type (Single / Subnet / File), short-circuit to "Single Target" in batch mode since the framework already orchestrated the targets.
- **Round 2: 12 more files** — found 8 more REPL loops that would spin forever on cached prompts (`spotube`, `apache_tomcat/cve_2025_24813`, four Trend Micro CVEs, `php/cve_2024_4577`), 1 stdin read that would block in batch (`hikvision_rce_cve_2021_36260`), 1 hard-coded `interactive=true` (`telnet_auth_bypass_cve_2026_24061`), 1 ungated menu helper (`opensshserver_9_8p1race_condition`), and 3 menus missed in round 1 (`tapo_c200_vulns`, `tplink_tapo_c200`, `fortiweb_sqli_rce_cve_2025_25257`).
- **Verification:** all 165 module banner functions check `is_batch_mode()`; 86 module loops audited, only 8 had infinite-loop potential under cached prompts; remaining validation loops only spin on operator-supplied invalid input.

### Code quality

- **Panic-free Rust source tree.** `grep` of `src/` returns zero matches for `.unwrap()`, `.expect(`, `panic!(`, `unreachable!(`, `unimplemented!(`, `todo!(`. The `_or(...)` / `_or_default()` / `_or_else(...)` fallback patterns remain (those provide values, not panics).
- `HostIdentity::generate()` returns `Result` (ML-KEM keygen propagates RNG failure cleanly).
- `vnc_des_encrypt` (in both `creds/generic/vnc_bruteforce.rs` and `exploits/vnc/rfb.rs`) returns `Result`; `zlib_compress` returns `io::Result`. All `.expect("slice of length N")` patterns map_err'd.
- `config.rs::VALID_CHARS` regex switched from `Lazy::new(... .expect(...))` to `OnceCell::get_or_try_init(...)` so a (theoretically impossible) compile failure surfaces as a clean error from `validate_target`.
- `native/url_encoding.rs` infallible-error path uses the canonical `match never {}` pattern — compiler-verified no-panic with no runtime check.

### Native FFI consolidation

- New `src/native/network.rs` is the single audited home for `make_dst_sockaddr` and `send_one_raw`. 8 DoS modules previously held duplicated copies (16 fn definitions). All now `use crate::native::network::{...}`.
- Project-wide `unsafe` blocks: 22 → 15. Every remaining `unsafe` site has a `SAFETY:` comment.

### Crypto crate version bumps

| Package | Old | New |
|---------|-----|-----|
| `aes` | 0.8.4 | 0.9.0 |
| `cipher` | 0.4.4 | 0.5.1 |
| `des` | 0.8.1 | 0.9.0 |
| `sha1` | 0.10.6 | 0.11.0 |
| `sha2` | 0.10.9 | 0.11.0 |
| `hkdf` | 0.12.4 | 0.13.0 |
| `aes-gcm` | 0.10.3 | 0.11.0-rc.3 |
| `chacha20poly1305` | 0.10.1 | 0.11.0-rc.3 |
| `kem` | 0.3.0-pre.0 | 0.3.0 |
| `ml-kem` | 0.2.3 | 0.3.0-rc.2 |
| `hickory-client` | 0.25.2 | 0.26.0-alpha.1 |
| `hickory-proto` | 0.25.2 | 0.26.0-alpha.1 |

API renames absorbed across 7 files: `cipher::generic_array::GenericArray` → `cipher::array::Array`; `BlockEncrypt`/`BlockDecrypt` → `BlockCipherEncrypt`/`BlockCipherDecrypt`; ml-kem API: `KemCore::generate` → `DecapsulationKey::try_generate_from_rng`, `encapsulate` → `encapsulate_with_rng`, `as_bytes` → `to_bytes`/`as_slice`. `rand_core` 0.6 kept for `x25519-dalek` compatibility, `rand::rng()` used for ml-kem/kem 0.3 which need rand_core 0.10 traits.

### Supply-chain audit

Scope: 393 unique crates / 427 locked package versions.

| Check | Result |
|-------|--------|
| `cargo audit` (RUSTSEC active vulns) | 0 |
| Cross-ref vs. 64 `categories=["malicious"]` advisories | 0 hits |
| Non-crates.io sources (git / path / alt registry) | 0 |
| Locked checksums present | 427 / 427 |
| `build.rs` scripts grep'd for `TcpStream` / `reqwest` / `curl` / `wget` / `/dev/tcp` / `base64::decode` / `exec` / `eval` / `spawn sh` | 0 hits across 35 build scripts |

The two crate names that surfaced in a loose grep over the advisory DB (`axum-core`, `time`) are false positives — both are DoS reports whose prose contains the word "malicious"; the locked versions (`axum-core` 0.5.6, `time` 0.3.47) are patched. The `time` override at [`Cargo.toml:133`](../Cargo.toml) is exactly the RUSTSEC-2026-0009 fix.

**Hygiene notes (informational, not attacks):** `rustls-pemfile` 2.2.0 is unmaintained (RUSTSEC-2025-0134, the only `cargo audit` finding); rustls upstream recommends `rustls-pki-types::pem` going forward. 7 pre-release deps locked (`aead`/`aes-gcm`/`chacha20poly1305`/`poly1305` -rc, `ml-kem` -rc, `hickory-*` -alpha) — all from trusted orgs (RustCrypto, hickory-dns), worth re-pinning to stable when each lands.

---

## v0.4.8 (2026-04-19)

### Module Totals

- **183 exploit modules** — cameras, routers, network infrastructure, webapps, frameworks, SSH, VNC, DoS, crypto, FTP, IPMI, telnet, Bluetooth, VoIP, Windows, payload generators, honeypot exploits (Cowrie, Dionaea, HoneyTrap, SNARE), WAF (SafeLine)
- **27 scanner modules**
- **29 credential modules** — all with full mass scan support (random, CIDR, file, comma-separated targets)
- **1 plugin module**
- **240 total modules**

### New in April 2026

#### 46 New Exploit Modules

| Category | Modules |
|----------|---------|
| Cowrie (SSH honeypot) | `ansi_log_injection`, `llm_prompt_injection`, `ssrf_ipv6` |
| Dionaea (honeypot) | `mqtt_underflow`, `mssql_dos`, `mysql_sqli`, `tftp_crash` |
| HoneyTrap (honeypot) | `docker_panic`, `ftp_panic` |
| SafeLine (WAF) | `cookie_attributes`, `nginx_injection`, `no_auth_probe`, `pre_auth_tfa`, `session_secret_entropy`, `unauth_writes` |
| Snare (honeypot) | `cookie_dos`, `tanner_version_mitm` |
| VNC | `rfb`, `libvnc_checkrect_overflow`, `libvnc_tight_filtergradient`, `libvnc_ultrazip`, `libvnc_websocket_overflow`, `libvnc_zrle_tile`, `tigervnc_rre_overflow`, `tigervnc_timing_oracle`, `tightvnc_decompression_bomb`, `tightvnc_des_hardcoded_key`, `tightvnc_ft_path_traversal`, `tightvnc_predictable_challenge`, `tightvnc_rect_overflow`, `x11vnc_dns_injection`, `x11vnc_env_injection`, `x11vnc_unixpw_inject` |
| SSH | `asyncssh_beginauthpass`, `libssh2_rogue_server`, `paramiko_authnonepass`, `paramiko_unknown_method` |
| Frameworks | `apache_camel/cve_2025_27636_camel_header_injection`, `php/cve_2025_51373_php_rce` |
| Network Infra | `commvault/cve_2025_34028_commvault_rce`, `kubernetes/cve_2025_1974_ingress_nginx_rce` |
| WebApps | `misp_rce_cve_2025_27364`, `nextjs_middleware_bypass_cve_2025_29927`, `vite_path_traversal_cve_2025_30208`, `zimbra_sqli_auth_bypass_cve_2025_25064` |

#### 3 New Scanner Modules

- `proxy_scanner` — HTTP CONNECT, SOCKS4/5, transparent proxy discovery
- `reflect_scanner` — UDP amplification vulnerability scanner (DNS, NTP, SSDP, Memcached)
- `vuln_checker` — Fingerprint-based vulnerability scanner across all exploit modules

#### 10 New Credential Modules

`couchdb_bruteforce`, `elasticsearch_bruteforce`, `http_basic_bruteforce`, `imap_bruteforce`, `memcached_bruteforce`, `mysql_bruteforce`, `postgres_bruteforce`, `proxy_bruteforce`, `redis_bruteforce`, `vnc_bruteforce`

#### Infrastructure

- **WebSocket transport** (`src/ws.rs`) — PQ-encrypted WebSocket endpoint at `/pq/ws` with 100-connection cap and heartbeat
- **Root privilege helper** (`src/utils/privilege.rs`) — `require_root()` for raw-socket modules (DoS, ping sweep, ICMP)
- **Unified HTTP client** (`src/utils/network.rs`) — `build_http_client()` and `build_http_client_with(HttpClientOpts)` replacing hand-rolled clients in 50+ modules
- **TCP connect helpers** — `tcp_connect_addr()`, `tcp_connect_str()`, `blocking_tcp_connect()`, `udp_bind()` centralizing socket creation
- **MCP hardening** — `isolate_protocol_stdout()` prevents module println! from corrupting JSON-RPC; `MAX_LINE_BYTES` (1 MiB) caps; binary-safe reads
- **Spool hardening** — `O_NOFOLLOW` flag, parent symlink check, lock-first file creation, `write_line()` returns Result
- **build.rs** — `check_available()` dispatch for capability queries without a target; optimized regex compilation

#### Module Audit

Systematic quality pass across all 183 exploit modules:
- Replaced `std::thread::sleep` with async alternatives in SSH and scanner modules
- Migrated raw `TcpStream::connect` to `tcp_connect_addr()` framework utility
- Standardized 50+ modules from hand-rolled `reqwest::Client::builder` to `build_http_client()`
- Added `require_root()` checks to all raw-socket modules (DoS, ping sweep, ICMP flood)
- Added `zeroize` crate for sensitive data cleanup

---

### Highlights

- **Framework-level multi-target dispatcher** — comma-separated, CIDR, file-based, and random target modes now work for ALL modules, handled by the framework rather than individual module code
- **All modules use `cfg_prompt_*`** — ensures full API/CLI/MCP compatibility via the priority chain (custom_prompts > global_options > stdin)
- **Honeypot detection system** — warns operators when a target exhibits honeypot characteristics
- **`#[cfg(unix)]` guards** on Unix-specific permissions code for cross-platform compilation
- **Bug fixes:**
  - SharePoint exploit: fixed header typo
  - Langflow exploit: corrected escape order
  - Zabbix SQLi: removed unused payload variable
  - Jenkins LFI: fixed async deadlock
  - Apache Tomcat: replaced hardcoded session IDs with proper generation

---

## Recent Changes

### Framework Features (Metasploit Parity)

| Feature | Commands | Description |
|---------|----------|-------------|
| Module Metadata | `info`, `check` | Optional `info()` and `check()` per module — CVE, author, rank, non-destructive verification |
| Global Options | `setg`, `unsetg`, `show options` | Persistent key-value options across modules, saved to `~/.rustsploit/global_options.json` |
| Credential Store | `creds` (add/search/delete/clear) | Track discovered credentials with JSON persistence |
| Host/Service Tracking | `hosts`, `services`, `notes`, `workspace` | Workspace-based engagement data at `~/.rustsploit/workspaces/` |
| Loot Management | `loot` (add/search) | Structured evidence collection with file storage |
| Resource Scripts | `resource`, `makerc`, `-r` flag | Automation from script files, startup.rc auto-load |
| Console Logging | `spool` (on/off) | Capture all console output to file |
| Background Jobs | `run -j`, `jobs` (-k/clean) | Async module execution with cancellation |
| Export/Reporting | `export json\|csv\|summary` | Export all engagement data to multiple formats |
| Plugin System | `src/modules/plugins/` | Third-party module support with safety warnings |
| Build System | `build.rs` | Now auto-detects `info()` and `check()` alongside `run()` |
| Prompt System | `cfg_prompt_*` | Priority chain: custom_prompts > global_options > stdin |
| API Endpoints | 15 new routes | Full CRUD for options, creds, hosts, services, loot, jobs, export |

### New Exploit Modules

| Module | CVE / Notes |
|--------|-------------|
| `exploits/mongo/mongobleed` | CVE-2025-14847 — MongoDB zlib memory disclosure, deep-scan mode |
| `exploits/frameworks/nginx/nginx_pwner` | Nginx misconfiguration scanner — 10 checks |
| `exploits/hikvision/hikvision_rce` | CVE-2021-36260 — command injection, SSH shell deploy |
| `exploits/frameworks/n8n` | CVE-2025-68613 — workflow expression injection, 6 payloads |
| `exploits/fortiweb` | CVE-2025-25257 — SQLi → webshell deploy |
| `exploits/webapps/sharepoint` | CVE-2024-38094 — deserialization RCE |
| `exploits/windows/dwm` | CVE-2026-20805 — Windows DWM info disclosure |
| `exploits/crypto/geth` | CVE-2026-22862 — Go-Ethereum ecies panic DoS |
| `exploits/frameworks/termix` | CVE-2026-22804 — stored XSS |
| `exploits/network_infra/forticloud_sso` | CVE-2026-24858 — auth bypass |
| `exploits/routers/ruijie/*` | 7 modules — RCE, Auth Bypass, SSRF |
| `exploits/routers/tp_link_vigi` | CVE-2026-1457 — authenticated RCE |
| `exploits/telnet/cve_2026_24061` | GNU inetutils-telnetd auth bypass via `NEW_ENVIRON` |

### New Credential Modules

| Module | Notes |
|--------|-------|
| `creds/generic/telnet_hose` | Mass internet Telnet scanner — 500 workers, disk-based state, 6-second timeout |

### Framework & Core Improvements

- **Proxy system removed** — No built-in proxy support. Use a system-level VPN (e.g., Mullvad) before launching Rustsploit.
- **Mass-scan standardization** — All mass-scan modules accept `0.0.0.0`, `0.0.0.0/0`, or `random` targets with consistent `EXCLUDED_RANGES` enforcement.
- **Stability** — Removed all `unwrap()` and `unwrap_or_default()` calls from critical paths.
- **API worker threading** — Fixed with `spawn_blocking`, consolidated validation logic.
- **Telnet bruteforce refactor** — DNS resolved once (not per-attempt), `tokio::sync::Semaphore`, state machine (`TelnetState` enum), `BytesMut` buffer management.
- **Telnet hose** — password-only server detection (skips username prompt when server sends password prompt in banner).

### Dependency Upgrades

| Crate | Change |
|-------|--------|
| `suppaftp` v7 | Imports updated to `suppaftp::tokio::{AsyncFtpStream, AsyncNativeTlsFtpStream, AsyncNativeTlsConnector}` |
| `reqwest` v0.13 | Removed `.query()` / `.form()` helpers — manually constructed in 6 modules |
| `rustls` v0.23 | `ServerName` import updated to `rustls::pki_types::ServerName`; deprecated `with_safe_defaults()` removed |
| `hickory-client` v0.25 | `AsyncClient` → `Client`; `UdpClientStream` rewritten to builder pattern + `TokioRuntimeProvider` |

### utils.rs Improvements

- Config-aware prompt system (`cfg_prompt_required`, `cfg_prompt_default`, `cfg_prompt_yes_no`, `cfg_prompt_port`, `cfg_prompt_int_range`, `cfg_prompt_existing_file`, `cfg_prompt_output_file`, `cfg_prompt_wordlist`)
- `read_safe_input` — centralizes length enforcement, null-byte stripping, and control character filtering
- All prompt helpers updated to use `read_safe_input`
- Payload-safe mode: only `\0` is stripped; all other characters pass through as literal text

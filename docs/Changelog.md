# Changelog

A high-level summary of significant changes. For the full detailed log, see [`changelogs/changelog-latest.md`](../changelogs/changelog-latest.md).

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

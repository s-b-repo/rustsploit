# Changelog

A high-level summary of significant changes. For the full detailed log, see [`changelogs/changelog-latest.md`](../changelogs/changelog-latest.md).

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

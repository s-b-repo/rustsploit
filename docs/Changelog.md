# Changelog

A high-level summary of significant changes. For the full detailed log, see [`changelogs/changelog-latest.md`](../changelogs/changelog-latest.md).

---

## v0.4.8 (2026-04-03)

### Module Totals

- **137 exploit modules** (24 with `check()`) — cameras, routers, network infrastructure, webapps, frameworks, SSH, DoS, crypto, FTP, IPMI, telnet, Bluetooth, VoIP, Windows, payload generators
- **24 scanner modules**
- **28 credential modules** — all with full mass scan support (random, CIDR, file, comma-separated targets)
- **1 plugin module**
- **190 total modules**

### Highlights

- **20 new exploit modules** — XWiki RCE, Dify default creds, SolarWinds WHD, MCPJam RCE, Langflow RCE, SAP NetWeaver (CVSS 10.0), SharePoint ToolPane, Craft CMS x2, Laravel Livewire, CitrixBleed 2, HPE OneView (CVSS 10.0), F5 BIG-IP, SonicWall SMA, Ivanti ICS x2, Tomcat PUT, WSUS, Erlang SSH (CVSS 10.0), FreePBX
- **8 new scanners** — ssl_scanner, service_scanner, redis_scanner, vnc_scanner, snmp_scanner, waf_detector, subdomain_scanner, nbns_scanner
- **9 new credential modules** — vnc, imap, mysql, postgres, redis, elasticsearch, couchdb, memcached, http_basic bruteforce
- **MCP integration** — Model Context Protocol server with 30 tools and 7 resources for Claude Desktop and external tool connectivity
- **Payload mutation engine** — 9 WAF bypass strategies (URL encode, case toggle, comment injection, unicode homoglyph, etc.) in `src/native/payload_engine.rs`
- **Native RDP bruteforce** — TCP+TLS+CredSSP/NTLM authentication, no xfreerdp/rdesktop dependency
- **Mass scan engine unification** — shared `run_mass_scan()` engine replaced ~900 lines of duplicated code across 13 cred modules
- **Bruteforce uplift** — ETA countdown, exponential backoff with jitter, account lockout detection across all 10 active bruteforce modules
- **Output system rewrite** — task-local `mprintln!` macros replace 4683 println! calls, enabling concurrent API module execution
- **Async prompts** — all cfg_prompt_* functions now async via `spawn_blocking`, freeing the tokio runtime during stdin reads
- **Source port binding** — `set source_port` for firewall bypass testing across TCP, UDP, and SSH connections
- **Streaming wordlists** — 100GB+ password files processed with constant memory via chunked streaming
- **WPair BLE exploit** — 51 device database, 6 exploit strategies, TUI mode, headless API mode
- **Framework-level multi-target dispatcher** — comma-separated, CIDR, file-based, and random target modes work for ALL 190 modules
- **All modules use `cfg_prompt_*`** — ensures full API/CLI/MCP compatibility via the priority chain (custom_prompts > global_options > stdin)
- **Honeypot detection system** — warns operators when a target exhibits honeypot characteristics
- **4-round security audit** — 32+ bug fixes across 22 files (path traversal, SSRF, race conditions, silent save failures, input validation)
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

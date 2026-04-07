# Future Features Roadmap

Rustsploit is under active development. Below are some of the major features planned for upcoming releases.

## Recently Completed

### 3rd-Party Plugin System
The `plugins/` directory is now fully operational. Drop `.rs` files into `src/modules/plugins/` with the standard `pub async fn run(target: &str)` signature and they are auto-discovered at build time. A safety warning is displayed at shell and API startup when plugins are loaded.

### Framework Services (Metasploit Parity)
The following Metasploit-inspired features have been implemented:
- **Module Metadata** (`info` command) — CVE, author, rank, description per module
- **Vulnerability Check** (`check` command) — Non-destructive verification
- **Global Options** (`setg`/`unsetg`) — Persistent options across modules
- **Credential Store** (`creds`) — Track discovered credentials with JSON persistence
- **Host/Service Tracking** (`hosts`/`services`) — Workspace-based engagement data
- **Loot Management** (`loot`) — Structured evidence collection
- **Resource Scripts** (`resource`) — Automation from script files
- **Console Logging** (`spool`) — Capture all output to file
- **Background Jobs** (`run -j`/`jobs`) — Async module execution
- **Export/Reporting** (`export`) — JSON, CSV, and summary reports

### MCP Integration
Model Context Protocol server with 30 tools and 7 resources for programmatic access from Claude Desktop and other MCP-compatible clients. Supports module execution, target management, credential/host/loot tracking, and data export via JSON-RPC 2.0 over stdio.

### Payload Mutation Engine
Dynamic payload mutation with 9 WAF bypass strategies (URL encode, double URL, case toggle, comment injection, whitespace swap, concat/split, null byte, unicode homoglyph, boundary wrap) in `src/native/payload_engine.rs`.

### Native RDP Authentication
Pure Rust TCP+TLS+CredSSP/NTLM brute force — no xfreerdp or rdesktop dependency. 10-50x faster than CLI process spawning.

### Mass Scan Engine Unification
Shared `run_mass_scan()` engine with `MassScanConfig` replaced ~900 lines of duplicated mass scan code across 13 credential modules. Single source of truth for exclusion ranges, state tracking, and progress reporting.

### Source Port Binding
Framework-level `set source_port` command for firewall bypass testing. Applied to TCP, UDP, and SSH connections via `tcp_connect()`, `udp_bind()`, and `blocking_tcp_connect()` helpers.

---

## Planned Features

### 1. Instant Configuration Loading
Currently, modules are configured interactively or via API JSON payloads. We plan to add support for instantly loading configuration profiles from disk.
- **Goal:** Allow users to save their favorite scan parameters (wordlists, threads, timeouts) to a `.toml` or `.yaml` file and load them instantly.
- **Usage Idea:** `run exploits/tomcat_rce --config profiles/aggressive.toml` or `set config profiles/aggressive.toml` in the shell.

### 2. Session/Handler Management
Add Metasploit-style session management with reverse/bind shell handlers.
- **Goal:** Multi/handler listener, session listing/interaction, background sessions.
- **Implementation:** Listener framework with TCP/HTTP handlers, session tracking with numeric IDs.

### 3. Post-Exploitation Modules
Add a `post/` module category for post-exploitation tasks.
- **Goal:** Privilege escalation checks, persistence mechanisms, credential extraction, lateral movement.
- **Implementation:** New module category auto-discovered by build.rs.

### 4. Network Pivoting
Route traffic through compromised hosts.
- **Goal:** SOCKS proxy, port forwarding, autoroute through sessions.
- **Implementation:** Requires session management (Feature 3) first.

### 5. Nmap Integration
Import scan results directly into the workspace.
- **Goal:** `db_import` command for Nmap XML, populate hosts/services automatically.
- **Implementation:** Parse Nmap XML output and feed into workspace.

---

*If you'd like to contribute to any of these features, please check out the [Contributing Guide](Contributing.md) and open a pull request!*

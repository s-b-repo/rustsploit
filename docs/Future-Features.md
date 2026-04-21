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

---

## Planned Features

### 1. Instant Configuration Loading
Currently, modules are configured interactively or via API JSON payloads. We plan to add support for instantly loading configuration profiles from disk.
- **Goal:** Allow users to save their favorite scan parameters (wordlists, threads, timeouts) to a `.toml` or `.yaml` file and load them instantly.
- **Usage Idea:** `run exploits/tomcat_rce --config profiles/aggressive.toml` or `set config profiles/aggressive.toml` in the shell.

### 2. Dynamic Source Port Modification
While we currently support advanced networking like IP spoofing in specific flood modules, we plan to bring dynamic source port control to the framework level.
- **Goal:** Allow scanners and exploit modules to bind to specific source ports (e.g., source port 53) to bypass poorly configured firewalls that trust traffic originating from privileged ports.
- **Implementation:** Extending the global configuration and socket helpers to accept an optional `bind_port` parameter.

### 3. Session/Handler Management
Add Metasploit-style session management with reverse/bind shell handlers.
- **Goal:** Multi/handler listener, session listing/interaction, background sessions.
- **Implementation:** Listener framework with TCP/HTTP handlers, session tracking with numeric IDs.

### 4. Post-Exploitation Modules
Add a `post/` module category for post-exploitation tasks.
- **Goal:** Privilege escalation checks, persistence mechanisms, credential extraction, lateral movement.
- **Implementation:** New module category auto-discovered by build.rs.

### 5. Network Pivoting
Route traffic through compromised hosts.
- **Goal:** SOCKS proxy, port forwarding, autoroute through sessions.
- **Implementation:** Requires session management (Feature 3) first.

### 6. Nmap Integration
Import scan results directly into the workspace.
- **Goal:** `db_import` command for Nmap XML, populate hosts/services automatically.
- **Implementation:** Parse Nmap XML output and feed into workspace.

---

*If you'd like to contribute to any of these features, please check out the [Contributing Guide](Contributing.md) and open a pull request!*

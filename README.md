# Rustsploit 

Modular offensive tooling for embedded targets, written in Rust and inspired by RouterSploit/Metasploit. One binary exposes the same module library through **four interfaces** — an interactive shell, a command-line runner, a post-quantum-encrypted REST/WebSocket API, and an MCP server — over an ever-growing library of exploits, scanners, and credential modules for routers, cameras, appliances, and general network services, with **Recog** service fingerprinting and **JARM/JA3** TLS fingerprinting built in.

> **Latest release:** see [`RELEASE_NOTES.txt`](RELEASE_NOTES.txt) — official `rmcp` MCP SDK, Recog + JARM/JA3/JA3S fingerprinting, a SecLists wordlist catalog, per-run output auto-save, HTTP connection pooling, and mass-scan fixes.


![Rustsploit Interactive Shell Demo](https://github.com/s-b-repo/rustsploit/raw/main/preview.png)

![Rustsploit Testing View](https://github.com/s-b-repo/rustsploit/raw/main/testing.png)

---

## 📖 Wiki & Documentation

Full documentation lives in the **[Rustsploit Wiki](docs/Home.md)**. Below is a quick index — click through for detailed guides, examples, and reference material.

| Document | Description |
|----------|-------------|
| [Getting Started](docs/Getting-Started.md) | Installation, build, quick-start, Docker deployment |
| [Interactive Shell](docs/Interactive-Shell.md) | Shell walkthrough, command palette, chaining, shortcuts |
| [CLI Reference](docs/CLI-Reference.md) | Command-line flags, non-shell usage, output formats |
| [API Server](docs/API-Server.md) | REST + WebSocket API, PQ encryption, endpoints, rate limiting |
| [API Usage Examples](docs/API-Usage-Examples.md) | Practical curl workflows, request/response samples |
| [Module Catalog](docs/Module-Catalog.md) | All modules by category — exploits, scanners, creds |
| [Module Development](docs/Module-Development.md) | How to author new modules, lifecycle, dispatcher |
| [Bad Patterns Catalogue](docs/BAD_PATTERNS.md) | 133-regex `grep` matrix every module must pass — banned `.unwrap`, swallow, panic, blocking-IO, lossy casts, crypto, injection, etc. Re-runnable via `scripts/audit-bad-patterns.sh` |
| [Bad Patterns Audit Report](docs/audit-report.md) | Latest whole-tree snapshot — strict-mode result on the 100 authored modules (zero hits) and observational counts on the rest of the framework |
| [Security & Validation](docs/Security-Validation.md) | Input validation, security patterns, honeypot detection |
| [Credential Modules Guide](docs/Credential-Modules-Guide.md) | Best practices for brute-force / cred modules |
| [Exploit Modules Guide](docs/Exploit-Modules-Guide.md) | Best practices for exploit modules |
| [Utilities & Helpers](docs/Utilities-Helpers.md) | `utils.rs` public API, target normalization, honeypot check |
| [Testing & QA](docs/Testing-QA.md) | Build checks, smoke tests, wordlist validation |
| [Changelog](docs/Changelog.md) | Release notes and version history |
| [Contributing](docs/Contributing.md) | Fork guide, PR checklist, code style |
| [Credits](docs/Credits.md) | Authors, acknowledgements, legal notice |

---

## Highlights

-  **Self-registering modules:** modules register at compile time via the `inventory` crate — add the file, a `register_native_module!` call, and a `pub mod <name>;` line in the parent `mod.rs`; no build-script indexer
-  **Interactive shell:** 40+ commands with shortcuts, command chaining (`&`), tab completion, and command history
-  **Module metadata:** `info()` per module — CVE references, author, rank. The framework is exploitation-only: modules run an exploit and report findings (there is no `check()` / non-destructive verification phase)
-  **Global options (`setg`):** Persistent key-value settings that apply across all modules — like Metasploit's datastore
-  **Credential store:** Track discovered credentials across sessions with `creds` commands and JSON persistence
-  **Host/service tracking:** Workspace-based engagement tracking with `hosts`, `services`, `notes` commands
-  **Loot management:** Structured evidence collection with file storage and metadata indexing
-  **Resource scripts:** Automate workflows from files, auto-load startup scripts, save command history with `makerc`
-  **Background jobs:** Run modules asynchronously with `run -j`, manage with `jobs` commands
-  **Export/reporting:** Export all engagement data to JSON, CSV, or human-readable summary reports
-  **Console logging & auto-save:** `spool` captures all output to a file on demand; in addition, **every console/CLI module run is auto-saved** (append mode) to `~/.rustsploit/loot/<module> <time> results.txt` — stdout and stderr both captured, multi-host sweeps accumulate into one per-run file
-  **Comprehensive credential tooling:** FTP(S), SSH, Telnet, POP3(S), SMTP, IMAP, RDP, RTSP, SNMP, L2TP, MQTT, VNC, MySQL, PostgreSQL, Redis, CouchDB, Elasticsearch, Memcached, HTTP Basic, Proxy, Fortinet — with IPv6 and TLS support
-  **Exploit coverage:** CVEs for VNC (LibVNC, TigerVNC, TightVNC, x11vnc), honeypots (Cowrie, Dionaea, HoneyTrap, SNARE), WAFs (SafeLine), Apache Camel, Kubernetes ingress-nginx, Commvault, MISP, Zimbra, Next.js, Vite, and 100+ more
-  **Scanners & utilities:** Port scanner, ping sweep, SSDP, HTTP title grabber, DNS recursion tester, directory bruteforcer, sequential fuzzer, proxy scanner, reflect scanner, vulnerability checker
-  **Service & TLS fingerprinting:** Rapid7 **Recog** banner → product/version/CPE matching folded into service detection, plus Salesforce **JARM** + **JA3/JA3S** active TLS server fingerprinting (`scanners/jarm_scan`)
-  **Wordlist catalog:** checksum-pinned **SecLists** wordlists fetched + SHA-256-verified on demand into `~/.rustsploit/wordlists/` (`utils::wordlist::resolve`)
-  **Performance:** shared, cached HTTP client — TLS config + connection pool reused across runs instead of rebuilt per request, with a bounded idle timeout for internet-scale sweeps
-  **API server:** PQ-encrypted WebSocket transport — post-quantum cryptography, full CRUD for credentials, hosts, services, loot, jobs
-  **MCP server:** Model Context Protocol server on the **official `rmcp` SDK (v1.7)** — 29 tools + 7 resources for AI-assisted pentesting via stdio
-  **Plugin system:** Third-party modules via `src/modules/plugins/` with compile-time `inventory` self-registration and startup safety warnings
-  **Security hardened:** Input validation, path traversal protection, honeypot detection, root privilege checks, spool symlink protection, memory-safe operations
-  **IPv4/IPv6 ready:** Both address families work out-of-the-box across all modules

---

## Quick Start

**One command** (Debian/Ubuntu/Kali):

```bash
sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev libdbus-1-dev cmake && (command -v cargo > /dev/null 2>&1 || (curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && . "$HOME/.cargo/env")) && git clone https://github.com/s-b-repo/rustsploit.git && cd rustsploit && cargo run
```
## How to turn Bluetooth OFF (e.g. on FreeBSD without Bluetooth hardware):

```
cargo build --no-default-features
```
## or
```
cargo run --no-default-features
```
## How to turn Bluetooth ON
```
cargo build --features bluetooth
```
## or
```
cargo run --features bluetooth
```

<details>
<summary>What each dependency does</summary>

| Package | Required by | Why |
|---------|------------|-----|
| `build-essential` | Native crate compilation | gcc, make, libc headers |
| `pkg-config` | `native-tls`, `ssh2` | Finds system libraries at build time |
| `libssl-dev` | `native-tls`, `ssh2` | OpenSSL headers for TLS and SSH |
| `libdbus-1-dev` | `btleplug` | D-Bus IPC for Bluetooth scanning |
| `cmake` | `ssh2` (libssh2-sys) | Builds libssh2 from source |


</details>

For other distros (Arch, Gentoo, Fedora), Docker deployment, and one-liner installs, see **[Getting Started](docs/Getting-Started.md)**.

---

## Quick Navigation

- **New user?** → [Getting Started](docs/Getting-Started.md)
- **Writing a module?** → [Module Development](docs/Module-Development.md)
- **Using the API?** → [API Server](docs/API-Server.md) + [API Usage Examples](docs/API-Usage-Examples.md)
- **Running from CLI?** → [CLI Reference](docs/CLI-Reference.md)
- **Full module list?** → [Module Catalog](docs/Module-Catalog.md)

---

## API server quick start

The PQ-encrypted API is what external integrations and web panels talk to.
Bind it to whichever interface you want — the bootstrap path is gated by a
one-time enrollment token printed at startup, **not** by the bind address.

```bash
# Local-only (default, useful for development)
cargo run --release -- --api

# Reachable on a LAN
cargo run --release -- --api --interface 192.0.2.10:8080

# Reachable from anywhere (bind to all interfaces)
cargo run --release -- --api --interface 0.0.0.0:8080
```

On startup the server prints something like:

```
═══════════════════════════════════════════════════════════════
ENROLLMENT TOKEN (one-time, prints once): tWQ9sIz3kZGdHc4w7g8hPxJrAaPN1c0v
Bootstrap a client by POSTing its PQ public keys + this
token to POST /pq/register-key:
  { token, name, x25519_pub, mlkem_ek }
After first successful registration the token is consumed; further
key changes must go through the established PQ session.
═══════════════════════════════════════════════════════════════
```

Hand that token to whichever client you want to enroll. The client POSTs
its X25519 + ML-KEM-768 public keys to `/pq/register-key` over the
network — no shared filesystem required, client and server can be on
different hosts. The token is consumed on first use; restart the server
to issue a new one.

Endpoints exposed by `--api`:

| Path | Auth | Purpose |
|------|------|---------|
| `GET /health` | none | Liveness |
| `POST /pq/handshake` | identity allowlist | PQXDH session establishment |
| `POST /pq/register-key` | enrollment token (one-time) | Bootstrap a new client identity |
| `GET /pq/ws` | PQ session | Bi-directional event/RPC channel |
| `ALL /api/*` | PQ session | REST surface (auto-generated from JSON-RPC dispatcher) |

---

## Private Internet Recommendations

The built-in proxy system has been removed in favor of system-level VPN solutions. We recommend **[Mullvad VPN](https://mullvad.net)** for its no-registration, audited no-logs policy, WireGuard support, and excellent Linux CLI. Simply connect your VPN before running the tool — all traffic routes through the tunnel.

---

## Contributing

Contributions welcome! See the **[Contributing Guide](docs/Contributing.md)** for the full process. In short:

1. Fork + branch from `main`
2. Add your module under the appropriate category
3. Run `cargo fmt` and `cargo check` before opening a PR

---

## Credits

- **Project Lead:** s-b-repo
- **Language:** 100% Rust
- **Inspired by:** RouterSploit, Metasploit Framework, pwntools

> ⚠️ Rustsploit is intended for authorized security testing and research purposes only. Obtain explicit permission before targeting any system you do not own.

---

<details>
<summary><sub>Support this project</sub></summary>
<p align="center"><br/>
If this tool saved you time, consider tossing $1 in Monero:<br/><br/>
<code>478Lb78LDscQ8ukEDTZqXgEtjoBX1jMuVGvgfy2RagxZZk89YuyVYsganfLUKnwggz8YiBxhG25yWWiHUppG9uarSiseseY</code><br/><br/>
<sub>XMR — private, untraceable, appreciated.</sub>
</p>
</details>
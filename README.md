# Rustsploit 

Modular offensive tooling for embedded targets, written in Rust and inspired by RouterSploit/Metasploit. Rustsploit ships an interactive shell, a command-line runner, and an ever-growing library of exploits, scanners, and credential modules for routers, cameras, appliances, and general network services.

![Screenshot](https://github.com/s-b-repo/rustsploit/raw/main/preview.png)
![Screenshot](https://github.com/s-b-repo/rustsploit/raw/main/testing.png)

---

## 📖 Wiki & Documentation

Full documentation lives in the **[Rustsploit Wiki](docs/Home.md)**. Below is a quick index — click through for detailed guides, examples, and reference material.

| Document | Description |
|----------|-------------|
| [Getting Started](docs/Getting-Started.md) | Installation, build, quick-start, Docker deployment |
| [Interactive Shell](docs/Interactive-Shell.md) | Shell walkthrough, command palette, chaining, shortcuts |
| [CLI Reference](docs/CLI-Reference.md) | Command-line flags, non-shell usage, output formats |
| [API Server](docs/API-Server.md) | REST API startup, endpoints, auth, rate limiting, hardening |
| [API Usage Examples](docs/API-Usage-Examples.md) | Practical curl workflows, request/response samples |
| [Module Catalog](docs/Module-Catalog.md) | All modules by category — exploits, scanners, creds |
| [Module Development](docs/Module-Development.md) | How to author new modules, lifecycle, dispatcher |
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

-  **Auto-discovered modules:** `build.rs` indexes `src/modules/**` — drop in new code, no manual registration needed
-  **Interactive shell:** 40+ commands with shortcuts, command chaining (`&`), tab completion, and command history
-  **Module metadata:** Optional `info()` and `check()` functions per module — CVE references, author, rank, non-destructive vulnerability verification
-  **Global options (`setg`):** Persistent key-value settings that apply across all modules — like Metasploit's datastore
-  **Credential store:** Track discovered credentials across sessions with `creds` commands and JSON persistence
-  **Host/service tracking:** Workspace-based engagement tracking with `hosts`, `services`, `notes` commands
-  **Loot management:** Structured evidence collection with file storage and metadata indexing
-  **Resource scripts:** Automate workflows from files, auto-load startup scripts, save command history with `makerc`
-  **Background jobs:** Run modules asynchronously with `run -j`, manage with `jobs` commands
-  **Export/reporting:** Export all engagement data to JSON, CSV, or human-readable summary reports
-  **Console logging:** `spool` command captures all output to file for documentation
-  **Comprehensive credential tooling:** FTP(S), SSH, Telnet, POP3(S), SMTP, RDP, RTSP, SNMP, L2TP, MQTT, Fortinet — with IPv6 and TLS support
-  **Exploit coverage:** CVEs for GNU inetutils-telnetd, Apache Tomcat, TP-Link, Ivanti, Zabbix, OpenSSH, Jenkins, PAN-OS, Heartbleed, and more
-  **Scanners & utilities:** Port scanner, ping sweep, SSDP, HTTP title grabber, DNS recursion tester, directory bruteforcer, sequential fuzzer
-  **REST API server:** 30+ endpoints — authentication, rate limiting, IP tracking, full CRUD for credentials, hosts, services, loot, jobs
-  **Plugin system:** Third-party modules via `src/modules/plugins/` with build-time discovery and startup safety warnings
-  **Security hardened:** Input validation, path traversal protection, honeypot detection, memory-safe operations
-  **IPv4/IPv6 ready:** Both address families work out-of-the-box across all modules

---

## Quick Start

```bash
# Install dependencies (Debian/Ubuntu/Kali)
sudo apt update
sudo apt install pkg-config libssl-dev rustc libdbus-1-dev freerdp2-x11

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone & build
git clone https://github.com/s-b-repo/rustsploit.git
cd rustsploit
cargo build

# Run
cargo run
```

For other distros (Arch, Gentoo, Fedora), Docker deployment, and one-liner installs, see **[Getting Started](docs/Getting-Started.md)**.

---

## Quick Navigation

- **New user?** → [Getting Started](docs/Getting-Started.md)
- **Writing a module?** → [Module Development](docs/Module-Development.md)
- **Using the API?** → [API Server](docs/API-Server.md) + [API Usage Examples](docs/API-Usage-Examples.md)
- **Running from CLI?** → [CLI Reference](docs/CLI-Reference.md)
- **Full module list?** → [Module Catalog](docs/Module-Catalog.md)

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

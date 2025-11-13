# Rustsploit 🛠️

Modular offensive tooling for Pentesting, internal and external networks. written in Rust and inspired by RouterSploit/Metasploit. Rustsploit ships an interactive shell, a command-line runner, rich proxy support, and an ever-growing library of exploits, scanners, and credential modules for routers, cameras, appliances, and general network services.

![Screenshot](https://github.com/s-b-repo/rustsploit/raw/main/preview.png)

- 📚 **Developer Docs:** [Full guide covering module lifecycle, proxy logic, shell flow, and dispatcher](https://github.com/s-b-repo/rustsploit/blob/main/docs/readme.md)
- 💬 **Interactive Shell:** Ergonomic command palette with shortcuts (e.g., `f1 ssh`, `u exploits/heartbleed`, `go`)
- 🌐 **Proxy Smartness:** Supports HTTP(S), SOCKS4/4a/5 (with hostname resolution), validation, and automatic rotation
- 🧱 **IPv4/IPv6 Ready:** Credential modules and sockets normalize targets so both address families work out-of-the-box

---

## Table of Contents

1. [Highlights](#highlights)
2. [Module Catalog](#module-catalog)
3. [Quick Start](#quick-start)
4. [Interactive Shell Walkthrough](#interactive-shell-walkthrough)
5. [CLI Usage](#cli-usage)
6. [API Server Mode](#api-server-mode)
7. [Proxy Workflow](#proxy-workflow)
8. [How Modules Are Discovered](#how-modules-are-discovered)
9. [Contributing](#contributing)
10. [Credits](#credits)

---

## Highlights

- ✅ **Auto-discovered modules:** `build.rs` indexes `src/modules/**` so new code drops in without manual registration
- ✅ **Interactive shell with color and shortcuts:** Quick command palette, target/module state tracking, alias commands (`help/?`, `modules/m`, `run/go`, etc.)
- ✅ **Ergonomic proxy system:** Load lists, validate availability, choose concurrency/timeouts, and rotate automatically on failure
- ✅ **Comprehensive credential tooling:** FTP(S), SSH, Telnet, POP3(S), SMTP, RDP, RTSP brute force modules with IPv6 and TLS support where applicable
- ✅ **Exploit coverage:** Apache Tomcat, Abus security cameras, Ivanti Connect Secure, TP-Link, Zabbix, Avtech cameras, Spotube, OpenSSH race condition, and more
- ✅ **Scanners & utilities:** Port scanner, ping sweep, SSDP discovery, HTTP title grabber, StalkRoute traceroute (root), sample modules for extension
- ✅ **Payload generation:** Batch malware dropper (`narutto_dropper`), BAT payload generator, custom credential checkers
- ✅ **Readable output:** Colored prompts, structured status messages, optional verbose logs and result persistence
- ✅ **REST API Server:** Launch a secure API server with authentication, rate limiting, IP tracking, and dynamic key rotation

---

## Module Catalog

Rustsploit ships categorized modules under `src/modules/`, automatically exposed to the shell/CLI. A non-exhaustive snapshot:

| Category | Highlights |
|----------|------------|
| `creds/generic` | FTP anonymous & FTPS brute force, SSH brute force, Telnet brute force, POP3(S) brute force, SMTP brute force, RTSP brute force (path + header bruting), RDP auth-only brute |
| `exploits/*` | Apache Tomcat (CVE-2025-24813 RCE, CatKiller CVE-2025-31650), TP-Link VN020 / WR740N DoS, Abus camera CVE-2023-26609 variants, Ivanti Connect Secure stack buffer overflow, Zabbix 7.0.0 SQLi, Avtech CVE-2024-7029, Spotube zero-day, OpenSSH 9.8p1 race condition, Uniview password disclosure, ACTi camera RCE |
| `scanners` | Port scanner, ping sweep, SSDP M-SEARCH enumerator, HTTP title fetcher, StalkRoute traceroute (firewall evasion) |
| `payloadgens` | `narutto_dropper`, BAT payload generator |
| `lists` | RTSP wordlists and helper files |

Run `modules` or `find <keyword>` in the shell for the authoritative list.

---

## Quick Start

### Requirements

```bash
sudo apt update
sudo apt install freerdp2-x11    # Required for the RDP brute force module
```

Ensure Rust and Cargo are installed (https://www.rust-lang.org/tools/install).

### Clone + Build

```bash
git clone https://github.com/s-b-repo/rustsploit.git
cd rustsploit
cargo build
```

### Run (Interactive Shell)

```bash
cargo run
```

### Install (optional)

```bash
cargo install --path .
```

---

## Interactive Shell Walkthrough

The shell tracks current module, target, and proxy state. All commands are case-insensitive and support aliases:

```text
RustSploit Command Palette
Command          Shortcuts                Description
--------------- ------------------------- ------------------------------
help             help | h | ?             Show this screen
modules          modules | ls | m         List discovered modules
find             find <kw> | f1 <kw>      Search modules by keyword
use              use <path> | u <path>    Select module (ex: u exploits/heartbleed)
set target       set target <value>       Set current target (IPv4/IPv6/hostname)
run              run | go                 Execute current module (honors proxy mode)
proxy_load       proxy_load [file] | pl   Load proxies from file (HTTP/HTTPS/SOCKS)
proxy_on/off     proxy_on | pon / ...     Toggle proxy usage
proxy_test       proxy_test | ptest       Validate proxies (URL, timeout, concurrency)
show_proxies     show_proxies | proxies   View proxy status
exit             exit | quit | q          Leave shell
```

Example session:

```text
rsf> f1 ssh
rsf> u creds/generic/ssh_bruteforce
rsf> set target 10.10.10.10
rsf> pl data/proxies.txt    # prompts if omitted
rsf> pon
rsf> proxy_test             # optional validation / filtering
rsf> go
```

If proxy mode is enabled, Rustsploit rotates through validated proxies, falls back to direct mode only after exhaustion, and politely reports successes or errors.

---

## CLI Usage

Modules can be executed without the shell using the `--command`, `--module`, and `--target` flags:

```bash
# Exploit
cargo run -- --command exploit --module heartbleed --target 192.168.1.1

# Scanner
cargo run -- --command scanner --module port_scanner --target 192.168.1.1

# Credentials
cargo run -- --command creds --module ssh_bruteforce --target 192.168.1.1
```

Any module exposed to the shell can be called here. Use the `modules` shell command or browse `src/modules/**` for canonical names.

---

## API Server Mode

Rustsploit includes a REST API server mode that allows remote control of the tool via HTTP endpoints. The API includes authentication, rate limiting, IP tracking, and security hardening features.

### Starting the API Server

```bash
# Basic API server (defaults to 0.0.0.0:8080)
cargo run -- --api --api-key your-secret-key-here

# With hardening enabled (auto-rotate API key on suspicious activity)
cargo run -- --api --api-key your-secret-key-here --harden

# Custom interface and IP limit
cargo run -- --api --api-key your-secret-key-here --harden --interface 127.0.0.1 --ip-limit 5

# Custom port
cargo run -- --api --api-key your-secret-key-here --interface 0.0.0.0:9000
```

### API Flags

| Flag | Description | Required |
|------|-------------|----------|
| `--api` | Enable API server mode | Yes |
| `--api-key <key>` | API key for authentication | Yes (when using `--api`) |
| `--harden` | Enable hardening mode (auto-rotate key on suspicious activity) | No |
| `--interface <addr>` | Network interface/IP to bind to (default: `0.0.0.0`) | No |
| `--ip-limit <num>` | Maximum unique IPs before auto-rotation (default: 10, requires `--harden`) | No |

### API Endpoints

All endpoints except `/health` require authentication via the `Authorization` header:

```bash
# Bearer token format
Authorization: Bearer your-api-key-here

# Or ApiKey format
Authorization: ApiKey your-api-key-here
```

#### Public Endpoints

- **`GET /health`** - Health check (no authentication required)
  ```bash
  curl http://localhost:8080/health
  ```

#### Protected Endpoints

- **`GET /api/modules`** - List all available modules
  ```bash
  curl -H "Authorization: Bearer your-api-key" http://localhost:8080/api/modules
  ```

- **`POST /api/run`** - Execute a module on a target
  ```bash
  curl -X POST -H "Authorization: Bearer your-api-key" \
       -H "Content-Type: application/json" \
       -d '{"module": "scanners/port_scanner", "target": "192.168.1.1"}' \
       http://localhost:8080/api/run
  ```

- **`GET /api/status`** - Get API server status and statistics
  ```bash
  curl -H "Authorization: Bearer your-api-key" http://localhost:8080/api/status
  ```

- **`POST /api/rotate-key`** - Manually rotate the API key
  ```bash
  curl -X POST -H "Authorization: Bearer your-api-key" \
       http://localhost:8080/api/rotate-key
  ```

- **`GET /api/ips`** - Get all tracked IP addresses with details
  ```bash
  curl -H "Authorization: Bearer your-api-key" http://localhost:8080/api/ips
  ```

- **`GET /api/auth-failures`** - Get authentication failure statistics
  ```bash
  curl -H "Authorization: Bearer your-api-key" http://localhost:8080/api/auth-failures
  ```

### Security Features

#### Rate Limiting
- IPs are automatically blocked for **30 seconds** after **3 failed authentication attempts**
- Blocked IPs receive HTTP `429 Too Many Requests` responses
- Failed attempts are logged to both terminal and log file
- Counter resets automatically after the block period expires
- Successful authentication resets the failure counter for that IP

#### Hardening Mode
When `--harden` is enabled:
- Tracks unique IP addresses accessing the API
- Automatically rotates the API key when the number of unique IPs exceeds the limit (default: 10)
- Logs all rotation events to terminal and `rustsploit_api.log`
- Clears IP tracking after key rotation

#### Logging
All API activity is logged to:
- **Terminal:** Real-time console output with colored status messages
- **Log File:** `rustsploit_api.log` in the current working directory

Log entries include:
- API requests and responses
- Authentication failures and rate limiting events
- IP tracking and hardening actions
- Key rotation events
- Module execution results

### Example API Workflow

```bash
# 1. Start the API server
cargo run -- --api --api-key my-secret-key --harden --ip-limit 5

# 2. Check health
curl http://localhost:8080/health

# 3. List available modules
curl -H "Authorization: Bearer my-secret-key" http://localhost:8080/api/modules

# 4. Run a port scan
curl -X POST -H "Authorization: Bearer my-secret-key" \
     -H "Content-Type: application/json" \
     -d '{"module": "scanners/port_scanner", "target": "192.168.1.1"}' \
     http://localhost:8080/api/run

# 5. Check status
curl -H "Authorization: Bearer my-secret-key" http://localhost:8080/api/status

# 6. View tracked IPs
curl -H "Authorization: Bearer my-secret-key" http://localhost:8080/api/ips
```

---

## Proxy Workflow

Rustsploit treats proxy lists as first-class citizens:

- Accepts HTTP, HTTPS, SOCKS4, SOCKS4a, SOCKS5, and SOCKS5h entries
- Loads from user-supplied files, skipping invalid lines with reasons
- Optional connectivity test prompts allow tuning:
  - Test URL (default `https://example.com`)
  - Timeout (seconds)
  - Max concurrent checks
- Keeps only working proxies when validation is requested
- Rotates at run time; if all proxies fail, reverts to direct host attempts automatically

Environment variables (`ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`) are managed transparently per attempt.

---

## How Modules Are Discovered

Rustsploit scans `src/modules/` recursively during build. Each module should expose:

```rust
pub async fn run(target: &str) -> anyhow::Result<()>;
```

Optional interactive entry points (`run_interactive`) can coexist. Module paths are referenced relative to `src/modules/`, for example:

- File: `src/modules/exploits/sample_exploit.rs`
- Shell path: `exploits/sample_exploit`

See the [Developer Guide](https://github.com/s-b-repo/rustsploit/blob/main/docs/readme.md) for scaffolding templates, async guidance, and tips on logging/persistence.

---

## Contributing

Contributions are welcome! High-level suggestions:

1. Fork + branch from `main`
2. Add your module under the appropriate category
3. Keep outputs concise, leverage `.yellow()/.green()` for status, and wrap heavy loops in async tasks when appropriate
4. Document usage patterns in module comments
5. Run `cargo fmt` and `cargo check` before opening a PR

Bug reports, feature requests, and module ideas are appreciated. Feel free to log issues or reach out with PoCs.

---

## Credits

- **Project Lead:** s-b-repo
- **Language:** 100% Rust
- **Wordlists:** Seclists + custom additions (`lists/` directory)
- **Inspired by:** RouterSploit, Metasploit Framework, pwntools

> ⚠️ Rustsploit is intended for authorized security testing and research purposes only. Obtain explicit permission before targeting any system you do not own.


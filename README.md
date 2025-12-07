# Rustsploit 🛠️

Modular offensive tooling for embedded targets, written in Rust and inspired by RouterSploit/Metasploit. Rustsploit ships an interactive shell, a command-line runner, rich proxy support, and an ever-growing library of exploits, scanners, and credential modules for routers, cameras, appliances, and general network services.

![Screenshot](https://github.com/s-b-repo/rustsploit/raw/main/preview.png)
![Screenshot](https://github.com/s-b-repo/rustsploit/raw/main/testing.png)


- 📚 **Developer Docs:** [Full guide covering module lifecycle, proxy logic, shell flow, and dispatcher](https://github.com/s-b-repo/rustsploit/blob/main/docs/readme.md)
- 💬 **Interactive Shell:** Ergonomic command palette with shortcuts (e.g., `f1 ssh`, `u exploits/heartbleed`, `go`)
- 🌐 **Proxy Smartness:** Supports HTTP(S), SOCKS4/4a/5 (with hostname resolution), validation, and automatic rotation
- 🧱 **IPv4/IPv6 Ready:** Credential modules and sockets normalize targets so both address families work out-of-the-box

---

## Table of Contents

1. [Highlights](#highlights)
2. [Module Catalog](#module-catalog)
3. [Quick Start](#quick-start)
4. [Docker Deployment](#docker-deployment)
5. [Interactive Shell Walkthrough](#interactive-shell-walkthrough)
6. [CLI Usage](#cli-usage)
7. [API Server Mode](#api-server-mode)
8. [Proxy Workflow](#proxy-workflow)
9. [How Modules Are Discovered](#how-modules-are-discovered)
10. [Contributing](#contributing)
11. [Credits](#credits)

---

## Highlights

- **Auto-discovered modules:** `build.rs` indexes `src/modules/**` so new code drops in without manual registration
- **Interactive shell with color and shortcuts:** Quick command palette, target/module state tracking, alias commands (`help/?`, `modules/m`, `run/go`, etc.)
- **Ergonomic proxy system:** Load lists, validate availability, choose concurrency/timeouts, and rotate automatically on failure
- **Comprehensive credential tooling:** FTP(S), SSH, Telnet, POP3(S), SMTP, RDP, RTSP, SNMP, L2TP, MQTT, Fortinet brute force modules with IPv6 and TLS support where applicable
- **Enhanced Telnet module:** Full IAC (Interpret As Command) negotiation, advanced error classification, verbose quick-check mode, robust buffer handling
- **Improved RDP module:** Streaming failover for large password files (>150MB), comprehensive error classification, multiple security level support (NLA/TLS/RDP/Negotiate/Auto)
- **Framework-level honeypot detection:** Automatic detection before scans using 200 common ports (warns if 11+ ports open)
- **Advanced target normalization:** Supports IPv4, IPv6, hostnames, URLs, CIDR notation with comprehensive validation
- **Exploit coverage:** Apache Tomcat, Abus security cameras, Ivanti Connect Secure, TP-Link, Zabbix, Avtech cameras, Spotube, OpenSSH race condition, and more
- **Scanners & utilities:** Port scanner, ping sweep, SSDP discovery, HTTP title grabber, DNS recursion tester, HTTP method scanner, StalkRoute traceroute (root)
- **Payload generation:** Batch malware dropper (`narutto_dropper`), BAT payload generator, custom credential checkers
- **Readable output:** Colored prompts, structured status messages, optional verbose logs and result persistence
- **REST API Server:** Launch a secure API server with authentication, rate limiting, IP tracking, and dynamic key rotation
- **Security hardened:** Comprehensive input validation, path traversal protection, length limits, and memory-safe operations throughout
- **Honeypot detection:** Framework-level automatic detection before module execution to warn about potentially deceptive targets
- **Enhanced target handling:** Advanced normalization supporting IPv4, IPv6 (with brackets), hostnames, URLs, CIDR notation, and port extraction

---

## Module Catalog

Rustsploit ships categorized modules under `src/modules/`, automatically exposed to the shell/CLI. A non-exhaustive snapshot:

| Category | Highlights |
|----------|------------|
| `creds/generic` | FTP anonymous & FTPS brute force, SSH brute force, SSH user enumeration (timing attack), SSH password spray, **Telnet brute force (with IAC negotiation)**, POP3(S) brute force, SMTP brute force, RTSP brute force (path + header bruting), **RDP auth-only brute (streaming mode, multiple security levels)**, **MQTT brute force**, SNMP community string brute force, L2TP/IPsec brute force, Fortinet SSL VPN brute force |
| `exploits/*` | Apache Tomcat (CVE-2025-24813 RCE, CatKiller CVE-2025-31650), TP-Link VN020 / WR740N DoS, Abus camera CVE-2023-26609 variants, Ivanti Connect Secure stack buffer overflow, Zabbix 7.0.0 SQLi, Avtech CVE-2024-7029, Spotube zero-day, OpenSSH 9.8p1 race condition, Uniview password disclosure, ACTi camera RCE, Flowise CVE-2025-59528 RCE, HTTP/2 Rapid Reset DoS, Jenkins LFI, PAN-OS Auth Bypass, Heartbleed, **SSHPWN Framework** (SFTP symlink/setuid/traversal, SCP injection/DoS, Session env injection) |
| `scanners` | Port scanner (TCP/UDP/SYN/ACK), ping sweep (ICMP/TCP/UDP/SYN/ACK), SSDP M-SEARCH enumerator, HTTP title fetcher, HTTP method scanner, DNS recursion/amplification tester, StalkRoute traceroute (firewall evasion), **SSH scanner** (banner grabbing, CIDR support) |
| `payloadgens` | `narutto_dropper`, BAT payload generator |
| `lists` | RTSP wordlists, telnet default credentials, and helper files |

Run `modules` or `find <keyword>` in the shell for the authoritative list.

---

## Quick Start

### Requirements

 ```
sudo apt update
sudo apt install freerdp2-x11    # Required for the RDP brute force module
```

Ensure Rust and Cargo are installed (https://www.rust-lang.org/tools/install).

### Clone + Build

 ```
git clone https://github.com/s-b-repo/rustsploit.git
cd rustsploit
cargo build
```

### Run (Interactive Shell)

 ```
cargo run
```

### Install (optional)

 ```
cargo install --path .
```

---

## Docker Deployment

Rustsploit ships with a standalone provisioning script that builds and launches the API inside Docker (mirroring the multi-stage workflow used in vxcontrol/pentagi).

### Requirements

- Docker Engine 24+ (or Docker Desktop)
- Docker Compose plugin (`docker compose`) or legacy `docker-compose`
- Python 3.8+

### Interactive Setup

 ```
python3 scripts/setup_docker.py
```

The helper will:

1. Confirm you are in the repository root (`Cargo.toml` present).
2. Ask how the API should bind (`127.0.0.1`, `0.0.0.0`, detected LAN IP, or custom host:port).
3. Let you enter or auto-generate an API key (printable ASCII, 128 chars max).
4. Toggle hardening mode and tune the IP limit if desired.
5. Generate:
   - `docker/Dockerfile.api` (build + serve stages)
   - `docker/entrypoint.sh` (passes CLI flags / hardening state)
   - `.env.rustsploit-docker` (API key, bind address, hardening settings)
   - `docker-compose.rustsploit.yml`
6. Optionally run `docker compose up -d --build` with BuildKit enabled.

Existing files are never overwritten without confirmation (use `--force` for scripted deployments).

### Non-Interactive / CI Usage

All prompts have CLI equivalents:

 ```
python3 scripts/setup_docker.py \
  --bind 0.0.0.0:8443 \
  --generate-key \
  --enable-hardening \
  --ip-limit 5 \
  --skip-up \
  --force \
  --non-interactive
```

This produces the Docker assets but skips the compose launch. To start the stack later:

 ```
docker compose -f docker-compose.rustsploit.yml up -d --build
```

Environment variables are written with 0600 permissions so secrets stay private. Re-run the script any time you want to regenerate artefacts or rotate the API key.

---

## New Features & Improvements

### Framework-Level Enhancements

- **Honeypot Detection**: Automatically scans 200 common ports before module execution. If 11+ ports are open, warns that the target is likely a honeypot. This check runs universally on every target after it's set.

- **Advanced Target Normalization**: The framework now supports:
  - IPv4: `192.168.1.1`, `192.168.1.1:8080`
  - IPv6: `::1`, `[::1]`, `[::1]:8080`, `2001:db8::1`
  - Hostnames: `.com`, `.com:443`
  - URLs: `http://.com:8080` (extracts host:port)
  - CIDR notation: `192.168.1.0/24`, `2001:db8::/32`
  
  All targets are validated for security (DoS prevention, path traversal protection, format validation).

### Module Improvements

- **Telnet Bruteforce**: 
  - Full Telnet IAC (Interpret As Command) negotiation support
  - Enhanced error classification (connection, DNS, authentication, protocol, I/O, timeout errors)
  - Verbose mode for quick checks showing all attempts and detailed statistics
  - Improved buffer handling and memory management

- **RDP Bruteforce**:
  - Automatic streaming failover for password files >150MB to prevent memory exhaustion
  - Comprehensive error classification (ConnectionFailed, AuthenticationFailed, CertificateError, Timeout, NetworkError, ProtocolError, ToolNotFound, Unknown)
  - Support for multiple RDP security levels: Auto, NLA, TLS, RDP, Negotiate
  - Command injection prevention in external tool calls

- **MQTT Bruteforce**: 
  - Full MQTT 3.1.1 protocol implementation
  - Proper CONNECT packet construction with variable-length encoding
  - CONNACK response parsing and error classification

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

session:

```
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

 ```
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

 ```
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

 ```
# Bearer token format
Authorization: Bearer your-api-key-here

# Or ApiKey format
Authorization: ApiKey your-api-key-here
```

#### Public Endpoints

- **`GET /health`** - Health check (no authentication required)
  ```
  curl http://localhost:8080/health
  ```

#### Protected Endpoints

- **`GET /api/modules`** - List all available modules
  ```
  curl -H "Authorization: Bearer your-api-key" http://localhost:8080/api/modules
  ```

- **`POST /api/run`** - Execute a module on a target
  ```
  curl -X POST -H "Authorization: Bearer your-api-key" \
       -H "Content-Type: application/json" \
       -d '{"module": "scanners/port_scanner", "target": "192.168.1.1"}' \
       http://localhost:8080/api/run
  ```

- **`GET /api/status`** - Get API server status and statistics
  ```
  curl -H "Authorization: Bearer your-api-key" http://localhost:8080/api/status
  ```

- **`POST /api/rotate-key`** - Manually rotate the API key
  ```
  curl -X POST -H "Authorization: Bearer your-api-key" \
       http://localhost:8080/api/rotate-key
  ```

- **`GET /api/ips`** - Get all tracked IP addresses with details
  ```
  curl -H "Authorization: Bearer your-api-key" http://localhost:8080/api/ips
  ```

- **`GET /api/auth-failures`** - Get authentication failure statistics
  ```
  curl -H "Authorization: Bearer your-api-key" http://localhost:8080/api/auth-failures
  ```

### telnet config 
 ```
{
  "port": 23,
  "username_wordlist": "usernames.txt",
  "password_wordlist": "passwords.txt",
  "threads": 10,
  "delay_ms": 50,
  "connection_timeout": 3,
  "read_timeout": 1,
  "stop_on_success": true,
  "verbose": false,
  "full_combo": true,
  "raw_bruteforce": false,
  "raw_charset": "",
  "raw_min_length": 0,
  "raw_max_length": 0,
  "output_file": "results.txt",
  "append_mode": false,
  "pre_validate": true,
  "retry_on_error": true,
  "max_retries": 2,
  "login_prompts": ["login:", "username:"],
  "password_prompts": ["password:"],
  "success_indicators": ["$", "#", "welcome"],
  "failure_indicators": ["incorrect", "failed"]
}
```
  
  
  
### Security Features

#### Input Validation & Security
- **Request Body Limiting:** Maximum 1MB request body to prevent DoS attacks
- **API Key Validation:** Keys must be printable ASCII, max 256 characters
- **Target Validation:** All targets are validated for length, control characters, and path traversal
- **Module Path Sanitization:** Module names are validated against path traversal and injection attacks
- **Resource Limits:** Automatic cleanup when tracked IPs or auth failures exceed 100,000 entries

#### Rate Limiting
- IPs are automatically blocked for **30 seconds** after **3 failed authentication attempts**
- Blocked IPs receive HTTP `429 Too Many Requests` responses
- Failed attempts are logged to both terminal and log file
- Counter resets automatically after the block period expires
- Successful authentication resets the failure counter for that IP
- Automatic cleanup of expired blocks and entries older than 1 hour

#### Hardening Mode
When `--harden` is enabled:
- Tracks unique IP addresses accessing the API
- Automatically rotates the API key when the number of unique IPs exceeds the limit (default: 10)
- Logs all rotation events to terminal and `rustsploit_api.log`
- Clears IP tracking after key rotation
- Automatic pruning when tracker exceeds 100,000 entries

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
- Resource cleanup operations

###  API Workflow

 ```
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
  - Test URL (default `https://.com`)
  - Timeout (seconds)
  - Max concurrent checks
- Keeps only working proxies when validation is requested
- Rotates at run time; if all proxies fail, reverts to direct host attempts automatically

Environment variables (`ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`) are managed transparently per attempt.

---

## How Modules Are Discovered

Rustsploit scans `src/modules/` recursively during build. Each module should expose:

```
pub async fn run(target: &str) -> anyhow::Result<()>;
```

Optional interactive entry points (`run_interactive`) can coexist. Module paths are referenced relative to `src/modules/`, for :

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


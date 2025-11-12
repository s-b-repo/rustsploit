# Rustsploit 🛠️

Modular offensive tooling for embedded targets, written in Rust and inspired by RouterSploit/Metasploit. Rustsploit ships an interactive shell, a command-line runner, rich proxy support, and an ever-growing library of exploits, scanners, and credential modules for routers, cameras, appliances, and general network services.

![Screenshot](https://github.com/s-b-repo/rustsploit/raw/main/preview.png)

-  **Developer Docs:** [Full guide covering module lifecycle, proxy logic, shell flow, and dispatcher](https://github.com/s-b-repo/rustsploit/blob/main/docs/readme.md)
-  **Interactive Shell:** Ergonomic command palette with shortcuts (e.g., `f1 ssh`, `u exploits/heartbleed`, `go`)
-  **Proxy Smartness:** Supports HTTP(S), SOCKS4/4a/5 (with hostname resolution), validation, and automatic rotation
-  **IPv4/IPv6 Ready:** Credential modules and sockets normalize targets so both address families work out-of-the-box

---

## Table of Contents

1. [Highlights](#highlights)
2. [Module Catalog](#module-catalog)
3. [Quick Start](#quick-start)
4. [Interactive Shell Walkthrough](#interactive-shell-walkthrough)
5. [CLI Usage](#cli-usage)
6. [Proxy Workflow](#proxy-workflow)
7. [How Modules Are Discovered](#how-modules-are-discovered)
8. [Contributing](#contributing)
9. [Credits](#credits)

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

## Interactive Shell Walkthrough

The shell tracks current module, target, and proxy state. All commands are case-insensitive and support aliases:

```
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

```
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


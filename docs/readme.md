# 🛠️ Rustsploit Developer Guide

> Reference manual for maintainers and contributors. Covers the architecture, build-time module discovery, shell ergonomics, proxy plumbing, and authoring guidelines for exploits, scanners, and credential modules.

---

## Table of Contents

1. [Project Overview](#project-overview)  
2. [Code Layout](#code-layout)  
3. [Build Pipeline & Module Discovery](#build-pipeline--module-discovery)  
4. [Shell Architecture](#shell-architecture)  
5. [Proxy Subsystem](#proxy-subsystem)  
6. [Command-Line Interface](#command-line-interface)  
7. [API Server Architecture](#api-server-architecture)  
8. [Authoring Modules](#authoring-modules)  
9. [Credential Modules: Best Practices](#credential-modules-best-practices)  
10. [Exploit Modules: Best Practices](#exploit-modules-best-practices)  
11. [Utilities & Helpers](#utilities--helpers)  
12. [Testing & QA](#testing--qa)  
13. [Roadmap & Ideas](#roadmap--ideas)  

---

## Project Overview

Rustsploit is a Rust-first re-imagining of RouterSploit:

- Async-native (Tokio) for scalable brute forcing and network IO
- Auto-discovered modules categorized as `exploits`, `scanners`, and `creds`
- Interactive shell + CLI runner referencing the same dispatch layer
- Proxy-aware execution with run-time rotation, validation, and fallback logic
- IPv4/IPv6-friendly: target normalization happens uniformly
- Carefully colored, concise output designed for operators on remote consoles

---

## Code Layout

```text
rustsploit/
├── Cargo.toml
├── build.rs                 # Generates dispatcher code by scanning src/modules
├── src/
│   ├── main.rs              # Entry point, selects CLI, shell, or API mode
│   ├── cli.rs               # Clap-based CLI parser and dispatcher
│   ├── shell.rs             # Interactive shell loop + UX helpers
│   ├── api.rs               # REST API server with auth, rate limiting, hardening
│   ├── commands/            # Dispatch glue for exploits/scanners/creds
│   │   ├── mod.rs
│   │   ├── exploit.rs
│   │   ├── exploit_gen.rs   # build.rs output
│   │   ├── scanner.rs
│   │   ├── scanner_gen.rs   # build.rs output
│   │   ├── creds.rs
│   │   └── creds_gen.rs     # build.rs output
│   ├── modules/             # Fully auto-discovered attack modules
│   │   ├── exploits/
│   │   ├── scanners/
│   │   └── creds/
│   └── utils.rs             # Shared helpers (proxy parsing, module lookup, etc.)
├── scripts/
│   └── setup_docker.py      # Docker/Compose provisioning helper (interactive + CLI)
├── docs/
│   └── readme.md            # This document
├── lists/
│   ├── readme.md            # Wordlist + data file catalogue
│   ├── rtsp-paths.txt
│   └── rtsphead.txt
└── README.md                # Product overview
```

Key takeaway: modules are just Rust files under `src/modules/**`. Add `pub mod my_module;` in the local `mod.rs`, and the build script handles the rest.

---

## Build Pipeline & Module Discovery

1. **`build.rs` scan:** Before compilation, build.rs walks `src/modules` (depth-limited) looking for `.rs` files that are not `mod.rs`.
2. **Signature detection:** If a file exposes `pub async fn run(`, it is treated as a callable module.
3. **Name generation:** Both a *short name* (`ssh_bruteforce`) and *qualified path* (`creds/generic/ssh_bruteforce`) are registered.
4. **Dispatcher emission:** Three files (`exploit_gen.rs`, `scanner_gen.rs`, `creds_gen.rs`) are emitted with exhaustive `match` statements that map names → `use crate::modules::...::run`.
5. **Shell + CLI usage:** When users invoke `use exploits/foo` or `--module foo`, the dispatcher resolves the actual function.

Because the dispatcher is generated at build time, there is no manual registry drift as long as modules live in the right folder and export `run`.

---

## Shell Architecture

The shell lives in `src/shell.rs`. Highlights:

- **Context:** `ShellContext` stores `current_module`, `current_target`, the loaded `proxy_list`, and `proxy_enabled` boolean.
- **Prompt helpers:** Inline functions prompt for paths, yes/no decisions, timeouts, etc.
- **Shortcut parsing:** `split_command` + `resolve_command` normalize input (e.g., `f1 ssh`, `pon`, `ptest`) to canonical keys.
- **Command palette:** `render_help()` prints a colorized table for quick reference.
- **Proxy tests:** `proxy_test` command triggers async validation via utils.
- **Run pipeline:** On `run`/`go`, the shell enforces:
  - Module selected
  - Target set
  - Proxy state respected (rotate until success or fallback direct)
  - Environment variables (`ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`) set/cleared per attempt
- **State reset:** On exit, nothing is persisted intentionally for OPSEC.

Extensions (tab completion, history) can be added by wrapping the loop with a line-editor crate, but are omitted today to keep dependencies minimal.

---

## Proxy Subsystem

Implemented in `utils.rs` and surfaced in the shell.

- **Loader:** `load_proxies_from_file` reads lists, normalizes schemes (defaulting to `http://`), validates host/port via `Url`, and tolerates comments or blank lines. Returns both valid entries and a list of parse errors (line number, reason).
- **Supported schemes:** `http`, `https`, `socks4`, `socks4a`, `socks5`, `socks5h`.
- **Tester:** `test_proxies` concurrently (Tokio) checks a user-chosen URL using `reqwest::Proxy::all`. Configurable timeout and max concurrency.
- **Result:** Working proxies are retained; failures are reported with the reason (connection refused, invalid cert, etc.).
- **Integration:** Shell invites the user to validate immediately after loading; `proxy_test` can also be used on demand.

Proxies are set globally via environment variables so both module HTTP requests and low-level sockets (if they honor `ALL_PROXY`) benefit.

---

## Command-Line Interface

`src/cli.rs` uses Clap to expose three commands:

- `--command exploit|scanner|creds`
- `--module <name>` (short or qualified, same mapping as the shell)
- `--target <host|IP>`

Example:

```bash
cargo run -- --command exploit --module heartbleed --target 203.0.113.12
```

If the module needs additional parameters, it can prompt interactively (e.g., brute-force modules ask for wordlists even in CLI mode). For automated pipelines, modules should provide sensible defaults or accept environment variables.

---

## API Server Architecture

The API server (`src/api.rs`) provides a REST API for remote control of Rustsploit. It's built on Axum and includes comprehensive security features.

### Architecture Overview

- **State Management:** `ApiState` holds shared state including:
  - Current API key (with rotation support)
  - IP tracker for hardening mode
  - Authentication failure tracker for rate limiting
  - Logging configuration

- **Authentication Middleware:** All protected routes go through `auth_middleware` which:
  - Extracts client IP from headers or connection info
  - Checks rate limiting before processing
  - Validates API key from `Authorization` header
  - Records failures and resets counters on success
  - Tracks IPs for hardening mode

- **Rate Limiting:** 
  - Tracks failed authentication attempts per IP
  - Blocks IPs for 30 seconds after 3 failed attempts
  - Automatically expires blocks and resets counters
  - Logs all rate limit events

- **Hardening Mode:**
  - Tracks unique IP addresses accessing the API
  - Auto-rotates API key when unique IP count exceeds limit
  - Clears IP tracking after rotation
  - Notifies via terminal and log file

### Key Components

**`ApiState`** - Central state container:
```rust
pub struct ApiState {
    pub current_key: Arc<RwLock<ApiKey>>,
    pub ip_tracker: Arc<RwLock<HashMap<String, IpTracker>>>,
    pub auth_failures: Arc<RwLock<HashMap<String, AuthFailureTracker>>>,
    pub harden_enabled: bool,
    pub ip_limit: u32,
    pub log_file: PathBuf,
}
```

**`auth_middleware`** - Authentication and rate limiting:
- Runs before all protected routes
- Extracts IP from `x-forwarded-for`, `x-real-ip`, or connection info
- Checks if IP is rate-limited
- Validates API key
- Records failures or resets on success

**Module Execution:**
- Modules run in separate OS threads with their own Tokio runtime
- This allows non-Send modules to execute asynchronously
- Results are logged to both terminal and log file

### API Endpoints

- **Public:** `/health` - No authentication required
- **Protected:** All `/api/*` endpoints require valid API key
  - `GET /api/modules` - List available modules
  - `POST /api/run` - Execute module on target
  - `GET /api/status` - Server status and statistics
  - `POST /api/rotate-key` - Manually rotate API key
  - `GET /api/ips` - Tracked IP addresses
  - `GET /api/auth-failures` - Authentication failure stats

### Logging

All API activity is logged to:
- Terminal: Real-time colored output
- File: `rustsploit_api.log` in current working directory

Log entries include timestamps, IP addresses, authentication events, rate limiting actions, and module execution results.

### Usage from CLI

```bash
# Start API server
cargo run -- --api --api-key secret-key

# With hardening
cargo run -- --api --api-key secret-key --harden --ip-limit 5

# Custom interface/port
cargo run -- --api --api-key secret-key --interface 127.0.0.1:9000
```

---

### Docker & Container Deployment

Rustsploit’s API can be containerised without hand-authoring Dockerfiles by using `scripts/setup_docker.py`. The tool is designed for both interactive operators and CI pipelines:

- Validates repository root, Docker availability, and Compose tooling.
- Accepts either prompts or CLI flags (`--bind`, `--generate-key`, `--enable-hardening`, `--ip-limit`, `--skip-up`, `--force`, `--non-interactive`, etc.).
- Emits the following artefacts (overwriting only with consent):
  - `docker/Dockerfile.api` – multi-stage builder + runtime image
  - `docker/entrypoint.sh` – passes API flags safely (enforces API key)
  - `.env.rustsploit-docker` – stores generated/selected secrets (0600 mode)
  - `docker-compose.rustsploit.yml` – production-ready stack with `no-new-privileges` and `tmpfs /tmp`
- Optionally runs `docker compose up -d --build` (BuildKit enabled).

Example scripted run:

```bash
python3 scripts/setup_docker.py \
  --bind 192.168.1.50 \
  --port 8443 \
  --generate-key \
  --enable-hardening \
  --ip-limit 3 \
  --skip-up \
  --force \
  --non-interactive
```

Later, launch the stack manually:

```bash
docker compose -f docker-compose.rustsploit.yml up -d --build
```

This section is intentionally high level—consult `python3 scripts/setup_docker.py --help` for the latest flag list.

---

## Authoring Modules

Every module must export:

```rust
use anyhow::Result;

pub async fn run(target: &str) -> Result<()> {
    // ...
    Ok(())
}
```

Guidelines:

1. **Location:** choose one of `src/modules/{exploits,scanners,creds}`. Use subfolders for vendor families (e.g., `exploits/cisco/`).
2. **`mod.rs`:** add `pub mod your_module;` in the sibling `mod.rs`. Without this, the build script ignores the file.
3. **Async I/O:** prefer `reqwest`, `tokio::net`, `tokio::process`, etc. Synchronous blocking code should be wrapped with `tokio::task::spawn_blocking` where possible (see SSH module).
4. **Logging:** leverage `colored` for clarity, but keep messages short and actionable. Use `[+]`, `[-]`, `[!]`, `[*]` prefixes consistently.
5. **Error handling:** bubble up with context (`anyhow::Context`) so the shell/CLI surface meaningful errors.
6. **Wordlists / resources:** store under `lists/` and document them in `lists/readme.md`.
7. **Optional interactive mode:** If the module benefits from multiple code paths, optionally expose `run_interactive` and call it from `run`.

### Example skeleton

```rust
use anyhow::{Context, Result};

pub async fn run(target: &str) -> Result<()> {
    println!("[*] Checking {}", target);

    let url = format!("http://{}/status", target);
    let body = reqwest::get(&url)
        .await
        .with_context(|| format!("failed to reach {}", url))?
        .text()
        .await
        .context("failed to fetch body")?;

    if body.contains("vulnerable") {
        println!("[+] {} appears vulnerable", target);
    } else {
        println!("[-] {} not vulnerable", target);
    }

    Ok(())
}
```

---

## Credential Modules: Best Practices

Modules like FTP/SSH/Telnet/POP3/SMTP/RTSP/RDP follow shared patterns:

- **Input prompts:** ask for port, username/password wordlists, concurrency limit, stop-on-success toggle, output file, verbose logging.
- **Sanitation:** trim wordlist entries, skip blanks, provide early exits if lists are empty.
- **Concurrency:**
  - Use `tokio::Semaphore` for asynchronous modules (FTP, SSH).
  - Use `threadpool` + `crossbeam-channel` for synchronous protocols (Telnet, POP3, SMTP).
- **Adaptive throttling:** Some modules (FTP) sample CPU/RAM to avoid saturating the host.
- **TLS/STARTTLS:** Accept invalid certs for offensive tooling convenience, but note this clearly.
- **Result persistence:** Offer to write `host -> user:pass` pairs to a local file (in `./` by default).
- **IPv6:** Use helpers like `format_addr` to wrap IPv6 addresses in brackets and support port suffixes.

---

## Exploit Modules: Best Practices

- **CVE referencing:** mention CVE IDs and vendor/product in comments and output.
- **Artifact handling:** If the exploit downloads or writes files (e.g., Heartbleed dump), store them in the current working directory or a named subfolder.
- **Clean-up:** If credentials or accounts are added (Abus camera module), explain the impact and clean-up instructions in output or comments.
- **Safety checks:** Validate responses before declaring success; false positives hurt credibility.
- **Options:** Use `prompt_*` helpers (borrow from existing modules) if end-user input is needed (e.g., RTSP advanced headers, extra path lists).

---

## Utilities & Helpers

`src/utils.rs` provides:

- `normalize_target`: wrap IPv6 addresses in brackets, pass through IPv4/hosts untouched.
- `module_exists` / `list_all_modules` / `find_modules`: used by shell to present module inventory.
- Proxy helpers described earlier (`load_proxies_from_file`, `test_proxies`, etc.).

Feel free to expand this file with reusable pieces (e.g., credential loader, HTTP header templates) to avoid duplication inside modules.

---

## Testing & QA

1. **Static checks:** `cargo fmt` and `cargo clippy` (where available).
2. **Build:** `cargo check` ensures new modules compile.
3. **Runtime smoke tests:**
   - Shell: `cargo run` → `modules` → run a harmless module (e.g., `scanners/sample_scanner`).
   - CLI: `cargo run -- --command scanner --module sample_scanner --target 127.0.0.1`.
4. **Proxy validation:** Load a mixed proxy file and confirm `proxy_test` filters entries correctly.
5. **Wordlists:** Validate that required lists exist (e.g., RTSP paths) and are referenced in docstrings.

When adding new modules, include short usage documentation (stdout prints, README notes) so other operators know how to drive them.

---

## Roadmap & Ideas

- Interactive shell improvements (history, tab completion, colored banners)
- Automated module testing harness (mock servers for POP3/SMTP/RTSP)
- Credential module templates (derive-style macros for common prompts)
- Integration with external wordlists (dynamic download or git submodules)
- Session logging (`tee` support) and output JSON export for pipeline ingestion
- Transport abstractions for UDP/DoS modules

Contributions are welcome—open an issue or start a discussion before large refactors.

---

Happy hacking, and remember: **authorized testing only**. Commit messages and module descriptions should always reflect controlled research usage. !*** End Patch

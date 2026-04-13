# Module Development

Reference for maintainers and contributors writing new Rustsploit modules.

---

## How Modules Are Discovered

Rustsploit uses a build-time code-generation approach — no manual registry:

1. **`build.rs` scan** — Before compilation, `build.rs` recursively walks `src/modules/` looking for `.rs` files that are not `mod.rs`.
2. **Signature detection** — A file that exposes `pub async fn run(` is treated as a callable module.
3. **Name generation** — Both a *short name* (`ssh_bruteforce`) and a *qualified path* (`creds/generic/ssh_bruteforce`) are registered.
4. **Dispatcher emission** — Generated files are written into `OUT_DIR` (not the source tree):
   - `exploit_dispatch.rs`
   - `creds_dispatch.rs`
   - `scanner_dispatch.rs`
   - `plugins_dispatch.rs`
   - `module_registry.rs`

   Each dispatch file contains an exhaustive `match` mapping names → `use crate::modules::...::run`. The registry file provides a unified module listing across all categories.
5. **Shell + CLI resolution** — `use exploits/foo` or `--module foo` both resolve through the dispatcher.

Because it's generated at build time, there is **no manual registry drift** as long as modules live in the correct folder and export `run`.

---

## Naming Convention

### No Underscore Prefixes

Do not use underscore prefixes on function names or variable names. All identifiers use standard Rust `snake_case` without leading underscores.

```rust
// CORRECT
fn validate_input(data: &str) -> bool { ... }
fn build_enriched_entry(path: &str) -> serde_json::Value { ... }
pub async fn run(target: &str) -> Result<()> { ... }

// WRONG — no leading underscores
fn _validate_input(data: &str) -> bool { ... }
let _unused = something();
```

### Variables Must Be Used

All declared variables must be consumed. Do not use the `_` prefix on variables to suppress unused warnings. If a variable is unused, remove it or use it.

```rust
// WRONG — suppressing unused warning
let _result = some_operation();

// CORRECT — use the variable
let result = some_operation();
log::debug!("Result: {:?}", result);
```

---

## Code Rules

- **No dead code.** All code must be intentional and used. Do not leave unused functions, imports, or variables.
- **No `unsafe` blocks.** Do not use `unsafe` Rust anywhere in this codebase.

---

## Project Code Layout

```text
rustsploit/
├── Cargo.toml
├── build.rs                  # Generates dispatcher by scanning src/modules
├── src/
│   ├── main.rs               # Entry point — CLI or shell mode, input validation
│   ├── cli.rs                # Clap-based CLI parser and dispatcher
│   ├── shell.rs              # Interactive shell loop + UX helpers
│   ├── api.rs                # REST API server — auth, rate limiting, hardening
│   ├── config.rs             # Global config and target validation
│   ├── module_info.rs        # ModuleInfo, CheckResult, ModuleRank types
│   ├── global_options.rs     # Per-workspace options (setg/unsetg)
│   ├── cred_store.rs         # Per-workspace credential store (JSON persistence)
│   ├── spool.rs              # Console output logging
│   ├── workspace.rs          # Host/service tracking + workspaces
│   ├── loot.rs               # Loot/evidence management
│   ├── export.rs             # JSON/CSV/summary report export
│   ├── jobs.rs               # Background job management
│   ├── commands/
│   │   ├── mod.rs            # Module discovery, fuzzy matching, multi-target dispatch
│   │   ├── exploit.rs
│   │   ├── scanner.rs
│   │   └── creds.rs
│   ├── modules/
│   │   ├── exploits/         # Exploit modules (137 modules, 24 with check)
│   │   ├── scanners/         # Scanner modules (24 modules)
│   │   ├── creds/            # Credential modules (28 modules)
│   │   └── plugins/          # Plugin modules (1 module)
│   ├── native/               # Native integrations
│   │   ├── mod.rs
│   │   ├── rdp.rs            # xfreerdp/rdesktop wrapper
│   │   ├── payload_engine.rs # Payload encoding/generation
│   │   ├── url_encoding.rs   # URL encoding utilities
│   │   └── async_tls.rs      # Async TLS helpers
│   └── utils/                # Shared helpers (directory module)
│       ├── mod.rs            # Re-exports
│       ├── prompt.rs         # Config-aware prompts (cfg_prompt_*)
│       ├── sanitize.rs       # Input validation, length limits
│       ├── target.rs         # Target normalization (IPv4/IPv6/CIDR/hostname)
│       ├── network.rs        # Network utilities
│       └── modules.rs        # Module discovery helpers
├── docs/                     # This wiki
├── lists/                    # Wordlists and data files
└── README.md                 # Product overview
```

---

## Required Module Signature

Every module **must** export:

```rust
use anyhow::Result;

pub async fn run(target: &str) -> Result<()> {
    // ...
    Ok(())
}
```

Optional: also expose `pub async fn run_interactive(target: &str) -> Result<()>` for modules with multiple code paths.

---

## Optional Module Functions

Modules can optionally provide metadata and vulnerability check functions. These are auto-detected by `build.rs` alongside `run()`:

### Module Info (`info`)

```rust
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "My Exploit Module".to_string(),
        description: "Exploits CVE-XXXX-YYYY in FooBar device firmware.".to_string(),
        authors: vec!["Your Name".to_string()],
        references: vec![
            "CVE-XXXX-YYYY".to_string(),
            "https://example.com/advisory".to_string(),
        ],
        disclosure_date: Some("2025-01-15".to_string()),
        rank: ModuleRank::Good,
    }
}
```

The `info` shell command and `GET /api/module/{category}/{name}` endpoint display this metadata.

**Rank values:** `Excellent` (reliable, no crash risk), `Great`, `Good` (default), `Normal`, `Low`, `Manual`.

### Vulnerability Check (`check`)

```rust
use crate::module_info::CheckResult;

pub async fn check(target: &str) -> CheckResult {
    // Non-destructive verification — do NOT exploit
    match test_vulnerability(target).await {
        Ok(true) => CheckResult::Vulnerable("Version 1.2.3 is affected".to_string()),
        Ok(false) => CheckResult::NotVulnerable("Patched version detected".to_string()),
        Err(e) => CheckResult::Error(format!("Check failed: {}", e)),
    }
}
```

The `check` shell command and `POST /api/check` endpoint run this without exploitation.

### Auto-Store Credentials and Loot

Modules can auto-store discovered data:

```rust
// Store a found credential (stored in the current workspace's credential store)
// Credentials are isolated per workspace — switching workspaces switches the store.
crate::cred_store::store_credential(host, port, "ssh", username, password,
    crate::cred_store::CredType::Password, "creds/generic/ssh_bruteforce");

// Store loot (config file, hash dump, etc.)
crate::loot::store_loot(host, "config", "Router config dump", data.as_bytes(), "exploits/router_rce");

// Track a discovered host/service
crate::workspace::track_host(ip, Some("router.local"), Some("Linux 4.x"));
crate::workspace::track_service(ip, 22, "tcp", "ssh", Some("OpenSSH 8.9"));
```

---

## Adding a New Module — Checklist

1. **Choose a location** under `src/modules/{exploits,scanners,creds}`.  
   Use subfolders for vendor families (e.g., `exploits/cisco/`).
2. **Create the `.rs` file** with the required `pub async fn run` signature.
3. **Register in `mod.rs`** — add `pub mod your_module;` to the sibling `mod.rs`.  
   Without this, `build.rs` ignores the file.
4. **Run `cargo check`** — the dispatcher is regenerated automatically.

---

## Module Skeleton

```rust
use anyhow::{Context, Result};
use colored::Colorize;
use crate::utils::{normalize_target, cfg_prompt_port, cfg_prompt_yes_no};

pub async fn run(target: &str) -> Result<()> {
    let target = normalize_target(target)?;
    let port = cfg_prompt_port("port", "Target port", 80).await?;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose output?", false).await?;

    println!("{} Checking {}:{}", "[*]".cyan(), target, port);

    let url = format!("http://{}:{}/status", target, port);
    let body = reqwest::get(&url)
        .await
        .with_context(|| format!("Failed to reach {}", url))?
        .text()
        .await
        .context("Failed to read response body")?;

    if body.contains("vulnerable") {
        println!("{} {} appears vulnerable", "[+]".green(), target);
    } else {
        if verbose {
            println!("{} Response: {}", "[*]".cyan(), body);
        }
        println!("{} {} not vulnerable", "[-]".red(), target);
    }

    Ok(())
}
```

---

## Output Conventions

| Prefix | Color | Meaning |
|--------|-------|---------|
| `[+]` | Green | Success / found |
| `[-]` | Red | Not found / not vulnerable |
| `[!]` | Yellow | Warning |
| `[*]` | Cyan | Info / progress |

Use `.green()`, `.red()`, `.yellow()`, `.cyan()` from the `colored` crate. Keep messages short and actionable.

---

## Async I/O Guidelines

- Prefer `reqwest`, `tokio::net`, `tokio::process` for async work.
- Wrap synchronous blocking calls with `tokio::task::spawn_blocking` (see the SSH module for reference).
- For concurrency:
  - `tokio::sync::Semaphore` (wrapped in `Arc`) for async modules.
  - `threadpool` + `crossbeam-channel` for synchronous protocols (Telnet, POP3).

---

## Error Handling

Bubble up errors using `anyhow::Context` so the shell/CLI surface meaningful messages:

```rust
.with_context(|| format!("Failed to connect to {}", target))?
```

Avoid `unwrap()` and `unwrap_or_default()` in critical paths.

---

## Wordlists & Resources

Store under `lists/` and document them in `lists/readme.md`. Reference paths relative to the working directory.

---

## Framework-Level Multi-Target Dispatch

The framework's command dispatcher (`src/commands/mod.rs`) automatically handles multiple target types for **all** modules. Module authors do not need to implement multi-target logic themselves -- the dispatcher wraps each module's `run()` function and handles:

- **Comma-separated targets**: `192.168.1.1,192.168.1.2,10.0.0.1` -- splits and dispatches each entry individually.
- **CIDR subnets**: `192.168.1.0/24` -- expands the subnet and runs the module against each host IP.
- **File-based target lists**: If the target string is a path to an existing file, each line is read and dispatched as a separate target.
- **Random mass scan**: `0.0.0.0`, `0.0.0.0/0`, or `random` -- generates random public IPs in an infinite loop (Ctrl+C to stop).

This means a module that only handles a single host in its `run()` function automatically gains subnet scanning, file-based targeting, and mass-scan capability through the framework.

---

## 0.0.0.0/0 Internet-Wide Scanning

Modules supporting mass-scan accept `0.0.0.0`, `0.0.0.0/0`, or `random` as targets. When detected, the module enters an infinite loop generating random public IPs using:

```rust
fn generate_random_public_ip() -> Ipv4Addr { ... }
fn is_excluded_ip(ip: Ipv4Addr) -> bool { ... }
```

The `EXCLUDED_RANGES` constant covers bogons, private, reserved, documentation CIDRs, and public DNS servers. Copy this pattern from an existing mass-scan module (e.g., `telnet_hose` or `hikvision_rce`).

Honeypot detection is disabled in mass-scan mode to avoid interactive prompts.

---

### MCP Tool Development

Rustsploit exposes an MCP (Model Context Protocol) tool interface under `src/mcp/`. MCP tools allow AI agents to invoke framework functionality programmatically through a structured JSON-RPC protocol.

**Adding an MCP tool:**

1. Create a new handler in `src/mcp/` that implements the MCP tool interface.
2. Define the tool's input schema (JSON Schema) and output format.
3. Register the tool in the MCP tool registry so it appears in `tools/list` responses.
4. Use the existing module dispatch system to route MCP tool calls to the appropriate exploit, scanner, or credential module.

MCP tools follow the same security model as the REST API: input validation, sanitization, and rate limiting all apply. The MCP layer is a thin adapter over the existing shell command dispatch -- it does not bypass any framework security controls.

---

### Payload Mutation Engine

The payload mutation engine (`src/native/payload_engine.rs`) provides encoding, obfuscation, and transformation of payloads for AV/EDR evasion. Module authors can use it to dynamically encode payloads before delivery.

**Supported encodings:**

- XOR with configurable key
- Base64 (standard and URL-safe)
- Hex encoding
- Zero-width Unicode steganography
- Custom alphabet substitution

**Usage in modules:**

```rust
use crate::native::payload_engine::{encode_payload, EncodingType};

let encoded = encode_payload(raw_payload, EncodingType::Xor { key: 0x41 })?;
```

The engine is used by the `payload_encoder` and `narutto_dropper` exploit modules. When writing new exploit modules that deliver payloads, prefer using the mutation engine over hardcoded encoding to benefit from future encoding additions.

---

## Mandatory Framework Rules

### Network Connections
- **TCP**: MUST use `crate::utils::network::tcp_connect()` or `tcp_connect_addr()` — never raw `TcpStream::connect`
- **UDP**: MUST use `crate::utils::network::udp_bind()` or `blocking_udp_bind()` — never raw `UdpSocket::bind("0.0.0.0:0")`
- **HTTP**: MUST use `crate::utils::build_http_client()` for reqwest clients (cached, connection pooling)
- **TLS**: Use `crate::native::async_tls::make_dangerous_tls_connector()` (cached singleton)
- **Blocking TCP**: Use `crate::utils::blocking_tcp_connect()` for SSH and other blocking protocols

These utilities automatically respect `setg source_port` for firewall bypass testing.

### Console Output
- MUST use `crate::mprintln!()` / `crate::meprintln!()` — never raw `println!` / `eprintln!`
- This ensures output is captured by the spool logging system when active

### DoS Modules
- Use `crate::native::dos_utils::FastRng` for packet randomization
- Use `crate::native::dos_utils::checksum_16()` for IP/TCP/UDP checksums
- Use `crate::native::dos_utils::is_spoof_enabled()` to check global `setg spoof_ip true`

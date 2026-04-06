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
│   ├── global_options.rs     # Persistent global options (setg/unsetg)
│   ├── cred_store.rs         # Credential store (JSON persistence)
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
│   │   ├── creds/            # Credential modules (19 modules)
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
// Store a found credential
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

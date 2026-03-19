# Module Development

Reference for maintainers and contributors writing new Rustsploit modules.

---

## How Modules Are Discovered

Rustsploit uses a build-time code-generation approach — no manual registry:

1. **`build.rs` scan** — Before compilation, `build.rs` recursively walks `src/modules/` looking for `.rs` files that are not `mod.rs`.
2. **Signature detection** — A file that exposes `pub async fn run(` is treated as a callable module.
3. **Name generation** — Both a *short name* (`ssh_bruteforce`) and a *qualified path* (`creds/generic/ssh_bruteforce`) are registered.
4. **Dispatcher emission** — Three files are generated:
   - `src/commands/exploit_gen.rs`
   - `src/commands/scanner_gen.rs`
   - `src/commands/creds_gen.rs`

   Each contains an exhaustive `match` mapping names → `use crate::modules::...::run`.
5. **Shell + CLI resolution** — `use exploits/foo` or `--module foo` both resolve through the dispatcher.

Because it's generated at build time, there is **no manual registry drift** as long as modules live in the correct folder and export `run`.

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
│   ├── commands/
│   │   ├── mod.rs
│   │   ├── exploit.rs
│   │   ├── exploit_gen.rs    # build.rs output
│   │   ├── scanner.rs
│   │   ├── scanner_gen.rs    # build.rs output
│   │   ├── creds.rs
│   │   └── creds_gen.rs      # build.rs output
│   ├── modules/
│   │   ├── exploits/         # Exploit modules
│   │   ├── scanners/         # Scanner modules
│   │   └── creds/            # Credential modules
│   └── utils.rs              # Shared helpers — normalization, prompts, validation
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
use crate::utils::normalize_target;

pub async fn run(target: &str) -> Result<()> {
    let target = normalize_target(target)?;
    println!("{} Checking {}", "[*]".cyan(), target);

    let url = format!("http://{}/status", target);
    let body = reqwest::get(&url)
        .await
        .with_context(|| format!("Failed to reach {}", url))?
        .text()
        .await
        .context("Failed to read response body")?;

    if body.contains("vulnerable") {
        println!("{} {} appears vulnerable", "[+]".green(), target);
    } else {
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

## 0.0.0.0/0 Internet-Wide Scanning

Modules supporting mass-scan accept `0.0.0.0`, `0.0.0.0/0`, or `random` as targets. When detected, the module enters an infinite loop generating random public IPs using:

```rust
fn generate_random_public_ip() -> Ipv4Addr { ... }
fn is_excluded_ip(ip: Ipv4Addr) -> bool { ... }
```

The `EXCLUDED_RANGES` constant covers bogons, private, reserved, documentation CIDRs, and public DNS servers. Copy this pattern from an existing mass-scan module (e.g., `telnet_hose` or `hikvision_rce`).

Honeypot detection is disabled in mass-scan mode to avoid interactive prompts.



# 🛠️ Developer Documentation: RouterSploit-Rust Framework

> This document details the internal architecture, auto-dispatch system, proxy retry logic, and step-by-step guide to writing modules for the Rust rewrite of RouterSploit.

---

## 🧠 Framework Philosophy

RouterSploit-Rust is a modular, async-capable, Rust-based rewrite of RouterSploit. Each module is standalone, invoked via:

- 📟 CLI (`cargo run -- --command ...`)
- 🖥️ Shell (`rsf>` prompt)

Goals:
- 🔒 Safe-by-default
- 📦 Cleanly separated modules
- ⚡ Async concurrency
- 🌐 Proxy-aware execution

---

## 🗂️ Directory Structure

```
routersploit_rust/
├── Cargo.toml
├── build.rs
└── src/
    ├── main.rs              # Entrypoint
    ├── cli.rs               # CLI argument parser
    ├── shell.rs             # Interactive shell logic
    ├── commands/            # Module dispatch logic
    │   ├── mod.rs
    │   ├── scanner.rs
    │   ├── scanner_gen.rs
    │   ├── exploit.rs
    │   ├── exploit_gen.rs
    │   ├── creds_gen.rs
    │   └── creds.rs
    ├── modules/             # All attack modules
    │   ├── mod.rs
    │   ├── exploits/
    │   ├── scanners/
    │   └── creds/
    └── utils.rs             # Common utilities
```

---

## 🔗 Module System

Each module is a Rust file with a required `run()` entry point:

```rust
pub async fn run(target: &str) -> anyhow::Result<()>
```

### Optional:

```rust
pub async fn run_interactive(target: &str) -> anyhow::Result<()> {
    // internal prompts or logic
}
```

### Placement:

- Exploits: `src/modules/exploits/`
- Scanners: `src/modules/scanners/`
- Credentials: `src/modules/creds/`

Subfolders are supported:
- `exploits/routers/tplink.rs` → `tplink` or `routers/tplink`
- `scanners/http/title.rs` → `title` or `http/title`

---

## ✅ Adding a New Module

### 1. Create File

```rust
// src/modules/scanners/ftp_weak_login.rs
use anyhow::Result;

pub async fn run(target: &str) -> Result<()> {
    run_interactive(target).await
}

pub async fn run_interactive(target: &str) -> Result<()> {
    println!("[*] Checking FTP on {}", target);
    Ok(())
}
```

### 2. Register in `mod.rs`

```rust
pub mod ftp_weak_login;
```

---

## 🧠 Auto-Dispatch System

The CLI/shell can call:
```bash
cargo run -- --command scanner --module ftp_weak_login --target 192.168.1.1
```

Or in the shell:
```
rsf> use scanners/ftp_weak_login
rsf> set target 192.168.1.1
rsf> run
```

Behind the scenes:

1. `build.rs` scans `src/modules/` recursively
2. Detects files with `pub async fn run(...)`
3. Generates:
   - `exploit_dispatch.rs`
   - `scanner_dispatch.rs`
   - `creds_dispatch.rs`
4. Registers short + full names (e.g., `ftp_weak_login` + `scanners/ftp_weak_login`)

---

## ❌ What Not To Do

- ❌ No `run()` → won’t dispatch
- ❌ Don’t name multiple functions `run()` in one file
- ❌ Don’t use `mod.rs` as a module — ignored by generator
- ❌ Don’t forget to update `mod.rs` when adding modules

---

## ⚙️ CLI Usage

```bash
cargo run -- --command exploit --module my_exploit --target 10.0.0.1
```

### Args:

- `--command`: exploit | scanner | creds
- `--module`: file name of module
- `--target`: IP or host

---

## 🖥️ Shell Usage

```bash
cargo run
```

Then:

```
rsf> help
rsf> modules
rsf> use scanners/heartbleed_scanner
rsf> set target 192.168.0.1
rsf> run
```

Maintains internal state:
- `current_module`
- `current_target`
- `proxy_list`
- `proxy_enabled`

---

## 🔁 Proxy Retry Logic (Shell Only)

Proxy logic only applies in shell mode (`rsf>`).

### Flow:

1. User types `run`
2. Shell checks:
   - Module is selected?
   - Target is set?
   - Proxy enabled?

---

### Case 1: Proxy ON, Proxies LOADED

- Create `HashSet<String>` → `tried_proxies`
- Loop:
  - Pick random untried proxy
  - Set `ALL_PROXY` using:
    ```rust
    env::set_var("ALL_PROXY", proxy);
    ```
  - Call `commands::run_module(...)`
  - On success: stop
  - On error: mark proxy as failed, try another

- If all proxies fail:
  - Clear proxy env:
    ```rust
    env::remove_var("ALL_PROXY");
    ```
  - Try once directly

---

### Case 2: Proxy ON, No Proxies Loaded

- Show warning
- Clear `ALL_PROXY`
- Run once directly

---

### Case 3: Proxy OFF

- Clear proxy vars
- Run module once

---

### Summary Flow:

```
If proxy_enabled:
    while untried proxies:
        pick → set env → run → if fail → mark tried
    if none work → clear env → try direct
else:
    clear env → try direct
```

---

## 🧪 Module Execution Flow

Whether via CLI or shell:

1. `commands::run_module(...)`
2. Determines type: `exploit`, `scanner`, or `cred`
3. Calls correct dispatcher
4. Dispatcher calls `run(target).await`
5. Output shown to user

---

## 🛑 Error Handling

- All modules must return `anyhow::Result<()>`
- Errors are caught and shown cleanly in CLI or shell

---

## ⚡ Async Features

- Entire framework is powered by `tokio`
- All I/O modules are `async`
- Use `tokio::spawn`, `FuturesUnordered`, etc. for concurrency

---

## 📡 Making Requests

Use `reqwest`:

```rust
let resp = reqwest::get(&url).await?.text().await?;
```

Or with client:

```rust
let client = reqwest::Client::new();
let resp = client.post(&url).json(&data).send().await?;
```

✅ All requests respect `ALL_PROXY`

---

## 🧪 Example Use Cases

### CLI

```bash
cargo run -- --command creds --module ftp_weak_login --target 192.168.1.100
```

### Shell

```bash
rsf> use creds/ftp_weak_login
rsf> set target 192.168.1.100
rsf> run
```

---

## 🧼 Shell Reset

No session data persists. When restarted, shell forgets all settings — no saved targets or modules (by design).

---

## 🔐 Adapting CVEs

To build a real-world exploit:
- Convert PoC to async Rust logic
- Validate by checking known response headers/content
- Place it in the right folder and wire `run()`

TCP/UDP logic:

```rust
use tokio::net::{TcpStream, UdpSocket};
```

---

## 💡 Feature Roadmap

add more exploits etc

---

## 👥 Contributors

- **Main Developer**: me.
- **Language**: 100% Rust.
- **Inspired by**: RouterSploit, Metasploit, pwntools.


Would you like this exported as a `DEVELOPER_GUIDE.md` file now? I can generate it for you in exact GitHub-flavored markdown.

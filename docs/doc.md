Here's a full-blown `docs.md` file (meant for GitHub or developer onboarding) that explains how **everything works** in the custom RouterSploit-like Rust framework — not just a README, but **developer-level documentation** that explains the internal architecture, how to add or modify modules, and how the CLI and shell interact with the framework.

---

# 🛠️ Developer Documentation: RouterSploit-Rust Framework

> This document explains the architecture, core logic, CLI, shell system, and how to add or modify exploit/scanner/credential modules. It is meant for developers looking to extend or maintain this Rust-based pentesting framework.

---

## 🧠 Framework Philosophy

This tool is a **modular, extensible**, and **safe-by-default** Rust rewrite of the RouterSploit concept. Each exploit, scanner, or credential brute-forcer lives in its own **module file**, and can be invoked via:

- 📟 Command-Line Interface (CLI)
- 🖥️ Interactive Shell

---

## 🗂️ Directory Structure

```
routersploit_rust/
├── Cargo.toml
└── src
    ├── main.rs              # Entry point
    ├── cli.rs               # Parses CLI args
    ├── shell.rs             # Interactive shell (rsf> prompt)
    ├── commands/            # Dispatch logic for exploit/scanner/creds
    │   ├── mod.rs
    │   ├── exploit.rs
    │   ├── scanner.rs
    │   └── creds.rs
    ├── modules/             # All available attack modules
    │   ├── mod.rs
    │   ├── exploits/
    │   │   ├── mod.rs
    │   │   └── sample_exploit.rs
    │   ├── scanners/
    │   │   ├── mod.rs
    │   │   └── sample_scanner.rs
    │   └── creds/
    │       ├── mod.rs
    │       └── sample_cred_check.rs
    └── utils.rs             # Utility helpers (e.g., list modules)
```

---

## 🔗 Module System

Each **module** (exploit/scanner/cred checker) is self-contained:

### Anatomy of a Module

```rust
pub async fn run(target: &str) -> Result<()> {
    println!("[*] Running <MODULE_NAME> on target {}", target);
    // Logic here
    Ok(())
}
```

Each module must:
- Be placed inside the correct subfolder (e.g., `modules/exploits/`)
- Have a `run(target: &str) -> Result<()>` function
- Be declared in its parent's `mod.rs`
- Be wired into the corresponding command handler (e.g., `commands/exploit.rs`)

---

## ⚙️ CLI Internals

Handled via **Clap** in `cli.rs`:

```
cargo run -- --command exploit --module sample_exploit --target 192.168.1.1
```

- Parses command like `--command scanner`, `--module sample_scanner`, `--target 192.168.1.1`
- Passed into `commands::handle_command()` for dispatch

---

## 🖥️ Interactive Shell

Start with:

```
cargo run
```

Inside the shell:

```
rsf> help
rsf> modules
rsf> use exploits/sample_exploit
rsf> set target 192.168.1.1
rsf> run
```

Shell maintains internal state:
- `current_module` (e.g., `exploits/sample_exploit`)
- `current_target` (e.g., `192.168.1.1`)

When `run` is called, it dispatches via `commands::run_module()`.

---

## 🧪 Running a Module (Backend Flow)

1. Shell or CLI calls `commands::run_module("exploits/sample_exploit", "192.168.1.1")`
2. `commands/mod.rs` matches `exploits/` and calls `commands/exploit.rs`
3. `commands/exploit.rs` matches `sample_exploit` and calls `modules/exploits/sample_exploit.rs`
4. `run(target: &str)` executes async exploit logic
5. Results are printed back to the user

---

## ➕ How to Add a New Exploit/Scanner/Cred Module

### 1. Create the Module File

Example: `src/modules/exploits/my_new_exploit.rs`

```rust
use anyhow::{Result, Context};
use reqwest;

pub async fn run(target: &str) -> Result<()> {
    println!("[*] Launching my_new_exploit on {}", target);
    let url = format!("http://{}/pwn", target);
    let resp = reqwest::get(&url)
        .await
        .context("Request failed")?
        .text()
        .await?;

    if resp.contains("owned") {
        println!("[+] Target is vulnerable!");
    } else {
        println!("[-] Not vulnerable.");
    }

    Ok(())
}
```

---

### 2. Register It in `mod.rs`

```rust
// src/modules/exploits/mod.rs
pub mod sample_exploit;
pub mod my_new_exploit;
```

---

### 3. Wire It into the Command Handler

```rust
// src/commands/exploit.rs
match module_name {
    "sample_exploit" => exploits::sample_exploit::run(target).await?,
    "my_new_exploit" => exploits::my_new_exploit::run(target).await?,
    _ => eprintln!("Unknown exploit module"),
}
```

---


---

## 🛑 Error Handling

- All `run()` functions return `Result<()>` using `anyhow` for easy error context.
- Errors are automatically printed when the main shell or CLI fails.

---

## ⚡ Async Support

- The project uses `tokio` runtime and `reqwest` async client.
- All modules can use `async fn run(...) -> Result<()>` safely.

---

## 📡 HTTP Requests

- Use `reqwest` for sending requests to the target:
```rust
let response = reqwest::get(&url).await?;
```

- Or with a custom client and headers/auth:
```rust
let client = reqwest::Client::new();
let resp = client.post(&url).json(&data).send().await?;
```

---

## 🧪 Example Use Cases

### CLI Mode

```
# Exploit a router
cargo run -- --command exploit --module sample_exploit --target 192.168.0.1
```

### Shell Mode

```
rsf> use exploits/sample_exploit
rsf> set target 192.168.0.1
rsf> run
```

---

## 🧼 Resetting Shell State

There is no persistent state between runs. All values (`module`, `target`) must be set each time unless you're adding support for config files or persistence.

---

## 🔐 Real Exploit Integration

To adapt a real-world CVE:

- Convert the PoC into an async HTTP request
- Simulate or validate the vulnerable response pattern
- Follow the above module creation workflow

If the exploit is based on open TCP/UDP, you can use `tokio::net::TcpStream` or `tokio::net::UdpSocket`.

---

## 🛠️ Feature Ideas

- 🧰 Add wordlist brute-forcers (like rockyou support)
- 📄 Export results to a file
- ⚡ Parallel scanning via `tokio::spawn`
- 🔌 Plugin system for runtime module loading
- 🔒 Encrypted config/profile saving
- 🧪 Integration with Shodan/Censys APIs

---

## 👥 Contributors

- Main Developer: You.
- Language: 100% Rust
- Base Concept: Inspired by RouterSploit, Metasploit, and pwntools.

---

## 🧾 License

---

Would you like me to convert this into a Markdown file (`docs.md`) and drop it into your project as-is? Or would you like GitHub-flavored `.md` formatting tailored with headers, badges, collapsible trees, etc.?

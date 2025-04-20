 the internal architecture, how to add or modify modules, and how the CLI and shell interact with the framework.

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

Below is a **step-by-step** walkthrough of the proxy logic in the updated `shell.rs` whenever the user types `run`. It explains how the **retry mechanism** works, how a **new proxy** is selected after a failure, and how we **stop** when all proxies are exhausted.

---

## 1. `run` Command Overview

When the user types **`run`** in the shell:

1. We check if there is a **selected module** (`current_module`) and a **target** (`current_target`). If either is missing, we prompt the user to set them.  

2. If both are set:
   - We look at whether **proxy usage** is **enabled** (`proxy_enabled = true`) and whether we have a **non-empty proxy list**.
   - Based on this, we do one of the following:
     - **Proxy is ON & we have proxies**: Attempt the exploit with **one or more** proxies in a loop (retrying).  
     - **Proxy is ON & we have no proxies**: Just do a **direct** attempt (warn user).  
     - **Proxy is OFF**: Only do a **direct** attempt.  

---

## 2. When Proxy is ON (and Proxies Are Loaded)

If `proxy_enabled == true` and `proxy_list` is **not** empty, the `run` logic does this:

1. **Create** a `HashSet<String>` called `tried_proxies` – this will track which proxies we have already used and failed on.

2. **Loop** until either:
   - We **succeed** with a proxy, or  
   - We have tried **all** proxies in `proxy_list`.

3. **Pick a Random Proxy**  
   - We call `pick_random_untried_proxy(&ctx.proxy_list, &tried_proxies)`.  
   - This function filters out any proxies that are already in `tried_proxies` (i.e., ones that failed previously).  
   - It then chooses **one** from the remaining pool **at random**.  
   - If all have been tried, it falls back to picking *any* random proxy from the full list (ensuring no panic).

4. **Set `ALL_PROXY` Environment Variable**  
   - We call `set_all_proxy_env(&chosen_proxy)`.  
   - Inside that function, we do:  
     ```rust
     env::set_var("ALL_PROXY", proxy);
     ```
   - Because your exploit modules use `reqwest` (with the `socks` feature), **any** request they make automatically goes through that proxy (whether it’s HTTP, HTTPS, SOCKS4, or SOCKS5).

5. **Run the Module**  
   ```rust
   match commands::run_module(module_path, t).await {
       Ok(_) => { ... }
       Err(e) => { ... }
   }
   ```
   - This calls the real exploit/scanner/cred module. The module tries to send its requests.  
   - Because `ALL_PROXY` is set, **all** of its traffic routes through the chosen proxy.  

6. **Check the Result**  
   - If it returns `Ok(())`, that means the exploit **did not** fail at the top level. We **break** the loop and stop retrying.  
   - If it returns `Err(e)`, we:
     1. Print an error message.  
     2. Add the **chosen proxy** to `tried_proxies`.  
     3. Repeat the loop, picking a new untried proxy.  

7. **Exhausting All Proxies**  
   - If we eventually try **every** proxy in `proxy_list` (i.e., `tried_proxies.len() == ctx.proxy_list.len()`) and **still** fail, we exit the loop.  

8. **Final Fallback: Direct Attempt**  
   - If we never got a success, we do a **final** attempt **without** any proxy:  
     ```rust
     clear_proxy_env_vars();
     commands::run_module(module_path, t).await;
     ```
   - That either succeeds or fails. If it fails, we simply print the error and continue (or end).  

---

## 3. When Proxy is ON but No Proxies Are Loaded

If `proxy_enabled == true` but `proxy_list` is empty:

1. We **cannot** pick a proxy, so we simply show a warning:
   ```
   [!] No proxies loaded, but proxy is ON. Doing direct attempt...
   ```
2. We call `clear_proxy_env_vars()` to ensure we’re not using a stale proxy environment variable.
3. We run the module once. No retries occur here.

---

## 4. When Proxy is OFF

If `proxy_enabled == false`, we do a **single** direct attempt:

1. `clear_proxy_env_vars()` is called to remove any existing proxy environment variables.  
2. `commands::run_module(module_path, t).await` is called.  
3. If it fails, we just print the error. We do **not** retry.

---

## 5. Summarizing the Retry Logic

Below is a simplified flowchart of the “**Proxy is ON & Proxies Are Loaded**” scenario:

```
+--------------------------+
| Start 'run' command      |
+--------------------------+
          |   (Check if module & target are set)
          v
+-------------------------------+
| tried_proxies = empty set    |
+-------------------------------+
          |
          | while tried_proxies.len() < proxy_list.len():
          v
+--------------------------------------------------+
| pick_random_untried_proxy(proxy_list, tried_set) |
+--------------------------------------------------+
          |
          | set_all_proxy_env(chosen_proxy)
          v
+-----------------------------------------+
| run_module(module_path, target) => Err? |
+-----------------------------------------+
          |            |
      (Ok) |            | (Err)
          v            v
        (Stop)     tried_proxies.insert(chosen_proxy)
                        (loop again)

If we exit the loop with no success:
  => clear_proxy_env_vars()
  => do a final direct run_module()
```

Hence, after each failure, we remove that proxy from the candidate pool and pick a new one. We do **not** pick the same failing proxy again. If, after exhausting **all** proxies, everything fails, we do one **direct** attempt with no proxy.

---

## 6. Why This Requires No Changes to Exploit Modules

- **All** changes happen at the shell level (the `run` command).  
- Each time we call `commands::run_module(...)`, we have **already** set the environment variable `ALL_PROXY`.  
- The exploit modules (e.g., `sample_exploit.rs`) simply use `reqwest` without knowing or caring about proxies.  
- `reqwest` automatically checks `ALL_PROXY` and routes traffic accordingly.  
- If that proxy fails for any reason (connection refused, times out, etc.), `run_module(...)` returns an error to the shell, triggering the **retry** logic.  

---

## 7. Practical Considerations

1. **Module-Level vs. Shell-Level Retries**  
   - We do an entire “exploit run” in one attempt. If the exploit tries multiple sub-requests and fails halfway, from the shell’s perspective it’s just one run that failed.  
   - We then pick a new proxy and re-run from scratch.  

2. **Timeouts**  
   - If a proxy is **very** slow or dead, you may not get an error for a while (unless your module sets timeouts).  
   - Consider setting a **short** timeout in your modules if you want to quickly detect non-functional proxies.  

3. **Full Proxy Exhaustion**  
   - If every proxy fails, we do a final direct attempt. If that also fails, we give up.  

4. **Thread-Safety**  
   - Because we’re doing everything in a single-threaded loop, environment-variable changes are straightforward.  
   - In a multi-threaded scenario, changing `ALL_PROXY` globally might cause conflicts or race conditions.  

---

## 8. Final Summary

1. **User** types `run`.  
2. If **proxy is on** and there are proxies in the list, the shell tries them **one by one** (random order), setting `ALL_PROXY` each time and calling `run_module`.  
3. On each **failure**, the shell adds that proxy to a “tried” set and repeats with a **new** proxy.  
4. If the user **exhausts** all proxies (they all fail), the shell **finally** attempts a **direct** run (no proxy).  
5. If the exploit **succeeds** at any point, we **stop** retrying.  
6. This entire sequence requires **no changes** to the exploit modules, as they already rely on `reqwest`, which automatically respects `ALL_PROXY`.

That’s the logic behind automatic proxy retries for failing requests!

# Utilities & Helpers

Rustsploit provides three utility modules that every module developer should know:

| Module | Import Path | Purpose |
|--------|-------------|---------|
| **Core Utils** | `crate::utils` | Target normalization, file loading, config-aware prompts, input validation |
| **Creds Utils** | `crate::modules::creds::utils` | Bruteforce statistics, subnet helpers, IP exclusion, scan state tracking |
| **Config** | `crate::config` | Global target state, module config, API prompt keys, results directory |

---

## `crate::utils` — Core Utilities

### `load_lines(path) → Result<Vec<String>>`

Reads a file line-by-line, trims whitespace, and drops empty lines. The standard way to load wordlists, username files, or any line-delimited input.

```rust
use crate::utils::load_lines;

let passwords = load_lines("passwords.txt")?;
for pw in &passwords {
    // each entry is trimmed, non-empty
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | `impl AsRef<Path>` | Path to the file to read |

**Returns:** `Vec<String>` of non-empty, trimmed lines. Errors if the file cannot be opened.

---

### `normalize_target(raw) → Result<String>`

Comprehensive target normalization and validation. This is the **single entry point** for converting any user-supplied target into a consistent format.

```rust
use crate::utils::normalize_target;

let target = normalize_target(user_input)?;
// target is now in one of:
//   "192.168.1.1"          (IPv4)
//   "192.168.1.1:8080"     (IPv4 + port)
//   "[::1]"                (IPv6)
//   "[::1]:8080"           (IPv6 + port)
//   "example.com"          (hostname)
//   "192.168.1.0/24"       (CIDR)
```

| Input Format | Example |
|--------------|---------|
| IPv4 | `192.168.1.1` |
| IPv4 + port | `192.168.1.1:8080` |
| IPv6 | `::1`, `2001:db8::1` |
| IPv6 + port | `[::1]:8080` |
| Hostname | `example.com`, `example.com:443` |
| URL | `http://example.com:8080` → extracts `example.com:8080` |
| CIDR | `192.168.1.0/24`, `2001:db8::/32` |

**Security:** Validates against DoS-length abuse (max 2048 chars), control characters, and path traversal patterns (`..`, `//`).

---

### Config-Aware Prompt Wrappers (`cfg_prompt_*`)

These are the **recommended prompts for module authors**. They check `ModuleConfig.custom_prompts` first (populated by the API), falling back to interactive stdin when running in shell mode. This makes your module work seamlessly in both shell and API modes.

#### `cfg_prompt_yes_no(key, msg, default_yes) → Result<bool>`

Boolean prompt. Accepts `y/yes/true/1` and `n/no/false/0`.

```rust
use crate::utils::cfg_prompt_yes_no;

let verbose = cfg_prompt_yes_no("verbose", "Enable verbose output?", false)?;
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `&str` | Lookup key in `ModuleConfig.custom_prompts` |
| `msg` | `&str` | Prompt message shown to user in shell mode |
| `default_yes` | `bool` | Default when input is empty or key absent in API mode |

---

#### `cfg_prompt_existing_file(key, msg) → Result<String>`

Prompts for a file path. Validates the file exists, rejects path traversal (`..`), symlinks, and control characters.

```rust
use crate::utils::cfg_prompt_existing_file;

let wordlist = cfg_prompt_existing_file("password_wordlist", "Password wordlist file")?;
let lines = load_lines(&wordlist)?;
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `&str` | Prompt key for API mode |
| `msg` | `&str` | Interactive prompt message |

**Errors** in API mode if key is missing (required field).

---

#### `cfg_prompt_int_range(key, msg, default, min, max) → Result<i64>`

Integer prompt with range validation.

```rust
use crate::utils::cfg_prompt_int_range;

let threads = cfg_prompt_int_range("threads", "Number of threads", 10, 1, 100)?;
let delay = cfg_prompt_int_range("delay_ms", "Delay between attempts (ms)", 50, 0, 60000)?;
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `&str` | Prompt key |
| `msg` | `&str` | Interactive prompt message |
| `default` | `i64` | Default value |
| `min` | `i64` | Minimum allowed value |
| `max` | `i64` | Maximum allowed value |

---

#### `cfg_prompt_default(key, msg, default) → Result<String>`

Generic string prompt with a default value.

```rust
use crate::utils::cfg_prompt_default;

let method = cfg_prompt_default("http_method", "HTTP method", "GET")?;
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `&str` | Prompt key |
| `msg` | `&str` | Interactive prompt message |
| `default` | `&str` | Default value when empty |

---

#### `cfg_prompt_port(key, msg, default) → Result<u16>`

Port number prompt. Validates range 1–65535.

```rust
use crate::utils::cfg_prompt_port;

let port = cfg_prompt_port("port", "Target port", 22)?;
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `&str` | Prompt key |
| `msg` | `&str` | Interactive prompt message |
| `default` | `u16` | Default port number |

---

#### `cfg_prompt_output_file(key, msg, default) → Result<String>`

Output filename prompt. **Forces basename only** — strips any directory path to prevent traversal. Rejects hidden files (starting with `.`) and filenames over 255 chars.

```rust
use crate::utils::cfg_prompt_output_file;

let output = cfg_prompt_output_file("output_file", "Output file", "results.txt")?;
// output is guaranteed to be a safe basename like "results.txt"
```

---

### Complete Module Integration Example

Here's a typical module using all the core utils together:

```rust
use crate::utils::{
    load_lines, normalize_target,
    cfg_prompt_yes_no, cfg_prompt_existing_file, cfg_prompt_int_range,
    cfg_prompt_default, cfg_prompt_port, cfg_prompt_output_file,
};

pub async fn run(target: &str) -> anyhow::Result<()> {
    let target = normalize_target(target)?;

    // Gather config — works in both shell and API mode
    let port       = cfg_prompt_port("port", "Target port", 22)?;
    let user_file  = cfg_prompt_existing_file("user_wordlist", "Username wordlist")?;
    let pass_file  = cfg_prompt_existing_file("pass_wordlist", "Password wordlist")?;
    let threads    = cfg_prompt_int_range("threads", "Threads", 10, 1, 100)? as usize;
    let delay      = cfg_prompt_int_range("delay_ms", "Delay (ms)", 50, 0, 60000)? as u64;
    let verbose    = cfg_prompt_yes_no("verbose", "Verbose output?", false)?;
    let output     = cfg_prompt_output_file("output_file", "Output file", "results.txt")?;

    // Load wordlists
    let users = load_lines(&user_file)?;
    let passwords = load_lines(&pass_file)?;

    println!("[*] Targeting {} with {} users × {} passwords", target, users.len(), passwords.len());
    // ... bruteforce logic ...
    Ok(())
}
```

---

## `crate::modules::creds::utils` — Credential Module Utilities

Import path:

```rust
use crate::modules::creds::utils::{
    BruteforceStats, is_subnet_target, parse_subnet, subnet_host_count,
    generate_random_public_ip, is_ip_checked, mark_ip_checked, parse_exclusions,
};
```

---

### `BruteforceStats`

Thread-safe statistics tracker for bruteforce modules. Uses atomics for counters and a `Mutex<HashMap>` for error categorization. Create one per module run and share via `Arc`.

```rust
use std::sync::Arc;
use crate::modules::creds::utils::BruteforceStats;

let stats = Arc::new(BruteforceStats::new());

// In each worker task:
let stats = Arc::clone(&stats);
tokio::spawn(async move {
    match attempt_login(&host, &user, &pass).await {
        Ok(true) => stats.record_success(),
        Ok(false) => stats.record_failure(),
        Err(e) => stats.record_error(format!("{}", e)).await,
    }

    // Show live progress (prints inline with \r)
    stats.print_progress();
});

// After all tasks complete:
stats.print_final().await;
```

#### Methods

| Method | Async | Description |
|--------|-------|-------------|
| `BruteforceStats::new()` | No | Create a new stats tracker (starts the timer) |
| `.record_success()` | No | Increment total + successful counters |
| `.record_failure()` | No | Increment total + failed counters |
| `.record_error(msg)` | **Yes** | Increment total + error counters, log error message |
| `.record_retry()` | No | Increment retry counter |
| `.print_progress()` | No | Print inline progress bar (`\r` overwrite) |
| `.print_final()` | **Yes** | Print full statistics summary with top 5 errors |

---

### `is_subnet_target(target) → bool`

Check if a target string is CIDR notation (e.g., `192.168.8.0/21`). Use this to branch between single-host and subnet-scan logic.

```rust
use crate::modules::creds::utils::is_subnet_target;

if is_subnet_target(&target) {
    // Iterate subnet
} else {
    // Single host
}
```

---

### `parse_subnet(target) → Result<IpNetwork>`

Parse a CIDR string into an `ipnetwork::IpNetwork`. **Does NOT allocate a Vec** — callers iterate lazily with `.iter()`, making it safe for any prefix size (`/0` through `/32`).

```rust
use crate::modules::creds::utils::parse_subnet;

let network = parse_subnet("192.168.1.0/24")?;
for ip in network.iter() {
    println!("Scanning {}", ip);
}
```

---

### `subnet_host_count(net) → u128`

Returns the number of host IPs in a network. Useful for progress display and ETA calculations.

```rust
use crate::modules::creds::utils::{parse_subnet, subnet_host_count};

let net = parse_subnet("10.0.0.0/8")?;
println!("Scanning {} hosts", subnet_host_count(&net));
// → "Scanning 16777216 hosts"
```

---

### `generate_random_public_ip(exclusions) → IpAddr`

Generates a random IPv4 address that is **not** in any excluded range. Automatically skips `10.x.x.x`, `127.x.x.x`, and `0.x.x.x` in addition to the provided exclusion list. Used by mass-scanning modules (Camxploit, etc.).

```rust
use crate::modules::creds::utils::{generate_random_public_ip, parse_exclusions};

let exclusions = parse_exclusions(&[
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",    // Private
    "100.64.0.0/10",                                       // CGNAT
    "224.0.0.0/4",                                          // Multicast
]);

let ip = generate_random_public_ip(&exclusions);
println!("Random target: {}", ip);
```

---

### `parse_exclusions(cidrs) → Vec<IpNetwork>`

Parses an array of CIDR strings into `IpNetwork` objects for use with `generate_random_public_ip`. Invalid CIDRs are silently skipped.

```rust
use crate::modules::creds::utils::parse_exclusions;

let excluded = parse_exclusions(&["10.0.0.0/8", "192.168.0.0/16", "not-valid"]);
// excluded.len() == 2 (invalid entry silently dropped)
```

---

### `is_ip_checked(ip, state_file) → bool` / `mark_ip_checked(ip, state_file)`

Persistent scan-state tracking. Prevents re-scanning the same IP across multiple runs by writing `checked: <ip>` lines to a state file.

```rust
use crate::modules::creds::utils::{is_ip_checked, mark_ip_checked};

let state_file = "mqtt_cidr_results.txt";

for ip in network.iter() {
    if is_ip_checked(&ip, state_file).await {
        continue; // Already scanned
    }

    // ... scan the IP ...

    mark_ip_checked(&ip, state_file).await;
}
```

| Function | Async | Description |
|----------|-------|-------------|
| `is_ip_checked(ip, state_file)` | **Yes** | Returns `true` if IP was previously marked. Creates the state file if missing. |
| `mark_ip_checked(ip, state_file)` | **Yes** | Appends `checked: <ip>` to the state file. |

> **Note:** Both functions accept any type implementing `ToString` for the IP parameter.

---

## Complete Credential Module Example

Putting both utility modules together in a real bruteforce module:

```rust
use std::sync::Arc;
use crate::utils::{
    load_lines, normalize_target,
    cfg_prompt_port, cfg_prompt_existing_file,
    cfg_prompt_int_range, cfg_prompt_yes_no, cfg_prompt_output_file,
};
use crate::modules::creds::utils::{
    BruteforceStats, is_subnet_target, parse_subnet, subnet_host_count,
    generate_random_public_ip, is_ip_checked, mark_ip_checked, parse_exclusions,
};

pub async fn run(target: &str) -> anyhow::Result<()> {
    let target = normalize_target(target)?;
    let port = cfg_prompt_port("port", "Target port", 1883)?;
    let user_file = cfg_prompt_existing_file("user_wordlist", "Username wordlist")?;
    let pass_file = cfg_prompt_existing_file("pass_wordlist", "Password wordlist")?;
    let threads = cfg_prompt_int_range("threads", "Threads", 10, 1, 200)? as usize;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose?", false)?;
    let output = cfg_prompt_output_file("output_file", "Output file", "results.txt")?;

    let users = load_lines(&user_file)?;
    let passwords = load_lines(&pass_file)?;
    let stats = Arc::new(BruteforceStats::new());

    if is_subnet_target(&target) {
        let network = parse_subnet(&target)?;
        println!("[*] Subnet scan: {} hosts", subnet_host_count(&network));
        for ip in network.iter() {
            if is_ip_checked(&ip, &output).await { continue; }
            // ... bruteforce ip ...
            mark_ip_checked(&ip, &output).await;
        }
    } else {
        // ... single host bruteforce ...
    }

    stats.print_final().await;
    Ok(())
}
```

---

## `crate::config` — Framework Configuration

Import path:

```rust
use crate::config::{
    GLOBAL_CONFIG, GlobalConfig, TargetConfig,
    ModuleConfig, get_module_config, set_module_config, clear_module_config,
    results_dir,
};
```

---

### `GLOBAL_CONFIG` (static `GlobalConfig`)

Thread-safe singleton that holds the current target. Set by the shell (`set target`) or CLI (`--target`). Module code reads it but rarely needs to write to it.

```rust
use crate::config::GLOBAL_CONFIG;

// Check if a target is set
if !GLOBAL_CONFIG.has_target() {
    println!("No target set!");
    return Ok(());
}

// Read the target as a string
let target = GLOBAL_CONFIG.get_target().unwrap();
println!("Targeting: {}", target);
```

#### `GlobalConfig` Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `.set_target(target)` | `Result<()>` | Set global target (IP, hostname, or CIDR). Validates input. |
| `.get_target()` | `Option<String>` | Get the target as a display string |
| `.get_single_target_ip()` | `Result<String>` | Get single IP; for subnets returns the network address |
| `.has_target()` | `bool` | Check if any target is set |
| `.is_subnet()` | `bool` | `true` if the target is a CIDR subnet |
| `.get_target_subnet()` | `Option<IpNetwork>` | Returns the `IpNetwork` if target is a subnet |
| `.get_target_size()` | `Option<u64>` | Number of IPs (1 for single, 2^(32-prefix) for subnets) |
| `.clear_target()` | `()` | Unset the target |

#### `TargetConfig` Enum

```rust
use crate::config::TargetConfig;

pub enum TargetConfig {
    Single(String),         // Single IP or hostname
    Subnet(IpNetwork),      // CIDR subnet
}
```

---

### `ModuleConfig` & API Prompt Keys

`ModuleConfig` bridges modules to the API. When the API server receives a `/api/run` request, it populates a `ModuleConfig` with the JSON `"prompts"` object. The `cfg_prompt_*` functions in `utils.rs` read these values instead of prompting stdin.

#### Struct Fields

```rust
pub struct ModuleConfig {
    pub port: Option<u16>,
    pub username_wordlist: Option<String>,
    pub password_wordlist: Option<String>,
    pub concurrency: Option<usize>,
    pub stop_on_success: Option<bool>,
    pub save_results: Option<bool>,
    pub output_file: Option<String>,
    pub verbose: Option<bool>,
    pub combo_mode: Option<bool>,
    pub custom_prompts: HashMap<String, String>,  // ← cfg_prompt_* reads from here
    pub api_mode: bool,                           // ← prevents stdin fallback
}
```

#### Helper Functions

| Function | Description |
|----------|-------------|
| `get_module_config()` | Get a clone of the current config (safe to call from any module) |
| `set_module_config(config)` | Set the config (called by API server before module execution) |
| `clear_module_config()` | Reset to defaults (called after module execution) |

```rust
use crate::config::get_module_config;

let config = get_module_config();
if config.api_mode {
    // Running via API — don't expect stdin
}
if let Some(port) = config.port {
    // Use pre-configured port
}
```

#### Standardized API Prompt Keys

When building API requests, use these standardized keys in the `"prompts"` JSON object:

**Common keys (most modules):**

| Key | Type | Description |
|-----|------|-------------|
| `port` | u16 | Target service port |
| `timeout` | int | Connection timeout (seconds or ms) |
| `verbose` | y/n | Verbose output |
| `save_results` | y/n | Save results to file |
| `output_file` | string | Output filename |
| `concurrency` | int | Concurrent threads/tasks |
| `threads` | int | Alias for concurrency |
| `wordlist` | path | Path to wordlist file |
| `target_file` | path | File containing targets |
| `mode` | string | Operation mode (1, 2, 3, etc.) |

**Scanner-specific keys** (see full list in `config.rs` doc comments):
- Port Scanner: `port_range`, `scan_method`, `show_only_open`
- Dir Brute: `scan_mode`, `delay_ms`, `random_agent`, `use_https`
- Sequential Fuzzer: `min_length`, `max_length`, `charset`, `encoding`
- API Endpoint Scanner: `output_dir`, `use_spoofing`, `enable_delete`, `modules`

---

### `results_dir() → PathBuf`

Returns `~/.rustsploit/results/`, creating it if needed. Use this when saving module output in API mode.

```rust
use crate::config::results_dir;

let out_path = results_dir().join("scan_output.txt");
std::fs::write(&out_path, results)?;
```

---

## Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_TARGET_LENGTH` | 2048 | Maximum target string length |
| `MAX_MODULE_PATH_LENGTH` | 512 | Maximum module path length |
| `MAX_COMMAND_LENGTH` | 8192 | Maximum command/input length |
| `MAX_PATH_LENGTH` | 4096 | Maximum file path length |
| `MAX_DEPTH` | 6 | Maximum module discovery depth |
| `MAX_HOSTNAME_LENGTH` | 253 | Maximum hostname length (config.rs) |

---

## Extending Utils

Add new reusable helpers to `utils.rs`, `creds/utils.rs`, or `config.rs` rather than copy-pasting into individual modules. Common candidates:
- HTTP header templates
- Response fingerprinting helpers
- Common error formatters
- Credential loaders with streaming support

# Utilities & Helpers

Rustsploit provides several utility modules that every module developer should know:

| Module | Import Path | Purpose |
|--------|-------------|---------|
| **Core Utils** | `crate::utils` | Target normalization, file loading, config-aware prompts, input validation |
| **Network Utils** | `crate::utils::network` | HTTP client builders, TCP/UDP connect helpers, honeypot check |
| **Privilege Utils** | `crate::utils::privilege` | Root privilege check for raw-socket modules |
| **Creds Helper** | `crate::utils::creds_helper` | Single-target credential brute-force harness (prompt, engine, loot, findings) |
| **Exploit Helper** | `crate::utils::exploit_helper` | HTTP probe helpers for single-target CVE exploit modules |
| **Creds Utils** | `crate::modules::creds::utils` | Bruteforce statistics, subnet helpers, IP exclusion, scan state tracking |
| **Config** | `crate::config` | Global target state, module config, API prompt keys, results directory |
| **Global Options** | `crate::global_options` | Persistent `setg` options — checked by `cfg_prompt_*` after custom_prompts |
| **Cred Store** | `crate::cred_store` | Store/query discovered credentials. Call `store_credential()` from modules |
| **Workspace** | `crate::workspace` | Track hosts/services. Call `track_host()` / `track_service()` from modules |
| **Loot** | `crate::loot` | Store collected evidence. Call `store_loot()` from modules |
| **Module Info** | `crate::module_info` | `ModuleInfo`, `ModuleRank`, `CheckResult` types for `info()`/`check()` |
| **Spool** | `crate::spool` | Console output logging. Call `spool::sprintln()` for spool-aware output |
| **Jobs** | `crate::jobs` | Background job management via `JOB_MANAGER` |
| **Export** | `crate::export` | Export engagement data to JSON/CSV/summary |

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

#### `cfg_prompt_required(key, msg) → Result<String>`

Required string prompt with no default. In API mode, errors if the key is missing from `custom_prompts`. Priority: custom_prompts > run_context target (for "target" key) > global_options > interactive stdin.

```rust
use crate::utils::cfg_prompt_required;

let community = cfg_prompt_required("community", "SNMP community string").await?;
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `&str` | Lookup key in `ModuleConfig.custom_prompts` |
| `msg` | `&str` | Prompt message shown to user in shell mode |

**Errors** in API mode if key is missing (required field).

---

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

#### `cfg_prompt_wordlist(key, msg) → Result<String>`

Wordlist file prompt. Validates the file exists, rejects path traversal and unsafe paths (same security as `cfg_prompt_existing_file`). Priority: custom_prompts > global_options > interactive stdin.

```rust
use crate::utils::cfg_prompt_wordlist;

let wordlist = cfg_prompt_wordlist("wordlist", "Path to wordlist file").await?;
let lines = load_lines(&wordlist)?;
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `&str` | Prompt key for API mode |
| `msg` | `&str` | Interactive prompt message |

**Errors** in API mode if key is missing (required field). Also errors if the file does not exist.

---

### Complete Module Integration Example

Here's a typical native module using core utils:

```rust
use anyhow::{Context, Result};
use crate::module::{ModuleCtx, ModuleOutcome};
use crate::utils::{
    load_lines,
    cfg_prompt_yes_no, cfg_prompt_existing_file,
    cfg_prompt_int_range, cfg_prompt_port,
    cfg_prompt_output_file,
};

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("requires single target")?;
    let mut outcome = ModuleOutcome::ok();

    let port       = cfg_prompt_port("port", "Target port", 22).await?;
    let user_file  = cfg_prompt_existing_file("user_wordlist", "Username wordlist").await?;
    let pass_file  = cfg_prompt_existing_file("pass_wordlist", "Password wordlist").await?;
    let threads    = cfg_prompt_int_range("threads", "Threads", 10, 1, 100).await? as usize;
    let verbose    = cfg_prompt_yes_no("verbose", "Verbose output?", false).await?;
    let output     = cfg_prompt_output_file("output_file", "Output file", "results.txt").await?;

    let users = load_lines(&user_file)?;
    let passwords = load_lines(&pass_file)?;

    crate::mprintln!("[*] Targeting {} with {} users × {} passwords", target, users.len(), passwords.len());
    // ... bruteforce logic using tcp_connect_str for source port support ...
    Ok(outcome)
}
```

---

## `crate::utils::creds_helper` — Single-Target Credential Harness (v0.5.5+)

The preferred way to write a credential brute-force module. Wraps: target parsing,
TCP precheck, wordlist prompts, brute-force engine wiring, loot persistence,
workspace tracking, and `Finding` emission.

```rust
use crate::utils::creds_helper::{self, CredsRun};
use crate::utils::LoginResult;

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("requires single target")?;
    creds_helper::run(
        target,
        CredsRun {
            service_name: "myproto",
            default_port: 1234,
            source_module: "creds/generic/myproto_bruteforce",
            defaults: &[("admin", "admin")],
            password_only: false,
        },
        |host, port, user, pass, timeout| async move {
            probe(&host, port, &user, &pass, timeout).await
        },
    )
    .await
}
```

### Probe closure signature

```rust
Fn(String, u16, String, String, Duration) -> Future<Output = LoginResult>
```

The fifth parameter (`Duration`) is the user-configured timeout from `setg timeout N`
or the interactive prompt. It is passed through to the probe so inner functions honour
the operator's setting — no hardcoded timeouts inside probes.

### Utility functions

| Function | Description |
|----------|-------------|
| `connect_with_timeout(addr, deadline)` | Async TCP connect via framework wrapper → `io::Result<TcpStream>` |
| `read_exact_with_timeout(reader, buf, deadline)` | Exact-read with timeout, flattened error |
| `parse_host_port(target, default_port)` | Public `(host, port)` splitter |

### Modules using creds_helper

All 13 generic credential modules: `couchdb`, `elasticsearch`, `fortinet`,
`l2tp`, `memcached`, `mqtt`, `mysql`, `postgres`, `rdp`, `rtsp`, `snmp`,
`telnet`, `vnc` bruteforces.

---

## `crate::utils::exploit_helper` — HTTP Exploit Probe Helpers (v0.5.5+)

Shared helpers for single-target CVE exploit probes:

| Function | Description |
|----------|-------------|
| `http_client(timeout)` | `reqwest::Client` via `build_http_client` |
| `marker(prefix)` | Random marker string for echo-based detection |
| `report_vulnerable(host, port, cve, summary, payload, source)` | Emit finding + loot |
| `report_not_vulnerable(host, port, reason)` | Log not-vulnerable result |
| `scheme_for(port)` | Returns `"https"` for 443/8443, `"http"` otherwise |

Used by 18+ exploit modules to reduce each to ~50 LOC.

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

> **Deprecated for module use.** Random IP generation is now handled by
> `scheduler::fanout_random` with `crate::exclusions::ExclusionSet`. Modules
> should NOT call this directly — the scheduler does the fan-out.

Generates a random IPv4 address that is **not** in any excluded range. Automatically skips `10.x.x.x`, `127.x.x.x`, and `0.x.x.x` in addition to the provided exclusion list.

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

The preferred pattern uses `creds_helper::run` (see the creds_helper section above).
For modules that need custom logic beyond the harness:

```rust
use anyhow::{Context, Result};
use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::utils::{
    load_lines,
    cfg_prompt_port, cfg_prompt_existing_file,
    cfg_prompt_int_range, cfg_prompt_yes_no, cfg_prompt_output_file,
};

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("requires single target")?;
    let mut outcome = ModuleOutcome::ok();

    let port = cfg_prompt_port("port", "Target port", 1883).await?;
    let user_file = cfg_prompt_existing_file("user_wordlist", "Username wordlist").await?;
    let pass_file = cfg_prompt_existing_file("pass_wordlist", "Password wordlist").await?;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose?", false).await?;

    let users = load_lines(&user_file)?;
    let passwords = load_lines(&pass_file)?;

    for user in &users {
        for pass in &passwords {
            // Use framework wrappers for source port support
            let stream = crate::utils::network::tcp_connect_str(
                &format!("{}:{}", target, port),
                std::time::Duration::from_secs(10),
            ).await;
            // ... attempt login ...
        }
    }

    Ok(outcome)
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

`ModuleConfig` bridges modules to the API. When the API server receives a `/api/run` request, it populates a `ModuleConfig` with the JSON `"prompts"` object. The `cfg_prompt_*` functions in `src/utils/prompt.rs` read these values instead of prompting stdin.

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
| `MAX_HOSTNAME_LENGTH` | 253 | Maximum hostname length (config.rs) |

---

## `crate::utils::network` — Network Utilities

Import path:

```rust
use crate::utils::network::{
    build_http_client, build_http_client_with, HttpClientOpts,
    tcp_connect_addr, tcp_connect_str, tcp_connect, tcp_port_open,
    blocking_tcp_connect, udp_bind, quick_honeypot_check,
};
```

---

### `build_http_client(timeout) → Result<Client>`

Creates a standard `reqwest::Client` with sensible defaults (danger-accept invalid certs, no redirect limit). Use this instead of hand-rolling `reqwest::Client::builder()`.

```rust
use crate::utils::network::build_http_client;

let client = build_http_client(Duration::from_secs(10))?;
let resp = client.get(&url).send().await?;
```

---

### `build_http_client_with(timeout, opts) → Result<Client>`

Extended HTTP client builder with additional options.

```rust
use crate::utils::network::{build_http_client_with, HttpClientOpts};

let client = build_http_client_with(Duration::from_secs(10), HttpClientOpts {
    cookie_store: true,
    follow_redirects: true,
    user_agent: Some("Mozilla/5.0".to_string()),
    ..HttpClientOpts::default()
})?;
```

#### `HttpClientOpts` Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cookie_store` | `bool` | `false` | Enable cookie jar |
| `follow_redirects` | `bool` | `false` | Follow HTTP redirects |
| `user_agent` | `Option<String>` | `None` | Custom User-Agent header |
| `default_headers` | `Option<HeaderMap>` | `None` | Default headers for all requests |

---

### `tcp_connect_addr(addr, timeout) → io::Result<TcpStream>`

Async TCP connection to a `SocketAddr` with timeout and **source port binding**.
When `setg source_port <port>` is active, the socket is bound to that port via
`socket2` before connecting. Uses `SO_REUSEADDR` (and `SO_REUSEPORT` on Linux)
so concurrent mass-scan tasks can share the same source port.

Preferred over raw `TcpStream::connect` — respects global source port setting.

```rust
use crate::utils::network::tcp_connect_addr;

let stream = tcp_connect_addr(addr, Duration::from_secs(5)).await?;
```

---

### `tcp_connect_str(addr_str, timeout) → io::Result<TcpStream>`

Async TCP connection from a `"host:port"` string. Resolves DNS and connects.
Same source port binding as `tcp_connect_addr`.

---

### `tcp_port_open(ip, port, timeout) → bool`

Quick async check if a TCP port is open.

---

### `blocking_tcp_connect(addr, timeout) → io::Result<std::net::TcpStream>`

Synchronous TCP connection for use in `spawn_blocking` contexts. Same source
port binding as the async variants. Used when third-party libraries require
a `std::net::TcpStream` (e.g. `telnet` crate's `Telnet::from_stream`).

---

### `udp_bind(target_ip) → io::Result<UdpSocket>`

Binds a UDP socket to the appropriate address family (IPv4 or IPv6) for the target.
When `setg source_port <port>` is active, binds to that source port.

---

### Source port binding details

All four TCP/UDP wrappers read `GlobalOptions::get("source_port")` at call time.
The implementation uses `socket2::Socket` to:

1. Create a socket with the correct address family
2. Set `SO_REUSEADDR` (and `SO_REUSEPORT` on Linux) for concurrent mass-scan compatibility
3. Bind to `0.0.0.0:<source_port>` (or `[::]:<source_port>` for IPv6)
4. Connect to the target

**Third-party library integration:** Libraries that normally create their own
TCP connections (suppaftp, telnet crate) must receive a pre-connected stream
from these wrappers:

```rust
// FTP via suppaftp
let tcp = tcp_connect_str(&addr, timeout).await?;
let ftp = AsyncFtpStream::connect_with_stream(tcp).await?;

// FTPS via suppaftp
let tcp = tcp_connect_str(&addr, timeout).await?;
let ftp_plain = AsyncNativeTlsFtpStream::connect_with_stream(tcp).await?;
let ftp_tls = ftp_plain.into_secure(connector, domain).await?;

// Telnet (blocking, via spawn_blocking)
let tcp = blocking_tcp_connect(&socket_addr, timeout)?;
let telnet = Telnet::from_stream(Box::new(tcp), 500);
```

---

### `quick_honeypot_check(ip) → bool`

Fast honeypot detection — probes common ports and returns `true` if 11+ respond (likely honeypot).

---

## `crate::utils::privilege` — Privilege Checks

### `require_root(context) → Result<()>`

Call at the top of `run()` in modules that need raw sockets (ICMP, SYN scan, packet crafting). Returns a clean error message if the current euid is not root.

```rust
use crate::utils::privilege::require_root;

pub async fn run(target: &str) -> Result<()> {
    require_root("ICMP raw socket")?;
    // ... raw socket operations ...
}
```

Used by: DoS modules (icmp_flood, syn_ack_flood, null_syn_exhaustion, dns_amplification, etc.), ping_sweep scanner.

---

## `crate::utils::wordlist` — Pinned Resolver + Streaming Reader (v0.4.9+)

Two surfaces in one module: a **checksum-pinned downloader** for canonical lists, and a **streaming line reader** for files too large to slurp into memory.

### `resolve(name) → Result<PathBuf>` (async)

Returns a local path to a wordlist by name. If not already cached, downloads from the pinned catalogue into `~/.rustsploit/wordlists/` (mode `0700`), with size cap (`MAX_BYTES = 256 MiB`), atomic tmp-rename (no torn writes if interrupted), and SHA-256 verification on every fetch — including cached copies, so silent disk tampering is detected.

```rust
use crate::utils::wordlist;

let pwlist = wordlist::resolve("rockyou_top10k").await?;
let lines = crate::utils::load_lines(&pwlist)?;
```

Failure modes: unknown name (suggests close matches via Levenshtein), HTTP error, content-length over cap, mid-stream size overrun, checksum mismatch (file is deleted and the call fails loudly).

### `catalogue() → Vec<&'static str>`

Returns the names of every wordlist this build knows about. Useful for `--list-wordlists`-style introspection.

The catalogue is **intentionally empty by default**. Entries get added by maintainers after fetching + hashing each upstream artefact:

```bash
curl -L <url> | sha256sum
```

There is no TODO placeholder — placeholder hashes that look real but aren't are an integrity hole, so the slot stays empty until verified. To request a wordlist be added, open a PR adding a `WordlistSpec { name, url, sha256, local_name }` tuple to `KNOWN_LISTS`.

### `BatchedReader` — streaming reader

`crate::utils::load_lines` reads a whole file into a `Vec<String>`, which is fine for ~10k entry lists but allocates ~14 GB for `rockyou.txt`-sized inputs. `BatchedReader` instead reads line-by-line through an async `BufReader`, materialising at most `batch_size` lines at a time. Memory use is bounded to `batch_size × average_line_length + 64 KiB` regardless of input size.

```rust
use crate::utils::wordlist::BatchedReader;

let mut reader = BatchedReader::open("rockyou.txt").await?;
while let Some(batch) = reader.next_batch().await? {
    for password in &batch {
        if crate::context::is_cancelled() { return Ok(()); }
        // try password against target
    }
}
```

Lines are trimmed; empty / `#`-prefixed lines are skipped (matches `load_lines` semantics). The reader is `!Send` across `await` (holds a `BufReader<File>`) — keep it on a single task; for parallel work, send each `Vec<String>` batch to workers via a channel.

Constructors:
- `BatchedReader::open(path).await` — default batch size (`DEFAULT_BATCH_SIZE = 8192`).
- `BatchedReader::open_with_batch_size(path, n).await` — explicit. `0` is treated as `1` to avoid pathological infinite loops.

Convenience driver:
- `for_each_batch(path, batch_size, |batch| async { ... }).await` — closure-style iteration, cleaner than the loop-and-call pattern when the body is a single `async` block.

Heuristic helper:
- `should_stream(path) -> bool` — returns true if the file size is `>= STREAMING_THRESHOLD` (16 MiB). Use it to pick the right reader without hard-coding a threshold:
  ```rust
  let lines: Vec<String> = if wordlist::should_stream(&path) {
      // streaming path
      let mut acc = Vec::new();
      let mut r = BatchedReader::open(&path).await?;
      while let Some(b) = r.next_batch().await? { acc.extend(b); }
      acc
  } else {
      crate::utils::load_lines(&path)?
  };
  ```

---

## `crate::native::network` — Low-Level FFI Helpers (v0.4.9+)

Single audited home for `unsafe` socket operations that previously lived duplicated across the DoS module tree. Three layers, pick the smallest one that fits the call site. Every `unsafe` block carries a `SAFETY:` comment.

### Layer 1 — IPv4 fast path (used by all 8 DoS modules today)

```rust
use crate::native::network::{make_dst_sockaddr, send_one_raw};

let dst = make_dst_sockaddr(target_ipv4);
let n = send_one_raw(raw_fd, &packet, &dst)?;
```

- `make_dst_sockaddr(ip: Ipv4Addr) -> libc::sockaddr_in` — POD `sockaddr_in` with `sin_family = AF_INET` and `sin_addr` populated. `sin_port` and `sin_zero` are left zero (raw sockets carry the L4 port in the user-built packet, not the sockaddr).
- `send_one_raw(fd, buf, &sockaddr_in) -> io::Result<usize>` — wrapper around `libc::sendto`; translates `errno` → `io::Error`; never panics.

### Layer 2 — IPv6 fast path

```rust
use crate::native::network::{make_dst_sockaddr_v6, send_one_raw_v6};

// scope_id matters for link-local (fe80::/10); pass 0 for global unicast.
let dst = make_dst_sockaddr_v6(target_ipv6, 0);
let n = send_one_raw_v6(raw_fd_v6, &packet, &dst)?;
```

- `make_dst_sockaddr_v6(ip: Ipv6Addr, scope_id: u32) -> libc::sockaddr_in6` — same shape as the IPv4 builder; `sin6_flowinfo` is left zero.
- `send_one_raw_v6(fd, buf, &sockaddr_in6) -> io::Result<usize>` — IPv6 counterpart of `send_one_raw`. Caller is responsible for `fd` being an `AF_INET6` raw socket.

### Layer 3 — Family-agnostic wrapper

When a module accepts both IPv4 and IPv6 targets and you don't want to fork the call site:

```rust
use crate::native::network::{make_dst_sockaddr_any, send_one_raw_any};

let dst = make_dst_sockaddr_any(target);   // target: std::net::IpAddr
let n = send_one_raw_any(raw_fd, &packet, &dst)?;
```

- `enum DstAddr { V4(sockaddr_in), V6(sockaddr_in6) }` — carries the family and the right `socklen_t` so the caller doesn't have to remember IPv4 vs IPv6 sizes.
- `make_dst_sockaddr_any(IpAddr) -> DstAddr` — convenience builder. For IPv6 link-local where `scope_id` matters, build the `sockaddr_in6` directly with `make_dst_sockaddr_v6` and wrap with `DstAddr::V6`.
- `send_one_raw_any(fd, buf, &DstAddr) -> io::Result<usize>` — `sendto` with the correct `socklen_t` derived from the variant.
- `DstAddr::as_ptr_len() -> (*const sockaddr, socklen_t)` — for callers building their own `sendmmsg(2)` arrays.

### Audit footprint

Project-wide `unsafe` count dropped from 22 → 15 in v0.4.9 by consolidating the IPv4 helpers. The IPv6 + Any helpers add 4 new `unsafe` sites all in this file, but every one carries a `SAFETY:` comment and the contract is identical to the IPv4 variants. Used today by the 8 DoS modules: `ssdp_amplification`, `syn_ack_flood`, `ntp_amplification`, `dns_amplification`, `udp_flood`, `icmp_flood`, `memcached_amplification`, `null_syn_exhaustion`.

---

## Extending Utils

Add new reusable helpers to `src/utils/` (the appropriate submodule: `prompt.rs`, `sanitize.rs`, `target.rs`, `network.rs`, or `modules.rs`), `creds/utils.rs`, or `config.rs` rather than copy-pasting into individual modules. Common candidates:
- HTTP header templates
- Response fingerprinting helpers
- Common error formatters
- Credential loaders with streaming support

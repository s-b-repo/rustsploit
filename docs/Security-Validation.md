# Security & Input Validation

Rustsploit implements defence-in-depth throughout the codebase. All contributors must follow these patterns when writing modules or modifying core code.

---

## Validation Constants

| File | Constant | Value | Purpose |
|------|----------|-------|---------|
| `shell.rs` | `MAX_INPUT_LENGTH` | 4096 | Maximum shell input length |
| `sanitize.rs` | `MAX_TARGET_LENGTH` | 2048 | Maximum target string length |
| `shell.rs` | `MAX_URL_LENGTH` | 2048 | Maximum URL length |
| `shell.rs` | `MAX_PATH_LENGTH` | 4096 | Maximum file path length |
| `utils.rs` | `MAX_FILE_SIZE` | 10 MB | Maximum file size to read |
| `config.rs` | `MAX_HOSTNAME_LENGTH` | 253 | DNS hostname limit |
| `api.rs` | `MAX_REQUEST_BODY_SIZE` | 1 MB | API request body limit |
| `api.rs` | `MAX_TRACKED_IPS` | 100,000 | IP tracker limit |

---

## Security Patterns

### 1. Input Length Validation

```rust
if input.len() > MAX_INPUT_LENGTH {
    return Err(anyhow!("Input too long (max {} characters)", MAX_INPUT_LENGTH));
}
```

### 2. Input Sanitization

The `sanitize_string_input()` function performs multiple layers of cleaning:

1. **Null byte removal** -- inputs containing `\0` are rejected outright
2. **Control character filtering** -- all control characters (except `\t`) are stripped from the input
3. **Length enforcement** -- inputs exceeding `MAX_COMMAND_LENGTH` are rejected

```rust
// Reject null bytes, then filter control characters (except tab)
let sanitized: String = input.chars()
    .filter(|c| !c.is_control() || *c == '\t')
    .collect();
```

For command-specific validation (`validate_command_input`), null bytes are stripped and length is enforced against `MAX_COMMAND_LENGTH`.

If suspicious patterns (`bash`, `sudo`, `../`) are detected, a warning is printed but the string is still returned unmodified:

```
[!] Input contains shell/path patterns. Treated as literal text string.
```

### 3. Path Traversal Prevention

```rust
if input.contains("..") || input.contains("//") {
    return Err(anyhow!("Path traversal detected"));
}
```

### 4. Target / Hostname Validation

Always use the framework's `normalize_target` function:

```rust
use crate::utils::normalize_target;

let normalized = normalize_target(raw_target)?;
// Handles IPv4, IPv6, hostnames, URLs, CIDR with full validation
```

For custom character validation:
```rust
use regex::Regex;
let valid_chars = Regex::new(r"^[a-zA-Z0-9.\-_:\[\]]+$").unwrap();
if !valid_chars.is_match(target) {
    return Err(anyhow!("Invalid characters in target"));
}
```

### 5. Overflow Protection

```rust
// Use saturating_add to prevent integer overflow
counter = counter.saturating_add(1);
```

### 6. Prompt Attempt Limiting

```rust
const MAX_ATTEMPTS: u8 = 10;
let mut attempts = 0u8;
loop {
    attempts += 1;
    if attempts > MAX_ATTEMPTS {
        println!("Too many invalid attempts. Using default.");
        return Ok(default);
    }
    // prompt logic
}
```

### 7. File Operations

When reading files:
1. Validate path does not contain `..`
2. Use `canonicalize()` to resolve the real path
3. Check file size before reading (ref: `MAX_FILE_SIZE`)
4. Skip symlinks for security

---

## API Security

The API server (`api.rs`) implements:

- **`RequestBodyLimitLayer`** — prevents DoS via oversized payloads (1 MB max)
- **Rate limiting** — 3 failed auth attempts → 30 s block per IP
- **Auto-cleanup** — old entries purged at 100,000 entries
- **IP tracking + key rotation** — suspicious activity triggers auto-rotation in hardening mode
- **Secure defaults** — by default, considers `127.0.0.1` as the intended private bind

---

## Honeypot Detection

The framework automatically runs `basic_honeypot_check` before any module execution when a target is set.

- Scans **200 common ports** with a 250 ms timeout each
- If **11 or more** ports respond, warns that the target is likely a honeypot
- Runs automatically in the shell's `run` and `run_all` commands
- Can be called manually from module code:

```rust
use crate::utils::basic_honeypot_check;
basic_honeypot_check(&ip).await;
```

---

## IP Exclusion Ranges (`EXCLUDED_RANGES`)

Standard across mass-scan capable modules (e.g., `camxploit`, `telnet_hose`, `telnet_bruteforce`, exploit modules with 0.0.0.0/0 support):

| CIDR | Category |
|------|----------|
| `10.0.0.0/8` | Private |
| `127.0.0.0/8` | Loopback |
| `172.16.0.0/12` | Private |
| `192.168.0.0/16` | Private |
| `224.0.0.0/4` | Multicast |
| `240.0.0.0/4` | Reserved |
| `0.0.0.0/8` | This network |
| `100.64.0.0/10` | Carrier-grade NAT |
| `169.254.0.0/16` | Link-local |
| `198.18.0.0/15` | Benchmarking |
| `198.51.100.0/24` | Documentation |
| `203.0.113.0/24` | Documentation |
| `255.255.255.255/32` | Broadcast |
| Public DNS | 1.1.1.1, 8.8.8.8, etc. |

Uses the `ipnetwork` crate for proper CIDR matching.

---

## Persistent Storage Security

All persistent data uses atomic write-to-temp-then-rename to prevent corruption:

| File | Purpose | Sensitivity |
|------|---------|-------------|
| `~/.rustsploit/global_options.json` | Global options (setg) | Low — user preferences |
| `~/.rustsploit/creds.json` | Discovered credentials | **High — contains passwords/hashes** |
| `~/.rustsploit/workspaces/<name>.json` | Hosts, services, notes | Medium — engagement data |
| `~/.rustsploit/loot_index.json` | Loot metadata | Medium |
| `~/.rustsploit/loot/` | Loot files | **High — may contain sensitive data** |
| `~/.rustsploit/results/` | Module output files | Medium |
| `~/.rustsploit/history.txt` | Shell command history | Medium |

**Important:** The `creds.json` and `loot/` files may contain sensitive data. Protect `~/.rustsploit/` with appropriate file permissions (e.g., `chmod 700`).

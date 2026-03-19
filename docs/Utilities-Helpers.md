# Utilities & Helpers

`src/utils.rs` provides shared helpers used across shells, CLI, API, and modules. Prefer these over rolling your own to ensure consistent validation and behavior.

---

## Target Normalization

### `normalize_target(raw: &str) -> Result<String>`

Comprehensive target normalization and validation. Accepts:

| Input | Example |
|-------|---------|
| IPv4 | `192.168.1.1` |
| IPv4 + port | `192.168.1.1:8080` |
| IPv6 | `::1`, `2001:db8::1` |
| IPv6 + port | `[::1]:8080` |
| Hostname | `example.com`, `example.com:443` |
| URL | `http://example.com:8080` (extracts host:port) |
| CIDR | `192.168.1.0/24`, `2001:db8::/32` |

Validates against: DoS-length abuse, control characters, path traversal patterns.

```rust
use crate::utils::normalize_target;

let target = normalize_target(raw_input)?;
```

### `extract_ip_from_target(target: &str) -> Result<String>`

Extracts the IP address or hostname from a normalized target string, stripping ports, brackets, and CIDR notation.

---

## Honeypot Detection

### `basic_honeypot_check(ip: &str) -> ()`

Scans 200 common ports with a 250 ms timeout per port. Prints a warning if 11 or more respond.

Runs automatically before module execution in the shell. Call manually in module code if needed:

```rust
use crate::utils::basic_honeypot_check;
basic_honeypot_check(&ip).await;
```

---

## Prompt Helpers

All prompts use `read_safe_input` internally, which enforces `MAX_COMMAND_LENGTH`, strips null bytes, and warns on suspicious patterns without blocking.

| Function | Description |
|----------|-------------|
| `prompt_input(msg)` | Generic string input (empty allowed) |
| `prompt_required(msg)` | String input — loops until non-empty |
| `prompt_default(msg, default)` | String input with fallback default |
| `prompt_yes_no(msg, default)` | Boolean prompt — returns `bool` |
| `prompt_port(msg, default)` | Port number prompt — validates 1–65535 |

```rust
use crate::utils::{prompt_input, prompt_required, prompt_default, prompt_yes_no, prompt_port};

let host = prompt_required("Target host: ")?;
let port = prompt_port("Port", 22)?;
let verbose = prompt_yes_no("Verbose output?", false)?;
```

---

## Module Discovery

| Function | Description |
|----------|-------------|
| `module_exists(name)` | Check if a module name is registered |
| `list_all_modules()` | Returns all registered module paths |
| `find_modules(keyword)` | Fuzzy search modules by keyword |

Used by the shell's `modules`, `find`, and `use` commands. Also used for fuzzy match suggestions (e.g., `sample_xploit` → `sample_exploit`).

---

## File Helpers

When reading files in modules, follow this pattern:

```rust
use std::path::Path;

fn safe_read_file(path: &str) -> Result<String> {
    // 1. Check for traversal
    if path.contains("..") {
        return Err(anyhow!("Path traversal detected"));
    }
    // 2. Canonicalize
    let real = Path::new(path).canonicalize()?;
    // 3. Check size
    let meta = std::fs::metadata(&real)?;
    if meta.len() > MAX_FILE_SIZE {
        return Err(anyhow!("File too large"));
    }
    // 4. Skip symlinks
    if meta.file_type().is_symlink() {
        return Err(anyhow!("Symlinks not allowed"));
    }
    Ok(std::fs::read_to_string(real)?)
}
```

---

## Constants

| Constant | Value | File |
|----------|-------|------|
| `MAX_FILE_SIZE` | 10 MB | `utils.rs` |
| `MAX_PROXIES` | 100,000 | `utils.rs` |
| `MAX_COMMAND_LENGTH` | (see source) | `utils.rs` |

---

## Extending Utils

Add new reusable helpers to `utils.rs` rather than copy-pasting into individual modules. Common candidates:
- Credential loaders (stream a wordlist in chunks)
- HTTP header templates
- Response fingerprinting helpers
- Common error formatters

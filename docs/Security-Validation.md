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
2. Open with `O_NOFOLLOW` to atomically reject symlinks (prevents TOCTOU)
3. Resolve canonical path via `/proc/self/fd/N` on the open file descriptor
4. Check file size before reading (ref: `MAX_FILE_SIZE`)
5. Use `Read::take()` to cap memory usage at IO level

When writing files (spool, export):
1. Validate filename (no traversal, no absolute paths, no symlinks)
2. Open with `O_NOFOLLOW` via `custom_flags(libc::O_NOFOLLOW)` on `OpenOptions`
3. Write to temp file, then atomic rename

### 8. SSRF Protection

The `is_blocked_target()` function blocks cloud metadata and internal endpoints:
- Parses target as `std::net::IpAddr` (handles IPv4, IPv6, mapped addresses)
- Blocks: `169.254.0.0/16` (link-local), `168.63.129.16` (Azure), `100.100.100.200` (Alibaba), `fd00:ec2::*` (AWS IPv6)
- Hostname check: `metadata.google.internal`
- Applied to: `run_module`, `run_all` (per-IP), `check_module`, `honeypot_check`, shell `run`/`run_all`/`check`

### 9. CIDR Size Limits

`run_all` rejects subnets that would cause resource exhaustion:
- IPv4: minimum /16 (65,536 hosts max)
- IPv6: minimum /48

### 10. SQL LIKE Escaping (ArcticAlopex)

All `like()` queries escape user input with `escapeLike()`:
```typescript
function escapeLike(v: string): string {
  return v.replace(/[%_\\]/g, (ch) => `\\${ch}`);
}
```

### 11. ACL Shell Command Gating (ArcticAlopex)

Shell commands are normalized before ACL matching:
```typescript
const cmd = command.trim().toLowerCase().replace(/\s+/g, " ");
```
This prevents whitespace-padding bypasses like `loot  delete`.

**Per-account login lockout:** In addition to IP-based rate limiting, a per-account lockout is enforced: 10 failed login attempts trigger a 30-minute lock on the account.

**Module restrictions enforcement:** The ACL `resolve()` engine now receives `role_module_restrictions` loaded from the database. Previously, an empty array was always passed, effectively bypassing module-level restrictions for all roles.

---

## API Security (Rustsploit Backend)

The API server (`api.rs`) implements:

- **Post-quantum encryption** — ML-KEM-768 + X25519 hybrid, ChaCha20-Poly1305 AEAD, Double Ratchet forward secrecy
- **`RequestBodyLimitLayer`** — prevents DoS via oversized payloads (1 MB max)
- **SSRF protection** — `is_blocked_target()` with IP parsing on all execution endpoints
- **CIDR limits** — rejects prefixes below /16 IPv4, /48 IPv6
- **Shell metacharacter blocking** — `contains_shell_metacharacters()` on all shell commands
- **Module name validation** — alphanumeric + `/` `_` `-` only, max 256 chars
- **File read cap** — `Read::take(1MB)` prevents OOM on large result files
- **Epoch monotonicity** — PQ session rejects replayed messages from older epochs
- **Counter-based nonces** — deterministic nonces derived from `[epoch|counter]`, no birthday risk

## API Security (ArcticAlopex Frontend)

The frontend proxy (`rsf-proxy.ts`, `rsf/[...path]/route.ts`) implements:

- **RBAC enforcement** — every RSF command re-gated against user's role permissions
- **Per-tenant mutex** — serializes write operations to prevent race conditions
- **Input validation** — module names and targets validated before shell command construction
- **Error propagation** — RSF backend errors (401, 500) surfaced to UI instead of silent success
- **Rate limiting** — per-user, Redis-backed, 30 module executions per minute
- **Rate limiting (auth)** — per-IP with second-to-last XFF extraction, 50K entry hard cap, stale cleanup
- **Session security** — HttpOnly, Secure, SameSite=Strict cookies, 8-hour TTL
- **CSRF protection** — SameSite=Strict prevents cross-origin requests
- **SQL injection** — Drizzle ORM parameterized queries + LIKE wildcard escaping
- **TOTP 2FA** — Optional Argon2id + TOTP, secret never exposed in API responses. TOTP secrets are encrypted at rest with AES-256-GCM via MASTER_KEY before DB storage.

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
| `~/.rustsploit/workspaces/{name}_options.json` | Per-workspace options | Low — user preferences |
| `~/.rustsploit/workspaces/{name}_creds.json` | Per-workspace credential store | **High — contains passwords/hashes** |
| `~/.rustsploit/workspaces/<name>.json` | Hosts, services, notes | Medium — engagement data |
| `~/.rustsploit/loot_index.json` | Loot metadata | Medium |
| `~/.rustsploit/loot/` | Loot files | **High — may contain sensitive data** |
| `~/.rustsploit/results/` | Module output files | Medium |
| `~/.rustsploit/history.txt` | Shell command history | Medium |
| `~/.rustsploit/logs/rustsploit.*.log` | Daily rolling log files | Low — operational logs |

**Important:** The `creds.json` and `loot/` files may contain sensitive data. Protect `~/.rustsploit/` with appropriate file permissions (e.g., `chmod 700`).

---

## Cloud Metadata SSRF Protection

The API server (`api.rs`) blocks requests targeting cloud metadata endpoints to prevent SSRF attacks:

| Blocked Target | Cloud Provider |
|----------------|---------------|
| `169.254.169.254` | AWS / GCP / Azure metadata |
| `metadata.google.internal` | GCP metadata |
| `100.100.100.200` | Alibaba Cloud metadata |

These checks apply to all module execution requests (`POST /api/run`) and target-setting operations. Requests targeting these addresses are rejected before any module code executes.

---

## MCP Input Validation

The MCP server (`src/mcp/`) applies the same validation rules as the REST API:

- **Tool parameters** are validated before dispatch. Missing required fields return a JSON-RPC error (`-32602 Invalid params`).
- **Target injection prevention**: The `run_module` tool strips any `target` key from the `prompts` object to prevent prompt-injection SSRF bypass. The target is only accepted from the top-level `target` parameter.
- **Module path validation**: Module paths are checked against the build-time discovered module list before execution.
- **Credential redaction**: The `rustsploit:///credentials` resource redacts secrets (first 3 characters + `***`) to prevent accidental exposure through MCP resource reads.
- **No file system access**: MCP tools do not expose direct file read/write operations. Export data is returned inline as JSON, not written to disk.
- **Rate limiting**: MCP runs over stdio (single client), so no per-IP rate limiting is needed. Concurrency is bounded by the framework's semaphore (CPU count, min 4).

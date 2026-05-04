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

- **PQ-only transport.** All `/api/*` traffic is encrypted with the post-quantum hybrid (ML-KEM-768 + X25519 → ChaCha20-Poly1305 AEAD with a Double Ratchet). No TLS — the PQ channel IS the transport.
- **Per-(server, client) HKDF salts.** As of v0.4.9, salts are NOT hardcoded protocol constants. They're derived at handshake time via `derive_salt(label, server_pubs, client_pubs, identity_dh)` — the `identity_dh` input requires possession of one identity private key to compute, so a passive observer who sees the four public keys still cannot reconstruct the salt. Different (server, client) pairs derive different salt domains; key material from one session never leaks into another.
- **SSH-style allowlist.** A client's identity public key MUST appear in `~/.rustsploit/pq_authorized_keys` for the handshake to succeed (`pq_channel.rs::process_handshake`).
- **Token-bound enrollment.** `POST /pq/register-key` is the only network path that can add a new entry to the allowlist. The token is generated fresh at every `--api` startup (24 random bytes, URL-safe base64), printed to the console once, held only in memory, compared in constant time, and zeroized on first successful use. Subsequent key changes require the established PQ session.
- **Bind-address-agnostic safety.** `--interface` accepts any address (including `0.0.0.0`). Safety doesn't come from refusing public binds — it comes from the token gating the allowlist. There is no `--insecure-bind` escape hatch.
- **`RequestBodyLimitLayer`** — prevents DoS via oversized payloads (1 MB max).
- **Handshake rate limiting** — `HANDSHAKE_RATE_MAX_PER_IP` (10 / 60s) on `/pq/handshake` and `/pq/register-key`. Auto-cleanup of stale entries every 5 min.
- **WebSocket limits** — max 100 concurrent connections, 1 MiB frame cap, 30s heartbeat.
- **Per-session mutex on the server** — `SessionStore` is `RwLock<HashMap<_, Arc<Mutex<PqSession>>>>` so the global map lock isn't held across the inner handler. Different tenants don't serialize through one lock.
- **AAD covers everything.** Every encrypted message authenticates `method | path?query | epoch | session_id` (request) or `status | epoch | session_id` (response). The AAD is built using the post-ratchet epoch on both sides so rekey transitions don't break verification.

---

## MCP Server Security

The MCP server (`mcp/server.rs`) implements:

- **`isolate_protocol_stdout()`** — redirects fd 1 to /dev/null so module `println!` cannot corrupt the JSON-RPC stream
- **`MAX_LINE_BYTES`** — 1 MiB cap on incoming lines to prevent memory exhaustion
- **Binary-safe reads** — uses `read_until()` instead of `read_line()` for no UTF-8 requirement
- **Non-UTF-8 error handling** — returns proper JSON-RPC error responses for malformed input

---

## Spool Security

The spool system (`spool.rs`) implements:

- **`O_NOFOLLOW`** — prevents TOCTOU race conditions on symlinked spool files
- **Parent symlink check** — rejects spool paths with symlinked parent directories
- **Lock-first pattern** — acquires write lock before creating files to prevent orphaned files
- **`write_line()` returns `Result`** — callers handle write failures instead of silently dropping output

---

## Privilege Checks

Modules requiring raw sockets call `require_root()` at startup:

```rust
use crate::utils::privilege::require_root;
require_root("ICMP raw socket")?;
```

Returns a descriptive error with the current euid instead of a cryptic "permission denied" from the socket layer. Used by DoS modules, ping sweep, and raw packet scanners.

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
| `~/.rustsploit/pq_host_key` | Server X25519 + ML-KEM-768 long-term private keys | **Critical — file mode 0600 enforced** |
| `~/.rustsploit/pq_authorized_keys` | SSH-style allowlist of client identity public keys (one JSON per line) | High — file mode 0600 enforced; symlink-safe writes |
| `~/.rustsploit/wordlists/` | Pinned wordlist cache (mode 0700) | Low |

**Important:** The `creds.json` and `loot/` files may contain sensitive data. Protect `~/.rustsploit/` with appropriate file permissions (e.g., `chmod 700`).

---

## Panic-free guarantee (v0.4.9+)

The Rust source tree (`src/`) contains zero panicking patterns. CI policy:

```bash
grep -rnE "\.unwrap\(\)|\.expect\(|panic!\(|unreachable!\(|unimplemented!\(|todo!\(" src/
# Must return zero matches.
```

This applies to module code as well — historical `.expect("slice of length N was checked")` patterns are converted to `try_into().map_err(|_| anyhow!(...))?` even when the invariant truly held, so a future reader doesn't need to verify by hand. The `_or(default)` / `_or_default()` / `_or_else(|| ...)` family is fine — those provide values, not panics.

---

## Supply-chain (v0.4.9 audit)

Scope: 393 unique crates / 427 locked package versions.

| Check | Result |
|-------|--------|
| `cargo audit` (RUSTSEC active vulns) | 0 |
| Cross-ref vs. `categories=["malicious"]` advisories | 0 hits |
| Non-crates.io sources (git / path / alt registry) | 0 |
| Locked checksums present | 427 / 427 |
| `build.rs` scripts grep'd for `TcpStream` / `reqwest` / `curl` / `wget` / `/dev/tcp` / `base64::decode` / `exec` / `eval` / `spawn sh` | 0 hits across 35 build scripts |

**Hygiene notes** (informational):

- `rustls-pemfile` 2.2.0 unmaintained (RUSTSEC-2025-0134) — rustls upstream recommends `rustls-pki-types::pem`; tracked for migration.
- 7 pre-release crypto deps locked (`aead`/`aes-gcm`/`chacha20poly1305`/`poly1305` -rc, `ml-kem` -rc, `hickory-*` -alpha) — all from trusted orgs (RustCrypto, hickory-dns); re-pin to stable when each lands.
- `time` is overridden at `Cargo.toml:133` to `>=0.3.47` to absorb RUSTSEC-2026-0009 from the transitive cookie store.

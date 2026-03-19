# Credential Modules Guide

Best practices for writing and extending brute-force / credential-checking modules.

---

## Common Prompts

Credential modules should interactively prompt for:

- Port number
- Username wordlist path
- Password wordlist path
- Concurrency limit (threads / semaphore slots)
- Stop-on-success toggle
- Output file path
- Verbose logging toggle

Use the shared helpers from `crate::utils`:
```rust
use crate::utils::{prompt_input, prompt_required, prompt_default, prompt_yes_no, prompt_port};
```

---

## Input Handling

- **Trim** wordlist entries and skip blank lines
- **Early exit** if a wordlist is empty
- **Validate paths** — no `..`, use `canonicalize()`
- **Stream large files** — for password files >150 MB, use streaming mode (see RDP module)

---

## Concurrency Model

| Protocol | Recommended approach |
|----------|---------------------|
| FTP, SSH, MQTT, HTTP | `tokio::sync::Semaphore` (wrapped in `Arc`) |
| Telnet, POP3, SMTP | `threadpool` + `crossbeam-channel` |

Avoid unbounded tasks — always cap with a semaphore or pool size.

---

## IPv6 Support

Use `format_addr` to wrap IPv6 addresses in brackets and handle port suffixes:

```rust
// Good
let addr = format_addr(&ip, port); // "[::1]:22"
```

---

## Error Classification

Implement specific error types for better debugging and reporting:

```rust
enum CredsError {
    ConnectionFailed(String),
    AuthenticationFailed,
    CertificateError,
    Timeout,
    NetworkError(String),
    ProtocolError(String),
    ToolNotFound,
}
```

---

## TLS / STARTTLS

Accept invalid certificates for offensive tooling convenience (e.g., `danger_accept_invalid_certs(true)` in reqwest / native-tls), but document this clearly in module comments and output.

---

## Result Persistence

Offer to write `host -> user:pass` pairs to a local file (default `./results.txt`):

```rust
if let Some(ref path) = output_file {
    let line = format!("{} -> {}:{}\n", target, user, pass);
    fs::OpenOptions::new().create(true).append(true).open(path)?.write_all(line.as_bytes())?;
}
```

---

## Module-Specific Notes

### FTP Bruteforce
- 5 operation modes: Single Target, Subnet (CIDR), Batch Scanner, Quick Default Check, Subnet Default Check
- JSON configuration system with load/save/validate
- 32 utility functions including streaming wordlists, JSON/CSV export, network intelligence
- Updated to `suppaftp::tokio` types (v7 compatibility)

### Telnet Bruteforce
- Full IAC (Interpret As Command) negotiation with `process_telnet_iac`
- State machine approach (`TelnetState` enum) — no hardcoded cycle loops
- DNS resolution happens **once** before spawning workers (not per-attempt)
- `BytesMut` for proper partial-read buffer handling
- Password detection handles servers that skip the username prompt

### Telnet Hose (Mass Scanner)
- 500 concurrent workers, disk-based state log (`telnet_hose_state.log`)
- Full Cartesian product of top usernames × passwords
- Accepts `0.0.0.0/0` or a file path as target
- **6-second hard timeout** per IP target
- Auto-detects password-only servers (skips username prompt)

### RDP Bruteforce
- Automatic streaming failover for password files >150 MB
- Security levels: `Auto`, `NLA`, `TLS`, `RDP`, `Negotiate`
- Command injection prevention via argument sanitization for external tool calls

### MQTT Bruteforce
- Full MQTT 3.1.1 protocol — proper variable-length encoding, UTF-8 strings
- `CONNECT` packet construction with `CONNACK` parsing

### SSH User Enumeration
- Timing-attack based (inspired by CVE-2018-15473)
- Statistical analysis using standard deviation to distinguish valid/invalid users
- `tokio::time::Instant` for precise measurements

### L2TP/IPsec
- Multi-platform: strongswan, xl2tpd, pppd, NetworkManager (Linux); rasdial (Windows); networksetup (macOS)
- Proper IPsec Phase 1/2 and L2TP session management
- L2TPv2 packet crafting with AVP encoding

### Camxploit
- Masscan-style parallel scanning (default 200 threads) with `EXCLUDED_RANGES`
- Port-based service filtering — hosts with only SSH/Telnet/RDP ports are skipped
- Time-based progress reporting and output file for discovered cameras

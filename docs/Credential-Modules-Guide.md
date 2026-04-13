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

Use the shared `cfg_prompt_*` helpers from `crate::utils`, which respect the priority chain (API custom_prompts > global options > interactive stdin):
```rust
use crate::utils::{cfg_prompt_required, cfg_prompt_default, cfg_prompt_yes_no, cfg_prompt_port};
```

---

## Input Handling

- **Trim** wordlist entries and skip blank lines
- **Early exit** if a wordlist is empty
- **Validate paths** — no `..`, use `canonicalize()`
- **Stream large files** — for password files >150 MB, use streaming mode (see RDP module)

---

## Concurrency Model

All bruteforce modules use the shared engine (`crate::modules::creds::utils`):

| Function | Use Case |
|----------|----------|
| `run_bruteforce()` | Single-target credential testing with concurrency, progress, retry |
| `run_subnet_bruteforce()` | CIDR subnet scanning with per-host credential testing |
| `run_mass_scan()` | Random/file/CIDR mass scanning with lightweight probes |
| `generate_combos_mode()` | Generate user/password pairs (linear, combo, or spray mode) |
| `load_credential_file()` | Load user:pass pairs from a colon-separated file |

Avoid custom concurrency — always use the engine which handles semaphores, progress reporting, lockout detection, and credential storage.

---

## Combo Modes

All bruteforce modules support three credential combination strategies via `ComboMode`:

| Mode | Ordering | Use Case |
|------|----------|----------|
| `Linear` | Pair user[i] with pass[i], cycling shorter list | Paired credentials from a breach dump |
| `Combo` | Full cross product (every user x every password) | Standard bruteforce |
| `Spray` | For each password, try all users before next password | Active Directory lockout avoidance |

Modules prompt: `Combo mode (linear/combo/spray) [combo]:`

---

## Credential File Support

Modules can load `user:pass` pairs directly from a file (one pair per line, colon-separated):

```rust
use crate::modules::creds::utils::load_credential_file;
let extra = load_credential_file("creds.txt")?;
combos.extend(extra);
```

---

## Jitter Support

`BruteforceConfig.jitter_ms` adds random delay (0..jitter_ms) between attempts to evade IDS pattern detection. Default is 0 (disabled). Also supported in `SubnetScanConfig`.

---

## Protocol Safety

- **Redis** — all commands use RESP array format (length-prefixed) to prevent \r\n injection
- **HTTP** — redirect responses are inspected for login/auth/signin/sso paths to prevent false positives
- **FTP** — 421 (connection limit) responses are classified as retryable errors with backoff
- **SMTP** — connection timeout is 10 seconds (configurable), not the previous 2 seconds

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

> **Note:** Discovered credentials are stored per-workspace. When you switch workspaces (`workspace <name>`), the credential store is scoped to that workspace. This keeps engagement data isolated between different assessments.

Offer to write `host -> user:pass` pairs to a local file (default `./results.txt`):

```rust
if let Some(ref path) = output_file {
    let line = format!("{} -> {}:{}\n", target, user, pass);
    fs::OpenOptions::new().create(true).append(true).open(path)?.write_all(line.as_bytes())?;
}
```

---

## Available Credential Modules (28 total)

### Remote Access Protocols

| Module | Port(s) | Auth Method | Features |
|--------|---------|-------------|----------|
| `ssh_bruteforce` | 22 | libssh2 password auth | Default creds, combo mode, streaming wordlists |
| `ssh_spray` | 22 | Password spray | One password across many targets |
| `ssh_user_enum` | 22 | Timing attack | CVE-2018-15473 style user enumeration |
| `telnet_bruteforce` | 23, 2323 | IAC negotiation + prompt detection | Multi-port, 55+ IoT defaults, shell verification, streaming |
| `telnet_hose` | 23, 2323, 23231 | Default creds mass scan | 500 concurrent, multi-port per host |
| `rdp_bruteforce` | 3389 | Native CredSSP/NTLM | NLA/TLS/RDP/Negotiate security levels |
| `vnc_bruteforce` | 5900 | DES challenge-response (RFB) | Password-only, bit-reversed DES key |
| `ftp_bruteforce` | 21 | FTP/FTPS LOGIN | TLS fallback, error classification |
| `ftp_anonymous` | 21 | Anonymous login check | FTPS fallback, LIST verification |

### Email Protocols

| Module | Port(s) | Auth Method | Features |
|--------|---------|-------------|----------|
| `smtp_bruteforce` | 25, 465, 587 | SMTP AUTH (PLAIN/LOGIN/CRAM-MD5) | STARTTLS support |
| `pop3_bruteforce` | 110, 995 | POP3 USER/PASS | TLS/STLS support |
| `imap_bruteforce` | 143, 993 | IMAP LOGIN | IMAPS (implicit TLS), RFC 3501 escaping |

### Database Protocols

| Module | Port(s) | Auth Method | Features |
|--------|---------|-------------|----------|
| `mysql_bruteforce` | 3306 | Native wire protocol (SHA1 handshake) | HandshakeV10 parsing, salt extraction |
| `postgres_bruteforce` | 5432 | MD5 or cleartext auth | Wire protocol, `md5(md5(pass+user)+salt)` |
| `redis_bruteforce` | 6379 | AUTH command (legacy + ACL) | Redis 6+ ACL support, INFO version detection |
| `elasticsearch_bruteforce` | 9200 | HTTP Basic Auth | Cluster detection, open-access check |
| `couchdb_bruteforce` | 5984 | Session auth + Basic fallback | `/_session` POST, `/_all_dbs` verification |
| `memcached_bruteforce` | 11211 | SASL PLAIN (binary protocol) | Open memcached detection, version check |

### Web Protocols

| Module | Port(s) | Auth Method | Features |
|--------|---------|-------------|----------|
| `http_basic_bruteforce` | 80, 443 | HTTP Basic Authentication | HTTPS, custom paths, redirect detection |
| `fortinet_bruteforce` | 443 | FortiOS web login | CSRF token extraction, realm support |

### Network Management

| Module | Port(s) | Auth Method | Features |
|--------|---------|-------------|----------|
| `snmp_bruteforce` | 161 (UDP) | SNMPv1/v2c community strings | Custom SNMP packet, BER parsing |

### IoT / Messaging

| Module | Port(s) | Auth Method | Features |
|--------|---------|-------------|----------|
| `mqtt_bruteforce` | 1883, 8883 | MQTT 3.1.1 CONNECT | TLS/SSL, anonymous detection, client ID |
| `rtsp_bruteforce` | 554 | RTSP Basic Auth | Path brute-forcing, custom headers |

### VPN

| Module | Port(s) | Auth Method | Features |
|--------|---------|-------------|----------|
| `l2tp_bruteforce` | 1701 (UDP) | L2TP/CHAP handshake | Full L2TP session + PPP CHAP |

### Utility

| Module | Description |
|--------|-------------|
| `enablebruteforce` | Raise file descriptor limits (ulimit) for high-concurrency scans |
| `sample_cred_check` | Template/example credential check module |
| `acti_camera_default` | Multi-protocol default credential check (FTP/SSH/Telnet/HTTP) |
| `camxploit` | Mass camera scanner with port + path + credential testing |

---

## Mass Scanning Support

All 28 credential modules support mass scanning via the framework's multi-target dispatcher. The framework automatically handles:

- **Random targets** (`random`, `0.0.0.0/0`) — generates random public IPs with `EXCLUDED_RANGES` enforcement
- **CIDR ranges** (e.g., `192.168.1.0/24`) — expands and iterates all hosts
- **File-based targets** — reads one target per line from a file path
- **Comma-separated targets** — splits and runs against each target

Modules use `is_mass_scan_target()` to detect mass-scan mode and `run_mass_scan()` to delegate to the framework dispatcher. This is handled at the framework level, so individual modules do not need custom mass-scan loops.

---

### Mass Scan Engine

The mass scan engine (`crate::modules::creds::utils::run_mass_scan`) provides a high-performance framework for internet-wide credential testing. It handles:

- **Random IP generation** with `EXCLUDED_RANGES` enforcement (bogons, private, reserved, documentation, and public DNS ranges)
- **Persistent state tracking** via `is_ip_checked()` / `mark_ip_checked()` to resume interrupted scans
- **Configurable concurrency** with semaphore-based worker pools (default 500 workers for mass scan)
- **Graceful shutdown** on Ctrl+C with state persistence

Modules call `run_mass_scan()` with a closure that performs the per-host probe. The engine manages IP generation, deduplication, and state. See `telnet_hose` and `camxploit` for reference implementations.

---

### ETA, Backoff, and Lockout Detection

Credential modules should implement lockout-aware brute forcing to avoid triggering account lockout policies:

- **Exponential backoff** -- When repeated authentication failures are detected from a single target, increase delay between attempts. The bruteforce engine tracks consecutive failures per host.
- **Lockout detection** -- Monitor for protocol-specific lockout indicators:
  - SSH: `Too many authentication failures` or connection refused after N attempts
  - RDP: `ERR_CONNECT_LOGON_TYPE_NOT_GRANTED` or `ERRCONNECT_ACCOUNT_LOCKED_OUT`
  - HTTP: `429 Too Many Requests` or `403 Forbidden` after prior successes
  - SMTP: `421` temporary rejection
- **ETA calculation** -- `BruteforceStats` tracks attempts/second and remaining combinations. Call `stats.print_progress()` for inline ETA display.
- **Per-host cooldown** -- When lockout is detected, pause attempts against that host for a configurable duration (default 300 seconds) while continuing against other targets in subnet/mass-scan mode.

---

### Streaming Wordlists

For large wordlist files (>150 MB), credential modules should use streaming mode instead of loading the entire file into memory. The streaming approach reads and processes entries in chunks:

```rust
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::fs::File;

let file = File::open(&wordlist_path).await?;
let reader = BufReader::new(file);
let mut lines = reader.lines();

while let Some(line) = lines.next_line().await? {
    let entry = line.trim().to_string();
    if entry.is_empty() { continue; }
    // ... process entry ...
}
```

The RDP bruteforce module (`rdp_bruteforce`) demonstrates this pattern with chunked password processing. When wordlists exceed the streaming threshold, the module reads passwords in batches of 10,000 rather than loading all entries at once. This keeps memory usage constant regardless of wordlist size.

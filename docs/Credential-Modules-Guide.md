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
| `generate_combos()` | Generate user/password pairs (combo or linear mode) |

Avoid custom concurrency — always use the engine which handles semaphores, progress reporting, lockout detection, and credential storage.

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

# Credential Modules Guide

Best practices for writing and extending brute-force / credential-checking modules.

---

## Preferred Pattern: `creds_helper::run`

New credential modules should use the shared harness in `src/utils/creds_helper.rs`
instead of hand-rolling prompt/engine/loot logic. It handles: target parsing, TCP
precheck, wordlist prompts, brute-force engine wiring, loot persistence, workspace
tracking, and `Finding` emission — all in one call.

```rust
use crate::utils::creds_helper::{self, CredsRun};
use crate::utils::LoginResult;

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("module requires a single-host target")?;
    creds_helper::run(
        target,
        CredsRun {
            service_name: "myproto",
            default_port: 1234,
            source_module: "creds/generic/myproto_bruteforce",
            defaults: &[("admin", "admin"), ("root", "")],
            password_only: false,
        },
        |host, port, user, pass, timeout| async move {
            probe(&host, port, &user, &pass, timeout).await
        },
    )
    .await
}
```

The probe closure receives five arguments: `(String, u16, String, String, Duration)`.
The `Duration` is the user-configured timeout (from `setg timeout N` or the prompt),
passed through so inner probe functions honour it — no hardcoded timeouts.

For password-only protocols (VNC, SNMP), set `password_only: true` and `drop(user)`
in the closure:

```rust
|host, port, user, pass, timeout| async move {
    drop(user);
    probe(&host, port, &pass, timeout).await
}
```

### Probe return type

Return `LoginResult` from probes:

```rust
async fn probe(host: &str, port: u16, pass: &str, timeout: Duration) -> LoginResult {
    // ... attempt login ...
    LoginResult::Success          // valid credential
    LoginResult::AuthFailed       // wrong password, keep going
    LoginResult::Error {          // transient or permanent error
        message: format!("connect: {e}"),
        retryable: true,
    }
}
```

### Utility functions in creds_helper

| Function | Description |
|----------|-------------|
| `connect_with_timeout(addr, deadline)` | Flattened async TCP connect → `io::Result<TcpStream>` |
| `read_exact_with_timeout(reader, buf, deadline)` | Flattened exact-read with timeout |
| `parse_host_port(target, default_port)` | Public host/port splitter for reuse |

---

## Manual Prompts (non-creds_helper modules)

For modules that don't use `creds_helper::run` (e.g. `ftp_bruteforce` with its FTPS
fallback and subnet branch), prompt interactively for:

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
| `run_bruteforce()` / `run_bruteforce_streaming()` | Single-target credential testing with concurrency, progress, retry |
| `run_subnet_bruteforce()` | CIDR subnet scanning with per-host credential testing |
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

## Source Port Awareness

All TCP/UDP connections must go through the framework's network wrappers so
`setg source_port <port>` is honoured universally:

| Wrapper | Use case |
|---------|----------|
| `tcp_connect_str(addr, timeout)` | Async TCP from `"host:port"` string |
| `tcp_connect_addr(addr, timeout)` | Async TCP from `SocketAddr` |
| `blocking_tcp_connect(addr, timeout)` | Sync TCP for `spawn_blocking` contexts |
| `udp_bind(Some(ip))` | UDP socket with correct address family |

**Third-party library pattern:** Libraries like `suppaftp` and `telnet` that
normally create their own TCP connections must receive a pre-connected stream
from the framework wrapper:

```rust
// FTP: connect through wrapper, then hand stream to suppaftp
let tcp_stream = tcp_connect_str(&addr, timeout).await?;
let mut ftp = AsyncFtpStream::connect_with_stream(tcp_stream).await?;

// Telnet: connect through wrapper, then hand stream to telnet crate
let tcp_stream = blocking_tcp_connect(&socket_addr, timeout)?;
let telnet = Telnet::from_stream(Box::new(tcp_stream), 500);
```

**Never call `TcpStream::connect()`, `UdpSocket::bind("0.0.0.0:0")`, or
library-level connect functions directly** — they bypass source port binding.

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
| `l2tp_bruteforce` | 1701 (UDP) | L2TPv2 SCCRQ detection | Gateway reachability probe (real L2TP credential brute-force needs full PPP+CHAP stack — out of scope) |

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

- **Random targets** (`random`, `0.0.0.0/0`) — generates random public IPs with exclusion-set enforcement
- **CIDR ranges** (e.g., `192.168.1.0/24`) — expands and iterates all hosts
- **File-based targets** — reads one target per line from a file path
- **Comma-separated targets** — splits and runs against each target

Mass scan is handled entirely at the framework level by `scheduler::run`. Modules
do **not** need `is_mass_scan_target()` checks or `run_mass_scan()` calls — the
scheduler fans out every target type and invokes modules with `Target::Single`.

# API Server

Rustsploit includes a built-in API server (`src/api.rs`, `src/ws.rs`) with post-quantum encrypted WebSocket transport and SSH-style identity key authentication. No TLS. No API keys.

---

## Starting the API Server

```bash
# Basic — auto-generates host key on first run
cargo run -- --api

# Custom bind address
cargo run -- --api --interface 0.0.0.0:9000

# Custom key paths
cargo run -- --api --pq-host-key /path/to/host_key --pq-authorized-keys /path/to/authorized_keys
```

On first run, the server generates a PQ host key pair at `~/.rustsploit/pq_host_key` and prints its fingerprint:
```
🔑 Host key fingerprint: PQ256:a1b2c3d4e5f6...
```

---

## API Flags

| Flag | Description | Required |
|------|-------------|----------|
| `--api` | Enable API server mode | Yes |
| `--interface <addr:port>` | Bind address (default: `127.0.0.1:8080`) | No |
| `--pq-host-key <path>` | PQ host key file (default: `~/.rustsploit/pq_host_key`) | No |
| `--pq-authorized-keys <path>` | Authorized client keys (default: `~/.rustsploit/pq_authorized_keys`) | No |

---

## Authentication — Post-Quantum Identity Keys

Authentication uses SSH-style public/private key pairs with post-quantum cryptography. No API keys or Bearer tokens.

### How it works

1. **Server** has a host key pair (ML-KEM-768 + X25519) stored at `~/.rustsploit/pq_host_key`
2. **Client** has its own identity key pair (ML-KEM-768 + X25519), persisted however the client sees fit (e.g. encrypted at rest in a database, in a keychain, or on disk)
3. Client's public key must be listed in `~/.rustsploit/pq_authorized_keys` — populated via the one-time `POST /pq/register-key` flow at first contact, or by hand-editing the file
4. On first connection, client and server perform a **mutual authentication handshake** at `POST /pq/handshake`
5. Both sides prove key ownership via DH proof-of-possession
6. Session keys are derived from 3 shared secrets: ephemeral X25519 DH + identity X25519 DH + ML-KEM-768
7. All subsequent API traffic is encrypted with ChaCha20-Poly1305 via a Double Ratchet (forward secrecy)

### Authorized keys format

`~/.rustsploit/pq_authorized_keys` — one JSON object per line:
```json
{"name":"acme-tenant","x25519_pub":"base64...","mlkem_ek":"base64..."}
{"name":"redteam","x25519_pub":"base64...","mlkem_ek":"base64..."}
```

### Security properties

| Property | Mechanism |
|----------|-----------|
| Quantum resistance | ML-KEM-768 (NIST FIPS 203, Level 3) |
| Classical resistance | X25519 hybrid (both must be broken) |
| Forward secrecy | Double Ratchet with periodic DH re-keying |
| Mutual authentication | Both sides prove identity key ownership |
| Replay protection | Monotonic epoch counter + unique nonces |
| Tampering detection | ChaCha20-Poly1305 AEAD with AAD |

---

## Endpoints

### Public (no PQ session needed)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/pq/handshake` | Establish PQ-encrypted session (mutual auth) |
| `POST` | `/pq/register-key` | Enroll a client public key using the one-time enrollment token |
| `GET` | `/pq/ws` | Upgrade to PQ-encrypted WebSocket transport |

### Protected (require active PQ session)

**Modules**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/modules` | List all available modules by category |
| `GET` | `/api/modules/search?q=<keyword>` | Search modules by keyword |
| `GET` | `/api/module/{category}/{name}` | Get module info/metadata |
| `POST` | `/api/run` | Execute a module against a target |

**Check**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/check` | Run a module's non-destructive vulnerability check |
| `POST` | `/api/run/all` (alias `POST /api/run_all`) | Run the selected module against all stored hosts |

**Shell**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/shell` | **Disabled** — returns `501 NOT_IMPLEMENTED`. Use the individual RPC endpoints (`/api/run`, `/api/target`, `/api/check`, …) instead. |

**Target**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/target` | Get current global target |
| `POST` | `/api/target` | Set global target |
| `DELETE` | `/api/target` | Clear global target |

**Honeypot Detection**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/honeypot-check` | Check if target is a honeypot |

**Results**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/results` | List saved result files |
| `GET` | `/api/results/{filename}` | Download a result file |

**Global Options**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/options` | List all global options (`setg` values) |
| `POST` | `/api/options` | Set a global option |
| `DELETE` | `/api/options` | Delete a global option |

**Credential Store**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/creds` | List stored credentials |
| `POST` | `/api/creds` | Add a credential manually |
| `DELETE` | `/api/creds` | Delete a credential by ID |

**Workspace / Hosts / Services**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/hosts` | List tracked hosts |
| `POST` | `/api/hosts` | Add a host (IP, hostname, OS guess) |
| `GET` | `/api/services` | List discovered services |
| `POST` | `/api/services` | Add a service (host, port, protocol, name) |
| `GET` | `/api/workspace` | Get current workspace name/data |
| `POST` | `/api/workspace` | Switch to a different workspace |

**Loot**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/loot` | List collected loot items |
| `POST` | `/api/loot` | Add loot (host, type, description, data) |

**Jobs**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/jobs` | List background jobs |
| `DELETE` | `/api/jobs/{id}` | Kill a background job by ID |

**Export**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/export?format=<json\|csv\|summary>` | Export engagement data |

> **Note:** Non-destructive vulnerability checks use the dedicated `POST /api/check` endpoint (a module and target must be set). The `POST /api/shell` endpoint is **disabled** and returns `501 NOT_IMPLEMENTED`.

> All responses include `request_id`, `timestamp`, and `duration_ms` fields for observability.

> The route table above lists the most commonly used endpoints. The dispatcher (`src/api.rs`) also exposes additional sub-routes such as `GET /api/modules/enriched`, `GET /api/creds/search`, `POST /api/creds/clear`, `POST /api/hosts/notes`, `POST /api/hosts/clear`, `POST /api/loot/clear`, `GET /api/workspaces`, `POST /api/jobs/limit`, `GET /api/jobs/{id}`, and `GET`/`POST /api/spool`. Treat `src/api.rs` as the source of truth for the full route set.

### WebSocket Transport

`GET /pq/ws` upgrades the connection to a PQ-encrypted WebSocket. After the initial `/pq/handshake`, clients can switch to WebSocket for persistent bidirectional communication.

**Features:**
- PQ-encrypted frames using ChaCha20-Poly1305 (same security as REST)
- Max 100 concurrent WebSocket connections
- 30-second heartbeat interval
- 1 MiB max frame size
- Sub-session key derivation from the PQ handshake session

**Headers required:**
- `X-PQ-Session-Id` — session ID from `/pq/handshake`
- Standard WebSocket upgrade headers

WebSocket messages use the same JSON request/response format as REST endpoints. The WebSocket transport is ideal for long-running operations, real-time job monitoring, and persistent client connections.

---

### Shell Command Endpoint (disabled)

`POST /api/shell` is **not implemented** and returns `501 NOT_IMPLEMENTED`. A
generic "run any shell command" endpoint is intentionally withheld until an ACL
design lands. Use the dedicated RPC endpoints instead:

| Want to… | Use |
|----------|-----|
| Select / inspect a module | `GET /api/modules`, `GET /api/module/{category}/{name}` |
| Set / clear the target | `POST` / `DELETE /api/target` |
| Run a module | `POST /api/run` (or `POST /api/run/all` for all stored hosts) |
| Run a non-destructive check | `POST /api/check` |
| Read / write global options | `GET` / `POST` / `DELETE /api/options` |
| Manage creds / hosts / services / loot | the corresponding `/api/creds`, `/api/hosts`, `/api/services`, `/api/loot` routes |

---

## Security Features

### Input Validation

| Check | Detail |
|-------|--------|
| Request body limit | Max 2 MiB (`DefaultBodyLimit`, prevents DoS) |
| Target validation | Length check, control char rejection, path traversal prevention |
| SSRF target filtering | Targets resolving to loopback/RFC1918/link-local/CGNAT/cloud-metadata ranges are rejected (`is_blocked_target` / `resolve_and_check` in `src/api.rs`) |
| Module path sanitization | Validated against injection and traversal attacks |

> There is no API-key mechanism. Authentication is performed by the
> post-quantum mutual handshake (enrollment token + client public key), not by
> a bearer key.

### Access Control

Access is gated by the PQ handshake: a client must complete `/pq/handshake`
with an authorized key (bootstrapped via an enrollment token) before any
`/api/*` route is reachable. There is **no** `ip_whitelist.conf` file or
IP-allowlist mechanism.

### Rate Limiting

The only rate limiter is on the PQ handshake endpoint (`src/pq_middleware.rs`):

- **10 handshake attempts per 60-second sliding window, per source IP.**
- Over-limit handshakes are rejected; timestamps older than the window are pruned automatically.

There is no general per-request-per-second limit and no failed-auth lockout on the `/api/*` routes themselves.

### Post-Quantum Host Key

The server generates an ML-KEM-768 + X25519 host key pair on first run at `~/.rustsploit/pq_host_key`. This is the server's permanent identity — like an SSH host key. The fingerprint is displayed on startup and should be verified by clients on first connection to prevent MITM attacks.

---

## Logging

All activity is logged to:
- **Terminal** — real-time colored output
- **`rustsploit_api.log`** — in the current working directory

Logged events include:
- API requests and responses
- Authentication failures and rate limit triggers
- IP tracking and hardening actions
- Key rotation events
- Module execution results
- Resource cleanup operations

---

## Module Prompts (API Mode)

All modules (exploits, scanners, and creds) support a `prompts` field in the
`/api/run` request body. This field is a JSON object of key→value pairs that
pre-fill interactive prompts so modules run non-interactively via the API.

### How It Works

1. Modules use `cfg_prompt_*()` functions that check `prompts` first
2. If a key is not found in `prompts`, global options (set via `setg` or
   `POST /api/options`) are checked next
3. If a key is present in either source, its value is used instead of prompting stdin
4. If a key is missing in API mode, the default value is used (or an error is
   returned for required prompts)
5. Boolean prompts accept: `y`/`n`/`yes`/`no`/`true`/`false`/`1`/`0`

### Common Prompt Keys

| Key | Type | Used By | Description |
|-----|------|---------|-------------|
| `port` | u16 | Most modules | Target service port |
| `target` | string | Some modules | Override target when empty |
| `command` | string | RCE exploits | Command to execute |
| `username` | string | Auth exploits/creds | Username or login |
| `password` | string | Auth exploits/creds | Password or credential |
| `mode` | string | Multi-mode modules | Select operation mode (1, 2, 3…) |
| `concurrency` | int | Scanners/creds | Max concurrent tasks |
| `output_file` | string | Modules with save | Output filename |
| `save_results` | y/n | Creds/scanners | Save results to file |
| `verbose` | y/n | Many modules | Verbose output |
| `skip_ssl` | y/n | Web exploits | Skip SSL verification |
| `proceed` | y/n | Dangerous exploits | Confirm execution |
| `lhost` | string | Reverse shell | Attacker listener IP |
| `lport` | string | Reverse shell | Attacker listener port |
| `username_wordlist` | path | Creds modules | Path to username wordlist |
| `password_wordlist` | path | Creds modules | Path to password wordlist |
| `stop_on_success` | y/n | Creds modules | Stop on first valid credential |
| `combo_mode` | y/n | Creds modules | user×pass combination mode |

### Example: Exploit Module via API

```json
{
  "module": "exploits/routers/tplink/tplink_archer_rce_cve_2024_53375",
  "target": "192.168.1.1",
  "prompts": {
    "username": "admin",
    "password": "admin123",
    "command": "id"
  }
}
```

### Example: Credential Module via API

```json
{
  "module": "creds/generic/ftp_bruteforce",
  "target": "10.10.10.10",
  "prompts": {
    "port": "21",
    "username_wordlist": "/opt/wordlists/users.txt",
    "password_wordlist": "/opt/wordlists/passwords.txt",
    "concurrency": "500",
    "stop_on_success": "y",
    "save_results": "y",
    "output_file": "ftp_results.txt",
    "verbose": "n",
    "combo_mode": "n"
  }
}
```

### Example: Database Bruteforce via API

```json
{
  "module": "creds/generic/mysql_bruteforce",
  "target": "10.10.10.10",
  "prompts": {
    "port": "3306",
    "use_defaults": "y",
    "username_wordlist": "/opt/wordlists/users.txt",
    "password_wordlist": "/opt/wordlists/passwords.txt",
    "concurrency": "20",
    "stop_on_success": "y",
    "save_results": "y",
    "output_file": "mysql_results.txt"
  }
}
```

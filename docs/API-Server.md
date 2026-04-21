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
2. **Client** has an identity key pair per tenant, stored encrypted in ArcticAlopex's database
3. Client's public key must be listed in `~/.rustsploit/pq_authorized_keys`
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
| `GET` | `/pq/ws` | Upgrade to PQ-encrypted WebSocket transport |

### Protected (26 endpoints — require active PQ session)

**Modules**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/modules` | List all available modules by category |
| `GET` | `/api/modules/search?q=<keyword>` | Search modules by keyword |
| `GET` | `/api/module/{category}/{name}` | Get module info/metadata |
| `POST` | `/api/run` | Execute a module against a target |

**Shell**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/shell` | Execute any shell command (full parity with interactive shell) |

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

> **Note:** The `check` command (non-destructive vulnerability check) is available via `POST /api/shell` with `{"command": "check"}` when a module and target are set. There is no dedicated `/api/check` endpoint.

> All responses include `request_id`, `timestamp`, and `duration_ms` fields for observability.

> **Total: 28 endpoints** (2 public + 26 protected) across 9 resource categories, plus WebSocket transport.

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

### Shell Command Endpoint

`POST /api/shell` provides **full parity** with the interactive shell. Every command
available in the `rsf>` prompt works via this endpoint. Commands that require interactive
prompts (like `creds add`, `services add`, `loot add`) accept inline arguments instead.

**Request format:**
```json
{
  "command": "single command string",
  "commands": ["cmd1", "cmd2", "cmd3"]
}
```

Use `command` for a single command or `commands` (array, 1-20 entries) for batching.
Shell metacharacters (`& | ; $ >`) are forbidden — use the `commands` array for chaining.

**Supported commands:**

| Category | Commands |
|----------|----------|
| Navigation | `help`, `modules`, `find <kw>`, `use <path>`, `info [path]`, `back` |
| Targeting | `set target <ip>`, `set subnet <CIDR>`, `set port <n>`, `show_target`, `clear_target` |
| Execution | `run [target]`, `run_all [target]`, `check` |
| Global Options | `setg <key> <val>`, `unsetg <key>`, `show_options` |
| Credentials | `creds`, `creds add <host> <port> <svc> <user> <secret> [type]`, `creds search <q>`, `creds delete <id>`, `creds clear` |
| Hosts/Services | `hosts`, `hosts add <ip>`, `services`, `services add <host> <port> <proto> <name> [ver]`, `notes <ip> <text>` |
| Workspace | `workspace [name]` |
| Loot | `loot`, `loot add <host> <type> <desc> <data>`, `loot search <q>` |
| Export | `export <json\|csv\|summary> <file>` |
| Jobs | `jobs`, `jobs -k <id>`, `jobs clean` |
| Logging | `spool [off\|file]` |

**Not available in API mode:** `resource` (security — prevents server-side file execution), `makerc` (no shell history).

**Response format:**
```json
{
  "success": true,
  "message": "N shell command(s) executed",
  "data": {
    "results": [
      {
        "command": "modules",
        "success": true,
        "output": "{\"total\": <dynamically generated>, ...}",
        "duration_ms": 2
      }
    ]
  }
}
```

Commands returning structured data (modules, creds, hosts, services, loot, jobs, options, info, check)
encode their output as JSON strings in the `output` field.

---

## Security Features

### Input Validation

| Check | Detail |
|-------|--------|
| Request body limit | Max 1 MB (prevents DoS) |
| API key validation | Must be printable ASCII, max 256 chars |
| Target validation | Length check, control char rejection, path traversal prevention |
| Module path sanitization | Validated against injection and traversal attacks |
| Resource limits | Auto-cleanup when tracked IPs or auth failures exceed 100,000 entries |

### IP Whitelist

An optional IP whitelist can be configured at `~/.rustsploit/ip_whitelist.conf` (one IP per line, `#` for comments). When the file exists and contains entries, only listed IPs are allowed to access the API. All other IPs receive HTTP `403 Forbidden`. If the file is absent or empty, all IPs are allowed.

### Rate Limiting

- **10 requests per second** per IP (general rate limit)
- **3 failed auth attempts** → IP blocked for **30 seconds**
- Blocked IPs receive HTTP `429 Too Many Requests`
- Failure counter resets automatically after the block expires
- Successful auth resets the failure counter for that IP
- Expired blocks and entries older than **1 hour** are auto-pruned

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

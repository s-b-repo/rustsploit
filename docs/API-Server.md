# API Server

Rustsploit includes a built-in REST API server (`src/api.rs`) that enables remote control via HTTP. It features authentication, rate limiting, IP tracking, hardening mode, and structured logging.

---

## Starting the API Server

```bash
# Basic (defaults to 0.0.0.0:8080)
cargo run -- --api --api-key your-secret-key-here

# With hardening (auto-rotate key on suspicious activity)
cargo run -- --api --api-key your-secret-key-here --harden

# Custom interface, port, and IP limit
cargo run -- --api --api-key your-secret-key-here --harden --interface 127.0.0.1:8443 --ip-limit 5
```

---

## API Flags

| Flag | Description | Required |
|------|-------------|----------|
| `--api` | Enable API server mode | Yes |
| `--api-key <key>` | Authentication key (printable ASCII, max 256 chars) | Yes |
| `--harden` | Enable hardening (auto-rotate key, IP tracking) | No |
| `--interface <addr:port>` | Bind address (default: `0.0.0.0:8080`) | No |
| `--ip-limit <n>` | Unique IPs before key rotation (default: 10, requires `--harden`) | No |

---

## Authentication

All endpoints except `/health` require the `Authorization` header:

```bash
# Bearer token format
Authorization: Bearer your-api-key-here

# ApiKey format (equivalent)
Authorization: ApiKey your-api-key-here
```

---

## Endpoints

### Public

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check — no auth required |

### Protected

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/modules` | List all available modules |
| `GET` | `/api/module/:category/:name` | Get details for a specific module |
| `POST` | `/api/run` | Execute a module on a target |
| `POST` | `/api/validate` | Validate parameters without execution |
| `GET` | `/api/status` | Server status and statistics |
| `POST` | `/api/rotate-key` | Manually rotate the API key |
| `GET` | `/api/ips` | All tracked IP addresses with details |
| `GET` | `/api/auth-failures` | Authentication failure statistics |

> All responses include `request_id`, `timestamp`, and `duration_ms` fields for observability.

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

### Rate Limiting

- **3 failed auth attempts** → IP blocked for **30 seconds**
- Blocked IPs receive HTTP `429 Too Many Requests`
- Failure counter resets automatically after the block expires
- Successful auth resets the failure counter for that IP
- Expired blocks and entries older than **1 hour** are auto-pruned

### Hardening Mode (`--harden`)

- Tracks unique IP addresses accessing the API
- Auto-rotates the API key when unique IPs exceed `--ip-limit` (default: 10)
- All rotation events logged to terminal and `rustsploit_api.log`
- IP tracking cleared after key rotation
- Tracker auto-pruned at 100,000 entries

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

## Module Config Example (Telnet)

```json
{
  "port": 23,
  "username_wordlist": "usernames.txt",
  "password_wordlist": "passwords.txt",
  "threads": 10,
  "delay_ms": 50,
  "connection_timeout": 3,
  "read_timeout": 1,
  "stop_on_success": true,
  "verbose": false,
  "full_combo": true,
  "raw_bruteforce": false,
  "output_file": "results.txt",
  "append_mode": false,
  "pre_validate": true,
  "retry_on_error": true,
  "max_retries": 2,
  "login_prompts": ["login:", "username:"],
  "password_prompts": ["password:"],
  "success_indicators": ["$", "#", "welcome"],
  "failure_indicators": ["incorrect", "failed"]
}
```

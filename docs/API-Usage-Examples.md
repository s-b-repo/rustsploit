# API Usage Examples

Practical workflows for interacting with the Rustsploit REST API.

> Start the server first: `cargo run -- --api`
>
> **Note:** Direct `curl` usage requires completing a PQ handshake first (programmatic clients only). For interactive use, connect via ArcticAlopex GUI which handles the PQ session automatically. The `curl` examples below show the plaintext request/response format — in practice, all traffic is PQ-encrypted.
>
> The `Authorization: Bearer` headers shown below are **no longer used** — authentication is via PQ identity keys established during the handshake. The examples retain the header for reference only.

---

## Health Check (No Auth)

```bash
curl http://localhost:8080/health
```

**Response:**
```json
{"status": "ok", "timestamp": "2026-03-17T14:00:00Z"}
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
  "count": 181,
  "request_id": "abc123",
  "timestamp": "2026-03-17T14:01:00Z",
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

## Validate Parameters (Dry Run)

```bash
curl -X POST \
     -H "Authorization: Bearer my-secret-key" \
     -H "Content-Type: application/json" \
     -d '{"module": "scanners/port_scanner", "target": "192.168.1.1"}' \
     http://localhost:8080/api/validate
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

## Check Server Status & Statistics

```bash
curl -H "Authorization: Bearer my-secret-key" \
     http://localhost:8080/api/status
```

**Response:**
```json
{
  "uptime_seconds": 3600,
  "requests_total": 142,
  "auth_failures": 3,
  "tracked_ips": 2,
  "hardening_enabled": true,
  "ip_limit": 5,
  "request_id": "def456",
  "timestamp": "2026-03-17T15:00:00Z",
  "duration_ms": 1
}
```

---

## View Tracked IPs

```bash
curl -H "Authorization: Bearer my-secret-key" \
     http://localhost:8080/api/ips
```

---

## View Auth Failure Stats

```bash
curl -H "Authorization: Bearer my-secret-key" \
     http://localhost:8080/api/auth-failures
```

---

## Manually Rotate API Key

```bash
curl -X POST \
     -H "Authorization: Bearer my-secret-key" \
     http://localhost:8080/api/rotate-key
```

The response includes the **new key** — store it immediately as the old key is invalidated.

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

## Shell Command Endpoint (Full Shell Parity)

The `/api/shell` endpoint supports **every interactive shell command**. Use the
`commands` array to chain multiple commands in a single request.

### Basic Shell Commands

```bash
# List all modules via shell endpoint
curl -X POST http://localhost:8080/api/shell \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"command": "modules"}'

# Search for SSH modules
curl -X POST http://localhost:8080/api/shell \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"command": "find ssh"}'

# Get module info
curl -X POST http://localhost:8080/api/shell \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"command": "info exploits/heartbleed"}'
```

### Chained Workflow (Select, Target, Run)

```bash
curl -X POST http://localhost:8080/api/shell \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "commands": [
      "use scanners/port_scanner",
      "set target 192.168.1.1",
      "run"
    ]
  }'
```

### Vulnerability Check

```bash
curl -X POST http://localhost:8080/api/shell \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "commands": [
      "use exploits/heartbleed",
      "set target 10.10.10.10",
      "check"
    ]
  }'
```

### Global Options via Shell

```bash
curl -X POST http://localhost:8080/api/shell \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "commands": [
      "setg port 8080",
      "setg concurrency 50",
      "show_options"
    ]
  }'
```

### Data Management via Shell

```bash
# Add credentials (inline — no interactive prompts in API mode)
curl -X POST http://localhost:8080/api/shell \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"command": "creds add 192.168.1.1 22 ssh admin password123 password"}'

# Search credentials
curl -X POST http://localhost:8080/api/shell \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"command": "creds search ssh"}'

# Add host and service
curl -X POST http://localhost:8080/api/shell \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "commands": [
      "hosts add 192.168.1.1",
      "services add 192.168.1.1 22 tcp ssh OpenSSH_8.9",
      "notes 192.168.1.1 Possible default credentials"
    ]
  }'

# Workspace management
curl -X POST http://localhost:8080/api/shell \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"command": "workspace pentest_2026"}'

# Loot management
curl -X POST http://localhost:8080/api/shell \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"command": "loot add 192.168.1.1 config router-config hostname_router1"}'

# Export data
curl -X POST http://localhost:8080/api/shell \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"command": "export json engagement_report.json"}'
```

### Background Jobs via Shell

```bash
curl -X POST http://localhost:8080/api/shell \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "commands": [
      "jobs",
      "jobs clean"
    ]
  }'
```

---

## Full Workflow Cheatsheet

```bash
# 1. Start server
cargo run -- --api

# 2. Health check
curl http://localhost:8080/health

# 3. List modules
curl -H "Authorization: Bearer my-secret-key" http://localhost:8080/api/modules

# 4. Port scan
curl -X POST -H "Authorization: Bearer my-secret-key" \
     -H "Content-Type: application/json" \
     -d '{"module": "scanners/port_scanner", "target": "192.168.1.1"}' \
     http://localhost:8080/api/run

# 5. Check status
curl -H "Authorization: Bearer my-secret-key" http://localhost:8080/api/status

# 6. View IPs
curl -H "Authorization: Bearer my-secret-key" http://localhost:8080/api/ips
```

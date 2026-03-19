# API Usage Examples

Practical `curl` workflows for interacting with the Rustsploit REST API.

> Start the server first: `cargo run -- --api --api-key my-secret-key --harden`

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
  "count": 120,
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

```bash
curl -X POST \
     -H "Authorization: Bearer my-secret-key" \
     -H "Content-Type: application/json" \
     -d '{"module": "exploits/heartbleed", "target": "10.10.10.10"}' \
     http://localhost:8080/api/run
```

---

## Run a Credential Module

```bash
curl -X POST \
     -H "Authorization: Bearer my-secret-key" \
     -H "Content-Type: application/json" \
     -d '{"module": "creds/generic/ssh_bruteforce", "target": "10.10.10.10"}' \
     http://localhost:8080/api/run
```

---

## Run MongoBleed (CVE-2025-14847)

```bash
curl -X POST \
     -H "Authorization: Bearer my-secret-key" \
     -H "Content-Type: application/json" \
     -d '{"module": "exploits/mongo/mongobleed", "target": "10.10.10.10:27017"}' \
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

## Full Workflow Cheatsheet

```bash
# 1. Start server
cargo run -- --api --api-key my-secret-key --harden --ip-limit 5

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

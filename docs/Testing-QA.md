# Testing & QA

Guidelines for verifying that new modules and framework changes are correct.

---

## Static Checks

Run before every commit or PR:

```bash
# Format code
cargo fmt

# Lint (use where available)
cargo clippy

# Compile check (fast, no linking)
cargo check
```

A clean `cargo check` with **0 errors and 0 warnings** is required. The current codebase (all 190 modules) passes this check cleanly.

---

## Build Verification

```bash
cargo build
```

`build.rs` regenerates the dispatchers (`exploit_dispatch.rs`, `scanner_dispatch.rs`, `creds_dispatch.rs`, `plugins_dispatch.rs`, `module_registry.rs`) into `OUT_DIR` during compilation. All 190 modules (137 exploits, 28 creds, 24 scanners, 1 plugin) are auto-discovered and dispatched by `build.rs`. If a new module fails to register, ensure `pub mod your_module;` is present in the sibling `mod.rs`.

---

## Runtime Smoke Tests

### Shell
```bash
cargo run
# Inside the shell:
modules               # Verify new module appears in list
find <keyword>        # Verify keyword search works
u scanners/sample_scanner
set target 127.0.0.1
go                    # Runs the sample scanner against localhost
```

### CLI
```bash
cargo run -- --command scanner --module sample_scanner --target 127.0.0.1
cargo run -- --list-modules   # Verify your module is listed
```

### API
```bash
# Start the server
cargo run -- --api

# Check your module appears
curl -H "Authorization: Bearer test-key" http://localhost:8080/api/modules | grep your_module
```

---

## Unit Tests

Run all unit tests:
```bash
cargo test
```

Module-level tests can be added inline:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_response() {
        let output = parse_response(b"some payload");
        assert!(output.is_some());
    }
}
```

For async tests:
```rust
#[tokio::test]
async fn test_async_behavior() {
    // ...
}
```

---

## Wordlist Validation

Before adding a module that depends on wordlists:
1. Confirm the file exists under `lists/`
2. Reference the path in docstrings or `lists/readme.md`
3. Validate it is non-empty at runtime and handle the empty case gracefully

---

## Framework Feature Smoke Tests

After modifying framework features, verify these work:

```bash
# Shell smoke test
cargo run
# Inside shell:
info exploits/sample_exploit    # Should display module metadata
setg port 8080                  # Set global option
show options                    # Should show port=8080
unsetg port                     # Remove it
creds                           # Should show empty cred store
hosts                           # Should show empty host list
workspace                       # Should show "default" workspace
loot                            # Should show empty loot
jobs                            # Should show no jobs
spool /tmp/test.log             # Start console logging
spool off                       # Stop logging
export json /tmp/test.json      # Should create JSON file
```

```bash
# API smoke test
cargo run -- --api

# New endpoints
curl -H "Authorization: Bearer test-key" http://localhost:8080/api/options
curl -H "Authorization: Bearer test-key" http://localhost:8080/api/creds
curl -H "Authorization: Bearer test-key" http://localhost:8080/api/hosts
curl -H "Authorization: Bearer test-key" http://localhost:8080/api/services
curl -H "Authorization: Bearer test-key" http://localhost:8080/api/workspace
curl -H "Authorization: Bearer test-key" http://localhost:8080/api/loot
curl -H "Authorization: Bearer test-key" http://localhost:8080/api/jobs
curl -H "Authorization: Bearer test-key" http://localhost:8080/api/export?format=json
```

---

## Regression Notes

| Area | What to verify |
|------|----------------|
| New cred module | Correct concurrency model, DNS resolved once (not per attempt) |
| New exploit | Response validated before declaring success, artifacts written to CWD |
| New scanner | Outputs parseable results, status codes filtered correctly |
| Mass-scan module | `EXCLUDED_RANGES` applied, no private/bogon IPs targeted |
| API change | `cargo check` clean, endpoint documented in [API Server](API-Server.md) |
| Utils change | All prompt helpers still compile, no dead code warnings |
| Module with `info()` | Build generates info_dispatch entry, `info` command displays metadata |
| Module with `check()` | Build generates check_dispatch entry, `check` command runs verification |
| Global options change | JSON file updated atomically, `cfg_prompt_*` respects priority chain |
| Workspace change | JSON saved on modification, workspace switch preserves data |
| Cred store change | JSON persistence works, search returns correct results |

---

## MCP Integration Tests

Verify MCP server functionality after modifying `src/mcp/`:

```bash
# Start MCP server (stdio transport)
cargo run -- --mcp

# In another terminal, pipe JSON-RPC requests via stdin:
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | cargo run -- --mcp

# Verify tool listing
echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | cargo run -- --mcp

# Verify resource listing
echo '{"jsonrpc":"2.0","id":3,"method":"resources/list","params":{}}' | cargo run -- --mcp
```

Key verification points:
- `initialize` returns protocol version `2024-11-05` and both `tools` and `resources` capabilities
- `tools/list` returns 30 tools
- `resources/list` returns 7 resources
- `tools/call` with `run_module` validates module path exists before execution
- `tools/call` with `run_module` strips `target` from prompts (SSRF prevention)
- Invalid JSON returns error code `-32700` (Parse error)
- Unknown methods return error code `-32601` (Method not found)
- Missing required params return error code `-32602` (Invalid params)

---

## Native RDP Tests

After modifying `src/native/rdp.rs`:

```bash
# Verify build compiles (RDP uses raw TCP, no external deps)
cargo check

# Test against a known RDP target (lab only)
cargo run
# In shell:
use creds/generic/rdp_bruteforce
set target <rdp-host>
run
```

Key verification points:
- TCP connection + X.224 negotiation completes
- TLS upgrade succeeds on standard RDP port 3389
- CredSSP/NTLM authentication follows correct sequence
- Failed auth returns clear error, does not hang
- No `unsafe` blocks used in implementation

---

## Known Disabled / Stubbed Code

| Module | Status | Reason |
|--------|--------|--------|
| `scanners/dns_recursion` | ✅ Fixed | Rewritten for hickory-client v0.25 (`AsyncClient` → `Client`, builder pattern + `TokioRuntimeProvider`) |

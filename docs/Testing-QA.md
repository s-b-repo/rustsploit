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

A clean `cargo check` with **0 errors and 0 warnings** is required. The current codebase (all 240 modules) passes this check cleanly.

---

## Build Verification

```bash
cargo build
```

`build.rs` regenerates the dispatchers (`exploit_dispatch.rs`, `scanner_dispatch.rs`, `creds_dispatch.rs`, `plugins_dispatch.rs`, `module_registry.rs`) into `OUT_DIR` during compilation. All 240 modules (183 exploits, 27 scanners, 29 creds, 1 plugin) are auto-discovered and dispatched by `build.rs`. If a new module fails to register, ensure `pub mod your_module;` is present in the sibling `mod.rs`.

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
cargo run -- -m scanners/sample_scanner -t 127.0.0.1
cargo run -- --list-modules   # Verify your module is listed
```

### API
```bash
# Start the server
cargo run -- --api

# Verify server starts (module listing requires PQ WebSocket session)
curl http://localhost:8080/health
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
# API smoke test — verify server starts and health endpoint responds
cargo run -- --api
curl http://localhost:8080/health
# All other endpoints require a PQ WebSocket session — see API-Server.md
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

## Known Disabled / Stubbed Code

| Module | Status | Reason |
|--------|--------|--------|
| `scanners/dns_recursion` | ✅ Fixed | Rewritten for hickory-client v0.25 (`AsyncClient` → `Client`, builder pattern + `TokioRuntimeProvider`) |

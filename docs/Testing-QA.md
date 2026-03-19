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

A clean `cargo check` with **0 errors and 0 warnings** is required.

---

## Build Verification

```bash
cargo build
```

`build.rs` regenerates the dispatchers (`exploit_gen.rs`, `scanner_gen.rs`, `creds_gen.rs`) during compilation. If a new module fails to register, ensure `pub mod your_module;` is present in the sibling `mod.rs`.

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
cargo run -- --api --api-key test-key

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

## Regression Notes

| Area | What to verify |
|------|----------------|
| New cred module | Correct concurrency model, DNS resolved once (not per attempt) |
| New exploit | Response validated before declaring success, artifacts written to CWD |
| New scanner | Outputs parseable results, status codes filtered correctly |
| Mass-scan module | `EXCLUDED_RANGES` applied, no private/bogon IPs targeted |
| API change | `cargo check` clean, endpoint documented in [API Server](API-Server.md) |
| Utils change | All prompt helpers still compile, no dead code warnings |

---

## Known Disabled / Stubbed Code

| Module | Status | Reason |
|--------|--------|--------|
| `scanners/dns_recursion` | ✅ Fixed | Rewritten for hickory-client v0.25 (`AsyncClient` → `Client`, builder pattern + `TokioRuntimeProvider`) |

# Plan: Improve Cargo Build/Run Compile Times

## Context

Clean build takes **14m 39s** (879s) across 431 compilation units. Incremental rebuilds are already fast (0.6s). The goal is to reduce clean/cold build times — critical for CI, fresh clones, and dependency updates.

The biggest bottlenecks (from `cargo --timings`):
- `rustsploit` final crate: **427s** (361 source files compiled as one unit)
- `aws-lc-sys`: **317s** (C library build for rustls crypto — pulled by reqwest & rustls)
- `dbus`: **116s** (solely from btleplug — used by 1 file)
- `tokio`: **105s**
- `darling_core` + `strum_macros`: **182s** (solely from ratatui — used by 1 file)
- `regex-automata` (×2): **175s**
- `clap_builder`: **76s**
- `h2`: **71s**
- `serde_derive` + `async-trait`: **135s**
- `libssh2-sys`: **62s** (C library for ssh2)
- `hickory-proto`: **60s** (used by 1 file)

---

## Changes (ordered by impact / risk)

### 1. Configure lld linker  
**Savings: ~30-60s | Risk: None | Effort: 2 min**

`lld` is installed at `/usr/bin/lld` but not configured. The default GNU `ld` is slow for a 110K-line binary.

Create `.cargo/config.toml`:
```toml
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=lld"]
```

---

### 2. Switch rustls crypto from aws-lc-rs to ring  
**Savings: ~250-280s | Risk: Low | Effort: 5 min**

`aws-lc-sys` (317s) compiles a massive C library via cmake. It's pulled in because `rustls 0.23` defaults to `aws-lc-rs`. The `ring` backend is functionally equivalent and compiles in ~30-50s.

`cargo tree -i aws-lc-sys` confirms the chain: `aws-lc-sys → aws-lc-rs → rustls → {reqwest, tokio-rustls, rustsploit}`.

In `Cargo.toml`:
```toml
rustls = { version = "0.23", default-features = false, features = ["ring", "logging", "std", "tls12"] }
```

No source code changes — `ring` and `aws-lc-rs` expose the same `rustls::crypto::CryptoProvider` API.

**File:** `Cargo.toml` line 50

---

### 3. Feature-gate btleplug + ratatui + crossterm  
**Savings: ~300s | Risk: Medium | Effort: 30 min**

These three crates are used by exactly **one file**: `src/modules/exploits/bluetooth/wpair.rs`. Their transitive cost:

| Dep chain | Compile time |
|-----------|-------------|
| btleplug → dbus | 116s |
| btleplug → async-trait | 68s |
| ratatui → strum_macros | 85s |
| ratatui → darling_core | 97s |
| ratatui → ratatui-core | 42s |
| crossterm | ~15s |

Confirmed via `cargo tree -i dbus`, `cargo tree -i strum_macros`, `cargo tree -i darling_core` — all solely from btleplug/ratatui.

**Changes:**

`Cargo.toml` — add features section, make deps optional:
```toml
[features]
default = []
bluetooth = ["dep:btleplug", "dep:ratatui", "dep:crossterm"]
```

```toml
btleplug = { version = "0.12", optional = true }
ratatui = { version = "0.30", optional = true }
crossterm = { version = "0.29", optional = true }
```

`src/modules/exploits/bluetooth/mod.rs` — gate the module:
```rust
#[cfg(feature = "bluetooth")]
pub mod wpair;
```

`build.rs` — skip bluetooth dir when feature is absent. In `generate_dispatch()` (or the `find_modules` walk), check `env::var("CARGO_FEATURE_BLUETOOTH")` and skip paths containing `bluetooth/` when it's not set. This prevents the generated dispatch from referencing `wpair::run` when the module doesn't exist.

When bluetooth is needed: `cargo build --features bluetooth` or `cargo run --features bluetooth`.

---

### 4. Clean up tokio feature flags  
**Savings: ~5-10s | Risk: None | Effort: 2 min**

Current line is redundant — `"full"` already includes every named feature plus extras like `test-util`:
```toml
tokio = { version = "1.51", features = ["full", "process", "fs", "io-std", "rt-multi-thread", "macros", "rt"] }
```

Replace with only what's actually used:
```toml
tokio = { version = "1.51", features = ["rt-multi-thread", "macros", "net", "io-util", "io-std", "fs", "process", "sync", "time", "signal"] }
```

**File:** `Cargo.toml` line 20

---

### 5. Feature-gate hickory DNS  
**Savings: ~60s | Risk: Low | Effort: 15 min**

`hickory-proto` (60s) + `hickory-client` are used by exactly **one file**: `src/modules/scanners/dns_recursion.rs`.

```toml
[features]
dns = ["dep:hickory-client", "dep:hickory-proto"]
```

```toml
hickory-client = { version = "0.25", optional = true }
hickory-proto = { version = "0.25", optional = true }
```

Gate in the scanner's `mod.rs` with `#[cfg(feature = "dns")]` and update `build.rs` to skip the module when the feature is absent.

---

## Files to modify

| File | Changes |
|------|---------|
| `.cargo/config.toml` | **Create** — lld linker config |
| `Cargo.toml` | rustls features, optional deps, `[features]` section, tokio cleanup |
| `build.rs` | Skip feature-gated module dirs during code generation |
| `src/modules/exploits/bluetooth/mod.rs` | `#[cfg(feature = "bluetooth")]` gate |
| Scanner mod.rs for dns_recursion | `#[cfg(feature = "dns")]` gate |

---

## Verification

1. `cargo clean && cargo build --timings 2>&1` — compare total time to baseline 879s
2. `cargo build --features bluetooth,dns --timings` — verify full build still works
3. `cargo run -- --help` — verify binary starts correctly
4. `cargo run` — enter shell, run a non-bluetooth module (e.g. `use scanners/port_scanner`, `set target 127.0.0.1`, `run`) to confirm dispatch works
5. `cargo build --features bluetooth` — verify bluetooth module compiles and appears in `list modules`

**Expected result:** Clean build drops from ~879s to ~250-350s (60-70% reduction), with changes 1-3 providing the bulk of the savings.

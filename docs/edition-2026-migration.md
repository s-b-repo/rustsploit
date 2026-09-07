# Edition 2026 Migration Notes

Status: prepared. No blocking changes required. Date: 2026-06-30.

## 1. unsafe_op_in_unsafe_fn — DONE

**Change:** Edition 2026 makes `unsafe_op_in_unsafe_fn` a hard error. Any unsafe
operation (deref raw pointer, call unsafe fn, access union field) inside an
`unsafe fn` body MUST be wrapped in an `unsafe {}` block.

**Status:** No `unsafe fn` exists anywhere in the codebase. All unsafe operations
(libc calls, raw fd handling, mem::zeroed for FFI structs) are already inside
explicit `unsafe {}` blocks in the following files:
- src/native/network.rs — socket/MMsgHdr FFI
- src/native/hex.rs — from_utf8_unchecked
- src/utils/uring_connect.rs — dup(2) + from_raw_fd
- src/mcp/server.rs — dup2 for stdout isolation

Zero code changes needed.

## 2. impl Trait tightening — DONE

**Change:** Edition 2026 may restrict `impl Trait` usage:
- No `impl Trait` in let bindings
- Stricter capture rules for return-position impl Trait (RPIT)
- Disallow `impl Trait` in trait associated types (unless opt-in)

**Status:** Only 2 module files use `impl Trait`, both in internal helper
functions, not in pub run() signatures:
- `api_attack_suite.rs:1212` — `fn add(..., summary: impl Into<String>)`
- `pop3_bruteforce.rs:312` — `fn pop3_authenticate(stream: &mut (impl Read+Write), ...)`

Neither is in a trait impl, a public API, or a return position. Zero impact.

## 3. gen {} blocks — opportunity documented

**Feature:** `gen {}` blocks (RFC 3513) provide zero-cost async generators.
Currently unstable under `#![feature(gen_blocks)]`. Expected stabilization
around Rust 2026 / 1.100+.

**Potential use in rustsploit:**
- DoS modules: `gen {}` could replace hand-rolled `tokio::spawn` loops with
  natural `for packet in gen { ... }` syntax, reducing allocations
- Mass-scan fan-out: `gen {}` in scheduler could yield hosts lazily without
  pre-allocating the full target vector
- Wordlist streaming: `gen { yield line }` instead of batched readers

**Action:** When stabilized, prototype in a single DoS module (e.g.,
connection_exhaustion_flood) to measure throughput vs spawn_all.

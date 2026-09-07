# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Rustsploit — a Rust offensive-security framework (RouterSploit/Metasploit-inspired). One binary (`rustsploit`) exposing the same module library through four interfaces: an interactive shell, a CLI runner, a PQ-encrypted REST/WebSocket API, and an MCP server. 468 self-registering modules under `src/modules/{exploits,scanners,creds,osint,post,plugins}` (exploits 352, scanners 73, creds 34, osint 3, plugins 4, post 2).

The framework is **exploitation-only**: the old `check()` / `CheckResult` non-destructive-verification subsystem was removed. Modules run an exploit and report findings; do not reintroduce a check phase.

## Build / run / test

```bash
cargo build                       # default features include `bluetooth` (needs libdbus-1-dev)
cargo build --no-default-features # no Bluetooth (e.g. headless / no BLE hardware)
cargo run                         # launch the interactive shell
cargo run -- --api                # PQ-encrypted API server (prints a one-time enrollment token)
cargo run -- -m <cat/name> -t <target>   # one-shot CLI run
cargo build --profile fast-release       # release-ish, thin LTO, fast to compile
cargo run -- --gen-module-catalog        # regenerate docs/Module-Catalog.md from the live registry
```

- Linker is `clang` + `lld` (see `.cargo/config.toml`); install `lld` or edit that file. System build deps: `build-essential pkg-config libssl-dev libdbus-1-dev cmake`.
- This is a **binary crate, not a lib** — tests live in `#[cfg(test)]` modules and run via the bin target:
  ```bash
  cargo test --bin rustsploit            # all tests
  cargo test --bin rustsploit cyclic     # single module/test by name filter
  cargo fmt && cargo check               # pre-commit hygiene
  ```

## Quality gate — banned patterns

`scripts/audit-bad-patterns.sh` enforces `docs/BAD_PATTERNS.md` (a regex matrix) across `src/`. Treat any hit as a hard failure. The most-enforced rules, which apply to **all** code you write here:

- No panics in module/library paths: no `.unwrap()`, `.expect()`, `.unwrap_or_default()`, `panic!`, `unreachable!`, `todo!`, indexing/slicing that can panic, `assert!` outside `#[cfg(test)]`. Use `?` with `anyhow::Context` or explicit `match`.
- **No silent error swallowing**: no `Err(_)`, `let _ =`, `if let Ok(...)`-without-`else`, `.map_err(|_| ...)`. Bind the error and surface it (`crate::meprintln!`/`tracing`) or propagate it. (The user actively flags this.)
- No `#[allow(dead_code)]` / lint suppression — wire code in or delete it.
- Use `tokio::sync::Mutex` (no poison) and async I/O; no blocking I/O inside async without `spawn_blocking`.

```bash
scripts/audit-bad-patterns.sh --strict --files <changed.rs ...>   # gate a change
scripts/check-docs.sh                                             # docs link/staleness gate
```

The only sanctioned exemption marker for the audit matrix is an inline `// audit-allow: <reason>` comment; `#[allow(...)]` attributes remain banned.

## Architecture — the big picture

### One dispatch path for four interfaces
Shell (`shell.rs`), CLI (`main.rs`/`cli.rs`), API (`api.rs` + `ws.rs`), and MCP (`mcp/`) all converge on **`commands::run_module(path, target, verbose)`** → **`scheduler::run(module, Target, opts, verbose)`**. Anything affecting how modules execute (target handling, options, timeouts, fan-out) belongs in the scheduler/commands layer so all four interfaces get it uniformly — don't special-case one transport.

API/MCP/background-job runs are marked `api_mode` (via a task-local `RunContext`); the shell/CLI console is not. This distinction gates several behaviors (prompting, timeouts) — see below.

### Module trait + compile-time registration
Every module implements `module::Module` (`info()`, `capabilities()`, `run(&ModuleCtx) -> Result<ModuleOutcome>`, optional `pre_check`/`cleanup`). Modules **self-register at compile time via `inventory`**, not a build script. Author a module with the `register_native_module!` macro at the bottom of the file:

```rust
register_native_module!(Category::Exploits, "ssh/my_exploit", native);              // run(&ModuleCtx)
register_native_module!(Category::Exploits, "bluetooth/wpair", native, interactive);// long-lived REPL/session
```

Adding a module requires three things: the file, the `register_native_module!` call, **and** a `pub mod <name>;` line in the parent `mod.rs` (e.g. `src/modules/scanners/mod.rs`) so it gets compiled. `module::find` / `registered` / `all_paths` read the inventory registry.

### Universal per-host fan-out
A module's `run()` **only ever sees a `Target::Single`** — one host per invocation. The scheduler (`scheduler.rs`) parses the operator's target into a `Target` (`module.rs`) and fans out: `fanout_cidr`, `fanout_file`, `fanout_multi`, `fanout_random`, `fanout_sequential`. Never add per-module mass-scan logic; let the scheduler iterate.

- **Full-internet sweep** = `random`, `0.0.0.0/0`, or bare `0.0.0.0` → `Target::Random`. These print a per-sweep advisory (effective port/concurrency/host-cap/timeout/exclusions) and require an interactive confirmation; API/piped runs proceed without prompting.
- Random sweeps use a **ported ZMap cyclic-group permutation** (`utils/cyclic.rs`, `CyclicIp`) — stateless, O(1) memory, no repeats — instead of sample-and-dedup.
- The per-target deadline (`setg timeout`, default 60s) is a **mass-scan safeguard**, not a general limit. It is intentionally skipped for interactive console single-target runs (`!api_mode && stdin().is_terminal()`) and for `interactive` modules, so prompts and REPLs aren't killed mid-input. Keep that gate.

### Runtime context & options
`ModuleCtx` carries `target`, typed `ModuleOptions`, a `CancellationToken`, `batch_mode`, `tenant_id`, an optional shared `prompt_cache`, and the rate limiter. A task-local `context::RUN_CONTEXT` scopes the `ModuleConfig` (`api_mode`, `custom_prompts`), cancel token, and prompt cache around a run.

Operator settings come from **global options** (`setg`, `global_options.rs`), persisted to `~/.rustsploit/global_options.json`. Modules read inputs through `utils::cfg_prompt_*` with fixed precedence: `custom_prompts` (per-request) → `RunContext` target → global options → interactive stdin. In `api_mode` or batch mode, `cfg_prompt_*` returns defaults instead of blocking on stdin — so an unanswered required option fails fast rather than hanging a headless run.

### Multi-tenancy
The API isolates callers by tenant: `tenant::CURRENT_TENANT` is scoped per request, and `tenant::resolve()` returns the active tenant's stores (loot/creds/hosts/jobs/options), falling back to the process-global stores in shell/CLI mode. When touching anything stateful, read/write through `tenant::resolve()` rather than a global singleton, or you'll leak one tenant's data into another.

### State, jobs, output
Engagement state persists under `~/.rustsploit/` (global options, `loot/`, creds, `checkpoint/` resume markers). Background jobs (`run -j`, API `background:true`) run via `jobs.rs` in `api_mode` with their output captured into an `OUTPUT_BUFFER` scope. Module console output uses `crate::mprintln!` / `crate::meprintln!` (buffer-aware), not `println!`, so API/job runs capture it.

### Key files
`module.rs` (trait, `Target`, `Capabilities`, registry, macro) · `scheduler.rs` (fan-out, timeouts, sweep advisory) · `commands/mod.rs` (`run_module` dispatch) · `context.rs` + `config.rs` + `global_options.rs` + `tenant.rs` (runtime state) · `shell.rs` (REPL) · `api.rs`/`ws.rs`/`pq_*` (PQ API) · `mcp/` (MCP server) · `utils/` (shared helpers — prefer reusing `utils::network`, `utils::prompt`, `utils::sanitize`, `utils::bruteforce`, `utils::wordlist` over reinventing).

## Docs
Deep references live in `docs/` — start at `Home.md` (index), `Architecture.md` (dispatch/fan-out/tenancy overview), and `Module-Development.md` before authoring a module. Exploit/Credential-Modules-Guide cover per-category best practices; `API-Server.md` / `MCP-Integration.md` cover the transports; `BAD_PATTERNS.md` is the banned-pattern rationale behind the audit script; `Roadmap.md` tracks planned work. Keep `docs/Module-Catalog.md` generated (`--gen-module-catalog`), never hand-edited.

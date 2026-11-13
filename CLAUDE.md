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

### The audit script is BASELINED, not absolute

The repository carries real legacy debt (md5 in fingerprinters, `"admin","admin"` in default credential lists, `as u32` casts, `Err(_)` in old modules). An absolute `--strict` gate over the whole tree is red on day one and therefore gets ignored. CI therefore runs the script in **baseline** mode:

```bash
# Aggregate gate — per-PATTERN counts for the whole tree.
scripts/audit-bad-patterns.sh --baseline .github/bad-patterns.baseline

# Per-file gate — per-FILE per-SECTION counts (catches "fix in A, add in B",
# which nets to zero at the pattern level).
scripts/audit-bad-patterns.sh --file-baseline .github/bad-patterns.files.baseline --strict-sections A,B,C

# Focused report on the files a PR touched.
scripts/audit-bad-patterns.sh --changed-from origin/main

# Nightly drift report: which patterns went UP (regression) or DOWN (debt paid).
scripts/audit-bad-patterns.sh --drift-report .github/bad-patterns.baseline

# When you FIX a violation, lower the baseline so the gate stays honest.
scripts/audit-bad-patterns.sh --update-baseline .github/bad-patterns.baseline
scripts/audit-bad-patterns.sh --update-file-baseline .github/bad-patterns.files.baseline --strict-sections A,B,C
```

**Rule for contributors:** never add to a baseline to make a gate pass. Baselines only ever go *down*, as violations are fixed. New code must be clean in sections A (panics), B (swallowed errors) and C (lint suppression) — the CI gate enforces this per file.

### Finding unwired / unused code

`scripts/audit-deadcode.sh` finds code that exists but nothing can reach:

- **uncompiled-file** — a `.rs` file that is not declared in its parent `mod.rs`. It is never compiled, so it never registers and the operator can never run it. (This is how `exploits/bluetooth/blueborne_l2cap` stayed invisible.)
- **missing-file** — a `mod X;` declaration with no `X.rs`.
- **unregistered-module** — a module file under `src/modules/` with `run()`/`info()` but no `register_native_module!`.
- **dead-code** — items the compiler reports as never used.
- **unused-dep** — crates in `Cargo.toml` that nothing imports (`cargo-machete`).

```bash
scripts/audit-deadcode.sh --no-cargo                       # fast, static checks only
scripts/audit-deadcode.sh --baseline .github/deadcode.baseline
scripts/audit-deadcode.sh --update-baseline .github/deadcode.baseline
```

Same rule as above: the baseline is the backlog. Wire the code up or delete it, then drop the entry.

### Generating the module catalog

`docs/Module-Catalog.md` is generated from the live registry by
`rustsploit --gen-module-catalog`. Linking this crate needs a few GB of RAM,
so `scripts/gen-module-catalog.py` parses the registrations straight out of
the source instead. It is a **fallback, not the source of truth** — CI
regenerates the catalog with the real binary and fails on any difference, so
drift between the two is caught immediately.

## CI/CD pipeline

Workflows live in `.github/workflows/`. All third-party actions are pinned to a **commit SHA** (with the version in a trailing comment) so a compromised tag cannot inject code into a release pipeline.

| Workflow | Workers | Purpose |
| --- | --- | --- |
| `ci.yml` | `fmt`, `fmt-repo`, `clippy`, `build`, `test`, `module-catalog`, `bad-patterns`, `bad-patterns-changed`, `deadcode`, `docs`, `gate` | Per-PR gate. `gate` aggregates the rest into the single required status check. |
| `security.yml` | `cargo-audit`, `cargo-deny`, `gitleaks`, `codeql`, `sbom`, `dependency-review` | Independent security workers, run in parallel. |
| `bug-hunt.yml` | `asan`, `miri`, `review` | Memory bugs and logic flaws. `asan` runs the test suite under AddressSanitizer (use-after-free, overflow, double-free, leaks); `miri` runs the pure-logic tests under the UB detector; `review` is a worker that reads the diff for inverted conditions, off-by-ones, leaked permits, TOCTOU and lock-order inversions. |
| `code-quality.yml` | `audit` | In-place code-quality worker. Anchored to the audit scripts, not free-form opinion. `audit` mode reports; `fix` mode edits, commits and pushes. |
| `release.yml` | `notes`, `build` (matrix), `checksums`, `release`, `changelog` | Tag-triggered release. One matrix worker per platform. |
| `release-notes.yml` | `notes` | PR preview of the next release notes; refreshes `changelogs/changelog-latest.md` on `main`. |
| `nightly.yml` | `baselines`, `docs-and-catalog`, `dependency-freshness`, `full-test` | Scheduled deep pass: advisory drift, baseline drift, catalog drift, `--all-features` tests. |

Notes:

- Heavy compile/test jobs run on a larger runner (`ubuntu-latest-8-cores`). Override with the `RUNNER_HEAVY` repository variable (e.g. `ubuntu-latest`) if the account has no larger runners. The crate has ~690 modules and links a vendored OpenSSL — a debug build with debuginfo OOMs a 7 GB runner, so CI sets `CARGO_PROFILE_DEV_DEBUG=0` and `RUSTFLAGS="-C debuginfo=0"`.
- `fmt` gates only the files a PR touched (the repo is not rustfmt-clean end to end). `fmt-repo` reports the whole-repo drift without blocking.
- `clippy` runs **without** `-D warnings`: the lint backlog is large and a hard gate would be permanently red. Warnings still surface as inline PR annotations.
- Release notes come from `scripts/generate-release-notes.sh` (conventional-commit classification + `changelogs/fragments/*.md`). The PR preview and the published notes use the same script, so they cannot diverge.

### Bluetooth transport capabilities

The Bluetooth support layer (`src/bluetooth/`) is compiled behind the `bluetooth` feature (default on). Beyond the original HCI/L2CAP/GATT plumbing it now also provides:

- **ACL data TX/RX** (`hci::write_acl` / `read_acl`) — the HCI socket used to *discard* ACL packets, so LMP could be read but never sent. This is the primitive every air-level BR/EDR attack needs.
- **Fixed-CID and LE-address-type L2CAP** (`hci::L2capChannel::connect_cid`) — the ATT (0x0004) and SMP (0x0006) channels are addressed by CID, not PSM, and an LE peer needs a public (1) or random (2) address type.
- **Raw ATT/GATT codec** (`bluetooth/att.rs`) — talks ATT directly instead of through the kernel's GATT stack, so a **client-chosen MTU** and a **malformed request** are both possible. The `Read Multiple Variable Request` builder is the primitive behind CVE-2023-40129.
- **Classic HID (HIDP)** (`bluetooth/hidp.rs`) — the BR/EDR counterpart to the LE HID-over-GATT path.
- **L2CAP ERTM** (`bluetooth/l2cap_ertm.rs`) — segmentation and flow control, so a large SDU can be pushed as a sequence of fragments.
- **Controller capability queries** (`hci::read_supported_commands` / `read_supported_features` / `read_le_supported_features` / `read_le_buffer_size`) — tells the operator which attack primitives the *local* radio can service before they build a payload.
- **A spec-correct SDP codec** (`bluetooth/sdp.rs`) — the data-element type/size tables now match Core Specification Vol 3, Part A, Tables 1.1/1.2. The previous table decoded every element into the wrong shape (type 1 read as a 128-bit integer, type 4 as a text string, type 6 as a sequence), and three of the codec's own unit tests were failing on `main`. The client is also continuation-state aware, so a peer whose record set spans several PDUs is fully enumerated.

New modules must follow the three-part contract: the file, the `register_native_module!` call, **and** a `pub mod <name>;` line in the parent `mod.rs`. `scripts/audit-deadcode.sh` catches the case where that third step is forgotten — the module compiles away and the operator can never run it.

### Desktop integration (KDE Plasma / GNOME)

`src/desktop.rs` provides two channels that behave identically on Plasma and on GNOME:

- **Freedesktop notifications** over the session bus (`org.freedesktop.Notifications`), which both `plasma-notification` and `gnome-shell` implement. Uses `zbus` directly rather than shelling out to `notify-send`, so it respects the user's notification settings and works under Wayland. Gated behind the `desktop` feature (default on).
- **Terminal title** via an OSC 2 sequence, which Konsole and GNOME Terminal (VTE) both honour — the running module shows in the taskbar entry.

The shell sends a notification when a module finishes and sets the title around a run. `desktop` reports what was detected; `desktop notify <msg>` sends a test notification. Everything degrades to a no-op on a headless box.

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

### Target kinds — network / radio / local

Not every module attacks a network host. `Capabilities.target_kind` (`module.rs`) says what a target *means* for a module, and the framework acts on it in the scheduler (so the shell, CLI, API and MCP behave identically):

| Kind | Target | Framework behaviour |
|------|--------|---------------------|
| `Network` (default) | IP / hostname / CIDR / host file / random sweep | Normal: the scheduler fans out. |
| `Radio` | A Bluetooth device address (`AA:BB:CC:DD:EE:FF`) | A non-MAC target is ignored with a warning; a mass target is **refused** (a `0.0.0.0` target must never start a full-internet sweep for a module that never opens a socket). The shell asks for a device address, not an IP. |
| `Local` | Nothing — the module works on local state (a capture file, the local controller) | Any target is ignored; the module runs on its local state. |

Declare it at registration: `register_native_module!(Category::X, "name", native, radio)` / `…, native, local` (combinable with `interactive` in either order). A device address is a valid target string — `normalize_target` accepts it, because it is a target for a radio module even though it is not an IPv6 literal.

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

# Module Development

Reference for maintainers and contributors writing new Rustsploit modules.

---

## How Modules Are Discovered

Rustsploit uses an `inventory`-based compile-time registry — no `build.rs`, no
codegen file, no central match table:

1. **Each module file ends with `crate::register_native_module!(...)`** — a macro
   that expands to a unique `__ModuleImpl` struct + `impl Module` + an
   `inventory::submit!` block.
2. **At binary startup, `inventory::iter::<ModuleEntry>` walks the registry**
   collected at link time. `crate::module::registered()` returns every
   `ModuleEntry`; `find(path)` looks up by `category/name` or short leaf name.
3. **Shell / CLI / API / MCP all resolve modules through `commands::run_module`**,
   which calls `module::find(...)` and then `scheduler::run(...)`. Single dispatcher.
4. **Mass-scan fan-out is universal** — `Target::Cidr` / `Multi` / `File` /
   `Random` is fanned out by `scheduler::run`. Modules only ever see
   `Target::Single` inside their `run` body.

Because the registry is collected at compile time, there is no runtime
discovery cost and no drift — if you forget the `register_native_module!`
line, the module simply isn't reachable.

---

## Code Rules

- **No dead code.** All code must be intentional and used. Do not leave unused functions, imports, or variables.
- **No `unsafe` blocks.** Do not use `unsafe` Rust anywhere in this codebase.

---

## Project Code Layout

```text
rustsploit/
├── Cargo.toml
├── src/
│   ├── main.rs               # Entry point — CLI or shell mode, input validation
│   ├── cli.rs                # Clap-based CLI parser and dispatcher
│   ├── shell.rs              # Interactive shell loop + UX helpers
│   ├── api.rs                # REST + WebSocket API server — PQ encryption, rate limiting
│   ├── ws.rs                 # PQ-encrypted WebSocket transport (/pq/ws)
│   ├── config.rs             # Global config and target validation
│   ├── module_info.rs        # ModuleInfo, CheckResult, ModuleRank types
│   ├── global_options.rs     # Persistent global options (setg/unsetg)
│   ├── cred_store.rs         # Credential store (JSON persistence)
│   ├── spool.rs              # Console output logging
│   ├── workspace.rs          # Host/service tracking + workspaces
│   ├── loot.rs               # Loot/evidence management
│   ├── export.rs             # JSON/CSV/summary report export
│   ├── jobs.rs               # Background job management
│   ├── mcp/
│   │   ├── mod.rs            # MCP server entry point (--mcp flag)
│   │   ├── server.rs         # JSON-RPC stdio transport with binary-safe reads
│   │   └── tools.rs          # 38 MCP tool implementations
│   ├── commands/
│   │   └── mod.rs            # Single dispatcher: module::find → scheduler::run
│   ├── module.rs             # Module trait, ModuleCtx, register_native_module! macro
│   ├── scheduler.rs          # Universal mass-scan fan-out, finding routing, checkpoint/resume
│   ├── modules/
│   │   ├── exploits/         # Exploit modules
│   │   ├── scanners/         # Scanner modules
│   │   ├── creds/            # Credential modules
│   │   ├── osint/            # OSINT modules
│   │   └── plugins/          # Plugin modules
│   ├── native/               # Native integrations
│   │   ├── mod.rs
│   │   ├── rdp.rs            # Native RDP auth (X.224, TLS, CredSSP/NTLM)
│   │   ├── payload_engine.rs # Payload encoding/generation
│   │   ├── url_encoding.rs   # URL encoding utilities
│   │   └── async_tls.rs      # Async TLS helpers
│   └── utils/                # Shared helpers (directory module)
│       ├── mod.rs            # Re-exports
│       ├── prompt.rs         # Config-aware prompts (cfg_prompt_*)
│       ├── sanitize.rs       # Input validation, length limits
│       ├── target.rs         # Target normalization (IPv4/IPv6/CIDR/hostname)
│       ├── network.rs        # HTTP client builders, TCP/UDP connect helpers
│       ├── privilege.rs      # Root privilege check (require_root)
│       └── modules.rs        # Module discovery helpers
├── docs/                     # This wiki
├── lists/                    # Wordlists and data files
└── README.md                 # Product overview
```

---

## Required Module Signature

Two shapes are accepted. New modules should use the **native shape**.

### Native shape (preferred)

```rust
use anyhow::{Context, Result};
use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{CheckResult, ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo { /* ... */ }

pub async fn check(ctx: &ModuleCtx) -> CheckResult { /* optional */ }

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().unwrap_or("");

    let mut outcome = ModuleOutcome::ok();
    // ... probe target ...
    if vulnerable {
        outcome.findings.push(Finding {
            target: target.to_string(),
            kind: FindingKind::Vulnerable,
            message: "<short marker>".to_string(),
            data: None,
        });
    }
    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Exploits, "your_module", native, has_check);
```

The macro form selects the body shape:
- `register_native_module!(Cat::X, "name")` — legacy, no check
- `register_native_module!(Cat::X, "name", has_check)` — legacy, with check
- `register_native_module!(Cat::X, "name", native)` — native, no check
- `register_native_module!(Cat::X, "name", native, has_check)` — native, with check

The scheduler routes `outcome.findings` into LootStore (`Credential`),
Workspace notes (`Vulnerable`), and the events bus (every kind). No manual
plumbing — see `route_findings` in `src/scheduler.rs`.

### Legacy shape (existing modules)

```rust
pub async fn run(target: &str) -> anyhow::Result<()> { /* ... */ Ok(()) }
pub async fn check(target: &str) -> CheckResult { /* optional */ }

crate::register_native_module!(crate::module::Category::Exploits, "your_module", has_check);
```

Stdout-only via `mprintln!`. Findings are not emitted — the macro discards
the `Result<()>` into `ModuleOutcome::ok()`.

---

## Migrating from legacy to native

Mechanical recipe per file:

1. Add the imports — `use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};`.
2. Change `pub async fn run(target: &str) -> Result<()>` to
   `pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome>`.
3. At the top of the body: `let target = ctx.target.as_single().unwrap_or("");`. Mass scan still works — the scheduler fans out `Cidr/Multi/File/Random` into per-host `Target::Single` before invoking `run`, so `as_single()` is `Some(...)` for every legitimate call. `unwrap_or("")` matches the legacy `target: &str` semantic; downstream `cfg_prompt_*` / `normalize_target` will surface a real error if the empty string actually leaks through.
4. Optionally migrate `check`: `pub async fn check(target: &str) -> CheckResult` →
   `pub async fn check(ctx: &ModuleCtx) -> CheckResult`, with the same
   `as_single()` pattern.
5. Replace `Ok(())` with `Ok(outcome)` (declare `let mut outcome = ModuleOutcome::ok();`
   near the top).
6. At each "found something" stdout site (vuln marker, recovered credential,
   open port banner), push a `Finding` of the right kind.
7. Update the registration line — append `, native` (and keep `, has_check`
   if applicable) so the registration becomes
   `register_native_module!(Cat::X, "name", native[, has_check]);`.

`ctx.options.get_or("port", 22u16)` replaces ad-hoc parsing of legacy
`cfg_prompt_*` answers when you need typed access; the legacy
`cfg_prompt_*` helpers continue to work because the macro keeps the
`RUN_CONTEXT` task-local in scope.

Reference migrations:
- `src/modules/exploits/sample_exploit.rs` — has_check + Vulnerable finding
- `src/modules/scanners/sample_scanner.rs` — Banner findings (HTTP/HTTPS)
- `src/modules/creds/generic/sample_cred_check.rs` — Credential finding with `data` JSON

---

## Optional Module Functions

Modules can optionally provide metadata and vulnerability check functions:

### Module Info (`info`)

```rust
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "My Exploit Module".to_string(),
        description: "Exploits CVE-XXXX-YYYY in FooBar device firmware.".to_string(),
        authors: vec!["Your Name".to_string()],
        references: vec![
            "CVE-XXXX-YYYY".to_string(),
            "https://example.com/advisory".to_string(),
        ],
        disclosure_date: Some("2025-01-15".to_string()),
        rank: ModuleRank::Good,
    }
}
```

The `info` shell command and `GET /api/module/{category}/{name}` endpoint display this metadata.

**Rank values:** `Excellent` (reliable, no crash risk), `Great`, `Good` (default), `Normal`, `Low`, `Manual`.

### Vulnerability Check (`check`)

```rust
use crate::module_info::CheckResult;

pub async fn check(target: &str) -> CheckResult {
    // Non-destructive verification — do NOT exploit
    match test_vulnerability(target).await {
        Ok(true) => CheckResult::Vulnerable("Version 1.2.3 is affected".to_string()),
        Ok(false) => CheckResult::NotVulnerable("Patched version detected".to_string()),
        Err(e) => CheckResult::Error(format!("Check failed: {}", e)),
    }
}
```

The `check` shell command and `POST /api/check` endpoint run this without exploitation.

### Auto-Store Credentials and Loot

Modules can auto-store discovered data:

```rust
// Store a found credential
crate::cred_store::store_credential(host, port, "ssh", username, password,
    crate::cred_store::CredType::Password, "creds/generic/ssh_bruteforce");

// Store loot (config file, hash dump, etc.)
crate::loot::store_loot(host, "config", "Router config dump", data.as_bytes(), "exploits/router_rce");

// Track a discovered host/service
crate::workspace::track_host(ip, Some("router.local"), Some("Linux 4.x"));
crate::workspace::track_service(ip, 22, "tcp", "ssh", Some("OpenSSH 8.9"));
```

---

## Adding a New Module — Checklist

1. **Choose a location** under `src/modules/{exploits,scanners,creds,osint,plugins}`.
   Use subfolders for vendor families (e.g., `exploits/cisco/`).
2. **Create the `.rs` file** with `pub fn info()` + `pub async fn run(...)` (native or legacy
   shape — see above) and end the file with `crate::register_native_module!(Category::X, "name"[, native][, has_check]);`.
3. **Register in `mod.rs`** — add `pub mod your_module;` to the sibling `mod.rs` so the
   compiler links the file. Without this the `inventory::submit!` block never reaches the
   binary and the module is silently un-dispatchable. There is no `build.rs` and no
   central match table — the registry is collected at link time from every
   `register_native_module!` invocation.
4. **Run `cargo build`** — the new module appears in `--list-modules` and is reachable
   through every front-end (CLI `-m`, shell `use`, `/api/run`, MCP `module.run`).
5. **Regenerate the catalog** (optional) — `cargo run -- --gen-module-catalog > docs/Module-Catalog.md`
   walks the live registry and rewrites the catalog.

---

## Module Skeleton (native shape)

```rust
use anyhow::{Context, Result};
use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::network::{build_http_client_with, HttpClientOpts};
use std::time::Duration;

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "example_status_probe".into(),
        description: "Probe /status for the 'vulnerable' marker.".into(),
        authors: vec!["Your Name".into()],
        references: vec!["https://example.com/advisory".into()],
        disclosure_date: None,
        rank: ModuleRank::Good,
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("module requires a single-host target")?
        .to_string();
    let port: u16 = ctx.options.get_or("port", 80u16);

    // Hierarchical rate limiter — global → per-module → per-target buckets.
    ctx.rate_limit(&target).await;

    let url = format!("http://{target}:{port}/status");
    let body = build_http_client_with(Duration::from_secs(15), HttpClientOpts::permissive())?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("Failed to reach {url}"))?
        .text()
        .await
        .context("Failed to read response body")?;

    let mut outcome = ModuleOutcome::ok();
    if body.contains("vulnerable") {
        outcome.findings.push(Finding {
            target: target.clone(),
            kind: FindingKind::Vulnerable,
            message: format!("{target}:{port} reports vulnerable"),
            data: None,
        });
    }
    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Scanners, "example_status_probe", native, has_check);
```

Notes:

- Mass-scan fan-out (`Cidr` / `File` / `Multi` / `Random`) is handled by the scheduler;
  inside `run` you only ever see `Target::Single`. `as_single()` returning `None` is
  a programming error, not user input.
- `ctx.options.get_or("key", default)` is the typed escape from string parsing.
  Operators set values via shell `set port 8080`, CLI `-o port=8080`, or the API
  `options` map — all routed through `ModuleOptions`.
- Findings push into `outcome.findings`; the scheduler routes them into LootStore
  (`Credential`), Workspace notes (`Vulnerable` / `OpenPort` / `Banner` / `Note`),
  and the events bus automatically. Do not call `cred_store::store_credential` or
  `workspace::add_note` yourself in native modules — emit a `Finding` instead.

### Legacy skeleton (existing modules)

```rust
use anyhow::{Context, Result};
use colored::Colorize;
use crate::utils::{normalize_target, cfg_prompt_port, cfg_prompt_yes_no};

pub async fn run(target: &str) -> Result<()> {
    let target = normalize_target(target)?;
    let port = cfg_prompt_port("port", "Target port", 80).await?;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose output?", false).await?;

    crate::mprintln!("{} Checking {}:{}", "[*]".cyan(), target, port);
    // ... probe ...
    Ok(())
}

crate::register_native_module!(crate::module::Category::Scanners, "example", has_check);
```

The legacy macro arms keep `cfg_prompt_*`, `mprintln!`, and `is_cancelled()` working
through the `RUN_CONTEXT` task-local that the macro installs around every call.
Findings are not emitted — the macro discards `Result<()>` into `ModuleOutcome::ok()`
and the route-findings pipeline sees nothing.

---

## Output Conventions

| Prefix | Color | Meaning |
|--------|-------|---------|
| `[+]` | Green | Success / found |
| `[-]` | Red | Not found / not vulnerable |
| `[!]` | Yellow | Warning |
| `[*]` | Cyan | Info / progress |

Use `.green()`, `.red()`, `.yellow()`, `.cyan()` from the `colored` crate. Keep messages short and actionable.

---

## Async I/O Guidelines

- Prefer `reqwest`, `tokio::net`, `tokio::process` for async work.
- Wrap synchronous blocking calls with `tokio::task::spawn_blocking` (see the SSH module for reference).
- For concurrency:
  - `tokio::sync::Semaphore` (wrapped in `Arc`) for async modules.
  - `threadpool` + `crossbeam-channel` for synchronous protocols (Telnet, POP3).

---

## Error Handling

Bubble up errors using `anyhow::Context` so the shell/CLI surface meaningful messages:

```rust
.with_context(|| format!("Failed to connect to {}", target))?
```

**No panics in module code.** As of v0.4.9 the entire `src/` tree is panic-free — `grep` finds zero `.unwrap()`, `.expect(`, `panic!(`, `unreachable!(`, `unimplemented!(`, or `todo!(`. Use `?` propagation, `_or(default)`, `_or_default()`, `_or_else(|| ...)`, or explicit `match { Err(e) => ... }`. The CI policy is to keep that grep returning empty.

For length-checked slice conversions (a common source of historical `.expect()`), use `try_into().map_err(|_| anyhow!("descriptive context"))?` rather than `.expect("length was checked")` — even when the length truly was checked. Future readers shouldn't have to verify the invariant by hand.

---

## Cancellation

Long-running modules MUST honor cancellation so `kill <job_id>` from the shell or `DELETE /api/jobs/<id>` from the API actually stops the work. The cancellation token is per-`RunContext` and is triggered automatically when a job is killed.

```rust
loop {
    if crate::context::is_cancelled() {
        crate::mprintln!("[!] Cancelled by user, stopping at host {}", current);
        break;
    }
    // ... one iteration of work ...
}
```

For `tokio::select!`-style code, use `crate::context::cancellation_token()` and `select!` against `tok.cancelled().await`:

```rust
let tok = crate::context::cancellation_token();
tokio::select! {
    res = real_work() => handle(res),
    _ = tok.cancelled() => {
        crate::mprintln!("[!] Cancelled");
        return Ok(());
    }
}
```

The framework also emits `ModuleStarted` and `ModuleFinished` events automatically around every `run_module(...)` call, so subscribers always see lifecycle transitions.

---

## Lifecycle Hooks

Native modules can override three optional hooks on the `Module` trait. The
scheduler runs them in a fixed order around every CLI/API invocation:

```text
pre_check  →  (per-host) check / run  →  cleanup
   ↑                                       ↑
 once, before fan-out                 once, after fan-out
```

- `pre_check(&ModuleCtx)` — validate `ctx.options` once before fan-out so a `/16`
  scan with a missing wordlist surfaces one error instead of 65 534 identical ones.
  Default: succeed.
- `cleanup(&ModuleCtx, &ModuleOutcome)` — release long-lived resources (open files,
  persistent connections) after the whole fan-out completes or is cancelled.
  `outcome` is the aggregate (success count + every routed finding). Default: no-op.

`check(&ModuleCtx)` is the existing non-destructive vulnerability check; the scheduler
exposes it via the shell `check` command and `POST /api/check`. Override
`fn has_check()` if your check is meaningful (the `register_native_module!` `has_check`
token sets this for you).

Tracked task spawns:

```rust
ctx.spawn(async move {
    long_running_telemetry().await;
});
```

`ctx.spawn` registers the join handle on the active `RunContext`. The scheduler
calls `crate::context::abort_all_spawned()` from `cleanup`, so cancelled or failed
runs do not leak orphan tasks. Plain `tokio::spawn` is still allowed but bypasses
this — only use it for genuinely fire-and-forget work that can outlive the module.

## Capabilities

`fn capabilities(&self) -> Capabilities` advertises what the module needs / promises:

```rust
use crate::module::Capabilities;

fn capabilities(&self) -> Capabilities {
    Capabilities {
        safe_for_high_concurrency: true,  // rate-limit-friendly probe
        requires_root: false,
        check_only: false,                // run() is destructive / interactive
        network: true,
    }
}
```

There is **no** per-module mass-scan flag — the scheduler fans out for every module
(`Capabilities::native_mass_scan` was removed in v0.5.1). Capabilities feed into UI
gating ("show check button", "warn that root is needed") and future scheduler
decisions; they are not load-bearing today, so default values are fine for most
modules.

## Scheduler Limits & Rate Limiter

`scheduler::SchedulerLimits` carries the per-invocation budget. Defaults are pulled
from the active tenant's `global_options` (`set` / `setg` in the shell):

| Field | Default | `global_options` key |
|---|---|---|
| `concurrency` | 50 | `concurrency` |
| `timeout_secs` | 60 | `module_timeout` |
| `max_random_hosts` | 10 000 | `max_random_hosts` |
| `precheck_port` | _none_ | `port` |
| `ipv6_max_hosts` | 2³² | _hard limit_ |
| `warn_threshold` | 65 536 | _hard limit_ |
| `honeypot_detection` | on | `honeypot_detection` |

Per-target deadlines are enforced with `tokio::time::timeout`; per-host honeypot
checks call `utils::network::quick_honeypot_check` and skip targets that look like
they have 11+ common ports open.

Rate limiting is hierarchical (`crate::rate_limit::GlobalLimiter`):

```text
global RPS  →  per-module RPS  →  per-target RPS
```

Native modules call `ctx.rate_limit(target_host).await` once per round trip:

```rust
for cred in &candidates {
    if ctx.is_cancelled() { break; }
    ctx.rate_limit(&target).await;          // gate every probe
    try_login(&target, cred).await?;
}
```

All tiers default to RPS = 0 (no-op). Operators tune them through `global_options`:

- `global_rps` — process-wide ceiling (the `LIMITER` singleton in `src/rate_limit.rs`).
- `module_rps` — default cap per module-type bucket; overridable per module via
  `module_rps:<category/name>` (e.g. `module_rps:scanners/cors_reflection_scanner`).
- `target_rps` — cap per `(module, target_host)` bucket.

Because `LIMITER` is a `Lazy<Arc<GlobalLimiter>>`, the same budget applies across
concurrent scheduler invocations — two parallel runs share one global bucket.

## Structured Findings

Native modules emit findings via `outcome.findings.push(Finding { ... })` — the
scheduler routes each one based on `kind`:

| `FindingKind` | Routed to |
|---|---|
| `Credential` | `LootStore::store_loot` (kind = `"credential"`, payload = `data` JSON or `message`) |
| `Vulnerable` | `Workspace::add_note` |
| `OpenPort` / `Banner` / `Note` | `Workspace::track_host` + `Workspace::add_note` (when message non-empty) |

Every finding (regardless of kind) is also broadcast as
`ModuleEvent::Finding { module, target, kind, message }` on the events bus.
WebSocket subscribers (panels, MCP tooling, integrations) consume them without
grepping stdout.

Legacy modules can still emit one-off events directly:

```rust
crate::events::emit(crate::events::ModuleEvent::CredentialFound {
    host: target.to_string(),
    port,
    service: "ssh".into(),
    username: user.into(),
});
```

Available variants (all `#[non_exhaustive]` — adding more is non-breaking):

- `ModuleStarted { module, target }` — auto-emitted by `commands::run_module`
- `ModuleFinished { module, target, success }` — auto-emitted on return
- `HostUp { host }`
- `ServiceDetected { host, port, service, version: Option<String> }`
- `CredentialFound { host, port, service, username }`
- `LootStored { id, host, kind }`

Emission is non-blocking and silently drops when there are no subscribers (the common CLI-only case).

---

## Batch Mode

When the framework dispatches a mass-scan target (`0.0.0.0`, `random`, CIDR, file, comma-separated), it enters **batch mode** and fans out N concurrent module invocations against single IPs. **Modules MUST gate interactive UI behind `is_batch_mode()`** or risk N concurrent menu prints flooding the terminal:

```rust
use crate::context::is_batch_mode;

pub async fn run(target: &str) -> Result<()> {
    if !is_batch_mode() {
        crate::mprintln!("=== My Module ===");
        crate::mprintln!("[*] Loaded {} targets", n);
    }

    // For menus that pick a target type (Single / Subnet / File),
    // short-circuit to "Single Target" — the framework already orchestrated targets.
    let mode = if is_batch_mode() {
        ModeChoice::SingleTarget
    } else {
        // print menu, read cfg_prompt_default("mode", ...), parse
    };

    // For REPL-style modules, break out after one action in batch mode:
    let in_batch = is_batch_mode();
    loop {
        let cmd = cfg_prompt_default("cmd", "exec");
        do_one_action(&cmd).await?;
        if in_batch { break; }
    }

    Ok(())
}
```

The cached `cfg_prompt_default(...)` returns the same value every call, so a REPL loop reading prompts spins forever in batch mode unless you `break;` after one iteration. This was the v0.4.9 root cause for ~22 modules across two sweeps — see the changelog entry.

---

## Wordlists & Resources

Store under `lists/` and document them in `lists/readme.md`. Reference paths relative to the working directory.

---

## Framework-Level Multi-Target Dispatch

`commands::run_module` resolves the requested name through `module::find` and hands the
boxed `Module` + parsed `Target` to `scheduler::run`. The scheduler is the only place
that knows how to fan a target out — module bodies always see `Target::Single`.

Supported target shapes (parsed by `Target::parse`):

- **Single host**: `10.0.0.1`, `example.com`, `[2001:db8::1]:80` → `Target::Single`.
- **Comma-separated list**: `192.168.1.1,192.168.1.2,10.0.0.1` → `Target::Multi`. Capped
  at 4 096 entries; each entry recursively re-parses (so a list of CIDRs is allowed).
- **CIDR subnet**: `192.168.1.0/24` → `Target::Cidr`. Refuses IPv6 ranges wider than
  `ipv6_max_hosts` (default 2³² hosts) and prompts above `warn_threshold` (default 65 536).
- **File-based target list**: any path that resolves to an existing file → `Target::File`.
  Blank/comment lines are skipped at fan-out time.
- **Random mass scan**: `0.0.0.0`, `0.0.0.0/0`, or `random` → `Target::Random`. Capped
  at `max_random_hosts` (default 10 000) and skips ranges in `crate::exclusions::ExclusionSet`.

Every shape goes through the same `pre_check` → fan-out → `route_findings` → `cleanup`
pipeline (see _Lifecycle Hooks_). A module that handles a single host correctly
inherits subnet, list, file, and `0.0.0.0/0` scanning for free.

---

## 0.0.0.0/0 Internet-Wide Scanning

`Target::Random` (parsed from `0.0.0.0`, `0.0.0.0/0`, or `random`) fans out random
public IPs through `scheduler::fanout_random`, capped at `SchedulerLimits::max_random_hosts`.
The scheduler skips addresses that match `crate::exclusions::ExclusionSet` — by
default this covers bogons, RFC 1918, reserved/documentation ranges, and the public
DNS providers. The set is built from the active tenant's `global_options` via
`crate::exclusions::shared()`; operators add or remove ranges through `set` /
`setg` keys (or an exclusion file) without touching module code.

Modules do **not** roll their own random-IP loops or `EXCLUDED_RANGES` constants —
the historical `utils::bruteforce::run_mass_scan` + per-module `MassScanConfig`
pattern was removed in v0.5.1. Honeypot detection is suppressed in mass-scan mode
because the per-host probe would itself be the slow path.

---

## Current Cleanup Work

Active workstreams (snapshot — see `docs/Legacy.md` for the running ledger):

- **Native body migration.** Every module is registered through `register_native_module!`
  but most still use the legacy `pub async fn run(target: &str)` shape behind the macro.
  Bodies are being ported one file at a time to `pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome>` so findings flow into LootStore / Workspace / events
  instead of stdout. Migration recipe is in _Migrating from legacy to native_ above.
- **Compiler warning sweep.** `cargo build` currently surfaces ~84 warnings — mostly
  unused imports left behind by mid-migration scanner / exploit modules
  (`FindingKind`, `Finding`, `cfg_prompt_*` helpers, leftover mass-scan constants
  like `EXCLUDED_RANGES`, `generate_random_public_ip`, `MASS_SCAN_CONCURRENCY`,
  `DEFAULT_TIMEOUT_SECS`, `COMMON_TELNET_PORTS`). Fix the underlying cause (delete
  the leftover code or wire it in) — do not paper over with `#[allow(dead_code)]`,
  `#[allow(unused_imports)]`, `let _ = ...`, or `_var` renames. The grep policy is
  zero suppression attributes in `src/`.
- **Bad error-handling patterns.** `grep -rn 'map_err(|e| anyhow!('` and
  `grep -rn 'let _ ='` periodically — both usually hide a real propagation path.
  Prefer `.with_context(|| "...")?` over re-wrapping with `anyhow!`, and replace
  `let _ = ...` with the explicit `if let Err(e) = ... { tracing::warn!(...); }`
  pattern when the failure really is recoverable.
- **Wordlist consolidation.** Module-level `WORDLIST.lines()` / `include_str!` blocks
  are being moved into `crate::utils::wordlist` so every brute-forcer reads through
  the same loader (with caching, size caps, and the `--strict-wordlist` toggle).
- **Helper consolidation.** TLS helpers in `src/native/async_tls.rs`,
  `read_async_capped` / `DEFAULT_BODY_CAP` in `src/utils/network.rs`, and the
  `cancellation_token()` accessor in `src/context.rs` are the canonical entry
  points. Modules (notably `http2_rapid_reset`, `sshpwn_session`, the DoS family)
  are being migrated off of their per-module reimplementations.
- **New scanner / OSINT modules** added recently — `cors_reflection_scanner`,
  `security_headers_scanner`, `csp_audit_scanner`, `subdomain_takeover_scanner`,
  `source_map_scanner`, `wellknown_scanner`, `wp_xmlrpc_scanner`, `wp_user_enum`,
  `s3_bucket_scanner`, `m365_userenum_scanner`, plus `osint/cname_chain` and
  `osint/jwks_inspector`. They auto-appear in `--list-modules` and the catalog;
  follow-up bug fixes are tracked under the per-module sections of
  `docs/Changelog.md`.
- **External bug-bounty corpus.** `_analysis/` carries the cross-program findings
  index used to drive new module work (which probes earned findings, which vector
  classes are still untested). It is the source of truth for "where should the next
  scanner live"; do not edit historical reports under `_analysis/`, append a new
  finding instead.
- **Open audit findings (medium / low).** Tenant cache eviction (M2),
  `std::sync::RwLock` on the tokio path (M3), and the L1–L4 path-validation
  cleanups remain. P0 items (PQ rekey deadlock, SSRF bypass) are tracked in
  `docs/Legacy.md` § _Out of scope_ and live on a separate hardening workstream.

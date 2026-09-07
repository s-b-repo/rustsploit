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
│   ├── pq_channel.rs         # PQ session crypto (X25519 + ML-KEM-768 + McEliece, ChaCha20-Poly1305)
│   ├── pq_middleware.rs      # Axum middleware enforcing PQ sessions on /api/*
│   ├── bluetooth/            # Bluetooth core layer (adapters, Fast Pair protocol) behind the `bluetooth` feature
│   ├── config.rs             # Global config and target validation
│   ├── context.rs            # Task-local RunContext (api_mode, cancellation, spawned-task tracking)
│   ├── module_info.rs        # ModuleInfo, ModuleRank types
│   ├── module.rs             # Module trait, Target, Capabilities, ModuleCtx, register_native_module! macro
│   ├── scheduler.rs          # Universal mass-scan fan-out, deadlines, finding routing, checkpoint/resume
│   ├── commands/
│   │   └── mod.rs            # Single dispatcher: module::find → scheduler::run
│   ├── global_options.rs     # Persistent global options (setg/unsetg)
│   ├── tenant.rs             # Multi-tenant store resolution (API isolation)
│   ├── rate_limit.rs         # Hierarchical rate limiter (global → module → target)
│   ├── exclusions.rs         # Exclusion set for internet-wide sweeps (bogons, RFC 1918, …)
│   ├── prescan.rs            # Optional pre-scan pass
│   ├── events.rs             # Typed event bus (ModuleStarted, CredentialFound, …)
│   ├── output.rs, output_stream.rs, spool.rs, results_sink.rs
│   │                         # Buffer-aware console output, spool, per-run auto-save
│   ├── cred_store.rs         # Credential store (JSON persistence)
│   ├── workspace.rs          # Host/service tracking + workspaces
│   ├── loot.rs               # Loot/evidence management
│   ├── export.rs             # JSON/CSV/summary report export
│   ├── jobs.rs               # Background job management
│   ├── sessions.rs, socks.rs # Session and SOCKS handling
│   ├── checkpoint.rs         # Resume markers for long brute-force runs
│   ├── profiles.rs           # save_profile / load_profile
│   ├── nmap_import.rs        # db_import for nmap results
│   ├── database.rs           # Optional persistent store (db feature)
│   ├── tommy.rs              # Interactive guided walkthrough (tommy command)
│   ├── mcp/
│   │   ├── mod.rs            # MCP server entry point (--mcp flag)
│   │   ├── server.rs         # rmcp ServerHandler adapter (official MCP SDK owns transport)
│   │   ├── tools.rs          # 29 MCP tool implementations
│   │   ├── resources.rs      # 7 MCP resources
│   │   ├── types.rs          # MCP JSON types
│   │   └── client.rs         # Outbound MCP client helper (talks to external MCP servers)
│   ├── modules/
│   │   ├── exploits/         # 352 exploit modules (vendor subfolders)
│   │   ├── scanners/         # 73 scanner modules
│   │   ├── creds/            # 34 credential modules
│   │   ├── osint/            # 3 OSINT modules
│   │   ├── post/             # 2 post-exploitation modules
│   │   └── plugins/          # 4 plugin modules
│   ├── native/               # Native integrations (the sanctioned home of unsafe FFI)
│   │   ├── rdp.rs            # Native RDP auth (X.224, TLS, CredSSP/NTLM)
│   │   ├── payload_engine.rs # Payload encoding/generation
│   │   ├── obfuscator_engine.rs # Shellcode obfuscation methods
│   │   ├── dos_utils.rs, network.rs, ip_packet.rs # Raw-socket DoS primitives
│   │   ├── async_tls.rs      # Async TLS helpers
│   │   └── hex.rs, io.rs, url_encoding.rs
│   └── utils/                # Shared helpers (directory module)
│       ├── mod.rs            # Re-exports
│       ├── prompt.rs         # Config-aware prompts (cfg_prompt_*)
│       ├── sanitize.rs       # Input validation, length limits, host/domain helpers
│       ├── target.rs         # Target normalization (IPv4/IPv6/CIDR/hostname)
│       ├── network.rs        # HTTP client builders, TCP/UDP connect helpers, honeypot check
│       ├── bruteforce.rs     # Generic async brute-force engine, resume/stop-mode
│       ├── creds_helper.rs   # Single-target cred-bruteforce harness
│       ├── exploit_helper.rs # Single-target HTTP CVE-probe helpers
│       ├── wordlist.rs       # Checksum-pinned SecLists resolver + streaming reader
│       ├── cyclic.rs         # ZMap-style cyclic-group IPv4 permutation (Target::Random)
│       ├── recog.rs, recog_db/ # Rapid7-Recog-style banner fingerprint engine + vendored DBs
│       ├── tls_fingerprint.rs # JARM / JA3 / JA3S builders
│       ├── waf_bypass/       # WAF detection + bypass technique engine
│       ├── uring_connect.rs  # io_uring TCP connect pool (io_uring feature)
│       ├── persistence.rs    # Atomic JSON write / corruption-safe load
│       ├── safe_io.rs        # Bounded reads (anti-OOM)
│       ├── throttle.rs       # 429/503-aware retry helper
│       ├── parallel.rs, stats.rs, http_ua.rs, privilege.rs, modules.rs
├── docs/                     # This wiki (docs/Module-Catalog.md is generated)
├── lists/                    # Wordlists and data files
└── scripts/                  # audit-bad-patterns.sh, check-docs.sh, setup_docker.py
```

---

## Required Module Signature

Every module uses the **native shape** — `run` receives the typed `ModuleCtx`
and returns a `ModuleOutcome` carrying structured findings. All 468 registered
modules are native; the old legacy `run(target: &str)` shape is accepted by the
macro's 2-arg arm for historical reasons but is not used and should not be used
for new work.

```rust
use anyhow::{Context, Result};
use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo { /* ... */ }

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("module requires a single-host target")?;

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

crate::register_native_module!(crate::module::Category::Exploits, "your_module", native);
```

The macro has exactly three arms:

- `register_native_module!(Cat::X, "name")` — legacy `run(target: &str)` shim; do not use for new modules
- `register_native_module!(Cat::X, "name", native)` — native `run(&ModuleCtx) -> Result<ModuleOutcome>`
- `register_native_module!(Cat::X, "name", native, interactive)` — native, and the scheduler skips the per-target deadline so long-lived REPLs/sessions are not killed mid-input

There is **no `has_check` arm**. Rustsploit is exploitation-only: modules run
an exploit and report findings. Do not add a `check()` phase.

The scheduler routes `outcome.findings` into the loot store (`Credential`),
workspace notes (`Vulnerable` / `OpenPort` / `Banner` / `Note`), and the events
bus (every kind). No manual plumbing — see [Architecture](Architecture.md).

---

## Legacy Shape (historical)

The 2-arg macro arm (`register_native_module!(Cat::X, "name")`) adapts an old
`pub async fn run(target: &str) -> Result<()>` body: the macro installs the
`RUN_CONTEXT` task-local so `cfg_prompt_*`, `mprintln!`, and `is_cancelled()`
keep working, and discards the `Result<()>` into `ModuleOutcome::ok()` — legacy
bodies emit no findings. **No registered module uses this arm anymore**; if you
encounter one, migrate it:

1. Change `pub async fn run(target: &str) -> Result<()>` to
   `pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome>`.
2. At the top of the body:
   `let target = ctx.target.as_single().context("module requires a single-host target")?;`
   The scheduler fans out `Cidr`/`Multi`/`File`/`Random` into per-host
   `Target::Single` before invoking `run`, so `as_single()` is `Some(...)` for
   every legitimate call; a `None` is a programming error.
3. Replace `Ok(())` with `Ok(outcome)` (declare
   `let mut outcome = ModuleOutcome::ok();` near the top).
4. At each "found something" stdout site (vuln marker, recovered credential,
   open port banner), push a `Finding` of the right kind.
5. Update the registration line to `register_native_module!(Cat::X, "name", native);`.

`ctx.options.get_or("port", 22u16)` gives typed access to options; the legacy
`cfg_prompt_*` helpers continue to work inside native bodies.

---

## Optional Module Functions

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
        default_port: Some(8080),
    }
}
```

The `info` shell command and `GET /api/module/{category}/{name}` endpoint display this metadata. `default_port` feeds the scheduler's mass-scan precheck (which port to probe when the operator hasn't set one).

**Rank values:** `Excellent` (reliable, no crash risk), `Great`, `Good` (default), `Normal`, `Low`, `Manual`.

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
2. **Create the `.rs` file** with `pub fn info()` + `pub async fn run(ctx: &ModuleCtx)`
   (native shape — see above) and end the file with
   `crate::register_native_module!(Category::X, "name", native);`.
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
        default_port: None,
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

crate::register_native_module!(crate::module::Category::Scanners, "example_status_probe", native);
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

### Legacy bodies

The old `pub async fn run(target: &str) -> Result<()>` shape is accepted only
through the macro's 2-arg arm (see _Legacy Shape_ above): `cfg_prompt_*`,
`mprintln!`, and `is_cancelled()` keep working through the `RUN_CONTEXT`
task-local the macro installs, but no findings are emitted. Migrate to the
native shape.

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

**No panics in module code.** The entire `src/` tree is panic-free and must stay that way — zero `.unwrap()`, `.expect(`, `.unwrap_or_default()`, `.unwrap_or(`, `.unwrap_or_else(`, `panic!(`, `unreachable!(`, `unimplemented!(`, or `todo!(`. Prefer `?` propagation with `anyhow::Context`, or an explicit `match` that surfaces the error via `crate::mprintln!`/`crate::meprintln!` and continues. Note that the whole `unwrap_or*` family is banned by the audit matrix ([BAD_PATTERNS.md](BAD_PATTERNS.md) A3–A5) — a silent fallback lies about what happened; a panic at least reports something.

For length-checked slice conversions (a common source of historical `.expect()`), use `try_into().with_context(|| "descriptive context")?` rather than `.expect("length was checked")` — even when the length truly was checked. Future readers shouldn't have to verify the invariant by hand.

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
pre_check  →  (per-host) run  →  cleanup
   ↑                              ↑
 once, before fan-out         once, after fan-out
```

- `pre_check(&ModuleCtx)` — validate `ctx.options` once before fan-out so a `/16`
  scan with a missing wordlist surfaces one error instead of 65 534 identical ones.
  Default: succeed.
- `cleanup(&ModuleCtx, &ModuleOutcome)` — release long-lived resources (open files,
  persistent connections) after the whole fan-out completes or is cancelled.
  `outcome` is the aggregate (success count + every routed finding). Default: no-op.

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
        requires_root: false,             // UI warns the operator when true
        check_only: false,                // vestigial; leave false
        network: true,
        interactive: false,               // true for REPL/session modules (set by `native, interactive`)
    }
}
```

There is **no** per-module mass-scan flag — the scheduler fans out for every module
(`Capabilities::native_mass_scan` was removed in v0.5.1). Capabilities feed into UI
gating ("warn that root is needed", "module is interactive") and future scheduler
decisions; they are not load-bearing today, so default values are fine for most
modules. The `register_native_module!(..., native, interactive)` arm sets
`interactive: true` for you.

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

## Network Wrappers & Source Port

All TCP/UDP connections must go through the framework's network wrappers so
`setg source_port <port>` is honoured universally — including during mass-scan
fan-out where hundreds of concurrent tasks share the same source port via
`SO_REUSEADDR` / `SO_REUSEPORT`.

| Wrapper | Use case |
|---------|----------|
| `tcp_connect_str(addr, timeout)` | Async TCP from `"host:port"` string |
| `tcp_connect_addr(addr, timeout)` | Async TCP from `SocketAddr` |
| `blocking_tcp_connect(addr, timeout)` | Sync TCP for `spawn_blocking` (e.g. telnet crate) |
| `udp_bind(Some(ip))` | UDP socket with correct address family |

**Third-party library pattern:** Libraries (suppaftp, telnet) that create their
own TCP connections bypass source port binding. Instead, connect through the
framework wrapper and pass the pre-connected stream:

```rust
// FTP (suppaftp)
let tcp = crate::utils::network::tcp_connect_str(&addr, timeout).await?;
let ftp = AsyncFtpStream::connect_with_stream(tcp).await?;

// Telnet (telnet crate, blocking)
let tcp = crate::utils::network::blocking_tcp_connect(&sa, timeout)?;
let telnet = Telnet::from_stream(Box::new(tcp), 500);
```

**Never use** `TcpStream::connect()`, `UdpSocket::bind("0.0.0.0:0")`, or
library-level connect functions (`AsyncFtpStream::connect(addr)`,
`Telnet::connect(addr)`) — they bypass source port binding.

---

## Target-Specific Filenames

When a module writes output files (results, configs, payloads), include the
target in the filename to avoid clobbering under concurrent mass scan:

```rust
let safe = target.replace(['/', ':', '.', '[', ']'], "_");
let path = format!("results_{}.txt", safe);
```

For temp directories, use per-invocation isolation:

```rust
let work_dir = std::env::temp_dir().join(
    format!("rsploit_module_{:08x}", rand::rng().random::<u32>())
);
```

---

## Batch Mode

When the framework dispatches a mass-scan target (`0.0.0.0`, `random`, CIDR, file, comma-separated), it enters **batch mode** and fans out N concurrent module invocations against single IPs. **Modules MUST gate interactive UI behind `is_batch_mode()`** or risk N concurrent menu prints flooding the terminal:

```rust
use crate::context::is_batch_mode;

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("module requires a single-host target")?;

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

    Ok(outcome)
}
```

The cached `cfg_prompt_default(...)` returns the same value every call, so a REPL loop reading prompts spins forever in batch mode unless you `break;` after one iteration. This was the v0.4.9 root cause for ~22 modules across two sweeps — see the changelog entry.

### Interactive REPLs and local-only modules

Modules with interactive REPLs (e.g. `h3c_websocket_dump`) or local-only
functionality (e.g. `windows_dwm_cve_2026_20805`) should bail immediately
in batch mode since they cannot operate meaningfully under fan-out:

```rust
if crate::utils::is_batch_mode() {
    anyhow::bail!("Interactive REPL not supported in mass-scan mode.");
}
```

---

## Wordlists & Resources

Store bundled lists under `lists/` and document them in `lists/readme.md`. Reference paths relative to the working directory.

For canonical lists, prefer the checksum-pinned resolver `crate::utils::wordlist::resolve(name)` over shipping a copy: it downloads + SHA-256-verifies into `~/.rustsploit/wordlists/` on first use and reuses the cache after. As of the 2026-06-13 release the catalog is seeded with 6 curated SecLists entries (`passwords-top-1k`, `passwords-top-10k`, `usernames-short`, `web-common`, `web-raft-small-dirs`, `subdomains-top5k`); `wordlist::catalogue()` lists every name this build knows. See [`Utilities-Helpers.md`](Utilities-Helpers.md).

## Service / TLS Fingerprinting Helpers

Two shared fingerprinting surfaces are available to scanner modules (added 2026-06-13):

- **`crate::utils::recog`** — a Rapid7-Recog-style banner matcher. Feed it a banner (SSH/FTP/SMTP/MySQL/HTTP `Server:` header) and it returns structured fields (`service.product` / `.version` / `.vendor`, `os.product`, `service.cpe23`). `scanners/service_scanner` already uses it to enrich detected versions with a product/version + CPE; new banner-reading scanners should reuse it rather than hand-rolling regex.
- **`crate::utils::tls_fingerprint`** — JARM (canonical 62-char hash), JA3, and JA3S over a raw `TcpStream`. The reference consumer is `scanners/jarm_scan`. Parsing is fully bounds-checked and degrades to the all-zero JARM hash on a down host / TLS alert / truncated response.

## Per-Run Output Auto-Save

Console / CLI module runs auto-append all of their output (stdout + stderr, captured through the `mprintln!` / `meprintln!` routing) to `~/.rustsploit/loot/<module> <YYYY-MM-DD_HH-MM-SS> results.txt` via `src/results_sink.rs` (append mode, begun/ended per run in `commands::run_module`). You do not need to add your own "save results to file" logic for this — append mode also means a multi-host mass scan accumulates into one run file instead of racing to overwrite. API / MCP runs return their output to the caller via `OUTPUT_BUFFER` and are not duplicated to disk.

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

Active workstreams (snapshot — see [`Legacy.md`](Legacy.md) for the running ledger and [`Roadmap.md`](Roadmap.md) for planned features):

- **Body migration: done.** All 468 registered modules use the native
  `run(&ModuleCtx) -> Result<ModuleOutcome>` shape; the 2-arg legacy macro arm is
  retained only as a historical shim. New modules must be native.
- **Zero-warning gate.** `cargo build` must stay at 0 errors / 0 warnings (default +
  bluetooth features). Fix the underlying cause (delete leftover code or wire it in) —
  do not paper over with `#[allow(dead_code)]`, `#[allow(unused_imports)]`,
  `let _ = ...`, or `_var` renames; suppression attributes are banned outright.
- **Bad error-handling patterns.** Grep `map_err(|_|` and `let _ =` periodically —
  both usually hide a real propagation path. Prefer `.with_context(|| "...")?` over
  re-wrapping with `anyhow!`, and replace `let _ = ...` with the explicit
  `if let Err(e) = ... { tracing::warn!(...); }` pattern when the failure really is
  recoverable.
- **Wordlist consolidation.** New brute-forcers should `wordlist::resolve(name)` a
  checksum-pinned catalog list rather than embed one. The catalog is seeded with 6
  curated SecLists entries (2026-06-13); `wordlist::catalogue()` lists every name this
  build knows. See [`Utilities-Helpers.md`](Utilities-Helpers.md).
- **Helper consolidation.** TLS helpers in `src/native/async_tls.rs`,
  `read_async_capped` / `DEFAULT_BODY_CAP` in `src/utils/network.rs`, and the
  `cancellation_token()` accessor in `src/context.rs` are the canonical entry
  points. Do not reimplement these per module (the DoS family and long-session
  modules were migrated off per-module reimplementations).
- **Open audit findings (medium / low).** Tracked in the `reports/` directory
  (whole-tree audit snapshots) and [`Legacy.md`](Legacy.md) § _Out of scope_; P0
  hardening items live on a separate workstream.

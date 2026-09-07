# Architecture

How Rustsploit executes a module run — dispatch, fan-out, runtime context, tenancy, and state. This is the mental model to hold before touching `src/scheduler.rs`, `src/module.rs`, or any transport.

---

## The Big Picture

One binary (`rustsploit`), four operator interfaces, **one dispatch path**:

```text
Interactive Shell (src/shell.rs)      ─┐
CLI runner (src/cli.rs → src/main.rs) │   ┌→ commands::run_module(path, target, verbose)
PQ REST/WebSocket API (src/api.rs,    ─┼──►│        │  module::find(path) → resolve module
   src/ws.rs, pq_*)                   │   └────────┤  Target::parse(target)
MCP server (src/mcp/, rmcp over stdio)┘            ▼
                                        scheduler::run(module, Target, options, verbose)
```

Anything that affects **how modules execute** — target parsing, option injection, timeouts, fan-out, finding routing — lives in the `commands`/`scheduler` layer so all four transports inherit it uniformly. Never special-case one transport.

API, MCP, and background-job runs are marked **`api_mode`** via a task-local `RunContext` (`src/context.rs`). Shell/CLI console runs are not. That flag gates interactive behaviors (prompting, sweep confirmation, per-target deadlines) — see *Scheduler deadlines* below.

---

## Module Model

### Trait contract

Every module implements `module::Module` (`src/module.rs`):

| Method | Required | Purpose |
|---|---|---|
| `info(&self) -> ModuleInfo` | yes | Name, description, CVE references, rank, default port |
| `capabilities(&self) -> Capabilities` | no | Advertises `safe_for_high_concurrency`, `requires_root`, `check_only`, `network`, `interactive` |
| `pre_check(&ModuleCtx) -> Result<()>` | no | Validate options **once, before fan-out** — fail fast instead of 65 534 identical errors |
| `run(&ModuleCtx) -> Result<ModuleOutcome>` | yes | The exploit/scan body. Only ever sees `Target::Single` |
| `cleanup(&ModuleCtx, &ModuleOutcome) -> Result<()>` | no | Release resources once, after fan-out completes or is cancelled |

Rustsploit is **exploitation-only**: modules run an exploit and report structured `Finding`s. There is no separate non-destructive `check()` phase — do not reintroduce one.

### Compile-time registration (no build script)

Modules self-register via the `inventory` crate — no `build.rs`, no codegen, no central match table:

1. The module file ends with the `register_native_module!` macro (three arms):
   ```rust
   register_native_module!(Category::Creds, "generic/ssh_bruteforce");        // legacy run(target: &str) shim
   register_native_module!(Category::Exploits, "webapps/foo", native);        // native run(&ModuleCtx)
   register_native_module!(Category::Exploits, "bluetooth/wpair", native, interactive); // native, no per-host deadline
   ```
2. The parent `mod.rs` declares `pub mod <name>;` so the file is compiled — without this line the `inventory::submit!` never links and the module is silently unreachable.
3. At startup, `inventory::iter::<ModuleEntry>` walks the registry collected at link time. `module::find` resolves `category/name` or short leaf names; `module::registered` / `module::all_paths` feed listing surfaces.

Current registry: **468 modules** — exploits 352, scanners 73, creds 34, osint 3, plugins 4, post 2. The authoritative list is `docs/Module-Catalog.md`, regenerated from the live registry with `cargo run -- --gen-module-catalog`.

---

## Target Parsing & Universal Fan-Out

An operator target is parsed into a `Target` (`src/module.rs`):

| Operator input | `Target` variant | Fan-out |
|---|---|---|
| `10.0.0.1`, `host.example.com`, `[2001:db8::1]:80` | `Single` | `fanout_single` |
| `192.168.1.0/24` (refuses IPv6 wider than `ipv6_max_hosts`; warns above `warn_threshold`) | `Cidr` | `fanout_cidr` |
| `a,b,c` comma list (≤4 096 entries, each recursively re-parsed) | `Multi` | `fanout_multi` |
| path to an existing file (blank/`#` lines skipped) | `File` | `fanout_file` |
| `random`, `0.0.0.0/0`, `0.0.0.0` | `Random` | `fanout_random` — ZMap-style cyclic-group permutation (`utils/cyclic.rs`): stateless, O(1) memory, no repeats; honors `scan_order sequential` → `fanout_sequential` |
| `seq` / `seq:<ip>` | `Sequential` | `fanout_sequential` from `FIRST_PUBLIC_IPV4` |

**A module's `run()` only ever sees `Target::Single`.** The scheduler iterates; modules never loop over hosts themselves. Single-host correctness therefore inherits subnet, list, file, and internet-wide scanning for free.

### Full-internet sweep guardrails

- `Target::Random` / `Sequential` prints a per-sweep **advisory** (effective port + provenance, concurrency, host cap, per-host timeout, exclusion count) and requires interactive confirmation — only when `!api_mode && stdin().is_terminal()`. API/MCP/piped runs proceed without prompting.
- When `max_random_hosts` is not explicitly set, a full sweep auto-raises the cap to the full public IPv4 space.
- `crate::exclusions::ExclusionSet` (bogons, RFC 1918, reserved/documentation ranges, public DNS resolvers — tenant-configurable via `setg exclusions`) is applied on both random paths.
- Interactive (`native, interactive`) modules are refused outright for mass targets.

### Scheduler deadlines

The per-target deadline (`setg timeout`, default 60 s) is a **mass-scan safeguard, not a general limit**. It is enforced:

- for every host of any mass fan-out,
- for single-target runs only when `api_mode || !stdin().is_terminal()`.

It is intentionally skipped for interactive console single-target runs and for `interactive` modules so prompts/REPLs are not killed mid-input. **Keep that gate.** Per-host retries: `MAX_HOST_ATTEMPTS = 2` on transient errors.

### Scheduler limits

`SchedulerLimits` defaults are pulled from the tenant's `global_options`:

| Field | Default | `setg` key |
|---|---|---|
| `concurrency` | 50 | `concurrency` |
| `timeout_secs` | 60 | `timeout` / `module_timeout` |
| `max_random_hosts` | 10 000 (auto-bumped for full sweeps) | `max_random_hosts` |
| `ipv6_max_hosts` | 2³² | hard limit |
| `warn_threshold` | 65 536 | hard limit |
| `honeypot_detection` | on | `honeypot_detection` |

Rate limiting is hierarchical (`src/rate_limit.rs` `GlobalLimiter`, shared `LIMITER` singleton so parallel runs share one global bucket):

```text
global_rps  →  module_rps (+ per-module override module_rps:<cat/name>)  →  target_rps
```

Native modules call `ctx.rate_limit(&target).await` before each probe. All tiers default to 0 (no-op). Optional pre-scan (`setg prescan`, `prescan_port`, `prescan_rate`) and per-host honeypot checks (`utils::network::quick_honeypot_check` — 30 ports / 200 ms; skipped in mass-scan mode) run ahead of the module body.

---

## Runtime Context & Options

`ModuleCtx` carries: `target` (parsed `Target`), typed `ModuleOptions`, a `CancellationToken`, `batch_mode`, `tenant_id`, an optional shared `prompt_cache`, and the rate limiter. A task-local `context::RUN_CONTEXT` scopes the `ModuleConfig` (`api_mode`, `custom_prompts`), cancel token, and prompt cache around each run; per-host fan-out tasks re-scope it because task-locals do not cross `tokio::spawn`.

Operator settings live in **global options** (`setg`/`unsetg`, `src/global_options.rs`) — a tenant-scoped `String→String` map persisted atomically to `~/.rustsploit/global_options.json` (key ≤256 chars, value ≤4 096, ≤1 024 entries). Shell aliases normalize Metasploit-style names: `RHOST(S)→target`, `RPORT→port`, `LPORT→source_port`, `LHOST→source_ip`, `THREADS→concurrency`, `MODULE_TIMEOUT→timeout`.

Modules read inputs through `utils::cfg_prompt_*` (`src/utils/prompt.rs`) with fixed precedence:

```text
custom_prompts (per-request)  →  RunContext target  →  global options  →  interactive stdin
```

In `api_mode` or batch mode, `cfg_prompt_*` returns defaults instead of blocking on stdin — an unanswered required option fails fast rather than hanging a headless run.

---

## Multi-Tenancy

The API isolates callers by tenant: `tenant::CURRENT_TENANT` is scoped per request, and `tenant::resolve()` returns the active tenant's stores (loot / creds / hosts / jobs / options), falling back to the process-global stores in shell/CLI mode. **Any code touching stateful data must go through `tenant::resolve()`**, not a global singleton — otherwise one tenant's data leaks into another's.

---

## State, Jobs, Output

- Engagement state persists under `~/.rustsploit/`: `global_options.json`, `loot/` (with per-run auto-save files), credential store, `checkpoint/` resume markers for brute-force runs.
- Background jobs (`run -j` in the shell, `background:true` via API/MCP) execute through `src/jobs.rs` in `api_mode` with their console output captured into an `OUTPUT_BUFFER` scope.
- Module console output must use the buffer-aware macros `crate::mprintln!` / `crate::meprintln!` — never `println!`/`eprintln!` — or API/job output capture and spool (`src/spool.rs`) lose it.
- Findings pushed to `outcome.findings` are routed automatically by the scheduler: `Credential` → loot store, `Vulnerable` → workspace notes, `OpenPort`/`Banner`/`Note` → host tracking + notes; every finding is also broadcast on the events bus (`src/events.rs`) for WebSocket/MCP subscribers.

---

## Key Files

| File | Role |
|---|---|
| `src/module.rs` | `Module` trait, `Target`, `Capabilities`, `ModuleCtx`, `ModuleOutcome`, registry, `register_native_module!` |
| `src/module_info.rs` | `ModuleInfo` / `ModuleRank` types |
| `src/scheduler.rs` | Fan-out engines, deadlines, retries, sweep advisory, finding routing, lifecycle hooks |
| `src/commands/mod.rs` | `run_module` — the single dispatch entry |
| `src/context.rs`, `src/config.rs` | Task-local `RunContext`, `api_mode`, cancellation, spawned-task tracking |
| `src/global_options.rs`, `src/tenant.rs` | Persistent options, tenant-scoped stores |
| `src/rate_limit.rs`, `src/exclusions.rs` | Hierarchical limiter, exclusion set |
| `src/shell.rs` | Interactive REPL |
| `src/cli.rs`, `src/main.rs` | CLI parser and entry point |
| `src/api.rs`, `src/ws.rs`, `src/pq_*.rs` | PQ-encrypted REST/WebSocket transports |
| `src/mcp/` | MCP server (rmcp SDK) — tools, resources, client helper |
| `src/jobs.rs`, `src/output.rs`, `src/spool.rs`, `src/results_sink.rs` | Background jobs, buffer-aware output, spool, per-run auto-save |
| `src/events.rs` | Typed event bus |
| `src/utils/` | Shared helpers — prefer `network`, `prompt`, `sanitize`, `bruteforce`, `wordlist`, `creds_helper`, `exploit_helper` over reinventing |
| `src/native/` | Native protocol implementations (RDP, payload engine, TLS helpers), the sanctioned home of `unsafe` |

---

## Invariants (do not break)

1. One dispatch path — new transports hang off `commands::run_module`, never call modules directly.
2. Modules see `Target::Single` — the scheduler owns iteration.
3. No panics, no silent error swallowing, no lint suppression — enforced by `scripts/audit-bad-patterns.sh --strict` (see [BAD_PATTERNS.md](BAD_PATTERNS.md)); the only sanctioned exemption is an inline `// audit-allow: <reason>` comment.
4. No blocking I/O in async contexts without `spawn_blocking`; `tokio::sync` primitives only.
5. Stateful access goes through `tenant::resolve()`.
6. Console output only via `mprintln!`/`meprintln!`.
7. `docs/Module-Catalog.md` is generated — never hand-edit; run `cargo run -- --gen-module-catalog`.

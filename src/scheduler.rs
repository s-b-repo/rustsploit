// src/scheduler.rs
//
// Unified scheduler. Single entry point for running a `Module` against any
// `Target` shape (single, CIDR, file, multi, random) with hierarchical
// concurrency control, automatic finding routing into
// `LootStore`/`Workspace`/`events`, cancellation, and prompt-cache propagation.
//
// Replaces the three parallel mass-scan loops in
// `src/commands/mod.rs::dispatch_single_target` by collapsing them into one
// streaming engine. Legacy callers can still hit `dispatch_single_target`
// during migration; new code (CLI, shell, API, MCP) calls
// `scheduler::run` directly.

use std::io::IsTerminal;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use colored::Colorize;
use tokio::sync::Semaphore;

use crate::module::{Finding, FindingKind, Module, ModuleCtx, ModuleOptions, ModuleOutcome, Target};

// ============================================================
// LIMITS
// ============================================================

#[derive(Debug, Clone, Copy)]
pub struct SchedulerLimits {
    /// Max concurrent in-flight tasks.
    pub concurrency: usize,
    /// Per-target deadline in seconds.
    pub timeout_secs: u64,
    /// Max hosts when fanning out a `Target::Random`.
    pub max_random_hosts: usize,
    /// Optional pre-check port for random scans.
    pub precheck_port: Option<u16>,
    /// Refuse IPv6 ranges wider than this.
    pub ipv6_max_hosts: u128,
    /// Warn / prompt above this IPv4 host count.
    pub warn_threshold: u128,
    /// Skip hosts that look like honeypots.
    pub honeypot_detection: bool,
}

impl Default for SchedulerLimits {
    fn default() -> Self {
        Self {
            concurrency: 50,
            timeout_secs: 60,
            max_random_hosts: 10_000,
            precheck_port: None,
            ipv6_max_hosts: 1u128 << 32,
            warn_threshold: 65_536,
            honeypot_detection: true,
        }
    }
}

impl SchedulerLimits {
    /// Pull defaults from the active tenant's `global_options`.
    pub fn from_global_options() -> Self {
        let mut l = Self::default();
        let scope = crate::tenant::resolve();
        let opts = scope.global_options();
        if let Some(v) = opts.try_get("concurrency")
            .or_else(|| opts.try_get("threads"))
            .and_then(|v| v.parse().ok())
        {
            l.concurrency = v;
        }
        if let Some(v) = opts.try_get("module_timeout")
            .or_else(|| opts.try_get("timeout"))
            .and_then(|v| v.parse().ok())
        {
            l.timeout_secs = v;
        }
        if let Some(v) = opts.try_get("max_random_hosts").and_then(|v| v.parse().ok()) {
            l.max_random_hosts = v;
        }
        l.precheck_port = opts.try_get("port").and_then(|v| v.parse().ok());
        if let Some(v) = opts.try_get("honeypot_detection") {
            l.honeypot_detection = !matches!(
                v.to_lowercase().as_str(),
                "n" | "no" | "false" | "0" | "off" | "disabled"
            );
        }
        l
    }
}

// ============================================================
// STATS
// ============================================================

#[derive(Default)]
struct ScanStats {
    /// Hosts on which the module ran and returned `Ok` with `success == true`.
    success: AtomicUsize,
    /// Hosts on which the module errored or returned `success == false`.
    failed: AtomicUsize,
    /// Hosts skipped before the module ran (precheck miss / honeypot /
    /// already-processed checkpoint).
    skipped: AtomicUsize,
    /// Hosts on which the module actually ran (`success + failed`).
    processed: AtomicUsize,
    /// Total `Finding`s collected across all hosts. This — not `success` —
    /// is the count the operator cares about: "did the scan find anything?".
    hits: AtomicUsize,
    /// Every host the fan-out looked at this run, whether skipped or run.
    /// Drives progress feedback so it advances even when most hosts are
    /// precheck-skipped (the common case on random/sparse mass scans).
    considered: AtomicUsize,
    abort: AtomicBool,
    findings: std::sync::Mutex<Vec<Finding>>,
}

/// Point-in-time view of a running scan's counters.
struct StatsSnapshot {
    processed: usize,
    success: usize,
    failed: usize,
    skipped: usize,
    hits: usize,
    considered: usize,
}

impl ScanStats {
    fn record(&self, outcome: Result<ModuleOutcome>) -> bool {
        match outcome {
            Ok(out) => {
                if out.success {
                    self.success.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.failed.fetch_add(1, Ordering::Relaxed);
                }
                if !out.findings.is_empty() {
                    self.hits.fetch_add(out.findings.len(), Ordering::Relaxed);
                    let mut g = self.findings.lock().unwrap_or_else(|e| e.into_inner());
                    g.extend(out.findings);
                }
                false
            }
            Err(e) => {
                tracing::debug!("module run failed: {e:#}");
                self.failed.fetch_add(1, Ordering::Relaxed);
                true
            }
        }
    }

    fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            processed: self.processed.load(Ordering::Relaxed),
            success: self.success.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            skipped: self.skipped.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            considered: self.considered.load(Ordering::Relaxed),
        }
    }

    /// Count one host as examined (skipped or run) and report whether a
    /// progress line should be emitted now: the first host, then every
    /// `step` hosts. Called at the very top of each spawned task — *before*
    /// any precheck — so feedback keeps moving on sparse/random ranges
    /// where the vast majority of hosts never reach the module.
    fn tick(&self, step: usize) -> Option<usize> {
        let n = self.considered.fetch_add(1, Ordering::Relaxed) + 1;
        if n == 1 || step == 0 || n.is_multiple_of(step) {
            Some(n)
        } else {
            None
        }
    }
}

/// Choose a progress-report interval so a scan emits a sane number of lines
/// regardless of size: ~tens-to-hundreds of updates rather than one-per-host
/// (spam) or one-per-100k (looks frozen).
fn progress_step_for(total: u128) -> usize {
    if total > 10_000_000 {
        10_000
    } else if total > 100_000 {
        1_000
    } else if total > 1_000 {
        100
    } else if total > 100 {
        25
    } else {
        10
    }
}

/// Format the shared progress line used by every fan-out so the operator
/// always sees the one number that matters — `hits` — alongside throughput.
fn progress_line(considered: usize, total: u128, s: &StatsSnapshot) -> String {
    let pct = if total > 0 {
        format!(" ({:.1}%)", (considered as f64 / total as f64) * 100.0)
    } else {
        String::new()
    };
    format!(
        "[*] Progress: {}/{}{} examined | {} hits | {} ran ({} ok / {} err) | {} skipped",
        considered, total, pct, s.hits, s.processed, s.success, s.failed, s.skipped
    )
}

// ============================================================
// PUBLIC ENTRY POINTS
// ============================================================

/// Run a module against a target with limits pulled from `global_options`.
pub async fn run(
    module: Arc<dyn Module>,
    target: Target,
    options: ModuleOptions,
    verbose: bool,
) -> Result<ModuleOutcome> {
    run_with_limits(
        module,
        target,
        options,
        verbose,
        SchedulerLimits::from_global_options(),
    )
    .await
}

pub async fn run_with_limits(
    module: Arc<dyn Module>,
    target: Target,
    options: ModuleOptions,
    verbose: bool,
    limits: SchedulerLimits,
) -> Result<ModuleOutcome> {
    run_with_limits_shared(module, target, options, verbose, limits, None).await
}

/// Internal entry that accepts an optional parent-shared semaphore so a
/// `fanout_multi` invocation can prevent its sub-targets' fan-outs from
/// each opening their own concurrency budget. When `shared_sem` is `None`
/// (top-level call), each fan-out function creates its own.
async fn run_with_limits_shared(
    module: Arc<dyn Module>,
    target: Target,
    options: ModuleOptions,
    verbose: bool,
    limits: SchedulerLimits,
    shared_sem: Option<Arc<Semaphore>>,
) -> Result<ModuleOutcome> {
    let cancel = crate::context::cancellation_token()
        .unwrap_or_default();
    let tenant_id = crate::context::current_tenant_id();
    let module_path = current_module_path(module.as_ref());

    // Refresh the rate limiter from the current options at the start of each
    // top-level scan (not for `fanout_multi` sub-targets, which pass a shared
    // semaphore) so a `setg target_rps` / `setg module_rps` changed since the
    // last run actually takes effect instead of being pinned to the values the
    // process-global limiter was first built with.
    if shared_sem.is_none() {
        crate::rate_limit::shared().reload().await;
    }

    // Pre-flight: validate options once before fan-out so the operator
    // sees one error instead of N identical errors across N hosts.
    let mut precheck_ctx = ModuleCtx::new(target.clone());
    precheck_ctx.options = options.clone();
    precheck_ctx.cancel = cancel.clone();
    precheck_ctx.tenant_id = tenant_id.clone();
    precheck_ctx.verbose = verbose;
    precheck_ctx.module_path = module_path.clone();
    if let Err(e) = module.pre_check(&precheck_ctx).await {
        crate::meprintln!("[!] Pre-flight check failed: {e:#}");
        return Err(e);
    }
    drop(precheck_ctx);

    // If no explicit `setg port` was given, fall back to the module's
    // declared default_port so mass-scan pre-checks can skip hosts that
    // don't have the service port open.
    let limits = {
        let mut l = limits;
        if l.precheck_port.is_none() {
            l.precheck_port = module.info().default_port;
        }
        // Full-sweep cap consistency: a literal `0.0.0.0/0` / `random` target
        // entered directly (e.g. `use <mod>; run`) never passes through the
        // shell's `setg target` handler, so without this it would silently fall
        // back to the scheduler default of 10_000 — while `setg target 0.0.0.0`
        // auto-bumps to the full public-IPv4 count. Normalise both paths: when
        // the operator has NOT explicitly set `max_random_hosts`, a full sweep
        // means every reachable public host. An explicit `setg max_random_hosts`
        // is always honoured. The advisory + confirmation gate still runs.
        if matches!(target, Target::Random) {
            let operator_set = crate::tenant::resolve()
                .global_options()
                .try_get("max_random_hosts")
                .is_some();
            if !operator_set {
                l.max_random_hosts = crate::utils::cyclic::total_public_ipv4_count() as usize;
            }
        }
        l
    };

    // Mass-scan fan-out is universal: every module gets fanned out per host
    // for Cidr/Multi/File/Random, sees `Target::Single` inside `run()`.
    let outcome = match target.clone() {
        Target::Single(_) => fanout_single(FanoutParams { module: module.clone(), target, options, cancel, tenant_id: tenant_id.clone(), limits, module_path: module_path.clone() }, verbose).await,
        Target::Cidr(_) => fanout_cidr(FanoutParams { module: module.clone(), target, options, cancel, tenant_id: tenant_id.clone(), limits, module_path: module_path.clone() }, shared_sem.clone()).await,
        Target::File(_) => fanout_file(FanoutParams { module: module.clone(), target, options, cancel, tenant_id: tenant_id.clone(), limits, module_path: module_path.clone() }, shared_sem.clone()).await,
        Target::Multi(_) => fanout_multi(module.clone(), target, options, cancel, tenant_id.clone(), verbose, limits).await,
        // `0.0.0.0/0` / `random` honour `setg scan_order sequential` so an
        // operator can flip the full-internet sweep between random and in-order.
        Target::Random => {
            if scan_order_is_sequential() {
                fanout_sequential(crate::module::FIRST_PUBLIC_IPV4, module.clone(), options, cancel, tenant_id.clone(), limits, module_path.clone(), shared_sem.clone()).await
            } else {
                fanout_random(module.clone(), options, cancel, tenant_id.clone(), limits, module_path.clone(), shared_sem.clone()).await
            }
        }
        Target::Sequential(start) => fanout_sequential(start, module.clone(), options, cancel, tenant_id.clone(), limits, module_path.clone(), shared_sem.clone()).await,
    };

    // Cleanup runs whether the fan-out succeeded or failed so modules
    // can release resources (connections, temp files) unconditionally.
    {
        let fallback = ModuleOutcome::fail();
        let out = match outcome {
            Ok(ref o) => o,
            Err(ref e) => {
                crate::meprintln!("[!] Fan-out failed: {e:#}");
                &fallback
            }
        };
        let mut cleanup_ctx = ModuleCtx::new(Target::Single(String::new()));
        cleanup_ctx.tenant_id = tenant_id;
        cleanup_ctx.verbose = verbose;
        cleanup_ctx.module_path = module_path;
        if let Err(e) = module.cleanup(&cleanup_ctx, out).await {
            crate::meprintln!("[!] Cleanup hook failed: {e:#}");
        }
    }

    outcome
}

/// Resolve a `&dyn Module` back to its registered `category/name` path.
/// Used by the scheduler to populate `ModuleCtx::module_path` so the rate
/// limiter and finding-routing know which entry produced a given outcome.
fn current_module_path(module: &dyn Module) -> String {
    let info_name = module.info().name;
    // Pass 1: compare display name without instantiating every module.
    // `entry.name` is the registry key (e.g. "ssh/known_vuln"), while
    // `info_name` is the human-readable title. We need to compare
    // info().name from the factory, but avoid instantiating all modules.
    // Instead, compare the passed module's info().name against each
    // factory's info().name — break on first match to avoid O(N) allocs.
    for entry in crate::module::registered() {
        if (entry.factory)().info().name == info_name {
            return format!("{}/{}", entry.category.as_str(), entry.name);
        }
    }
    info_name
}

/// One initial attempt plus a single retry per host. Bounded so a transient
/// blip is absorbed without doubling the wall-clock of a full sweep.
const MAX_HOST_ATTEMPTS: usize = 2;

/// Classify an error as a transient network condition worth one retry. A closed
/// port (`ConnectionRefused`) or a non-IO module error (e.g. "target not
/// affected") is terminal, so a mass scan never wastes a retry on a host that
/// simply does not run the service.
fn is_transient_error(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            use std::io::ErrorKind;
            if matches!(
                io.kind(),
                ErrorKind::TimedOut
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::BrokenPipe
                    | ErrorKind::UnexpectedEof
            ) {
                return true;
            }
        }
    }
    // The per-host deadline wrapper produces an anyhow error (not an io::Error)
    // whose message starts with "timed out".
    err.to_string().contains("timed out")
}

/// Run a module against one host with bounded retry on transient failures, then
/// return the outcome for the caller to record. A transient error is retried up
/// to `MAX_HOST_ATTEMPTS` with a short backoff; any other error returns
/// immediately. Either way a single host never aborts the surrounding mass-scan
/// loop — the caller records the outcome and continues to the next host.
async fn run_host_with_retry(
    module: &Arc<dyn Module>,
    ctx: &ModuleCtx,
    per_host_timeout: Option<Duration>,
) -> Result<ModuleOutcome> {
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        let res = match per_host_timeout {
            Some(d) => match tokio::time::timeout(d, module.run(ctx)).await {
                Ok(r) => r,
                Err(e) => Err(anyhow::anyhow!("timed out: {e}")),
            },
            None => module.run(ctx).await,
        };
        match res {
            Ok(outcome) => return Ok(outcome),
            Err(e) => {
                if attempt < MAX_HOST_ATTEMPTS && !ctx.is_cancelled() && is_transient_error(&e) {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
                return Err(e);
            }
        }
    }
}

// ============================================================
// FAN-OUT
// ============================================================

/// Shared parameters for all fanout dispatch functions.
struct FanoutParams {
    module: Arc<dyn Module>,
    target: Target,
    options: ModuleOptions,
    cancel: tokio_util::sync::CancellationToken,
    tenant_id: Option<String>,
    limits: SchedulerLimits,
    module_path: String,
}

async fn fanout_single(
    params: FanoutParams,
    verbose: bool,
) -> Result<ModuleOutcome> {
    let FanoutParams { module, target, options, cancel, tenant_id, limits, module_path } = params;
    let host = target.as_single().unwrap_or("").to_string();
    if limits.honeypot_detection
        && crate::utils::network::quick_honeypot_check(&host).await
    {
        crate::mprintln!(
            "{}",
            format!(
                "[!] Target {} appears to be a honeypot (11+ common ports open) — skipping",
                host
            )
            .red()
            .bold()
        );
        return Ok(ModuleOutcome::ok());
    }
    let mut ctx = ModuleCtx::new(target);
    ctx.options = options;
    ctx.cancel = cancel;
    ctx.tenant_id = tenant_id;
    ctx.verbose = verbose;
    ctx.module_path = module_path;
    // The per-target deadline is a MASS-SCAN safeguard: when fanning out across
    // many hosts, one slow/hung host must not starve the scan. For a SINGLE,
    // deliberately-chosen target it is actively harmful:
    //   * interactive modules (wpair's REPL) own their own session lifetime, and
    //   * any module that prompts the operator inside run() (e.g. asyncssh's
    //     "Username to impersonate") gets killed the moment the human takes
    //     longer than the deadline to type. Worse, that prompt is a blocking
    //     `spawn_blocking` stdin read which cannot be cancelled — killing the
    //     run orphans the reader thread, which then races the shell for the next
    //     line (the "lag after error" + corrupted REPL input).
    //
    // Enforce the deadline only when there is NO human at the console to answer
    // prompts or hit Ctrl-C — i.e. an API/MCP/background run (api_mode), or a
    // scripted/piped CLI run whose stdin is not a terminal. In those contexts
    // cfg_prompt_* resolves from options/defaults (it never blocks on a real
    // keyboard) and the run must stay bounded so it can't hang a request or a
    // script. An interactive console (stdin is a TTY) is exempt: the operator
    // chose this single target, can watch it, and can interrupt it — and a
    // prompt blocking on the keyboard must never count against a deadline.
    // Interactive modules (wpair's REPL) are always exempt. Mass-scan fan-out
    // paths keep their own per-host timeouts (fanout_cidr/_file/_random).
    let no_console_operator =
        crate::config::get_module_config().api_mode || !std::io::stdin().is_terminal();
    let enforce_deadline = !module.capabilities().interactive && no_console_operator;
    let outcome = if enforce_deadline {
        tokio::time::timeout(Duration::from_secs(limits.timeout_secs), module.run(&ctx))
            .await
            .map_err(|e| {
                anyhow::anyhow!("Module timed out after {}s: {e}", limits.timeout_secs)
            })??
    } else {
        module.run(&ctx).await?
    };
    // Publish single-target progress to the job's scan counters (if any).
    if let Some(c) = crate::context::scan_counters() {
        c.total.store(1, Ordering::Relaxed);
        if outcome.success {
            c.succeeded.store(1, Ordering::Relaxed);
        } else {
            c.failed.store(1, Ordering::Relaxed);
        }
    }
    route_findings(&outcome, module.as_ref()).await;
    Ok(outcome)
}

async fn fanout_cidr(
    params: FanoutParams,
    shared_sem: Option<Arc<Semaphore>>,
) -> Result<ModuleOutcome> {
    let FanoutParams { module, target, options, cancel, tenant_id, limits, module_path } = params;
    let cidr = match &target {
        Target::Cidr(s) => s.clone(),
        // Reachable only via an internal dispatch bug; surface it as a clean
        // error rather than panicking the process (and it clears the no-panic gate).
        _ => anyhow::bail!("internal error: fanout_cidr called with non-Cidr target"),
    };
    let network = crate::utils::parse_subnet(&cidr)?;
    let host_count = crate::utils::subnet_host_count(&network);

    if host_count <= 1 {
        let single = Target::Single(network.network().to_string());
        return Box::pin(run_with_limits_shared(
            module, single, options, false, limits, shared_sem,
        ))
        .await;
    }
    if network.is_ipv6() && host_count > limits.ipv6_max_hosts {
        anyhow::bail!(
            "IPv6 subnet {} expands to {} hosts — too wide. Use a narrower prefix.",
            network,
            host_count
        );
    }
    if host_count > limits.warn_threshold {
        let est_secs = (host_count / (limits.concurrency.max(1) as u128))
            .saturating_mul(limits.timeout_secs as u128);
        let est = if est_secs > 86_400 {
            format!("{:.1} days", est_secs as f64 / 86_400.0)
        } else if est_secs > 3600 {
            format!("{:.1} hours", est_secs as f64 / 3600.0)
        } else {
            format!("{} minutes", est_secs / 60)
        };
        crate::mprintln!(
            "{}",
            format!(
                "[!] Large scan: {} expands to {} hosts (worst-case ~{} at concurrency {})",
                network, host_count, est, limits.concurrency
            )
            .yellow()
            .bold()
        );
        let cfg = crate::config::get_module_config();
        if !cfg.api_mode && !crate::utils::is_batch_mode() {
            let confirmed = crate::utils::prompt_yes_no(
                &format!("Proceed with scanning all {} hosts?", host_count),
                false,
            )
            .await?;
            if !confirmed {
                anyhow::bail!("CIDR scan of {} aborted by user.", network);
            }
        }
    }

    // --- Pre-batch interactive prompt phase ---
    let cfg = crate::config::get_module_config();
    if !cfg.api_mode {
        pre_batch_prompt(&module, &options, cancel.clone(), tenant_id.clone(), &module_path).await?;
    }

    let batch_guard = crate::context::enter_batch_mode();
    let stats = Arc::new(ScanStats::default());
    // When the parent (e.g. `fanout_multi`) supplies a shared semaphore,
    // use it so cross-target runs share one concurrency budget; otherwise
    // create a fresh one sized to the configured concurrency.
    let sem = shared_sem
        .unwrap_or_else(|| Arc::new(Semaphore::new(limits.concurrency)));
    let prompt_cache = crate::context::new_prompt_cache();

    let checkpoint = open_checkpoint(&module_path, &cidr).await;

    // Optional: hand the CIDR to masscan/zmap first, then run the module
    // only against live hosts. Speedup is dramatic on sparse ranges.
    let prescan_choice = crate::prescan::Prescan::from_global_options();
    let live_hosts: Option<Vec<String>> = if prescan_choice.is_enabled() {
        match crate::prescan::discover_live(&network, prescan_choice).await {
            Ok(ips) if !ips.is_empty() => Some(ips),
            Ok(_) => None,
            Err(e) => {
                crate::meprintln!(
                    "[!] prescan failed: {e:#}. Falling back to per-IP fan-out."
                );
                None
            }
        }
    } else {
        None
    };

    let effective_count: u128 = match &live_hosts {
        Some(v) => v.len() as u128,
        None => host_count,
    };
    let progress_step = progress_step_for(effective_count);
    crate::mprintln!(
        "{}",
        format!(
            "[*] Subnet: {} ({} {}) — running '{}' with concurrency {}",
            network,
            effective_count,
            if live_hosts.is_some() { "live hosts via prescan" } else { "hosts" },
            module.info().name,
            limits.concurrency
        )
        .cyan()
    );

    let ip_iter: Box<dyn Iterator<Item = std::net::IpAddr> + Send> = match live_hosts {
        Some(ips) => Box::new(ips.into_iter().filter_map(|s| s.parse().ok())),
        None => Box::new(network.iter()),
    };

    // Per-fanout JoinSet — tracks completion of *this* fan-out's spawns
    // even when the semaphore is shared with a sibling sub-target via
    // `fanout_multi`. Without this we couldn't tell when our own slice
    // of the work was done.
    let mut joinset = tokio::task::JoinSet::<()>::new();

    // Honor the operator's exclusion list and the service-port precheck on CIDR
    // scans too (previously only `fanout_random` did), so `setg exclusions ...`
    // actually filters a subnet sweep and a sparse range doesn't run the module
    // against every host whose service port is closed.
    let exclusions = crate::exclusions::shared();
    let precheck_port = limits.precheck_port;
    let honeypot = limits.honeypot_detection;

    for ip in ip_iter {
        if cancel.is_cancelled() || stats.abort.load(Ordering::Relaxed) {
            break;
        }
        let ip_str = ip.to_string();
        // Count every host the fan-out looks at as "considered" (even when
        // skipped here in the producer before spawning), so progress's
        // examined/total denominator stays accurate under exclusions/resume.
        if exclusions.contains(ip) {
            stats.considered.fetch_add(1, Ordering::Relaxed);
            stats.skipped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        // Skip already-processed targets when resuming.
        if let Some(cp) = &checkpoint
            && cp.already_processed(&ip_str).await {
                stats.considered.fetch_add(1, Ordering::Relaxed);
                stats.skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        // Race the permit acquisition against cancellation: when the semaphore
        // is saturated this await can block for a long time, and without the
        // race a Ctrl-C would not stop the dispatcher from enqueuing more hosts
        // until a permit happened to free up. `biased` checks cancel first.
        let permit = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            p = sem.clone().acquire_owned() => p.context("Semaphore closed")?,
        };
        let module_clone = module.clone();
        let opts = options.clone();
        let cache = prompt_cache.clone();
        let cancel_clone = cancel.clone();
        let tenant = tenant_id.clone();
        let stats_clone = stats.clone();
        let mp = module_path.clone();
        let cp_clone = checkpoint.clone();

        joinset.spawn(async move {
            // Load-bearing: holds the owned semaphore permit for the task's
            // whole lifetime so concurrency stays bounded; the slot is freed
            // when this task ends. This is NOT a `let _ =` discard.
            let _permit = permit;
            let ip_str = ip.to_string();
            if let Some(n) = stats_clone.tick(progress_step) {
                crate::mprintln!("{}", progress_line(n, effective_count, &stats_clone.snapshot()));
            }
            // Service-port + honeypot precheck (skips hosts that don't have the
            // module's port open), consistent with the random fan-out.
            if !crate::utils::network::mass_scan_precheck(ip, precheck_port, honeypot).await {
                stats_clone.skipped.fetch_add(1, Ordering::Relaxed);
                record_checkpoint(&cp_clone, &ip_str).await;
                return;
            }
            stats_clone.processed.fetch_add(1, Ordering::Relaxed);
            let mut ctx = ModuleCtx::new(Target::Single(ip_str.clone()));
            ctx.options = opts;
            ctx.cancel = cancel_clone;
            ctx.tenant_id = tenant;
            ctx.batch_mode = true;
            ctx.prompt_cache = Some(cache);
            ctx.module_path = mp;
            let outcome = run_host_with_retry(
                &module_clone,
                &ctx,
                Some(Duration::from_secs(limits.timeout_secs)),
            )
            .await;
            stats_clone.record(outcome);
            record_checkpoint(&cp_clone, &ip_str).await;
        });
    }

    drain_joinset(&mut joinset).await;
    let completed_cleanly = !cancel.is_cancelled() && !stats.abort.load(Ordering::Relaxed);
    finalize_checkpoint(&checkpoint, completed_cleanly).await;
    let outcome = finalize(&format!("Subnet Scan ({})", network), &stats, effective_count as usize, completed_cleanly);
    route_findings(&outcome, module.as_ref()).await;
    drop(batch_guard);
    Ok(outcome)
}

async fn fanout_file(
    params: FanoutParams,
    shared_sem: Option<Arc<Semaphore>>,
) -> Result<ModuleOutcome> {
    let FanoutParams { module, target, options, cancel, tenant_id, limits, module_path } = params;
    let path = match &target {
        Target::File(p) => p.clone(),
        _ => anyhow::bail!("internal error: fanout_file called with non-File target"),
    };
    let content = crate::utils::safe_read_to_string_async(
        path.to_str().unwrap_or(""),
        None,
    )
    .await
    .with_context(|| format!("Failed to read target file '{}'", path.display()))?;
    let targets: Vec<String> = content
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .collect();
    let count = targets.len();
    crate::mprintln!(
        "{}",
        format!(
            "[*] File target list: {} hosts from '{}' — running '{}'",
            count,
            path.display(),
            module.info().name
        )
        .cyan()
        .bold()
    );

    // --- Pre-batch interactive prompt phase ---
    let cfg = crate::config::get_module_config();
    if !cfg.api_mode {
        pre_batch_prompt(&module, &options, cancel.clone(), tenant_id.clone(), &module_path).await?;
    }

    let batch_guard = crate::context::enter_batch_mode();
    let stats = Arc::new(ScanStats::default());
    let sem = shared_sem
        .unwrap_or_else(|| Arc::new(Semaphore::new(limits.concurrency)));
    let prompt_cache = crate::context::new_prompt_cache();
    // Checkpoint key includes the file path so different host lists
    // checkpoint independently.
    let checkpoint = open_checkpoint(&module_path, &path.to_string_lossy()).await;
    let progress_step = progress_step_for(count as u128);
    let mut joinset = tokio::task::JoinSet::<()>::new();

    // Apply exclusions + the service-port precheck to file scans too. Entries
    // that are IP literals get the same treatment as random/CIDR scans; hostname
    // entries can't be cheaply IP-filtered, so they fall back to the honeypot
    // check only (resolving every name up front would add latency).
    let exclusions = crate::exclusions::shared();
    let precheck_port = limits.precheck_port;
    let honeypot = limits.honeypot_detection;

    for host in targets {
        if cancel.is_cancelled() {
            break;
        }
        // Count producer-side skips as considered too (accurate progress).
        if let Ok(ip) = host.parse::<std::net::IpAddr>()
            && exclusions.contains(ip) {
                stats.considered.fetch_add(1, Ordering::Relaxed);
                stats.skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        if let Some(cp) = checkpoint.as_ref()
            && cp.already_processed(&host).await {
                stats.considered.fetch_add(1, Ordering::Relaxed);
                stats.skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        // Race the permit acquisition against cancellation: when the semaphore
        // is saturated this await can block for a long time, and without the
        // race a Ctrl-C would not stop the dispatcher from enqueuing more hosts
        // until a permit happened to free up. `biased` checks cancel first.
        let permit = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            p = sem.clone().acquire_owned() => p.context("Semaphore closed")?,
        };
        let module_clone = module.clone();
        let opts = options.clone();
        let cache = prompt_cache.clone();
        let cancel_clone = cancel.clone();
        let tenant = tenant_id.clone();
        let stats_clone = stats.clone();
        let mp = module_path.clone();
        let cp_clone = checkpoint.clone();

        joinset.spawn(async move {
            // Load-bearing: holds the owned semaphore permit for the task's
            // whole lifetime so concurrency stays bounded; the slot is freed
            // when this task ends. This is NOT a `let _ =` discard.
            let _permit = permit;
            if let Some(n) = stats_clone.tick(progress_step) {
                crate::mprintln!("{}", progress_line(n, count as u128, &stats_clone.snapshot()));
            }
            // IP-literal entries get the full service-port + honeypot precheck;
            // hostname entries keep the honeypot-only check.
            let skip = match host.parse::<std::net::IpAddr>() {
                Ok(ip) => !crate::utils::network::mass_scan_precheck(ip, precheck_port, honeypot).await,
                Err(e) => {
                    tracing::trace!("'{host}' is not an IP literal ({e}); honeypot-only precheck");
                    honeypot && crate::utils::network::quick_honeypot_check(&host).await
                }
            };
            if skip {
                stats_clone.skipped.fetch_add(1, Ordering::Relaxed);
                record_checkpoint(&cp_clone, &host).await;
                return;
            }
            stats_clone.processed.fetch_add(1, Ordering::Relaxed);
            let mut ctx = ModuleCtx::new(Target::Single(host.clone()));
            ctx.options = opts;
            ctx.cancel = cancel_clone;
            ctx.tenant_id = tenant;
            ctx.batch_mode = true;
            ctx.prompt_cache = Some(cache);
            ctx.module_path = mp;
            let outcome = run_host_with_retry(
                &module_clone,
                &ctx,
                Some(Duration::from_secs(limits.timeout_secs)),
            )
            .await;
            stats_clone.record(outcome);
            record_checkpoint(&cp_clone, &host).await;
        });
    }

    drain_joinset(&mut joinset).await;
    let completed_cleanly = !cancel.is_cancelled();
    finalize_checkpoint(&checkpoint, completed_cleanly).await;
    let outcome = finalize("File Target Scan", &stats, count, completed_cleanly);
    route_findings(&outcome, module.as_ref()).await;
    drop(batch_guard);
    Ok(outcome)
}

async fn fanout_multi(
    module: Arc<dyn Module>,
    target: Target,
    options: ModuleOptions,
    cancel: tokio_util::sync::CancellationToken,
    tenant_id: Option<String>,
    verbose: bool,
    limits: SchedulerLimits,
) -> Result<ModuleOutcome> {
    let parts = match target {
        Target::Multi(p) => p,
        _ => anyhow::bail!("internal error: fanout_multi called with non-Multi target"),
    };
    let total = parts.len();
    if let Some(ref tid) = tenant_id {
        tracing::debug!("fanout_multi: tenant_id={}, targets={}", tid, total);
    }
    crate::mprintln!(
        "{}",
        format!(
            "[*] Multi-target detected: {} targets — running '{}' against each",
            total,
            module.info().name
        )
        .cyan()
    );
    // Single shared semaphore across every sub-target's fan-out so the
    // total in-flight task count never exceeds `limits.concurrency`,
    // regardless of how many CIDR/file/random sub-targets run.
    let shared_sem = Arc::new(Semaphore::new(limits.concurrency));
    let mut combined = ModuleOutcome::ok();
    for (i, sub) in parts.into_iter().enumerate() {
        if cancel.is_cancelled() {
            break;
        }
        crate::mprintln!(
            "\n{}",
            format!("[*] === Target {}/{} ===", i + 1, total).cyan().bold()
        );
        match Box::pin(run_with_limits_shared(
            module.clone(),
            sub,
            options.clone(),
            verbose,
            limits,
            Some(shared_sem.clone()),
        ))
        .await
        {
            Ok(out) => {
                if !out.success {
                    combined.success = false;
                }
                combined.findings.extend(out.findings);
            }
            Err(e) => {
                combined.success = false;
                crate::meprintln!("{}", format!("[!] Sub-target failed: {:?}", e).red());
            }
        }
    }
    Ok(combined)
}

async fn fanout_random(
    module: Arc<dyn Module>,
    options: ModuleOptions,
    cancel: tokio_util::sync::CancellationToken,
    tenant_id: Option<String>,
    limits: SchedulerLimits,
    module_path: String,
    shared_sem: Option<Arc<Semaphore>>,
) -> Result<ModuleOutcome> {
    // Full-internet sweep advisory + interactive confirmation FIRST. Declining
    // must abort before anything is touched — including the prompt-harvest
    // dry-run below, which actually runs the module against a placeholder host.
    if !full_sweep_advisory_and_confirm(
        &module,
        &limits,
        Some(limits.max_random_hosts),
        "Random mass scan",
    )
    .await?
    {
        return Ok(ModuleOutcome::ok());
    }

    // --- Pre-batch interactive prompt phase ---
    // Run module prompts ONCE before batch mode so the user can configure
    // interactively. Answers are cached and reused for all targets.
    let cfg = crate::config::get_module_config();
    if !cfg.api_mode {
        pre_batch_prompt(&module, &options, cancel.clone(), tenant_id.clone(), &module_path).await?;
    }

    let batch_guard = crate::context::enter_batch_mode();
    let stats = Arc::new(ScanStats::default());
    let sem = shared_sem
        .unwrap_or_else(|| Arc::new(Semaphore::new(limits.concurrency)));
    let prompt_cache = crate::context::new_prompt_cache();
    // Pluggable per-tenant exclusion list. Operators control via
    // `setg exclusions ...`; falls back to bogons + RFC1918 + Cloudflare + DNS.
    let exclusion_set = crate::exclusions::shared();
    let exclusions = Arc::new(exclusion_set.networks().to_vec());
    let module_err = Arc::new(AtomicUsize::new(0));
    // Random scans checkpoint by IP so a kill-then-restart skips the IPs
    // that already ran. Useful when the operator sets `max_random_hosts`
    // high and aborts mid-scan.
    let checkpoint = open_checkpoint(&module_path, "random").await;
    let mut joinset = tokio::task::JoinSet::<()>::new();

    crate::mprintln!(
        "{}",
        format!(
            "[*] Random mass scan — running '{}' against random public IPs (Ctrl+C to stop)",
            module.info().name
        )
        .cyan()
        .bold()
    );
    crate::mprintln!(
        "{}",
        format!(
            "[*] Will scan up to {} hosts with concurrency {} (ZMap-style stateless permutation — no repeats)",
            limits.max_random_hosts, limits.concurrency
        )
        .cyan()
    );

    let progress_step = progress_step_for(limits.max_random_hosts as u128);
    // ZMap-style stateless permutation of the IPv4 space: every address is
    // visited at most once with O(1) memory and no dedup table (see
    // `crate::utils::cyclic`). This replaces the old random-sample + `HashSet`,
    // which grew unboundedly and — as coverage rose — wasted an ever-larger
    // share of samples re-drawing addresses it had already seen.
    let mut cyclic = crate::utils::cyclic::CyclicIp::random()?;
    let mut dispatched: usize = 0;
    while dispatched < limits.max_random_hosts {
        if cancel.is_cancelled() || stats.abort.load(Ordering::Relaxed) {
            break;
        }
        // Pull the next real, non-excluded address from the permutation.
        // Reserved ranges and operator exclusions are skipped without counting
        // against the host budget (they were never valid targets). `None` means
        // the entire address space has been enumerated.
        let ip = 'pick: loop {
            match cyclic.next() {
                Some(addr) => {
                    if crate::utils::cyclic::is_reserved_ipv4(addr) {
                        continue;
                    }
                    let ip = std::net::IpAddr::V4(addr);
                    if exclusions.iter().any(|net| net.contains(ip)) {
                        continue;
                    }
                    break 'pick Some(ip);
                }
                None => break 'pick None,
            }
        };
        let Some(ip) = ip else { break };
        dispatched += 1;
        let ip_str = ip.to_string();
        if let Some(cp) = checkpoint.as_ref()
            && cp.already_processed(&ip_str).await {
                stats.skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        // Race the permit acquisition against cancellation: when the semaphore
        // is saturated this await can block for a long time, and without the
        // race a Ctrl-C would not stop the dispatcher from enqueuing more hosts
        // until a permit happened to free up. `biased` checks cancel first.
        let permit = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            p = sem.clone().acquire_owned() => p.context("Semaphore closed")?,
        };
        let module_clone = module.clone();
        let opts = options.clone();
        let cache = prompt_cache.clone();
        let cancel_clone = cancel.clone();
        let tenant = tenant_id.clone();
        let stats_clone = stats.clone();
        let module_err_clone = module_err.clone();
        let port = limits.precheck_port;
        let honeypot = limits.honeypot_detection;
        let mp = module_path.clone();
        let cp_clone = checkpoint.clone();

        joinset.spawn(async move {
            // Load-bearing: holds the owned semaphore permit for the task's
            // whole lifetime so concurrency stays bounded; the slot is freed
            // when this task ends. This is NOT a `let _ =` discard.
            let _permit = permit;
            // Tick BEFORE the precheck so progress advances even when (as is
            // typical for random ranges) almost every host fails the port
            // precheck and is skipped. Previously progress only moved on
            // hosts that passed the precheck, so a sparse scan looked frozen.
            if let Some(n) = stats_clone.tick(progress_step) {
                crate::mprintln!(
                    "{}",
                    progress_line(n, limits.max_random_hosts as u128, &stats_clone.snapshot())
                );
            }
            if !crate::utils::network::mass_scan_precheck(ip, port, honeypot).await {
                stats_clone.skipped.fetch_add(1, Ordering::Relaxed);
                record_checkpoint(&cp_clone, &ip.to_string()).await;
                return;
            }
            stats_clone.processed.fetch_add(1, Ordering::Relaxed);
            let mut ctx = ModuleCtx::new(Target::Single(ip.to_string()));
            ctx.options = opts;
            ctx.cancel = cancel_clone;
            ctx.tenant_id = tenant;
            ctx.batch_mode = true;
            ctx.prompt_cache = Some(cache);
            ctx.module_path = mp;
            let outcome = run_host_with_retry(
                &module_clone,
                &ctx,
                Some(Duration::from_secs(limits.timeout_secs)),
            )
            .await;
            let was_err = stats_clone.record(outcome);
            record_checkpoint(&cp_clone, &ip.to_string()).await;
            if was_err {
                let n = module_err_clone.fetch_add(1, Ordering::Relaxed) + 1;
                let ok_so_far = stats_clone.success.load(Ordering::Relaxed);
                // Warn once if the run looks misconfigured, but keep going:
                // transient failures are already retried, and the operator asked
                // for error -> retry -> continue rather than an automatic abort.
                if n == 10 && ok_so_far == 0 {
                    crate::meprintln!(
                        "{}",
                        "[!] First 10 dispatches errored with no successes — continuing anyway (check module/target config if this persists; Ctrl+C to stop)."
                            .yellow()
                    );
                }
            }
        });
    }

    drain_joinset(&mut joinset).await;
    let completed_cleanly = !cancel.is_cancelled() && !stats.abort.load(Ordering::Relaxed);
    finalize_checkpoint(&checkpoint, completed_cleanly).await;
    // Denominator is the host budget, not the post-precheck count, so
    // "examined / total" reflects how far through the random sweep we got.
    let outcome = finalize("Random Mass Scan", &stats, limits.max_random_hosts, completed_cleanly);
    route_findings(&outcome, module.as_ref()).await;
    drop(batch_guard);
    Ok(outcome)
}

/// `true` when the operator selected sequential mass-scan order via
/// `setg scan_order sequential` (also accepts `seq`).
fn scan_order_is_sequential() -> bool {
    crate::tenant::resolve()
        .global_options()
        .try_get("scan_order")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "sequential" || v == "seq"
        })
        .unwrap_or(false)
}

/// Sequential public-IPv4 sweep from `start` (clamped to the first public
/// address) up to the last public address (223.255.255.255), in order. Honors
/// the exclusion list, the service-port precheck, honeypot detection, and a
/// high-water-mark checkpoint so a killed scan resumes from where it left off.
/// Unbounded by default; capped only when the operator sets `max_random_hosts`.
#[allow(clippy::too_many_arguments)]
async fn fanout_sequential(
    start: u32,
    module: Arc<dyn Module>,
    options: ModuleOptions,
    cancel: tokio_util::sync::CancellationToken,
    tenant_id: Option<String>,
    limits: SchedulerLimits,
    module_path: String,
    shared_sem: Option<Arc<Semaphore>>,
) -> Result<ModuleOutcome> {
    const LAST_PUBLIC: u32 = 0xDFFF_FFFF; // 223.255.255.255 (end of Class A-C)

    let cfg = crate::config::get_module_config();

    // Optional operator cap. Unbounded unless `max_random_hosts` is explicitly set.
    let cap: Option<usize> = match crate::tenant::resolve()
        .global_options()
        .try_get("max_random_hosts")
    {
        Some(v) => match v.trim().parse::<usize>() {
            Ok(n) => Some(n),
            Err(e) => {
                crate::meprintln!(
                    "[!] invalid max_random_hosts '{}' ({e}) — running unbounded.",
                    v.trim()
                );
                None
            }
        },
        None => None,
    };

    // Full-internet sweep advisory + interactive confirmation FIRST. Declining
    // must abort before anything is touched (the resume marker, and the
    // prompt-harvest dry-run below which runs the module against a placeholder).
    if !full_sweep_advisory_and_confirm(&module, &limits, cap, "Sequential mass scan").await? {
        return Ok(ModuleOutcome::ok());
    }

    // Pre-batch interactive prompt phase (after confirmation).
    if !cfg.api_mode {
        pre_batch_prompt(&module, &options, cancel.clone(), tenant_id.clone(), &module_path).await?;
    }

    let batch_guard = crate::context::enter_batch_mode();
    let stats = Arc::new(ScanStats::default());
    let sem = shared_sem.unwrap_or_else(|| Arc::new(Semaphore::new(limits.concurrency)));
    let prompt_cache = crate::context::new_prompt_cache();
    let exclusions = crate::exclusions::shared();
    let module_err = Arc::new(AtomicUsize::new(0));

    // High-water-mark resume: the per-IP set used by random/CIDR does not scale
    // to billions of addresses, so sequential stores the last dispatched IP and
    // resumes from `hi + 1`.
    let scan_id = crate::checkpoint::auto_scan_id(&module_path, "sequential");
    let mut start_ip = start.max(crate::module::FIRST_PUBLIC_IPV4);
    if let Some(hi) = crate::checkpoint::read_seq_marker(&scan_id) {
        let resume = hi.saturating_add(1);
        if resume > start_ip {
            crate::mprintln!(
                "{}",
                format!(
                    "[*] Resuming sequential scan from {}.",
                    std::net::Ipv4Addr::from(resume)
                )
                .green()
            );
            start_ip = resume;
        }
    }

    let range_total: u128 = if start_ip > LAST_PUBLIC {
        0
    } else {
        (LAST_PUBLIC - start_ip) as u128 + 1
    };
    let total: u128 = match cap {
        Some(c) => (c as u128).min(range_total),
        None => range_total,
    };

    crate::mprintln!(
        "{}",
        format!(
            "[*] Sequential mass scan — running '{}' from {} to {} (Ctrl+C to stop)",
            module.info().name,
            std::net::Ipv4Addr::from(start_ip),
            std::net::Ipv4Addr::from(LAST_PUBLIC)
        )
        .cyan()
        .bold()
    );
    match cap {
        Some(c) => crate::mprintln!(
            "{}",
            format!("[*] Capped at {c} hosts (max_random_hosts), concurrency {}", limits.concurrency).cyan()
        ),
        None => crate::mprintln!(
            "{}",
            format!("[*] Unbounded sweep, concurrency {}", limits.concurrency).cyan()
        ),
    }

    let progress_step = progress_step_for(total);
    let mut joinset = tokio::task::JoinSet::<()>::new();
    let mut dispatched: usize = 0;
    let mut ip = start_ip;
    let mut last_dispatched = start_ip;

    loop {
        if ip > LAST_PUBLIC || cancel.is_cancelled() || stats.abort.load(Ordering::Relaxed) {
            break;
        }
        if let Some(c) = cap
            && dispatched >= c
        {
            break;
        }
        let addr = std::net::Ipv4Addr::from(ip);
        if exclusions.contains(std::net::IpAddr::V4(addr)) {
            match ip.checked_add(1) {
                Some(n) => {
                    ip = n;
                    continue;
                }
                None => break,
            }
        }

        // Race permit acquisition against cancellation (see `fanout_random`).
        let permit = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            p = sem.clone().acquire_owned() => p.context("Semaphore closed")?,
        };

        let module_clone = module.clone();
        let opts = options.clone();
        let cache = prompt_cache.clone();
        let cancel_clone = cancel.clone();
        let tenant = tenant_id.clone();
        let stats_clone = stats.clone();
        let module_err_clone = module_err.clone();
        let port = limits.precheck_port;
        let honeypot = limits.honeypot_detection;
        let mp = module_path.clone();
        let timeout_secs = limits.timeout_secs;

        joinset.spawn(async move {
            // Load-bearing: holds the permit for the task's lifetime.
            let _permit = permit;
            if let Some(n) = stats_clone.tick(progress_step) {
                crate::mprintln!("{}", progress_line(n, total, &stats_clone.snapshot()));
            }
            if !crate::utils::network::mass_scan_precheck(std::net::IpAddr::V4(addr), port, honeypot)
                .await
            {
                stats_clone.skipped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            stats_clone.processed.fetch_add(1, Ordering::Relaxed);
            let mut ctx = ModuleCtx::new(Target::Single(addr.to_string()));
            ctx.options = opts;
            ctx.cancel = cancel_clone;
            ctx.tenant_id = tenant;
            ctx.batch_mode = true;
            ctx.prompt_cache = Some(cache);
            ctx.module_path = mp;
            let outcome = run_host_with_retry(
                &module_clone,
                &ctx,
                Some(Duration::from_secs(timeout_secs)),
            )
            .await;
            let was_err = stats_clone.record(outcome);
            if was_err {
                let n = module_err_clone.fetch_add(1, Ordering::Relaxed) + 1;
                let ok_so_far = stats_clone.success.load(Ordering::Relaxed);
                // Warn once if the run looks misconfigured, but keep going:
                // transient failures are already retried, and the operator asked
                // for error -> retry -> continue rather than an automatic abort.
                if n == 10 && ok_so_far == 0 {
                    crate::meprintln!(
                        "{}",
                        "[!] First 10 dispatches errored with no successes — continuing anyway (check module/target config if this persists; Ctrl+C to stop)."
                            .yellow()
                    );
                }
            }
        });

        dispatched += 1;
        last_dispatched = ip;
        // Persist the high-water mark periodically (cheap; bounds resume granularity).
        if dispatched.is_multiple_of(progress_step.max(1)) {
            crate::checkpoint::write_seq_marker(&scan_id, ip);
        }

        match ip.checked_add(1) {
            Some(n) => ip = n,
            None => break,
        }
    }

    drain_joinset(&mut joinset).await;
    let reached_end = ip > LAST_PUBLIC;
    let completed_cleanly =
        reached_end && !cancel.is_cancelled() && !stats.abort.load(Ordering::Relaxed);
    if completed_cleanly {
        crate::checkpoint::clear_seq_marker(&scan_id);
    } else {
        // Save where we stopped so the next run resumes.
        crate::checkpoint::write_seq_marker(&scan_id, last_dispatched);
    }
    let outcome = finalize("Sequential Mass Scan", &stats, total as usize, completed_cleanly);
    route_findings(&outcome, module.as_ref()).await;
    drop(batch_guard);
    Ok(outcome)
}

// ============================================================
// PRE-BATCH PROMPT COLLECTION
// ============================================================

/// Runs the module once against a dummy target BEFORE batch mode activates.
/// This lets `cfg_prompt_*` functions prompt interactively (since batch mode
/// is not yet active). Answers are stored in global options so that once
/// batch mode is entered, all tasks find the values pre-populated and never
/// need to prompt stdin.
///
/// If the module errors during this dry-run (expected — it can't reach the
/// dummy target), the error is ignored as long as prompts were collected.
async fn pre_batch_prompt(
    module: &Arc<dyn Module>,
    options: &ModuleOptions,
    cancel: tokio_util::sync::CancellationToken,
    tenant_id: Option<String>,
    module_path: &str,
) -> Result<()> {
    crate::mprintln!(
        "{}",
        "[*] Mass scan mode — configuring module options (answers apply to ALL targets)".cyan().bold()
    );
    crate::mprintln!(
        "{}",
        "    Tip: pre-set values with 'setg <key> <value>' to skip prompts next time.".dimmed()
    );
    crate::mprintln!();

    // Build a context that looks like a normal single-target run.
    // batch_mode is false, so cfg_prompt_* will prompt interactively.
    let mut ctx = ModuleCtx::new(Target::Single("0.0.0.1".to_string()));
    ctx.options = options.clone();
    ctx.cancel = cancel;
    ctx.tenant_id = tenant_id;
    ctx.batch_mode = false;
    // Mark this as a prompt-harvest dry run: `cfg_prompt_*` still prompts
    // (batch_mode is false), but a module that honours `prompt_only` will return
    // immediately after gathering answers instead of doing real work against the
    // placeholder host. Output is captured below as a belt-and-suspenders for
    // modules that don't yet check the flag.
    ctx.prompt_only = true;
    ctx.prompt_cache = None;
    ctx.module_path = module_path.to_string();

    // This dry-run exists ONLY to drive the module's `cfg_prompt_*` calls so a
    // human can answer them once before the batch starts. The operator is
    // typing at the console here, so the bound must be generous: a 5s deadline
    // (the old value) would fire while the operator is still answering, and
    // because each prompt is a blocking `spawn_blocking` stdin read that cannot
    // be cancelled, killing the dry-run orphaned that reader thread — which then
    // raced the next prompt / the shell for input. Keep a large backstop purely
    // so a misbehaving module's post-prompt network work can't hang batch setup
    // forever (the dummy target 0.0.0.1 normally fails fast); the operator can
    // always Ctrl-C.
    // Capture the dry-run's console output into a throwaway buffer so it never
    // reaches the operator. This phase exists ONLY to drive the module's
    // `cfg_prompt_*` calls; without this, a connect-based module (e.g.
    // service_scanner) actually "scans" the placeholder host 0.0.0.1 and prints
    // a confusing `Scanning 0.0.0.1 … 0 services detected` block. Interactive
    // prompts use `print!` (real stdout) and stay visible; only `mprintln!` /
    // `meprintln!` module output is suppressed.
    let run_fut = crate::output::OUTPUT_BUFFER.scope(
        crate::output::OutputBuffer::new(),
        module.run(&ctx),
    );
    let result = tokio::time::timeout(Duration::from_secs(300), run_fut).await;

    // The prompts have already been answered and stored by cfg_prompt_*. The
    // dry-run's outcome is not actionable (it exists only to harvest prompts),
    // so each arm binds and logs it at debug — NOT propagated, because
    // propagating an expected dry-run error would abort the whole batch.
    match result {
        Ok(Ok(outcome)) => tracing::debug!(
            "pre_batch_prompt: dry-run completed with {} finding(s) (ignored — placeholder host)",
            outcome.findings.len()
        ),
        Ok(Err(e)) => tracing::warn!("pre_batch_prompt: config dry-run errored (prompts may be incomplete): {e:#}"),
        Err(elapsed) => tracing::warn!("pre_batch_prompt: config dry-run timed out (prompts may be incomplete): {elapsed}"),
    }

    crate::mprintln!();
    Ok(())
}

/// Print a one-time advisory before a full-internet sweep (`random` /
/// `0.0.0.0` / `0.0.0.0/0`, random or sequential) showing the knobs an operator
/// usually wants to set, then — on an interactive console only — ask for an
/// explicit confirmation. Returns `false` when the operator declines (the
/// caller aborts the sweep). API/MCP and piped/scripted runs are never prompted
/// (they proceed), mirroring how the per-target deadline is gated.
///
/// `cap` is the host ceiling for this sweep: `Some(n)` (random, or sequential
/// with `max_random_hosts` set) or `None` (an unbounded sequential sweep).
async fn full_sweep_advisory_and_confirm(
    module: &Arc<dyn Module>,
    limits: &SchedulerLimits,
    cap: Option<usize>,
    sweep_label: &str,
) -> Result<bool> {
    // Effective service port for the per-host precheck. `limits.precheck_port`
    // is already resolved to `setg port` if set, else the module's own
    // `default_port` (see run_with_limits_shared) — exactly the "default to the
    // module's port" behaviour. Surface where it came from so a stale global
    // `setg port` that differs from the module default is visible.
    let module_default = module.info().default_port;
    let global_port = match crate::tenant::resolve().global_options().try_get("port") {
        Some(v) => match v.trim().parse::<u16>() {
            Ok(p) => Some(p),
            Err(e) => {
                // Surface, don't swallow: a bad `setg port` would otherwise be
                // silently ignored and the operator would never know why the
                // precheck used a different port.
                crate::meprintln!(
                    "[!] Ignoring invalid `setg port` value '{}': {e}",
                    v.trim()
                );
                None
            }
        },
        None => None,
    };
    let port_line = match (limits.precheck_port, global_port, module_default) {
        (Some(p), Some(_), Some(d)) if p != d => {
            format!("{p}  (from `setg port`; this module's default is {d})")
        }
        (Some(p), Some(_), _) => format!("{p}  (from `setg port`)"),
        (Some(p), None, _) => format!("{p}  (module default)"),
        (None, _, _) => {
            "none — this module declares no default port, so every host is probed".to_string()
        }
    };
    let host_cap = match cap {
        Some(n) => format!("{n} hosts"),
        None => "unbounded (entire public IPv4 space)".to_string(),
    };
    let excl = crate::exclusions::shared().networks().len();

    crate::mprintln!(
        "{}",
        format!(
            "[!] {sweep_label}: '{}' will probe public hosts across the whole Internet.",
            module.info().name
        )
        .yellow()
        .bold()
    );
    crate::mprintln!("{}", "    Settings for this sweep (override with `setg <key> <value>`):".yellow());
    crate::mprintln!("      {:<17}{}", "port:", port_line);
    crate::mprintln!("      {:<17}{}   {}", "concurrency:", limits.concurrency, "(setg concurrency <n>)".dimmed());
    crate::mprintln!("      {:<17}{}   {}", "host cap:", host_cap, "(setg max_random_hosts <n>)".dimmed());
    crate::mprintln!("      {:<17}{}s   {}", "per-host timeout:", limits.timeout_secs, "(setg timeout <n>)".dimmed());
    crate::mprintln!(
        "      {:<17}{} networks excluded (RFC1918/bogons/...)   {}",
        "exclusions:",
        excl,
        "(setg exclusions ...)".dimmed()
    );

    // Only a human at an interactive console is asked to confirm. API/MCP runs
    // (api_mode) and piped/scripted CLI runs (stdin not a TTY) proceed — they
    // opted in by passing the target and there is no keyboard to answer.
    let cfg = crate::config::get_module_config();
    let interactive_console = !cfg.api_mode && std::io::stdin().is_terminal();
    if !interactive_console {
        return Ok(true);
    }
    let proceed = crate::utils::prompt_yes_no("Proceed with the full-internet sweep?", false).await?;
    if !proceed {
        crate::mprintln!("{}", "[*] Full-internet sweep aborted by operator.".yellow());
    }
    Ok(proceed)
}

// ============================================================
// HELPERS
// ============================================================

/// Wait for every task currently in the per-fanout `JoinSet` to finish.
/// We can't use `Semaphore::acquire_many(concurrency)` for this barrier
/// when the semaphore is shared (a sibling sub-target via `fanout_multi`
/// might still hold permits). The `JoinSet` tracks *this* fanout's spawns
/// only.
async fn drain_joinset(joinset: &mut tokio::task::JoinSet<()>) {
    while let Some(res) = joinset.join_next().await {
        if let Err(e) = res
            && !e.is_cancelled() {
                tracing::debug!("spawned task panicked: {e:#}");
            }
    }
}

/// Open (or resume) a crash-recovery checkpoint for a fan-out invocation.
/// On resume, prints how many targets were already processed. On failure,
/// logs and returns `None` so the scan continues without resume support.
async fn open_checkpoint(
    module_path: &str,
    target_label: &str,
) -> Option<Arc<crate::checkpoint::CheckpointWriter>> {
    let scan_id = crate::checkpoint::auto_scan_id(module_path, target_label);
    match crate::checkpoint::CheckpointWriter::open(&scan_id, module_path, target_label) {
        Ok(cp) => {
            let prior = cp.count().await;
            if prior > 0 {
                crate::mprintln!(
                    "{}",
                    format!(
                        "[*] Resuming checkpoint '{}' — {} targets already processed, will skip.",
                        scan_id, prior
                    )
                    .green()
                );
            }
            Some(Arc::new(cp))
        }
        Err(e) => {
            crate::meprintln!(
                "[!] Could not open checkpoint: {}. Continuing without resume.",
                e
            );
            None
        }
    }
}

/// Record a target as processed, swallowing only at debug-trace level so
/// scans don't terminate on transient disk errors.
async fn record_checkpoint(
    cp: &Option<Arc<crate::checkpoint::CheckpointWriter>>,
    target: &str,
) {
    if let Some(cp) = cp.as_ref()
        && let Err(e) = cp.record(target).await {
            tracing::debug!(target = %target, "checkpoint record failed: {e:#}");
        }
}

/// Final flush + delete-on-success. The checkpoint file is preserved on
/// cancellation/abort so the next run resumes; cleanly-finished scans
/// remove the file.
async fn finalize_checkpoint(
    cp: &Option<Arc<crate::checkpoint::CheckpointWriter>>,
    completed_cleanly: bool,
) {
    let Some(cp) = cp.as_ref() else { return };
    if let Err(e) = cp.flush().await {
        crate::meprintln!("[!] Checkpoint flush failed: {e:#}");
    }
    if completed_cleanly
        && let Err(e) = cp.finish().await {
            crate::meprintln!("[!] Checkpoint finalize failed: {e:#}");
        }
}

fn finalize(label: &str, stats: &ScanStats, total: usize, completed_cleanly: bool) -> ModuleOutcome {
    let s = stats.snapshot();
    // Publish the final per-target breakdown to the job's scan counters (if this
    // run is a backgrounded job that scoped them) so `jobs`/get_detail reports
    // real total/succeeded/failed instead of always-zero.
    if let Some(c) = crate::context::scan_counters() {
        c.total.store(total as u64, Ordering::Relaxed);
        c.succeeded.store(s.success as u64, Ordering::Relaxed);
        c.failed.store(s.failed as u64, Ordering::Relaxed);
    }
    crate::mprintln!("\n{}", format!("=== {} Summary ===", label).cyan().bold());
    crate::mprintln!("  Hosts examined:  {} / {}", s.considered, total);
    crate::mprintln!(
        "  Module ran on:   {}  ({} ok, {} errored)",
        s.processed, s.success, s.failed
    );
    if s.skipped > 0 {
        crate::mprintln!(
            "  {}",
            format!(
                "Skipped:         {}  (no service port / honeypot / already done)",
                s.skipped
            )
            .yellow()
        );
    }
    // The headline number the operator actually cares about: did the scan
    // find anything? `success`/`ok` only means a host did not error — it is
    // not a hit. Surface findings explicitly so a scan that ran cleanly but
    // found nothing reads as "0 findings", not "N successful".
    let findings: Vec<Finding> = stats.findings.lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .cloned()
        .collect();
    if s.hits > 0 {
        crate::mprintln!(
            "  {}",
            format!("Findings:        {}  (saved to loot / workspace)", s.hits)
                .green()
                .bold()
        );
        // List what was actually found, not just the count. Under a mass scan
        // the per-host hit lines scroll away behind progress output, so the
        // operator otherwise sees "Findings: N" with no idea *what* — e.g.
        // which proxies/hosts. Cap the list so a huge sweep cannot flood the
        // terminal; the full set is still persisted to loot / workspace.
        const MAX_LISTED: usize = 100;
        for f in findings.iter().take(MAX_LISTED) {
            crate::mprintln!("    {}", format!("[+] {}", f.message).green());
        }
        if findings.len() > MAX_LISTED {
            crate::mprintln!(
                "    {}",
                format!(
                    "… and {} more (see loot / workspace)",
                    findings.len() - MAX_LISTED
                )
                .dimmed()
            );
        }
    } else {
        crate::mprintln!(
            "  {}",
            "Findings:        0  (nothing found)".yellow()
        );
    }
    // A scan that was cancelled (Ctrl-C) or auto-aborted stopped before
    // examining every host, so its result is NOT a clean success even if no
    // host errored — surfacing it as `success: true` would make an interrupted
    // run indistinguishable from a complete one.
    ModuleOutcome {
        success: completed_cleanly && s.failed == 0,
        findings,
    }
}

/// Auto-route findings into LootStore / Workspace / events bus.
async fn route_findings(outcome: &ModuleOutcome, module: &dyn Module) {
    let module_name = module.info().name;
    for f in &outcome.findings {
        let kind_str = match f.kind {
            FindingKind::Vulnerable => "vulnerable",
            FindingKind::Credential => "credential",
            FindingKind::OpenPort => "open_port",
            FindingKind::Banner => "banner",
            FindingKind::Note => "note",
        };
        match f.kind {
            FindingKind::Credential => {
                let payload = f
                    .data
                    .as_ref()
                    .and_then(|v| serde_json::to_vec(v).ok())
                    .unwrap_or_else(|| f.message.as_bytes().to_vec());
                if crate::loot::store_loot(
                    &f.target,
                    "credential",
                    &f.message,
                    &payload,
                    &module_name,
                )
                .await
                .is_none() {
                    eprintln!("[!] Failed to store loot for {}", f.target);
                }
            }
            FindingKind::Vulnerable => {
                // `add_note` no-ops (silently) for a host that was never
                // tracked, so register it first — otherwise a vuln found on a
                // freshly-seen host (or a non-IP target like a BLE MAC) would
                // be dropped on the floor.
                crate::workspace::track_host(&f.target, None, None).await;
                crate::workspace::add_note(
                    &f.target,
                    &format!("[{}] {}", module_name, f.message),
                )
                .await;
            }
            FindingKind::OpenPort | FindingKind::Banner | FindingKind::Note => {
                crate::workspace::track_host(&f.target, None, None).await;
                if !f.message.is_empty() {
                    crate::workspace::add_note(
                        &f.target,
                        &format!("[{}] {}", module_name, f.message),
                    )
                    .await;
                }
            }
        }
        crate::events::emit(crate::events::ModuleEvent::Finding {
            module: module_name.clone(),
            target: f.target.clone(),
            kind: kind_str.to_string(),
            message: f.message.clone(),
        });
    }
}

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
    success: AtomicUsize,
    failed: AtomicUsize,
    skipped: AtomicUsize,
    processed: AtomicUsize,
    abort: AtomicBool,
    findings: std::sync::Mutex<Vec<Finding>>,
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

    fn snapshot(&self) -> (usize, usize, usize, usize) {
        (
            self.processed.load(Ordering::Relaxed),
            self.success.load(Ordering::Relaxed),
            self.failed.load(Ordering::Relaxed),
            self.skipped.load(Ordering::Relaxed),
        )
    }
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
        l
    };

    // Mass-scan fan-out is universal: every module gets fanned out per host
    // for Cidr/Multi/File/Random, sees `Target::Single` inside `run()`.
    let outcome = match target.clone() {
        Target::Single(_) => fanout_single(FanoutParams { module: module.clone(), target, options, cancel, tenant_id: tenant_id.clone(), limits, module_path: module_path.clone() }, verbose).await,
        Target::Cidr(_) => fanout_cidr(FanoutParams { module: module.clone(), target, options, cancel, tenant_id: tenant_id.clone(), limits, module_path: module_path.clone() }, shared_sem.clone()).await,
        Target::File(_) => fanout_file(FanoutParams { module: module.clone(), target, options, cancel, tenant_id: tenant_id.clone(), limits, module_path: module_path.clone() }, shared_sem.clone()).await,
        Target::Multi(_) => fanout_multi(module.clone(), target, options, cancel, tenant_id.clone(), verbose, limits).await,
        Target::Random => fanout_random(module.clone(), options, cancel, tenant_id.clone(), limits, module_path.clone(), shared_sem.clone()).await,
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
    let outcome = tokio::time::timeout(
        Duration::from_secs(limits.timeout_secs),
        module.run(&ctx),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Module timed out after {}s: {e}", limits.timeout_secs))??;
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
        _ => unreachable!("fanout_cidr called with non-Cidr target"),
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
            * limits.timeout_secs as u128;
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

    let batch_guard = crate::context::enter_batch_mode();
    let stats = Arc::new(ScanStats::default());
    // When the parent (e.g. `fanout_multi`) supplies a shared semaphore,
    // use it so cross-target runs share one concurrency budget; otherwise
    // create a fresh one sized to the configured concurrency.
    let sem = shared_sem
        .unwrap_or_else(|| Arc::new(Semaphore::new(limits.concurrency)));
    let prompt_cache = crate::context::new_prompt_cache();

    let progress_step: u128 = if host_count > 10_000_000 { 10_000 }
        else if host_count > 100_000 { 1_000 }
        else if host_count > 1_000 { 100 }
        else { 50 };

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

    for ip in ip_iter {
        if cancel.is_cancelled() || stats.abort.load(Ordering::Relaxed) {
            break;
        }
        let ip_str = ip.to_string();
        // Skip already-processed targets when resuming.
        if let Some(cp) = &checkpoint
            && cp.already_processed(&ip_str).await {
                stats.skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        let permit = sem.clone().acquire_owned().await.context("Semaphore closed")?;
        let module_clone = module.clone();
        let opts = options.clone();
        let cache = prompt_cache.clone();
        let cancel_clone = cancel.clone();
        let tenant = tenant_id.clone();
        let stats_clone = stats.clone();
        let mp = module_path.clone();
        let cp_clone = checkpoint.clone();

        joinset.spawn(async move {
            let _permit = permit;
            let ip_str = ip.to_string();
            if limits.honeypot_detection
                && crate::utils::network::quick_honeypot_check(&ip_str).await
            {
                stats_clone.skipped.fetch_add(1, Ordering::Relaxed);
                record_checkpoint(&cp_clone, &ip_str).await;
                return;
            }
            let processed = stats_clone.processed.fetch_add(1, Ordering::Relaxed) as u128 + 1;
            if processed.is_multiple_of(progress_step) || processed == 1 {
                let (_, ok, err, _) = stats_clone.snapshot();
                crate::mprintln!(
                    "[*] Progress: {}/{} hosts ({:.1}%) | {} ok | {} err",
                    processed,
                    effective_count,
                    (processed as f64 / effective_count as f64) * 100.0,
                    ok,
                    err
                );
            }
            let mut ctx = ModuleCtx::new(Target::Single(ip_str.clone()));
            ctx.options = opts;
            ctx.cancel = cancel_clone;
            ctx.tenant_id = tenant;
            ctx.batch_mode = true;
            ctx.prompt_cache = Some(cache);
            ctx.module_path = mp;
            let outcome = tokio::time::timeout(
                Duration::from_secs(limits.timeout_secs),
                module_clone.run(&ctx),
            )
            .await
            .map_err(|e| anyhow::anyhow!("timed out: {e}"))
            .and_then(|r| r);
            stats_clone.record(outcome);
            record_checkpoint(&cp_clone, &ip_str).await;
        });
    }

    drain_joinset(&mut joinset).await;
    let completed_cleanly = !cancel.is_cancelled() && !stats.abort.load(Ordering::Relaxed);
    finalize_checkpoint(&checkpoint, completed_cleanly).await;
    let outcome = finalize(&format!("Subnet Scan ({})", network), &stats, effective_count as usize);
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
        _ => unreachable!("fanout_file called with non-File target"),
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

    let batch_guard = crate::context::enter_batch_mode();
    let stats = Arc::new(ScanStats::default());
    let sem = shared_sem
        .unwrap_or_else(|| Arc::new(Semaphore::new(limits.concurrency)));
    let prompt_cache = crate::context::new_prompt_cache();
    // Checkpoint key includes the file path so different host lists
    // checkpoint independently.
    let checkpoint = open_checkpoint(&module_path, &path.to_string_lossy()).await;
    let mut joinset = tokio::task::JoinSet::<()>::new();

    for host in targets {
        if cancel.is_cancelled() {
            break;
        }
        if let Some(cp) = checkpoint.as_ref()
            && cp.already_processed(&host).await {
                stats.skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        let permit = sem.clone().acquire_owned().await.context("Semaphore closed")?;
        let module_clone = module.clone();
        let opts = options.clone();
        let cache = prompt_cache.clone();
        let cancel_clone = cancel.clone();
        let tenant = tenant_id.clone();
        let stats_clone = stats.clone();
        let mp = module_path.clone();
        let cp_clone = checkpoint.clone();

        joinset.spawn(async move {
            let _permit = permit;
            if limits.honeypot_detection
                && crate::utils::network::quick_honeypot_check(&host).await
            {
                stats_clone.skipped.fetch_add(1, Ordering::Relaxed);
                record_checkpoint(&cp_clone, &host).await;
                return;
            }
            let processed = stats_clone.processed.fetch_add(1, Ordering::Relaxed) + 1;
            if processed % 50 == 0 || processed == 1 {
                crate::mprintln!("[*] Progress: {}/{} hosts processed...", processed, count);
            }
            let mut ctx = ModuleCtx::new(Target::Single(host.clone()));
            ctx.options = opts;
            ctx.cancel = cancel_clone;
            ctx.tenant_id = tenant;
            ctx.batch_mode = true;
            ctx.prompt_cache = Some(cache);
            ctx.module_path = mp;
            let outcome = tokio::time::timeout(
                Duration::from_secs(limits.timeout_secs),
                module_clone.run(&ctx),
            )
            .await
            .map_err(|e| anyhow::anyhow!("timed out: {e}"))
            .and_then(|r| r);
            stats_clone.record(outcome);
            record_checkpoint(&cp_clone, &host).await;
        });
    }

    drain_joinset(&mut joinset).await;
    let completed_cleanly = !cancel.is_cancelled();
    finalize_checkpoint(&checkpoint, completed_cleanly).await;
    let outcome = finalize("File Target Scan", &stats, count);
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
        _ => unreachable!("fanout_multi called with non-Multi target"),
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
            "[*] Will scan up to {} random hosts with concurrency {}",
            limits.max_random_hosts, limits.concurrency
        )
        .cyan()
    );

    let mut seen = std::collections::HashSet::<std::net::IpAddr>::new();
    for _ in 0..limits.max_random_hosts {
        if cancel.is_cancelled() || stats.abort.load(Ordering::Relaxed) {
            break;
        }
        let ip = crate::utils::generate_random_public_ip(&exclusions);
        if !seen.insert(ip) {
            continue;
        }
        let ip_str = ip.to_string();
        if let Some(cp) = checkpoint.as_ref()
            && cp.already_processed(&ip_str).await {
                stats.skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        let permit = sem.clone().acquire_owned().await.context("Semaphore closed")?;
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
            let _permit = permit;
            if !crate::utils::network::mass_scan_precheck(ip, port, honeypot).await {
                stats_clone.skipped.fetch_add(1, Ordering::Relaxed);
                record_checkpoint(&cp_clone, &ip.to_string()).await;
                return;
            }
            let processed = stats_clone.processed.fetch_add(1, Ordering::Relaxed) + 1;
            if processed % 50 == 0 || processed == 1 {
                let (_, ok, err, sk) = stats_clone.snapshot();
                crate::mprintln!(
                    "[*] Progress: {} processed | {} ok | {} err | {} skipped",
                    processed, ok, err, sk
                );
            }
            let mut ctx = ModuleCtx::new(Target::Single(ip.to_string()));
            ctx.options = opts;
            ctx.cancel = cancel_clone;
            ctx.tenant_id = tenant;
            ctx.batch_mode = true;
            ctx.prompt_cache = Some(cache);
            ctx.module_path = mp;
            let outcome = tokio::time::timeout(
                Duration::from_secs(limits.timeout_secs),
                module_clone.run(&ctx),
            )
            .await
            .map_err(|e| anyhow::anyhow!("timed out: {e}"))
            .and_then(|r| r);
            let was_err = stats_clone.record(outcome);
            record_checkpoint(&cp_clone, &ip.to_string()).await;
            if was_err {
                let n = module_err_clone.fetch_add(1, Ordering::Relaxed) + 1;
                let ok_so_far = stats_clone.success.load(Ordering::Relaxed);
                if n >= 10
                    && ok_so_far == 0
                    && !stats_clone.abort.swap(true, Ordering::Relaxed)
                {
                    crate::meprintln!(
                        "{}",
                        "[!] First 10 module dispatches all errored with no successes — aborting random mass scan."
                            .red()
                            .bold()
                    );
                }
            }
        });
    }

    drain_joinset(&mut joinset).await;
    let completed_cleanly = !cancel.is_cancelled() && !stats.abort.load(Ordering::Relaxed);
    finalize_checkpoint(&checkpoint, completed_cleanly).await;
    let outcome = finalize(
        "Random Mass Scan",
        &stats,
        stats.processed.load(Ordering::Relaxed),
    );
    route_findings(&outcome, module.as_ref()).await;
    drop(batch_guard);
    Ok(outcome)
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

fn finalize(label: &str, stats: &ScanStats, total: usize) -> ModuleOutcome {
    let (_, ok, err, sk) = stats.snapshot();
    crate::mprintln!("\n{}", format!("=== {} Summary ===", label).cyan().bold());
    crate::mprintln!("  Total:      {}", total);
    crate::mprintln!("  {}", format!("Successful: {}", ok).green());
    crate::mprintln!("  {}", format!("Failed:     {}", err).red());
    if sk > 0 {
        crate::mprintln!("  {}", format!("Skipped:    {}", sk).yellow());
    }
    let findings = stats.findings.lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .cloned()
        .collect();
    ModuleOutcome {
        success: err == 0,
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

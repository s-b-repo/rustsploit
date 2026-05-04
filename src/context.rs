// src/context.rs
//
// Per-run execution context using tokio task-locals.
// Provides per-task ModuleConfig, target, and output accumulator
// for concurrent API runs.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::ModuleConfig;
use crate::output::OutputAccumulator;

const MAX_PROMPT_CACHE_ENTRIES: usize = 256;

/// Shared prompt cache for mass scan / CIDR / file target modes.
/// The first concurrent task to need a prompt key acquires the lock,
/// prompts the user interactively, and caches the result. All subsequent tasks
/// find the cached answer and skip the prompt entirely.
pub type PromptCache = Arc<tokio::sync::Mutex<HashMap<String, String>>>;

/// Create a new empty prompt cache.
pub fn new_prompt_cache() -> PromptCache {
    Arc::new(tokio::sync::Mutex::new(HashMap::new()))
}

/// Try to insert into a prompt cache, respecting the size cap.
/// Returns false if the cache is full (entry not inserted).
pub fn cache_insert(map: &mut HashMap<String, String>, key: String, value: String) -> bool {
    if map.len() >= MAX_PROMPT_CACHE_ENTRIES && !map.contains_key(&key) {
        return false;
    }
    map.insert(key, value);
    true
}

// ============================================================
// GLOBAL BATCH MODE — fallback for when task-locals don't propagate
// ============================================================

/// Refcount of active batch guards. Batch mode is active when > 0.
static BATCH_REFCOUNT: AtomicUsize = AtomicUsize::new(0);
static BATCH_CACHE: std::sync::LazyLock<PromptCache> = std::sync::LazyLock::new(new_prompt_cache);

static BATCH_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static CACHE_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// RAII guard that decrements the batch refcount on drop, even on early
/// `?` returns or panics. Use `enter_batch_mode()` to obtain one.
pub struct BatchGuard(());

impl Drop for BatchGuard {
    fn drop(&mut self) {
        BATCH_REFCOUNT.fetch_sub(1, Ordering::Release);
    }
}

/// Activate global batch mode. Returns a guard that automatically
/// deactivates it when dropped (including on `?` early returns).
/// Nested/concurrent calls are safe — batch stays active until all guards drop.
/// The cache is cleared lazily on first access in each new batch generation,
/// so this function is lock-free and safe to call from async code.
pub fn enter_batch_mode() -> BatchGuard {
    let prev = BATCH_REFCOUNT.fetch_add(1, Ordering::AcqRel);
    if prev == 0 {
        BATCH_GEN.fetch_add(1, Ordering::Release);
    }
    BatchGuard(())
}

pub fn is_batch_active() -> bool {
    BATCH_REFCOUNT.load(Ordering::Acquire) > 0
}

pub fn batch_cache() -> &'static PromptCache {
    &BATCH_CACHE
}

pub fn batch_generation() -> u64 {
    BATCH_GEN.load(Ordering::Acquire)
}

pub(crate) fn cache_generation() -> u64 {
    CACHE_GEN.load(Ordering::Acquire)
}

pub(crate) fn set_cache_generation(generation: u64) {
    CACHE_GEN.store(generation, Ordering::Release);
}

tokio::task_local! {
    /// Task-local run context. Set by the API/CLI dispatcher before invoking a module.
    /// Modules don't need to reference this directly — the `cfg_prompt_*` functions
    /// check it automatically.
    pub static RUN_CONTEXT: Arc<RunContext>;
}

/// Per-run context carrying module config, target, and structured output accumulator.
pub struct RunContext {
    /// Module configuration for this run (prompts, api_mode, etc.)
    pub config: ModuleConfig,
    /// Per-request target override (API mode). Shell mode leaves this None.
    pub target: Option<String>,
    /// Accumulated structured findings from this module run.
    pub output: OutputAccumulator,
    /// Shared prompt cache for concurrent dispatch modes.
    /// When set, `cfg_prompt_*` functions check this cache before prompting stdin.
    pub prompt_cache: Option<PromptCache>,
    /// Cooperative cancellation signal for this run. `Job::kill` triggers
    /// `.cancel()` on this token; modules can check `crate::context::is_cancelled()`
    /// in their loops to terminate gracefully. Default is an unfired token, so
    /// modules that don't check it behave exactly as before.
    pub cancel: tokio_util::sync::CancellationToken,
    /// Tenant identity for multi-tenant isolation. Set from the PQ session's
    /// `client_name` in API mode; `None` in shell mode (falls back to "local").
    pub tenant_id: Option<String>,
}

impl RunContext {
    /// Create a new run context with config and target.
    pub fn with_target(config: ModuleConfig, target: String) -> Self {
        Self {
            config,
            target: Some(target),
            output: OutputAccumulator::new(),
            prompt_cache: None,
            cancel: tokio_util::sync::CancellationToken::new(),
            tenant_id: None,
        }
    }

    /// Create a run context with a shared prompt cache (for mass scan / CIDR modes).
    /// All concurrent tasks share the same cache so prompts are answered only once.
    pub fn with_prompt_cache(config: ModuleConfig, cache: PromptCache, target: String) -> Self {
        Self {
            config,
            target: Some(target),
            output: OutputAccumulator::new(),
            prompt_cache: Some(cache),
            cancel: tokio_util::sync::CancellationToken::new(),
            tenant_id: None,
        }
    }

    /// Attach an externally-managed cancellation token (e.g. one owned by
    /// `JobManager` so `kill` can trigger it).
    pub fn with_cancellation(mut self, token: tokio_util::sync::CancellationToken) -> Self {
        self.cancel = token;
        self
    }

}

// ============================================================
// COOPERATIVE CANCELLATION HELPERS
// ============================================================

/// Returns `true` if the current run has been cancelled.
///
/// Module loops that want to be interruptible should call this each iteration:
///
/// ```ignore
/// for target in targets {
///     if crate::context::is_cancelled() { break; }
///     ...
/// }
/// ```
///
/// Returns `false` if called outside of a `RUN_CONTEXT` scope (e.g. in tests
/// or top-level CLI code), so it's always safe to call.
#[allow(dead_code)] // public helper, called from modules that opt in
pub fn is_cancelled() -> bool {
    RUN_CONTEXT.try_with(|ctx| ctx.cancel.is_cancelled()).unwrap_or(false)
}

/// Returns a clone of the current run's cancellation token, suitable for
/// passing to `tokio::select!` or `child.cancelled().await`.
///
/// Returns `None` if called outside of a `RUN_CONTEXT` scope.
#[allow(dead_code)] // public helper, called from modules that opt in
pub fn cancellation_token() -> Option<tokio_util::sync::CancellationToken> {
    RUN_CONTEXT.try_with(|ctx| ctx.cancel.clone()).ok()
}

/// Returns the tenant_id for the current run, or `None` if not in a
/// tenant-scoped context (shell mode / no RunContext).
pub fn current_tenant_id() -> Option<String> {
    RUN_CONTEXT.try_with(|ctx| ctx.tenant_id.clone()).ok().flatten()
}

// ============================================================
// HELPER: Run a future within a RunContext scope
// ============================================================

/// Execute an async closure inside a task-local `RUN_CONTEXT` with a target.
/// Returns the closure's result plus the `RunContext`.
/// Automatically inherits the tenant identity from `CURRENT_TENANT` if set.
pub async fn run_with_context_target<F, Fut, T>(config: crate::config::ModuleConfig, target: String, f: F) -> (T, std::sync::Arc<RunContext>)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let mut rc = RunContext::with_target(config, target);
    if let Ok(tid) = crate::tenant::CURRENT_TENANT.try_with(|t| t.clone()) {
        rc.tenant_id = Some(tid);
    }
    let ctx = std::sync::Arc::new(rc);
    let ctx_clone = ctx.clone();
    let result = RUN_CONTEXT.scope(ctx_clone, f()).await;
    (result, ctx)
}

/// Same as `run_with_context_target`, but threads an externally-managed
/// `CancellationToken` into the `RunContext`. Used by the job manager so that
/// `Job::kill` can signal cooperative cancellation to module code via
/// `crate::context::is_cancelled()`.
pub async fn run_with_context_target_and_cancel<F, Fut, T>(
    config: crate::config::ModuleConfig,
    target: String,
    cancel: tokio_util::sync::CancellationToken,
    f: F,
) -> (T, std::sync::Arc<RunContext>)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let mut rc = RunContext::with_target(config, target).with_cancellation(cancel);
    if let Ok(tid) = crate::tenant::CURRENT_TENANT.try_with(|t| t.clone()) {
        rc.tenant_id = Some(tid);
    }
    let ctx = std::sync::Arc::new(rc);
    let ctx_clone = ctx.clone();
    let result = RUN_CONTEXT.scope(ctx_clone, f()).await;
    (result, ctx)
}

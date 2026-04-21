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
}

impl RunContext {
    /// Create a new run context with config and target.
    pub fn with_target(config: ModuleConfig, target: String) -> Self {
        Self {
            config,
            target: Some(target),
            output: OutputAccumulator::new(),
            prompt_cache: None,
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
        }
    }
}

// ============================================================
// HELPER: Run a future within a RunContext scope
// ============================================================

/// Execute an async closure inside a task-local `RUN_CONTEXT` with a target.
/// Returns the closure's result plus the `RunContext`.
pub async fn run_with_context_target<F, Fut, T>(config: crate::config::ModuleConfig, target: String, f: F) -> (T, std::sync::Arc<RunContext>)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let ctx = std::sync::Arc::new(RunContext::with_target(config, target));
    let ctx_clone = ctx.clone();
    let result = RUN_CONTEXT.scope(ctx_clone, f()).await;
    (result, ctx)
}

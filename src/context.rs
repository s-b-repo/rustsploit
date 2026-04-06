// src/context.rs
//
// Per-run execution context using tokio task-locals.
// Provides per-task ModuleConfig, target, and output accumulator
// for concurrent API runs.

use std::sync::Arc;

use crate::config::ModuleConfig;
use crate::output::OutputAccumulator;

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
}

impl RunContext {
    /// Create a new run context with config and target.
    pub fn with_target(config: ModuleConfig, target: String) -> Self {
        Self {
            config,
            target: Some(target),
            output: OutputAccumulator::new(),
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

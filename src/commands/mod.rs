// src/commands/mod.rs
//
// Thin command dispatcher on top of the unified `crate::scheduler` engine
// and the `crate::module` inventory registry. All target expansion (CIDR,
// file, multi, random), concurrency control, prompt-cache propagation,
// honeypot detection, and finding routing happens inside the scheduler —
// this file is responsible only for resolving the user-supplied module
// name and routing to the scheduler.

use anyhow::Result;
use std::sync::Arc;

use crate::cli::Cli;
use crate::config;
use crate::module::{self, Module, ModuleOptions, Target};
use crate::scheduler;

// ============================================================
// CLI ENTRY POINTS
// ============================================================

/// CLI subcommand dispatcher (`exploit`, `scanner`, `creds`, ...).
pub async fn handle_command(command: &str, cli_args: &Cli) -> Result<()> {
    crate::utils::verbose_log(cli_args.verbose, "Handling CLI command...");

    let raw = if let Some(t) = cli_args.target.clone() {
        t
    } else if config::GLOBAL_CONFIG.has_target() {
        match config::GLOBAL_CONFIG.get_target() {
            Some(t) => {
                crate::mprintln!("[*] Using global target: {}", t);
                t
            }
            None => return Err(anyhow::anyhow!("No target specified and global target not set")),
        }
    } else {
        return Err(anyhow::anyhow!(
            "No target specified. Use --target <ip> or --set-target <ip/subnet>"
        ));
    };

    let module = cli_args.module.clone().unwrap_or_default();
    let stripped = match command {
        "exploit" => module.trim_start_matches("exploits/").to_string(),
        "scanner" => module.trim_start_matches("scanners/").to_string(),
        "creds" => module.trim_start_matches("creds/").to_string(),
        "plugins" => module.trim_start_matches("plugins/").to_string(),
        "osint" => module.trim_start_matches("osint/").to_string(),
        _ => module,
    };
    if stripped.is_empty() {
        return Err(anyhow::anyhow!("No module specified"));
    }
    run_module(&stripped, &raw, cli_args.verbose).await
}

/// Resolve the user-supplied module path/short-name and run it through the
/// unified scheduler. Replaces the legacy `dispatch_with_cidr` /
/// `dispatch_single_target` machinery.
pub async fn run_module(module_path: &str, raw_target: &str, verbose: bool) -> Result<()> {
    tracing::info!(module = %module_path, target = %raw_target, "Starting module execution");
    crate::utils::verbose_log(
        verbose,
        &format!(
            "Attempting to run module '{}' against '{}'",
            module_path, raw_target
        ),
    );

    let module_box = match module::find(module_path) {
        Some(m) => m,
        None => {
            use colored::Colorize;
            crate::meprintln!("{}", format!("Unknown module '{}'.", module_path).red());
            let all = discover_modules_cached();
            let best = all
                .iter()
                .map(|m| (m, strsim::levenshtein(module_path, m)))
                .min_by_key(|&(_, d)| d);
            if let Some((suggestion, dist)) = best
                && dist < 5 {
                    crate::meprintln!(
                        "{}",
                        format!("  Did you mean: {}?", suggestion).yellow()
                    );
                }
            return Err(anyhow::anyhow!("Module not found"));
        }
    };

    let target_str = if raw_target.is_empty() {
        if config::GLOBAL_CONFIG.has_target() {
            match config::GLOBAL_CONFIG.get_target() {
                Some(t) => {
                    crate::mprintln!("[*] Using global target: {}", t);
                    t
                }
                None => return Err(anyhow::anyhow!("No global target set")),
            }
        } else {
            return Err(anyhow::anyhow!("No target specified."));
        }
    } else {
        raw_target.to_string()
    };

    let target = Target::parse(&target_str)?;
    let resolved_path = resolve_full_path(module_path).unwrap_or_else(|| module_path.to_string());

    crate::events::emit(crate::events::ModuleEvent::ModuleStarted {
        module: resolved_path.clone(),
        target: target_str.clone(),
    });

    let module: Arc<dyn Module> = module_box.into();
    let mut opts = ModuleOptions::default();
    // Populate ModuleOptions from global options so native modules can read
    // them via ctx.options (e.g. port, source_port, threads, etc.).
    let global_opts = crate::global_options::GLOBAL_OPTIONS.all().await;
    for (k, v) in &global_opts {
        opts.set(k.clone(), v.clone());
    }
    let result = scheduler::run(module, target, opts, verbose).await;

    crate::events::emit(crate::events::ModuleEvent::ModuleFinished {
        module: resolved_path,
        target: target_str,
        success: result.is_ok(),
    });

    result.map(|_| ())
}

// ============================================================
// PUBLIC API SURFACE (consumed by shell, ws, mcp, jobs, api, utils)
// ============================================================

/// Process-wide cached list of `category/name` paths for every registered
/// module. Sorted, deterministic.
pub fn discover_modules_cached() -> &'static Vec<String> {
    static CACHE: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    CACHE.get_or_init(module::all_paths)
}

pub fn discover_modules() -> Vec<String> {
    discover_modules_cached().clone()
}

/// Number of registered plugin-category modules (zero unless someone wires
/// in dynamic plugins through the inventory registry).
pub fn plugin_count() -> usize {
    module::registered()
        .filter(|e| e.category == module::Category::Plugins)
        .count()
}

/// Static category list, derived from the `Category` enum.
pub fn categories() -> &'static [&'static str] {
    &["scanners", "exploits", "creds", "osint", "plugins"]
}

/// True if the module advertises a `check()` function.
pub fn has_check(module_path: &str) -> bool {
    module::find(module_path).map(|m| m.has_check()).unwrap_or(false)
}

pub fn module_info(module_path: &str) -> Option<crate::module_info::ModuleInfo> {
    module::find(module_path).map(|m| m.info())
}

/// Run a non-destructive vulnerability check if the module supports it.
pub async fn check_module(
    module_path: &str,
    target: &str,
) -> Option<crate::module_info::CheckResult> {
    let m = module::find(module_path)?;
    let target_parsed = match Target::parse(target) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("check_module: invalid target '{}': {}", target, e);
            return None;
        }
    };
    // Reject mass targets for check
    if !matches!(&target_parsed, Target::Single(_)) {
        tracing::warn!("check_module: mass targets not supported for check, use a single host");
        return None;
    }
    let mut ctx = crate::module::ModuleCtx::new(target_parsed);
    ctx.module_path = module_path.to_string();
    ctx.tenant_id = crate::context::current_tenant_id();
    if let Some(tok) = crate::context::cancellation_token() {
        ctx.cancel = tok;
    }
    m.check(&ctx).await
}

// ============================================================
// HELPERS
// ============================================================

/// Find the canonical `category/name` form of a module if the user supplied
/// just the short name. Returns `None` for an unknown module.
fn resolve_full_path(module_path: &str) -> Option<String> {
    if module_path.contains('/') {
        // Already qualified; verify it exists.
        return module::registered()
            .find(|e| format!("{}/{}", e.category.as_str(), e.name) == module_path)
            .map(|e| format!("{}/{}", e.category.as_str(), e.name));
    }
    module::registered()
        .find(|e| e.name == module_path)
        .map(|e| format!("{}/{}", e.category.as_str(), e.name))
}

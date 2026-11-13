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
            None => {
                return Err(anyhow::anyhow!(
                    "No target specified and global target not set"
                ));
            }
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
            if let Some(suggestion) = suggest_module(module_path) {
                crate::meprintln!("{}", format!("  Did you mean: {}?", suggestion).yellow());
            }
            return Err(anyhow::anyhow!("Module not found"));
        }
    };

    let target_kind = module_box.capabilities().target_kind;
    let target_str = if raw_target.is_empty() {
        if !target_kind.is_network() {
            // A radio module (local Bluetooth radio) and a local-state module
            // do NOT inherit the global target: that IP belongs to the last
            // network module the operator ran and is meaningless for a
            // module that never opens a socket.
            String::new()
        } else if config::GLOBAL_CONFIG.has_target() {
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

    // An empty target is the "no target" state of a radio / local-state
    // module: it works on whatever is in range (or on local state). Every
    // other module needs a host, so an empty target is an error there.
    let target = if target_str.is_empty() {
        Target::Single(String::new())
    } else {
        Target::parse(&target_str)?
    };
    let resolved_path = resolve_full_path(module_path).unwrap_or_else(|| module_path.to_string());

    crate::events::emit(crate::events::ModuleEvent::ModuleStarted {
        module: resolved_path.clone(),
        target: target_str.clone(),
    });

    let module: Arc<dyn Module> = module_box.into();
    let mut opts = ModuleOptions::default();
    // Populate ModuleOptions from the *tenant-scoped* options so native modules
    // reading ctx.options (port, source_port, threads, etc.) see the requesting
    // tenant's values — not the process-global singleton, which would leak a
    // shell/MCP operator's `setg` values into other tenants' runs.
    // `resolve()` falls back to the global store when there is no tenant (CLI).
    let scoped_opts = crate::tenant::resolve().global_options().all().await;
    for (k, v) in &scoped_opts {
        if k.starts_with("__") {
            continue;
        }
        opts.set(k.clone(), v.clone());
    }
    // Auto-save: append all of this run's console output to
    // `~/.rustsploit/loot/<module> <time> results.txt`. Scoped to interactive
    // console / CLI runs (sequential, so a single global sink is race-free);
    // API / MCP runs return their captured output to the caller instead.
    let autosave = !crate::config::get_module_config().api_mode;
    if autosave {
        crate::results_sink::begin(&resolved_path);
    }

    // Pass the canonical path through so rate-limit buckets, loot
    // attribution, and checkpoints key off `category/name` instead of a
    // best-effort reverse lookup by display name (which mis-attributes when
    // two modules share an info().name).
    let result = scheduler::run(module, target, opts, verbose, &resolved_path).await;

    if autosave {
        crate::results_sink::end();
    }

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
    &["scanners", "exploits", "creds", "osint", "plugins", "post"]
}

pub fn module_info(module_path: &str) -> Option<crate::module_info::ModuleInfo> {
    module::find(module_path).map(|m| m.info())
}

// ============================================================
// HELPERS
// ============================================================

/// Find the canonical `category/name` form of a module from whatever the
/// operator typed.
///
/// Accepts, in order of preference:
///   - `category/name`      exact
///   - `name/with/path`     exact entry name, any category
///   - `name`               exact entry name
///   - `leaf`               the final segment of the entry name
///   - `category/leaf`      the final segment, restricted to one category
///
/// This mirrors `module::find`'s resolution so that `use` and `info` agree:
/// `info ssh_bruteforce` already worked, `use ssh_bruteforce` did not.
///
/// Returns `None` for an unknown module.
pub fn resolve_full_path(module_path: &str) -> Option<String> {
    let path = module_path.trim();
    if path.is_empty() {
        return None;
    }
    let canonical = |e: &module::ModuleEntry| format!("{}/{}", e.category.as_str(), e.name);

    // 1. Exact `category/name`.
    if let Some(e) = module::registered().find(|e| canonical(e) == path) {
        return Some(canonical(e));
    }
    // 2. Exact entry name, any category (`generic/ssh_bruteforce`).
    if let Some(e) = module::registered().find(|e| e.name == path) {
        return Some(canonical(e));
    }
    // 3. Leaf match — the final segment of the entry name (`ssh_bruteforce`).
    //    First match wins so the result is deterministic.
    if let Some(e) =
        module::registered().find(|e| e.name.rsplit('/').next().unwrap_or(e.name) == path)
    {
        return Some(canonical(e));
    }
    // 4. `category/leaf` — leaf match restricted to one category.
    if let Some((cat, leaf)) = path.split_once('/')
        && let Some(category) = module::Category::parse(cat)
        && let Some(e) = module::registered()
            .find(|e| e.category == category && e.name.rsplit('/').next().unwrap_or(e.name) == leaf)
    {
        return Some(canonical(e));
    }
    None
}

/// Suggest the module path closest to `input`.
///
/// Prefers a suffix match (`ssh` -> `creds/generic/ssh_bruteforce`) because
/// that is what an operator typing a fragment almost always means, and falls
/// back to a Levenshtein distance over the full path set.
///
/// Returns `None` when nothing is close enough to be worth suggesting.
pub fn suggest_module(input: &str) -> Option<String> {
    let needle = input.trim();
    if needle.is_empty() {
        return None;
    }
    let all = discover_modules_cached();
    if all.is_empty() {
        return None;
    }

    // Suffix match: the input is the tail of a path, or the leaf of an
    // entry name. Cheap, and far more likely to be right than an edit
    // distance.
    let lower = needle.to_ascii_lowercase();
    let mut suffix_matches: Vec<&String> = all
        .iter()
        .filter(|m| {
            let m_lower = m.to_ascii_lowercase();
            m_lower.ends_with(&lower) || m_lower.contains(&format!("/{lower}"))
        })
        .collect();
    suffix_matches.sort();
    if let Some(first) = suffix_matches.first() {
        return Some((*first).clone());
    }

    // Fall back to the closest edit distance. The threshold scales with the
    // length of the input so a short typo still matches.
    let threshold = if needle.len() <= 4 { 2 } else { 5 };
    let best = all
        .iter()
        .map(|m| (m, strsim::levenshtein(needle, m)))
        .min_by_key(|&(_, d)| d);
    match best {
        Some((suggestion, dist)) if dist < threshold => Some(suggestion.clone()),
        _ => None,
    }
}

pub mod creds;
pub mod exploit;
pub mod osint;
pub mod plugins;
pub mod scanner;

// Auto-generated registry of all module categories (from build.rs)
mod registry {
    include!(concat!(env!("OUT_DIR"), "/module_registry.rs"));
}

use anyhow::{Result, Context};
use crate::cli::Cli;
use crate::config;
use crate::utils::normalize_target;
use crate::utils::{
    is_subnet_target, parse_subnet, subnet_host_count,
    is_mass_scan_target, generate_random_public_ip, parse_exclusions, EXCLUDED_RANGES,
};

/// CLI dispatcher
pub async fn handle_command(command: &str, cli_args: &Cli) -> Result<()> {
    crate::utils::verbose_log(cli_args.verbose, "Handling CLI command...");

    let raw = if let Some(ref t) = cli_args.target {
        t.clone()
    } else if config::GLOBAL_CONFIG.has_target() {
        match config::GLOBAL_CONFIG.get_target() {
            Some(t) => {
                crate::mprintln!("[*] Using global target: {}", t);
                t
            }
            None => return Err(anyhow::anyhow!("No target specified and global target not set")),
        }
    } else {
        return Err(anyhow::anyhow!("No target specified. Use --target <ip> or --set-target <ip/subnet>"));
    };

    // Skip normalization for mass scan targets (random, 0.0.0.0, file paths)
    let target = if is_mass_scan_target(&raw) {
        raw.clone()
    } else {
        normalize_target(&raw)?
    };
    crate::utils::verbose_log(cli_args.verbose, &format!("Normalized target: {}", target));

    let module = match cli_args.module.clone() {
        Some(m) => m,
        None => String::new(),
    };

    // Resolve the module name by trimming category prefix
    let (category, module_name) = match command {
        "exploit" => ("exploits", module.trim_start_matches("exploits/").to_string()),
        "scanner" => ("scanners", module.trim_start_matches("scanners/").to_string()),
        "creds" => ("creds", module.trim_start_matches("creds/").to_string()),
        "plugins" => ("plugins", module.trim_start_matches("plugins/").to_string()),
        other => (other, module.clone()),
    };

    // CIDR auto-expansion: iterate over every IP in the subnet concurrently
    dispatch_with_cidr(category, &module_name, &target).await?;

    Ok(())
}

/// Interactive module runner
pub async fn run_module(module_path: &str, raw_target: &str, verbose: bool) -> Result<()> {
    tracing::info!(module = %module_path, target = %raw_target, "Starting module execution");
    crate::utils::verbose_log(verbose, &format!("Attempting to run module '{}' against '{}'", module_path, raw_target));

    // 1. Resolve module using compile-time list. The cached HashMap covers
    // both full ("category/name") and short ("name") forms in O(1), avoiding
    // the previous two linear scans.
    let available = discover_modules_cached();
    let index = module_index();
    let resolved: &str = match index.get(module_path) {
        Some(&i) => {
            let m = &available[i];
            // Distinguish exact-vs-short for the verbose log to preserve the
            // prior diagnostic output.
            if m == module_path {
                crate::utils::verbose_log(verbose, &format!("Exact module match found: {}", m));
            } else {
                crate::utils::verbose_log(verbose, &format!("Short module match found: {}", m));
            }
            m.as_str()
        }
        None => {
            use colored::*;
            crate::meprintln!("{}", format!("Unknown module '{}'.", module_path).red());
            // Did-you-mean: still O(n) but only on the miss path.
            let best_match = available.iter()
                .map(|m| (m, strsim::levenshtein(module_path, m)))
                .min_by_key(|&(_, dist)| dist);
            if let Some((suggestion, dist)) = best_match {
                if dist < 5 {
                    crate::meprintln!("{}", format!("  Did you mean: {}?", suggestion).yellow());
                }
            }
            return Err(anyhow::anyhow!("Module not found"));
        }
    };

    // 2. Resolve target
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

    // Skip normalization for mass scan targets (random, 0.0.0.0, file paths)
    let target = if is_mass_scan_target(&target_str) {
        target_str.clone()
    } else {
        normalize_target(&target_str)?
    };
    crate::utils::verbose_log(verbose, &format!("Target resolved to: {}", target));

    let mut parts = resolved.splitn(2, '/');
    let category = parts.next().unwrap_or("");
    let module_name = parts.next().unwrap_or("");

    // Emit a ModuleStarted event so /pq/ws subscribers (panels, MCP tools)
    // see lifecycle transitions without per-module instrumentation. Modules
    // that want to publish richer findings still call `events::emit(...)`
    // themselves.
    let resolved_owned = resolved.to_string();
    let target_owned = target.clone();
    crate::events::emit(crate::events::ModuleEvent::ModuleStarted {
        module: resolved_owned.clone(),
        target: target_owned.clone(),
    });

    let result = dispatch_with_cidr(category, module_name, &target).await;

    crate::events::emit(crate::events::ModuleEvent::ModuleFinished {
        module: resolved_owned,
        target: target_owned,
        success: result.is_ok(),
    });

    result
}

/// Dispatch a module against a target, with automatic CIDR subnet expansion
/// and comma-separated multi-target support.
///
/// Handles:
/// - Single IP/hostname: dispatches directly
/// - CIDR subnet: iterates over every IP concurrently
/// - Comma-separated list: dispatches each entry (with subnet expansion for CIDRs)
async fn dispatch_with_cidr(category: &str, module_name: &str, target: &str) -> Result<()> {
    use colored::Colorize;

    // Comma-separated multi-target: split and dispatch each
    if target.contains(',') {
        let targets: Vec<&str> = target.split(',').map(|t| t.trim()).filter(|t| !t.is_empty()).collect();
        let count = targets.len();
        crate::mprintln!("{}", format!(
            "[*] Multi-target detected: {} targets — running '{}/{}' against each",
            count, category, module_name
        ).cyan());

        for (i, t) in targets.iter().enumerate() {
            crate::mprintln!("\n{}", format!(
                "[*] === Target {}/{}: {} ===", i + 1, count, t
            ).cyan().bold());
            if let Err(e) = dispatch_single_target(category, module_name, t).await {
                crate::meprintln!("{}", format!("[!] Target '{}' failed: {:?}", t, e).red());
            }
        }

        crate::mprintln!("\n{}", format!(
            "[*] Multi-target scan complete: {} targets processed", count
        ).green().bold());
        return Ok(());
    }

    dispatch_single_target(category, module_name, target).await
}

/// Dispatch a single target (IP/hostname, CIDR subnet, file, or random mass scan).
///
/// This is the unified framework-level dispatcher that ensures every module
/// supports all target types: single IP, CIDR, file-based target lists, and
/// random internet scanning — even if the module has no built-in mass scan handler.
async fn dispatch_single_target(category: &str, module_name: &str, target: &str) -> Result<()> {
    use colored::Colorize;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    let is_random = target == "random" || target == "0.0.0.0" || target == "0.0.0.0/0";
    let is_file = !is_random && !is_subnet_target(target) && std::path::Path::new(target).is_file();

    // --- Check if honeypot detection is enabled (global option, default: on) ---
    // Users can disable with: setg honeypot_detection n
    // API users can disable with: prompts: { "honeypot_detection": "n" }
    let honeypot_enabled = {
        let config = crate::config::get_module_config();
        if let Some(val) = config.custom_prompts.get("honeypot_detection") {
            !matches!(val.to_lowercase().as_str(), "n" | "no" | "false" | "0" | "off" | "disabled")
        } else if let Some(val) = crate::tenant::resolve().global_options().try_get("honeypot_detection") {
            !matches!(val.to_lowercase().as_str(), "n" | "no" | "false" | "0" | "off" | "disabled")
        } else {
            true // enabled by default
        }
    };

    // --- Random / Internet-wide mass scan (target == "random" or "0.0.0.0") ---
    // If the module's run() handles mass-scan targets itself (detected at build
    // time by source-grepping for `is_mass_scan_target` / `run_mass_scan` /
    // `MassScanConfig {`), call it ONCE with the original target so it can
    // pick its own concurrency, banner, prompt cache, etc. Otherwise fall
    // through to the framework's per-IP loop below.
    if is_random && registry::mass_scan_capable_by_category(category, module_name) {
        crate::mprintln!("{}", format!(
            "[*] Module '{}/{}' has a native mass-scan handler — running it directly.",
            category, module_name
        ).cyan());
        return registry::dispatch_by_category(category, module_name, target).await;
    }

    // Framework-managed loop: generates random public IPs, does a TCP port
    // pre-check (if port is known via setg), enters batch mode so interactive
    // prompts are asked once and cached for all subsequent hosts.
    if is_random {
        let batch_guard = crate::context::enter_batch_mode();
        crate::mprintln!("{}", format!(
            "[*] Random mass scan — running '{}/{}' against random public IPs (Ctrl+C to stop)",
            category, module_name
        ).cyan().bold());

        let concurrency: usize = crate::tenant::resolve().global_options()
            .try_get("concurrency")
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);
        let max_hosts: usize = crate::tenant::resolve().global_options()
            .try_get("max_random_hosts")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10_000);
        let module_timeout_secs: u64 = crate::tenant::resolve().global_options()
            .try_get("module_timeout")
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        let precheck_port: Option<u16> = crate::tenant::resolve().global_options()
            .try_get("port")
            .and_then(|v| v.parse().ok());

        crate::mprintln!("{}", format!(
            "[*] Will scan up to {} random hosts with concurrency {} (setg max_random_hosts / concurrency to change){}",
            max_hosts, concurrency,
            if let Some(p) = precheck_port { format!(" | port pre-check: {}", p) } else { String::new() }
        ).cyan());

        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let success_count = Arc::new(AtomicUsize::new(0));
        let fail_count = Arc::new(AtomicUsize::new(0));
        let checked = Arc::new(AtomicUsize::new(0));
        let exclusions = Arc::new(parse_exclusions(EXCLUDED_RANGES));
        // First module error captured during the scan. Without this the user
        // sees thousands of "err" tally rows but no clue why everything failed
        // — for example `ping_sweep` requires root and would otherwise silently
        // bail on every dispatch with only `tracing::debug!` output.
        let first_error: Arc<std::sync::OnceLock<String>> = Arc::new(std::sync::OnceLock::new());
        let early_abort = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // Counts ONLY actual module-dispatch errors (Ok(Err) or timeout).
        // Distinct from fail_count, which also includes precheck rejections
        // (honeypots / closed ports). Used as the abort signal so a sea of
        // legitimately-skipped hosts doesn't trip the early-bail.
        let module_err_count = Arc::new(AtomicUsize::new(0));

        let category = category.to_string();
        let module_name = module_name.to_string();

        let prompt_cache = crate::context::new_prompt_cache();
        let parent_config = crate::config::get_module_config();
        let mut seen = std::collections::HashSet::<std::net::IpAddr>::new();

        for _ in 0..max_hosts {
            if early_abort.load(Ordering::Relaxed) {
                break;
            }
            let ip = generate_random_public_ip(&exclusions);
            if !seen.insert(ip) {
                continue;
            }
            let ip_str = ip.to_string();

            let permit = semaphore.clone().acquire_owned().await
                .context("Semaphore closed")?;
            let sc = success_count.clone();
            let fc = fail_count.clone();
            let tc = checked.clone();
            let cat = category.clone();
            let mname = module_name.clone();
            let pc = prompt_cache.clone();
            let cfg = parent_config.clone();
            let first_err = first_error.clone();
            let abort_flag = early_abort.clone();
            let merr = module_err_count.clone();

            tokio::spawn(async move {
                // Combined port pre-check + honeypot detection via native network lib
                if !crate::utils::network::mass_scan_precheck(ip, precheck_port, honeypot_enabled).await {
                    fc.fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                    return;
                }

                let idx = tc.fetch_add(1, Ordering::Relaxed) + 1;
                if idx % 50 == 0 || idx == 1 {
                    crate::mprintln!("[*] Progress: {} hosts scanned | {} ok | {} err",
                        idx,
                        sc.load(Ordering::Relaxed),
                        fc.load(Ordering::Relaxed));
                }
                let ctx = std::sync::Arc::new(crate::context::RunContext::with_prompt_cache(
                    cfg, pc, ip_str.clone(),
                ));
                let dispatch_result = crate::context::RUN_CONTEXT.scope(ctx, async {
                    tokio::time::timeout(
                        std::time::Duration::from_secs(module_timeout_secs),
                        registry::dispatch_by_category(&cat, &mname, &ip_str),
                    ).await
                }).await;
                match dispatch_result {
                    Ok(Ok(_)) => { sc.fetch_add(1, Ordering::Relaxed); }
                    Ok(Err(e)) => {
                        let msg = format!("{e:#}");
                        tracing::debug!("Mass scan {} failed: {}", ip_str, msg);
                        // Surface the first error so the user can diagnose
                        // misconfigurations (e.g. ping_sweep needing root).
                        if first_err.set(msg.clone()).is_ok() {
                            crate::mprintln!(
                                "{}",
                                format!("[!] First module error (suppressing duplicates): {msg}").yellow()
                            );
                        }
                        fc.fetch_add(1, Ordering::Relaxed);
                        let merrs = merr.fetch_add(1, Ordering::Relaxed) + 1;
                        // Bail when the first 10 actual module dispatches all
                        // error and none succeed — that's a fatal misconfig,
                        // not a "no live hosts" outcome.
                        if merrs >= 10 && sc.load(Ordering::Relaxed) == 0 {
                            if !abort_flag.swap(true, Ordering::Relaxed) {
                                crate::meprintln!(
                                    "{}",
                                    format!(
                                        "[!] First {merrs} module dispatches all errored with no successes — aborting mass scan. \
                                         Underlying error: {msg}"
                                    ).red().bold()
                                );
                            }
                        }
                    }
                    Err(_) => {
                        fc.fetch_add(1, Ordering::Relaxed);
                        merr.fetch_add(1, Ordering::Relaxed);
                    }
                }
                drop(permit);
            });
        }

        if let Err(e) = semaphore.acquire_many(concurrency as u32).await {
            crate::meprintln!("[!] Drain barrier failed: {}", e);
        }

        drop(batch_guard);
        print_scan_summary("Random Mass Scan",
            checked.load(Ordering::Relaxed),
            success_count.load(Ordering::Relaxed),
            fail_count.load(Ordering::Relaxed));
        return Ok(());
    }

    // --- File-based target list ---
    if is_file {
        let batch_guard = crate::context::enter_batch_mode();
        let content = crate::utils::safe_read_to_string_async(target, None).await
            .with_context(|| format!("Failed to read target file '{}'", target))?;
        let targets: Vec<String> = content.lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .collect();

        let count = targets.len();
        crate::mprintln!("{}", format!(
            "[*] File target list: {} hosts from '{}' — running '{}/{}'",
            count, target, category, module_name
        ).cyan().bold());

        let concurrency: usize = crate::tenant::resolve().global_options()
            .try_get("concurrency")
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);
        let module_timeout_secs: u64 = crate::tenant::resolve().global_options()
            .try_get("module_timeout")
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let success_count = Arc::new(AtomicUsize::new(0));
        let fail_count = Arc::new(AtomicUsize::new(0));
        let total = Arc::new(AtomicUsize::new(0));

        let category = category.to_string();
        let module_name = module_name.to_string();

        // Shared prompt cache: all concurrent tasks share one set of prompt answers
        let prompt_cache = crate::context::new_prompt_cache();
        let parent_config = crate::config::get_module_config();

        for ip_str in targets {
            let permit = semaphore.clone().acquire_owned().await
                .context("Semaphore closed")?;
            let sc = success_count.clone();
            let fc = fail_count.clone();
            let tc = total.clone();
            let cat = category.clone();
            let mname = module_name.clone();
            let pc = prompt_cache.clone();
            let cfg = parent_config.clone();

            tokio::spawn(async move {
                // Quick honeypot check before running module
                if honeypot_enabled && crate::utils::network::quick_honeypot_check(&ip_str).await {
                    crate::meprintln!("[!] Skipping {} — honeypot detected", ip_str);
                    fc.fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                    return;
                }

                let idx = tc.fetch_add(1, Ordering::Relaxed) + 1;
                if idx % 50 == 0 || idx == 1 {
                    crate::mprintln!("[*] Progress: {}/{} hosts processed...", idx, count);
                }
                let ctx = std::sync::Arc::new(crate::context::RunContext::with_prompt_cache(
                    cfg, pc, ip_str.clone(),
                ));
                let dispatch_result = crate::context::RUN_CONTEXT.scope(ctx, async {
                    tokio::time::timeout(
                        std::time::Duration::from_secs(module_timeout_secs),
                        registry::dispatch_by_category(&cat, &mname, &ip_str),
                    ).await
                }).await;
                match dispatch_result {
                    Ok(Ok(_)) => { sc.fetch_add(1, Ordering::Relaxed); }
                    Ok(Err(e)) => {
                        crate::meprintln!("[!] {} failed: {:?}", ip_str, e);
                        fc.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        fc.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!("File target {} timed out after {}s", ip_str, module_timeout_secs);
                    }
                }
            });
        }

        // Drain barrier: wait until all in-flight tasks release their permits.
        if let Err(e) = semaphore.acquire_many(concurrency as u32).await {
            crate::meprintln!("[!] Drain barrier failed (semaphore closed): {}", e);
        }

        drop(batch_guard);
        print_scan_summary("File Target Scan",
            total.load(Ordering::Relaxed),
            success_count.load(Ordering::Relaxed),
            fail_count.load(Ordering::Relaxed));
        return Ok(());
    }

    // --- CIDR subnet expansion — handles ANY size subnet via lazy iteration ---
    if is_subnet_target(target) {
        let network = parse_subnet(target)?;
        let host_count = subnet_host_count(&network);

        // /32 or /128 — single host, dispatch directly without subnet machinery
        if host_count <= 1 {
            let ip_str = network.network().to_string();
            crate::mprintln!("{}", format!(
                "[*] Single-host subnet {} — dispatching as {}", target, ip_str
            ).cyan());
            registry::dispatch_by_category(category, module_name, &ip_str).await?;
            return Ok(());
        }

        // Safety gate: warn about very large CIDR ranges and give time
        // estimates. The actual execution is properly streaming (lazy
        // iteration + semaphore-gated spawning), so memory stays bounded
        // regardless of range size. The risk is wall-clock time, not OOM.
        //
        // IPv6 ranges wider than /96 (4 billion+ hosts) are rejected
        // outright — even at 1000 hosts/sec that's 136 years.
        const WARN_THRESHOLD: u128 = 65_536; // warn above /16 IPv4
        const IPV6_MAX_HOSTS: u128 = 1 << 32; // /96 = 4 billion

        if network.is_ipv6() && host_count > IPV6_MAX_HOSTS {
            return Err(anyhow::anyhow!(
                "IPv6 subnet {} expands to {} hosts — that range is too wide to iterate. \
                 Use /96 or narrower, or supply specific targets in a file.",
                network, host_count
            ));
        }

        if host_count > WARN_THRESHOLD {
            let concurrency_est: u128 = crate::tenant::resolve().global_options()
                .try_get("concurrency")
                .and_then(|v| v.parse().ok())
                .unwrap_or(50);
            let timeout_est: u128 = crate::tenant::resolve().global_options()
                .try_get("module_timeout")
                .and_then(|v| v.parse().ok())
                .unwrap_or(60);
            let est_secs = (host_count / concurrency_est.max(1)) * timeout_est;
            let est_display = if est_secs > 86400 {
                format!("{:.1} days", est_secs as f64 / 86400.0)
            } else if est_secs > 3600 {
                format!("{:.1} hours", est_secs as f64 / 3600.0)
            } else {
                format!("{} minutes", est_secs / 60)
            };

            crate::mprintln!("{}", format!(
                "[!] Large scan: {} expands to {} hosts (worst-case ~{} at concurrency {})",
                network, host_count, est_display, concurrency_est
            ).yellow().bold());

            let config = crate::config::get_module_config();
            if !config.api_mode && !crate::utils::is_batch_mode() {
                let confirmed = crate::utils::prompt_yes_no(
                    &format!("Proceed with scanning all {} hosts?", host_count),
                    false,
                ).await?;

                if !confirmed {
                    return Err(anyhow::anyhow!(
                        "CIDR scan of {} ({} hosts) aborted by user.",
                        network, host_count
                    ));
                }
            }
        }

        let batch_guard = crate::context::enter_batch_mode();

        // Concurrency from global options, default 50
        let concurrency: usize = crate::tenant::resolve().global_options()
            .try_get("concurrency")
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);
        let module_timeout_secs: u64 = crate::tenant::resolve().global_options()
            .try_get("module_timeout")
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        crate::mprintln!("{}", format!(
            "[*] Subnet: {} ({} hosts) — running '{}/{}' with concurrency {}",
            network, host_count, category, module_name, concurrency
        ).cyan());

        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let success_count = Arc::new(AtomicUsize::new(0));
        let fail_count = Arc::new(AtomicUsize::new(0));
        let total = Arc::new(AtomicUsize::new(0));

        let category = category.to_string();
        let module_name = module_name.to_string();

        // Shared prompt cache: all concurrent tasks share one set of prompt answers
        let prompt_cache = crate::context::new_prompt_cache();
        let parent_config = crate::config::get_module_config();

        // Adaptive progress interval: every 50 for small, 1000 for medium, 10000 for huge
        let progress_interval = if host_count > 10_000_000 {
            10_000
        } else if host_count > 100_000 {
            1_000
        } else if host_count > 1_000 {
            100
        } else {
            50
        };

        // Lazy iteration — never allocates all IPs in memory
        for ip in network.iter() {
            let permit = semaphore.clone().acquire_owned().await
                .context("Semaphore closed")?;
            let sc = success_count.clone();
            let fc = fail_count.clone();
            let tc = total.clone();
            let cat = category.clone();
            let mname = module_name.clone();
            let ip_str = ip.to_string();
            let pc = prompt_cache.clone();
            let cfg = parent_config.clone();

            tokio::spawn(async move {
                if honeypot_enabled && crate::utils::network::quick_honeypot_check(&ip_str).await {
                    crate::meprintln!("[!] Skipping {} — honeypot detected", ip_str);
                    fc.fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                    return;
                }

                let idx = tc.fetch_add(1, Ordering::Relaxed) + 1;
                if idx % progress_interval == 0 || idx == 1 {
                    crate::mprintln!("[*] Progress: {}/{} hosts ({:.1}%) | {} ok | {} err",
                        idx, host_count,
                        (idx as f64 / host_count as f64) * 100.0,
                        sc.load(Ordering::Relaxed),
                        fc.load(Ordering::Relaxed));
                }
                let ctx = std::sync::Arc::new(crate::context::RunContext::with_prompt_cache(
                    cfg, pc, ip_str.clone(),
                ));
                let dispatch_result = crate::context::RUN_CONTEXT.scope(ctx, async {
                    tokio::time::timeout(
                        std::time::Duration::from_secs(module_timeout_secs),
                        registry::dispatch_by_category(&cat, &mname, &ip_str),
                    ).await
                }).await;
                match dispatch_result {
                    Ok(Ok(_)) => { sc.fetch_add(1, Ordering::Relaxed); }
                    Ok(Err(e)) => {
                        crate::meprintln!("[!] {} failed: {:?}", ip_str, e);
                        fc.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        fc.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!("Subnet {} timed out after {}s", ip_str, module_timeout_secs);
                    }
                }
                drop(permit);
            });
        }

        // Drain barrier: wait until all in-flight tasks release their permits.
        if let Err(e) = semaphore.acquire_many(concurrency as u32).await {
            crate::meprintln!("[!] Drain barrier failed (semaphore closed): {}", e);
        }

        drop(batch_guard);
        print_scan_summary("Subnet Scan",
            host_count as usize,
            success_count.load(Ordering::Relaxed),
            fail_count.load(Ordering::Relaxed));
        return Ok(());
    }

    // --- Single target ---
    if honeypot_enabled && crate::utils::network::quick_honeypot_check(target).await {
        crate::mprintln!("{}", format!(
            "[!] Target {} appears to be a honeypot (11+ common ports open) — skipping",
            target
        ).red().bold());
        return Ok(());
    }
    registry::dispatch_by_category(category, module_name, target).await?;
    Ok(())
}

/// Generate a random IP address within a given network range.
/// Works for both IPv4 and IPv6 subnets of any size, including private ranges.


fn print_scan_summary(label: &str, total: usize, success: usize, failed: usize) {
    use colored::Colorize;
    crate::mprintln!("\n{}", format!("=== {} Summary ===", label).cyan().bold());
    crate::mprintln!("  Total:      {}", total);
    crate::mprintln!("  {}", format!("Successful: {}", success).green());
    crate::mprintln!("  {}", format!("Failed:     {}", failed).red());
}

/// Helper to aggregate all available modules from generated registry.
///
/// Backed by a process-wide `OnceLock` so the underlying `format!` per
/// module only runs once per process. Every dispatch + every `module_exists`
/// + every fuzzy-match call hits this path, so the cache pays for itself
/// after the first lookup. Returned `Vec` is cloned out of the cache —
/// callers that don't need ownership can use `discover_modules_cached()`.
pub fn discover_modules() -> Vec<String> {
    discover_modules_cached().clone()
}

/// Borrowed view of the cached module list. Prefer this over
/// `discover_modules()` from hot paths to avoid the `Vec` clone.
pub fn discover_modules_cached() -> &'static Vec<String> {
    static CACHE: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    CACHE.get_or_init(registry::all_modules)
}

/// Index `category/module_name` → registry slot (currently just the index in
/// `discover_modules_cached()`). Lets `module_exists` and the dispatch
/// short-name lookup do an `O(1)` hash check instead of two linear scans.
fn module_index() -> &'static std::collections::HashMap<&'static str, usize> {
    static INDEX: std::sync::OnceLock<std::collections::HashMap<&'static str, usize>> =
        std::sync::OnceLock::new();
    INDEX.get_or_init(|| {
        let modules = discover_modules_cached();
        let mut map = std::collections::HashMap::with_capacity(modules.len() * 2);
        for (i, m) in modules.iter().enumerate() {
            // SAFETY: `modules` is owned by the static `OnceLock`, so its
            // contents live for `'static`. We only ever borrow into the
            // cached `Vec`, never mutate it — promoting the slice to
            // `'static` is sound because the OnceLock can never be reset.
            let m_static: &'static str = unsafe { std::mem::transmute::<&str, &'static str>(m.as_str()) };
            map.insert(m_static, i);
            // Also index by short name (post-`/`) so dispatch can match
            // unqualified module names without a separate scan.
            if let Some((_, short)) = m_static.rsplit_once('/') {
                // First-write wins: if two categories define the same short
                // name, the earliest (alphabetically) keeps the slot — that
                // matches the prior `find` behaviour, which returned the
                // first match.
                map.entry(short).or_insert(i);
            }
        }
        map
    })
}

/// Check if any third-party plugins are loaded.
pub fn plugin_count() -> usize {
    discover_modules().iter().filter(|m| m.starts_with("plugins/")).count()
}

pub fn categories() -> &'static [&'static str] {
    registry::CATEGORIES
}

pub fn has_check(module_path: &str) -> bool {
    let mut parts = module_path.splitn(2, '/');
    let category = match parts.next() { Some(c) => c, None => return false };
    let module_name = match parts.next() { Some(m) => m, None => return false };
    registry::check_available_by_category(category, module_name)
}

pub fn module_info(module_path: &str) -> Option<crate::module_info::ModuleInfo> {
    let mut parts = module_path.splitn(2, '/');
    let category = parts.next()?;
    let module_name = parts.next()?;
    registry::info_by_category(category, module_name)
}

/// Run a non-destructive vulnerability check if the module supports it.
pub async fn check_module(module_path: &str, target: &str) -> Option<crate::module_info::CheckResult> {
    let mut parts = module_path.splitn(2, '/');
    let category = parts.next()?;
    let module_name = parts.next()?;
    registry::check_by_category(category, module_name, target).await
}

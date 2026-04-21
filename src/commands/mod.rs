pub mod creds;
pub mod exploit;
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

    // 1. Resolve module using compile-time list
    let available = discover_modules();

    // Fuzzy matching logic
    let full_match = available.iter().find(|m| m == &module_path);
    let short_match = available.iter().find(|m| {
        m.rsplit_once('/').map(|(_, short)| short == module_path).unwrap_or(false)
    });

    if let Some(m) = full_match {
        crate::utils::verbose_log(verbose, &format!("Exact module match found: {}", m));
    } else if let Some(m) = short_match {
        crate::utils::verbose_log(verbose, &format!("Short module match found: {}", m));
    }

    let resolved = if let Some(m) = full_match {
        m
    } else if let Some(m) = short_match {
        m
    } else {
        use colored::*;
        crate::meprintln!("{}", format!("Unknown module '{}'.", module_path).red());

        // Fuzzy matching
        let best_match = available.iter()
            .map(|m| (m, strsim::levenshtein(module_path, m)))
            .min_by_key(|&(_, dist)| dist);

        if let Some((suggestion, dist)) = best_match {
            if dist < 5 {
                crate::meprintln!("{}", format!("  Did you mean: {}?", suggestion).yellow());
            }
        }

        return Err(anyhow::anyhow!("Module not found"));
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

    dispatch_with_cidr(category, module_name, &target).await?;

    Ok(())
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
        } else if let Some(val) = crate::global_options::GLOBAL_OPTIONS.try_get("honeypot_detection") {
            !matches!(val.to_lowercase().as_str(), "n" | "no" | "false" | "0" | "off" | "disabled")
        } else {
            true // enabled by default
        }
    };

    // --- Random / Internet-wide mass scan (target == "random" or "0.0.0.0") ---
    // Framework manages the loop: generates random public IPs, does a TCP port
    // pre-check (if port is known via setg), enters batch mode so interactive
    // prompts are asked once and cached for all subsequent hosts.
    if is_random {
        let batch_guard = crate::context::enter_batch_mode();
        crate::mprintln!("{}", format!(
            "[*] Random mass scan — running '{}/{}' against random public IPs (Ctrl+C to stop)",
            category, module_name
        ).cyan().bold());

        let concurrency: usize = crate::global_options::GLOBAL_OPTIONS
            .try_get("concurrency")
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);
        let max_hosts: usize = crate::global_options::GLOBAL_OPTIONS
            .try_get("max_random_hosts")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10_000);
        let module_timeout_secs: u64 = crate::global_options::GLOBAL_OPTIONS
            .try_get("module_timeout")
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        let precheck_port: Option<u16> = crate::global_options::GLOBAL_OPTIONS
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

        let category = category.to_string();
        let module_name = module_name.to_string();

        let prompt_cache = crate::context::new_prompt_cache();
        let parent_config = crate::config::get_module_config();
        let mut seen = std::collections::HashSet::<std::net::IpAddr>::new();

        for _ in 0..max_hosts {
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
                        tracing::debug!("Mass scan {} failed: {:?}", ip_str, e);
                        fc.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        fc.fetch_add(1, Ordering::Relaxed);
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

        let concurrency: usize = crate::global_options::GLOBAL_OPTIONS
            .try_get("concurrency")
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);
        let module_timeout_secs: u64 = crate::global_options::GLOBAL_OPTIONS
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

        let batch_guard = crate::context::enter_batch_mode();

        // Concurrency from global options, default 50
        let concurrency: usize = crate::global_options::GLOBAL_OPTIONS
            .try_get("concurrency")
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);
        let module_timeout_secs: u64 = crate::global_options::GLOBAL_OPTIONS
            .try_get("module_timeout")
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        // Warn for very large subnets but don't block
        if host_count > 1_000_000 {
            crate::mprintln!("{}", format!(
                "[!] Large subnet: {} ({} hosts) — this will take a while. Concurrency: {}. Ctrl+C to stop.",
                network, host_count, concurrency
            ).yellow().bold());
        }

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

/// Helper to aggregate all available modules from generated registry
pub fn discover_modules() -> Vec<String> {
    registry::all_modules()
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

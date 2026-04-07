pub mod exploit;
pub mod scanner;
pub mod creds;
pub mod plugins;

// Auto-generated registry of all module categories (from build.rs)
mod registry {
    include!(concat!(env!("OUT_DIR"), "/module_registry.rs"));
}

use anyhow::{Result, Context};
use crate::cli::Cli;
use crate::config;
use crate::utils::normalize_target;
use crate::modules::creds::utils::{
    is_subnet_target, parse_subnet, subnet_host_count,
    is_mass_scan_target, generate_random_public_ip, parse_exclusions,
    is_ip_checked, mark_ip_checked, EXCLUDED_RANGES,
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
    if is_random {
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
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let success_count = Arc::new(AtomicUsize::new(0));
        let fail_count = Arc::new(AtomicUsize::new(0));
        let checked = Arc::new(AtomicUsize::new(0));
        let exclusions = Arc::new(parse_exclusions(EXCLUDED_RANGES));

        let subnet_filter: Arc<Option<ipnetwork::IpNetwork>> = Arc::new(None);

        let category = category.to_string();
        let module_name = module_name.to_string();
        let state_file = format!("{}_{}_mass_state.log", category, module_name)
            .replace('/', "_");

        crate::mprintln!("{}", format!("[*] Will scan up to {} random hosts with concurrency {} (setg max_random_hosts / concurrency to change)", max_hosts, concurrency).cyan());

        for _ in 0..max_hosts {
            let permit = semaphore.clone().acquire_owned().await
                .context("Semaphore closed")?;
            let sc = success_count.clone();
            let fc = fail_count.clone();
            let tc = checked.clone();
            let cat = category.clone();
            let mname = module_name.clone();
            let exc = exclusions.clone();
            let sf = state_file.clone();
            let subnet = subnet_filter.clone();

            tokio::spawn(async move {
                // Generate IP: random within subnet, or random public
                let ip = if let Some(ref net) = *subnet {
                    generate_random_ip_in_network(net)
                } else {
                    generate_random_public_ip(&exc)
                };
                let ip_str = ip.to_string();

                if is_ip_checked(&ip, &sf).await {
                    tc.fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                    return;
                }
                mark_ip_checked(&ip, &sf).await;

                // Quick honeypot check before running module
                if honeypot_enabled && crate::utils::network::quick_honeypot_check(&ip_str).await {
                    crate::meprintln!("[!] Skipping {} — honeypot detected", ip_str);
                    fc.fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                    return;
                }

                let idx = tc.fetch_add(1, Ordering::Relaxed) + 1;
                if idx % 100 == 0 || idx == 1 {
                    crate::mprintln!("[*] Progress: {} hosts scanned | {} ok | {} err",
                        idx,
                        sc.load(Ordering::Relaxed),
                        fc.load(Ordering::Relaxed));
                }
                match registry::dispatch_by_category(&cat, &mname, &ip_str).await {
                    Ok(_) => { sc.fetch_add(1, Ordering::Relaxed); }
                    Err(e) => {
                        fc.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!("Mass scan {} failed: {:?}", ip_str, e);
                    }
                }
                drop(permit);
            });
        }

        // Wait for all tasks: acquire all permits back
        for _ in 0..concurrency {
            let _ = semaphore.acquire().await;
        }

        let sc = success_count.load(Ordering::Relaxed);
        let fc = fail_count.load(Ordering::Relaxed);
        print_scan_summary("Mass Scan", checked.load(Ordering::Relaxed), sc, fc);
        auto_log_result(&category, &module_name, "random", sc > 0, &format!("mass_scan ok={} err={}", sc, fc));
        return Ok(());
    }

    // --- File-based target list ---
    if is_file {
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

        let concurrency = 50usize;
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let success_count = Arc::new(AtomicUsize::new(0));
        let fail_count = Arc::new(AtomicUsize::new(0));
        let total = Arc::new(AtomicUsize::new(0));

        let category = category.to_string();
        let module_name = module_name.to_string();

        for ip_str in targets {
            let permit = semaphore.clone().acquire_owned().await
                .context("Semaphore closed")?;
            let sc = success_count.clone();
            let fc = fail_count.clone();
            let tc = total.clone();
            let cat = category.clone();
            let mname = module_name.clone();

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
                match registry::dispatch_by_category(&cat, &mname, &ip_str).await {
                    Ok(_) => { sc.fetch_add(1, Ordering::Relaxed); }
                    Err(e) => {
                        crate::meprintln!("[!] {} failed: {:?}", ip_str, e);
                        fc.fetch_add(1, Ordering::Relaxed);
                    }
                }
                drop(permit);
            });
        }

        // Wait for all tasks
        for _ in 0..concurrency {
            let _ = semaphore.acquire().await;
        }

        let sc = success_count.load(Ordering::Relaxed);
        let fc = fail_count.load(Ordering::Relaxed);
        print_scan_summary("File Target Scan", total.load(Ordering::Relaxed), sc, fc);
        auto_log_result(&category, &module_name, target, sc > 0, &format!("file_scan ok={} err={}", sc, fc));
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

        // Concurrency from global options, default 50
        let concurrency: usize = crate::global_options::GLOBAL_OPTIONS
            .try_get("concurrency")
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);

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
                match registry::dispatch_by_category(&cat, &mname, &ip_str).await {
                    Ok(_) => { sc.fetch_add(1, Ordering::Relaxed); }
                    Err(e) => {
                        crate::meprintln!("[!] {} failed: {:?}", ip_str, e);
                        fc.fetch_add(1, Ordering::Relaxed);
                    }
                }
                drop(permit);
            });
        }

        // Wait for all tasks
        for _ in 0..concurrency {
            let _ = semaphore.acquire().await;
        }

        let sc = success_count.load(Ordering::Relaxed);
        let fc = fail_count.load(Ordering::Relaxed);
        print_scan_summary("Subnet Scan", host_count as usize, sc, fc);
        auto_log_result(&category, &module_name, target, sc > 0, &format!("subnet_scan ok={} err={}", sc, fc));
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
    let result = registry::dispatch_by_category(category, module_name, target).await;
    auto_log_result(category, module_name, target, result.is_ok(), "");
    result?;
    Ok(())
}

/// Generate a random IP address within a given network range.
/// Works for both IPv4 and IPv6 subnets of any size, including private ranges.
fn generate_random_ip_in_network(net: &ipnetwork::IpNetwork) -> std::net::IpAddr {
    use rand::RngExt;
    let mut rng = rand::rng();
    match net {
        ipnetwork::IpNetwork::V4(v4net) => {
            let base: u32 = v4net.network().into();
            let prefix = v4net.prefix() as u32;
            if prefix >= 32 {
                return std::net::IpAddr::V4(v4net.network());
            }
            let host_bits = 32 - prefix;
            // Mask for randomizable host portion
            let host_mask: u32 = (1u64.checked_shl(host_bits).unwrap_or(0) - 1) as u32;
            let net_mask: u32 = !host_mask;
            let random_host: u32 = rng.random::<u32>() & host_mask;
            let ip = (base & net_mask) | random_host;
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip))
        }
        ipnetwork::IpNetwork::V6(v6net) => {
            let base: u128 = v6net.network().into();
            let prefix = v6net.prefix() as u32;
            if prefix >= 128 {
                return std::net::IpAddr::V6(v6net.network());
            }
            let host_bits = 128 - prefix;
            let host_mask: u128 = if host_bits >= 128 {
                u128::MAX
            } else {
                (1u128 << host_bits) - 1
            };
            let net_mask: u128 = !host_mask;
            let random_host: u128 = (rng.random::<u128>()) & host_mask;
            let ip = (base & net_mask) | random_host;
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip))
        }
    }
}

fn print_scan_summary(label: &str, total: usize, success: usize, failed: usize) {
    use colored::Colorize;
    crate::mprintln!("\n{}", format!("=== {} Summary ===", label).cyan().bold());
    crate::mprintln!("  Total:      {}", total);
    crate::mprintln!("  {}", format!("Successful: {}", success).green());
    crate::mprintln!("  {}", format!("Failed:     {}", failed).red());
}

/// Auto-save a module execution log entry to ~/.rustsploit/results/ in append mode.
/// Called after every module dispatch so all modules (exploit, scanner, creds) get
/// persistent output regardless of whether the module itself saves to file.
fn auto_log_result(category: &str, module_name: &str, target: &str, success: bool, detail: &str) {
    // Check if auto_save_results is enabled (default: on)
    if let Some(val) = crate::global_options::GLOBAL_OPTIONS.try_get("auto_save_results") {
        if matches!(val.to_lowercase().as_str(), "n" | "no" | "false" | "0" | "off" | "disabled") {
            return;
        }
    }
    let results_dir = crate::config::results_dir();
    // Sanitize module name for filename
    let safe_name: String = module_name.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect();
    let filename = format!("{}_{}.txt", category, safe_name);
    let path = results_dir.join(&filename);
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let status = if success { "SUCCESS" } else { "COMPLETED" };
    let line = if detail.is_empty() {
        format!("[{}] {} {}/{} target={}\n", timestamp, status, category, module_name, target)
    } else {
        format!("[{}] {} {}/{} target={} {}\n", timestamp, status, category, module_name, target, detail)
    };
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        use std::io::Write;
        if let Err(e) = file.write_all(line.as_bytes()) { crate::meprintln!("[!] Write error: {}", e); }
    }
}

/// Helper to aggregate all available modules from generated registry
pub fn discover_modules() -> Vec<String> {
    registry::all_modules()
}

/// Check if any third-party plugins are loaded.
pub fn plugin_count() -> usize {
    discover_modules().iter().filter(|m| m.starts_with("plugins/")).count()
}

/// All known categories (auto-generated from src/modules/ subdirectories)
pub fn categories() -> &'static [&'static str] {
    registry::CATEGORIES
}

/// Get module info metadata if the module provides it.
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

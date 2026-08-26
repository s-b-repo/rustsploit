//! API Health Check + Module Discovery (UTILITY)
//!
//! A utility plugin module that reports framework health and module
//! discovery statistics. Useful for operations/debugging and for API
//! clients discovering the framework's module inventory.
//!
//! Reports:
//!   - Total registered module count
//!   - Module counts per category (exploits, scanners, creds, osint, plugins)
//!   - Build info and feature flags
//!   - API server reachability (if running)
//!   - Module path listing
//!
//! All stats emitted as FindingKind::Note findings for API consumption.

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use anyhow::Result;
use colored::*;

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "API Health Check + Module Discovery".to_string(),
        description: "Utility module that reports framework health statistics \
                      and module discovery information. Returns total registered \
                      module count, per-category breakdowns, build info, and API \
                      server reachability. All results emitted as Note findings \
                      for consumption by API clients and debugging. No network \
                      probes against external targets."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: ModuleRank::Good,
        default_port: None,
    }
}

/// Count modules by category.
fn count_by_category() -> Vec<(String, usize)> {
    let mut cats: Vec<(String, usize)> = vec![
        ("exploits".to_string(), 0),
        ("scanners".to_string(), 0),
        ("creds".to_string(), 0),
        ("osint".to_string(), 0),
        ("plugins".to_string(), 0),
    ];

    for entry in crate::module::registered() {
        let cat_str = entry.category.as_str();
        // find the matching category and increment count
        for (cat_name, count) in cats.iter_mut() {
            if cat_name == cat_str {
                *count += 1;
                break;
            }
        }
    }

    cats
}

/// Gather build info labels from compile-time features / env.
fn build_info() -> Vec<(String, String)> {
    let mut info: Vec<(String, String)> = Vec::new();

    // Compiler version (set by cargo, may be absent)
    let rustc_ver = option_env!("RUSTC_VERSION")
        .unwrap_or("unknown")
        .to_string();
    info.push(("rustc_version".to_string(), rustc_ver));

    // Crate version from Cargo
    let pkg_ver = option_env!("CARGO_PKG_VERSION")
        .unwrap_or("unknown")
        .to_string();
    info.push(("crate_version".to_string(), pkg_ver));

    // Target OS
    #[cfg(target_os = "linux")]
    info.push(("target_os".to_string(), "linux".to_string()));
    #[cfg(target_os = "macos")]
    info.push(("target_os".to_string(), "macos".to_string()));
    #[cfg(target_os = "windows")]
    info.push(("target_os".to_string(), "windows".to_string()));
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    info.push(("target_os".to_string(), "other".to_string()));

    // Architecture
    #[cfg(target_arch = "x86_64")]
    info.push(("target_arch".to_string(), "x86_64".to_string()));
    #[cfg(target_arch = "aarch64")]
    info.push(("target_arch".to_string(), "aarch64".to_string()));
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    info.push((
        "target_arch".to_string(),
        std::env::consts::ARCH.to_string(),
    ));

    // Profile
    #[cfg(debug_assertions)]
    info.push(("profile".to_string(), "debug".to_string()));
    #[cfg(not(debug_assertions))]
    info.push(("profile".to_string(), "release".to_string()));

    // Feature flags (only check features that exist in this crate)
    #[cfg(feature = "io_uring")]
    info.push(("io_uring".to_string(), "enabled".to_string()));
    #[cfg(not(feature = "io_uring"))]
    info.push(("io_uring".to_string(), "disabled".to_string()));

    info
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let mut outcome = ModuleOutcome::ok();

    // Prompt-only guard - return early, no work needed.
    if ctx.prompt_only {
        return Ok(outcome);
    }

    let target_str = ctx
        .target
        .as_single()
        .map(|s| s.to_string())
        .unwrap_or_else(|| ctx.target.as_legacy_str());

    crate::mprintln!(
        "{}",
        "=== RustSploit Framework Health Check ===".bold().cyan()
    );
    crate::mprintln!("{} Target context: {}", "[*]".cyan(), target_str);
    crate::mprintln!();

    // Total module count
    let total = crate::module::count();
    crate::mprintln!(
        "{} Total registered modules: {}",
        "[*]".cyan(),
        total.to_string().bold()
    );
    outcome.findings.push(Finding {
        target: target_str.clone(),
        kind: FindingKind::Note,
        message: format!("Total registered modules: {}", total),
        data: Some(serde_json::json!({
            "metric": "total_modules",
            "value": total,
        })),
    });

    // Per-category counts
    crate::mprintln!("{} Module counts by category:", "[*]".cyan());
    let cat_counts = count_by_category();
    for (cat, count) in &cat_counts {
        crate::mprintln!(
            "  {} {}: {}",
            "  -".dimmed(),
            cat,
            count.to_string().green()
        );
        outcome.findings.push(Finding {
            target: target_str.clone(),
            kind: FindingKind::Note,
            message: format!("Category '{}': {} modules", cat, count),
            data: Some(serde_json::json!({
                "metric": "category_count",
                "category": cat,
                "count": count,
            })),
        });
    }

    // Build info
    crate::mprintln!();
    crate::mprintln!("{} Build information:", "[*]".cyan());
    let bi = build_info();
    for (key, value) in &bi {
        crate::mprintln!("  {} {}: {}", "  -".dimmed(), key, value);
    }

    outcome.findings.push(Finding {
        target: target_str.clone(),
        kind: FindingKind::Note,
        message: format!("Build info: {:?}", bi),
        data: Some(serde_json::json!({
            "metric": "build_info",
            "info": bi.iter().map(|(k, v)| serde_json::json!({k: v})).collect::<Vec<_>>(),
        })),
    });

    // All module paths (first 50, for catalog)
    crate::mprintln!();
    let all_paths = crate::module::all_paths();
    crate::mprintln!(
        "{} Module paths ({} total, showing first 50):",
        "[*]".cyan(),
        all_paths.len()
    );
    let preview: Vec<&String> = all_paths.iter().take(50).collect();
    for path in &preview {
        crate::mprintln!("  {} {}", "  -".dimmed(), path);
    }
    if all_paths.len() > 50 {
        crate::mprintln!("  {} ... and {} more", "  -".dimmed(), all_paths.len() - 50);
    }

    outcome.findings.push(Finding {
        target: target_str.clone(),
        kind: FindingKind::Note,
        message: format!("Module catalog: {} total paths", all_paths.len()),
        data: Some(serde_json::json!({
            "metric": "module_catalog",
            "total_paths": all_paths.len(),
            "preview": preview,
        })),
    });

    // API server reachability (self-check)
    // Attempt to probe a local API server if an api_port option is provided
    let api_port: u16 = ctx.options.get_or("api_port", 0u16);
    if api_port > 0 {
        let api_url = format!("http://127.0.0.1:{}/api/health", api_port);
        crate::mprintln!();
        crate::mprintln!("{} Probing API server at {}...", "[*]".cyan(), api_url);

        match crate::utils::build_http_client(std::time::Duration::from_secs(5)) {
            Ok(client) => match client.get(&api_url).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 200 {
                        crate::mprintln!(
                            "{} API server reachable at {} (HTTP 200)",
                            "[+]".green(),
                            api_url
                        );
                        outcome.findings.push(Finding {
                            target: target_str.clone(),
                            kind: FindingKind::Note,
                            message: format!("API server reachable at {}", api_url),
                            data: Some(serde_json::json!({
                                "metric": "api_reachable",
                                "url": api_url,
                                "status": 200,
                            })),
                        });
                    } else {
                        crate::mprintln!(
                            "{} API server returned HTTP {} at {}",
                            "[!]".yellow(),
                            status,
                            api_url
                        );
                    }
                }
                Err(e) => {
                    crate::mprintln!(
                        "{} API server not reachable at {}: {}",
                        "[-]".red(),
                        api_url,
                        e
                    );
                }
            },
            Err(e) => {
                crate::mprintln!(
                    "{} Failed to build HTTP client for health check: {}",
                    "[!]".yellow(),
                    e
                );
            }
        }
    }

    crate::mprintln!();
    crate::mprintln!("{} Health check complete.", "[+]".green());

    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Plugins, "api_health_check", native);

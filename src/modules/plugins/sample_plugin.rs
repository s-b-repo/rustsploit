// Sample third-party plugin template.
// Copy this file as a starting point for new plugins.
//
// NOTE: "plugins" here means **compile-time module templates** — they are
// auto-discovered by `build.rs` and baked into the binary, not loaded
// dynamically at runtime. To ship a new plugin, drop a `.rs` file in this
// directory and rebuild.
//
// Requirements:
//   - Must have: `pub async fn run(target: &str) -> anyhow::Result<()>`
//   - Use `cfg_prompt_*` for all user input (enables API compatibility)
//   - Use `is_mass_scan_target` + `run_mass_scan` for mass scan support
//   - Never call `std::process::exit()` — return Err instead
//   - No `unsafe` outside of audited helpers in `src/native/` (the framework
//     itself uses `unsafe` for raw-socket FFI; plugin-level code should not
//     need it).

use anyhow::Result;
use colored::*;
use crate::utils::cfg_prompt_default;
use crate::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};

pub async fn run(target: &str) -> Result<()> {
    if is_mass_scan_target(target) {
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "Sample-Plugin",
            default_port: 80,
            state_file: "sample_plugin_mass_state.log",
            default_output: "sample_plugin_mass_results.txt",
            default_concurrency: 200,
        }, move |ip, port| {
            async move {
                // Canonical TCP connect (also honors `setg src_port`).
                let addr = format!("{}:{}", ip, port);
                match crate::utils::network::tcp_connect_str(&addr, std::time::Duration::from_secs(3)).await {
                    Ok(_) => {
                        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                        Some(format!("[{}] {}:{} open\n", ts, ip, port))
                    }
                    Err(e) => {
                        // Trace level — closed ports are the common case in
                        // mass scans, debug spam would dwarf real signal.
                        tracing::trace!(target = %addr, "sample_plugin probe failed: {}", e);
                        None
                    }
                }
            }
        }).await;
    }

    crate::mprintln!("{}", "=== Sample Plugin ===".bold().cyan());
    crate::mprintln!("[*] This is a template for third-party plugins.");
    crate::mprintln!("[*] Target: {}", target);
    let action = cfg_prompt_default("action", "Action to perform", "scan").await?;
    crate::mprintln!("[*] Action selected: {}", action);
    crate::mprintln!("{}", "[+] Plugin executed successfully.".green());
    Ok(())
}

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "Sample Plugin".to_string(),
        description: "Template plugin demonstrating the RustSploit plugin API with mass scan support and cfg_prompt integration.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

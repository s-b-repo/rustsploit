// Sample third-party plugin template.
// Copy this file as a starting point for new plugins.
//
// NOTE: "plugins" here means **compile-time module templates** — they are
// baked into the binary at build time, not loaded dynamically at runtime.
// To ship a new plugin, drop a `.rs` file in this directory, end it with
// `crate::register_native_module!(...)`, and rebuild.
//
// Requirements:
//   - Must have: `pub async fn run(ctx: &ModuleCtx) -> anyhow::Result<ModuleOutcome>`
//   - Use `cfg_prompt_*` for all user input (enables API compatibility)
//   - Mass-scan fan-out is universal — the scheduler handles CIDR/random/file
//     targets; modules only ever see a single host.
//   - Never call `std::process::exit()` — return Err instead
//   - No `unsafe` outside of audited helpers in `src/native/` (the framework
//     itself uses `unsafe` for raw-socket FFI; plugin-level code should not
//     need it).

use anyhow::{Context, Result};
use colored::*;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::utils::cfg_prompt_default;

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("sample_plugin requires a single-host target")?;

    crate::mprintln!("{}", "=== Sample Plugin ===".bold().cyan());
    crate::mprintln!("[*] This is a template for third-party plugins.");
    crate::mprintln!("[*] Target: {}", target);
    let action = cfg_prompt_default("action", "Action to perform", "scan").await?;
    crate::mprintln!("[*] Action selected: {}", action);
    crate::mprintln!("{}", "[+] Plugin executed successfully.".green());

    let mut outcome = ModuleOutcome::ok();
    outcome.findings.push(Finding {
        target: target.to_string(),
        kind: FindingKind::Note,
        message: format!("sample_plugin executed action '{}' against {}", action, target),
        data: Some(serde_json::json!({
            "action": action,
            "target": target,
        })),
    });
    Ok(outcome)
}

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "Sample Plugin".to_string(),
        description: "Template plugin demonstrating the RustSploit native plugin API — uses ModuleCtx + ModuleOutcome and emits a Note finding per invocation.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

crate::register_native_module!(crate::module::Category::Plugins, "sample_plugin", native);

pub mod exploit;
pub mod scanner;
pub mod creds;

use anyhow::Result;
use crate::cli::Cli;
use walkdir::WalkDir;

/// Handle CLI arguments like:
/// --command scanner --module scanners/port_scanner --target 192.168.1.1
pub async fn handle_command(command: &str, cli_args: &Cli) -> Result<()> {
    let target = cli_args.target.clone().unwrap_or_default();
    let module = cli_args.module.clone().unwrap_or_default();

    match command {
        "exploit" => {
            let trimmed = module.trim_start_matches("exploits/");
            exploit::run_exploit(trimmed, &target).await?;
        },
        "scanner" => {
            let trimmed = module.trim_start_matches("scanners/");
            scanner::run_scan(trimmed, &target).await?;
        },
        "creds" => {
            let trimmed = module.trim_start_matches("creds/");
            creds::run_cred_check(trimmed, &target).await?;
        },
        _ => {
            eprintln!("Unknown command '{}'", command);
        }
    }

    Ok(())
}

/// Handle `run` in the interactive shell after `use <module>`
/// Supports both full paths like "scanners/port_scanner" and short names like "port_scanner"
pub async fn run_module(module_path: &str, target: &str) -> Result<()> {
    let available = discover_modules();

    // Exact match (e.g. "scanners/port_scanner")
    let full_match = available.iter().find(|m| m == &module_path);

    // Short match (e.g. "port_scanner" from "scanners/port_scanner")
    let short_match = available.iter().find(|m| {
        m.rsplit_once('/')
            .map(|(_, short)| short == module_path)
            .unwrap_or(false)
    });

    let resolved = if let Some(m) = full_match {
        m
    } else if let Some(m) = short_match {
        m
    } else {
        eprintln!("❌ Unknown module '{}'. Available modules:", module_path);
        for module in available {
            println!("  {}", module);
        }
        return Ok(());
    };

    let mut parts = resolved.splitn(2, '/');
    let category = parts.next().unwrap_or("");
    let module_name = parts.next().unwrap_or("");

    match category {
        "exploits" => exploit::run_exploit(module_name, target).await?,
        "scanners" => scanner::run_scan(module_name, target).await?,
        "creds" => creds::run_cred_check(module_name, target).await?,
        _ => eprintln!("❌ Category '{}' is not supported.", category),
    }

    Ok(())
}

/// Walks src/modules/{exploits,scanners,creds} recursively and returns all `.rs` modules (excluding mod.rs)
pub fn discover_modules() -> Vec<String> {
    let mut modules = Vec::new();
    let categories = ["exploits", "scanners", "creds"];

    for category in categories {
        let base_path = format!("src/modules/{}", category);
        let walker = WalkDir::new(&base_path).max_depth(6);

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();

            if path.is_file()
                && path.extension().map_or(false, |e| e == "rs")
                && path.file_name().map_or(true, |n| n != "mod.rs")
            {
                if let Ok(relative) = path.strip_prefix("src/modules") {
                    let module_path = relative
                        .with_extension("") // remove .rs
                        .to_string_lossy()
                        .replace("\\", "/"); // Windows compatibility
                    modules.push(module_path);
                }
            }
        }
    }

    modules
}

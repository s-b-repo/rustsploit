pub mod exploit;
pub mod scanner;
pub mod creds;

use anyhow::Result;
use crate::cli::Cli;
use crate::config;
use crate::utils::normalize_target;

/// CLI dispatcher
pub async fn handle_command(command: &str, cli_args: &Cli) -> Result<()> {
    // Target resolution logic...
    let raw = if let Some(ref t) = cli_args.target {
        t.clone()
    } else if config::GLOBAL_CONFIG.has_target() {
        match config::GLOBAL_CONFIG.get_single_target_ip() {
            Ok(ip) => {
                println!("[*] Using global target: {}", config::GLOBAL_CONFIG.get_target().unwrap_or_default());
                ip
            }
            Err(e) => return Err(anyhow::anyhow!("No target specified and global target error: {}", e)),
        }
    } else {
        return Err(anyhow::anyhow!("No target specified. Use --target <ip> or --set-target <ip/subnet>"));
    };
    
    let target = normalize_target(&raw)?;
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
        _ => eprintln!("Unknown command '{}'", command),
    }

    Ok(())
}

/// Interactive module runner
pub async fn run_module(module_path: &str, raw_target: &str) -> Result<()> {
    // 1. Resolve module using compile-time list
    let available = discover_modules();
    
    // Fuzzy matching logic
    let full_match = available.iter().find(|m| m == &module_path);
    let short_match = available.iter().find(|m| {
        m.rsplit_once('/').map(|(_, short)| short == module_path).unwrap_or(false)
    });

    let resolved = if let Some(m) = full_match {
        m
    } else if let Some(m) = short_match {
        m
    } else {
        eprintln!("❌ Unknown module '{}'. Available modules:", module_path);
        // List modules grouped by category
        // TODO: Could use `list_all_modules` logic from utils if public, or reimplement simply here
        for m in available {
            println!("  {}", m);
        }
        return Ok(());
    };

    // 2. Resolve target
    let target_str = if raw_target.is_empty() {
        if config::GLOBAL_CONFIG.has_target() {
            match config::GLOBAL_CONFIG.get_single_target_ip() {
                Ok(ip) => {
                    println!("[*] Using global target: {}", config::GLOBAL_CONFIG.get_target().unwrap_or_default());
                    ip
                }
                Err(e) => return Err(anyhow::anyhow!("Global target error: {}", e)),
            }
        } else {
            return Err(anyhow::anyhow!("No target specified."));
        }
    } else {
        raw_target.to_string()
    };
    
    let target = normalize_target(&target_str)?;

    let mut parts = resolved.splitn(2, '/');
    let category = parts.next().unwrap_or("");
    let module_name = parts.next().unwrap_or("");

    match category {
        "exploits" => exploit::run_exploit(module_name, &target).await?,
        "scanners" => scanner::run_scan(module_name, &target).await?,
        "creds"    => creds::run_cred_check(module_name, &target).await?,
        _ => eprintln!("❌ Category '{}' is not supported.", category),
    }

    Ok(())
}

/// Helper to aggregate all available modules from generated constants
pub fn discover_modules() -> Vec<String> {
    let mut modules = Vec::new();

    // Map exploit::AVAILABLE_MODULES -> "exploits/{name}"
    modules.extend(exploit::AVAILABLE_MODULES.iter().map(|m| format!("exploits/{}", m)));
    modules.extend(scanner::AVAILABLE_MODULES.iter().map(|m| format!("scanners/{}", m)));
    modules.extend(creds::AVAILABLE_MODULES.iter().map(|m| format!("creds/{}", m)));

    modules
}

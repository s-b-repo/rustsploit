pub mod exploit;
pub mod scanner;
pub mod creds;

use anyhow::Result;
use crate::cli::Cli;
use crate::config;
use walkdir::WalkDir;
use crate::utils::normalize_target;

/// CLI dispatcher: e.g. --command scanner --target "::1" --module scanners/port_scanner
pub async fn handle_command(command: &str, cli_args: &Cli) -> Result<()> {
    // Use CLI target if provided, otherwise try global target
    let raw = if let Some(ref t) = cli_args.target {
        t.clone()
    } else if config::GLOBAL_CONFIG.has_target() {
        // Use single IP from global target (handles subnets intelligently)
        match config::GLOBAL_CONFIG.get_single_target_ip() {
            Ok(ip) => {
                println!("[*] Using global target: {}", config::GLOBAL_CONFIG.get_target().unwrap_or_default());
                ip
            }
            Err(e) => {
                return Err(anyhow::anyhow!("No target specified and global target error: {}", e));
            }
        }
    } else {
        return Err(anyhow::anyhow!("No target specified. Use --target <ip> or --set-target <ip/subnet>"));
    };
    
    let target = normalize_target(&raw)?; // IPv6 wrap only, no port
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

/// Interactive shell: handles `run` with raw target string
/// If raw_target is empty, uses global target if available
pub async fn run_module(module_path: &str, raw_target: &str) -> Result<()> {
    let available = discover_modules();

    let full_match = available.iter().find(|m| m == &module_path);
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
        for m in available {
            println!("  {}", m);
        }
        return Ok(());
    };

    // Use provided target, or fall back to global target
    let target_str = if raw_target.is_empty() {
        if config::GLOBAL_CONFIG.has_target() {
            match config::GLOBAL_CONFIG.get_single_target_ip() {
                Ok(ip) => {
                    println!("[*] Using global target: {}", config::GLOBAL_CONFIG.get_target().unwrap_or_default());
                    ip
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("No target specified and global target error: {}", e));
                }
            }
        } else {
            return Err(anyhow::anyhow!("No target specified. Use 'set target <ip/subnet>' or provide target when running module"));
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

/// Finds all .rs module paths inside `src/modules/**`, excluding mod.rs
pub fn discover_modules() -> Vec<String> {
    let mut modules = Vec::new();
    let categories = ["exploits", "scanners", "creds"];

    for category in &categories {
        let base = format!("src/modules/{}", category);
        for entry in WalkDir::new(&base).max_depth(6).into_iter().filter_map(|e| e.ok()) {
            let p = entry.path();
            if p.is_file()
                && p.extension().map_or(false, |e| e == "rs")
                && p.file_name().map_or(true, |n| n != "mod.rs")
            {
                if let Ok(rel) = p.strip_prefix("src/modules") {
                    let module_path = rel
                        .with_extension("")
                        .to_string_lossy()
                        .replace("\\", "/");
                    modules.push(module_path);
                }
            }
        }
    }

    modules
}

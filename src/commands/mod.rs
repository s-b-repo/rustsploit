pub mod exploit;
pub mod scanner;
pub mod creds;

use anyhow::Result;
use crate::cli::Cli;
use walkdir::WalkDir;

/// Handle CLI commands like: --command exploit --module creds/generic/ftp_anonymous --target x.x.x.x
pub async fn handle_command(command: &str, cli_args: &Cli) -> Result<()> {
    let target = cli_args.target.clone().unwrap_or_default();
    let module = cli_args.module.clone().unwrap_or_default();

    match command {
        "exploit" => {
            let trimmed = module.trim_start_matches("exploits/"); // normalize
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

/// Called from the interactive shell (e.g. 'use creds/generic/ftp_anonymous' + 'run')
pub async fn run_module(module_path: &str, target: &str) -> Result<()> {
    let available = discover_modules();

    if !available.contains(&module_path.to_string()) {
        eprintln!("Unknown module '{}'. Available modules:", module_path);
        for module in available {
            println!("  {}", module);
        }
        return Ok(());
    }

    // Split path like "creds/generic/ftp_anonymous" -> ("creds", "generic/ftp_anonymous")
    let mut parts = module_path.splitn(2, '/');
    let category = parts.next().unwrap_or("");
    let module_name = parts.next().unwrap_or("");

    match category {
        "exploits" => {
            exploit::run_exploit(module_name, target).await?;
        },
        "scanners" => {
            scanner::run_scan(module_name, target).await?;
        },
        "creds" => {
            creds::run_cred_check(module_name, target).await?;
        },
        _ => {
            eprintln!("Category '{}' is not supported.", category);
        }
    }

    Ok(())
}

/// Discover modules in src/modules/{exploits,scanners,creds} recursively up to 6 levels deep
pub fn discover_modules() -> Vec<String> {
    let mut modules = Vec::new();

    let categories = ["exploits", "scanners", "creds"];

    for category in categories {
        let base_path = format!("src/modules/{}", category);
        let walker = WalkDir::new(&base_path).max_depth(6);

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();

            if path.is_file() && path.extension().map(|e| e == "rs").unwrap_or(false) {
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

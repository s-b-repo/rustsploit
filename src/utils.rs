use colored::*;
use std::fs;
use std::path::Path;

/// Dynamically checks if a module path exists
pub fn module_exists(module_path: &str) -> bool {
    if let Some((category, name)) = module_path.split_once('/') {
        let path = format!("src/modules/{}/{}.rs", category, name);
        Path::new(&path).exists()
    } else {
        false
    }
}

/// Lists all available modules in exploits, scanners, and creds
pub fn list_all_modules() {
    let categories = [
        ("exploits", "Exploits"),
        ("scanners", "Scanners"),
        ("creds", "Credentials"),
    ];

    println!("{}", "Available modules:".bold().underline());

    for (folder, display_name) in categories {
        let mut modules = Vec::new();
        let dir_path = format!("src/modules/{}", folder);

        if let Ok(entries) = fs::read_dir(&dir_path) {
            for entry in entries.flatten() {
                if let Some(file_name) = entry.file_name().to_str() {
                    if file_name.ends_with(".rs") && file_name != "mod.rs" {
                        let module_name = file_name.trim_end_matches(".rs").to_string();
                        modules.push(module_name);
                    }
                }
            }
        }

        modules.sort();

        if !modules.is_empty() {
            println!("\n{}:", display_name.blue().bold());
            for module in modules {
                println!("  - {}", format!("{}/{}", folder, module).green());
            }
        }
    }
}

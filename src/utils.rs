// src/utils.rs

use colored::*;
use std::fs;
use std::io::{BufRead, BufReader, Error};
use std::path::Path;
use anyhow::{Result};

/// Maximum folder depth to traverse
const MAX_DEPTH: usize = 6;

/// Take “1.2.3.4”, “::1”, “[::1]:8080” or “hostname” and
/// always return a valid “host:port” or “[ipv6]:port” string.
pub fn normalize_target(raw: &str) -> Result<String> {
    if raw.contains("]:") || raw.starts_with('[') {
        // Already normalized, like [::1]:8080 or [2001:db8::1]
        return Ok(raw.to_string());
    }

    // Looks like an unwrapped IPv6 address if it has multiple colons
    let is_ipv6 = raw.matches(':').count() >= 2;

    if is_ipv6 {
        Ok(format!("[{}]", raw))
    } else {
        Ok(raw.to_string())
    }
}


/// Recursively list .rs files up to a certain depth (unchanged)
fn collect_module_paths(dir: &Path, depth: usize) -> Vec<String> {
    let mut modules = Vec::new();

    if depth > MAX_DEPTH || !dir.exists() {
        return modules;
    }

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();

            if path.is_dir() {
                modules.extend(collect_module_paths(&path, depth + 1));
            } else if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
                if file_name.ends_with(".rs") && file_name != "mod.rs" {
                    let relative_path = path
                        .strip_prefix("src/modules")
                        .unwrap_or(&path)
                        .with_extension("")
                        .to_string_lossy()
                        .replace('\\', "/"); // For Windows
                    modules.push(relative_path);
                }
            }
        }
    }

    modules
}

/// Dynamically checks if a module path exists at any depth (unchanged)
pub fn module_exists(module_path: &str) -> bool {
    let modules = collect_module_paths(Path::new("src/modules"), 0);
    modules.iter().any(|m| m == module_path)
}

/// Lists all available modules recursively under src/modules/ (unchanged)
pub fn list_all_modules() {
    println!("{}", "Available modules:".bold().underline());
    let modules = collect_module_paths(Path::new("src/modules"), 0);
    if modules.is_empty() {
        println!("{}", "No modules found.".red());
        return;
    }

    let mut grouped = std::collections::BTreeMap::new();

    for module in modules {
        let parts: Vec<&str> = module.split('/').collect();
        let category = parts.get(0).unwrap_or(&"Other").to_string();
        grouped
            .entry(category)
            .or_insert_with(Vec::new)
            .push(module.clone());
    }

    for (category, paths) in grouped {
        println!("\n{}:", category.blue().bold());
        for path in paths {
            println!("  - {}", path.green());
        }
    }
}

/// Finds and displays modules matching a keyword (unchanged)
pub fn find_modules(keyword: &str) {
    let keyword_lower = keyword.to_lowercase();
    let modules = collect_module_paths(Path::new("src/modules"), 0);

    let filtered: Vec<String> = modules
        .into_iter()
        .filter(|m| m.to_lowercase().contains(&keyword_lower))
        .collect();

    if filtered.is_empty() {
        println!(
            "{}",
            format!("No modules found matching '{}'.", keyword).red()
        );
        return;
    }

    println!(
        "{}",
        format!("Modules matching '{}':", keyword).bold().underline()
    );

    let mut grouped = std::collections::BTreeMap::new();
    for module in filtered {
        let parts: Vec<&str> = module.split('/').collect();
        let category = parts.get(0).unwrap_or(&"Other").to_string();
        grouped
            .entry(category)
            .or_insert_with(Vec::new)
            .push(module.clone());
    }

    for (category, paths) in grouped {
        println!("\n{}:", category.blue().bold());
        for path in paths {
            println!("  - {}", path.green());
        }
    }
}

/// Parses a single proxy line (unchanged)
fn parse_proxy_line(line: &str) -> String {
    let trimmed = line.trim().to_lowercase();
    if trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("socks4://")
        || trimmed.starts_with("socks5://")
    {
        line.to_string()
    } else {
        format!("http://{}", line)
    }
}

/// Load proxies from a file, returning normalized proxy URLs (unchanged)
pub fn load_proxies_from_file(filename: &str) -> Result<Vec<String>, Error> {
    let file = fs::File::open(filename)?;
    let reader = BufReader::new(file);

    let mut proxies = Vec::new();
    for line in reader.lines() {
        let line = line?.trim().to_string();
        if !line.is_empty() {
            proxies.push(parse_proxy_line(&line));
        }
    }

    Ok(proxies)
}

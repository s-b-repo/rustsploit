// src/utils.rs

use colored::*;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use anyhow::{Result, anyhow, Context};
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest;
use tokio::sync::Semaphore;
use url::Url;

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

const SUPPORTED_PROXY_SCHEMES: &[&str] = &["http", "https", "socks4", "socks4a", "socks5", "socks5h"];

#[derive(Debug, Clone)]
pub struct ProxyParseError {
    pub line_number: usize,
    pub content: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct ProxyLoadSummary {
    pub proxies: Vec<String>,
    pub skipped: Vec<ProxyParseError>,
}

#[derive(Debug, Clone)]
pub struct ProxyTestFailure {
    pub proxy: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct ProxyTestSummary {
    pub working: Vec<String>,
    pub failed: Vec<ProxyTestFailure>,
}

/// Attempt to normalise and validate a proxy entry.
fn normalize_proxy_candidate(line: &str) -> Result<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("empty line"));
    }

    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{}", trimmed)
    };

    let url = Url::parse(&candidate).map_err(|e| anyhow!("invalid proxy syntax: {}", e))?;

    if !SUPPORTED_PROXY_SCHEMES.iter().any(|scheme| url.scheme() == *scheme) {
        return Err(anyhow!("unsupported proxy scheme '{}'", url.scheme()));
    }

    if url.host_str().is_none() {
        return Err(anyhow!("missing proxy host"));
    }

    if url.port().is_none() {
        return Err(anyhow!("missing proxy port"));
    }

    Ok(candidate)
}

/// Load proxies from a file, returning a summary containing valid proxies and skipped entries.
pub fn load_proxies_from_file(filename: &str) -> Result<ProxyLoadSummary> {
    let file = fs::File::open(filename)
        .with_context(|| format!("failed to open proxy file '{}'", filename))?;
    let reader = BufReader::new(file);

    let mut proxies = Vec::new();
    let mut skipped = Vec::new();

    for (idx, line_res) in reader.lines().enumerate() {
        let raw_line = line_res
            .with_context(|| format!("failed to read line {} in '{}'", idx + 1, filename))?;
        let trimmed = raw_line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        match normalize_proxy_candidate(trimmed) {
            Ok(proxy) => proxies.push(proxy),
            Err(err) => skipped.push(ProxyParseError {
                line_number: idx + 1,
                content: trimmed.to_string(),
                reason: err.to_string(),
            }),
        }
    }

    if proxies.is_empty() {
        return Err(anyhow!("no valid proxies found in '{}'", filename));
    }

    Ok(ProxyLoadSummary { proxies, skipped })
}

/// Test proxies concurrently and return which passed connectivity checks.
pub async fn test_proxies(
    proxies: &[String],
    test_url: &str,
    timeout_secs: u64,
    max_parallel: usize,
) -> ProxyTestSummary {
    if proxies.is_empty() {
        return ProxyTestSummary {
            working: Vec::new(),
            failed: Vec::new(),
        };
    }

    let timeout = Duration::from_secs(timeout_secs.max(1));
    let parallel = max_parallel.max(1);
    let semaphore = Arc::new(Semaphore::new(parallel));
    let mut tasks = FuturesUnordered::new();

    for proxy in proxies.iter().cloned() {
        let test_url = test_url.to_string();
        let semaphore = Arc::clone(&semaphore);
        tasks.push(tokio::spawn(async move {
            let permit = semaphore.acquire_owned().await;
            if permit.is_err() {
                return (proxy, Err(anyhow!("failed to acquire semaphore permit")));
            }
            let _permit = permit.unwrap();
            let result = check_proxy(&proxy, &test_url, timeout).await;
            (proxy, result)
        }));
    }

    let mut summary = ProxyTestSummary {
        working: Vec::new(),
        failed: Vec::new(),
    };

    while let Some(res) = tasks.next().await {
        match res {
            Ok((proxy, Ok(()))) => summary.working.push(proxy),
            Ok((proxy, Err(err))) => summary.failed.push(ProxyTestFailure {
                proxy,
                reason: err.to_string(),
            }),
            Err(join_err) => summary.failed.push(ProxyTestFailure {
                proxy: "<spawn failed>".to_string(),
                reason: join_err.to_string(),
            }),
        }
    }

    summary
}

async fn check_proxy(proxy: &str, test_url: &str, timeout: Duration) -> Result<()> {
    let proxy_cfg = reqwest::Proxy::all(proxy)
        .with_context(|| format!("invalid proxy '{}'", proxy))?;

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .proxy(proxy_cfg)
        .danger_accept_invalid_certs(true)
        .build()
        .context("failed to build reqwest client")?;

    let response = client
        .get(test_url)
        .send()
        .await
        .with_context(|| format!("request via proxy '{}' failed", proxy))?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "received HTTP status {} while hitting {}",
            response.status(),
            test_url
        ));
    }

    Ok(())
}

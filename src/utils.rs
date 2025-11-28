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
use regex::Regex;

/// Maximum folder depth to traverse
const MAX_DEPTH: usize = 6;

/// Maximum length for target strings to prevent DoS
const MAX_TARGET_LENGTH: usize = 2048;

/// Maximum length for module paths
const MAX_MODULE_PATH_LENGTH: usize = 512;

/// Maximum file size to read (10MB) - prevents reading huge files
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum number of proxies to process
const MAX_PROXIES: usize = 100000;

/// Maximum parallel proxy tests
const MAX_PARALLEL_PROXIES: usize = 1000;

/// Maximum timeout for proxy tests (5 minutes)
const MAX_PROXY_TIMEOUT_SECS: u64 = 300;

/// Take "1.2.3.4", "::1", "[::1]:8080" or "hostname" and
/// always return a valid "host:port" or "[ipv6]:port" string.
/// 
/// # Security
/// - Validates input length to prevent DoS
/// - Sanitizes input to prevent injection
/// - Validates hostname format
pub fn normalize_target(raw: &str) -> Result<String> {
    // Input validation
    let trimmed = raw.trim();
    
    // Check length to prevent DoS
    if trimmed.is_empty() {
        return Err(anyhow!("Target cannot be empty"));
    }
    
    if trimmed.len() > MAX_TARGET_LENGTH {
        return Err(anyhow!(
            "Target too long (max {} characters, got {})",
            MAX_TARGET_LENGTH,
            trimmed.len()
        ));
    }
    
    // Basic sanitization - remove control characters and excessive whitespace
    let sanitized: String = trimmed
        .chars()
        .filter(|c| !c.is_control() || *c == ' ' || *c == '\t')
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    
    if sanitized.is_empty() {
        return Err(anyhow!("Target contains only invalid characters"));
    }
    
    // Check for path traversal attempts
    if sanitized.contains("..") || sanitized.contains("//") {
        return Err(anyhow!("Invalid target format: contains path traversal characters"));
    }
    
    // Handle already normalized formats
    if sanitized.contains("]:") || sanitized.starts_with('[') {
        // Validate the format
        if sanitized.starts_with('[') && !sanitized.contains(']') {
            return Err(anyhow!("Invalid IPv6 format: missing closing bracket"));
        }
        // Basic validation - check it's not just brackets
        let inner = sanitized.trim_matches(|c| c == '[' || c == ']');
        if inner.is_empty() {
            return Err(anyhow!("Invalid target: empty address"));
        }
        return Ok(sanitized.to_string());
    }

    // Detect IPv6 addresses (multiple colons, no dots)
    let colon_count = sanitized.matches(':').count();
    let has_dots = sanitized.contains('.');
    
    // IPv6 detection: multiple colons and no dots (or dots only in port)
    let is_ipv6 = colon_count >= 2 && !has_dots;
    
    // Additional IPv6 validation
    if is_ipv6 {
        // Check for valid IPv6 characters
        let ipv6_re = Regex::new(r"^[0-9a-fA-F:]+$").unwrap();
        let addr_part = sanitized.split(':').next().unwrap_or("");
        if !ipv6_re.is_match(addr_part) && !addr_part.is_empty() {
            return Err(anyhow!("Invalid IPv6 address format: '{}'", sanitized));
        }
        Ok(format!("[{}]", sanitized))
    } else {
        // Validate hostname/IPv4 format
        // Basic validation: no spaces, reasonable characters
        if sanitized.contains(' ') {
            return Err(anyhow!("Invalid target format: contains spaces"));
        }
        
        // Check for valid hostname/IPv4/CIDR characters (allow / for CIDR notation)
        let host_re = Regex::new(r"^[a-zA-Z0-9.\-_:/]+$").unwrap();
        if !host_re.is_match(&sanitized) {
            return Err(anyhow!("Invalid target format: contains invalid characters"));
        }
        
        Ok(sanitized.to_string())
    }
}

/// Recursively list .rs files up to a certain depth with security checks
fn collect_module_paths(dir: &Path, depth: usize) -> Vec<String> {
    let mut modules = Vec::new();

    // Depth limit to prevent infinite recursion
    if depth > MAX_DEPTH {
        return modules;
    }
    
    // Validate directory exists and is readable
    if !dir.exists() {
        return modules;
    }
    
    // Prevent path traversal - ensure we're within src/modules
    let modules_base = Path::new("src/modules");
    if !dir.starts_with(modules_base) && depth > 0 {
        // Only allow traversal within src/modules
        return modules;
    }

    // Read directory with error handling
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return modules, // Silently skip unreadable directories
    };

    for entry in entries.flatten() {
        let path = entry.path();

        // Check for symlinks that might cause issues
        if path.is_symlink() {
            continue; // Skip symlinks for security
        }

        if path.is_dir() {
            // Recursively collect from subdirectories
            modules.extend(collect_module_paths(&path, depth + 1));
        } else if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
            // Only process .rs files, skip mod.rs
            if file_name.ends_with(".rs") && file_name != "mod.rs" {
                // Validate path length
                let relative_path = match path.strip_prefix("src/modules") {
                    Ok(rel) => rel,
                    Err(_) => &path, // Fallback to full path if strip fails
                };
                
                let path_str = relative_path
                    .with_extension("")
                    .to_string_lossy()
                    .replace('\\', "/"); // Windows path normalization
                
                // Validate path length
                if path_str.len() <= MAX_MODULE_PATH_LENGTH {
                    modules.push(path_str);
                }
            }
        }
    }

    modules
}

/// Dynamically checks if a module path exists at any depth with validation
pub fn module_exists(module_path: &str) -> bool {
    // Input validation
    if module_path.is_empty() {
        return false;
    }
    
    if module_path.len() > MAX_MODULE_PATH_LENGTH {
        return false;
    }
    
    // Check for path traversal attempts
    if module_path.contains("..") || module_path.contains("//") {
        return false;
    }
    
    let modules = collect_module_paths(Path::new("src/modules"), 0);
    modules.iter().any(|m| m == module_path)
}

/// Lists all available modules recursively under src/modules/
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

/// Finds and displays modules matching a keyword with validation
pub fn find_modules(keyword: &str) {
    // Input validation
    if keyword.is_empty() {
        println!("{}", "Keyword cannot be empty.".red());
        return;
    }
    
    // Limit keyword length
    if keyword.len() > 100 {
        println!("{}", "Keyword too long (max 100 characters).".red());
        return;
    }
    
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

/// Validates and sanitizes a proxy URL
fn validate_proxy_url(url: &Url) -> Result<()> {
    // Check scheme
    if !SUPPORTED_PROXY_SCHEMES.iter().any(|scheme| url.scheme() == *scheme) {
        return Err(anyhow!("unsupported proxy scheme '{}'", url.scheme()));
    }

    // Validate host
    let host = url.host_str()
        .ok_or_else(|| anyhow!("missing proxy host"))?;
    
    // Validate host length
    if host.is_empty() {
        return Err(anyhow!("proxy host cannot be empty"));
    }
    
    if host.len() > 253 { // Max DNS hostname length
        return Err(anyhow!("proxy host too long (max 253 characters)"));
    }
    
    // Validate hostname format (basic check)
    let host_re = Regex::new(r"^[a-zA-Z0-9.\-_:\[\]]+$").unwrap();
    if !host_re.is_match(host) {
        return Err(anyhow!("invalid proxy host format"));
    }
    
    // Check for localhost/private IP abuse (warning only, not blocking)
    if host == "localhost" || host == "127.0.0.1" || host == "::1" {
        // Allow but could log warning in production
    }

    // Validate port
    let port = url.port()
        .ok_or_else(|| anyhow!("missing proxy port"))?;
    
    if port == 0 {
        return Err(anyhow!("proxy port cannot be 0"));
    }

    // Port is already validated to be in u16 range (0-65535) by Url::parse
    // We just need to check it's not 0 (already checked above)
    // Additional validation: check for common restricted ports if needed

    Ok(())
}

/// Attempt to normalise and validate a proxy entry with enhanced security
fn normalize_proxy_candidate(line: &str) -> Result<String> {
    let trimmed = line.trim();
    
    // Input validation
    if trimmed.is_empty() {
        return Err(anyhow!("empty line"));
    }
    
    // Length check to prevent DoS
    if trimmed.len() > 2048 {
        return Err(anyhow!("proxy line too long (max 2048 characters)"));
    }
    
    // Sanitize input - remove control characters (but allow newline/carriage return for line processing)
    let sanitized: String = trimmed
        .chars()
        .filter(|c| {
            let ch = *c;
            !ch.is_control() || ch == '\n' || ch == '\r'
        })
        .collect();
    
    if sanitized.is_empty() {
        return Err(anyhow!("proxy line contains only invalid characters"));
    }

    // Add scheme if missing
    let candidate = if sanitized.contains("://") {
        sanitized
    } else {
        format!("http://{}", sanitized)
    };

    // Parse URL
    let url = Url::parse(&candidate)
        .map_err(|e| anyhow!("invalid proxy syntax: {}", e))?;

    // Validate the proxy URL
    validate_proxy_url(&url)?;

    Ok(candidate)
}

/// Load proxies from a file with enhanced security and validation
pub fn load_proxies_from_file(filename: &str) -> Result<ProxyLoadSummary> {
    // Input validation
    if filename.is_empty() {
        return Err(anyhow!("filename cannot be empty"));
    }
    
    // Path validation - prevent path traversal
    let path = Path::new(filename);
    
    // Check for path traversal attempts
    if filename.contains("..") {
        return Err(anyhow!("path traversal detected in filename: '{}'", filename));
    }
    
    // Resolve to absolute path to check
    let canonical = path.canonicalize()
        .map_err(|e| anyhow!("failed to resolve file path '{}': {}", filename, e))?;
    
    // Check file exists and is a regular file
    if !canonical.is_file() {
        return Err(anyhow!("'{}' is not a regular file", filename));
    }
    
    // Check file size to prevent reading huge files
    let metadata = fs::metadata(&canonical)
        .with_context(|| format!("failed to read file metadata for '{}'", filename))?;
    
    if metadata.len() > MAX_FILE_SIZE {
        return Err(anyhow!(
            "file too large (max {} bytes, got {} bytes)",
            MAX_FILE_SIZE,
            metadata.len()
        ));
    }
    
    // Open file
    let file = fs::File::open(&canonical)
        .with_context(|| format!("failed to open proxy file '{}'", filename))?;
    let reader = BufReader::new(file);

    let mut proxies = Vec::new();
    let mut skipped = Vec::new();
    let mut line_count = 0usize;

    for (idx, line_res) in reader.lines().enumerate() {
        line_count = idx + 1;
        
        // Limit number of lines to process
        if line_count > MAX_PROXIES {
            skipped.push(ProxyParseError {
                line_number: line_count,
                content: format!("... (truncated after {} lines)", MAX_PROXIES),
                reason: format!("file exceeds maximum line limit ({})", MAX_PROXIES),
            });
            break;
        }
        
        let raw_line = line_res
            .with_context(|| format!("failed to read line {} in '{}'", idx + 1, filename))?;
        let trimmed = raw_line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        match normalize_proxy_candidate(trimmed) {
            Ok(proxy) => proxies.push(proxy),
            Err(err) => skipped.push(ProxyParseError {
                line_number: idx + 1,
                content: if trimmed.len() > 100 {
                    format!("{}...", &trimmed[..100])
                } else {
                    trimmed.to_string()
                },
                reason: err.to_string(),
            }),
        }
    }

    if proxies.is_empty() {
        return Err(anyhow!("no valid proxies found in '{}' (processed {} lines)", filename, line_count));
    }
    
    // Limit number of proxies
    if proxies.len() > MAX_PROXIES {
        let original_count = proxies.len();
        proxies.truncate(MAX_PROXIES);
        return Err(anyhow!(
            "too many proxies (max {}, found {}). Truncated to {}",
            MAX_PROXIES,
            original_count,
            MAX_PROXIES
        ));
    }

    Ok(ProxyLoadSummary { proxies, skipped })
}

/// Test proxies concurrently with enhanced validation and resource limits
pub async fn test_proxies(
    proxies: &[String],
    test_url: &str,
    timeout_secs: u64,
    max_parallel: usize,
) -> ProxyTestSummary {
    // Input validation
    if proxies.is_empty() {
        return ProxyTestSummary {
            working: Vec::new(),
            failed: Vec::new(),
        };
    }
    
    // Validate and limit inputs
    let timeout_secs = timeout_secs.min(MAX_PROXY_TIMEOUT_SECS).max(1);
    let max_parallel = max_parallel.min(MAX_PARALLEL_PROXIES).max(1);
    
    // Limit number of proxies to test
    let proxies_to_test = if proxies.len() > MAX_PROXIES {
        &proxies[..MAX_PROXIES]
    } else {
        proxies
    };
    
    // Validate test URL
    let test_url = test_url.trim();
    if test_url.is_empty() {
        return ProxyTestSummary {
            working: Vec::new(),
            failed: proxies_to_test.iter().map(|p| ProxyTestFailure {
                proxy: p.clone(),
                reason: "test URL is empty".to_string(),
            }).collect(),
        };
    }
    
    // Validate URL format
    if let Err(e) = Url::parse(test_url) {
        return ProxyTestSummary {
            working: Vec::new(),
            failed: proxies_to_test.iter().map(|p| ProxyTestFailure {
                proxy: p.clone(),
                reason: format!("invalid test URL: {}", e),
            }).collect(),
        };
    }

    let timeout = Duration::from_secs(timeout_secs);
    let semaphore = Arc::new(Semaphore::new(max_parallel));
    let mut tasks = FuturesUnordered::new();

    for proxy in proxies_to_test.iter().cloned() {
        let test_url = test_url.to_string();
        let semaphore = Arc::clone(&semaphore);
        tasks.push(tokio::spawn(async move {
            let permit = match semaphore.acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    return (proxy, Err(anyhow!("failed to acquire semaphore permit")));
                }
            };
            let _permit = permit;
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

/// Check a single proxy with enhanced error handling and validation
async fn check_proxy(proxy: &str, test_url: &str, timeout: Duration) -> Result<()> {
    // Validate inputs
    if proxy.is_empty() {
        return Err(anyhow!("proxy cannot be empty"));
    }
    
    if test_url.is_empty() {
        return Err(anyhow!("test URL cannot be empty"));
    }
    
    // Validate URL format
    let _test_url_parsed = Url::parse(test_url)
        .map_err(|e| anyhow!("invalid test URL '{}': {}", test_url, e))?;

    // Create proxy configuration
    let proxy_cfg = reqwest::Proxy::all(proxy)
        .with_context(|| format!("invalid proxy '{}'", proxy))?;

    // Build HTTP client with timeout
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .proxy(proxy_cfg)
        .danger_accept_invalid_certs(true)
        .build()
        .context("failed to build reqwest client")?;

    // Make request with timeout
    let response = client
        .get(test_url)
        .timeout(timeout)
        .send()
        .await
        .with_context(|| format!("request via proxy '{}' failed", proxy))?;

    // Check response status
    let status = response.status();
    if !status.is_success() {
        return Err(anyhow!(
            "received HTTP status {} while hitting {}",
            status,
            test_url
        ));
    }

    Ok(())
}

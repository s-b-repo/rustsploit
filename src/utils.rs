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
use once_cell::sync::Lazy; // Added for safe static regex initialization

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

/// Maximum length for command inputs to prevent DoS
const MAX_COMMAND_LENGTH: usize = 8192;

/// Maximum length for file paths to prevent DoS
const MAX_PATH_LENGTH: usize = 4096;

/// Dangerous command characters that should be sanitized or rejected
const DANGEROUS_CMD_CHARS: &[char] = &['\x00', '\n', '\r', '\t'];

/// Comprehensive target normalization function.
/// 
/// Supports multiple input formats:
/// - IPv4: "192.168.1.1", "192.168.1.1:8080"
/// - IPv6: "::1", "[::1]", "[::1]:8080", "2001:db8::1"
/// - Hostnames: "example.com", "example.com:443"
/// - URLs: "http://example.com:8080" (extracts host:port)
/// - CIDR: "192.168.1.0/24", "2001:db8::/32"
/// 
/// Returns normalized format:
/// - IPv4/hostname: "host:port" or "host" (if no port)
/// - IPv6: "[ipv6]:port" or "[ipv6]" (if no port)
/// - CIDR: "network/prefix" (preserved as-is)
/// 
/// # Security
/// - Validates input length to prevent DoS
/// - Sanitizes input to prevent injection
/// - Validates hostname/IP format
/// - Prevents path traversal attempts
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
    
    // Check for path traversal attempts early
    if trimmed.contains("..") || trimmed.contains("//") {
        return Err(anyhow!("Invalid target format: contains path traversal characters"));
    }
    
    // Try to parse as URL first (handles http://, https://, etc.)
    if let Ok(url) = Url::parse(trimmed) {
        if let Some(host) = url.host_str() {
            let port = url.port().unwrap_or(0);
            let normalized = if port > 0 {
                format!("{}:{}", host, port)
            } else {
                host.to_string()
            };
            // Recursively normalize to handle IPv6 wrapping
            return normalize_target(&normalized);
        }
    }
    
    // Basic sanitization - remove control characters except space/tab
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
    
    // Check for CIDR notation (contains /)
    if sanitized.contains('/') {
        // Validate CIDR format
        let parts: Vec<&str> = sanitized.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid CIDR format: expected 'network/prefix'"));
        }
        
        let network = parts[0].trim();
        let prefix_str = parts[1].trim();
        
        // Validate prefix is a number
        let prefix: u8 = prefix_str.parse()
            .map_err(|_| anyhow!("Invalid CIDR prefix: '{}' (must be 0-128 for IPv6, 0-32 for IPv4)", prefix_str))?;
        
        // Normalize the network part (without prefix)
        let normalized_network = normalize_target(network)?;
        
        // Validate prefix range based on IP version
        let is_ipv6 = normalized_network.starts_with('[') || normalized_network.matches(':').count() >= 2;
        if is_ipv6 {
            if prefix > 128 {
                return Err(anyhow!("Invalid IPv6 CIDR prefix: {} (max 128)", prefix));
            }
        } else {
            if prefix > 32 {
                return Err(anyhow!("Invalid IPv4 CIDR prefix: {} (max 32)", prefix));
            }
        }
        
        return Ok(format!("{}/{}", normalized_network, prefix));
    }
    
    // Handle already normalized IPv6 with brackets: [::1]:8080 or [::1]
    if sanitized.starts_with('[') {
        if let Some(bracket_end) = sanitized.find(']') {
            let ipv6_part = &sanitized[1..bracket_end];
            let after_bracket = &sanitized[bracket_end + 1..];
            
            // Validate IPv6 address
            if !is_valid_ipv6(ipv6_part) {
                return Err(anyhow!("Invalid IPv6 address: '{}'", ipv6_part));
            }
            
            // Check for port after bracket
            if after_bracket.starts_with(':') {
                let port_str = &after_bracket[1..].trim();
                if port_str.is_empty() {
                    return Err(anyhow!("Invalid port format: missing port number"));
                }
                let port: u16 = port_str.parse()
                    .map_err(|_| anyhow!("Invalid port number: '{}'", port_str))?;
                if port == 0 {
                    return Err(anyhow!("Port cannot be 0"));
                }
                return Ok(format!("[{}]:{}", ipv6_part, port));
            } else if !after_bracket.is_empty() {
                return Err(anyhow!("Invalid format after IPv6 address: '{}'", after_bracket));
            }
            return Ok(format!("[{}]", ipv6_part));
        } else {
            return Err(anyhow!("Invalid IPv6 format: missing closing bracket"));
        }
    }
    
    // Check if it contains a port (format: host:port or ip:port)
    let colon_count = sanitized.matches(':').count();
    let has_dots = sanitized.contains('.');
    
    // IPv6 detection: multiple colons typically indicates IPv6
    let is_likely_ipv6 = colon_count >= 2 && !has_dots;
    
    if is_likely_ipv6 {
        // IPv6 address (may or may not have port)
        if let Some(last_colon_pos) = sanitized.rfind(':') {
            // Check if last colon is part of IPv6 or port separator
            let before_colon = &sanitized[..last_colon_pos];
            let after_colon = &sanitized[last_colon_pos + 1..];
            
            // If after colon is all digits, it's likely a port
            if after_colon.chars().all(|c| c.is_ascii_digit()) && !after_colon.is_empty() {
                let port: u16 = after_colon.parse()
                    .map_err(|_| anyhow!("Invalid port number: '{}'", after_colon))?;
                if port == 0 {
                    return Err(anyhow!("Port cannot be 0"));
                }
                
                // Validate IPv6 part
                if !is_valid_ipv6(before_colon) {
                    return Err(anyhow!("Invalid IPv6 address: '{}'", before_colon));
                }
                return Ok(format!("[{}]:{}", before_colon, port));
            }
        }
        
        // IPv6 without port
        if !is_valid_ipv6(&sanitized) {
            return Err(anyhow!("Invalid IPv6 address format: '{}'", sanitized));
        }
        return Ok(format!("[{}]", sanitized));
    }
    
    // IPv4 or hostname (may have port)
    if sanitized.contains(':') {
        if let Some(colon_pos) = sanitized.rfind(':') {
            let host_part = &sanitized[..colon_pos];
            let port_str = &sanitized[colon_pos + 1..];
            
            if port_str.is_empty() {
                return Err(anyhow!("Invalid port format: missing port number"));
            }
            
            let port: u16 = port_str.parse()
                .map_err(|_| anyhow!("Invalid port number: '{}'", port_str))?;
            if port == 0 {
                return Err(anyhow!("Port cannot be 0"));
            }
            
            // Validate host part
            if host_part.is_empty() {
                return Err(anyhow!("Invalid target: empty hostname/IP"));
            }
            
            // Validate hostname/IPv4 format
            if !is_valid_hostname_or_ipv4(host_part) {
                return Err(anyhow!("Invalid hostname or IPv4 address: '{}'", host_part));
            }
            
            return Ok(format!("{}:{}", host_part, port));
        }
    }
    
    // No port - just hostname or IPv4
    if sanitized.contains(' ') {
        return Err(anyhow!("Invalid target format: contains spaces (did you mean to include a port?)"));
    }
    
    // Validate hostname/IPv4 format
    if !is_valid_hostname_or_ipv4(&sanitized) {
        return Err(anyhow!("Invalid hostname or IPv4 address format: '{}'", sanitized));
    }
    
    Ok(sanitized.to_string())
}

/// Validate IPv6 address format (basic validation)
/// Supports compressed notation (::), mixed IPv4/IPv6 (::ffff:192.168.1.1), etc.
fn is_valid_ipv6(addr: &str) -> bool {
    if addr.is_empty() {
        return false;
    }
    
    // Check for valid IPv6 characters: hex digits, colons, and dots (for IPv4-mapped)
    static IPV6_CHAR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9a-fA-F:.]+$").expect("Invalid Regex"));
    if !IPV6_CHAR_RE.is_match(addr) {
        return false;
    }
    
    // Check for valid :: usage (only one allowed, and not at start/end unless it's ::1 style)
    let double_colon_count = addr.matches("::").count();
    if double_colon_count > 1 {
        return false;
    }
    
    // Handle special cases
    if addr == "::" || addr == "::1" {
        return true;
    }
    
    // Check for IPv4-mapped IPv6 (::ffff:192.168.1.1 or similar)
    if addr.contains('.') {
        // Must be in format like ::ffff:192.168.1.1
        let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
        if parts.len() == 2 {
            let ipv4_part = parts[0];
            // Validate IPv4 part
            let ipv4_parts: Vec<&str> = ipv4_part.split('.').collect();
            if ipv4_parts.len() == 4 {
                let is_valid_ipv4 = ipv4_parts.iter().all(|part| {
                    part.parse::<u8>().is_ok()
                });
                if is_valid_ipv4 {
                    // Valid IPv4-mapped IPv6
                    return true;
                }
            }
        }
        return false;
    }
    
    // Split by colons to validate segments
    let segments: Vec<&str> = addr.split(':').collect();
    
    // With :: compression, we can have fewer than 8 segments
    // Without ::, we need exactly 8 segments
    if double_colon_count == 0 {
        // No compression - must have exactly 8 segments
        if segments.len() != 8 {
            return false;
        }
    } else {
        // With compression - can have 2-7 segments
        if segments.len() < 2 || segments.len() > 7 {
            return false;
        }
    }
    
    // Validate each segment (except empty ones from ::)
    for segment in &segments {
        if segment.is_empty() {
            continue; // Empty segment from :: compression
        }
        if segment.len() > 4 {
            return false; // Each segment max 4 hex digits
        }
        // Validate hex digits
        if !segment.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    
    true
}

/// Validate hostname or IPv4 address format
fn is_valid_hostname_or_ipv4(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    
    // Check for valid characters (alphanumeric, dots, hyphens, underscores)
    static HOST_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9.\-_]+$").expect("Invalid Regex"));
    if !HOST_RE.is_match(host) {
        return false;
    }
    
    // Check if it looks like IPv4 (contains dots and all segments are numeric)
    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() == 4 {
            // Could be IPv4 - validate each octet
            let is_ipv4 = parts.iter().all(|part| {
                part.parse::<u8>().is_ok()
            });
            if is_ipv4 {
                return true; // Valid IPv4
            }
        }
    }
    
    // Hostname validation: must start and end with alphanumeric
    if host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    
    if host.starts_with('-') || host.ends_with('-') {
        return false;
    }
    
    // Check hostname length (max 253 characters per RFC)
    if host.len() > 253 {
        return false;
    }
    
    // Check individual label length (max 63 characters per RFC)
    for label in host.split('.') {
        if label.len() > 63 {
            return false;
        }
    }
    
    true
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
    static PROXY_HOST_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9.\-_:\[\]]+$").expect("Invalid Regex"));
    if !PROXY_HOST_RE.is_match(host) {
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

/// Extract IP address or hostname from target string.
/// Handles formats: IP:port, [IPv6]:port, hostname:port, CIDR notation
/// Returns the host/IP part without port or brackets.
fn extract_ip_from_target(target: &str) -> Option<String> {
    let trimmed = target.trim();
    
    // Handle CIDR notation: extract network part before /
    if let Some(slash_pos) = trimmed.find('/') {
        let network_part = &trimmed[..slash_pos];
        return extract_ip_from_target(network_part);
    }
    
    // Handle IPv6 with brackets: [::1]:8080 or [::1]
    if trimmed.starts_with('[') {
        if let Some(bracket_end) = trimmed.find(']') {
            let ipv6_part = &trimmed[1..bracket_end];
            return Some(ipv6_part.to_string());
        }
        // Malformed - missing closing bracket, but try to extract anyway
        return Some(trimmed.trim_start_matches('[').to_string());
    }
    
    // Handle IPv4 or hostname with port: 192.168.1.1:8080 or hostname:8080
    if let Some(colon_pos) = trimmed.rfind(':') {
        let before_colon = &trimmed[..colon_pos];
        let after_colon = &trimmed[colon_pos + 1..];
        
        // Check if after colon is a port (all digits)
        if after_colon.chars().all(|c| c.is_ascii_digit()) && !after_colon.is_empty() {
            // It's a port - extract host part
            // But check if before_colon is IPv6 (multiple colons)
            let colon_count = before_colon.matches(':').count();
            if colon_count >= 2 {
                // IPv6 address - return as is (without brackets)
                return Some(before_colon.to_string());
            }
            // IPv4 or hostname - return host part
            return Some(before_colon.to_string());
        }
    }
    
    // No port or malformed - check if it's IPv6 (multiple colons)
    let colon_count = trimmed.matches(':').count();
    if colon_count >= 2 {
        // IPv6 without brackets - return as is
        return Some(trimmed.to_string());
    }
    
    // No port - return as is (IPv4 or hostname)
    Some(trimmed.to_string())
}

/// Perform a lightweight honeypot check by probing common ports.
/// If 11 or more ports are open, warns that the target is likely a honeypot.
pub async fn basic_honeypot_check(target: &str) {
    // Extract IP address from target (handles IP:port format)
    let ip = match extract_ip_from_target(target) {
        Some(ip) => ip,
        None => {
            // If we can't extract IP, skip check
            return;
        }
    };
    
    // Skip check for hostnames (contains non-IP characters)
    if ip.contains(|c: char| c.is_alphabetic() && c != ':') && !ip.contains(':') {
        // Likely a hostname, skip honeypot check
        return;
    }
    
    println!();
    println!("{}", "╔══════════════════════════════════════════════╗".bright_yellow());
    println!("{}", "║   HONEYPOT DETECTION CHECK                  ║".bright_yellow());
    println!("{}", "╚══════════════════════════════════════════════╝".bright_yellow());
    println!();
    println!("[*] Scanning {} common ports on {}...", 200, ip);
    
    // Common ports typically exposed by network services.
    const COMMON_PORTS: &[u16] = &[
        11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 26, 37, 38, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 86, 88, 89, 91, 92, 94, 95, 97, 99,
        101, 102, 104, 110, 111, 113, 119, 143, 154, 161, 175, 177, 179, 180, 189, 195, 221, 234, 243, 263, 264, 285, 311, 314, 385, 389,
        400, 427, 440, 441, 442, 443, 444, 446, 447, 449, 450, 451, 452, 462, 465, 480, 485, 488, 502, 503, 513, 515, 541, 548, 554, 556,
        587, 591, 593, 602, 631, 636, 646, 666, 685, 700, 743, 771, 777, 785, 789, 805, 806, 811, 832, 833, 843, 873, 880, 886, 887, 902,
        953, 990, 992, 993, 995, 998, 999, 1013, 1022, 1023, 1024, 1027, 1080, 1099, 1110, 1111, 1153, 1181, 1188, 1195, 1198, 1200, 1207,
        1234, 1291, 1292, 1311, 1337, 1366, 1370, 1377, 1388, 1400, 1414, 1433, 1444, 1447, 1451, 1453, 1454, 1457, 1460, 1471, 1521, 1554,
        1599, 1604, 1605, 1650, 1723, 1741, 1820, 1830, 1883
    ];

    let mut open_count = 0usize;
    let mut open_ports = Vec::new();

    for &port in COMMON_PORTS {
        let addr = format!("{}:{}", ip, port);
        let conn = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            tokio::net::TcpStream::connect(&addr),
        )
        .await;

        if let Ok(Ok(stream)) = conn {
            // We only care that the TCP handshake completed; drop immediately.
            drop(stream);
            open_count += 1;
            if open_ports.len() < 20 {
                open_ports.push(port);
            }
        }
    }

    println!("[*] Found {} open port(s) out of {} scanned", open_count, COMMON_PORTS.len());
    
    // Threshold: if 11 or more common ports are open, likely a honeypot
    if open_count >= 11 {
        println!();
        println!("{}", "╔══════════════════════════════════════════════╗".red().bold());
        println!("{}", "║   ⚠️  HONEYPOT DETECTED                     ║".red().bold());
        println!("{}", "╚══════════════════════════════════════════════╝".red().bold());
        println!();
        println!(
            "{}",
            format!(
                "[!] Target {} has {} / {} common ports open - likely honeypot",
                ip,
                open_count,
                COMMON_PORTS.len()
            )
            .yellow()
            .bold()
        );
        println!("{}", "    This is likely a honeypot system".yellow().bold());
        if open_count <= 20 && !open_ports.is_empty() {
            println!("{}", format!("    Open ports: {:?}", &open_ports[..open_count.min(20)]).yellow());
        }
        println!();
    } else {
        println!("{}", "[+] No honeypot indicators detected".green());
        println!();
    }
}

/// Validates and sanitizes command input to prevent injection attacks and DoS
/// 
/// # Security Features
/// - Length limits to prevent DoS
/// - Dangerous character filtering
/// - Control character removal
/// 
/// # Arguments
/// - `command`: The command string to validate
/// 
/// # Returns
/// - `Ok(String)`: Sanitized command if valid
/// - `Err`: Error if validation fails
pub fn validate_command_input(command: &str) -> Result<String> {
    let trimmed = command.trim();
    
    // Check if empty
    if trimmed.is_empty() {
        return Err(anyhow!("Command cannot be empty"));
    }
    
    // Check length to prevent DoS
    if trimmed.len() > MAX_COMMAND_LENGTH {
        return Err(anyhow!(
            "Command too long (max {} characters, got {})",
            MAX_COMMAND_LENGTH,
            trimmed.len()
        ));
    }
    
    // Remove dangerous control characters
    let sanitized: String = trimmed
        .chars()
        .filter(|c| !DANGEROUS_CMD_CHARS.contains(c))
        .collect();
    
    if sanitized.is_empty() {
        return Err(anyhow!("Command contains only invalid characters"));
    }
    
    Ok(sanitized)
}

/// Validates file path to prevent path traversal attacks
/// 
/// # Security Features
/// - Path traversal detection (.., //, etc.)
/// - Length limits to prevent DoS
/// - Control character filtering
/// - Absolute path validation (optional)
/// 
/// # Arguments
/// - `path`: The file path to validate
/// - `allow_absolute`: Whether to allow absolute paths
/// 
/// # Returns
/// - `Ok(String)`: Sanitized path if valid
/// - `Err`: Error if validation fails
pub fn validate_file_path(path: &str, allow_absolute: bool) -> Result<String> {
    let trimmed = path.trim();
    
    // Check if empty
    if trimmed.is_empty() {
        return Err(anyhow!("File path cannot be empty"));
    }
    
    // Check length to prevent DoS
    if trimmed.len() > MAX_PATH_LENGTH {
        return Err(anyhow!(
            "File path too long (max {} characters, got {})",
            MAX_PATH_LENGTH,
            trimmed.len()
        ));
    }
    
    // Check for path traversal attempts
    if trimmed.contains("..") {
        return Err(anyhow!("Path traversal detected: '..' not allowed"));
    }
    
    // Check for double slashes (potential traversal)
    if trimmed.contains("//") {
        return Err(anyhow!("Invalid path format: double slashes not allowed"));
    }
    
    // Check for control characters
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(anyhow!("File path cannot contain control characters"));
    }
    
    // Check for absolute paths if not allowed
    if !allow_absolute {
        if trimmed.starts_with('/') || (cfg!(windows) && trimmed.chars().nth(1) == Some(':')) {
            return Err(anyhow!("Absolute paths not allowed"));
        }
    }
    
    // Basic path validation - ensure it's a reasonable path
    let _path_obj = Path::new(trimmed);
    
    // Check for null bytes (shouldn't happen after trim, but double-check)
    if trimmed.contains('\x00') {
        return Err(anyhow!("File path cannot contain null bytes"));
    }
    
    // On Windows, check for invalid characters
    #[cfg(windows)]
    {
        const INVALID_CHARS: &[char] = &['<', '>', ':', '"', '|', '?', '*'];
        if trimmed.chars().any(|c| INVALID_CHARS.contains(&c)) {
            return Err(anyhow!("File path contains invalid characters for Windows"));
        }
    }
    
    Ok(trimmed.to_string())
}

/// Escapes shell metacharacters in a command string to prevent command injection
/// 
/// # Security Features
/// - Escapes all shell metacharacters: $, `, |, &, ;, >, <, (, ), {, }, [, ], *, ?, ~, !, #
/// - Handles quotes and backslashes
/// - Prevents command chaining and injection
/// 
/// # Arguments
/// - `cmd`: The command string to escape
/// 
/// # Returns
/// - Escaped command string safe for shell execution
pub fn escape_shell_command(cmd: &str) -> String {
    let mut escaped = String::with_capacity(cmd.len() * 2);
    
    for ch in cmd.chars() {
        match ch {
            // Shell metacharacters that need escaping
            '$' | '`' | '|' | '&' | ';' | '>' | '<' | '(' | ')' | '{' | '}' | '[' | ']' | '*' | '?' | '~' | '!' | '#' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            // Quotes and backslashes
            '"' | '\'' | '\\' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            // Newlines and other control characters
            '\n' => {
                escaped.push_str("\\n");
            }
            '\r' => {
                escaped.push_str("\\r");
            }
            '\t' => {
                escaped.push_str("\\t");
            }
            // Regular characters
            _ => {
                escaped.push(ch);
            }
        }
    }
    
    escaped
}

/// Escapes command for JavaScript/Node.js execSync context
/// 
/// # Security Features
/// - Escapes backslashes, quotes, and newlines for JavaScript strings
/// - Escapes shell metacharacters if the command will be executed in a shell
/// - Handles both single and double quotes
/// 
/// # Arguments
/// - `cmd`: The command string to escape
/// - `escape_shell_meta`: Whether to also escape shell metacharacters (default: true)
/// 
/// # Returns
/// - Escaped command string safe for JavaScript execSync
pub fn escape_js_command(cmd: &str, escape_shell_meta: bool) -> String {
    let mut escaped = String::with_capacity(cmd.len() * 2);
    
    for ch in cmd.chars() {
        match ch {
            // JavaScript string escaping
            '\\' => {
                escaped.push_str("\\\\");
            }
            '"' => {
                escaped.push_str("\\\"");
            }
            '\'' => {
                escaped.push_str("\\'");
            }
            '\n' => {
                escaped.push_str("\\n");
            }
            '\r' => {
                escaped.push_str("\\r");
            }
            '\t' => {
                escaped.push_str("\\t");
            }
            // Shell metacharacters (if execSync uses shell)
            ch if escape_shell_meta && matches!(ch, '$' | '`' | '|' | '&' | ';' | '>' | '<' | '(' | ')' | '{' | '}' | '[' | ']' | '*' | '?' | '~' | '!' | '#') => {
                escaped.push('\\');
                escaped.push(ch);
            }
            // Regular characters
            _ => {
                escaped.push(ch);
            }
        }
    }
    
    escaped
}

/// Validates URL input to prevent injection and ensure proper format
/// 
/// # Security Features
/// - Length limits
/// - URL format validation
/// - Dangerous protocol filtering (optional)
/// 
/// # Arguments
/// - `url`: The URL string to validate
/// - `allowed_schemes`: Optional list of allowed URL schemes (e.g., ["http", "https"])
/// 
/// # Returns
/// - `Ok(String)`: Validated URL if valid
/// - `Err`: Error if validation fails
pub fn validate_url(url: &str, allowed_schemes: Option<&[&str]>) -> Result<String> {
    let trimmed = url.trim();
    
    // Check if empty
    if trimmed.is_empty() {
        return Err(anyhow!("URL cannot be empty"));
    }
    
    // Check length
    if trimmed.len() > MAX_COMMAND_LENGTH {
        return Err(anyhow!(
            "URL too long (max {} characters, got {})",
            MAX_COMMAND_LENGTH,
            trimmed.len()
        ));
    }
    
    // Parse URL
    let parsed_url = Url::parse(trimmed)
        .map_err(|e| anyhow!("Invalid URL format: {}", e))?;
    
    // Check scheme if restrictions provided
    if let Some(schemes) = allowed_schemes {
        let scheme = parsed_url.scheme();
        if !schemes.iter().any(|&s| s == scheme) {
            return Err(anyhow!(
                "URL scheme '{}' not allowed. Allowed schemes: {:?}",
                scheme,
                schemes
            ));
        }
    }
    
    // Validate host exists
    if parsed_url.host_str().is_none() {
        return Err(anyhow!("URL must contain a host"));
    }
    
    Ok(trimmed.to_string())
}

// ============================================================
// INTERACTIVE PROMPT HELPERS
// ============================================================

use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

/// Prompts the user for input, ensuring it is not empty.
pub async fn prompt_required(msg: &str) -> Result<String> {
    loop {
        print!("{}", format!("{}: ", msg).cyan().bold());
        tokio::io::stdout().flush().await.context("Failed to flush stdout")?;
        let mut s = String::new();
        tokio::io::BufReader::new(tokio::io::stdin())
            .read_line(&mut s)
            .await
            .context("Failed to read input")?;
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
        println!("{}", "This field is required.".yellow());
    }
}

/// Prompts the user for input, using a default value if empty.
pub async fn prompt_default(msg: &str, default: &str) -> Result<String> {
    print!("{}", format!("{} [{}]: ", msg, default).cyan().bold());
    tokio::io::stdout().flush().await.context("Failed to flush stdout")?;
    let mut s = String::new();
    tokio::io::BufReader::new(tokio::io::stdin())
        .read_line(&mut s)
        .await
        .context("Failed to read input")?;
    let trimmed = s.trim();
    Ok(if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    })
}

/// Prompts the user for a yes/no answer.
pub async fn prompt_yes_no(msg: &str, default_yes: bool) -> Result<bool> {
    let default = if default_yes { "y" } else { "n" };
    loop {
        print!("{}", format!("{} (y/n) [{}]: ", msg, default).cyan().bold());
        tokio::io::stdout()
            .flush()
            .await
            .context("Failed to flush stdout")?;
        let mut s = String::new();
        tokio::io::BufReader::new(tokio::io::stdin())
            .read_line(&mut s)
            .await
            .context("Failed to read input")?;
        match s.trim().to_lowercase().as_str() {
            ""        => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no"  => return Ok(false),
            _ => println!("{}", "Invalid input. Please enter 'y' or 'n'.".yellow()),
        }
    }
}

pub async fn prompt_int_range(msg: &str, default: i64, min: i64, max: i64) -> Result<i64> {
    loop {
        let input = prompt_default(msg, &default.to_string()).await?;
        match input.trim().parse::<i64>() {
            Ok(n) if n >= min && n <= max => return Ok(n),
            _ => println!("{}", format!("Please enter a number between {} and {}.", min, max).yellow()),
        }
    }
}

pub async fn prompt_wordlist(msg: &str) -> Result<String> {
    loop {
        let input = prompt_required(msg).await?;
        let path = Path::new(&input);
        if !path.exists() {
            println!("{}", format!("File '{}' does not exist.", input).yellow());
            continue;
        }
        if !path.is_file() {
            println!("{}", format!("'{}' is not a regular file.", input).yellow());
            continue;
        }
        return Ok(input);
    }
}

/// Prompts for an existing file path.
pub async fn prompt_existing_file(msg: &str) -> Result<String> {
    loop {
        let candidate = prompt_required(msg).await?;
        if Path::new(&candidate).is_file() {
            return Ok(candidate);
        } else {
            println!("{}", format!("File '{}' does not exist or is not a regular file.", candidate).yellow());
        }
    }
}

/// Helper to load lines from a file.
pub fn load_lines<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let file = fs::File::open(path.as_ref())
        .with_context(|| format!("Failed to open file '{}'", path.as_ref().display()))?;
    let reader = BufReader::new(file);
    Ok(reader
        .lines()
        .filter_map(|line| line.ok().map(|s| s.trim().to_string()))
        .filter(|line| !line.is_empty())
        .collect())
}

/// Helper to get a safe filename in the current directory.
pub fn get_filename_in_current_dir(input: &str) -> std::path::PathBuf {
    Path::new(input)
        .file_name()
        .map(|name_os_str| std::path::PathBuf::from(format!("./{}", name_os_str.to_string_lossy())))
        .unwrap_or_else(|| std::path::PathBuf::from(input))
}

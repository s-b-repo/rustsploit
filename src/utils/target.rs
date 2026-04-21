// src/utils/target.rs
//
// Target normalization, IPv6/hostname validation, and IP extraction.

use std::net::ToSocketAddrs;

use anyhow::{Context, Result, anyhow};
use colored::*;
use once_cell::sync::Lazy;
use regex::Regex;
use url::Url;

use super::prompt::{prompt_default, prompt_port, prompt_yes_no};
use super::sanitize::MAX_TARGET_LENGTH;

// ============================================================
// TARGET NORMALIZATION
// ============================================================

/// Comprehensive target normalization function.
///
/// Supports IPv4, IPv6, hostnames, URLs, and CIDR notation.
/// Returns normalized format with proper IPv6 bracketing.
pub fn normalize_target(raw: &str) -> Result<String> {
    let trimmed = raw.trim();

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

    // Comma-separated multi-target: normalize each individually
    if trimmed.contains(',') {
        let parts: Vec<&str> = trimmed.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return Err(anyhow!("No valid targets in comma-separated list"));
        }
        if parts.len() == 1 {
            return normalize_target(parts[0]);
        }
        let mut normalized = Vec::with_capacity(parts.len());
        for part in parts {
            normalized.push(normalize_target(part)?);
        }
        return Ok(normalized.join(", "));
    }

    if trimmed.contains("..") || trimmed.contains("//") {
        return Err(anyhow!(
            "Invalid target format: contains path traversal characters"
        ));
    }

    // Try to parse as URL first
    if let Ok(url) = Url::parse(trimmed) {
        if let Some(host) = url.host_str() {
            let port = url.port().unwrap_or(0);
            let normalized = if port > 0 {
                format!("{}:{}", host, port)
            } else {
                host.to_string()
            };
            return normalize_target(&normalized);
        }
    }

    // Basic sanitization
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

    // CIDR notation
    if sanitized.contains('/') {
        let parts: Vec<&str> = sanitized.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid CIDR format: expected 'network/prefix'"));
        }
        let network = parts[0].trim();
        let prefix_str = parts[1].trim();
        let prefix: u8 = prefix_str.parse().map_err(|_| {
            anyhow!(
                "Invalid CIDR prefix: '{}' (must be 0-128 for IPv6, 0-32 for IPv4)",
                prefix_str
            )
        })?;
        let normalized_network = normalize_target(network)?;
        let is_ipv6 =
            normalized_network.starts_with('[') || normalized_network.matches(':').count() >= 2;
        if is_ipv6 {
            if prefix > 128 {
                return Err(anyhow!("Invalid IPv6 CIDR prefix: {} (max 128)", prefix));
            }
        } else if prefix > 32 {
            return Err(anyhow!("Invalid IPv4 CIDR prefix: {} (max 32)", prefix));
        }
        return Ok(format!("{}/{}", normalized_network, prefix));
    }

    // IPv6 with brackets
    if sanitized.starts_with('[') {
        if let Some(bracket_end) = sanitized.find(']') {
            let ipv6_part = &sanitized[1..bracket_end];
            let after_bracket = &sanitized[bracket_end + 1..];
            if !is_valid_ipv6(ipv6_part) {
                return Err(anyhow!("Invalid IPv6 address: '{}'", ipv6_part));
            }
            if after_bracket.starts_with(':') {
                let port_str = &after_bracket[1..].trim();
                if port_str.is_empty() {
                    return Err(anyhow!("Invalid port format: missing port number"));
                }
                let port: u16 = port_str
                    .parse()
                    .map_err(|_| anyhow!("Invalid port number: '{}'", port_str))?;
                if port == 0 {
                    return Err(anyhow!("Port cannot be 0"));
                }
                return Ok(format!("[{}]:{}", ipv6_part, port));
            } else if !after_bracket.is_empty() {
                return Err(anyhow!(
                    "Invalid format after IPv6 address: '{}'",
                    after_bracket
                ));
            }
            return Ok(format!("[{}]", ipv6_part));
        } else {
            return Err(anyhow!("Invalid IPv6 format: missing closing bracket"));
        }
    }

    // IPv6 detection (multiple colons)
    let colon_count = sanitized.matches(':').count();
    let has_dots = sanitized.contains('.');
    let is_likely_ipv6 = colon_count >= 2 && !has_dots;

    if is_likely_ipv6 {
        if let Some(last_colon_pos) = sanitized.rfind(':') {
            let before_colon = &sanitized[..last_colon_pos];
            let after_colon = &sanitized[last_colon_pos + 1..];
            if after_colon.chars().all(|c| c.is_ascii_digit()) && !after_colon.is_empty() {
                let port: u16 = after_colon
                    .parse()
                    .map_err(|_| anyhow!("Invalid port number: '{}'", after_colon))?;
                if port == 0 {
                    return Err(anyhow!("Port cannot be 0"));
                }
                if !is_valid_ipv6(before_colon) {
                    return Err(anyhow!("Invalid IPv6 address: '{}'", before_colon));
                }
                return Ok(format!("[{}]:{}", before_colon, port));
            }
        }
        if !is_valid_ipv6(&sanitized) {
            return Err(anyhow!("Invalid IPv6 address format: '{}'", sanitized));
        }
        return Ok(format!("[{}]", sanitized));
    }

    // IPv4 or hostname with port
    if sanitized.contains(':') {
        if let Some(colon_pos) = sanitized.rfind(':') {
            let host_part = &sanitized[..colon_pos];
            let port_str = &sanitized[colon_pos + 1..];
            if port_str.is_empty() {
                return Err(anyhow!("Invalid port format: missing port number"));
            }
            let port: u16 = port_str
                .parse()
                .map_err(|_| anyhow!("Invalid port number: '{}'", port_str))?;
            if port == 0 {
                return Err(anyhow!("Port cannot be 0"));
            }
            if host_part.is_empty() {
                return Err(anyhow!("Invalid target: empty hostname/IP"));
            }
            if !is_valid_hostname_or_ipv4(host_part) {
                return Err(anyhow!("Invalid hostname or IPv4 address: '{}'", host_part));
            }
            return Ok(format!("{}:{}", host_part, port));
        }
    }

    // No port
    if sanitized.contains(' ') {
        return Err(anyhow!(
            "Invalid target format: contains spaces (did you mean to include a port?)"
        ));
    }
    if !is_valid_hostname_or_ipv4(&sanitized) {
        return Err(anyhow!(
            "Invalid hostname or IPv4 address format: '{}'",
            sanitized
        ));
    }
    Ok(sanitized.to_string())
}

// ============================================================
// IPv6 / HOSTNAME VALIDATION
// ============================================================

/// Validate IPv6 address format (basic validation).
fn is_valid_ipv6(addr: &str) -> bool {
    if addr.is_empty() {
        return false;
    }
    static IPV6_CHAR_RE: Lazy<Result<Regex, regex::Error>> =
        Lazy::new(|| Regex::new(r"^[0-9a-fA-F:.]+$"));
    let re = match &*IPV6_CHAR_RE {
        Ok(re) => re,
        Err(_) => return false,
    };
    if !re.is_match(addr) {
        return false;
    }
    let double_colon_count = addr.matches("::").count();
    if double_colon_count > 1 {
        return false;
    }
    if addr == "::" || addr == "::1" {
        return true;
    }
    // IPv4-mapped IPv6
    if addr.contains('.') {
        let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
        if parts.len() == 2 {
            let ipv4_part = parts[0];
            let ipv4_parts: Vec<&str> = ipv4_part.split('.').collect();
            if ipv4_parts.len() == 4 {
                let is_valid_ipv4 = ipv4_parts.iter().all(|part| part.parse::<u8>().is_ok());
                if is_valid_ipv4 {
                    return true;
                }
            }
        }
        return false;
    }
    let segments: Vec<&str> = addr.split(':').collect();
    if double_colon_count == 0 {
        if segments.len() != 8 {
            return false;
        }
    } else if segments.len() < 2 || segments.len() > 7 {
        return false;
    }
    for segment in &segments {
        if segment.is_empty() {
            continue;
        }
        if segment.len() > 4 {
            return false;
        }
        if !segment.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    true
}

/// Validate hostname or IPv4 address format.
fn is_valid_hostname_or_ipv4(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    static HOST_RE: Lazy<Result<Regex, regex::Error>> =
        Lazy::new(|| Regex::new(r"^[a-zA-Z0-9.\-_]+$"));
    let re = match &*HOST_RE {
        Ok(re) => re,
        Err(_) => return false,
    };
    if !re.is_match(host) {
        return false;
    }
    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() == 4 {
            let is_ipv4 = parts.iter().all(|part| part.parse::<u8>().is_ok());
            if is_ipv4 {
                return true;
            }
        }
    }
    if host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    if host.starts_with('-') || host.ends_with('-') {
        return false;
    }
    if host.len() > 253 {
        return false;
    }
    for label in host.split('.') {
        if label.len() > 63 {
            return false;
        }
    }
    true
}

// ============================================================
// DOMAIN TARGETING
// ============================================================

/// Resolve a domain name to its first IP address.
pub fn resolve_domain(domain: &str) -> Result<String> {
    let lookup = format!("{}:0", domain);
    let mut addrs = lookup
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve domain '{}'", domain))?;
    match addrs.next() {
        Some(addr) => Ok(addr.ip().to_string()),
        None => Err(anyhow!("Domain '{}' resolved to no addresses", domain)),
    }
}

/// Resolve a domain and return all IPs.
pub fn resolve_domain_all(domain: &str) -> Result<Vec<String>> {
    let lookup = format!("{}:0", domain);
    let addrs: Vec<String> = lookup
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve domain '{}'", domain))?
        .map(|a| a.ip().to_string())
        .collect();
    if addrs.is_empty() {
        return Err(anyhow!("Domain '{}' resolved to no addresses", domain));
    }
    Ok(addrs)
}

/// Check if a string looks like a domain name (not an IP).
pub fn is_domain(input: &str) -> bool {
    let trimmed = input.trim();
    // Strip protocol prefix if present
    let host = if let Some(rest) = trimmed.strip_prefix("https://") {
        rest.split('/').next().unwrap_or(rest).split(':').next().unwrap_or(rest)
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        rest.split('/').next().unwrap_or(rest).split(':').next().unwrap_or(rest)
    } else {
        trimmed.split(':').next().unwrap_or(trimmed)
    };
    if !host.contains('.') || host.is_empty() {
        return false;
    }
    if !host.chars().any(|c| c.is_alphabetic()) {
        return false; // Likely an IPv4
    }
    if host.contains("::") || host.matches(':').count() >= 2 {
        return false;
    }
    true
}

/// Interactive domain targeting prompt.
/// Asks user for protocol (http/https) and optional custom port,
/// then resolves the domain and returns (resolved_target, full_url).
pub async fn prompt_domain_target(domain: &str) -> Result<(String, String)> {
    let clean_domain = domain.trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(domain)
        .split(':')
        .next()
        .unwrap_or(domain)
        .trim();

    if clean_domain.is_empty() {
        return Err(anyhow!("Domain cannot be empty"));
    }

    crate::mprintln!("{}", format!("[*] Domain target detected: {}", clean_domain).cyan());

    // Resolve domain
    match resolve_domain_all(clean_domain) {
        Ok(ips) => {
            crate::mprintln!("{}", format!("[+] Resolved to: {}", ips.join(", ")).green());
        }
        Err(e) => {
            crate::mprintln!("{}", format!("[!] DNS resolution failed: {}", e).red());
            crate::mprintln!("{}", "[*] Continuing with domain name (some modules may fail)".yellow());
        }
    }

    // Ask protocol
    crate::mprintln!("\n{}", "Select protocol:".bold());
    crate::mprintln!("  1) https (default)");
    crate::mprintln!("  2) http");
    crate::mprintln!("  3) https with custom port");
    crate::mprintln!("  4) http with custom port");
    crate::mprintln!("  5) Use resolved IP directly (no protocol)");

    let choice = prompt_default("Choice", "1").await?;

    let (scheme, port) = match choice.as_str() {
        "1" => ("https".to_string(), 443u16),
        "2" => ("http".to_string(), 80u16),
        "3" => {
            let p = prompt_port("HTTPS port", 443).await?;
            ("https".to_string(), p)
        }
        "4" => {
            let p = prompt_port("HTTP port", 80).await?;
            ("http".to_string(), p)
        }
        "5" => {
            let ip = resolve_domain(clean_domain)?;
            let use_port = prompt_yes_no("Specify a port?", false).await?;
            if use_port {
                let p = prompt_port("Port", 80).await?;
                let target = format!("{}:{}", ip, p);
                crate::mprintln!("{}", format!("[*] Target: {}", target).green());
                return Ok((target.clone(), target));
            }
            crate::mprintln!("{}", format!("[*] Target: {}", ip).green());
            return Ok((ip.clone(), ip));
        }
        _ => {
            crate::mprintln!("{}", "[*] Defaulting to https:443".yellow());
            ("https".to_string(), 443u16)
        }
    };

    // Ask whether to target the domain name or resolved IP
    let use_ip = prompt_yes_no("Target the resolved IP instead of domain name?", false).await?;

    let host = if use_ip {
        match resolve_domain(clean_domain) {
            Ok(ip) => ip,
            Err(_) => {
                crate::mprintln!("{}", "[!] Resolution failed, using domain name".yellow());
                clean_domain.to_string()
            }
        }
    } else {
        clean_domain.to_string()
    };

    let full_url = if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
        format!("{}://{}", scheme, host)
    } else {
        format!("{}://{}:{}", scheme, host, port)
    };

    let resolved_target = if port == 443 || port == 80 {
        host.clone()
    } else {
        format!("{}:{}", host, port)
    };

    crate::mprintln!("{}", format!("[*] Target: {}", resolved_target).green());
    crate::mprintln!("{}", format!("[*] URL:    {}", full_url).cyan());

    Ok((resolved_target, full_url))
}

// ============================================================
// IP EXTRACTION
// ============================================================

/// Extract IP address or hostname from target string.
pub fn extract_ip_from_target(target: &str) -> Option<String> {
    let trimmed = target.trim();
    if let Some(slash_pos) = trimmed.find('/') {
        let network_part = &trimmed[..slash_pos];
        return extract_ip_from_target(network_part);
    }
    if trimmed.starts_with('[') {
        if let Some(bracket_end) = trimmed.find(']') {
            let ipv6_part = &trimmed[1..bracket_end];
            return Some(ipv6_part.to_string());
        }
        return Some(trimmed.trim_start_matches('[').to_string());
    }
    if let Some(colon_pos) = trimmed.rfind(':') {
        let before_colon = &trimmed[..colon_pos];
        let after_colon = &trimmed[colon_pos + 1..];
        if after_colon.chars().all(|c| c.is_ascii_digit()) && !after_colon.is_empty() {
            let colon_count = before_colon.matches(':').count();
            if colon_count >= 2 {
                return Some(before_colon.to_string());
            }
            return Some(before_colon.to_string());
        }
    }
    let colon_count = trimmed.matches(':').count();
    if colon_count >= 2 {
        return Some(trimmed.to_string());
    }
    Some(trimmed.to_string())
}


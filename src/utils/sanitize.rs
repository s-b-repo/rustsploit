// src/utils/sanitize.rs
//
// Input sanitization, validation, and shell escaping utilities.

use anyhow::{Result, anyhow};
use std::path::Path;
use url::Url;

/// Maximum length for command inputs to prevent DoS
pub(crate) const MAX_COMMAND_LENGTH: usize = 8192;

/// Maximum length for file paths to prevent DoS
const MAX_PATH_LENGTH: usize = 4096;

/// Maximum length for target strings to prevent DoS
pub(crate) const MAX_TARGET_LENGTH: usize = 2048;

/// Maximum length for module paths
pub(crate) const MAX_MODULE_PATH_LENGTH: usize = 512;

// ============================================================
// CORE SANITIZATION
// ============================================================

/// Sanitize an arbitrary string value: strip null bytes, control characters,
/// and enforce maximum length.
pub fn sanitize_string_input(input: &str) -> Result<String> {
    if input.len() > MAX_COMMAND_LENGTH {
        return Err(anyhow!("Input too long (max {} chars)", MAX_COMMAND_LENGTH));
    }
    if input.contains('\0') {
        return Err(anyhow!("Input contains null bytes"));
    }
    let sanitized: String = input.chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .collect();
    Ok(sanitized)
}

/// Validate a file path for safety: rejects path traversal, null bytes,
/// control characters, symlinks, and excessively long paths.
pub fn validate_safe_file_path(path: &str) -> Result<String> {
    let sanitized = sanitize_string_input(path)?;
    let trimmed = sanitized.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("File path cannot be empty"));
    }
    if trimmed.len() > MAX_PATH_LENGTH {
        return Err(anyhow!("File path too long (max {} chars)", MAX_PATH_LENGTH));
    }
    if trimmed.contains("..") {
        return Err(anyhow!("Path traversal detected: '..' is not allowed in file paths"));
    }
    if trimmed.contains("//") {
        return Err(anyhow!("Invalid path: double slashes are not allowed"));
    }
    let p = Path::new(trimmed);
    if let Ok(m) = p.symlink_metadata() {
        if m.file_type().is_symlink() {
            return Err(anyhow!("Symlinks are not allowed: {}", trimmed));
        }
    }
    Ok(trimmed.to_string())
}

// ============================================================
// VALIDATION
// ============================================================

/// Simple target sanitization - trims and validates basic format.
pub fn sanitize_target_simple(input: &str) -> std::result::Result<String, &'static str> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Target cannot be empty.");
    }
    if trimmed.len() > MAX_TARGET_LENGTH {
        return Err("Target value is too long.");
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("Target cannot contain control characters.");
    }
    Ok(trimmed.to_string())
}

/// Validates and sanitizes command input to prevent injection attacks and DoS.
pub fn validate_command_input(command: &str) -> Result<String> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Command cannot be empty"));
    }
    if trimmed.len() > MAX_COMMAND_LENGTH {
        return Err(anyhow!(
            "Command too long (max {} characters, got {})",
            MAX_COMMAND_LENGTH,
            trimmed.len()
        ));
    }
    let sanitized: String = trimmed
        .chars()
        .filter(|c| *c != '\0')
        .collect();
    if sanitized.is_empty() {
        return Err(anyhow!("Command contains only invalid characters"));
    }
    Ok(sanitized)
}

/// Validates file path to prevent path traversal attacks.
pub fn validate_file_path(path: &str, allow_absolute: bool) -> Result<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("File path cannot be empty"));
    }
    if trimmed.len() > MAX_PATH_LENGTH {
        return Err(anyhow!(
            "File path too long (max {} characters, got {})",
            MAX_PATH_LENGTH,
            trimmed.len()
        ));
    }
    if trimmed.contains("..") {
        return Err(anyhow!("Path traversal detected: '..' not allowed"));
    }
    if trimmed.contains("//") {
        return Err(anyhow!("Invalid path format: double slashes not allowed"));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(anyhow!("File path cannot contain control characters"));
    }
    if !allow_absolute {
        if trimmed.starts_with('/') || (cfg!(windows) && trimmed.chars().nth(1) == Some(':')) {
            return Err(anyhow!("Absolute paths not allowed"));
        }
    }
    if trimmed.contains('\x00') {
        return Err(anyhow!("File path cannot contain null bytes"));
    }
    #[cfg(windows)]
    {
        const INVALID_CHARS: &[char] = &['<', '>', ':', '"', '|', '?', '*'];
        if trimmed.chars().any(|c| INVALID_CHARS.contains(&c)) {
            return Err(anyhow!("File path contains invalid characters for Windows"));
        }
    }
    Ok(trimmed.to_string())
}

/// Validates URL input to prevent injection and ensure proper format.
pub fn validate_url(url: &str, allowed_schemes: Option<&[&str]>) -> Result<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("URL cannot be empty"));
    }
    if trimmed.len() > MAX_COMMAND_LENGTH {
        return Err(anyhow!(
            "URL too long (max {} characters, got {})",
            MAX_COMMAND_LENGTH,
            trimmed.len()
        ));
    }
    let parsed_url = Url::parse(trimmed)
        .map_err(|e| anyhow!("Invalid URL format: {}", e))?;
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
    if parsed_url.host_str().is_none() {
        return Err(anyhow!("URL must contain a host"));
    }
    Ok(trimmed.to_string())
}

// ============================================================
// SHELL ESCAPING
// ============================================================

/// Escapes shell metacharacters in a command string.
pub fn escape_shell_command(cmd: &str) -> String {
    let mut escaped = String::with_capacity(cmd.len() * 2);
    for ch in cmd.chars() {
        match ch {
            '$' | '`' | '|' | '&' | ';' | '>' | '<' | '(' | ')' | '{' | '}' | '[' | ']' | '*' | '?' | '~' | '!' | '#' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            '"' | '\'' | '\\' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Escapes command for JavaScript/Node.js execSync context.
pub fn escape_js_command(cmd: &str, escape_shell_meta: bool) -> String {
    let mut escaped = String::with_capacity(cmd.len() * 2);
    for ch in cmd.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\'' => escaped.push_str("\\'"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if escape_shell_meta && matches!(ch, '$' | '`' | '|' | '&' | ';' | '>' | '<' | '(' | ')' | '{' | '}' | '[' | ']' | '*' | '?' | '~' | '!' | '#') => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}


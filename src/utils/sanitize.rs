// src/utils/sanitize.rs
//
// Input sanitization, validation, and shell escaping utilities.

use std::path::{Component, Path};

use anyhow::{Context, Result, anyhow};
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
    let p = Path::new(trimmed);
    // Reject `..` as a path component (ParentDir), not as a substring.
    // The substring check rejects legitimate filenames like `myapp..backup`.
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(anyhow!("Path traversal detected: '..' is not allowed in file paths"));
    }
    // Fast-fail TOCTOU check: a symlink visible at this point in time. The
    // consumer is still responsible for opening with O_NOFOLLOW (or the
    // platform equivalent) since the path could be replaced between this
    // check and any subsequent open() call.
    if let Ok(m) = p.symlink_metadata()
        && m.file_type().is_symlink() {
            return Err(anyhow!("Symlinks are not allowed: {}", trimmed));
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
    if trimmed.contains('\0') {
        return Err(anyhow!("Command input contains null bytes"));
    }
    if trimmed.chars().any(|c| c.is_control() && c != '\t' && c != '\n') {
        return Err(anyhow!("Command input contains control characters"));
    }
    Ok(trimmed.to_string())
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
    // Reject `..` as a path component (ParentDir), not as a substring.
    // Substring check would also reject legitimate filenames like `foo..bar`.
    if Path::new(trimmed).components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(anyhow!("Path traversal detected: '..' not allowed"));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(anyhow!("File path cannot contain control characters"));
    }
    if !allow_absolute
        && (trimmed.starts_with('/') || (cfg!(windows) && trimmed.chars().nth(1) == Some(':'))) {
            return Err(anyhow!("Absolute paths not allowed"));
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
        .context("Invalid URL format")?;
    if let Some(schemes) = allowed_schemes {
        let scheme = parsed_url.scheme();
        if !schemes.contains(&scheme) {
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
    let mut escaped = String::with_capacity(cmd.len().saturating_mul(2));
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
    let mut escaped = String::with_capacity(cmd.len().saturating_mul(2));
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


// src/utils/prompt.rs
//
// Interactive prompt functions and config-aware prompt wrappers.
// These check ModuleConfig.custom_prompts first, falling back
// to interactive stdin if no value is pre-set.
//
// All prompt functions are async — stdin reads are offloaded to
// a blocking thread via `tokio::task::spawn_blocking` so they
// never stall the tokio runtime (background jobs, API server, etc.
// continue to make progress while the user is typing).

use anyhow::{Result, anyhow, Context};
use colored::*;
use std::io::Write;
use std::path::Path;

use super::sanitize::{sanitize_string_input, validate_safe_file_path};

// ============================================================
// INTERACTIVE PROMPTS
// ============================================================

/// Reads input from stdin, treating it as a literal string payload.
/// - Enforces max length (MAX_COMMAND_LENGTH).
/// - Strips null bytes and control characters.
/// - Returns sanitized text (trimmed).
///
/// The blocking `stdin().read_line()` call runs on a dedicated OS thread
/// so the tokio runtime is free to drive other tasks.
async fn read_safe_input() -> Result<String> {
    std::io::stdout().flush().context("Failed to flush stdout")?;
    let raw = tokio::task::spawn_blocking(|| {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).map(|_| s)
    })
    .await
    .context("Blocking task panicked")?
    .context("Failed to read input")?;
    let trimmed = raw.trim().to_string();
    sanitize_string_input(&trimmed)
}

/// Prompts the user for input, ensuring it is not empty.
pub async fn prompt_required(msg: &str) -> Result<String> {
    loop {
        print!("{}", format!("{}: ", msg).cyan().bold());
        let input = read_safe_input().await?;
        if !input.is_empty() {
             return Ok(input);
        }
        crate::mprintln!("{}", "This field is required.".yellow());
    }
}

/// Prompts the user for input, using a default value if empty.
pub async fn prompt_default(msg: &str, default: &str) -> Result<String> {
    print!("{}", format!("{} [{}]: ", msg, default).cyan().bold());
    let input = read_safe_input().await?;
    Ok(if input.is_empty() {
        default.to_string()
    } else {
        input
    })
}

/// Prompts the user for a yes/no answer.
pub async fn prompt_yes_no(msg: &str, default_yes: bool) -> Result<bool> {
    let default = if default_yes { "y" } else { "n" };
    loop {
        print!("{}", format!("{} (y/n) [{}]: ", msg, default).cyan().bold());
        let input = read_safe_input().await?;
        match input.to_lowercase().as_str() {
            ""        => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no"  => return Ok(false),
            _ => crate::mprintln!("{}", "Invalid input. Please enter 'y' or 'n'.".yellow()),
        }
    }
}

pub async fn prompt_int_range(msg: &str, default: i64, min: i64, max: i64) -> Result<i64> {
    loop {
        let input = prompt_default(msg, &default.to_string()).await?;
        match input.trim().parse::<i64>() {
            Ok(n) if n >= min && n <= max => return Ok(n),
            _ => crate::mprintln!("{}", format!("Please enter a number between {} and {}.", min, max).yellow()),
        }
    }
}

pub async fn prompt_port(msg: &str, default: u16) -> Result<u16> {
    loop {
        let input = prompt_default(msg, &default.to_string()).await?;
        match input.parse::<u16>() {
            Ok(n) if n > 0 => return Ok(n),
            _ => crate::mprintln!("{}", "Please enter a valid port (1-65535).".yellow()),
        }
    }
}

/// Prompts for an existing file path.
/// Validates against path traversal, symlinks, and control characters.
pub async fn prompt_existing_file(msg: &str) -> Result<String> {
    loop {
        let candidate = prompt_required(msg).await?;
        match validate_safe_file_path(&candidate) {
            Ok(safe_path) => {
                if Path::new(&safe_path).is_file() {
                    return Ok(safe_path);
                } else {
                    crate::mprintln!("{}", format!("File '{}' does not exist or is not a regular file.", safe_path).yellow());
                }
            }
            Err(e) => {
                crate::mprintln!("{}", format!("Invalid path: {}", e).yellow());
            }
        }
    }
}

/// Prompts for a wordlist file path.
pub async fn prompt_wordlist(msg: &str) -> Result<String> {
    prompt_existing_file(msg).await
}

// ============================================================
// CONFIG-AWARE PROMPT WRAPPERS
// ============================================================

/// Config-aware required prompt.
/// Priority: custom_prompts > run_context target > global_options > interactive stdin
pub async fn cfg_prompt_required(key: &str, msg: &str) -> Result<String> {
    let config = crate::config::get_module_config();
    if let Some(val) = config.custom_prompts.get(key) {
        let sanitized = sanitize_string_input(val)
            .map_err(|e| anyhow!("Invalid value for '{}': {}", key, e))?;
        if !sanitized.is_empty() {
            return Ok(sanitized);
        }
    }
    // For "target" key, check the per-request RunContext target (API mode)
    if key == "target" {
        if let Some(val) = crate::config::get_run_target() {
            let sanitized = sanitize_string_input(&val)
                .map_err(|e| anyhow!("Invalid run target: {}", e))?;
            if !sanitized.is_empty() {
                return Ok(sanitized);
            }
        }
    }
    // Check global options (setg)
    if let Some(val) = crate::global_options::GLOBAL_OPTIONS.get(key).await {
        let sanitized = sanitize_string_input(&val)
            .map_err(|e| anyhow!("Invalid global option for '{}': {}", key, e))?;
        if !sanitized.is_empty() {
            return Ok(sanitized);
        }
    }
    if config.api_mode {
        return Err(anyhow!("Missing required prompt key '{}' (prompt: '{}'). Supply it in the 'prompts' field of the API request.", key, msg));
    }
    prompt_required(msg).await
}

/// Config-aware prompt with default value.
/// Priority: custom_prompts > global_options > interactive stdin
pub async fn cfg_prompt_default(key: &str, msg: &str, default: &str) -> Result<String> {
    let config = crate::config::get_module_config();
    if let Some(val) = config.custom_prompts.get(key) {
        let sanitized = sanitize_string_input(val)
            .map_err(|e| anyhow!("Invalid value for '{}': {}", key, e))?;
        return Ok(if sanitized.is_empty() { default.to_string() } else { sanitized });
    }
    // Check global options (setg)
    if let Some(val) = crate::global_options::GLOBAL_OPTIONS.get(key).await {
        let sanitized = sanitize_string_input(&val)
            .map_err(|e| anyhow!("Invalid global option for '{}': {}", key, e))?;
        if !sanitized.is_empty() {
            return Ok(sanitized);
        }
    }
    if config.api_mode {
        return Ok(default.to_string());
    }
    prompt_default(msg, default).await
}

/// Config-aware yes/no prompt.
/// Priority: custom_prompts > global_options > interactive stdin
pub async fn cfg_prompt_yes_no(key: &str, msg: &str, default_yes: bool) -> Result<bool> {
    let config = crate::config::get_module_config();
    if let Some(val) = config.custom_prompts.get(key) {
        let sanitized = sanitize_string_input(val)
            .map_err(|e| anyhow!("Invalid value for '{}': {}", key, e))?;
        match sanitized.to_lowercase().trim() {
            "y" | "yes" | "true" | "1" => return Ok(true),
            "n" | "no" | "false" | "0" => return Ok(false),
            other if !other.is_empty() && config.api_mode => {
                return Err(anyhow!(
                    "Invalid boolean value for '{}': '{}'. Use y/n/yes/no/true/false/1/0.",
                    key, other
                ));
            }
            _ => {} // fall through
        }
    }
    // Check global options (setg)
    if let Some(val) = crate::global_options::GLOBAL_OPTIONS.get(key).await {
        match val.to_lowercase().trim() {
            "y" | "yes" | "true" | "1" => return Ok(true),
            "n" | "no" | "false" | "0" => return Ok(false),
            _ => {} // fall through
        }
    }
    if config.api_mode {
        return Ok(default_yes);
    }
    prompt_yes_no(msg, default_yes).await
}

/// Config-aware port prompt.
/// Priority: custom_prompts > global_options > interactive stdin
pub async fn cfg_prompt_port(key: &str, msg: &str, default: u16) -> Result<u16> {
    let config = crate::config::get_module_config();
    if let Some(val) = config.custom_prompts.get(key) {
        let sanitized = sanitize_string_input(val)
            .map_err(|e| anyhow!("Invalid value for '{}': {}", key, e))?;
        let trimmed = sanitized.trim();
        if !trimmed.is_empty() {
            match trimmed.parse::<u16>() {
                Ok(p) if p > 0 => return Ok(p),
                Ok(_) => return Err(anyhow!("Invalid port for '{}': port cannot be 0", key)),
                Err(_) => {
                    if config.api_mode {
                        return Err(anyhow!("Invalid port value for '{}': '{}'", key, trimmed));
                    }
                }
            }
        }
    }
    // Check global options (setg)
    if let Some(val) = crate::global_options::GLOBAL_OPTIONS.get(key).await {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            match trimmed.parse::<u16>() {
                Ok(p) if p > 0 => return Ok(p),
                _ => {} // fall through to interactive
            }
        }
    }
    if config.api_mode {
        return Ok(default);
    }
    prompt_port(msg, default).await
}

/// Config-aware file path prompt (validates file exists).
/// Priority: custom_prompts > global_options > interactive stdin
pub async fn cfg_prompt_existing_file(key: &str, msg: &str) -> Result<String> {
    let config = crate::config::get_module_config();
    if let Some(val) = config.custom_prompts.get(key) {
        if !val.is_empty() {
            let safe_path = validate_safe_file_path(val)
                .map_err(|e| anyhow!("Invalid file path for '{}': {}", key, e))?;
            if Path::new(&safe_path).is_file() {
                return Ok(safe_path);
            }
            return Err(anyhow!("File not found: {}", safe_path));
        }
    }
    // Check global options (setg)
    if let Some(val) = crate::global_options::GLOBAL_OPTIONS.get(key).await {
        if !val.is_empty() {
            let safe_path = validate_safe_file_path(&val)
                .map_err(|e| anyhow!("Invalid global file path for '{}': {}", key, e))?;
            if Path::new(&safe_path).is_file() {
                return Ok(safe_path);
            }
        }
    }
    if config.api_mode {
        return Err(anyhow!("Missing required prompt key '{}' (prompt: '{}'). Supply a valid file path in the 'prompts' field.", key, msg));
    }
    prompt_existing_file(msg).await
}

/// Config-aware integer range prompt.
/// Priority: custom_prompts > global_options > interactive stdin
pub async fn cfg_prompt_int_range(key: &str, msg: &str, default: i64, min: i64, max: i64) -> Result<i64> {
    let config = crate::config::get_module_config();
    if let Some(val) = config.custom_prompts.get(key) {
        let sanitized = sanitize_string_input(val)
            .map_err(|e| anyhow!("Invalid value for '{}': {}", key, e))?;
        let trimmed = sanitized.trim();
        if !trimmed.is_empty() {
            match trimmed.parse::<i64>() {
                Ok(n) if n >= min && n <= max => return Ok(n),
                Ok(n) => {
                    if config.api_mode {
                        return Err(anyhow!(
                            "Value for '{}' out of range: {} (must be {}-{})",
                            key, n, min, max
                        ));
                    }
                }
                Err(_) => {
                    if config.api_mode {
                        return Err(anyhow!("Invalid numeric value for '{}': '{}'", key, trimmed));
                    }
                }
            }
        }
    }
    // Check global options (setg)
    if let Some(val) = crate::global_options::GLOBAL_OPTIONS.get(key).await {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            if let Ok(n) = trimmed.parse::<i64>() {
                if n >= min && n <= max {
                    return Ok(n);
                }
            }
        }
    }
    if config.api_mode {
        return Ok(default);
    }
    prompt_int_range(msg, default, min, max).await
}

/// Config-aware output file prompt.
pub async fn cfg_prompt_output_file(key: &str, msg: &str, default: &str) -> Result<String> {
    let raw = cfg_prompt_default(key, msg, default).await?;
    let filename = Path::new(&raw)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    if filename.is_empty() || filename.starts_with('.') {
        return Err(anyhow!("Invalid output filename: '{}'. Cannot be empty or start with '.'", raw));
    }
    if filename.len() > 255 {
        return Err(anyhow!("Output filename too long (max 255 chars)"));
    }
    Ok(filename)
}

/// Config-aware wordlist prompt.
/// Priority: custom_prompts > global_options > interactive stdin
pub async fn cfg_prompt_wordlist(key: &str, msg: &str) -> Result<String> {
    let config = crate::config::get_module_config();
    if let Some(val) = config.custom_prompts.get(key) {
        if !val.is_empty() {
            let safe_path = validate_safe_file_path(val)
                .map_err(|e| anyhow!("Invalid wordlist path for '{}': {}", key, e))?;
            if Path::new(&safe_path).is_file() {
                return Ok(safe_path);
            }
            return Err(anyhow!("Wordlist file not found: '{}'", val));
        }
    }
    // Check global options (setg)
    if let Some(val) = crate::global_options::GLOBAL_OPTIONS.get(key).await {
        if !val.is_empty() {
            if let Ok(safe_path) = validate_safe_file_path(&val) {
                if Path::new(&safe_path).is_file() {
                    return Ok(safe_path);
                }
            }
        }
    }
    if config.api_mode {
        return Err(anyhow!("Missing required prompt key '{}' (prompt: '{}'). Supply it in the 'prompts' field of the API request.", key, msg));
    }
    prompt_wordlist(msg).await
}

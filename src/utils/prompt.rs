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

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use colored::*;

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

/// Maximum number of times any interactive prompt will retry on invalid input
/// before giving up. Prevents a closed/redirected stdin from pinning a worker
/// in an infinite loop.
const MAX_PROMPT_RETRIES: usize = 100;

/// Prompts the user for input, ensuring it is not empty.
pub async fn prompt_required(msg: &str) -> Result<String> {
    // Bound the retry loop so a closed/looping stdin can't pin a worker.
    for _ in 0..MAX_PROMPT_RETRIES {
        print!("{}", format!("{}: ", msg).cyan().bold());
        let input = read_safe_input().await?;
        if !input.is_empty() {
             return Ok(input);
        }
        crate::mprintln!("{}", "This field is required.".yellow());
    }
    Err(anyhow!("Prompt aborted after {} empty inputs", MAX_PROMPT_RETRIES))
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
    for _ in 0..MAX_PROMPT_RETRIES {
        print!("{}", format!("{} (y/n) [{}]: ", msg, default).cyan().bold());
        let input = read_safe_input().await?;
        match input.to_lowercase().as_str() {
            ""        => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no"  => return Ok(false),
            _ => crate::mprintln!("{}", "Invalid input. Please enter 'y' or 'n'.".yellow()),
        }
    }
    Err(anyhow!("Yes/no prompt aborted after {} invalid inputs", MAX_PROMPT_RETRIES))
}

pub async fn prompt_int_range(msg: &str, default: i64, min: i64, max: i64) -> Result<i64> {
    for _ in 0..MAX_PROMPT_RETRIES {
        let input = prompt_default(msg, &default.to_string()).await?;
        match input.trim().parse::<i64>() {
            Ok(n) if n >= min && n <= max => return Ok(n),
            _ => crate::mprintln!("{}", format!("Please enter a number between {} and {}.", min, max).yellow()),
        }
    }
    Err(anyhow!("Integer range prompt aborted after {} invalid inputs", MAX_PROMPT_RETRIES))
}

pub async fn prompt_port(msg: &str, default: u16) -> Result<u16> {
    for _ in 0..MAX_PROMPT_RETRIES {
        let input = prompt_default(msg, &default.to_string()).await?;
        match input.parse::<u16>() {
            Ok(n) if n > 0 => return Ok(n),
            _ => crate::mprintln!("{}", "Please enter a valid port (1-65535).".yellow()),
        }
    }
    Err(anyhow!("Port prompt aborted after {} invalid inputs", MAX_PROMPT_RETRIES))
}

/// Prompts for an existing file path.
/// Validates against path traversal, symlinks, and control characters.
pub async fn prompt_existing_file(msg: &str) -> Result<String> {
    for _ in 0..MAX_PROMPT_RETRIES {
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
    Err(anyhow!("Existing-file prompt aborted after {} invalid inputs", MAX_PROMPT_RETRIES))
}

/// Prompts for a wordlist file path.
pub async fn prompt_wordlist(msg: &str) -> Result<String> {
    prompt_existing_file(msg).await
}

// ============================================================
// SHARED PROMPT CACHE (MASS SCAN / CIDR)
// ============================================================

/// Check the shared prompt cache (active in mass scan / CIDR / file modes).
///
/// When a prompt cache is active, the first task to request a given key will
/// run `fallback` (typically the interactive prompt) while holding the cache
/// lock, serializing access so only ONE prompt appears per key. All subsequent
/// tasks receive the cached answer instantly.
///
/// Returns `None` if no prompt cache is active (single-target / normal mode).
async fn cached_prompt<F, Fut>(key: &str, fallback: F) -> Option<Result<String>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<String>>,
{
    // Global batch cache — works even when task-locals don't propagate
    if crate::context::is_batch_active() {
        let cache = crate::context::batch_cache();
        let mut guard = cache.lock().await;
        let batch_gen = crate::context::batch_generation();
        if crate::context::cache_generation() != batch_gen {
            guard.clear();
            crate::context::set_cache_generation(batch_gen);
        }
        if let Some(val) = guard.get(key) {
            return Some(Ok(val.clone()));
        }
        let result = fallback().await;
        if let Ok(ref val) = result {
            crate::context::cache_insert(&mut guard, key.to_string(), val.clone());
        }
        return Some(result);
    }

    // Task-local prompt cache
    let cache = crate::context::RUN_CONTEXT
        .try_with(|ctx| ctx.prompt_cache.clone())
        .ok()
        .flatten()?;
    let mut guard = cache.lock().await;
    if let Some(val) = guard.get(key) {
        return Some(Ok(val.clone()));
    }
    let result = fallback().await;
    if let Ok(ref val) = result {
        crate::context::cache_insert(&mut guard, key.to_string(), val.clone());
    }
    Some(result)
}

// ============================================================
// PERSIST PROMPT ANSWERS FOR BATCH REUSE
// ============================================================

/// After prompting the user interactively, store the answer in global options
/// so that batch-mode tasks (which skip interactive prompts) can find it.
/// This enables the "configure once, run against all targets" pattern.
async fn persist_prompt_answer(key: &str, value: &str) {
    crate::tenant::resolve()
        .global_options()
        .set(key, value)
        .await;
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
            .with_context(|| format!("Invalid value for '{}'", key))?;
        if !sanitized.is_empty() {
            return Ok(sanitized);
        }
    }
    // For "target" key, check the per-request RunContext target (API mode)
    if key == "target"
        && let Some(val) = crate::config::get_run_target() {
            let sanitized = sanitize_string_input(&val)
                .context("Invalid run target")?;
            if !sanitized.is_empty() {
                return Ok(sanitized);
            }
        }
    // Check global options (setg)
    if let Some(val) = crate::tenant::resolve().global_options().get(key).await {
        let sanitized = sanitize_string_input(&val)
            .with_context(|| format!("Invalid global option for '{}'", key))?;
        if !sanitized.is_empty() {
            return Ok(sanitized);
        }
    }
    if config.api_mode || crate::context::is_batch_active() {
        return Err(anyhow!("Missing required prompt key '{}' (prompt: '{}'). Set it with: setg {} <value>", key, msg, key));
    }
    // Shared prompt cache: prompt once, reuse for all concurrent tasks
    let msg_owned = msg.to_string();
    if let Some(result) = cached_prompt(key, || async move {
        prompt_required(&msg_owned).await
    }).await {
        if let Ok(ref val) = result {
            persist_prompt_answer(key, val).await;
        }
        return result;
    }
    let result = prompt_required(msg).await;
    if let Ok(ref val) = result {
        persist_prompt_answer(key, val).await;
    }
    result
}

/// Config-aware prompt with default value.
/// Priority: custom_prompts > global_options > interactive stdin
pub async fn cfg_prompt_default(key: &str, msg: &str, default: &str) -> Result<String> {
    let config = crate::config::get_module_config();
    if let Some(val) = config.custom_prompts.get(key) {
        let sanitized = sanitize_string_input(val)
            .with_context(|| format!("Invalid value for '{}'", key))?;
        return Ok(if sanitized.is_empty() { default.to_string() } else { sanitized });
    }
    // Check global options (setg)
    if let Some(val) = crate::tenant::resolve().global_options().get(key).await {
        let sanitized = sanitize_string_input(&val)
            .with_context(|| format!("Invalid global option for '{}'", key))?;
        if !sanitized.is_empty() {
            return Ok(sanitized);
        }
    }
    if config.api_mode || crate::context::is_batch_active() {
        return Ok(default.to_string());
    }
    // Shared prompt cache: prompt once, reuse for all concurrent tasks
    let msg_owned = msg.to_string();
    let default_owned = default.to_string();
    if let Some(result) = cached_prompt(key, || async move {
        prompt_default(&msg_owned, &default_owned).await
    }).await {
        if let Ok(ref val) = result {
            persist_prompt_answer(key, val).await;
        }
        return result;
    }
    let result = prompt_default(msg, default).await;
    if let Ok(ref val) = result {
        persist_prompt_answer(key, val).await;
    }
    result
}

/// Config-aware yes/no prompt.
/// Priority: custom_prompts > global_options > interactive stdin
pub async fn cfg_prompt_yes_no(key: &str, msg: &str, default_yes: bool) -> Result<bool> {
    let config = crate::config::get_module_config();
    if let Some(val) = config.custom_prompts.get(key) {
        let sanitized = sanitize_string_input(val)
            .with_context(|| format!("Invalid value for '{}'", key))?;
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
    if let Some(val) = crate::tenant::resolve().global_options().get(key).await {
        match val.to_lowercase().trim() {
            "y" | "yes" | "true" | "1" => return Ok(true),
            "n" | "no" | "false" | "0" => return Ok(false),
            _ => {} // fall through
        }
    }
    if config.api_mode || crate::context::is_batch_active() {
        return Ok(default_yes);
    }
    // Shared prompt cache: prompt once, reuse for all concurrent tasks
    let msg_owned = msg.to_string();
    if let Some(result) = cached_prompt(key, || async move {
        let val = prompt_yes_no(&msg_owned, default_yes).await?;
        Ok(if val { "y".to_string() } else { "n".to_string() })
    }).await {
        if let Ok(ref val) = result {
            persist_prompt_answer(key, val).await;
        }
        return result.map(|v| v == "y");
    }
    let result = prompt_yes_no(msg, default_yes).await;
    if let Ok(val) = result {
        persist_prompt_answer(key, if val { "y" } else { "n" }).await;
        return Ok(val);
    }
    result
}

/// Config-aware port prompt.
/// Priority: custom_prompts > global_options > interactive stdin
pub async fn cfg_prompt_port(key: &str, msg: &str, default: u16) -> Result<u16> {
    let config = crate::config::get_module_config();
    if let Some(val) = config.custom_prompts.get(key) {
        let sanitized = sanitize_string_input(val)
            .with_context(|| format!("Invalid value for '{}'", key))?;
        let trimmed = sanitized.trim();
        if !trimmed.is_empty() {
            match trimmed.parse::<u16>() {
                Ok(p) if p > 0 => return Ok(p),
                Ok(_) => return Err(anyhow!("Invalid port for '{}': port cannot be 0", key)),
                Err(e) => {
                    tracing::debug!("port parse error for '{key}': {e}");
                    if config.api_mode {
                        return Err(anyhow!("Invalid port value for '{}': '{}'", key, trimmed));
                    }
                }
            }
        }
    }
    // Check global options (setg)
    if let Some(val) = crate::tenant::resolve().global_options().get(key).await {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            match trimmed.parse::<u16>() {
                Ok(p) if p > 0 => return Ok(p),
                _ => {} // fall through to interactive
            }
        }
    }
    if config.api_mode || crate::context::is_batch_active() {
        return Ok(default);
    }
    // Shared prompt cache: prompt once, reuse for all concurrent tasks
    let msg_owned = msg.to_string();
    if let Some(result) = cached_prompt(key, || async move {
        let val = prompt_port(&msg_owned, default).await?;
        Ok(val.to_string())
    }).await {
        if let Ok(ref val) = result {
            persist_prompt_answer(key, val).await;
        }
        let val = result?;
        return val.parse::<u16>().map_err(|e| anyhow!("Invalid cached port value for '{}': {e}", key));
    }
    let result = prompt_port(msg, default).await;
    if let Ok(val) = result {
        persist_prompt_answer(key, &val.to_string()).await;
        return Ok(val);
    }
    result
}

/// Config-aware file path prompt (validates file exists).
/// Priority: custom_prompts > global_options > interactive stdin
pub async fn cfg_prompt_existing_file(key: &str, msg: &str) -> Result<String> {
    let config = crate::config::get_module_config();
    if let Some(val) = config.custom_prompts.get(key)
        && !val.is_empty() {
            let safe_path = validate_safe_file_path(val)
                .with_context(|| format!("Invalid file path for '{}'", key))?;
            if Path::new(&safe_path).is_file() {
                return Ok(safe_path);
            }
            return Err(anyhow!("File not found: {}", safe_path));
        }
    // Check global options (setg)
    if let Some(val) = crate::tenant::resolve().global_options().get(key).await
        && !val.is_empty() {
            let safe_path = validate_safe_file_path(&val)
                .with_context(|| format!("Invalid global file path for '{}'", key))?;
            if Path::new(&safe_path).is_file() {
                return Ok(safe_path);
            }
        }
    if config.api_mode || crate::context::is_batch_active() {
        return Err(anyhow!("Missing required prompt key '{}' (prompt: '{}'). Set it with: setg {} <path>", key, msg, key));
    }
    // Shared prompt cache: prompt once, reuse for all concurrent tasks
    let msg_owned = msg.to_string();
    if let Some(result) = cached_prompt(key, || async move {
        prompt_existing_file(&msg_owned).await
    }).await {
        if let Ok(ref val) = result {
            persist_prompt_answer(key, val).await;
        }
        return result;
    }
    let result = prompt_existing_file(msg).await;
    if let Ok(ref val) = result {
        persist_prompt_answer(key, val).await;
    }
    result
}

/// Config-aware integer range prompt.
/// Priority: custom_prompts > global_options > interactive stdin
pub async fn cfg_prompt_int_range(key: &str, msg: &str, default: i64, min: i64, max: i64) -> Result<i64> {
    let config = crate::config::get_module_config();
    if let Some(val) = config.custom_prompts.get(key) {
        let sanitized = sanitize_string_input(val)
            .with_context(|| format!("Invalid value for '{}'", key))?;
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
                Err(e) => {
                    tracing::debug!("numeric parse error for '{key}': {e}");
                    if config.api_mode {
                        return Err(anyhow!("Invalid numeric value for '{}': '{}'", key, trimmed));
                    }
                }
            }
        }
    }
    // Check global options (setg)
    if let Some(val) = crate::tenant::resolve().global_options().get(key).await {
        let trimmed = val.trim();
        if !trimmed.is_empty()
            && let Ok(n) = trimmed.parse::<i64>()
                && n >= min && n <= max {
                    return Ok(n);
                }
    }
    if config.api_mode || crate::context::is_batch_active() {
        return Ok(default);
    }
    // Shared prompt cache: prompt once, reuse for all concurrent tasks
    let msg_owned = msg.to_string();
    if let Some(result) = cached_prompt(key, || async move {
        let val = prompt_int_range(&msg_owned, default, min, max).await?;
        Ok(val.to_string())
    }).await {
        if let Ok(ref val) = result {
            persist_prompt_answer(key, val).await;
        }
        let val = result?;
        return val.parse::<i64>().map_err(|e| anyhow!("Invalid cached int value for '{}': {e}", key));
    }
    let result = prompt_int_range(msg, default, min, max).await;
    if let Ok(val) = result {
        persist_prompt_answer(key, &val.to_string()).await;
        return Ok(val);
    }
    result
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
    if let Some(val) = config.custom_prompts.get(key)
        && !val.is_empty() {
            let safe_path = validate_safe_file_path(val)
                .with_context(|| format!("Invalid wordlist path for '{}'", key))?;
            if Path::new(&safe_path).is_file() {
                return Ok(safe_path);
            }
            return Err(anyhow!("Wordlist file not found: '{}'", val));
        }
    // Check global options (setg)
    if let Some(val) = crate::tenant::resolve().global_options().get(key).await
        && !val.is_empty()
            && let Ok(safe_path) = validate_safe_file_path(&val)
                && Path::new(&safe_path).is_file() {
                    return Ok(safe_path);
                }
    if config.api_mode || crate::context::is_batch_active() {
        return Err(anyhow!("Missing required prompt key '{}' (prompt: '{}'). Set it with: setg {} <path>", key, msg, key));
    }
    // Shared prompt cache: prompt once, reuse for all concurrent tasks
    let msg_owned = msg.to_string();
    if let Some(result) = cached_prompt(key, || async move {
        prompt_wordlist(&msg_owned).await
    }).await {
        if let Ok(ref val) = result {
            persist_prompt_answer(key, val).await;
        }
        return result;
    }
    let result = prompt_wordlist(msg).await;
    if let Ok(ref val) = result {
        persist_prompt_answer(key, val).await;
    }
    result
}

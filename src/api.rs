use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use subtle::ConstantTimeEq;
use tower::ServiceBuilder;
use tower_http::{
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};

use crate::commands;

/// Maximum request body size (1MB)
const MAX_REQUEST_BODY_SIZE: usize = 1024 * 1024;

// ─── IP Whitelist ───────────────────────────────────────────────────

/// Load IP whitelist from ~/.rustsploit/ip_whitelist.conf
/// File format: one IP per line, '#' comments, blank lines ignored
fn load_ip_whitelist() -> Vec<String> {
    let path = dirs_path().join("ip_whitelist.conf");
    if !path.exists() {
        return Vec::new();
    }
    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            contents
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| l.to_string())
                .collect()
        }
        Err(e) => {
            eprintln!("[WARN] Failed to read IP whitelist {}: {}", path.display(), e);
            Vec::new()
        }
    }
}

/// Get the rustsploit config directory (~/.rustsploit/)
fn dirs_path() -> std::path::PathBuf {
    let home = home::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    home.join(".rustsploit")
}

// ─── State ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ApiState {
    api_key: String,
    verbose: bool,
    /// Optional IP whitelist — if non-empty, only these IPs can access the API
    ip_whitelist: Arc<Vec<String>>,
    /// Persistent module selection (mirrors ShellContext.current_module)
    current_module: Arc<Mutex<Option<String>>>,
    /// Per-IP rate limiter: IP -> (request_count, window_start)
    rate_limiter: Arc<Mutex<HashMap<std::net::IpAddr, (u32, Instant)>>>,
}

/// Max requests per IP per window
const RATE_LIMIT_MAX_REQUESTS: u32 = 10;
/// Rate limit window duration (1 second)
const RATE_LIMIT_WINDOW_SECS: u64 = 1;

// ─── Request / Response Types ───────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct ApiResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

fn ok_response(message: impl Into<String>, data: Option<serde_json::Value>) -> ApiResponse {
    ApiResponse {
        success: true,
        message: message.into(),
        data,
        error_code: None,
    }
}

fn err_response(message: impl Into<String>, code: &str) -> ApiResponse {
    ApiResponse {
        success: false,
        message: message.into(),
        data: None,
        error_code: Some(code.to_string()),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunModuleRequest {
    pub module: String,
    pub target: String,
    // Optional module config fields (passed to modules like the CLI would)
    pub port: Option<u16>,
    pub username_wordlist: Option<String>,
    pub password_wordlist: Option<String>,
    pub concurrency: Option<usize>,
    pub stop_on_success: Option<bool>,
    pub save_results: Option<bool>,
    pub output_file: Option<String>,
    pub verbose: Option<bool>,
    pub combo_mode: Option<bool>,
    /// Generic prompt overrides — any key/value pair that modules read via
    /// `cfg_prompt_*()`. Examples: {"mode": "1", "timeout": "5", "retries": "3"}
    pub prompts: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize)]
pub struct SetTargetRequest {
    pub target: String,
}

#[derive(Serialize, Deserialize)]
pub struct HoneypotCheckRequest {
    pub target: String,
}

#[derive(Serialize, Deserialize)]
pub struct ExecRequest {
    /// Single command (backward compatible)
    pub command: Option<String>,
    /// Array of commands for chaining (preferred, more secure than string splitting)
    pub commands: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
struct ExecResult {
    command: String,
    success: bool,
    output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
}

// ─── Validation Helpers ─────────────────────────────────────────────

fn validate_module_name(module: &str) -> bool {
    !module.is_empty()
        && module.len() <= 256
        && module.chars().all(|c| matches!(c, 'a'..='z' | '0'..='9' | '/' | '_' | '-'))
}

fn validate_target(target: &str) -> bool {
    !target.is_empty() && target.len() <= 2048 && !target.chars().any(|c| c.is_control())
}

/// Check if a target IP is a blocked internal/metadata address.
/// Blocks cloud metadata IPs (169.254.0.0/16), null addresses (0.0.0.0), etc.
fn is_blocked_target(target: &str) -> bool {
    let ip_str = target.split(':').next().unwrap_or(target);
    if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                // Block link-local / cloud metadata (169.254.0.0/16)
                if v4.octets()[0] == 169 && v4.octets()[1] == 254 {
                    return true;
                }
                // Block 0.0.0.0
                if v4.is_unspecified() {
                    return true;
                }
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_unspecified() {
                    return true;
                }
            }
        }
    }
    // Also check raw string for targets like "169.254.169.254:80"
    ip_str.starts_with("169.254.")
}

/// Check if exec input contains shell metacharacters that could enable injection.
fn contains_shell_metacharacters(input: &str) -> bool {
    input.chars().any(|c| matches!(c, '&' | '|' | ';' | '`' | '$' | '>' | '<' | '\n' | '\r'))
        || input.contains("$(")
        || input.contains("${")
}

// ─── Auth Middleware ────────────────────────────────────────────────

async fn auth_middleware(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    // Rate limiting (runs first, before auth, to prevent unauthenticated floods)
    {
        let ip = addr.ip();
        let now = Instant::now();
        if let Ok(mut limiter) = state.rate_limiter.lock() {
            let entry = limiter.entry(ip).or_insert((0, now));
            if now.duration_since(entry.1).as_secs() >= RATE_LIMIT_WINDOW_SECS {
                *entry = (1, now);
            } else {
                entry.0 += 1;
                if entry.0 > RATE_LIMIT_MAX_REQUESTS {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(err_response(
                            format!(
                                "Rate limit exceeded: max {} requests per second",
                                RATE_LIMIT_MAX_REQUESTS
                            ),
                            "RATE_LIMITED",
                        )),
                    )
                        .into_response();
                }
            }
        }
    }

    // IP whitelist check (if configured)
    if !state.ip_whitelist.is_empty() {
        let client_ip = addr.ip().to_string();
        if !state.ip_whitelist.iter().any(|allowed| allowed == &client_ip) {
            return (
                StatusCode::FORBIDDEN,
                Json(err_response(
                    format!("IP {} not in whitelist", client_ip),
                    "IP_BLOCKED",
                )),
            )
                .into_response();
        }
    }

    // Extract API key from Authorization header
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let provided_key = if let Some(key) = auth_header.strip_prefix("Bearer ") {
        key
    } else if let Some(key) = auth_header.strip_prefix("ApiKey ") {
        key
    } else {
        auth_header
    };

    // Constant-time comparison
    let valid = provided_key.as_bytes().ct_eq(state.api_key.as_bytes());
    if !bool::from(valid) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(err_response("Invalid API key", "AUTH_FAILED")),
        )
            .into_response();
    }

    if state.verbose {
        eprintln!("[API] Authenticated request from {}", addr.ip());
    }

    next.run(request).await
}

// ─── Endpoint Handlers ─────────────────────────────────────────────

async fn health_check() -> Json<ApiResponse> {
    Json(ok_response("API is running", None))
}

/// GET /api/modules — list all modules (like CLI `modules`)
async fn list_modules() -> Json<ApiResponse> {
    let modules = commands::discover_modules();
    let mut exploits = Vec::new();
    let mut scanners = Vec::new();
    let mut creds = Vec::new();

    for module in &modules {
        if module.starts_with("exploits/") {
            exploits.push(module.clone());
        } else if module.starts_with("scanners/") {
            scanners.push(module.clone());
        } else if module.starts_with("creds/") {
            creds.push(module.clone());
        }
    }

    Json(ok_response(
        format!("{} modules available", modules.len()),
        Some(serde_json::json!({
            "total": modules.len(),
            "exploits": exploits,
            "scanners": scanners,
            "creds": creds,
        })),
    ))
}

/// GET /api/modules/search?q=keyword — search modules (like CLI `find`)
async fn search_modules(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<ApiResponse> {
    let keyword = params.get("q").map(|s| s.as_str()).unwrap_or("");

    if keyword.is_empty() {
        return Json(err_response(
            "Missing search query parameter 'q'",
            "INVALID_INPUT",
        ));
    }

    let modules = commands::discover_modules();
    let kw = keyword.to_lowercase();
    let matches: Vec<String> = modules
        .into_iter()
        .filter(|m| m.to_lowercase().contains(&kw))
        .collect();

    Json(ok_response(
        format!("Found {} modules matching '{}'", matches.len(), keyword),
        Some(serde_json::json!({ "modules": matches })),
    ))
}

/// GET /api/module/{category}/{name} — check if module exists (like CLI `use`)
async fn get_module_info(
    axum::extract::Path((category, name)): axum::extract::Path<(String, String)>,
) -> Response {
    let module_path = format!("{}/{}", category, name);
    if commands::discover_modules().contains(&module_path) {
        (
            StatusCode::OK,
            Json(ok_response(
                "Module found",
                Some(serde_json::json!({
                    "module": module_path,
                    "category": category,
                    "name": name,
                    "exists": true,
                })),
            )),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(err_response(
                format!("Module '{}' not found", module_path),
                "INVALID_MODULE",
            )),
        )
            .into_response()
    }
}

/// GET /api/target — show current target (like CLI `show_target`)
async fn get_target() -> Json<ApiResponse> {
    let target = crate::config::GLOBAL_CONFIG.get_target();
    let size = crate::config::GLOBAL_CONFIG.get_target_size();
    let is_subnet = crate::config::GLOBAL_CONFIG.is_subnet();

    Json(ok_response(
        if target.is_some() {
            "Target retrieved"
        } else {
            "No target set"
        },
        Some(serde_json::json!({
            "target": target,
            "size": size,
            "is_subnet": is_subnet,
        })),
    ))
}

/// POST /api/target — set target (like CLI `set target <val>`)
async fn set_target(Json(payload): Json<SetTargetRequest>) -> Response {
    let target_raw = payload.target.as_str();

    if !validate_target(target_raw) {
        return (
            StatusCode::BAD_REQUEST,
            Json(err_response("Invalid target format", "INVALID_TARGET")),
        )
            .into_response();
    }

    match crate::config::GLOBAL_CONFIG.set_target(target_raw) {
        Ok(_) => {
            let is_subnet = crate::config::GLOBAL_CONFIG.is_subnet();
            let size = crate::config::GLOBAL_CONFIG.get_target_size();
            (
                StatusCode::OK,
                Json(ok_response(
                    format!("Target set to '{}'", target_raw),
                    Some(serde_json::json!({
                        "target": target_raw,
                        "is_subnet": is_subnet,
                        "size": size,
                    })),
                )),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(err_response(
                format!("Failed to set target: {}", e),
                "INVALID_TARGET",
            )),
        )
            .into_response(),
    }
}

/// DELETE /api/target — clear target (like CLI `clear_target`)
async fn clear_target() -> Json<ApiResponse> {
    crate::config::GLOBAL_CONFIG.clear_target();
    Json(ok_response("Target cleared", None))
}

/// POST /api/run — run module synchronously (like CLI `run`)
///
/// This mirrors the CLI: calls `commands::run_module()` directly,
/// captures stdout/stderr, and returns the output in the response.
async fn run_module(
    State(state): State<ApiState>,
    Json(payload): Json<RunModuleRequest>,
) -> Response {
    let start = std::time::Instant::now();
    let module_name = payload.module.as_str();
    let target_raw = payload.target.as_str();

    // Validate inputs
    if !validate_module_name(module_name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(err_response(
                "Invalid module name format",
                "INVALID_MODULE",
            )),
        )
            .into_response();
    }
    if !validate_target(target_raw) {
        return (
            StatusCode::BAD_REQUEST,
            Json(err_response("Invalid target format", "INVALID_TARGET")),
        )
            .into_response();
    }
    if is_blocked_target(target_raw) {
        return (
            StatusCode::FORBIDDEN,
            Json(err_response(
                "Target is a blocked internal/metadata address (link-local 169.254.0.0/16 or 0.0.0.0)",
                "BLOCKED_TARGET",
            )),
        )
            .into_response();
    }

    // Check module exists
    if !commands::discover_modules().contains(&module_name.to_string()) {
        return (
            StatusCode::NOT_FOUND,
            Json(err_response(
                format!("Module '{}' not found", module_name),
                "INVALID_MODULE",
            )),
        )
            .into_response();
    }

    // Set module config (like CLI does via prompts, the API passes them in the request)
    let mut module_config = crate::config::ModuleConfig {
        port: payload.port,
        username_wordlist: payload.username_wordlist.clone(),
        password_wordlist: payload.password_wordlist.clone(),
        concurrency: payload.concurrency,
        stop_on_success: payload.stop_on_success,
        save_results: payload.save_results,
        output_file: payload.output_file.clone(),
        verbose: payload.verbose,
        combo_mode: payload.combo_mode,
        custom_prompts: payload.prompts.clone().unwrap_or_default(),
        api_mode: true,
    };

    // Inject dedicated fields into custom_prompts so cfg_prompt_* picks them up.
    // Only insert if not already set by the explicit prompts map.
    if let Some(v) = module_config.save_results {
        module_config.custom_prompts.entry("save_results".into())
            .or_insert(if v { "y".into() } else { "n".into() });
    }
    if let Some(v) = module_config.verbose {
        module_config.custom_prompts.entry("verbose".into())
            .or_insert(if v { "y".into() } else { "n".into() });
    }
    if let Some(v) = module_config.stop_on_success {
        module_config.custom_prompts.entry("stop_on_success".into())
            .or_insert(if v { "y".into() } else { "n".into() });
    }
    if let Some(v) = module_config.combo_mode {
        module_config.custom_prompts.entry("combo_mode".into())
            .or_insert(if v { "y".into() } else { "n".into() });
    }
    if let Some(ref v) = module_config.output_file {
        module_config.custom_prompts.entry("output_file".into())
            .or_insert(v.clone());
    }

    crate::config::set_module_config(module_config);

    let verbose = state.verbose || payload.verbose.unwrap_or(false);

    if state.verbose {
        eprintln!(
            "[API] Running module '{}' against '{}' (verbose={})",
            module_name, target_raw, verbose
        );
    }

    // Run synchronously with stdout/stderr capture
    // CWD to results directory so module File::create calls write there
    let results_dir = crate::config::results_dir();
    let original_dir = std::env::current_dir().ok();
    let _ = std::env::set_current_dir(&results_dir);

    // Capture stdout during module execution.
    let captured_output = {
        use std::io::Read;
        let mut stdout_buf = gag::BufferRedirect::stdout()
            .unwrap_or_else(|_| gag::BufferRedirect::stdout().unwrap());
        let mut stderr_buf = gag::BufferRedirect::stderr()
            .unwrap_or_else(|_| gag::BufferRedirect::stderr().unwrap());

        let result = commands::run_module(module_name, target_raw, verbose).await;

        let mut stdout_output = String::new();
        let mut stderr_output = String::new();
        let _ = stdout_buf.read_to_string(&mut stdout_output);
        let _ = stderr_buf.read_to_string(&mut stderr_output);
        drop(stdout_buf);
        drop(stderr_buf);

        (result, stdout_output, stderr_output)
    };

    // Restore CWD
    if let Some(dir) = original_dir {
        let _ = std::env::set_current_dir(dir);
    }

    // Clear module config after execution
    crate::config::clear_module_config();

    let duration_ms = start.elapsed().as_millis() as u64;
    let (result, stdout_output, stderr_output) = captured_output;

    // Truncate output to prevent huge responses (max 64KB)
    let max_output = 64 * 1024;
    let stdout_truncated = if stdout_output.len() > max_output {
        format!("{}\n... (output truncated at {} bytes)", &stdout_output[..max_output], stdout_output.len())
    } else {
        stdout_output
    };

    match result {
        Ok(_) => (
            StatusCode::OK,
            Json(ok_response(
                format!(
                    "Module '{}' executed successfully against '{}'",
                    module_name, target_raw
                ),
                Some(serde_json::json!({
                    "module": module_name,
                    "target": target_raw,
                    "status": "completed",
                    "duration_ms": duration_ms,
                    "output": stdout_truncated,
                    "stderr": stderr_output,
                })),
            )),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_response(
                format!(
                    "Module '{}' failed on '{}': {}",
                    module_name, target_raw, e
                ),
                "EXECUTION_ERROR",
            )),
        )
            .into_response(),
    }
}

// ─── Results File Retrieval ─────────────────────────────────────────

/// Validate a result filename: ASCII-only, no path components, safe characters, .txt only.
fn validate_result_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.is_ascii()
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && !name.starts_with('.')
        && name.ends_with(".txt")
}

/// GET /api/results — list saved .txt result files in the results directory
/// Only regular .txt files are listed; symlinks, hidden files, and non-.txt files are excluded.
async fn list_results() -> Json<ApiResponse> {
    let results_dir = crate::config::results_dir();
    let mut files: Vec<serde_json::Value> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&results_dir) {
        for entry in entries.flatten() {
            // Use symlink_metadata to detect symlinks (metadata() follows symlinks)
            let symlink_meta = match entry.path().symlink_metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            // Skip symlinks entirely — prevent symlink-based path escapes
            if symlink_meta.file_type().is_symlink() {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    // Only list .txt files, ASCII names, no hidden files
                    if name.is_ascii()
                        && name.ends_with(".txt")
                        && !name.starts_with('.')
                    {
                        files.push(serde_json::json!({
                            "name": name,
                            "size_bytes": meta.len(),
                            "modified": meta.modified().ok()
                                .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
                                .map(|d| d.as_secs()),
                        }));
                    }
                }
            }
        }
    }

    files.sort_by(|a, b| {
        let a_name = a["name"].as_str().unwrap_or("");
        let b_name = b["name"].as_str().unwrap_or("");
        a_name.cmp(b_name)
    });

    Json(ok_response(
        format!("{} result file(s) found", files.len()),
        Some(serde_json::json!({
            "files": files,
        })),
    ))
}

/// GET /api/results/{filename} — retrieve a specific saved .txt result file
/// Filename must be ASCII-only, end with .txt, no path separators, safe characters only.
/// Returns the file content as plain text within a JSON envelope.
async fn get_result_file(
    axum::extract::Path(filename): axum::extract::Path<String>,
) -> Response {
    // validate_result_filename enforces .txt extension, ASCII-only, no path separators, etc.
    if !validate_result_filename(&filename) {
        return (
            StatusCode::BAD_REQUEST,
            Json(err_response(
                "Invalid filename. Must be ASCII-only, end with .txt, no path separators, only alphanumeric/underscore/dash/dot.",
                "INVALID_FILENAME",
            )),
        )
            .into_response();
    }

    let results_dir = crate::config::results_dir();
    let file_path = results_dir.join(&filename);

    // Reject symlinks before canonicalizing — prevents following malicious symlinks
    match file_path.symlink_metadata() {
        Ok(sym_meta) => {
            if sym_meta.file_type().is_symlink() {
                return (
                    StatusCode::FORBIDDEN,
                    Json(err_response("Access denied: symlinks are not allowed", "SYMLINK_DENIED")),
                )
                    .into_response();
            }
        }
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(err_response(
                    format!("Result file '{}' not found", filename),
                    "NOT_FOUND",
                )),
            )
                .into_response();
        }
    }

    // Double-check the resolved path is still inside results_dir (canonicalize to prevent path escapes)
    match file_path.canonicalize() {
        Ok(canonical) => {
            let results_canonical = results_dir.canonicalize().unwrap_or(results_dir.clone());
            if !canonical.starts_with(&results_canonical) {
                return (
                    StatusCode::FORBIDDEN,
                    Json(err_response("Access denied: path escapes results directory", "PATH_TRAVERSAL")),
                )
                    .into_response();
            }
        }
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(err_response(
                    format!("Result file '{}' not found", filename),
                    "NOT_FOUND",
                )),
            )
                .into_response();
        }
    }

    // Verify it's a regular file (not a directory, device, etc.)
    match file_path.metadata() {
        Ok(meta) if !meta.is_file() => {
            return (
                StatusCode::BAD_REQUEST,
                Json(err_response("Requested path is not a regular file", "NOT_A_FILE")),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(err_response(
                    format!("Result file '{}' not found", filename),
                    "NOT_FOUND",
                )),
            )
                .into_response();
        }
        _ => {}
    }

    match std::fs::read_to_string(&file_path) {
        Ok(content) => {
            // Cap at 1MB to prevent memory exhaustion
            let max_size = 1024 * 1024;
            let content = if content.len() > max_size {
                format!("{}\n... (truncated at {} bytes, total: {} bytes)",
                    &content[..max_size], max_size, content.len())
            } else {
                content
            };

            (
                StatusCode::OK,
                Json(ok_response(
                    format!("File '{}' retrieved", filename),
                    Some(serde_json::json!({
                        "filename": filename,
                        "content": content,
                        "size_bytes": file_path.metadata().map(|m| m.len()).unwrap_or(0),
                    })),
                )),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(err_response(
                format!("Could not read file '{}': {}", filename, e),
                "READ_ERROR",
            )),
        )
            .into_response(),
    }
}

/// POST /api/honeypot-check — honeypot port scan (like CLI pre-run check)
async fn honeypot_check(Json(payload): Json<HoneypotCheckRequest>) -> Response {
    let target_raw = payload.target.as_str();

    if !validate_target(target_raw) {
        return (
            StatusCode::BAD_REQUEST,
            Json(err_response("Invalid target format", "INVALID_TARGET")),
        )
            .into_response();
    }
    if is_blocked_target(target_raw) {
        return (
            StatusCode::FORBIDDEN,
            Json(err_response(
                "Target is a blocked internal/metadata address (link-local 169.254.0.0/16 or 0.0.0.0)",
                "BLOCKED_TARGET",
            )),
        )
            .into_response();
    }

    let ip = match crate::utils::extract_ip_from_target(target_raw) {
        Some(ip) => ip,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(err_response(
                    "Could not extract IP from target",
                    "INVALID_TARGET",
                )),
            )
                .into_response();
        }
    };

    const COMMON_PORTS: &[u16] = &[
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389,
        5900, 8080, 8443, 8888, 9090, 1433, 1521, 5432, 6379, 11211, 27017, 161, 389, 636, 902,
        1080, 1194, 1883, 5672, 8883, 9200, 15672, 25565, 27018, 28017, 50000, 50070, 61616,
    ];

    let scan_timeout = std::time::Duration::from_millis(500);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(50));
    let mut tasks = Vec::new();

    for &port in COMMON_PORTS {
        let ip = ip.clone();
        let sem = semaphore.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            let addr = format!("{}:{}", ip, port);
            let conn = tokio::time::timeout(scan_timeout, tokio::net::TcpStream::connect(&addr))
                .await;
            if let Ok(Ok(_)) = conn {
                Some(port)
            } else {
                None
            }
        }));
    }

    let mut open_ports: Vec<u16> = Vec::new();
    for task in tasks {
        if let Ok(Some(port)) = task.await {
            open_ports.push(port);
        }
    }
    open_ports.sort();

    let is_honeypot = open_ports.len() >= 11;

    (
        StatusCode::OK,
        Json(ok_response(
            format!("Honeypot check completed for {}", ip),
            Some(serde_json::json!({
                "target": ip,
                "open_ports": open_ports,
                "open_count": open_ports.len(),
                "total_scanned": COMMON_PORTS.len(),
                "is_honeypot": is_honeypot,
                "threshold": 11,
            })),
        )),
    )
        .into_response()
}

// ─── Shell-Parity Exec Endpoint ─────────────────────────────────────

/// POST /api/exec — execute internal commands remotely (mirrors interactive shell)
/// Supports secure command chaining via JSON array `commands` field.
/// Each command is individually validated — no shell metacharacters allowed.
async fn exec_command(
    State(state): State<ApiState>,
    Json(payload): Json<ExecRequest>,
) -> Response {
    // Build command list from either `commands` (array) or `command` (single string)
    let command_list: Vec<String> = if let Some(cmds) = &payload.commands {
        if cmds.is_empty() || cmds.len() > 20 {
            return (
                StatusCode::BAD_REQUEST,
                Json(err_response("Commands array must have 1-20 entries", "INVALID_INPUT")),
            ).into_response();
        }
        cmds.clone()
    } else if let Some(cmd) = &payload.command {
        vec![cmd.clone()]
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(err_response("Provide 'command' (string) or 'commands' (array)", "INVALID_INPUT")),
        ).into_response();
    };

    let mut results: Vec<ExecResult> = Vec::new();

    for raw_cmd in &command_list {
        let trimmed = raw_cmd.trim().to_string();
        if trimmed.is_empty() || trimmed.len() > 4096 {
            results.push(ExecResult {
                command: trimmed,
                success: false,
                output: "Command is empty or too long (max 4096 chars)".to_string(),
                duration_ms: None,
            });
            continue;
        }

        // Validate each individual command against shell metacharacters
        if contains_shell_metacharacters(&trimmed) {
            results.push(ExecResult {
                command: trimmed,
                success: false,
                output: "Command contains forbidden characters (& | ; ` $ > <). Use the 'commands' JSON array for chaining.".to_string(),
                duration_ms: None,
            });
            continue;
        }

        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let cmd = match parts.next() {
            Some(c) => c.to_lowercase(),
            None => continue,
        };
        let rest = parts.next().unwrap_or("").trim().to_string();
        let command_key = crate::shell::resolve_command(&cmd);

        let start = std::time::Instant::now();

        match command_key.as_str() {
            "help" => {
                results.push(ExecResult {
                    command: trimmed.to_string(),
                    success: true,
                    output: "Available commands: help, modules, find <query>, use <module>, \
                             set/target <ip>, show_target, clear_target, run, run_all, back, exit"
                        .to_string(),
                    duration_ms: None,
                });
            }

            "modules" => {
                let modules = commands::discover_modules();
                let mut exploits = Vec::new();
                let mut scanners = Vec::new();
                let mut creds = Vec::new();
                for m in &modules {
                    if m.starts_with("exploits/") { exploits.push(m.as_str()); }
                    else if m.starts_with("scanners/") { scanners.push(m.as_str()); }
                    else if m.starts_with("creds/") { creds.push(m.as_str()); }
                }
                results.push(ExecResult {
                    command: trimmed.to_string(),
                    success: true,
                    output: serde_json::json!({
                        "total": modules.len(),
                        "exploits": exploits,
                        "scanners": scanners,
                        "creds": creds,
                    }).to_string(),
                    duration_ms: None,
                });
            }

            "find" => {
                if rest.is_empty() {
                    results.push(ExecResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: find <query>".to_string(),
                        duration_ms: None,
                    });
                } else {
                    let query = rest.to_lowercase();
                    let modules = commands::discover_modules();
                    let matches: Vec<&String> = modules.iter()
                        .filter(|m| m.to_lowercase().contains(&query))
                        .collect();
                    results.push(ExecResult {
                        command: trimmed.to_string(),
                        success: true,
                        output: serde_json::json!({
                            "query": query,
                            "matches": matches,
                            "count": matches.len(),
                        }).to_string(),
                        duration_ms: None,
                    });
                }
            }

            "use" => {
                if rest.is_empty() {
                    results.push(ExecResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: use <module_path>".to_string(),
                        duration_ms: None,
                    });
                } else {
                    let sanitized = crate::shell::sanitize_module_path(&rest);
                    match sanitized {
                        Some(path) => {
                            let modules = commands::discover_modules();
                            let found = modules.iter().any(|m| m == &path)
                                || modules.iter().any(|m| {
                                    m.rsplit_once('/').map(|(_, s)| s == path).unwrap_or(false)
                                });
                            if found {
                                if let Ok(mut cm) = state.current_module.lock() {
                                    *cm = Some(path.clone());
                                }
                                results.push(ExecResult {
                                    command: trimmed.to_string(),
                                    success: true,
                                    output: format!("Module selected: {}", path),
                                    duration_ms: None,
                                });
                            } else {
                                // Fuzzy suggestion
                                let best = modules.iter()
                                    .map(|m| (m, strsim::levenshtein(&path, m)))
                                    .min_by_key(|(_, d)| *d);
                                let suggestion = if let Some((s, d)) = best {
                                    if d < 5 { format!(" Did you mean: {}?", s) } else { String::new() }
                                } else {
                                    String::new()
                                };
                                results.push(ExecResult {
                                    command: trimmed.to_string(),
                                    success: false,
                                    output: format!("Unknown module '{}'.{}", path, suggestion),
                                    duration_ms: None,
                                });
                            }
                        }
                        None => {
                            results.push(ExecResult {
                                command: trimmed.to_string(),
                                success: false,
                                output: "Invalid module path".to_string(),
                                duration_ms: None,
                            });
                        }
                    }
                }
            }

            "set" => {
                if rest.is_empty() {
                    results.push(ExecResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: set <target>".to_string(),
                        duration_ms: None,
                    });
                } else if !validate_target(&rest) {
                    results.push(ExecResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Invalid target".to_string(),
                        duration_ms: None,
                    });
                } else {
                    match crate::config::GLOBAL_CONFIG.set_target(&rest) {
                        Ok(_) => {
                            results.push(ExecResult {
                                command: trimmed.to_string(),
                                success: true,
                                output: format!("Target set to: {}", rest),
                                duration_ms: None,
                            });
                        }
                        Err(e) => {
                            results.push(ExecResult {
                                command: trimmed.to_string(),
                                success: false,
                                output: format!("Failed to set target: {}", e),
                                duration_ms: None,
                            });
                        }
                    }
                }
            }

            "show_target" => {
                let target = crate::config::GLOBAL_CONFIG.get_target().unwrap_or_else(|| "Not set".to_string());
                let module = state.current_module.lock().ok().and_then(|cm| cm.clone()).unwrap_or_else(|| "None".to_string());
                results.push(ExecResult {
                    command: trimmed.to_string(),
                    success: true,
                    output: serde_json::json!({
                        "target": target,
                        "current_module": module,
                    }).to_string(),
                    duration_ms: None,
                });
            }

            "clear_target" => {
                crate::config::GLOBAL_CONFIG.clear_target();
                results.push(ExecResult {
                    command: trimmed.to_string(),
                    success: true,
                    output: "Target cleared".to_string(),
                    duration_ms: None,
                });
            }

            "back" => {
                if let Ok(mut cm) = state.current_module.lock() {
                    *cm = None;
                }
                results.push(ExecResult {
                    command: trimmed.to_string(),
                    success: true,
                    output: "Module deselected".to_string(),
                    duration_ms: None,
                });
            }

            "run" => {
                let module_path = state.current_module.lock().ok().and_then(|cm| cm.clone());
                if module_path.is_none() {
                    results.push(ExecResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "No module selected. Use 'use <module>' first.".to_string(),
                        duration_ms: None,
                    });
                } else {
                    let module_path = module_path.unwrap();
                    // Resolve target: from rest arg, or global config
                    let target = if !rest.is_empty() {
                        rest.clone()
                    } else if crate::config::GLOBAL_CONFIG.has_target() {
                        crate::config::GLOBAL_CONFIG.get_target().unwrap_or_default()
                    } else {
                        results.push(ExecResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "No target set. Use 'set <target>' first.".to_string(),
                            duration_ms: None,
                        });
                        continue;
                    };

                    let verbose = state.verbose;
                    let run_start = std::time::Instant::now();
                    match commands::run_module(&module_path, &target, verbose).await {
                        Ok(_) => {
                            results.push(ExecResult {
                                command: trimmed.to_string(),
                                success: true,
                                output: format!("Module '{}' executed against '{}'", module_path, target),
                                duration_ms: Some(run_start.elapsed().as_millis() as u64),
                            });
                        }
                        Err(e) => {
                            results.push(ExecResult {
                                command: trimmed.to_string(),
                                success: false,
                                output: format!("Module failed: {}", e),
                                duration_ms: Some(run_start.elapsed().as_millis() as u64),
                            });
                        }
                    }
                }
            }

            "run_all" => {
                let target = if !rest.is_empty() {
                    rest.clone()
                } else if crate::config::GLOBAL_CONFIG.has_target() {
                    crate::config::GLOBAL_CONFIG.get_target().unwrap_or_default()
                } else {
                    results.push(ExecResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "No target set for run_all".to_string(),
                        duration_ms: None,
                    });
                    continue;
                };

                let modules = commands::discover_modules();
                let verbose = state.verbose;
                let run_start = std::time::Instant::now();
                let mut ok_count = 0usize;
                let mut fail_count = 0usize;
                for m in &modules {
                    match commands::run_module(m, &target, verbose).await {
                        Ok(_) => ok_count += 1,
                        Err(_) => fail_count += 1,
                    }
                }
                results.push(ExecResult {
                    command: trimmed.to_string(),
                    success: true,
                    output: format!("run_all complete: {} ok, {} failed out of {} modules",
                        ok_count, fail_count, modules.len()),
                    duration_ms: Some(run_start.elapsed().as_millis() as u64),
                });
            }

            "exit" => {
                results.push(ExecResult {
                    command: trimmed.to_string(),
                    success: true,
                    output: "Exit not applicable in API mode".to_string(),
                    duration_ms: None,
                });
            }

            other => {
                results.push(ExecResult {
                    command: trimmed.to_string(),
                    success: false,
                    output: format!("Unknown command: '{}'", other),
                    duration_ms: Some(start.elapsed().as_millis() as u64),
                });
            }
        }
    }

    let all_ok = results.iter().all(|r| r.success);
    let total = results.len();

    (
        if all_ok { StatusCode::OK } else { StatusCode::OK },
        Json(ok_response(
            format!("{} command(s) executed", total),
            Some(serde_json::json!({
                "results": results,
            })),
        )),
    ).into_response()
}

// ─── Server Entry Point ─────────────────────────────────────────────

pub async fn start_api_server(
    bind_address: &str,
    api_key: String,
    verbose: bool,
) -> Result<()> {
    // Load optional IP whitelist
    let whitelist = load_ip_whitelist();
    if !whitelist.is_empty() {
        println!("🔒 IP whitelist loaded: {} entries", whitelist.len());
        for ip in &whitelist {
            println!("   ✓ {}", ip);
        }
    } else {
        println!("🌐 No IP whitelist configured (all IPs allowed)");
        println!("   Tip: Create ~/.rustsploit/ip_whitelist.conf to restrict access");
    }

    let state = ApiState {
        api_key: api_key.clone(),
        verbose,
        ip_whitelist: Arc::new(whitelist),
        current_module: Arc::new(Mutex::new(None)),
        rate_limiter: Arc::new(Mutex::new(HashMap::new())),
    };

    println!("🚀 Starting RustSploit API server...");
    println!("📍 Binding to: {}", bind_address);
    println!("🔑 API key: {}", api_key);
    println!("📢 Verbose: {}", verbose);

    // Protected routes (require API key)
    let protected = Router::new()
        .route("/api/modules", get(list_modules))
        .route("/api/modules/search", get(search_modules))
        .route("/api/module/{category}/{name}", get(get_module_info))
        .route("/api/run", post(run_module))
        .route("/api/target", get(get_target))
        .route("/api/target", post(set_target))
        .route("/api/target", axum::routing::delete(clear_target))
        .route("/api/honeypot-check", post(honeypot_check))
        .route("/api/exec", post(exec_command))
        .route("/api/results", get(list_results))
        .route("/api/results/{filename}", get(get_result_file))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Public routes + merge protected
    let app = Router::new()
        .route("/health", get(health_check))
        .merge(protected)
        .layer(
            ServiceBuilder::new()
                .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_SIZE))
                .layer(TraceLayer::new_for_http()),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_address)
        .await
        .context(format!("Failed to bind to {}", bind_address))?;

    println!("✅ API server is running!");
    println!(
        "📖 Example: curl -H 'Authorization: Bearer {}' http://{}/api/modules",
        api_key, bind_address
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("API server error")?;

    Ok(())
}
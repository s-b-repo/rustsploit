use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, StatusCode},
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
use tower::ServiceBuilder;
use tower_http::{
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};

use colored::*;
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
            tracing::warn!(path = %path.display(), error = %e, "Failed to read IP whitelist");
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
    verbose: bool,
    /// Optional IP whitelist — if non-empty, only these IPs can access the API
    ip_whitelist: Arc<Vec<String>>,
    /// Persistent module selection (mirrors ShellContext.current_module)
    current_module: Arc<Mutex<Option<String>>>,
    /// Per-IP rate limiter: IP -> (request_count, window_start)
    rate_limiter: Arc<Mutex<HashMap<std::net::IpAddr, (u32, Instant)>>>,
    /// Limits concurrent module execution to avoid resource exhaustion.
    /// No longer serializes to 1 — per-task output capture allows concurrency.
    run_semaphore: Arc<tokio::sync::Semaphore>,
}

/// Max requests per IP per window
const RATE_LIMIT_MAX_REQUESTS: u32 = 30;
/// Rate limit window duration in seconds
const RATE_LIMIT_WINDOW_SECS: u64 = 10;

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
pub struct ShellRequest {
    /// Single command (backward compatible)
    pub command: Option<String>,
    /// Array of commands for chaining (preferred, more secure than string splitting)
    pub commands: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
struct ShellResult {
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

/// Target blocking is disabled — all targets are allowed.
/// This is a pentesting framework; operators are responsible for their own targeting.
fn is_blocked_target(_target: &str) -> bool {
    false
}

/// Check if exec input contains shell metacharacters that could enable injection.
fn contains_shell_metacharacters(input: &str) -> bool {
    input.chars().any(|c| matches!(c, '&' | '|' | ';' | '`' | '$' | '>' | '<' | '\n' | '\r'))
        || input.contains("$(")
        || input.contains("${")
}

// Auth middleware removed — authentication is now via PQ handshake (SSH-style identity keys).
// The PQ middleware in pq_middleware.rs handles decryption and verifies the session.
// Unauthenticated requests without X-PQ-Session header are rejected by the PQ middleware.

// ─── Endpoint Handlers ─────────────────────────────────────────────

async fn health_check() -> Json<ApiResponse> {
    Json(ok_response("API is running", None))
}

/// GET /api/modules — list all modules (like CLI `modules`)
async fn list_modules() -> Json<ApiResponse> {
    let modules = commands::discover_modules();

    // Group modules by category dynamically
    let mut by_category: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    for module in &modules {
        let category = module.split('/').next().unwrap_or("other").to_string();
        by_category.entry(category).or_default().push(module.clone());
    }

    Json(ok_response(
        format!("{} modules available", modules.len()),
        Some(serde_json::json!({
            "total": modules.len(),
            "categories": commands::categories(),
            "modules": by_category,
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

/// GET /api/module/*path — check if module exists + return metadata
/// Accepts any depth: /api/module/scanners/port_scanner or /api/module/creds/generic/ftp_anonymous
async fn get_module_info(
    axum::extract::Path(module_path): axum::extract::Path<String>,
) -> Response {
    let module_path = module_path.trim_matches('/').to_string();
    let category = module_path.split('/').next().unwrap_or("").to_string();
    let name = module_path.split('/').last().unwrap_or("").to_string();

    if commands::discover_modules().contains(&module_path) {
        let info = commands::module_info(&module_path);
        let info_data = info.map(|i| serde_json::to_value(&i).ok()).flatten();
        (
            StatusCode::OK,
            Json(ok_response(
                "Module found",
                Some(serde_json::json!({
                    "module": module_path,
                    "category": category,
                    "name": name,
                    "exists": true,
                    "info": info_data,
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

// ─── Global Options API ────────────────────────────────────────────

/// GET /api/options — list all global options
async fn get_options() -> Json<ApiResponse> {
    let opts = crate::global_options::GLOBAL_OPTIONS.all().await;
    Json(ok_response(
        format!("{} global options", opts.len()),
        Some(serde_json::json!({ "options": opts })),
    ))
}

/// POST /api/options — set a global option
async fn set_option(Json(payload): Json<HashMap<String, String>>) -> Json<ApiResponse> {
    let mut set_count = 0;
    for (key, value) in &payload {
        crate::global_options::GLOBAL_OPTIONS.set(key, value).await;
        set_count += 1;
    }
    Json(ok_response(format!("{} option(s) set", set_count), None))
}

/// DELETE /api/options — clear a specific option (via query param or body)
async fn delete_option(Json(payload): Json<HashMap<String, String>>) -> Json<ApiResponse> {
    let mut removed = 0;
    for key in payload.keys() {
        if crate::global_options::GLOBAL_OPTIONS.unset(key).await {
            removed += 1;
        }
    }
    Json(ok_response(format!("{} option(s) removed", removed), None))
}

// ─── Credential Store API ──────────────────────────────────────────

/// GET /api/creds — list all credentials
async fn list_creds() -> Json<ApiResponse> {
    tracing::info!("API: credentials listed");
    let creds = crate::cred_store::CRED_STORE.list().await;
    Json(ok_response(
        format!("{} credentials", creds.len()),
        Some(serde_json::to_value(&creds).unwrap_or_default()),
    ))
}

/// POST /api/creds — add a credential
async fn add_cred(Json(payload): Json<serde_json::Value>) -> Json<ApiResponse> {
    let host = payload.get("host").and_then(|v| v.as_str()).unwrap_or("");
    let port = payload.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let service = payload.get("service").and_then(|v| v.as_str()).unwrap_or("unknown");
    let username = payload.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let secret = payload.get("secret").and_then(|v| v.as_str()).unwrap_or("");
    let cred_type_str = payload.get("cred_type").and_then(|v| v.as_str()).unwrap_or("password");
    let source = payload.get("source_module").and_then(|v| v.as_str()).unwrap_or("api");

    if host.is_empty() || username.is_empty() {
        return Json(err_response("host and username are required", "INVALID_INPUT"));
    }

    let cred_type = match cred_type_str {
        "hash" => crate::cred_store::CredType::Hash,
        "key" => crate::cred_store::CredType::Key,
        "token" => crate::cred_store::CredType::Token,
        _ => crate::cred_store::CredType::Password,
    };

    let id = crate::cred_store::CRED_STORE.add(host, port, service, username, secret, cred_type, source).await;
    tracing::info!(host = %host, service = %service, "API: credential added");
    Json(ok_response("Credential added", Some(serde_json::json!({ "id": id }))))
}

/// DELETE /api/creds — delete a credential by ID
async fn delete_cred(Json(payload): Json<serde_json::Value>) -> Json<ApiResponse> {
    let id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("");
    if crate::cred_store::CRED_STORE.delete(id).await {
        tracing::info!(id = %id, "API: credential deleted");
        Json(ok_response("Credential deleted", None))
    } else {
        Json(err_response("Credential not found", "NOT_FOUND"))
    }
}

// ─── Workspace API ─────────────────────────────────────────────────

/// GET /api/hosts — list tracked hosts
async fn list_hosts() -> Json<ApiResponse> {
    let hosts = crate::workspace::WORKSPACE.hosts().await;
    Json(ok_response(
        format!("{} hosts", hosts.len()),
        Some(serde_json::to_value(&hosts).unwrap_or_default()),
    ))
}

/// POST /api/hosts — add a host
async fn add_host(Json(payload): Json<serde_json::Value>) -> Json<ApiResponse> {
    let ip = payload.get("ip").and_then(|v| v.as_str()).unwrap_or("");
    if ip.is_empty() {
        return Json(err_response("ip is required", "INVALID_INPUT"));
    }
    let hostname = payload.get("hostname").and_then(|v| v.as_str());
    let os_guess = payload.get("os_guess").and_then(|v| v.as_str());
    crate::workspace::WORKSPACE.add_host(ip, hostname, os_guess).await;
    Json(ok_response("Host added", None))
}

/// GET /api/services — list tracked services
async fn list_services() -> Json<ApiResponse> {
    let services = crate::workspace::WORKSPACE.services().await;
    Json(ok_response(
        format!("{} services", services.len()),
        Some(serde_json::to_value(&services).unwrap_or_default()),
    ))
}

/// POST /api/services — add a service
async fn add_service(Json(payload): Json<serde_json::Value>) -> Json<ApiResponse> {
    let host = payload.get("host").and_then(|v| v.as_str()).unwrap_or("");
    let port = payload.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let protocol = payload.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp");
    let service_name = payload.get("service_name").and_then(|v| v.as_str()).unwrap_or("unknown");
    let version = payload.get("version").and_then(|v| v.as_str());

    if host.is_empty() || port == 0 {
        return Json(err_response("host and port are required", "INVALID_INPUT"));
    }
    crate::workspace::WORKSPACE.add_service(host, port, protocol, service_name, version).await;
    Json(ok_response("Service added", None))
}

/// GET /api/workspace — show current workspace info
async fn get_workspace() -> Json<ApiResponse> {
    let name = crate::workspace::WORKSPACE.current_name().await;
    let workspaces = crate::workspace::WORKSPACE.list_workspaces().await;
    Json(ok_response("Workspace info", Some(serde_json::json!({
        "current": name,
        "available": workspaces,
    }))))
}

/// POST /api/workspace — switch workspace
async fn switch_workspace(Json(payload): Json<serde_json::Value>) -> Json<ApiResponse> {
    let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if name.is_empty() {
        return Json(err_response("name is required", "INVALID_INPUT"));
    }
    crate::workspace::WORKSPACE.switch(name).await;
    Json(ok_response(format!("Switched to workspace '{}'", name), None))
}

// ─── Loot API ──────────────────────────────────────────────────────

/// GET /api/loot — list loot entries
async fn list_loot() -> Json<ApiResponse> {
    let loot = crate::loot::LOOT_STORE.list().await;
    Json(ok_response(
        format!("{} loot items", loot.len()),
        Some(serde_json::to_value(&loot).unwrap_or_default()),
    ))
}

/// POST /api/loot — add loot
async fn add_loot(Json(payload): Json<serde_json::Value>) -> Json<ApiResponse> {
    let host = payload.get("host").and_then(|v| v.as_str()).unwrap_or("");
    let loot_type = payload.get("loot_type").and_then(|v| v.as_str()).unwrap_or("other");
    let description = payload.get("description").and_then(|v| v.as_str()).unwrap_or("");
    let data = payload.get("data").and_then(|v| v.as_str()).unwrap_or("");
    let source = payload.get("source_module").and_then(|v| v.as_str()).unwrap_or("api");

    if host.is_empty() {
        return Json(err_response("host is required", "INVALID_INPUT"));
    }

    match crate::loot::LOOT_STORE.add_text(host, loot_type, description, data, source).await {
        Some(id) => Json(ok_response("Loot stored", Some(serde_json::json!({ "id": id })))),
        None => Json(err_response("Failed to store loot", "INTERNAL_ERROR")),
    }
}

// ─── Jobs API ──────────────────────────────────────────────────────

/// GET /api/jobs — list background jobs
async fn list_jobs() -> Json<ApiResponse> {
    let jobs = crate::jobs::JOB_MANAGER.list();
    let job_data: Vec<serde_json::Value> = jobs.iter().map(|(id, module, target, started, status)| {
        serde_json::json!({
            "id": id,
            "module": module,
            "target": target,
            "started": started,
            "status": status,
        })
    }).collect();
    Json(ok_response(
        format!("{} jobs", job_data.len()),
        Some(serde_json::json!({ "jobs": job_data })),
    ))
}

/// DELETE /api/jobs/{id} — kill a job
async fn kill_job(axum::extract::Path(id): axum::extract::Path<u32>) -> Json<ApiResponse> {
    if crate::jobs::JOB_MANAGER.kill(id) {
        Json(ok_response(format!("Job {} cancelled", id), None))
    } else {
        Json(err_response(format!("Job {} not found", id), "NOT_FOUND"))
    }
}

// ─── Export API ────────────────────────────────────────────────────

/// GET /api/export — export engagement data
async fn export_data(
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Response {
    let format = params.get("format").map(|s| s.as_str()).unwrap_or("json");

    // Gather data inline for API response
    let loot_entries = crate::loot::LOOT_STORE.list().await;
    let data = serde_json::json!({
        "workspace": crate::workspace::WORKSPACE.current_name().await,
        "exported_at": chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        "hosts": crate::workspace::WORKSPACE.hosts().await,
        "services": crate::workspace::WORKSPACE.services().await,
        "credentials": crate::cred_store::CRED_STORE.list().await,
        "loot": loot_entries,
    });

    match format {
        "json" => (
            StatusCode::OK,
            Json(ok_response("Export complete", Some(data))),
        ).into_response(),
        _ => (
            StatusCode::BAD_REQUEST,
            Json(err_response("Use format=json for API export", "INVALID_INPUT")),
        ).into_response(),
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

    // Validate output_file for path traversal before injecting into prompts
    if let Some(ref f) = payload.output_file {
        let bad = f.contains("..") || f.contains('/') || f.contains('\\') || f.contains('\0');
        if bad {
            return (
                StatusCode::BAD_REQUEST,
                Json(err_response(
                    "Invalid output_file: must not contain path separators or traversal sequences",
                    "INVALID_OUTPUT_FILE",
                )),
            ).into_response();
        }
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
    if let Some(v) = module_config.port {
        module_config.custom_prompts.entry("port".into())
            .or_insert(v.to_string());
    }
    if let Some(ref v) = module_config.username_wordlist {
        module_config.custom_prompts.entry("username_wordlist".into())
            .or_insert(v.clone());
    }
    if let Some(ref v) = module_config.password_wordlist {
        module_config.custom_prompts.entry("password_wordlist".into())
            .or_insert(v.clone());
    }
    if let Some(v) = module_config.concurrency {
        module_config.custom_prompts.entry("concurrency".into())
            .or_insert(v.to_string());
    }
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

    // Strip "target" from custom_prompts to prevent SSRF bypass via prompt injection.
    // The validated target is passed directly to run_module() — modules should NOT
    // read a different target from custom_prompts.
    module_config.custom_prompts.remove("target");

    let verbose = state.verbose || payload.verbose.unwrap_or(false);

    if state.verbose {
        tracing::info!(
            module = module_name,
            target = target_raw,
            verbose,
            "Running module via API"
        );
    }

    tracing::info!(module = %module_name, target = %target_raw, "API: dispatching module");

    // Acquire concurrency permit to avoid resource exhaustion
    let _permit = match state.run_semaphore.acquire().await {
        Ok(permit) => permit,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(err_response(
                    "Server is shutting down",
                    "SERVICE_UNAVAILABLE",
                )),
            )
                .into_response();
        }
    };

    // Per-task output capture — no process-global gag, no serialization needed.
    // Each API request gets its own OutputBuffer via task-local storage,
    // so multiple modules can run concurrently without output interleaving.
    let output_buf = crate::output::OutputBuffer::new();
    let buf_clone = output_buf.clone();

    // Run inside a task-local RunContext so cfg_prompt_* reads per-request
    // config instead of the process-global MODULE_CONFIG.
    let (result, run_ctx) = crate::context::run_with_context_target(module_config, target_raw.to_string(), || async {
        crate::output::OUTPUT_BUFFER.scope(buf_clone, async {
            commands::run_module(module_name, target_raw, verbose).await
        }).await
    }).await;

    let duration_ms = start.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let stdout_output = output_buf.drain_stdout();
    let stderr_output = output_buf.drain_stderr();
    let module_output = run_ctx.output.take();

    // Truncate output to prevent huge responses (max 64KB)
    let max_output = 64 * 1024;
    let output_truncated = if stdout_output.len() > max_output {
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
                    "output": output_truncated,
                    "stderr": stderr_output,
                    "findings": module_output.findings,
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
            let _permit = match sem.acquire().await {
                Ok(permit) => permit,
                Err(e) => {
                    eprintln!("[!] Semaphore acquire failed: {}", e);
                    return None;
                }
            };
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

/// POST /api/shell — run interactive-shell commands remotely (mirrors the interactive `rsf>` shell)
///
/// Supports all interactive shell commands: `use`, `set target`, `set subnet`, `show_target`,
/// `clear_target`, `run`, `run_all`, `find`, `modules`, `back`, `info`, `check`, `setg`, `unsetg`,
/// `show_options`, `creds`, `hosts`, `services`, `notes`, `workspace`, `loot`, `export`, `jobs`, `spool`.
///
/// For direct module execution with prompts, prefer POST /api/run instead.
/// Supports secure command chaining via JSON array `commands` field.
/// Each command is individually validated — no shell metacharacters allowed.
/// Interactive-prompt commands (creds add, services add, loot add) accept inline arguments.
async fn shell_command(
    State(state): State<ApiState>,
    Json(payload): Json<ShellRequest>,
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

    let mut results: Vec<ShellResult> = Vec::new();

    for raw_cmd in &command_list {
        let trimmed = raw_cmd.trim().to_string();
        if trimmed.is_empty() || trimmed.len() > 4096 {
            results.push(ShellResult {
                command: trimmed,
                success: false,
                output: "Command is empty or too long (max 4096 chars)".to_string(),
                duration_ms: None,
            });
            continue;
        }

        // Validate each individual command against shell metacharacters
        if contains_shell_metacharacters(&trimmed) {
            results.push(ShellResult {
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
                results.push(ShellResult {
                    command: trimmed.to_string(),
                    success: true,
                    output: "Available commands (same as interactive shell):\n\
                             \n\
                             ── Navigation & Discovery ──\n\
                             help | h | ?                  — This help\n\
                             modules | ls | m              — List all modules\n\
                             find <kw> | f1 <kw>          — Search modules by keyword\n\
                             use <path> | u <path>        — Select a module\n\
                             info [path] | i              — Show module metadata\n\
                             back | b                     — Deselect current module\n\
                             \n\
                             ── Targeting ──\n\
                             set target <ip> | t <ip>     — Set target (single IP/hostname)\n\
                             set subnet <CIDR> | sn <CIDR>— Set target to CIDR subnet\n\
                             set port <port>              — Set global port\n\
                             show_target | st             — Show current target & module\n\
                             clear_target | ct            — Clear target\n\
                             \n\
                             ── Execution ──\n\
                             run [target]                 — Run selected module\n\
                             run -j                       — Run module as background job\n\
                             run_all [target]             — Run all modules against target\n\
                             check | ch                   — Non-destructive vulnerability check\n\
                             \n\
                             ── Global Options ──\n\
                             setg <key> <val> | sg        — Set global option\n\
                             unsetg <key> | ug            — Unset global option\n\
                             show_options | so            — Display all global options\n\
                             \n\
                             ── Data Management ──\n\
                             creds                        — List credentials\n\
                             creds add <host> <port> <svc> <user> <secret> [type] — Add credential\n\
                             creds search <query>         — Search credentials\n\
                             creds delete <id>            — Delete credential\n\
                             creds clear                  — Clear all credentials\n\
                             hosts                        — List tracked hosts\n\
                             hosts add <ip>               — Add host\n\
                             hosts delete <ip>            — Remove host and its services\n\
                             hosts clear                  — Clear all hosts and services\n\
                             services                     — List tracked services\n\
                             services add <host> <port> <proto> <name> [ver] — Add service\n\
                             services delete <host> <port> — Remove a service\n\
                             notes <ip> <text>            — Add note to host\n\
                             workspace [name] | ws        — List or switch workspaces\n\
                             loot                         — List loot\n\
                             loot add <host> <type> <desc> <data> — Add loot\n\
                             loot search <query>          — Search loot\n\
                             loot delete <id>             — Delete loot entry\n\
                             loot clear                   — Clear all loot\n\
                             \n\
                             ── Automation & Export ──\n\
                             export <json|csv|summary> <file> — Export engagement data\n\
                             spool [off|file]             — Control output logging\n\
                             jobs | j                     — List background jobs\n\
                             jobs -k <id>                 — Kill a background job\n\
                             jobs clean                   — Clean up finished jobs\n\
                             exit                         — (no-op in API mode)"
                        .to_string(),
                    duration_ms: None,
                });
            }

            "modules" => {
                let modules = commands::discover_modules();
                let mut by_category: std::collections::BTreeMap<&str, Vec<&str>> = std::collections::BTreeMap::new();
                for m in &modules {
                    let cat = m.split('/').next().unwrap_or("other");
                    by_category.entry(cat).or_default().push(m.as_str());
                }
                results.push(ShellResult {
                    command: trimmed.to_string(),
                    success: true,
                    output: serde_json::json!({
                        "total": modules.len(),
                        "categories": commands::categories(),
                        "modules": by_category,
                    }).to_string(),
                    duration_ms: None,
                });
            }

            "find" => {
                if rest.is_empty() {
                    results.push(ShellResult {
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
                    results.push(ShellResult {
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
                    results.push(ShellResult {
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
                                results.push(ShellResult {
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
                                results.push(ShellResult {
                                    command: trimmed.to_string(),
                                    success: false,
                                    output: format!("Unknown module '{}'.{}", path, suggestion),
                                    duration_ms: None,
                                });
                            }
                        }
                        None => {
                            results.push(ShellResult {
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
                // Handle "set port <val>" and "set source_port <val>" as global option shortcuts
                if let Some(val) = rest.strip_prefix("port ") {
                    let val = val.trim();
                    match val.parse::<u16>() {
                        Ok(p) if p > 0 => {
                            crate::global_options::GLOBAL_OPTIONS.set("port", val).await;
                            results.push(ShellResult {
                                command: trimmed.to_string(),
                                success: true,
                                output: format!("Global port set to: {}", val),
                                duration_ms: Some(start.elapsed().as_millis() as u64),
                            });
                        }
                        _ => {
                            results.push(ShellResult {
                                command: trimmed.to_string(),
                                success: false,
                                output: "Invalid port. Must be 1-65535.".to_string(),
                                duration_ms: None,
                            });
                        }
                    }
                } else if let Some(val) = rest.strip_prefix("source_port ") {
                    let val = val.trim();
                    if val == "0" || val.is_empty() {
                        crate::global_options::GLOBAL_OPTIONS.unset("source_port").await;
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: true,
                            output: "Source port cleared (will use OS-assigned).".to_string(),
                            duration_ms: Some(start.elapsed().as_millis() as u64),
                        });
                    } else {
                        match val.parse::<u16>() {
                            Ok(p) if p > 0 => {
                                crate::global_options::GLOBAL_OPTIONS.set("source_port", val).await;
                                results.push(ShellResult {
                                    command: trimmed.to_string(),
                                    success: true,
                                    output: format!("Global source port set to: {}", val),
                                    duration_ms: Some(start.elapsed().as_millis() as u64),
                                });
                            }
                            _ => {
                                results.push(ShellResult {
                                    command: trimmed.to_string(),
                                    success: false,
                                    output: "Invalid source port. Must be 1-65535 (or 0 to clear).".to_string(),
                                    duration_ms: None,
                                });
                            }
                        }
                    }
                } else {
                // Mirror shell.rs: `set target <ip>`, `t <ip>`, `set subnet <cidr>`, `sn <cidr>`
                // Peel off leading "target ", "t ", "subnet ", "sn " keywords to extract the value
                let raw_value = if rest.starts_with("target ") {
                    rest.strip_prefix("target ").unwrap_or(&rest).trim()
                } else if rest.starts_with("t ") {
                    rest.strip_prefix("t ").unwrap_or(&rest).trim()
                } else {
                    rest.trim()
                };

                if raw_value.is_empty() {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: set target <ip>  or  set subnet <CIDR>  or  t <ip>  or  sn <CIDR>".to_string(),
                        duration_ms: None,
                    });
                } else if !validate_target(raw_value) {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Invalid target".to_string(),
                        duration_ms: None,
                    });
                } else {
                    // Strip CIDR prefix if user did `set target 1.2.3.4/24` (single-IP intent)
                    let ip_only = if raw_value.contains('/') {
                        raw_value.split('/').next().unwrap_or(raw_value)
                    } else {
                        raw_value
                    };
                    match crate::config::GLOBAL_CONFIG.set_target(ip_only) {
                        Ok(_) => {
                            results.push(ShellResult {
                                command: trimmed.to_string(),
                                success: true,
                                output: format!("Target set to: {}", ip_only),
                                duration_ms: None,
                            });
                        }
                        Err(e) => {
                            results.push(ShellResult {
                                command: trimmed.to_string(),
                                success: false,
                                output: format!("Failed to set target: {}", e),
                                duration_ms: None,
                            });
                        }
                    }
                }
                } // close else from port/source_port handling
            }

            "set_subnet" => {
                // Mirror shell.rs set_subnet: accepts `sn <CIDR>`, `subnet <CIDR>`, `set subnet <CIDR>`
                let raw_value = if rest.starts_with("subnet ") {
                    rest.strip_prefix("subnet ").unwrap_or(&rest).trim()
                } else if rest.starts_with("sn ") {
                    rest.strip_prefix("sn ").unwrap_or(&rest).trim()
                } else {
                    rest.trim()
                };

                if raw_value.is_empty() {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: sn <CIDR>  or  set subnet <CIDR>  (e.g. 192.168.1.0/24)".to_string(),
                        duration_ms: None,
                    });
                } else if !raw_value.contains('/') {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Not a subnet — use CIDR notation (e.g. 192.168.1.0/24). For single IPs use: set target <IP>".to_string(),
                        duration_ms: None,
                    });
                } else if !validate_target(raw_value) {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Invalid CIDR target".to_string(),
                        duration_ms: None,
                    });
                } else if raw_value.parse::<ipnetwork::IpNetwork>().is_err() {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: format!("Invalid CIDR notation: {}", raw_value),
                        duration_ms: None,
                    });
                } else {
                    match crate::config::GLOBAL_CONFIG.set_target(raw_value) {
                        Ok(_) => {
                            let size = crate::config::GLOBAL_CONFIG.get_target_size();
                            let msg = match size {
                                Some(s) => format!("Subnet set to: {} ({} IPs)", raw_value, s),
                                None    => format!("Subnet set to: {}", raw_value),
                            };
                            results.push(ShellResult {
                                command: trimmed.to_string(),
                                success: true,
                                output: msg,
                                duration_ms: None,
                            });
                        }
                        Err(e) => {
                            results.push(ShellResult {
                                command: trimmed.to_string(),
                                success: false,
                                output: format!("Failed to set subnet: {}", e),
                                duration_ms: None,
                            });
                        }
                    }
                }
            }

            "show_target" => {
                let target = crate::config::GLOBAL_CONFIG.get_target().unwrap_or_else(|| "Not set".to_string());
                let module = state.current_module.lock().ok().and_then(|cm| cm.clone()).unwrap_or_else(|| "None".to_string());
                results.push(ShellResult {
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
                results.push(ShellResult {
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
                results.push(ShellResult {
                    command: trimmed.to_string(),
                    success: true,
                    output: "Module deselected".to_string(),
                    duration_ms: None,
                });
            }

            "run" => {
                let background = rest.trim() == "-j" || rest.trim() == "--job";
                let rest_for_target = if background { String::new() } else { rest.clone() };

                let module_path = state.current_module.lock().ok().and_then(|cm| cm.clone());
                if let Some(module_path) = module_path {
                    // Resolve target: from rest arg, or global config
                    let target = if !rest_for_target.is_empty() {
                        rest_for_target.clone()
                    } else if crate::config::GLOBAL_CONFIG.has_target() {
                        crate::config::GLOBAL_CONFIG.get_target().unwrap_or_default()
                    } else {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "No target set. Use 'set <target>' first.".to_string(),
                            duration_ms: None,
                        });
                        continue;
                    };

                    // SSRF guard — shell 'run' must also validate the resolved target
                    if !validate_target(&target) {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "Target is invalid or blocked (internal/private address)".to_string(),
                            duration_ms: None,
                        });
                        continue;
                    }

                    let verbose = state.verbose;

                    if background {
                        // Background job: spawn via JOB_MANAGER
                        let job_id = crate::jobs::JOB_MANAGER.spawn(
                            module_path.clone(), target.clone(), verbose,
                        );
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: true,
                            output: format!("Job {} started: {} against {}", job_id, module_path, target),
                            duration_ms: Some(start.elapsed().as_millis() as u64),
                        });
                    } else {
                        // Foreground execution
                        let run_start = std::time::Instant::now();
                        let _permit = match state.run_semaphore.acquire().await {
                            Ok(permit) => permit,
                            Err(_) => {
                                results.push(ShellResult {
                                    command: trimmed.to_string(),
                                    success: false,
                                    output: "Server is shutting down".to_string(),
                                    duration_ms: None,
                                });
                                continue;
                            }
                        };
                        match commands::run_module(&module_path, &target, verbose).await {
                            Ok(_) => {
                                results.push(ShellResult {
                                    command: trimmed.to_string(),
                                    success: true,
                                    output: format!("Module '{}' executed against '{}'", module_path, target),
                                    duration_ms: Some(run_start.elapsed().as_millis() as u64),
                                });
                            }
                            Err(e) => {
                                results.push(ShellResult {
                                    command: trimmed.to_string(),
                                    success: false,
                                    output: format!("Module failed: {}", e),
                                    duration_ms: Some(run_start.elapsed().as_millis() as u64),
                                });
                            }
                        }
                    }
                } else {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "No module selected. Use 'use <module>' first.".to_string(),
                        duration_ms: None,
                    });
                }
            }

            "run_all" => {
                let target = if !rest.is_empty() {
                    rest.clone()
                } else if crate::config::GLOBAL_CONFIG.has_target() {
                    crate::config::GLOBAL_CONFIG.get_target().unwrap_or_default()
                } else {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "No target set for run_all".to_string(),
                        duration_ms: None,
                    });
                    continue;
                };

                // SSRF guard — run_all must check the resolved target too
                if !validate_target(&target) {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Target is invalid or blocked (internal/private address)".to_string(),
                        duration_ms: None,
                    });
                    continue;
                }

                let modules = commands::discover_modules();
                let verbose = state.verbose;
                let run_start = std::time::Instant::now();
                let mut ok_count = 0usize;
                let mut fail_count = 0usize;
                for m in &modules {
                    let _permit = match state.run_semaphore.acquire().await {
                        Ok(permit) => permit,
                        Err(_) => {
                            fail_count += 1;
                            continue;
                        }
                    };
                    match commands::run_module(m, &target, verbose).await {
                        Ok(_) => ok_count += 1,
                        Err(_) => fail_count += 1,
                    }
                }
                results.push(ShellResult {
                    command: trimmed.to_string(),
                    success: true,
                    output: format!("run_all complete: {} ok, {} failed out of {} modules",
                        ok_count, fail_count, modules.len()),
                    duration_ms: Some(run_start.elapsed().as_millis() as u64),
                });
            }

            // ═══════════════════════════════════════════════
            // INFO — Module metadata
            // ═══════════════════════════════════════════════
            "info" => {
                let module_path = if !rest.is_empty() {
                    Some(rest.clone())
                } else {
                    state.current_module.lock().ok().and_then(|cm| cm.clone())
                };
                if let Some(ref path) = module_path {
                    if let Some(info) = commands::module_info(path) {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: true,
                            output: serde_json::json!({
                                "module": path,
                                "info": info,
                            }).to_string(),
                            duration_ms: Some(start.elapsed().as_millis() as u64),
                        });
                    } else {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: format!("No metadata available for '{}'. Modules can provide metadata by adding a pub fn info() -> ModuleInfo function.", path),
                            duration_ms: Some(start.elapsed().as_millis() as u64),
                        });
                    }
                } else {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "No module selected. Use 'info <module_path>' or select a module first.".to_string(),
                        duration_ms: None,
                    });
                }
            }

            // ═══════════════════════════════════════════════
            // CHECK — Non-destructive vulnerability check
            // ═══════════════════════════════════════════════
            "check" => {
                let module_path = state.current_module.lock().ok().and_then(|cm| cm.clone());
                if let Some(ref path) = module_path {
                    let target = crate::config::GLOBAL_CONFIG.get_target();
                    if let Some(ref t) = target {
                        if !validate_target(t) || is_blocked_target(t) {
                            results.push(ShellResult {
                                command: trimmed.to_string(),
                                success: false,
                                output: "Target is invalid or blocked (internal/private address)".to_string(),
                                duration_ms: None,
                            });
                        } else {
                            match commands::check_module(path, t).await {
                                Some(result) => {
                                    results.push(ShellResult {
                                        command: trimmed.to_string(),
                                        success: true,
                                        output: serde_json::json!({
                                            "module": path,
                                            "target": t,
                                            "result": result,
                                        }).to_string(),
                                        duration_ms: Some(start.elapsed().as_millis() as u64),
                                    });
                                }
                                None => {
                                    results.push(ShellResult {
                                        command: trimmed.to_string(),
                                        success: false,
                                        output: format!("Module '{}' does not support the check method.", path),
                                        duration_ms: Some(start.elapsed().as_millis() as u64),
                                    });
                                }
                            }
                        }
                    } else {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "No target set. Use 'set target <value>' first.".to_string(),
                            duration_ms: None,
                        });
                    }
                } else {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "No module selected. Use 'use <module>' first.".to_string(),
                        duration_ms: None,
                    });
                }
            }

            // ═══════════════════════════════════════════════
            // GLOBAL OPTIONS
            // ═══════════════════════════════════════════════
            "setg" => {
                if let Some((key, value)) = rest.split_once(char::is_whitespace) {
                    let key = key.trim();
                    let value = value.trim();
                    if key.is_empty() || value.is_empty() || key.len() > 256 || value.len() > 256 {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "Usage: setg <key> <value> (max 256 chars each)".to_string(),
                            duration_ms: None,
                        });
                    } else {
                        crate::global_options::GLOBAL_OPTIONS.set(key, value).await;
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: true,
                            output: format!("{} => {}", key, value),
                            duration_ms: Some(start.elapsed().as_millis() as u64),
                        });
                    }
                } else {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: setg <key> <value>".to_string(),
                        duration_ms: None,
                    });
                }
            }

            "unsetg" => {
                let key = rest.trim();
                if key.is_empty() {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: unsetg <key>".to_string(),
                        duration_ms: None,
                    });
                } else if crate::global_options::GLOBAL_OPTIONS.unset(key).await {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: true,
                        output: format!("Unset global option '{}'", key),
                        duration_ms: Some(start.elapsed().as_millis() as u64),
                    });
                } else {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: format!("Global option '{}' was not set.", key),
                        duration_ms: Some(start.elapsed().as_millis() as u64),
                    });
                }
            }

            "show_options" => {
                let opts = crate::global_options::GLOBAL_OPTIONS.all().await;
                results.push(ShellResult {
                    command: trimmed.to_string(),
                    success: true,
                    output: serde_json::json!({ "options": opts }).to_string(),
                    duration_ms: Some(start.elapsed().as_millis() as u64),
                });
            }

            // ═══════════════════════════════════════════════
            // CREDENTIALS
            // ═══════════════════════════════════════════════
            "creds" => {
                if rest.is_empty() {
                    let entries = crate::cred_store::CRED_STORE.list().await;
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: true,
                        output: serde_json::json!({ "credentials": entries }).to_string(),
                        duration_ms: Some(start.elapsed().as_millis() as u64),
                    });
                } else if let Some(args) = rest.strip_prefix("add ") {
                    // Parse: creds add <host> <port> <service> <username> <secret> [type]
                    let parts: Vec<&str> = args.splitn(6, char::is_whitespace).collect();
                    if parts.len() < 5 {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "Usage: creds add <host> <port> <service> <username> <secret> [type]".to_string(),
                            duration_ms: None,
                        });
                    } else {
                        let host = parts[0].trim();
                        let port: u16 = match parts[1].trim().parse() {
                            Ok(p) if p > 0 => p,
                            _ => {
                                results.push(ShellResult {
                                    command: trimmed.to_string(),
                                    success: false,
                                    output: "Invalid port number. Must be 1-65535.".to_string(),
                                    duration_ms: None,
                                });
                                continue;
                            }
                        };
                        let service = parts[2].trim();
                        let username = parts[3].trim();
                        let (secret, cred_type) = if parts.len() >= 6 {
                            (parts[4].trim(), match parts[5].trim() {
                                "hash" => crate::cred_store::CredType::Hash,
                                "key" => crate::cred_store::CredType::Key,
                                "token" => crate::cred_store::CredType::Token,
                                _ => crate::cred_store::CredType::Password,
                            })
                        } else {
                            (parts[4].trim(), crate::cred_store::CredType::Password)
                        };
                        let id = crate::cred_store::CRED_STORE.add(host, port, service, username, secret, cred_type, "api-shell").await;
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: true,
                            output: format!("Credential stored (ID: {})", id),
                            duration_ms: Some(start.elapsed().as_millis() as u64),
                        });
                    }
                } else if let Some(query) = rest.strip_prefix("search ") {
                    let found = crate::cred_store::CRED_STORE.search(query.trim()).await;
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: true,
                        output: serde_json::json!({ "results": found }).to_string(),
                        duration_ms: Some(start.elapsed().as_millis() as u64),
                    });
                } else if let Some(id) = rest.strip_prefix("delete ") {
                    let deleted = crate::cred_store::CRED_STORE.delete(id.trim()).await;
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: deleted,
                        output: if deleted {
                            format!("Credential '{}' deleted.", id.trim())
                        } else {
                            format!("Credential '{}' not found.", id.trim())
                        },
                        duration_ms: Some(start.elapsed().as_millis() as u64),
                    });
                } else if rest == "clear" {
                    crate::cred_store::CRED_STORE.clear().await;
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: true,
                        output: "All credentials cleared.".to_string(),
                        duration_ms: Some(start.elapsed().as_millis() as u64),
                    });
                } else if rest == "add" {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: creds add <host> <port> <service> <username> <secret> [type]".to_string(),
                        duration_ms: None,
                    });
                } else {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: creds [add <host> <port> <svc> <user> <secret> [type]|search <query>|delete <id>|clear]".to_string(),
                        duration_ms: None,
                    });
                }
            }

            // ═══════════════════════════════════════════════
            // SPOOL — Output logging
            // ═══════════════════════════════════════════════
            "spool" => {
                if rest.is_empty() {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: true,
                        output: "Use 'spool <filename>' to start or 'spool off' to stop.".to_string(),
                        duration_ms: None,
                    });
                } else if rest == "off" {
                    if let Some(name) = crate::spool::SPOOL.stop() {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: true,
                            output: format!("Spool stopped. Output saved to '{}'", name),
                            duration_ms: Some(start.elapsed().as_millis() as u64),
                        });
                    } else {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: true,
                            output: "Spool was not active.".to_string(),
                            duration_ms: None,
                        });
                    }
                } else {
                    match crate::spool::SPOOL.start(&rest) {
                        Ok(()) => {
                            results.push(ShellResult {
                                command: trimmed.to_string(),
                                success: true,
                                output: format!("Spooling output to '{}'", rest),
                                duration_ms: Some(start.elapsed().as_millis() as u64),
                            });
                        }
                        Err(e) => {
                            results.push(ShellResult {
                                command: trimmed.to_string(),
                                success: false,
                                output: format!("Failed to start spool: {}", e),
                                duration_ms: Some(start.elapsed().as_millis() as u64),
                            });
                        }
                    }
                }
            }

            // ═══════════════════════════════════════════════
            // RESOURCE / MAKERC — Blocked in API mode
            // ═══════════════════════════════════════════════
            "resource" => {
                results.push(ShellResult {
                    command: trimmed.to_string(),
                    success: false,
                    output: "Resource scripts are disabled in API mode for security. Send commands directly via the 'commands' JSON array.".to_string(),
                    duration_ms: None,
                });
            }

            "makerc" => {
                results.push(ShellResult {
                    command: trimmed.to_string(),
                    success: false,
                    output: "makerc is not applicable in API mode (no shell history).".to_string(),
                    duration_ms: None,
                });
            }

            // ═══════════════════════════════════════════════
            // HOSTS
            // ═══════════════════════════════════════════════
            "hosts" => {
                if rest.is_empty() {
                    let entries = crate::workspace::WORKSPACE.hosts().await;
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: true,
                        output: serde_json::json!({ "hosts": entries }).to_string(),
                        duration_ms: Some(start.elapsed().as_millis() as u64),
                    });
                } else if let Some(ip) = rest.strip_prefix("add ") {
                    let ip = ip.trim();
                    if ip.is_empty() {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "Usage: hosts add <ip>".to_string(),
                            duration_ms: None,
                        });
                    } else {
                        crate::workspace::WORKSPACE.add_host(ip, None, None).await;
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: true,
                            output: format!("Host '{}' added to workspace.", ip),
                            duration_ms: Some(start.elapsed().as_millis() as u64),
                        });
                    }
                } else if let Some(ip) = rest.strip_prefix("delete ") {
                    let ip = ip.trim();
                    if ip.is_empty() {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "Usage: hosts delete <ip>".to_string(),
                            duration_ms: None,
                        });
                    } else {
                        let deleted = crate::workspace::WORKSPACE.delete_host(ip).await;
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: deleted,
                            output: if deleted {
                                format!("Host '{}' and its services removed.", ip)
                            } else {
                                format!("Host '{}' not found.", ip)
                            },
                            duration_ms: Some(start.elapsed().as_millis() as u64),
                        });
                    }
                } else if rest == "clear" {
                    crate::workspace::WORKSPACE.clear_hosts().await;
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: true,
                        output: "All hosts and services cleared.".to_string(),
                        duration_ms: Some(start.elapsed().as_millis() as u64),
                    });
                } else {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: hosts [add <ip>|delete <ip>|clear]".to_string(),
                        duration_ms: None,
                    });
                }
            }

            // ═══════════════════════════════════════════════
            // SERVICES
            // ═══════════════════════════════════════════════
            "services" => {
                if rest.is_empty() {
                    let entries = crate::workspace::WORKSPACE.services().await;
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: true,
                        output: serde_json::json!({ "services": entries }).to_string(),
                        duration_ms: Some(start.elapsed().as_millis() as u64),
                    });
                } else if let Some(args) = rest.strip_prefix("add ") {
                    // Parse: services add <host> <port> <proto> <service_name> [version]
                    let parts: Vec<&str> = args.splitn(5, char::is_whitespace).collect();
                    if parts.len() < 4 {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "Usage: services add <host> <port> <protocol> <service_name> [version]".to_string(),
                            duration_ms: None,
                        });
                    } else {
                        let host = parts[0].trim();
                        let port: u16 = match parts[1].trim().parse() {
                            Ok(p) if p > 0 => p,
                            _ => {
                                results.push(ShellResult {
                                    command: trimmed.to_string(),
                                    success: false,
                                    output: "Invalid port number. Must be 1-65535.".to_string(),
                                    duration_ms: None,
                                });
                                continue;
                            }
                        };
                        let proto = parts[2].trim();
                        let svc = parts[3].trim();
                        let version = if parts.len() >= 5 { Some(parts[4].trim()) } else { None };
                        crate::workspace::WORKSPACE.add_service(host, port, proto, svc, version).await;
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: true,
                            output: format!("Service {}:{}/{} added.", host, port, svc),
                            duration_ms: Some(start.elapsed().as_millis() as u64),
                        });
                    }
                } else if rest == "add" {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: services add <host> <port> <protocol> <service_name> [version]".to_string(),
                        duration_ms: None,
                    });
                } else if let Some(args) = rest.strip_prefix("delete ") {
                    let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
                    if parts.len() < 2 {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "Usage: services delete <host> <port>".to_string(),
                            duration_ms: None,
                        });
                    } else {
                        let host = parts[0].trim();
                        match parts[1].trim().parse::<u16>() {
                            Ok(port) if port > 0 => {
                                let deleted = crate::workspace::WORKSPACE.delete_service(host, port).await;
                                results.push(ShellResult {
                                    command: trimmed.to_string(),
                                    success: deleted,
                                    output: if deleted {
                                        format!("Service {}:{} removed.", host, port)
                                    } else {
                                        format!("Service {}:{} not found.", host, port)
                                    },
                                    duration_ms: Some(start.elapsed().as_millis() as u64),
                                });
                            }
                            _ => {
                                results.push(ShellResult {
                                    command: trimmed.to_string(),
                                    success: false,
                                    output: "Invalid port number. Must be 1-65535.".to_string(),
                                    duration_ms: None,
                                });
                            }
                        }
                    }
                } else {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: services [add <host> <port> <proto> <name> [version]|delete <host> <port>]".to_string(),
                        duration_ms: None,
                    });
                }
            }

            // ═══════════════════════════════════════════════
            // NOTES
            // ═══════════════════════════════════════════════
            "notes" => {
                if let Some((ip, note)) = rest.split_once(char::is_whitespace) {
                    let ip = ip.trim();
                    let note = note.trim();
                    if ip.is_empty() || note.is_empty() {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "Usage: notes <ip> <note text>".to_string(),
                            duration_ms: None,
                        });
                    } else if crate::workspace::WORKSPACE.add_note(ip, note).await {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: true,
                            output: format!("Note added to host '{}'.", ip),
                            duration_ms: Some(start.elapsed().as_millis() as u64),
                        });
                    } else {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: format!("Host '{}' not found. Add it first with 'hosts add {}'.", ip, ip),
                            duration_ms: Some(start.elapsed().as_millis() as u64),
                        });
                    }
                } else {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: notes <ip> <note text>".to_string(),
                        duration_ms: None,
                    });
                }
            }

            // ═══════════════════════════════════════════════
            // WORKSPACE
            // ═══════════════════════════════════════════════
            "workspace" => {
                if rest.is_empty() {
                    let current = crate::workspace::WORKSPACE.current_name().await;
                    let workspaces = crate::workspace::WORKSPACE.list_workspaces().await;
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: true,
                        output: serde_json::json!({
                            "current": current,
                            "workspaces": workspaces,
                        }).to_string(),
                        duration_ms: Some(start.elapsed().as_millis() as u64),
                    });
                } else {
                    let name = rest.trim();
                    if name.is_empty() || name.len() > 64 {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "Workspace name must be 1-64 characters.".to_string(),
                            duration_ms: None,
                        });
                    } else if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                        crate::workspace::WORKSPACE.switch(name).await;
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: true,
                            output: format!("Switched to workspace '{}'", name),
                            duration_ms: Some(start.elapsed().as_millis() as u64),
                        });
                    } else {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "Workspace name must be alphanumeric (with _ and -).".to_string(),
                            duration_ms: None,
                        });
                    }
                }
            }

            // ═══════════════════════════════════════════════
            // LOOT
            // ═══════════════════════════════════════════════
            "loot" => {
                if rest.is_empty() {
                    let entries = crate::loot::LOOT_STORE.list().await;
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: true,
                        output: serde_json::json!({ "loot": entries }).to_string(),
                        duration_ms: Some(start.elapsed().as_millis() as u64),
                    });
                } else if let Some(args) = rest.strip_prefix("add ") {
                    // Parse: loot add <host> <type> <description> <data>
                    let parts: Vec<&str> = args.splitn(4, char::is_whitespace).collect();
                    if parts.len() < 4 {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "Usage: loot add <host> <type> <description> <data>".to_string(),
                            duration_ms: None,
                        });
                    } else {
                        let host = parts[0].trim();
                        let ltype = parts[1].trim();
                        let desc = parts[2].trim();
                        let data = parts[3].trim();
                        if let Some(id) = crate::loot::LOOT_STORE.add_text(host, ltype, desc, data, "api-shell").await {
                            results.push(ShellResult {
                                command: trimmed.to_string(),
                                success: true,
                                output: format!("Loot stored (ID: {})", id),
                                duration_ms: Some(start.elapsed().as_millis() as u64),
                            });
                        } else {
                            results.push(ShellResult {
                                command: trimmed.to_string(),
                                success: false,
                                output: "Failed to store loot.".to_string(),
                                duration_ms: Some(start.elapsed().as_millis() as u64),
                            });
                        }
                    }
                } else if let Some(query) = rest.strip_prefix("search ") {
                    let found = crate::loot::LOOT_STORE.search(query.trim()).await;
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: true,
                        output: serde_json::json!({ "results": found }).to_string(),
                        duration_ms: Some(start.elapsed().as_millis() as u64),
                    });
                } else if rest == "add" {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: loot add <host> <type> <description> <data>".to_string(),
                        duration_ms: None,
                    });
                } else if let Some(id) = rest.strip_prefix("delete ") {
                    let id = id.trim();
                    if id.is_empty() {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "Usage: loot delete <id>".to_string(),
                            duration_ms: None,
                        });
                    } else {
                        let deleted = crate::loot::LOOT_STORE.delete(id).await;
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: deleted,
                            output: if deleted {
                                format!("Loot '{}' deleted.", id)
                            } else {
                                format!("Loot '{}' not found.", id)
                            },
                            duration_ms: Some(start.elapsed().as_millis() as u64),
                        });
                    }
                } else if rest == "clear" {
                    crate::loot::LOOT_STORE.clear().await;
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: true,
                        output: "All loot cleared.".to_string(),
                        duration_ms: Some(start.elapsed().as_millis() as u64),
                    });
                } else {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: loot [add <host> <type> <desc> <data>|search <query>|delete <id>|clear]".to_string(),
                        duration_ms: None,
                    });
                }
            }

            // ═══════════════════════════════════════════════
            // EXPORT
            // ═══════════════════════════════════════════════
            "export" => {
                if let Some((fmt, path)) = rest.split_once(char::is_whitespace) {
                    let path = path.trim();
                    if path.is_empty() || path.contains("..") || path.contains('\0') || path.contains('/') || path.contains('\\') {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "Invalid file path.".to_string(),
                            duration_ms: None,
                        });
                    } else {
                        let export_result = match fmt.trim() {
                            "json" => crate::export::export_json(path).await,
                            "csv" => crate::export::export_csv(path).await,
                            "summary" => crate::export::export_summary(path).await,
                            _ => {
                                results.push(ShellResult {
                                    command: trimmed.to_string(),
                                    success: false,
                                    output: "Usage: export <json|csv|summary> <filename>".to_string(),
                                    duration_ms: None,
                                });
                                continue;
                            }
                        };
                        match export_result {
                            Ok(()) => {
                                results.push(ShellResult {
                                    command: trimmed.to_string(),
                                    success: true,
                                    output: format!("Exported {} to '{}'", fmt.trim(), path),
                                    duration_ms: Some(start.elapsed().as_millis() as u64),
                                });
                            }
                            Err(e) => {
                                results.push(ShellResult {
                                    command: trimmed.to_string(),
                                    success: false,
                                    output: format!("Export failed: {}", e),
                                    duration_ms: Some(start.elapsed().as_millis() as u64),
                                });
                            }
                        }
                    }
                } else {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: export <json|csv|summary> <filename>".to_string(),
                        duration_ms: None,
                    });
                }
            }

            // ═══════════════════════════════════════════════
            // JOBS
            // ═══════════════════════════════════════════════
            "jobs" => {
                if rest.is_empty() {
                    let job_list = crate::jobs::JOB_MANAGER.list();
                    let jobs_json: Vec<serde_json::Value> = job_list.iter().map(|(id, module, target, started, status)| {
                        serde_json::json!({
                            "id": id,
                            "module": module,
                            "target": target,
                            "started": started,
                            "status": status,
                        })
                    }).collect();
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: true,
                        output: serde_json::json!({ "jobs": jobs_json }).to_string(),
                        duration_ms: Some(start.elapsed().as_millis() as u64),
                    });
                } else if let Some(id_str) = rest.strip_prefix("-k ") {
                    if let Ok(id) = id_str.trim().parse::<u32>() {
                        if crate::jobs::JOB_MANAGER.kill(id) {
                            results.push(ShellResult {
                                command: trimmed.to_string(),
                                success: true,
                                output: format!("Job {} cancelled.", id),
                                duration_ms: Some(start.elapsed().as_millis() as u64),
                            });
                        } else {
                            results.push(ShellResult {
                                command: trimmed.to_string(),
                                success: false,
                                output: format!("Job {} not found.", id),
                                duration_ms: Some(start.elapsed().as_millis() as u64),
                            });
                        }
                    } else {
                        results.push(ShellResult {
                            command: trimmed.to_string(),
                            success: false,
                            output: "Usage: jobs -k <id>".to_string(),
                            duration_ms: None,
                        });
                    }
                } else if rest == "clean" {
                    crate::jobs::JOB_MANAGER.cleanup();
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: true,
                        output: "Finished jobs cleaned up.".to_string(),
                        duration_ms: Some(start.elapsed().as_millis() as u64),
                    });
                } else {
                    results.push(ShellResult {
                        command: trimmed.to_string(),
                        success: false,
                        output: "Usage: jobs [-k <id>|clean]".to_string(),
                        duration_ms: None,
                    });
                }
            }

            "exit" => {
                results.push(ShellResult {
                    command: trimmed.to_string(),
                    success: true,
                    output: "Exit not applicable in API mode".to_string(),
                    duration_ms: None,
                });
            }

            other => {
                results.push(ShellResult {
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
        if all_ok { StatusCode::OK } else { StatusCode::BAD_REQUEST },
        Json(ok_response(
            format!("{} shell command(s) executed", total),
            Some(serde_json::json!({
                "results": results,
            })),
        )),
    ).into_response()
}

// ─── TLS Helpers ────────────────────────────────────────────────────

// ─── Security Headers Middleware ────────────────────────────────────

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        "Cache-Control",
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static("default-src 'none'"),
    );
    // HSTS: only useful when TLS is active, but safe to always set
    headers.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    response
}

// ─── Rate Limiting Middleware ───────────────────────────────────────

async fn rate_limit_middleware(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let ip = addr.ip();
    let now = Instant::now();

    let allowed = {
        let mut limiter = state.rate_limiter.lock().unwrap();
        let entry = limiter.entry(ip).or_insert((0, now));

        // Reset window if expired
        if now.duration_since(entry.1).as_secs() >= RATE_LIMIT_WINDOW_SECS {
            *entry = (0, now);
        }

        entry.0 += 1;
        entry.0 <= RATE_LIMIT_MAX_REQUESTS
    };

    if !allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(err_response(
                format!("Rate limit exceeded ({} requests per {}s)", RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS),
                "RATE_LIMITED",
            )),
        )
            .into_response();
    }

    next.run(request).await
}

// ─── IP Whitelist Middleware ────────────────────────────────────────

async fn ip_whitelist_middleware(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    if !state.ip_whitelist.is_empty() {
        let ip_str = addr.ip().to_string();
        if !state.ip_whitelist.contains(&ip_str) {
            return (
                StatusCode::FORBIDDEN,
                Json(err_response(
                    "Your IP is not in the whitelist",
                    "IP_BLOCKED",
                )),
            )
                .into_response();
        }
    }
    next.run(request).await
}

// ─── Server Entry Point ─────────────────────────────────────────────

pub async fn start_api_server(
    bind_address: &str,
    verbose: bool,
    host_key_path: &std::path::Path,
    authorized_keys_path: &std::path::Path,
) -> Result<()> {
    // Load or generate PQ host identity key
    let host_identity = crate::pq_channel::HostIdentity::load_or_generate(host_key_path)
        .context("Failed to load/generate PQ host key")?;

    // Load authorized client keys
    let authorized_keys = crate::pq_channel::load_authorized_keys(authorized_keys_path)
        .context("Failed to load authorized keys")?;

    let pq_sessions = crate::pq_channel::new_session_store();

    // Load optional IP whitelist
    let whitelist = load_ip_whitelist();
    if !whitelist.is_empty() {
        println!("🔒 IP whitelist loaded: {} entries", whitelist.len());
        for ip in &whitelist {
            println!("   ✓ {}", ip);
        }
    } else {
        println!("🌐 No IP whitelist configured (all IPs allowed)");
    }

    let state = ApiState {
        verbose,
        ip_whitelist: Arc::new(whitelist),
        current_module: Arc::new(Mutex::new(None)),
        rate_limiter: Arc::new(Mutex::new(HashMap::new())),
        run_semaphore: Arc::new(tokio::sync::Semaphore::new(num_cpus::get().max(4))),
    };

    let n_plugins = crate::commands::plugin_count();
    if n_plugins > 0 {
        eprintln!("{}", "[!] WARNING: Third-party plugins loaded. RustSploit is NOT responsible for third-party plugin behavior.".red().bold());
        eprintln!("[!] Loaded plugins: {}", n_plugins);
    }

    println!("🚀 Starting RustSploit API server (PQ-encrypted, no TLS)...");
    println!("📍 Binding to: {}", bind_address);
    println!("🔑 Host key fingerprint: {}", host_identity.fingerprint());
    println!("🔐 Authorized clients: {}", authorized_keys.len());
    for key in &authorized_keys {
        println!("   ✓ {} ({})",
            key.name,
            crate::pq_channel::fingerprint(&key.x25519_public, &key.mlkem_ek));
    }
    println!("📢 Verbose: {}", verbose);

    // Protected routes (require API key)
    let protected = Router::new()
        .route("/api/modules", get(list_modules))
        .route("/api/modules/search", get(search_modules))
        .route("/api/module/{*path}", get(get_module_info))
        .route("/api/run", post(run_module))
        .route("/api/target", get(get_target))
        .route("/api/target", post(set_target))
        .route("/api/target", axum::routing::delete(clear_target))
        .route("/api/honeypot-check", post(honeypot_check))
        .route("/api/shell", post(shell_command))
        .route("/api/results", get(list_results))
        .route("/api/results/{filename}", get(get_result_file))
        // Global options
        .route("/api/options", get(get_options))
        .route("/api/options", post(set_option))
        .route("/api/options", axum::routing::delete(delete_option))
        // Credential store
        .route("/api/creds", get(list_creds))
        .route("/api/creds", post(add_cred))
        .route("/api/creds", axum::routing::delete(delete_cred))
        // Workspace / hosts / services
        .route("/api/hosts", get(list_hosts))
        .route("/api/hosts", post(add_host))
        .route("/api/services", get(list_services))
        .route("/api/services", post(add_service))
        .route("/api/workspace", get(get_workspace))
        .route("/api/workspace", post(switch_workspace))
        // Loot
        .route("/api/loot", get(list_loot))
        .route("/api/loot", post(add_loot))
        // Jobs
        .route("/api/jobs", get(list_jobs))
        .route("/api/jobs/{id}", axum::routing::delete(kill_job))
        // Export
        .route("/api/export", get(export_data))
        .layer(axum::middleware::from_fn(crate::pq_middleware::pq_middleware));

    // PQ shared state as Extension (accessible by middleware and handshake handler)
    let pq_state = Arc::new(crate::pq_middleware::PqSharedState {
        sessions: pq_sessions,
        host_identity: Arc::new(host_identity),
        authorized_keys: Arc::new(authorized_keys),
    });

    // Public routes: health check + PQ handshake (must be unauthenticated)
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/pq/handshake", post(crate::pq_middleware::handshake_handler))
        .merge(protected)
        .layer(axum::Extension(pq_state))
        .layer(axum::middleware::from_fn_with_state(state.clone(), rate_limit_middleware))
        .layer(axum::middleware::from_fn_with_state(state.clone(), ip_whitelist_middleware))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(
            ServiceBuilder::new()
                .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_SIZE))
                .layer(TraceLayer::new_for_http()),
        )
        .with_state(state);

    // PQ-encrypted server — no TLS, no API keys
    // All API routes are encrypted via the PQ middleware layer.
    // Authentication is via the PQ handshake (SSH-style identity keys).
    println!("✅ API server is running on http://{}", bind_address);
    println!("🔐 Transport: Post-Quantum encryption (ML-KEM-768 + X25519 + ChaCha20-Poly1305)");
    println!("🔑 Authentication: SSH-style identity keys (no API keys, no TLS)");
    println!("   Clients must complete PQ handshake at POST /pq/handshake before API access");

    let listener = tokio::net::TcpListener::bind(bind_address)
        .await
        .context(format!("Failed to bind to {}", bind_address))?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("API server error")?;

    Ok(())
}
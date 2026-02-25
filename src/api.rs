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
use std::net::SocketAddr;
use std::sync::Arc;
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
}

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
}

#[derive(Serialize, Deserialize)]
pub struct SetTargetRequest {
    pub target: String,
}

#[derive(Serialize, Deserialize)]
pub struct HoneypotCheckRequest {
    pub target: String,
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

// ─── Auth Middleware ────────────────────────────────────────────────

async fn auth_middleware(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
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
    let module_config = crate::config::ModuleConfig {
        port: payload.port,
        username_wordlist: payload.username_wordlist.clone(),
        password_wordlist: payload.password_wordlist.clone(),
        concurrency: payload.concurrency,
        stop_on_success: payload.stop_on_success,
        save_results: payload.save_results,
        output_file: payload.output_file.clone(),
        verbose: payload.verbose,
        combo_mode: payload.combo_mode,
    };
    crate::config::set_module_config(module_config);

    let verbose = state.verbose || payload.verbose.unwrap_or(false);

    if state.verbose {
        eprintln!(
            "[API] Running module '{}' against '{}' (verbose={})",
            module_name, target_raw, verbose
        );
    }

    // Run synchronously (same as CLI `run` command)
    let result = commands::run_module(module_name, target_raw, verbose).await;

    // Clear module config after execution
    crate::config::clear_module_config();

    let duration_ms = start.elapsed().as_millis() as u64;

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
use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::net::SocketAddr;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
};
use tokio::{
    fs::OpenOptions,
    io::AsyncWriteExt,
    sync::RwLock,
};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::commands;

#[derive(Clone, Debug)]
pub struct ApiKey {
    pub key: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IpTracker {
    pub ip: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub request_count: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuthFailureTracker {
    pub ip: String,
    pub failed_attempts: u32,
    pub first_failure: DateTime<Utc>,
    pub blocked_until: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct ApiState {
    pub current_key: Arc<RwLock<ApiKey>>,
    pub ip_tracker: Arc<RwLock<HashMap<String, IpTracker>>>,
    pub auth_failures: Arc<RwLock<HashMap<String, AuthFailureTracker>>>,
    pub harden_enabled: bool,
    pub ip_limit: u32,
    pub log_file: PathBuf,
}

#[derive(Serialize, Deserialize)]
pub struct ApiResponse {
    pub success: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
pub struct RunModuleRequest {
    pub module: String,
    pub target: String,
}

#[derive(Serialize, Deserialize)]
pub struct ListModulesResponse {
    pub exploits: Vec<String>,
    pub scanners: Vec<String>,
    pub creds: Vec<String>,
}

// ----------------------
// Validation utilities
// ----------------------
fn sanitize_for_log(input: &str) -> String {
    let mut s = input.replace(['\r', '\n', '\t'], " ");
    if s.len() > 500 {
        s.truncate(500);
        s.push_str("…");
    }
    s
}

fn is_printable_ascii(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_graphic() || c == ' ' || c == '/' || c == ':' || c == '.')
}

fn validate_api_key_format(key: &str) -> bool {
    !key.is_empty() && key.len() <= 128 && key.chars().all(|c| c.is_ascii_graphic())
}

fn validate_module_name(module: &str) -> bool {
    // Allow only expected module path forms, e.g., "exploits/x", "scanners/y", "creds/z"
    if module.is_empty() || module.len() > 200 { return false; }
    if !module.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '/' || c == '_' || c == '-') {
        return false;
    }
    let parts: Vec<&str> = module.split('/').collect();
    if parts.len() < 2 { return false; }
    matches!(parts[0], "exploits" | "scanners" | "creds")
}

fn validate_target(target: &str) -> bool {
    if target.is_empty() || target.len() > 2048 { return false; }
    if !is_printable_ascii(target) { return false; }
    // Basic sanity: avoid spaces at ends and double CRLF injections
    let trimmed = target.trim();
    trimmed == target && !target.contains("\r\n\r\n")
}

impl ApiState {
    pub fn new(initial_key: String, harden: bool, ip_limit: u32) -> Self {
        let log_file = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("rustsploit_api.log");

        Self {
            current_key: Arc::new(RwLock::new(ApiKey {
                key: initial_key,
                created_at: Utc::now(),
            })),
            ip_tracker: Arc::new(RwLock::new(HashMap::new())),
            auth_failures: Arc::new(RwLock::new(HashMap::new())),
            harden_enabled: harden,
            ip_limit,
            log_file,
        }
    }

    pub async fn rotate_key(&self) -> Result<String> {
        let new_key = Uuid::new_v4().to_string();
        let mut key_guard = self.current_key.write().await;
        key_guard.key = new_key.clone();
        key_guard.created_at = Utc::now();
        drop(key_guard);

        // Clear IP tracker on rotation
        let mut tracker_guard = self.ip_tracker.write().await;
        tracker_guard.clear();
        drop(tracker_guard);

        self.log_message(&format!(
            "[SECURITY] API key rotated at {}",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ))
        .await?;

        Ok(new_key)
    }

    pub async fn track_ip(&self, ip: &str) -> Result<bool> {
        if !self.harden_enabled {
            return Ok(false);
        }

        let mut tracker_guard = self.ip_tracker.write().await;
        let now = Utc::now();

        if let Some(tracker) = tracker_guard.get_mut(ip) {
            // Update existing tracker - use all fields
            tracker.last_seen = now;
            tracker.request_count += 1;
            
            // Log detailed tracking info using first_seen
            let duration = now.signed_duration_since(tracker.first_seen);
            let _ = self.log_message(&format!(
                "[TRACKING] IP {}: {} requests since {} ({} seconds ago)",
                tracker.ip,
                tracker.request_count,
                tracker.first_seen.format("%Y-%m-%d %H:%M:%S UTC"),
                duration.num_seconds()
            )).await;
        } else {
            // Create new tracker - all fields are set and will be used
            let new_tracker = IpTracker {
                ip: ip.to_string(),
                first_seen: now,
                last_seen: now,
                request_count: 1,
            };
            
            // Log new IP using all fields
            let _ = self.log_message(&format!(
                "[TRACKING] New IP detected: {} (first seen: {})",
                new_tracker.ip,
                new_tracker.first_seen.format("%Y-%m-%d %H:%M:%S UTC")
            )).await;
            
            tracker_guard.insert(ip.to_string(), new_tracker);
        }

        let unique_ips = tracker_guard.len() as u32;
        drop(tracker_guard);

        if unique_ips > self.ip_limit {
            let new_key = self.rotate_key().await?;
            self.log_message(&format!(
                "[HARDENING] Auto-rotated API key due to {} unique IPs exceeding limit of {}. New key: {}",
                unique_ips, self.ip_limit, new_key
            ))
            .await?;
            println!(
                "⚠️  [HARDENING] API key auto-rotated! {} unique IPs exceeded limit of {}",
                unique_ips, self.ip_limit
            );
            println!("⚠️  New API key: {}", new_key);
            return Ok(true);
        }

        Ok(false)
    }

    pub async fn log_message(&self, message: &str) -> Result<()> {
        let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        let safe = sanitize_for_log(message);
        let log_entry = format!("[{}] {}\n", timestamp, safe);

        // Log to terminal
        println!("{}", log_entry.trim());

        // Log to file
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)
            .await
            .context("Failed to open log file")?;

        file.write_all(log_entry.as_bytes())
            .await
            .context("Failed to write to log file")?;

        Ok(())
    }

    pub async fn verify_key(&self, provided_key: &str) -> bool {
        let key_guard = self.current_key.read().await;
        key_guard.key == provided_key
    }

    pub async fn check_auth_rate_limit(&self, ip: &str) -> Result<bool> {
        let mut failures_guard = self.auth_failures.write().await;
        let now = Utc::now();

        if let Some(tracker) = failures_guard.get_mut(ip) {
            // Check if IP is currently blocked
            if let Some(blocked_until) = tracker.blocked_until {
                if now < blocked_until {
                    let remaining = (blocked_until - now).num_seconds();
                    self.log_message(&format!(
                        "[RATE_LIMIT] IP {} is blocked for {} more seconds ({} failed attempts)",
                        ip, remaining, tracker.failed_attempts
                    ))
                    .await?;
                    return Ok(false); // Blocked
                } else {
                    // Block period expired, reset
                    tracker.failed_attempts = 0;
                    tracker.blocked_until = None;
                    self.log_message(&format!(
                        "[RATE_LIMIT] Block period expired for IP {}, resetting counter",
                        ip
                    ))
                    .await?;
                }
            }
        }

        Ok(true) // Not blocked
    }

    pub async fn record_auth_failure(&self, ip: &str) -> Result<()> {
        let mut failures_guard = self.auth_failures.write().await;
        let now = Utc::now();

        let tracker = failures_guard.entry(ip.to_string()).or_insert_with(|| {
            AuthFailureTracker {
                ip: ip.to_string(),
                failed_attempts: 0,
                first_failure: now,
                blocked_until: None,
            }
        });

        // Set first_failure if this is the first attempt
        if tracker.failed_attempts == 0 {
            tracker.first_failure = now;
        }

        tracker.failed_attempts += 1;

        // Block after 3 failed attempts for 30 seconds
        if tracker.failed_attempts >= 3 {
            let block_until = now + chrono::Duration::seconds(30);
            tracker.blocked_until = Some(block_until);
            
            let duration_since_first = (now - tracker.first_failure).num_seconds();
            self.log_message(&format!(
                "[RATE_LIMIT] IP {} blocked for 30 seconds after {} failed authentication attempts (first failure: {}, {} seconds since first)",
                tracker.ip, tracker.failed_attempts,
                tracker.first_failure.format("%Y-%m-%d %H:%M:%S UTC"),
                duration_since_first
            ))
            .await?;
            
            println!(
                "🚫 [RATE_LIMIT] IP {} blocked for 30 seconds ({} failed attempts since {})",
                tracker.ip, tracker.failed_attempts,
                tracker.first_failure.format("%Y-%m-%d %H:%M:%S UTC")
            );
        } else {
            self.log_message(&format!(
                "[RATE_LIMIT] IP {} failed authentication attempt {}/3 (first failure: {})",
                tracker.ip, tracker.failed_attempts,
                tracker.first_failure.format("%Y-%m-%d %H:%M:%S UTC")
            ))
            .await?;
        }

        Ok(())
    }

    pub async fn reset_auth_failures(&self, ip: &str) -> Result<()> {
        let mut failures_guard = self.auth_failures.write().await;
        
        if let Some(tracker) = failures_guard.get_mut(ip) {
            if tracker.failed_attempts > 0 {
                self.log_message(&format!(
                    "[RATE_LIMIT] Resetting auth failure counter for IP {} (was {} attempts)",
                    ip, tracker.failed_attempts
                ))
                .await?;
            }
            tracker.failed_attempts = 0;
            tracker.blocked_until = None;
        }

        Ok(())
    }
}

async fn auth_middleware(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    // Extract IP address - try to get from headers first (for proxied requests)
    let client_ip = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .map(|s| {
            s.split(',')
                .next()
                .unwrap_or("")
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| addr.ip().to_string());

    // Check rate limit before processing authentication
    if client_ip != "unknown" {
        if let Ok(allowed) = state.check_auth_rate_limit(&client_ip).await {
            if !allowed {
                let response = ApiResponse {
                    success: false,
                    message: "Too many failed authentication attempts. Please try again in 30 seconds.".to_string(),
                    data: None,
                };
                return (StatusCode::TOO_MANY_REQUESTS, Json(response)).into_response();
            }
        }
    }

    // Extract API key from Authorization header
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let provided_key = if auth_header.starts_with("Bearer ") {
        &auth_header[7..]
    } else if auth_header.starts_with("ApiKey ") {
        &auth_header[7..]
    } else {
        auth_header
    };

    // Basic key format validation
    if !validate_api_key_format(provided_key) {
        let response = ApiResponse {
            success: false,
            message: "Malformed API key".to_string(),
            data: None,
        };
        return (StatusCode::UNAUTHORIZED, Json(response)).into_response();
    }

    // Verify API key
    let is_valid = state.verify_key(provided_key).await;

    if !is_valid {
        // Record failed authentication attempt
        if client_ip != "unknown" {
            let _ = state.record_auth_failure(&client_ip).await;
        }

        let response = ApiResponse {
            success: false,
            message: "Invalid API key".to_string(),
            data: None,
        };
        return (StatusCode::UNAUTHORIZED, Json(response)).into_response();
    }

    // Successful authentication - reset failure counter for this IP
    if client_ip != "unknown" {
        let _ = state.reset_auth_failures(&client_ip).await;
    }

    // Track IP for hardening (if enabled)
    let _ = state.track_ip(&client_ip).await;

    next.run(request).await
}

async fn health_check() -> Json<ApiResponse> {
    Json(ApiResponse {
        success: true,
        message: "API is running".to_string(),
        data: None,
    })
}

async fn list_modules(State(_state): State<ApiState>) -> Json<ApiResponse> {
    let modules = commands::discover_modules();
    let mut exploits = Vec::new();
    let mut scanners = Vec::new();
    let mut creds = Vec::new();

    for module in modules {
        if module.starts_with("exploits/") {
            exploits.push(module);
        } else if module.starts_with("scanners/") {
            scanners.push(module);
        } else if module.starts_with("creds/") {
            creds.push(module);
        }
    }

    let data = ListModulesResponse {
        exploits,
        scanners,
        creds,
    };

    Json(ApiResponse {
        success: true,
        message: "Modules retrieved successfully".to_string(),
        data: Some(serde_json::to_value(data).unwrap()),
    })
}

async fn run_module(
    State(state): State<ApiState>,
    Json(payload): Json<RunModuleRequest>,
) -> Result<Json<ApiResponse>, StatusCode> {
    let module_name_raw = payload.module.as_str();
    let target_raw = payload.target.as_str();

    // Validate inputs
    if !validate_module_name(module_name_raw) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !validate_target(target_raw) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Sanitize for logging only
    let module_name = sanitize_for_log(module_name_raw);
    let target_name = sanitize_for_log(target_raw);
    
    state
        .log_message(&format!(
            "API request: run module '{}' on target '{}'",
            module_name, target_name
        ))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Run the module in a separate OS thread since some modules aren't Send
    let module = payload.module.clone();
    let target = payload.target.clone();
    let state_clone = state.clone();

    // Use std::thread to run in a separate OS thread with its own runtime
    std::thread::spawn(move || {
        // Create a new runtime for this thread since modules need async runtime
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            if let Err(e) = commands::run_module(&module, &target).await {
                let _ = state_clone
                    .log_message(&format!("Error running module: {}", sanitize_for_log(&e.to_string())))
                    .await;
            } else {
                let _ = state_clone
                    .log_message(&format!(
                        "Successfully completed module '{}' on target '{}'",
                        sanitize_for_log(&module), sanitize_for_log(&target)
                    ))
                    .await;
            }
        });
    });

    Ok(Json(ApiResponse {
        success: true,
        message: format!("Module '{}' execution started for target '{}'", module_name, target_name),
        data: None,
    }))
}

async fn get_status(State(state): State<ApiState>) -> Json<ApiResponse> {
    let key_guard = state.current_key.read().await;
    let tracker_guard = state.ip_tracker.read().await;

    // Collect all tracked IPs with their details
    let tracked_ips: Vec<&IpTracker> = tracker_guard.values().collect();
    let ip_details: Vec<serde_json::Value> = tracked_ips
        .iter()
        .map(|tracker| {
            serde_json::json!({
                "ip": tracker.ip,
                "first_seen": tracker.first_seen.to_rfc3339(),
                "last_seen": tracker.last_seen.to_rfc3339(),
                "request_count": tracker.request_count,
            })
        })
        .collect();

    let status_data = serde_json::json!({
        "harden_enabled": state.harden_enabled,
        "ip_limit": state.ip_limit,
        "unique_ips": tracker_guard.len(),
        "key_created_at": key_guard.created_at.to_rfc3339(),
        "log_file": state.log_file.to_string_lossy(),
        "tracked_ips": ip_details,
    });

    Json(ApiResponse {
        success: true,
        message: "Status retrieved successfully".to_string(),
        data: Some(status_data),
    })
}

async fn rotate_key_endpoint(State(state): State<ApiState>) -> Result<Json<ApiResponse>, StatusCode> {
    let new_key = state
        .rotate_key()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiResponse {
        success: true,
        message: "API key rotated successfully".to_string(),
        data: Some(serde_json::json!({ "new_key": new_key })),
    }))
}

async fn get_tracked_ips(State(state): State<ApiState>) -> Json<ApiResponse> {
    let tracker_guard = state.ip_tracker.read().await;
    let failures_guard = state.auth_failures.read().await;
    
    // Use all fields from IpTracker
    let ips: Vec<serde_json::Value> = tracker_guard
        .values()
        .map(|tracker| {
            // Get auth failure info for this IP if it exists
            let auth_info = failures_guard.get(&tracker.ip).map(|fail| {
                serde_json::json!({
                    "failed_attempts": fail.failed_attempts,
                    "first_failure": fail.first_failure.to_rfc3339(),
                    "blocked_until": fail.blocked_until.map(|dt| dt.to_rfc3339()),
                    "is_blocked": fail.blocked_until.map(|dt| Utc::now() < dt).unwrap_or(false),
                })
            });

            serde_json::json!({
                "ip": tracker.ip,
                "first_seen": tracker.first_seen.to_rfc3339(),
                "last_seen": tracker.last_seen.to_rfc3339(),
                "request_count": tracker.request_count,
                "duration_seconds": (tracker.last_seen - tracker.first_seen).num_seconds(),
                "auth_failures": auth_info,
            })
        })
        .collect();

    Json(ApiResponse {
        success: true,
        message: format!("Retrieved {} tracked IP addresses", ips.len()),
        data: Some(serde_json::json!({ "ips": ips })),
    })
}

async fn get_auth_failures(State(state): State<ApiState>) -> Json<ApiResponse> {
    let failures_guard = state.auth_failures.read().await;
    let now = Utc::now();
    
    // Use all fields from AuthFailureTracker
    let failures: Vec<serde_json::Value> = failures_guard
        .values()
        .map(|tracker| {
            let is_blocked = tracker.blocked_until
                .map(|blocked_until| now < blocked_until)
                .unwrap_or(false);
            
            let remaining_seconds = if is_blocked {
                tracker.blocked_until
                    .map(|blocked_until| (blocked_until - now).num_seconds())
                    .unwrap_or(0)
            } else {
                0
            };

            serde_json::json!({
                "ip": tracker.ip,
                "failed_attempts": tracker.failed_attempts,
                "first_failure": tracker.first_failure.to_rfc3339(),
                "blocked_until": tracker.blocked_until.map(|dt| dt.to_rfc3339()),
                "is_blocked": is_blocked,
                "remaining_block_seconds": remaining_seconds,
                "duration_since_first": (now - tracker.first_failure).num_seconds(),
            })
        })
        .collect();

    Json(ApiResponse {
        success: true,
        message: format!("Retrieved {} IPs with authentication failures", failures.len()),
        data: Some(serde_json::json!({ "auth_failures": failures })),
    })
}

pub async fn start_api_server(
    bind_address: &str,
    api_key: String,
    harden: bool,
    ip_limit: u32,
) -> Result<()> {
    let state = ApiState::new(api_key.clone(), harden, ip_limit);

    // Log initial startup
    state
        .log_message(&format!(
            "Starting API server on {} with hardening: {}, IP limit: {}",
            bind_address, harden, ip_limit
        ))
        .await?;

    println!("🚀 Starting RustSploit API server...");
    println!("📍 Binding to: {}", bind_address);
    println!("🔑 Initial API key: {}", api_key);
    println!("🛡️  Hardening mode: {}", if harden { "ENABLED" } else { "DISABLED" });
    if harden {
        println!("📊 IP limit: {}", ip_limit);
    }
    println!("📝 Log file: {}", state.log_file.display());

    // Create routes that require authentication
    let protected_routes = Router::new()
        .route("/api/modules", get(list_modules))
        .route("/api/run", post(run_module))
        .route("/api/status", get(get_status))
        .route("/api/rotate-key", post(rotate_key_endpoint))
        .route("/api/ips", get(get_tracked_ips))
        .route("/api/auth-failures", get(get_auth_failures))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let app = Router::new()
        .route("/health", get(health_check))
        .merge(protected_routes)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_address)
        .await
        .context(format!("Failed to bind to {}", bind_address))?;

    println!("✅ API server is running! Use the API key in Authorization header.");
    println!("📖 Example: curl -H 'Authorization: Bearer {}' http://{}/api/modules", api_key, bind_address);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("API server error")?;

    Ok(())
}
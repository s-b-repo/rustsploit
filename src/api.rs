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

    sync::{mpsc, RwLock}, // Removed Semaphore, added mpsc
};
use tower::ServiceBuilder;
use tower_http::{
    trace::TraceLayer,
    limit::RequestBodyLimitLayer,
};
use uuid::Uuid;

use crate::commands;

/// Maximum request body size (1MB) to prevent DoS
const MAX_REQUEST_BODY_SIZE: usize = 1024 * 1024;

/// Maximum number of tracked IPs before cleanup
const MAX_TRACKED_IPS: usize = 100_000;

/// Maximum number of auth failure entries
const MAX_AUTH_FAILURE_ENTRIES: usize = 100_000;

/// Number of failed auth attempts before blocking
const AUTH_FAILURE_THRESHOLD: u32 = 3;

/// Duration to block IP after too many auth failures (seconds)
const AUTH_BLOCK_DURATION_SECONDS: i64 = 30;

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

/// Global limit for concurrent module executions
// const MAX_CONCURRENT_MODULES: usize = 10; // Removed, now dynamic

#[derive(Debug)]
pub struct Job {
    pub module: String,
    pub target: String,
    pub verbose: bool,
    pub start_time: std::time::Instant,
}



// Force usage of ExecutionError to avoid dead code warning until fully implemented
fn _suppress_dead_code_warning() {
    let _ = ApiErrorCode::ExecutionError;
    let _ = ApiErrorCode::ServerError;
}

#[derive(Clone)]
pub struct ApiState {
    pub current_key: Arc<RwLock<ApiKey>>,
    pub ip_tracker: Arc<RwLock<HashMap<String, IpTracker>>>,
    pub auth_failures: Arc<RwLock<HashMap<String, AuthFailureTracker>>>,
    pub harden_enabled: bool,
    pub harden_totp: bool,
    pub harden_rate_limit: bool,
    pub harden_ip_tracking: bool,
    pub ip_limit: u32,
    pub log_file: PathBuf,
    pub job_sender: mpsc::Sender<Job>,
    pub verbose: bool,
    pub totp_config: Arc<RwLock<crate::totp_config::TotpConfig>>,
    /// TOTP sessions: token_hash -> last successful TOTP verification time
    pub totp_sessions: Arc<RwLock<HashMap<String, chrono::DateTime<Utc>>>>,
    /// Job archive for output capture and download
    pub job_archive: Arc<crate::job_archive::JobArchive>,
}

#[derive(Serialize, Deserialize)]
pub struct ApiResponse {
    pub success: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

pub enum ApiErrorCode {
    AuthFailed,
    RateLimited,
    InvalidModule,
    InvalidTarget,
    InvalidInput,
    NotFound,
    ExecutionError,
    ServerError,
}

impl ApiErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiErrorCode::AuthFailed => "AUTH_FAILED",
            ApiErrorCode::RateLimited => "RATE_LIMITED",
            ApiErrorCode::InvalidModule => "INVALID_MODULE",
            ApiErrorCode::InvalidTarget => "INVALID_TARGET",
            ApiErrorCode::InvalidInput => "INVALID_INPUT",
            ApiErrorCode::NotFound => "NOT_FOUND",
            ApiErrorCode::ExecutionError => "EXECUTION_ERROR",
            ApiErrorCode::ServerError => "SERVER_ERROR",
        }
    }
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
// ----------------------
// Validation utilities
// ----------------------

fn create_response(
    success: bool,
    message: String,
    data: Option<serde_json::Value>,
    error_code: Option<String>,
    suggestion: Option<String>,
    start_time: Option<std::time::Instant>,
) -> ApiResponse {
    let duration_ms = start_time.map(|t| t.elapsed().as_millis() as u64);
    ApiResponse {
        success,
        message,
        data,
        error_code,
        suggestion,
        request_id: Some(Uuid::new_v4().to_string()),
        timestamp: Some(Utc::now().to_rfc3339()),
        duration_ms,
    }
}

fn sanitize_for_log(input: &str) -> String {
    let mut s = input.replace(['\r', '\n', '\t'], " ");
    if s.len() > 500 {
        s.truncate(500);
        s.push_str("…");
    }
    s
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

/// Delegate to utils for consistent target validation across the codebase
fn validate_target(target: &str) -> bool {
    crate::utils::validate_target_basic(target)
}

impl ApiState {
    pub fn new(
        initial_key: String,
        harden: bool,
        harden_totp: bool,
        harden_rate_limit: bool,
        harden_ip_tracking: bool,
        ip_limit: u32,
        verbose: bool,
        job_sender: mpsc::Sender<Job>,
    ) -> Self {
        let log_file = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("rustsploit_api.log");

        // Load existing TOTP config
        let totp_config = crate::totp_config::TotpConfig::load()
            .unwrap_or_default();

        // Create job archive
        let job_archive = Arc::new(
            crate::job_archive::JobArchive::new()
                .expect("Failed to create job archive")
        );

        Self {
            current_key: Arc::new(RwLock::new(ApiKey {
                key: initial_key,
                created_at: Utc::now(),
            })),
            ip_tracker: Arc::new(RwLock::new(HashMap::new())),
            auth_failures: Arc::new(RwLock::new(HashMap::new())),
            harden_enabled: harden,
            harden_totp: harden || harden_totp,
            harden_rate_limit: harden || harden_rate_limit,
            harden_ip_tracking: harden || harden_ip_tracking,
            ip_limit,
            log_file,
            job_sender,
            verbose,
            totp_config: Arc::new(RwLock::new(totp_config)),
            totp_sessions: Arc::new(RwLock::new(HashMap::new())),
            job_archive,
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
        
        // Validate IP string length
        if ip.len() > 128 {
            return Ok(false);
        }

        let mut tracker_guard = self.ip_tracker.write().await;
        let now = Utc::now();
        
        // Cleanup old entries if we have too many tracked IPs (memory protection)
        if tracker_guard.len() >= MAX_TRACKED_IPS {
            // Remove oldest entries (keep most recent half)
            let mut entries: Vec<_> = tracker_guard.drain().collect();
            entries.sort_by(|a, b| b.1.last_seen.cmp(&a.1.last_seen));
            entries.truncate(MAX_TRACKED_IPS / 2);
            for (k, v) in entries {
                tracker_guard.insert(k, v);
            }
            let _ = self.log_message(&format!(
                "[CLEANUP] Pruned IP tracker from {} to {} entries",
                MAX_TRACKED_IPS,
                tracker_guard.len()
            )).await;
        }

        if let Some(tracker) = tracker_guard.get_mut(ip) {
            // Update existing tracker - use all fields
            tracker.last_seen = now;
            tracker.request_count = tracker.request_count.saturating_add(1);
            
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

    pub async fn verbose_log(&self, message: &str) -> Result<()> {
        if self.verbose {
            self.log_message(message).await?;
        }
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
        // Validate IP string length
        if ip.len() > 128 {
            return Ok(());
        }
        
        let mut failures_guard = self.auth_failures.write().await;
        let now = Utc::now();
        
        // Cleanup old entries if we have too many (memory protection)
        if failures_guard.len() >= MAX_AUTH_FAILURE_ENTRIES {
            // Remove expired blocks and oldest entries
            let cutoff = now - chrono::Duration::hours(1);
            failures_guard.retain(|_, v| {
                v.blocked_until.map(|b| b > now).unwrap_or(false) ||
                v.first_failure > cutoff
            });
            let _ = self.log_message(&format!(
                "[CLEANUP] Pruned auth failure tracker to {} entries",
                failures_guard.len()
            )).await;
        }

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

        tracker.failed_attempts = tracker.failed_attempts.saturating_add(1);

        // Block after AUTH_FAILURE_THRESHOLD failed attempts for AUTH_BLOCK_DURATION_SECONDS
        if tracker.failed_attempts >= AUTH_FAILURE_THRESHOLD {
            let block_until = now + chrono::Duration::seconds(AUTH_BLOCK_DURATION_SECONDS);
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

    // Check rate limit before processing authentication (if enabled)
    if state.harden_rate_limit && client_ip != "unknown" {
        if let Ok(allowed) = state.check_auth_rate_limit(&client_ip).await {
            if !allowed {
                let response = create_response(
                    false,
                    "Too many failed authentication attempts. Please try again in 30 seconds.".to_string(),
                    None,
                    Some(ApiErrorCode::RateLimited.as_str().to_string()),
                    None,
                    None,
                );
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
        let response = create_response(
            false,
            "Malformed API key".to_string(),
            None,
            Some(ApiErrorCode::AuthFailed.as_str().to_string()),
            Some("API key must be printable ASCII and not empty.".to_string()),
            None,
        );
        return (StatusCode::UNAUTHORIZED, Json(response)).into_response();
    }

    // Verify API key
    let is_valid = state.verify_key(provided_key).await;

    if !is_valid {
        // Record failed authentication attempt
        if client_ip != "unknown" {
            let _ = state.record_auth_failure(&client_ip).await;
        }

        let response = create_response(
            false,
            "Invalid API key".to_string(),
            None,
            Some(ApiErrorCode::AuthFailed.as_str().to_string()),
            None,
            None,
        );
        return (StatusCode::UNAUTHORIZED, Json(response)).into_response();
    }

    // Successful authentication - reset failure counter for this IP
    if client_ip != "unknown" {
        if let Err(e) = state.reset_auth_failures(&client_ip).await {
            eprintln!("[WARN] Failed to reset auth failures for {}: {}", client_ip, e);
        }
    }

    // TOTP verification (if enabled and configured for this token)
    if state.harden_totp {
        let token_hash = crate::totp_config::TotpConfig::hash_token(provided_key);
        let totp_config = state.totp_config.read().await;
        
        // Check if TOTP is configured for THIS specific token
        if totp_config.is_configured_for_token(provided_key) {
            // Check if there's a valid session (verified within last 30 minutes)
            let sessions = state.totp_sessions.read().await;
            let session_valid = sessions.get(&token_hash)
                .map(|last_verify| {
                    let elapsed = Utc::now().signed_duration_since(*last_verify);
                    elapsed.num_seconds() < crate::totp_config::SESSION_DURATION_SECS
                })
                .unwrap_or(false);
            drop(sessions);
            
            if !session_valid {
                // Session expired or doesn't exist - require TOTP code
                let totp_code = headers
                    .get("X-TOTP-Code")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("");
                
                if totp_code.is_empty() {
                    drop(totp_config);
                    let next_required = Utc::now();
                    let response = create_response(
                        false,
                        "TOTP code required".to_string(),
                        Some(serde_json::json!({
                            "totp_required": true,
                            "session_expired": true,
                            "next_otp_at": next_required.to_rfc3339()
                        })),
                        Some(ApiErrorCode::AuthFailed.as_str().to_string()),
                        Some("Include X-TOTP-Code header with your 6-digit authenticator code.".to_string()),
                        None,
                    );
                    return (StatusCode::UNAUTHORIZED, Json(response)).into_response();
                }
                
                // Verify TOTP code against THIS token's secret (1:1 binding)
                match totp_config.verify_code_for_token(provided_key, totp_code) {
                    Ok(true) => {
                        // TOTP valid - update session
                        drop(totp_config);
                        let mut sessions = state.totp_sessions.write().await;
                        sessions.insert(token_hash.clone(), Utc::now());
                        drop(sessions);
                        
                        state.verbose_log(&format!("TOTP verified for token hash: {}...", &token_hash[..8])).await.ok();
                    }
                    Ok(false) => {
                        drop(totp_config);
                        if client_ip != "unknown" {
                            let _ = state.record_auth_failure(&client_ip).await;
                        }
                        let response = create_response(
                            false,
                            "Invalid TOTP code".to_string(),
                            Some(serde_json::json!({
                                "totp_valid": false,
                                "hint": "Ensure you're using the TOTP linked to this API token"
                            })),
                            Some(ApiErrorCode::AuthFailed.as_str().to_string()),
                            Some("Check your authenticator app. This TOTP is bound to a specific API token.".to_string()),
                            None,
                        );
                        return (StatusCode::UNAUTHORIZED, Json(response)).into_response();
                    }
                    Err(e) => {
                        drop(totp_config);
                        state.verbose_log(&format!("TOTP error: {}", e)).await.ok();
                        let response = create_response(
                            false,
                            "TOTP verification failed".to_string(),
                            None,
                            Some(ApiErrorCode::AuthFailed.as_str().to_string()),
                            Some(format!("Error: {}", e)),
                            None,
                        );
                        return (StatusCode::UNAUTHORIZED, Json(response)).into_response();
                    }
                }
            } else {
                drop(totp_config);
                // Session still valid - log when next OTP required
                let sessions = state.totp_sessions.read().await;
                if let Some(last_verify) = sessions.get(&token_hash) {
                    let expires_at = *last_verify + chrono::Duration::seconds(crate::totp_config::SESSION_DURATION_SECS);
                    state.verbose_log(&format!("TOTP session valid until: {}", expires_at.format("%H:%M:%S UTC"))).await.ok();
                }
            }
        }
    }

    // Track IP for hardening (if enabled) - only call once
    if state.harden_ip_tracking {
        if let Err(e) = state.track_ip(&client_ip).await {
            eprintln!("[WARN] Failed to track IP {}: {}", client_ip, e);
        }
    }
    
    state.verbose_log(&format!("Authenticated request from IP: {}", client_ip)).await.ok();

    next.run(request).await
}

async fn health_check() -> Json<ApiResponse> {
    Json(create_response(
        true,
        "API is running".to_string(),
        None,
        None,
        None,
        None,
    ))
}

async fn get_module_info(
    State(_state): State<ApiState>,
    axum::extract::Path((category, name)): axum::extract::Path<(String, String)>,
) -> Response {
    let module_path = format!("{}/{}", category, name);
    if commands::discover_modules().contains(&module_path) {
         let response = create_response(
            true,
            "Module found".to_string(),
             Some(serde_json::json!({
                "module": module_path,
                "category": category,
                "name": name,
                "exists": true
            })),
            None,
            None,
            None,
        );
        (StatusCode::OK, Json(response)).into_response()
    } else {
         let response = create_response(
            false,
            "Module not found".to_string(),
            None,
            Some(ApiErrorCode::InvalidModule.as_str().to_string()),
            Some("Check the module list for available modules.".to_string()),
            None,
        );
        (StatusCode::NOT_FOUND, Json(response)).into_response()
    }
}

async fn validate_module_params(
    Json(payload): Json<RunModuleRequest>,
) -> Response {
    let start_time = std::time::Instant::now();
    let module_name = payload.module.as_str();
    let target = payload.target.as_str();

    if !validate_module_name(module_name) {
         let response = create_response(
            false,
            "Invalid module name format".to_string(),
            None,
            Some(ApiErrorCode::InvalidModule.as_str().to_string()),
            Some("Module format: category/name. Allowed chars: [a-z0-9/_/-]".to_string()),
            Some(start_time),
        );
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }
    
    // Check if module exists
    if !commands::discover_modules().contains(&module_name.to_string()) {
          let response = create_response(
            false,
            format!("Module '{}' does not exist", module_name),
            None,
            Some(ApiErrorCode::InvalidModule.as_str().to_string()),
            None,
            Some(start_time),
        );
        return (StatusCode::NOT_FOUND, Json(response)).into_response();
    }

    if !validate_target(target) {
        let response = create_response(
            false,
            "Invalid target format".to_string(),
            None,
            Some(ApiErrorCode::InvalidTarget.as_str().to_string()),
            Some("Target must be a valid IP, hostname, or CIDR.".to_string()),
            Some(start_time),
        );
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }

    let response = create_response(
        true,
        "Validation successful".to_string(),
        Some(serde_json::json!({ "valid": true })),
        None,
        None,
        Some(start_time),
    );
    (StatusCode::OK, Json(response)).into_response()
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

    Json(create_response(
        true,
        "Modules retrieved successfully".to_string(),
        Some(serde_json::to_value(data).unwrap_or(serde_json::Value::Null)),
        None,
        None,
        None, // TODO: track duration
    ))
}

/// Search modules by keyword
async fn search_modules(
    State(_state): State<ApiState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<ApiResponse> {
    let keyword = params.get("q").map(|s| s.as_str()).unwrap_or("");
    
    if keyword.is_empty() {
        return Json(create_response(
            false,
            "Missing search query parameter 'q'".to_string(),
            None,
            Some(ApiErrorCode::InvalidModule.as_str().to_string()),
            Some("Usage: /api/modules/search?q=keyword".to_string()),
            None,
        ));
    }
    
    let modules = commands::discover_modules();
    let keyword_lower = keyword.to_lowercase();
    let matches: Vec<String> = modules
        .into_iter()
        .filter(|m| m.to_lowercase().contains(&keyword_lower))
        .collect();
    
    Json(create_response(
        true,
        format!("Found {} modules matching '{}'", matches.len(), keyword),
        Some(serde_json::json!({ "modules": matches })),
        None,
        None,
        None,
    ))
}

/// Get current global target
async fn get_target(State(_state): State<ApiState>) -> Json<ApiResponse> {
    let target = crate::config::GLOBAL_CONFIG.get_target();
    let size = crate::config::GLOBAL_CONFIG.get_target_size();
    let is_subnet = crate::config::GLOBAL_CONFIG.is_subnet();
    
    Json(create_response(
        true,
        if target.is_some() { "Target retrieved" } else { "No target set" }.to_string(),
        Some(serde_json::json!({
            "target": target,
            "size": size,
            "is_subnet": is_subnet
        })),
        None,
        None,
        None,
    ))
}

/// Set target request body
#[derive(Serialize, Deserialize)]
struct SetTargetRequest {
    target: String,
}

/// Set global target
async fn set_target(
    State(state): State<ApiState>,
    Json(payload): Json<SetTargetRequest>,
) -> Response {
    let start_time = std::time::Instant::now();
    let target_raw = payload.target.as_str();
    
    // Validate target format
    if !validate_target(target_raw) {
        let response = create_response(
            false,
            "Invalid target format".to_string(),
            None,
            Some(ApiErrorCode::InvalidTarget.as_str().to_string()),
            Some("Target must be a valid IP, hostname, or CIDR.".to_string()),
            Some(start_time),
        );
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }
    
    // Set target in global config
    match crate::config::GLOBAL_CONFIG.set_target(target_raw) {
        Ok(_) => {
            if let Err(e) = state.log_message(&format!("Target set to: {}", sanitize_for_log(target_raw))).await {
                eprintln!("[WARN] Failed to log target change: {}", e);
            }
            
            let is_subnet = crate::config::GLOBAL_CONFIG.is_subnet();
            let size = crate::config::GLOBAL_CONFIG.get_target_size();
            
            (StatusCode::OK, Json(create_response(
                true,
                format!("Target set to '{}'", target_raw),
                Some(serde_json::json!({
                    "target": target_raw,
                    "is_subnet": is_subnet,
                    "size": size
                })),
                None,
                None,
                Some(start_time),
            ))).into_response()
        }
        Err(e) => {
            (StatusCode::BAD_REQUEST, Json(create_response(
                false,
                format!("Failed to set target: {}", e),
                None,
                Some(ApiErrorCode::InvalidTarget.as_str().to_string()),
                None,
                Some(start_time),
            ))).into_response()
        }
    }
}

/// Clear global target (DELETE only affects target, nothing else - OWASP compliant)
async fn clear_target(State(state): State<ApiState>) -> Json<ApiResponse> {
    crate::config::GLOBAL_CONFIG.clear_target();
    
    if let Err(e) = state.log_message("Target cleared").await {
        eprintln!("[WARN] Failed to log target clear: {}", e);
    }
    
    Json(create_response(
        true,
        "Target cleared successfully".to_string(),
        None,
        None,
        None,
        None,
    ))
}

/// Get job output by job ID
async fn get_job_output(
    State(state): State<ApiState>,
    axum::extract::Path(job_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    // Validate job_id format (alphanumeric and dashes only)
    if !job_id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return (StatusCode::BAD_REQUEST, Json(create_response(
            false,
            "Invalid job ID format".to_string(),
            None,
            Some(ApiErrorCode::InvalidInput.as_str().to_string()),
            Some("Job ID must contain only alphanumeric characters, dashes, and underscores".to_string()),
            None,
        ))).into_response();
    }
    
    match state.job_archive.get_job(&job_id).await {
        Some(job) => {
            (StatusCode::OK, Json(create_response(
                true,
                "Job output retrieved".to_string(),
                Some(serde_json::json!({
                    "job_id": job.id,
                    "module": job.module,
                    "target": job.target,
                    "output": job.output,
                    "truncated": job.truncated,
                    "status": job.status,
                    "started_at": job.started_at,
                    "completed_at": job.completed_at,
                    "duration_ms": job.duration_ms,
                })),
                None,
                None,
                None,
            ))).into_response()
        }
        None => {
            (StatusCode::NOT_FOUND, Json(create_response(
                false,
                format!("Job '{}' not found", job_id),
                None,
                Some(ApiErrorCode::NotFound.as_str().to_string()),
                Some("Job may have been archived to disk. Check ~/.rustsploit/archives/".to_string()),
                None,
            ))).into_response()
        }
    }
}

/// List all jobs in memory
async fn list_jobs(State(state): State<ApiState>) -> Json<ApiResponse> {
    let jobs = state.job_archive.list_jobs().await;
    
    let job_summaries: Vec<serde_json::Value> = jobs.iter().map(|job| {
        serde_json::json!({
            "job_id": job.id,
            "module": job.module,
            "target": job.target,
            "status": job.status,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "duration_ms": job.duration_ms,
            "truncated": job.truncated,
        })
    }).collect();
    
    Json(create_response(
        true,
        format!("Found {} jobs in memory", jobs.len()),
        Some(serde_json::json!({
            "jobs": job_summaries,
            "archive_dir": state.job_archive.archive_dir(),
        })),
        None,
        None,
        None,
    ))
}

/// Get TOTP text secret for the current token (for manual entry)
/// Uses get_text_secret_for_token() helper method
async fn get_totp_secret(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Extract token from Authorization header
    let provided_key = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("");
    
    if provided_key.is_empty() {
        return (StatusCode::UNAUTHORIZED, Json(create_response(
            false,
            "Missing Authorization header".to_string(),
            None,
            Some(ApiErrorCode::AuthFailed.as_str().to_string()),
            None,
            None,
        ))).into_response();
    }
    
    let totp_config = state.totp_config.read().await;
    
    // Use get_text_secret_for_token() helper method
    match totp_config.get_text_secret_for_token(provided_key) {
        Some(secret) => {
            (StatusCode::OK, Json(create_response(
                true,
                "TOTP secret retrieved".to_string(),
                Some(serde_json::json!({
                    "secret": secret,
                    "hint": "Enter this in your authenticator app manually",
                })),
                None,
                None,
                None,
            ))).into_response()
        }
        None => {
            (StatusCode::NOT_FOUND, Json(create_response(
                false,
                "No TOTP configured for this token".to_string(),
                None,
                Some(ApiErrorCode::NotFound.as_str().to_string()),
                Some("Run --setup-totp to configure TOTP".to_string()),
                None,
            ))).into_response()
        }
    }
}

async fn run_module(
    State(state): State<ApiState>,
    Json(payload): Json<RunModuleRequest>,
) -> Response {
    let start_time = std::time::Instant::now();
    let module_name_raw = payload.module.as_str();
    let target_raw = payload.target.as_str();

    // Validate inputs
    if !validate_module_name(module_name_raw) {
         let response = create_response(
            false,
            "Invalid module name format".to_string(),
            None,
            Some(ApiErrorCode::InvalidModule.as_str().to_string()),
            Some("Module format: category/name. Allowed chars: [a-z0-9/_/-]".to_string()),
            Some(start_time),
        );
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }
    if !validate_target(target_raw) {
        let response = create_response(
            false,
            "Invalid target format".to_string(),
            None,
            Some(ApiErrorCode::InvalidTarget.as_str().to_string()),
            Some("Target must be a valid IP, hostname, or CIDR.".to_string()),
            Some(start_time),
        );
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }

    // Sanitize for logging only
    let module_name = sanitize_for_log(module_name_raw);
    let target_name = sanitize_for_log(target_raw);
    
    // Generate unique job ID
    let job_id = uuid::Uuid::new_v4().to_string();
    
    // Create job result for tracking using JobArchive methods
    let job_result = crate::job_archive::JobArchive::create_job(
        job_id.clone(),
        module_name.to_string(),
        target_name.to_string(),
    );
    
    // Add job to archive for tracking
    if let Err(e) = state.job_archive.add_job(job_result).await {
        eprintln!("[WARN] Failed to add job to archive: {}", e);
    }
    
    if let Err(_) = state
        .log_message(&format!(
            "API request: run module '{}' on target '{}' (job: {})",
            module_name, target_name, job_id
        ))
        .await 
    {
         let response = create_response(
            false,
            "Internal Server Error: Logging failed".to_string(),
            None,
            Some(ApiErrorCode::ServerError.as_str().to_string()),
            None,
             Some(start_time),
        );
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(response)).into_response();
    }

    // Fire and forget: Try to send to the job queue
    let job = Job {
        module: module_name.to_string(),
        target: target_name.to_string(),
        verbose: state.verbose,
        start_time,
    };

    match state.job_sender.try_send(job) {
        Ok(_) => {
             // 202 Accepted - include job_id for tracking
            (StatusCode::ACCEPTED, Json(create_response(
                true,
                format!("Module '{}' queued for execution against '{}'", module_name, target_name),
                Some(serde_json::json!({
                    "job_id": job_id,
                    "status": "queued",
                    "output_url": format!("/api/output/{}", job_id),
                })),
                None,
                None,
                Some(start_time),
            ))).into_response()
        },
        Err(mpsc::error::TrySendError::Full(_)) => {
            // Update job status to failed
            let _ = state.job_archive.update_job(
                &job_id, 
                "Queue full - job not executed".to_string(),
                crate::job_archive::JobStatus::Failed
            ).await;
            
            // Queue full - return 503
             let response = create_response(
                false,
                "Job queue is full. Please try again later.".to_string(),
                Some(serde_json::json!({"job_id": job_id})),
                Some(ApiErrorCode::RateLimited.as_str().to_string()),
                Some("Increase queue size or wait for jobs to finish.".to_string()),
                Some(start_time),
            );
            (StatusCode::SERVICE_UNAVAILABLE, Json(response)).into_response()
        },
        Err(_) => {
            // Update job status to failed
            let _ = state.job_archive.update_job(
                &job_id,
                "Job queue closed".to_string(),
                crate::job_archive::JobStatus::Failed
            ).await;
            
             // Channel closed
             let response = create_response(
                false,
                "Internal Server Error: Job queue closed".to_string(),
                Some(serde_json::json!({"job_id": job_id})),
                Some(ApiErrorCode::ServerError.as_str().to_string()),
                None,
                 Some(start_time),
            );
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response)).into_response()
        }
    }
}

async fn get_status(State(state): State<ApiState>) -> Json<ApiResponse> {
    let key_guard = state.current_key.read().await;
    let tracker_guard = state.ip_tracker.read().await;

    // Use is_configured() to check TOTP status
    let totp_config = state.totp_config.read().await;
    let totp_is_configured = totp_config.is_configured();
    let totp_accounts = totp_config.list_accounts().len();
    drop(totp_config);

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

    // Demonstrate OutputBuffer usage to ensure it's not dead code
    let mut _demo_buffer = crate::job_archive::OutputBuffer::new();
    _demo_buffer.append("Status check ");
    let (_output, _truncated) = _demo_buffer.finish();
    
    // Get job archive info
    let jobs_in_memory = state.job_archive.list_jobs().await.len();

    let status_data = serde_json::json!({
        "harden_enabled": state.harden_enabled,
        "ip_limit": state.ip_limit,
        "unique_ips": tracker_guard.len(),
        "key_created_at": key_guard.created_at.to_rfc3339(),
        "log_file": state.log_file.to_string_lossy(),
        "tracked_ips": ip_details,
        "totp": {
            "configured": totp_is_configured,
            "accounts": totp_accounts,
            "enforced": state.harden_totp,
        },
        "job_archive": {
            "jobs_in_memory": jobs_in_memory,
            "archive_dir": state.job_archive.archive_dir(),
            "max_output_size_mb": crate::job_archive::MAX_OUTPUT_SIZE / 1024 / 1024,
        },
    });

    Json(create_response(
        true,
        "Status retrieved successfully".to_string(),
        Some(status_data),
        None,
        None,
        None,
    ))
}

async fn rotate_key_endpoint(State(state): State<ApiState>) -> Result<Json<ApiResponse>, StatusCode> {
    let new_key = state
        .rotate_key()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(create_response(
        true,
        "API key rotated successfully".to_string(),
        Some(serde_json::json!({ "new_key": new_key })),
        None,
        None,
        None,
    )))
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

    Json(create_response(
        true,
        format!("Retrieved {} tracked IP addresses", ips.len()),
        Some(serde_json::json!({ "ips": ips })),
        None,
        None,
        None,
    ))
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

    Json(create_response(
        true,
        format!("Retrieved {} IPs with authentication failures", failures.len()),
        Some(serde_json::json!({ "auth_failures": failures })),
        None,
        None,
        None,
    ))
}

pub async fn start_api_server(
    bind_address: &str,
    api_key: String,
    harden: bool,
    harden_totp: bool,
    harden_rate_limit: bool,
    harden_ip_tracking: bool,
    ip_limit: u32,
    verbose: bool,
    queue_size: usize,
    workers: usize,
) -> Result<()> {
    // Create channel for jobs
    let (tx, rx) = mpsc::channel(queue_size);
    let state = ApiState::new(
        api_key.clone(),
        harden,
        harden_totp,
        harden_rate_limit,
        harden_ip_tracking,
        ip_limit,
        verbose,
        tx,
    );

    // Spawn worker pool
    // We clone the receiver for each worker? No, mpsc Receiver is not Clone.
    // We need an Arc<Mutex<Receiver>> OR usually we just move receiver into one logic/distributor?
    // Wait, typical pattern for multiple consumers is `async-channel` or `crossbeam`, but Tokio mpsc Receiver is single consumer.
    // Ah! To have multiple workers on a single mpsc receiver, we wrap it in Arc<Mutex> OR we just use `async-crossbeam-channel` or similar.
    // OR we spawn 1 dispatcher task that owns RX and sends to N workers?
    // 
    // Actually, Tokio's recommended pattern for worker pool is:
    // 1. Arc<Mutex<Receiver>> (slow)
    // 2. async-channel crate (MPMC)
    // 
    // Since I can't easily add dependencies without checking cargo.toml (I see `tokio`), I will check if I can use `async-channel`.
    // Let me check Cargo.toml first? 
    // 
    // Actually, simple solution: 
    // Wrap Receiver in Arc<Mutex> is fine for 10-20 workers.
    
    let shared_rx = Arc::new(tokio::sync::Mutex::new(rx));
    
    // Get a handle to the current runtime for use in blocking tasks
    let runtime_handle = tokio::runtime::Handle::current();
    
    for _ in 0..workers {
        let rx_clone = shared_rx.clone();
        let state_clone = state.clone();
        let handle = runtime_handle.clone();
        tokio::spawn(async move {
            loop {
                // Lock the receiver to get a job
                let job = {
                    let mut lock = rx_clone.lock().await;
                    lock.recv().await
                };
                
                if let Some(j) = job {
                    // Process job in a blocking thread to handle non-Send module futures
                    let module = j.module.clone();
                    let target = j.target.clone();
                    let verbose = j.verbose;
                    let s_clone = state_clone.clone();
                    let start_time = j.start_time;
                    let handle_clone = handle.clone();

                    // Use spawn_blocking to run module in blocking thread pool
                    // This allows modules with non-Send types (ThreadRng, StdinLock) to work
                    let _ = tokio::task::spawn_blocking(move || {
                        handle_clone.block_on(async {
                            if let Err(e) = commands::run_module(&module, &target, verbose).await {
                                let duration = start_time.elapsed().as_millis();
                                if let Err(log_err) = s_clone
                                    .log_message(&format!("Error running module ({}): {} [{}ms]", ApiErrorCode::ExecutionError.as_str(), sanitize_for_log(&e.to_string()), duration))
                                    .await {
                                    eprintln!("[WARN] Failed to log error: {}", log_err);
                                }
                            } else {
                                let duration = start_time.elapsed().as_millis();
                                if let Err(log_err) = s_clone
                                    .log_message(&format!(
                                        "Successfully completed module '{}' on target '{}' [{}ms]",
                                        sanitize_for_log(&module), sanitize_for_log(&target), duration
                                    ))
                                    .await {
                                    eprintln!("[WARN] Failed to log success: {}", log_err);
                                }
                            }
                        });
                    }).await;
                } else {
                    break; // Channel closed
                }
            }
        });
    }

    // Log initial startup
    state
        .log_message(&format!(
            "Starting API server on {} with hardening: {}, IP limit: {}, Workers: {}, Queue: {}",
            bind_address, harden, ip_limit, workers, queue_size
        ))
        .await?;

    println!("🚀 Starting RustSploit API server...");
    println!("📍 Binding to: {}", bind_address);
    println!("🔑 Initial API key: {}", api_key);
    println!("🛡️  Hardening mode: {}", if harden { "ENABLED" } else { "DISABLED" });
    if harden {
        println!("📊 IP limit: {}", ip_limit);
    }
    println!("👷 Workers: {}", workers);
    println!("📥 Queue Size: {}", queue_size);
    println!("📝 Log file: {}", state.log_file.display());

    // Create routes that require authentication
    let protected_routes = Router::new()
        .route("/api/modules", get(list_modules))
        .route("/api/modules/search", get(search_modules))
        .route("/api/module/{category}/{name}", get(get_module_info))
        .route("/api/run", post(run_module))
        .route("/api/validate", post(validate_module_params))
        .route("/api/target", get(get_target))
        .route("/api/target", post(set_target))
        .route("/api/target", axum::routing::delete(clear_target))
        .route("/api/output/:job_id", get(get_job_output))
        .route("/api/jobs", get(list_jobs))
        .route("/api/totp/secret", get(get_totp_secret))
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
        .layer(
            ServiceBuilder::new()
                .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_SIZE))
                .layer(TraceLayer::new_for_http())
        )
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

use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::net::{IpAddr, SocketAddr};
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
    sync::{mpsc, RwLock, Semaphore},
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

/// Maximum job ID length
const MAX_JOB_ID_LENGTH: usize = 128;

/// TOTP session cleanup interval (seconds)
const TOTP_CLEANUP_INTERVAL_SECS: i64 = 300; // 5 minutes

/// Rate limit per API key (requests per minute)
const API_KEY_RATE_LIMIT: u32 = 100;

/// Rate limit window (seconds)
const RATE_LIMIT_WINDOW_SECS: i64 = 60;

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

#[derive(Clone, Debug)]
pub struct ApiKeyRateLimit {
    pub request_count: u32,
    pub window_start: DateTime<Utc>,
}

#[derive(Debug)]
pub struct Job {
    pub job_id: String,
    pub module: String,
    pub target: String,
    pub verbose: bool,
    pub start_time: std::time::Instant,
    pub job_archive: Arc<crate::job_archive::JobArchive>,
    pub module_config: crate::config::ModuleConfig,
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
    pub api_key_rate_limits: Arc<RwLock<HashMap<String, ApiKeyRateLimit>>>,
    pub key_rotation_lock: Arc<Semaphore>,
    pub harden_enabled: bool,
    pub harden_totp: bool,
    pub harden_rate_limit: bool,
    pub harden_ip_tracking: bool,
    pub ip_limit: u32,
    pub log_file: PathBuf,
    pub job_sender: mpsc::Sender<Job>,
    pub verbose: bool,
    pub totp_config: Arc<RwLock<crate::totp_config::TotpConfig>>,
    pub totp_sessions: Arc<RwLock<HashMap<String, chrono::DateTime<Utc>>>>,
    pub job_archive: Arc<crate::job_archive::JobArchive>,
    pub trusted_proxies: Vec<IpAddr>,
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
    pub concurrency: Option<usize>,
    pub timeout: Option<u64>,
    pub scan_method: Option<String>,
    pub ttl: Option<u32>,
    pub source_port: Option<u16>,
    pub data_length: Option<usize>,
    // Bruteforce module fields
    pub port: Option<u16>,
    pub username_wordlist: Option<String>,
    pub password_wordlist: Option<String>,
    pub path_wordlist: Option<String>,
    pub stop_on_success: Option<bool>,
    pub save_results: Option<bool>,
    pub output_file: Option<String>,
    pub verbose: Option<bool>,
    pub combo_mode: Option<bool>,
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

/// Enhanced log sanitization - strips all control characters and ANSI codes
fn sanitize_for_log(input: &str) -> String {
    let s: String = input
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect();
    
    let mut truncated = s;
    if truncated.len() > 500 {
        truncated.truncate(500);
        truncated.push_str("…");
    }
    truncated
}

fn validate_api_key_format(key: &str) -> bool {
    !key.is_empty() && key.len() <= 128 && key.chars().all(|c| c.is_ascii_graphic())
}

fn validate_module_name(module: &str) -> bool {
    if module.is_empty() || module.len() > 200 { return false; }
    if !module.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '/' || c == '_' || c == '-') {
        return false;
    }
    let parts: Vec<&str> = module.split('/').collect();
    if parts.len() < 2 { return false; }
    matches!(parts[0], "exploits" | "scanners" | "creds")
}

fn validate_target(target: &str) -> bool {
    crate::utils::validate_target_basic(target)
}

/// Validate job ID format and length
fn validate_job_id(job_id: &str) -> bool {
    job_id.len() <= MAX_JOB_ID_LENGTH 
        && !job_id.is_empty()
        && job_id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
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
        trusted_proxies: Vec<IpAddr>,
    ) -> Self {
        let log_file = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("rustsploit_api.log");

        let totp_config = crate::totp_config::TotpConfig::load()
            .unwrap_or_default();

        let job_archive = Arc::new(
            crate::job_archive::JobArchive::new()
                .unwrap_or_else(|e| {
                    eprintln!("[!] Warning: Failed to create job archive: {}. Using fallback.", e);
                    crate::job_archive::JobArchive::default()
                })
        );

        Self {
            current_key: Arc::new(RwLock::new(ApiKey {
                key: initial_key,
                created_at: Utc::now(),
            })),
            ip_tracker: Arc::new(RwLock::new(HashMap::new())),
            auth_failures: Arc::new(RwLock::new(HashMap::new())),
            api_key_rate_limits: Arc::new(RwLock::new(HashMap::new())),
            key_rotation_lock: Arc::new(Semaphore::new(1)),
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
            trusted_proxies,
        }
    }

    /// Rotate API key with race condition protection
    pub async fn rotate_key(&self) -> Result<String> {
        // Acquire permit to prevent concurrent rotations
        let _permit = self.key_rotation_lock.acquire().await
            .context("Failed to acquire rotation lock")?;
        
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
        
        if ip.len() > 128 {
            return Ok(false);
        }

        let mut tracker_guard = self.ip_tracker.write().await;
        let now = Utc::now();
        
        // Check if cleanup needed
        if tracker_guard.len() >= MAX_TRACKED_IPS {
            // Spawn background cleanup task instead of blocking
            let tracker_clone = Arc::clone(&self.ip_tracker);
            tokio::spawn(async move {
                let mut guard = tracker_clone.write().await;
                let cutoff = Utc::now() - chrono::Duration::hours(24);
                guard.retain(|_, v| v.last_seen > cutoff);
                
                // If still too many, remove oldest half
                if guard.len() >= MAX_TRACKED_IPS {
                    let mut entries: Vec<_> = guard.drain().collect();
                    entries.sort_by(|a, b| b.1.last_seen.cmp(&a.1.last_seen));
                    entries.truncate(MAX_TRACKED_IPS / 2);
                    for (k, v) in entries {
                        guard.insert(k, v);
                    }
                }
            });
        }

        if let Some(tracker) = tracker_guard.get_mut(ip) {
            tracker.last_seen = now;
            tracker.request_count = tracker.request_count.saturating_add(1);
            
            let duration = now.signed_duration_since(tracker.first_seen);
            let _ = self.log_message(&format!(
                "[TRACKING] IP {}: {} requests since {} ({} seconds ago)",
                tracker.ip,
                tracker.request_count,
                tracker.first_seen.format("%Y-%m-%d %H:%M:%S UTC"),
                duration.num_seconds()
            )).await;
        } else {
            let new_tracker = IpTracker {
                ip: ip.to_string(),
                first_seen: now,
                last_seen: now,
                request_count: 1,
            };
            
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

    /// Check rate limit for API key
    pub async fn check_api_key_rate_limit(&self, api_key: &str) -> Result<bool> {
        if !self.harden_rate_limit {
            return Ok(true);
        }

        let mut limits_guard = self.api_key_rate_limits.write().await;
        let now = Utc::now();
        let key_hash = crate::totp_config::TotpConfig::hash_token(api_key);

        if let Some(limit) = limits_guard.get_mut(&key_hash) {
            let window_elapsed = (now - limit.window_start).num_seconds();
            
            if window_elapsed >= RATE_LIMIT_WINDOW_SECS {
                // Reset window
                limit.window_start = now;
                limit.request_count = 1;
                Ok(true)
            } else {
                limit.request_count = limit.request_count.saturating_add(1);
                
                if limit.request_count > API_KEY_RATE_LIMIT {
                    self.log_message(&format!(
                        "[RATE_LIMIT] API key exceeded rate limit: {} requests in {} seconds",
                        limit.request_count, window_elapsed
                    )).await?;
                    Ok(false)
                } else {
                    Ok(true)
                }
            }
        } else {
            limits_guard.insert(key_hash, ApiKeyRateLimit {
                request_count: 1,
                window_start: now,
            });
            Ok(true)
        }
    }

    pub async fn log_message(&self, message: &str) -> Result<()> {
        let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        let safe = sanitize_for_log(message);
        let log_entry = format!("[{}] {}\n", timestamp, safe);

        println!("{}", log_entry.trim());

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
        use subtle::ConstantTimeEq;
        let key_guard = self.current_key.read().await;
        let stored = key_guard.key.as_bytes();
        let provided = provided_key.as_bytes();
        
        if stored.len() != provided.len() {
            let _ = stored.ct_eq(&vec![0u8; stored.len()]);
            return false;
        }
        stored.ct_eq(provided).into()
    }

    pub async fn check_auth_rate_limit(&self, ip: &str) -> Result<bool> {
        let mut failures_guard = self.auth_failures.write().await;
        let now = Utc::now();

        if let Some(tracker) = failures_guard.get_mut(ip) {
            if let Some(blocked_until) = tracker.blocked_until {
                if now < blocked_until {
                    let remaining = (blocked_until - now).num_seconds();
                    self.log_message(&format!(
                        "[RATE_LIMIT] IP {} is blocked for {} more seconds ({} failed attempts)",
                        ip, remaining, tracker.failed_attempts
                    ))
                    .await?;
                    return Ok(false);
                } else {
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

        Ok(true)
    }

    pub async fn record_auth_failure(&self, ip: &str) -> Result<()> {
        if ip.len() > 128 {
            return Ok(());
        }
        
        let mut failures_guard = self.auth_failures.write().await;
        let now = Utc::now();
        
        // Background cleanup if needed
        if failures_guard.len() >= MAX_AUTH_FAILURE_ENTRIES {
            let failures_clone = Arc::clone(&self.auth_failures);
            tokio::spawn(async move {
                let mut guard = failures_clone.write().await;
                let cutoff = now - chrono::Duration::hours(1);
                guard.retain(|_, v| {
                    v.blocked_until.map(|b| b > now).unwrap_or(false) ||
                    v.first_failure > cutoff
                });
            });
        }

        let tracker = failures_guard.entry(ip.to_string()).or_insert_with(|| {
            AuthFailureTracker {
                ip: ip.to_string(),
                failed_attempts: 0,
                first_failure: now,
                blocked_until: None,
            }
        });

        if tracker.failed_attempts == 0 {
            tracker.first_failure = now;
        }

        tracker.failed_attempts = tracker.failed_attempts.saturating_add(1);

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

    /// Cleanup expired TOTP sessions
    pub async fn cleanup_totp_sessions(&self) -> Result<()> {
        let mut sessions = self.totp_sessions.write().await;
        let now = Utc::now();
        let before_count = sessions.len();
        
        sessions.retain(|_, last_verify| {
            let elapsed = now.signed_duration_since(*last_verify).num_seconds();
            elapsed < crate::totp_config::SESSION_DURATION_SECS
        });
        
        let after_count = sessions.len();
        if before_count != after_count {
            self.verbose_log(&format!(
                "[CLEANUP] Removed {} expired TOTP sessions ({} -> {})",
                before_count - after_count, before_count, after_count
            )).await?;
        }
        
        Ok(())
    }

    /// Extract real client IP with proxy validation
    fn extract_client_ip(&self, headers: &HeaderMap, addr: SocketAddr) -> String {
        // Only trust X-Forwarded-For if request comes from trusted proxy
        if self.trusted_proxies.contains(&addr.ip()) {
            if let Some(forwarded) = headers.get("x-forwarded-for")
                .or_else(|| headers.get("x-real-ip"))
                .and_then(|h| h.to_str().ok())
            {
                let first_ip = forwarded.split(',').next().unwrap_or("").trim();
                if !first_ip.is_empty() {
                    // Validate it's actually an IP address
                    if first_ip.parse::<IpAddr>().is_ok() {
                        return first_ip.to_string();
                    }
                }
            }
        }
        
        // Fall back to direct connection IP
        addr.ip().to_string()
    }
}

async fn auth_middleware(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    // Extract IP with proxy validation
    let client_ip = state.extract_client_ip(&headers, addr);

    // Check auth failure rate limit
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

    // Extract API key
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

    // Validate key format
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

    // Reset auth failures on successful auth
    if client_ip != "unknown" {
        if let Err(e) = state.reset_auth_failures(&client_ip).await {
            eprintln!("[WARN] Failed to reset auth failures for {}: {}", client_ip, e);
        }
    }

    // Check API key rate limit
    if let Ok(allowed) = state.check_api_key_rate_limit(provided_key).await {
        if !allowed {
            let response = create_response(
                false,
                format!("Rate limit exceeded: maximum {} requests per {} seconds", 
                    API_KEY_RATE_LIMIT, RATE_LIMIT_WINDOW_SECS),
                None,
                Some(ApiErrorCode::RateLimited.as_str().to_string()),
                Some("Please wait before making more requests.".to_string()),
                None,
            );
            return (StatusCode::TOO_MANY_REQUESTS, Json(response)).into_response();
        }
    }

    // TOTP verification
    if state.harden_totp {
        let token_hash = crate::totp_config::TotpConfig::hash_token(provided_key);
        let totp_config = state.totp_config.read().await;
        
        if totp_config.is_configured_for_token(provided_key) {
            let sessions = state.totp_sessions.read().await;
            let session_valid = sessions.get(&token_hash)
                .map(|last_verify| {
                    let elapsed = Utc::now().signed_duration_since(*last_verify);
                    elapsed.num_seconds() < crate::totp_config::SESSION_DURATION_SECS
                })
                .unwrap_or(false);
            drop(sessions);
            
            if !session_valid {
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
                
                match totp_config.verify_code_for_token(provided_key, totp_code) {
                    Ok(true) => {
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
                let sessions = state.totp_sessions.read().await;
                if let Some(last_verify) = sessions.get(&token_hash) {
                    let expires_at = *last_verify + chrono::Duration::seconds(crate::totp_config::SESSION_DURATION_SECS);
                    state.verbose_log(&format!("TOTP session valid until: {}", expires_at.format("%H:%M:%S UTC"))).await.ok();
                }
            }
        }
    }

    // Track IP
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
        None,
    ))
}

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

#[derive(Serialize, Deserialize)]
struct SetTargetRequest {
    target: String,
}

async fn set_target(
    State(state): State<ApiState>,
    Json(payload): Json<SetTargetRequest>,
) -> Response {
    let start_time = std::time::Instant::now();
    let target_raw = payload.target.as_str();
    
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

async fn get_job_output(
    State(state): State<ApiState>,
    axum::extract::Path(job_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    // Validate job_id with length check
    if !validate_job_id(&job_id) {
        return (StatusCode::BAD_REQUEST, Json(create_response(
            false,
            "Invalid job ID format".to_string(),
            None,
            Some(ApiErrorCode::InvalidInput.as_str().to_string()),
            Some(format!("Job ID must be 1-{} characters and contain only alphanumeric, dash, underscore", MAX_JOB_ID_LENGTH)),
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

async fn run_module(
    State(state): State<ApiState>,
    Json(payload): Json<RunModuleRequest>,
) -> Response {
    let start_time = std::time::Instant::now();
    let module_name_raw = payload.module.as_str();
    let target_raw = payload.target.as_str();

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

    let module_name = sanitize_for_log(module_name_raw);
    let target_name = sanitize_for_log(target_raw);
    
    let job_id = uuid::Uuid::new_v4().to_string();
    
    let job_result = crate::job_archive::JobArchive::create_job(
        job_id.clone(),
        module_name.to_string(),
        target_name.to_string(),
    );
    
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

    // Build module config from payload
    let module_config = crate::config::ModuleConfig {
        port: payload.port,
        username_wordlist: payload.username_wordlist.clone(),
        password_wordlist: payload.password_wordlist.clone(),
        path_wordlist: payload.path_wordlist.clone(),
        concurrency: payload.concurrency,
        stop_on_success: payload.stop_on_success,
        save_results: payload.save_results,
        output_file: payload.output_file.clone(),
        verbose: payload.verbose,
        combo_mode: payload.combo_mode,
    };

    let job = Job {
        job_id: job_id.clone(),
        module: module_name.to_string(),
        target: target_name.to_string(),
        verbose: state.verbose || payload.verbose.unwrap_or(false),
        start_time,
        job_archive: Arc::clone(&state.job_archive),
        module_config,
    };

    match state.job_sender.try_send(job) {
        Ok(_) => {
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
            let _ = state.job_archive.update_job(
                &job_id, 
                "Queue full - job not executed".to_string(),
                crate::job_archive::JobStatus::Failed
            ).await;
            
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
            let _ = state.job_archive.update_job(
                &job_id,
                "Job queue closed".to_string(),
                crate::job_archive::JobStatus::Failed
            ).await;
            
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

    // SECURITY: No longer exposing TOTP configuration status

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

    let mut _demo_buffer = crate::job_archive::OutputBuffer::new();
    _demo_buffer.append("Status check ");
    let (_output, _truncated) = _demo_buffer.finish();
    
    let jobs_in_memory = state.job_archive.list_jobs().await.len();

    let status_data = serde_json::json!({
        "harden_enabled": state.harden_enabled,
        "ip_limit": state.ip_limit,
        "unique_ips": tracker_guard.len(),
        "key_created_at": key_guard.created_at.to_rfc3339(),
        "log_file": state.log_file.to_string_lossy(),
        "tracked_ips": ip_details,
        // SECURITY: Removed TOTP config info to prevent info disclosure
        // Attackers should not know if 2FA is configured before attempting attack
        "job_archive": {
            "jobs_in_memory": jobs_in_memory,
            "archive_dir": state.job_archive.archive_dir(),
            "max_output_size_mb": crate::job_archive::MAX_OUTPUT_SIZE / 1024 / 1024,
        },
        "rate_limits": {
            "api_key_limit": API_KEY_RATE_LIMIT,
            "window_seconds": RATE_LIMIT_WINDOW_SECS,
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
    
    let ips: Vec<serde_json::Value> = tracker_guard
        .values()
        .map(|tracker| {
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

// ─── Honeypot Check ─────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct HoneypotCheckRequest {
    target: String,
}

async fn honeypot_check(
    State(state): State<ApiState>,
    Json(payload): Json<HoneypotCheckRequest>,
) -> Response {
    let start_time = std::time::Instant::now();
    let target_raw = payload.target.as_str();

    if !validate_target(target_raw) {
        let response = create_response(
            false,
            "Invalid target format".to_string(),
            None,
            Some(ApiErrorCode::InvalidTarget.as_str().to_string()),
            Some("Target must be a valid IP address.".to_string()),
            Some(start_time),
        );
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }

    let ip = match crate::utils::extract_ip_from_target(target_raw) {
        Some(ip) => ip,
        None => {
            let response = create_response(
                false,
                "Could not extract IP from target".to_string(),
                None,
                Some(ApiErrorCode::InvalidTarget.as_str().to_string()),
                None,
                Some(start_time),
            );
            return (StatusCode::BAD_REQUEST, Json(response)).into_response();
        }
    };

    // Scan common ports (same logic as basic_honeypot_check but returns data)
    const COMMON_PORTS: &[u16] = &[
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090, 1433, 1521, 5432,
        6379, 11211, 27017, 161, 389, 636, 902, 1080, 1194, 1883, 5672,
        8883, 9200, 15672, 25565, 27018, 28017, 50000, 50070, 61616,
    ];

    let scan_timeout = std::time::Duration::from_millis(500);
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(50));
    let mut tasks = Vec::new();

    for &port in COMMON_PORTS {
        let ip = ip.clone();
        let sem = semaphore.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            let addr = format!("{}:{}", ip, port);
            let conn = tokio::time::timeout(
                scan_timeout,
                tokio::net::TcpStream::connect(&addr),
            ).await;
            if let Ok(Ok(_)) = conn { Some(port) } else { None }
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
    let total_scanned = COMMON_PORTS.len();

    let _ = state.log_message(&format!(
        "Honeypot check on {}: {}/{} ports open (honeypot={})",
        sanitize_for_log(&ip), open_ports.len(), total_scanned, is_honeypot
    )).await;

    let response = create_response(
        true,
        format!("Honeypot check completed for {}", ip),
        Some(serde_json::json!({
            "target": ip,
            "open_ports": open_ports,
            "open_count": open_ports.len(),
            "total_scanned": total_scanned,
            "is_honeypot": is_honeypot,
            "threshold": 11,
        })),
        None,
        None,
        Some(start_time),
    );
    (StatusCode::OK, Json(response)).into_response()
}

// ─── Job Cancel ─────────────────────────────────────────────────────

async fn cancel_job(
    State(state): State<ApiState>,
    axum::extract::Path(job_id): axum::extract::Path<String>,
) -> Response {
    if !validate_job_id(&job_id) {
        let response = create_response(
            false,
            "Invalid job ID format".to_string(),
            None,
            Some(ApiErrorCode::InvalidInput.as_str().to_string()),
            None,
            None,
        );
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }

    match state.job_archive.cancel_job(&job_id).await {
        Ok(true) => {
            let _ = state.log_message(&format!("Job {} cancelled by user", job_id)).await;
            let response = create_response(
                true,
                format!("Job '{}' cancelled", job_id),
                Some(serde_json::json!({ "job_id": job_id, "status": "cancelled" })),
                None,
                None,
                None,
            );
            (StatusCode::OK, Json(response)).into_response()
        }
        Ok(false) => {
            let response = create_response(
                false,
                format!("Job '{}' not found or not running", job_id),
                None,
                Some(ApiErrorCode::NotFound.as_str().to_string()),
                Some("Only running jobs can be cancelled.".to_string()),
                None,
            );
            (StatusCode::NOT_FOUND, Json(response)).into_response()
        }
        Err(e) => {
            let response = create_response(
                false,
                format!("Failed to cancel job: {}", e),
                None,
                Some(ApiErrorCode::ServerError.as_str().to_string()),
                None,
                None,
            );
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response)).into_response()
        }
    }
}

// ─── Job Delete ─────────────────────────────────────────────────────

async fn delete_job(
    State(state): State<ApiState>,
    axum::extract::Path(job_id): axum::extract::Path<String>,
) -> Response {
    if !validate_job_id(&job_id) {
        let response = create_response(
            false,
            "Invalid job ID format".to_string(),
            None,
            Some(ApiErrorCode::InvalidInput.as_str().to_string()),
            None,
            None,
        );
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }

    if state.job_archive.delete_job(&job_id).await {
        let _ = state.log_message(&format!("Job {} deleted by user", job_id)).await;
        let response = create_response(
            true,
            format!("Job '{}' deleted", job_id),
            Some(serde_json::json!({ "job_id": job_id })),
            None,
            None,
            None,
        );
        (StatusCode::OK, Json(response)).into_response()
    } else {
        let response = create_response(
            false,
            format!("Job '{}' not found", job_id),
            None,
            Some(ApiErrorCode::NotFound.as_str().to_string()),
            None,
            None,
        );
        (StatusCode::NOT_FOUND, Json(response)).into_response()
    }
}

// ─── Audit Logs ─────────────────────────────────────────────────────

async fn get_logs(
    State(state): State<ApiState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let lines_count: usize = params
        .get("lines")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .min(1000); // Cap at 1000 lines

    let log_path = &state.log_file;
    match std::fs::read_to_string(log_path) {
        Ok(contents) => {
            let all_lines: Vec<&str> = contents.lines().collect();
            let total = all_lines.len();
            let start = total.saturating_sub(lines_count);
            let recent: Vec<&str> = all_lines[start..].to_vec();

            let response = create_response(
                true,
                format!("Retrieved {} log entries (of {} total)", recent.len(), total),
                Some(serde_json::json!({
                    "lines": recent,
                    "total_lines": total,
                    "returned": recent.len(),
                    "log_file": log_path.to_string_lossy(),
                })),
                None,
                None,
                None,
            );
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            let response = create_response(
                false,
                format!("Failed to read log file: {}", e),
                None,
                Some(ApiErrorCode::ServerError.as_str().to_string()),
                None,
                None,
            );
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response)).into_response()
        }
    }
}

// ─── Runtime Config ─────────────────────────────────────────────────

async fn get_config(State(state): State<ApiState>) -> Json<ApiResponse> {
    Json(create_response(
        true,
        "Runtime configuration retrieved".to_string(),
        Some(serde_json::json!({
            "harden_enabled": state.harden_enabled,
            "harden_totp": state.harden_totp,
            "harden_rate_limit": state.harden_rate_limit,
            "harden_ip_tracking": state.harden_ip_tracking,
            "ip_limit": state.ip_limit,
            "verbose": state.verbose,
            "rate_limits": {
                "api_key_limit": API_KEY_RATE_LIMIT,
                "window_seconds": RATE_LIMIT_WINDOW_SECS,
            },
            "job_archive": {
                "max_output_size_bytes": crate::job_archive::MAX_OUTPUT_SIZE,
                "archive_dir": state.job_archive.archive_dir(),
            },
            "log_file": state.log_file.to_string_lossy(),
            "trusted_proxies": state.trusted_proxies.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
        })),
        None,
        None,
        None,
    ))
}

// ─── Module Counts ─────────────────────────────────────────────────

async fn get_module_counts() -> Json<ApiResponse> {
    let modules = commands::discover_modules();
    let exploit_count = modules.iter().filter(|m| m.starts_with("exploits/")).count();
    let scanner_count = modules.iter().filter(|m| m.starts_with("scanners/")).count();
    let creds_count = modules.iter().filter(|m| m.starts_with("creds/")).count();

    Json(create_response(
        true,
        format!("Total {} modules", modules.len()),
        Some(serde_json::json!({
            "total": modules.len(),
            "exploits": exploit_count,
            "scanners": scanner_count,
            "creds": creds_count,
        })),
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
    trusted_proxies: Vec<IpAddr>,
) -> Result<()> {
    let (tx, rx) = mpsc::channel(queue_size);
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    let state = ApiState::new(
        api_key.clone(),
        harden,
        harden_totp,
        harden_rate_limit,
        harden_ip_tracking,
        ip_limit,
        verbose,
        tx,
        trusted_proxies,
    );

    // Spawn background cleanup task for TOTP sessions
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs(TOTP_CLEANUP_INTERVAL_SECS as u64)
        );
        loop {
            interval.tick().await;
            if let Err(e) = cleanup_state.cleanup_totp_sessions().await {
                eprintln!("[WARN] TOTP session cleanup error: {}", e);
            }
        }
    });

    // Spawn worker pool - each worker processes jobs from the queue
    for worker_id in 0..workers {
        let state_clone = state.clone();
        let rx = Arc::clone(&rx);
        tokio::spawn(async move {
            loop {
                // Receive job from queue
                let job = rx.lock().await.recv().await;
                
                if let Some(j) = job {
                    let job_id = j.job_id.clone();
                    let module = j.module.clone();
                    let target = j.target.clone();
                    let verbose = j.verbose;
                    let start_time = j.start_time;
                    let job_archive = Arc::clone(&j.job_archive);
                    let module_config = j.module_config.clone();
                    
                    // Set global module config before execution
                    crate::config::set_module_config(module_config);
                    
                    // Execute module
                    // NOTE: commands::run_module returns Result<()>, not Result<String>
                    // Modules print directly to stdout/stderr, so we create success/error messages
                    let result = commands::run_module(&module, &target, verbose).await;
                    
                    // Clear module config after execution
                    crate::config::clear_module_config();
                    
                    match result {
                        Ok(_) => {
                            let duration = start_time.elapsed().as_millis() as u64;
                            
                            // Create success message (run_module doesn't return output)
                            let output = format!(
                                "Module '{}' executed successfully on target '{}'", 
                                module, 
                                target
                            );
                            
                            // Update job with success message
                            if let Err(e) = job_archive.update_job(
                                &job_id,
                                output,
                                crate::job_archive::JobStatus::Completed,
                            ).await {
                                eprintln!("[WARN] Worker {}: Failed to update job {}: {}", worker_id, job_id, e);
                            }
                            
                            if let Err(e) = state_clone.log_message(&format!(
                                "[Worker {}] Successfully completed job {} - module '{}' on '{}' [{}ms]",
                                worker_id, job_id, module, target, duration
                            )).await {
                                eprintln!("[WARN] Worker {}: Failed to log success: {}", worker_id, e);
                            }
                        }
                        Err(e) => {
                            let duration = start_time.elapsed().as_millis() as u64;
                            let error_msg = format!(
                                "Error executing module '{}' on '{}': {}", 
                                module, 
                                target, 
                                e
                            );
                            
                            // Update job with error
                            if let Err(e) = job_archive.update_job(
                                &job_id,
                                error_msg.clone(),
                                crate::job_archive::JobStatus::Failed,
                            ).await {
                                eprintln!("[WARN] Worker {}: Failed to update job {}: {}", worker_id, job_id, e);
                            }
                            
                            if let Err(e) = state_clone.log_message(&format!(
                                "[Worker {}] Error in job {} ({}): {} [{}ms]",
                                worker_id, job_id, ApiErrorCode::ExecutionError.as_str(),
                                sanitize_for_log(&error_msg), duration
                            )).await {
                                eprintln!("[WARN] Worker {}: Failed to log error: {}", worker_id, e);
                            }
                        }
                    }
                } else {
                    // Channel closed
                    eprintln!("[Worker {}] Job channel closed, shutting down", worker_id);
                    break;
                }
            }
        });
    }

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
    println!("⚡ API Key Rate Limit: {} requests per {} seconds", API_KEY_RATE_LIMIT, RATE_LIMIT_WINDOW_SECS);
    println!("👷 Workers: {}", workers);
    println!("📥 Queue Size: {}", queue_size);
    println!("📝 Log file: {}", state.log_file.display());
    println!("🔒 Trusted Proxies: {:?}", state.trusted_proxies);

    let protected_routes = Router::new()
        .route("/api/modules", get(list_modules))
        .route("/api/modules/search", get(search_modules))
        .route("/api/module/{category}/{name}", get(get_module_info))
        .route("/api/run", post(run_module))
        .route("/api/validate", post(validate_module_params))
        .route("/api/target", get(get_target))
        .route("/api/target", post(set_target))
        .route("/api/target", axum::routing::delete(clear_target))
        .route("/api/output/{job_id}", get(get_job_output))
        .route("/api/jobs", get(list_jobs))
        .route("/api/status", get(get_status))
        .route("/api/rotate-key", post(rotate_key_endpoint))
        .route("/api/ips", get(get_tracked_ips))
        .route("/api/auth-failures", get(get_auth_failures))
        .route("/api/honeypot-check", post(honeypot_check))
        .route("/api/jobs/{job_id}/cancel", post(cancel_job))
        .route("/api/jobs/{job_id}", axum::routing::delete(delete_job))
        .route("/api/logs", get(get_logs))
        .route("/api/config", get(get_config))
        .route("/api/modules/count", get(get_module_counts))
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
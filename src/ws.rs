use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, ConnectInfo},
    response::Response,
};
use base64::Engine;
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::pq_channel::{decrypt_ws_frame, derive_ws_subsession, encrypt_ws_frame, WsSubSession};
use crate::pq_middleware::PqSharedState;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const MAX_WS_FRAME_SIZE: usize = 1024 * 1024;
const MAX_TOTAL_CONNECTIONS: usize = 100;
const HEARTBEAT_INTERVAL_SECS: u64 = 30;

static TOTAL_WS_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

pub async fn ws_upgrade(
    axum::Extension(pq): axum::Extension<Arc<PqSharedState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let session_b64 = headers
        .get("X-PQ-Session")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let session_b64 = match session_b64 {
        Some(s) => s,
        None => {
            return axum::response::IntoResponse::into_response((
                axum::http::StatusCode::UNAUTHORIZED,
                "Missing X-PQ-Session header",
            ));
        }
    };

    let session_id_vec = match B64.decode(&session_b64) {
        Ok(v) => v,
        Err(_) => {
            return axum::response::IntoResponse::into_response((
                axum::http::StatusCode::BAD_REQUEST,
                "Invalid session ID encoding",
            ));
        }
    };

    let session_id: [u8; 16] = match session_id_vec.try_into() {
        Ok(id) => id,
        Err(_) => {
            return axum::response::IntoResponse::into_response((
                axum::http::StatusCode::BAD_REQUEST,
                "Session ID must be 16 bytes",
            ));
        }
    };

    let sub_session = {
        let store = pq.sessions.read().await;
        match store.get(&session_id) {
            Some(session) => match derive_ws_subsession(session) {
                Ok(sub) => sub,
                Err(e) => {
                    tracing::warn!("WS sub-session derivation failed for {}: {}", addr, e);
                    return axum::response::IntoResponse::into_response((
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        "Sub-session derivation failed",
                    ));
                }
            },
            None => {
                return axum::response::IntoResponse::into_response((
                    axum::http::StatusCode::UNAUTHORIZED,
                    "Unknown PQ session",
                ));
            }
        }
    };

    let prev = TOTAL_WS_CONNECTIONS.fetch_add(1, Ordering::AcqRel);
    if prev >= MAX_TOTAL_CONNECTIONS {
        TOTAL_WS_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
        return axum::response::IntoResponse::into_response((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "WebSocket connection limit reached",
        ));
    }

    let pq_clone = pq.clone();
    ws.max_frame_size(MAX_WS_FRAME_SIZE)
        .on_upgrade(move |socket| handle_ws(socket, sub_session, session_id, pq_clone, addr))
}

async fn handle_ws(
    socket: WebSocket,
    sub_session: WsSubSession,
    parent_session_id: [u8; 16],
    pq: Arc<PqSharedState>,
    addr: SocketAddr,
) {
    tracing::info!("WS connected: {}", addr);

    let session_id_b64 = B64.encode(sub_session.session_id);
    let sub = Arc::new(Mutex::new(sub_session));
    let subscribed_jobs: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));

    let (mut ws_tx, mut ws_rx) = socket.split();
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    let writer_sub = sub.clone();
    let writer_aad_prefix = session_id_b64.clone();
    let writer_handle = tokio::spawn(async move {
        while let Some(plaintext) = outbound_rx.recv().await {
            let aad = format!("ws|s2c|{}", writer_aad_prefix);
            let frame = {
                let mut s = writer_sub.lock().await;
                match encrypt_ws_frame(&mut s, &plaintext, aad.as_bytes()) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!("WS encrypt error: {}", e);
                        break;
                    }
                }
            };
            if let Err(e) = ws_tx.send(Message::Binary(frame.into())).await {
                tracing::debug!("WS send error: {}", e);
                break;
            }
        }
    });

    let mut job_rx = crate::jobs::JOB_MANAGER.subscribe();
    let event_tx = outbound_tx.clone();
    let event_jobs = subscribed_jobs.clone();
    let event_handle = tokio::spawn(async move {
        loop {
            match job_rx.recv().await {
                Ok(event) => {
                    let event_id = match &event {
                        crate::jobs::JobEvent::Started { id, .. } => *id,
                        crate::jobs::JobEvent::Completed { id } => *id,
                        crate::jobs::JobEvent::Failed { id, .. } => *id,
                        crate::jobs::JobEvent::Cancelled { id } => *id,
                    };
                    let is_started = matches!(&event, crate::jobs::JobEvent::Started { .. });
                    if !is_started && !event_jobs.lock().await.contains(&event_id) {
                        continue;
                    }
                    let event_json = match &event {
                        crate::jobs::JobEvent::Started { id, module, target } => {
                            json!({"type": "event", "event": "job:started", "data": {"id": id, "module": module, "target": target}})
                        }
                        crate::jobs::JobEvent::Completed { id } => {
                            json!({"type": "event", "event": "job:completed", "data": {"id": id}})
                        }
                        crate::jobs::JobEvent::Failed { id, error } => {
                            json!({"type": "event", "event": "job:failed", "data": {"id": id, "error": error}})
                        }
                        crate::jobs::JobEvent::Cancelled { id } => {
                            json!({"type": "event", "event": "job:cancelled", "data": {"id": id}})
                        }
                    };
                    let bytes = match serde_json::to_vec(&event_json) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::debug!("WS event serialize error: {}", e);
                            continue;
                        }
                    };
                    if event_tx.send(bytes).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::debug!("WS event subscriber lagged by {} events", n);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let heartbeat_tx = outbound_tx.clone();
    let heartbeat_pq = pq.clone();
    let heartbeat_session = parent_session_id;
    let heartbeat_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
        loop {
            interval.tick().await;
            let store = heartbeat_pq.sessions.read().await;
            if !store.contains_key(&heartbeat_session) {
                tracing::info!("WS parent PQ session expired, closing");
                break;
            }
            drop(store);
            let pong = serde_json::to_vec(&json!({"type": "heartbeat"}))
                .unwrap_or_default();
            if heartbeat_tx.send(pong).await.is_err() {
                break;
            }
        }
    });

    let reader_sub = sub.clone();
    let reader_tx = outbound_tx.clone();
    let reader_aad_prefix = session_id_b64.clone();
    let reader_jobs = subscribed_jobs.clone();

    loop {
        let msg = match ws_rx.next().await {
            Some(Ok(msg)) => msg,
            Some(Err(e)) => {
                tracing::debug!("WS recv error from {}: {}", addr, e);
                break;
            }
            None => break,
        };

        let frame_bytes = match msg {
            Message::Binary(b) => b.to_vec(),
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => continue,
            _ => continue,
        };

        if frame_bytes.len() > MAX_WS_FRAME_SIZE {
            tracing::warn!("WS frame too large from {}: {} bytes", addr, frame_bytes.len());
            break;
        }

        let plaintext = {
            let aad = format!("ws|c2s|{}", reader_aad_prefix);
            let mut s = reader_sub.lock().await;
            match decrypt_ws_frame(&mut s, &frame_bytes, aad.as_bytes()) {
                Ok(pt) => pt,
                Err(e) => {
                    tracing::warn!("WS decrypt failed from {}: {}", addr, e);
                    break;
                }
            }
        };

        let request: Value = match serde_json::from_slice(&plaintext) {
            Ok(v) => v,
            Err(e) => {
                let err_resp = json!({"error": {"code": "PARSE_ERROR", "message": format!("Invalid JSON: {}", e)}});
                if let Ok(bytes) = serde_json::to_vec(&err_resp) && reader_tx.send(bytes).await.is_err() {
                    break;
                }
                continue;
            }
        };

        let req_id = request.get("id").cloned();
        let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(json!({}));

        if method == "subscribe:output" {
            if let Some(job_id_u64) = params.get("jobId").and_then(|v| v.as_u64()) {
                let job_id: u32 = match u32::try_from(job_id_u64) {
                    Ok(id) => id,
                    Err(_) => {
                        let resp = json!({"id": req_id, "error": {"code": "INVALID_JOB_ID", "message": "jobId exceeds u32 range"}});
                        if let Ok(bytes) = serde_json::to_vec(&resp) && reader_tx.send(bytes).await.is_err() {
                            break;
                        }
                        continue;
                    }
                };
                let mut jobs = reader_jobs.lock().await;
                if jobs.len() >= 100 {
                    let resp = json!({"id": req_id, "error": {"code": "SUB_LIMIT", "message": "Max 100 job subscriptions per connection"}});
                    if let Ok(bytes) = serde_json::to_vec(&resp) && reader_tx.send(bytes).await.is_err() {
                        break;
                    }
                } else {
                    jobs.insert(job_id);
                    let resp = json!({"id": req_id, "result": {"subscribed": job_id}});
                    if let Ok(bytes) = serde_json::to_vec(&resp) && reader_tx.send(bytes).await.is_err() {
                        break;
                    }
                }
            }
            continue;
        }
        if method == "unsubscribe:output" {
            if let Some(job_id_u64) = params.get("jobId").and_then(|v| v.as_u64()) {
                if let Ok(job_id) = u32::try_from(job_id_u64) {
                    reader_jobs.lock().await.remove(&job_id);
                }
            }
            continue;
        }

        let result = dispatch_rpc(method, &params).await;
        let response = match result {
            Ok(data) => json!({"id": req_id, "result": data}),
            Err(e) => json!({"id": req_id, "error": {"code": e.0, "message": e.1}}),
        };
        if let Ok(bytes) = serde_json::to_vec(&response) && reader_tx.send(bytes).await.is_err() {
            break;
        }
    }

    writer_handle.abort();
    event_handle.abort();
    heartbeat_handle.abort();
    TOTAL_WS_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
    tracing::info!("WS disconnected: {}", addr);
}

type RpcResult = Result<Value, (String, String)>;

fn rpc_err(code: &str, msg: impl Into<String>) -> (String, String) {
    (code.to_string(), msg.into())
}

fn require_str<'a>(params: &'a Value, key: &str) -> Result<&'a str, (String, String)> {
    params.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| rpc_err("INVALID_INPUT", format!("Missing required parameter: {}", key)))
}

async fn dispatch_rpc(method: &str, params: &Value) -> RpcResult {
    match method {
        "health" => rpc_health().await,
        "list_modules" => rpc_list_modules().await,
        "list_modules_enriched" => rpc_list_modules_enriched().await,
        "search_modules" => rpc_search_modules(params).await,
        "module_info" => rpc_module_info(params).await,
        "get_target" => rpc_get_target().await,
        "set_target" => rpc_set_target(params).await,
        "clear_target" => rpc_clear_target().await,
        "run_module" => rpc_run_module(params).await,
        "run_all" => rpc_run_module(params).await,
        "check_module" => rpc_check_module(params).await,
        "honeypot_check" => rpc_honeypot_check(params).await,
        "list_options" => rpc_list_options().await,
        "set_option" => rpc_set_option(params).await,
        "delete_option" => rpc_delete_option(params).await,
        "list_creds" => rpc_list_creds(params).await,
        "add_cred" => rpc_add_cred(params).await,
        "delete_cred" => rpc_delete_cred(params).await,
        "search_creds" => rpc_search_creds(params).await,
        "clear_creds" => rpc_clear_creds().await,
        "list_hosts" => rpc_list_hosts(params).await,
        "add_host" => rpc_add_host(params).await,
        "delete_host" => rpc_delete_host(params).await,
        "add_host_note" => rpc_add_host_note(params).await,
        "clear_hosts" => rpc_clear_hosts().await,
        "list_services" => rpc_list_services(params).await,
        "add_service" => rpc_add_service(params).await,
        "delete_service" => rpc_delete_service(params).await,
        "list_loot" => rpc_list_loot(params).await,
        "add_loot" => rpc_add_loot(params).await,
        "delete_loot" => rpc_delete_loot(params).await,
        "search_loot" => rpc_search_loot(params).await,
        "clear_loot" => rpc_clear_loot().await,
        "get_workspace" => rpc_get_workspace().await,
        "switch_workspace" => rpc_switch_workspace(params).await,
        "list_workspaces" => rpc_list_workspaces().await,
        "list_jobs" => rpc_list_jobs().await,
        "get_job" => rpc_get_job(params).await,
        "kill_job" => rpc_kill_job(params).await,
        "set_job_limit" => rpc_set_job_limit(params).await,
        "spool_status" => rpc_spool_status().await,
        "spool_start" => rpc_spool_start(params).await,
        "spool_stop" => rpc_spool_stop().await,
        "list_results" => rpc_list_results().await,
        "get_result" => rpc_get_result(params).await,
        "export" => rpc_export(params).await,
        _ => Err(rpc_err("METHOD_NOT_FOUND", format!("Unknown method: {}", method))),
    }
}

// ── Health ────────────────────────────────────────────────────────────

async fn rpc_health() -> RpcResult {
    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "active_jobs": crate::jobs::JOB_MANAGER.running_count(),
        "max_jobs": crate::jobs::JOB_MANAGER.get_max_running(),
    }))
}

// ── Modules ──────────────────────────────────────────────────────────

async fn rpc_list_modules() -> RpcResult {
    let modules = crate::commands::discover_modules();
    let mut by_category: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    for module in &modules {
        let category = module.split('/').next().unwrap_or("other").to_string();
        by_category.entry(category).or_default().push(module.clone());
    }
    Ok(json!({"modules": by_category, "total": modules.len()}))
}

async fn rpc_list_modules_enriched() -> RpcResult {
    let modules = crate::commands::discover_modules();
    let enriched: Vec<Value> = modules.iter().map(|m| {
        let info = crate::commands::module_info(m).unwrap_or_else(|| crate::module_info::ModuleInfo {
            name: m.to_string(), description: String::new(), authors: vec![],
            references: vec![], disclosure_date: None, rank: crate::module_info::ModuleRank::Good,
        });
        let category = m.split('/').next().unwrap_or("other");
        json!({
            "path": m,
            "name": info.name,
            "description": info.description,
            "authors": info.authors,
            "category": category,
            "has_check": crate::commands::has_check(m),
            "rank": format!("{:?}", info.rank),
        })
    }).collect();
    let categories: Vec<&str> = crate::commands::categories().to_vec();
    Ok(json!({"modules": enriched, "total": enriched.len(), "categories": categories}))
}

async fn rpc_search_modules(params: &Value) -> RpcResult {
    let query = require_str(params, "q")?;
    if query.len() > 256 {
        return Err(rpc_err("INVALID_INPUT", "Search query too long (max 256)"));
    }
    let modules = crate::commands::discover_modules();
    let lower = query.to_lowercase();
    let matches: Vec<&String> = modules.iter().filter(|m| m.to_lowercase().contains(&lower)).collect();
    Ok(json!({"matches": matches, "total": matches.len()}))
}

async fn rpc_module_info(params: &Value) -> RpcResult {
    let path = require_str(params, "path")?;
    if !crate::api::validate_module_name(path) {
        return Err(rpc_err("INVALID_INPUT", "Invalid module path"));
    }
    match crate::commands::module_info(path) {
        Some(info) => serde_json::to_value(&info).map_err(|e| rpc_err("SERIALIZE_ERROR", e.to_string())),
        None => Err(rpc_err("NOT_FOUND", format!("Module '{}' not found", path))),
    }
}

// ── Target ───────────────────────────────────────────────────────────

async fn rpc_get_target() -> RpcResult {
    let target = crate::config::GLOBAL_CONFIG.get_target();
    let size = crate::config::GLOBAL_CONFIG.get_target_size().unwrap_or(0);
    Ok(json!({
        "target": target,
        "size": size,
        "is_subnet": size > 1,
    }))
}

async fn rpc_set_target(params: &Value) -> RpcResult {
    let target = require_str(params, "target")?;
    if !crate::api::validate_target(target) {
        return Err(rpc_err("INVALID_INPUT", "Invalid target format"));
    }
    if crate::api::is_blocked_target(target) {
        return Err(rpc_err("SSRF_BLOCKED", "Target matches blocked cloud metadata range"));
    }
    if crate::api::is_blocked_target_resolved(target).await {
        return Err(rpc_err("SSRF_BLOCKED", "Target resolves to blocked address"));
    }
    match crate::config::GLOBAL_CONFIG.set_target(target) {
        Ok(_) => {
            let t = crate::config::GLOBAL_CONFIG.get_target();
            let size = crate::config::GLOBAL_CONFIG.get_target_size().unwrap_or(0);
            Ok(json!({"target": t, "size": size}))
        }
        Err(e) => Err(rpc_err("TARGET_ERROR", e.to_string())),
    }
}

async fn rpc_clear_target() -> RpcResult {
    crate::config::GLOBAL_CONFIG.clear_target();
    Ok(json!({"cleared": true}))
}

// ── Run Module ───────────────────────────────────────────────────────

async fn rpc_run_module(params: &Value) -> RpcResult {
    let module = require_str(params, "module")?;
    let target = require_str(params, "target")?;

    if !crate::api::validate_module_name(module) {
        return Err(rpc_err("INVALID_INPUT", "Invalid module name"));
    }
    if !crate::api::validate_target(target) {
        return Err(rpc_err("INVALID_INPUT", "Invalid target"));
    }
    if crate::api::is_blocked_target_resolved(target).await {
        return Err(rpc_err("SSRF_BLOCKED", "Target resolves to blocked address"));
    }
    if !crate::commands::discover_modules().contains(&module.to_string()) {
        return Err(rpc_err("MODULE_NOT_FOUND", format!("Module '{}' not found", module)));
    }

    if let Some(prompts) = params.get("prompts").and_then(|v| v.as_object()) {
        for (k, v) in prompts {
            if !k.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return Err(rpc_err("INVALID_INPUT", format!("Invalid prompt key: {}", k)));
            }
            if v.as_str().is_some_and(crate::api::contains_shell_metacharacters) {
                return Err(rpc_err("INVALID_INPUT", format!("Shell metacharacters in prompt value for key '{}'", k)));
            }
        }
    }

    if params.get("username_wordlist").and_then(|v| v.as_str())
        .is_some_and(crate::api::contains_shell_metacharacters) {
        return Err(rpc_err("INVALID_INPUT", "Shell metacharacters in username_wordlist"));
    }
    if params.get("password_wordlist").and_then(|v| v.as_str())
        .is_some_and(crate::api::contains_shell_metacharacters) {
        return Err(rpc_err("INVALID_INPUT", "Shell metacharacters in password_wordlist"));
    }
    if params.get("combo_mode").and_then(|v| v.as_str())
        .is_some_and(crate::api::contains_shell_metacharacters) {
        return Err(rpc_err("INVALID_INPUT", "Shell metacharacters in combo_mode"));
    }
    if params.get("output_file").and_then(|v| v.as_str())
        .is_some_and(|of| of.contains("..") || of.contains('/') || of.contains('\\') || of.contains('\0')) {
        return Err(rpc_err("INVALID_OUTPUT_FILE", "Path traversal in output_file"));
    }

    let verbose = params.get("verbose").and_then(|v| v.as_bool()).unwrap_or(false);
    let background = params.get("background").and_then(|v| v.as_bool()).unwrap_or(false);

    let mut custom_prompts: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if let Some(prompts) = params.get("prompts").and_then(|v| v.as_object()) {
        for (k, v) in prompts {
            if k == "target" {
                continue;
            }
            if let Some(val) = v.as_str() {
                custom_prompts.insert(k.clone(), val.to_string());
            }
        }
    }
    if let Some(port) = params.get("port").and_then(|v| v.as_u64()) {
        custom_prompts.entry("port".into()).or_insert_with(|| port.to_string());
    }
    if let Some(wl) = params.get("username_wordlist").and_then(|v| v.as_str()) {
        custom_prompts.entry("username_wordlist".into()).or_insert_with(|| wl.to_string());
    }
    if let Some(wl) = params.get("password_wordlist").and_then(|v| v.as_str()) {
        custom_prompts.entry("password_wordlist".into()).or_insert_with(|| wl.to_string());
    }
    if let Some(c) = params.get("concurrency").and_then(|v| v.as_u64()) {
        custom_prompts.entry("concurrency".into()).or_insert_with(|| c.to_string());
    }
    if let Some(s) = params.get("stop_on_success").and_then(|v| v.as_bool()) {
        custom_prompts.entry("stop_on_success".into()).or_insert_with(|| if s { "true" } else { "false" }.to_string());
    }
    if let Some(of) = params.get("output_file").and_then(|v| v.as_str()) {
        custom_prompts.entry("output_file".into()).or_insert_with(|| of.to_string());
    }
    if let Some(cm) = params.get("combo_mode").and_then(|v| v.as_str()) {
        custom_prompts.entry("combo_mode".into()).or_insert_with(|| cm.to_string());
    }

    let module_config = crate::config::ModuleConfig {
        api_mode: true,
        custom_prompts,
    };

    if background {
        match crate::jobs::JOB_MANAGER.spawn(
            module.to_string(),
            target.to_string(),
            verbose,
            Some(module_config),
        ) {
            Ok((job_id, _progress)) => {
                Ok(json!({"job_id": job_id, "status": "started"}))
            }
            Err(e) => Err(rpc_err("JOB_LIMIT", e)),
        }
    } else {
        let target_owned = target.to_string();
        let module_owned = module.to_string();
        let output_buf = crate::output::OutputBuffer::new();
        let buf_clone = output_buf.clone();

        let (result, _ctx) = crate::context::run_with_context_target(
            module_config,
            target_owned.clone(),
            || async move {
                crate::output::OUTPUT_BUFFER
                    .scope(buf_clone, async move {
                        crate::commands::run_module(&module_owned, &target_owned, verbose).await
                    })
                    .await
            },
        )
        .await;

        let stdout = output_buf.drain_stdout();
        let stderr = output_buf.drain_stderr();
        match result {
            Ok(_) => Ok(json!({
                "status": "completed",
                "module": module,
                "target": target,
                "stdout": stdout,
                "stderr": stderr,
            })),
            Err(e) => Err(rpc_err("MODULE_ERROR", e.to_string())),
        }
    }
}

async fn rpc_check_module(params: &Value) -> RpcResult {
    let module = require_str(params, "module")?;
    let target = require_str(params, "target")?;
    if !crate::api::validate_module_name(module) {
        return Err(rpc_err("INVALID_INPUT", "Invalid module name"));
    }
    if !crate::api::validate_target(target) {
        return Err(rpc_err("INVALID_INPUT", "Invalid target"));
    }
    if crate::api::is_blocked_target_resolved(target).await {
        return Err(rpc_err("SSRF_BLOCKED", "Target resolves to blocked address"));
    }
    match crate::commands::check_module(module, target).await {
        Some(result) => Ok(json!({"module": module, "target": target, "result": result.to_string()})),
        None => Err(rpc_err("CHECK_ERROR", "Module does not support check or was not found")),
    }
}

async fn rpc_honeypot_check(params: &Value) -> RpcResult {
    let target = require_str(params, "target")?;
    if !crate::api::validate_target(target) {
        return Err(rpc_err("INVALID_INPUT", "Invalid target"));
    }
    if crate::api::is_blocked_target_resolved(target).await {
        return Err(rpc_err("SSRF_BLOCKED", "Target resolves to blocked address"));
    }
    let is_honeypot = crate::utils::network::quick_honeypot_check(target).await;
    Ok(json!({"target": target, "is_honeypot": is_honeypot}))
}

// ── Options ──────────────────────────────────────────────────────────

async fn rpc_list_options() -> RpcResult {
    let opts = crate::global_options::GLOBAL_OPTIONS.all().await;
    Ok(json!({"options": opts}))
}

async fn rpc_set_option(params: &Value) -> RpcResult {
    let obj = params.as_object().ok_or_else(|| rpc_err("INVALID_INPUT", "params must be an object"))?;
    let mut set_count = 0usize;
    for (key, val) in obj {
        let value = val.as_str().unwrap_or("");
        if key.is_empty() || key.len() > 256 {
            return Err(rpc_err("INVALID_INPUT", format!("Option key '{}' invalid (1-256 chars)", key)));
        }
        if value.len() > 4096 {
            return Err(rpc_err("INVALID_INPUT", format!("Value for '{}' too long (max 4096)", key)));
        }
        if !crate::global_options::GLOBAL_OPTIONS.set(key, value).await {
            return Err(rpc_err("OPTION_ERROR", format!("Failed to set '{}'", key)));
        }
        set_count += 1;
    }
    Ok(json!({"set": set_count}))
}

async fn rpc_delete_option(params: &Value) -> RpcResult {
    let key = require_str(params, "key")?;
    if crate::global_options::GLOBAL_OPTIONS.unset(key).await {
        Ok(json!({"deleted": key}))
    } else {
        Err(rpc_err("NOT_FOUND", format!("Option '{}' not found", key)))
    }
}

// ── Credentials ──────────────────────────────────────────────────────

async fn rpc_list_creds(params: &Value) -> RpcResult {
    let all = crate::cred_store::CRED_STORE.list().await;

    let filter_host = params.get("host").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    let filter_service = params.get("service").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    let filter_search = params.get("search").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    let reveal = params.get("reveal").and_then(|v| v.as_bool()).unwrap_or(false);

    let filtered: Vec<_> = all.into_iter().filter(|c| {
        if filter_host.is_some_and(|h| !c.host.contains(h)) { return false; }
        if filter_service.is_some_and(|s| !c.service.contains(s)) { return false; }
        if let Some(q) = filter_search {
            let q = q.to_lowercase();
            if !c.host.to_lowercase().contains(&q) && !c.username.to_lowercase().contains(&q)
                && !c.service.to_lowercase().contains(&q) { return false; }
        }
        true
    }).collect();

    let total = filtered.len();
    let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(50).min(1000) as usize;
    let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let page: Vec<_> = filtered.into_iter().skip(offset).take(limit).collect();

    let creds_json = if reveal {
        serde_json::to_value(&page).map_err(|e| rpc_err("SERIALIZE_ERROR", e.to_string()))?
    } else {
        let redacted: Vec<Value> = page.iter().map(|c| {
            let masked = if c.secret.len() <= 2 { "****".to_string() }
            else { format!("{}****", &c.secret[..2]) };
            json!({
                "id": c.id, "host": c.host, "port": c.port,
                "service": c.service, "username": c.username,
                "secret": masked, "cred_type": format!("{:?}", c.cred_type),
                "valid": c.valid, "source_module": c.source_module,
            })
        }).collect();
        serde_json::to_value(redacted).map_err(|e| rpc_err("SERIALIZE_ERROR", e.to_string()))?
    };

    Ok(json!({"credentials": creds_json, "total": total, "limit": limit, "offset": offset}))
}

async fn rpc_add_cred(params: &Value) -> RpcResult {
    let host = require_str(params, "host")?;
    let username = require_str(params, "username")?;
    let secret = require_str(params, "secret")?;
    let port_raw = params.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
    if port_raw == 0 || port_raw > 65535 {
        return Err(rpc_err("INVALID_INPUT", "port must be 1-65535"));
    }
    let port = port_raw as u16;
    let service = params.get("service").and_then(|v| v.as_str()).unwrap_or("unknown");
    let source = params.get("source_module").and_then(|v| v.as_str()).unwrap_or("ws");

    if host.len() > 4096 || username.len() > 4096 || secret.len() > 4096 || service.len() > 4096 {
        return Err(rpc_err("INVALID_INPUT", "Field exceeds max length (4096)"));
    }

    let cred_type = match params.get("cred_type").and_then(|v| v.as_str()).unwrap_or("password") {
        "password" => crate::cred_store::CredType::Password,
        "hash" => crate::cred_store::CredType::Hash,
        "key" => crate::cred_store::CredType::Key,
        "token" => crate::cred_store::CredType::Token,
        other => return Err(rpc_err("INVALID_INPUT", format!("Unknown cred_type '{}' (valid: password, hash, key, token)", other))),
    };

    let id = match crate::cred_store::CRED_STORE.add(host, port, service, username, secret, cred_type, source).await {
        Some(id) => id,
        None => return Err(rpc_err("STORE_ERROR", "Credential add failed (store limit or validation)")),
    };
    Ok(json!({"id": id}))
}

async fn rpc_delete_cred(params: &Value) -> RpcResult {
    let id = require_str(params, "id")?;
    if crate::cred_store::CRED_STORE.delete(id).await {
        Ok(json!({"deleted": id}))
    } else {
        Err(rpc_err("NOT_FOUND", format!("Credential '{}' not found", id)))
    }
}

async fn rpc_search_creds(params: &Value) -> RpcResult {
    let query = require_str(params, "q")?;
    if query.len() > 256 {
        return Err(rpc_err("INVALID_INPUT", "Search query too long (max 256)"));
    }
    let results = crate::cred_store::CRED_STORE.search(query).await;
    let results_json = serde_json::to_value(&results).map_err(|e| rpc_err("SERIALIZE_ERROR", e.to_string()))?;
    Ok(json!({"results": results_json, "total": results.len()}))
}

async fn rpc_clear_creds() -> RpcResult {
    crate::cred_store::CRED_STORE.clear().await;
    Ok(json!({"cleared": true}))
}

// ── Hosts ────────────────────────────────────────────────────────────

async fn rpc_list_hosts(params: &Value) -> RpcResult {
    let all = crate::workspace::WORKSPACE.hosts().await;
    let filter_os = params.get("os").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    let filter_search = params.get("search").and_then(|v| v.as_str()).filter(|s| !s.is_empty());

    let filtered: Vec<_> = all.into_iter().filter(|h| {
        if let Some(os) = filter_os {
            match h.os_guess {
                Some(ref guess) if guess.to_lowercase().contains(&os.to_lowercase()) => {}
                _ => return false,
            }
        }
        if let Some(q) = filter_search {
            let q = q.to_lowercase();
            if !h.ip.to_lowercase().contains(&q)
                && !h.hostname.as_deref().unwrap_or("").to_lowercase().contains(&q) { return false; }
        }
        true
    }).collect();

    let total = filtered.len();
    let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(50).min(1000) as usize;
    let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let page: Vec<_> = filtered.into_iter().skip(offset).take(limit).collect();

    let hosts_json = serde_json::to_value(&page).map_err(|e| rpc_err("SERIALIZE_ERROR", e.to_string()))?;
    Ok(json!({"hosts": hosts_json, "total": total, "limit": limit, "offset": offset}))
}

async fn rpc_add_host(params: &Value) -> RpcResult {
    let ip = require_str(params, "ip")?;
    if ip.len() > 256 || ip.chars().any(|c| c.is_control()) {
        return Err(rpc_err("INVALID_INPUT", "Invalid IP format"));
    }
    if !ip.chars().all(|c| c.is_alphanumeric() || matches!(c, '.' | ':' | '-' | '[' | ']')) {
        return Err(rpc_err("INVALID_INPUT", "IP contains invalid characters"));
    }
    let hostname = params.get("hostname").and_then(|v| v.as_str());
    if hostname.is_some_and(|h| h.len() > 256 || h.chars().any(|c| c.is_control())) {
        return Err(rpc_err("INVALID_INPUT", "hostname too long or contains control chars"));
    }
    let os_guess = params.get("os_guess").and_then(|v| v.as_str());
    if os_guess.is_some_and(|o| o.len() > 256 || o.chars().any(|c| c.is_control())) {
        return Err(rpc_err("INVALID_INPUT", "os_guess too long or contains control chars"));
    }
    crate::workspace::WORKSPACE.add_host(ip, hostname, os_guess).await;
    Ok(json!({"added": ip}))
}

async fn rpc_delete_host(params: &Value) -> RpcResult {
    let ip = require_str(params, "ip")?;
    if crate::workspace::WORKSPACE.delete_host(ip).await {
        Ok(json!({"deleted": ip}))
    } else {
        Err(rpc_err("NOT_FOUND", format!("Host '{}' not found", ip)))
    }
}

async fn rpc_add_host_note(params: &Value) -> RpcResult {
    let ip = require_str(params, "ip")?;
    let note = require_str(params, "note")?;
    if note.len() > 4096 {
        return Err(rpc_err("INVALID_INPUT", "Note too long (max 4096)"));
    }
    if crate::workspace::WORKSPACE.add_note(ip, note).await {
        Ok(json!({"added": true}))
    } else {
        Err(rpc_err("NOT_FOUND", format!("Host '{}' not found or note limit reached", ip)))
    }
}

async fn rpc_clear_hosts() -> RpcResult {
    crate::workspace::WORKSPACE.clear_hosts().await;
    Ok(json!({"cleared": true}))
}

// ── Services ─────────────────────────────────────────────────────────

async fn rpc_list_services(params: &Value) -> RpcResult {
    let all = crate::workspace::WORKSPACE.services().await;
    let filter_host = params.get("host").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    let filter_port = params.get("port").and_then(|v| v.as_u64()).map(|p| p as u16);
    let filter_search = params.get("search").and_then(|v| v.as_str()).filter(|s| !s.is_empty());

    let filtered: Vec<_> = all.into_iter().filter(|s| {
        if filter_host.is_some_and(|h| !s.host.contains(h)) { return false; }
        if filter_port.is_some_and(|p| s.port != p) { return false; }
        if let Some(q) = filter_search {
            let q = q.to_lowercase();
            if !s.host.to_lowercase().contains(&q) && !s.service_name.to_lowercase().contains(&q) { return false; }
        }
        true
    }).collect();

    let total = filtered.len();
    let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(50).min(1000) as usize;
    let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let page: Vec<_> = filtered.into_iter().skip(offset).take(limit).collect();

    let services_json = serde_json::to_value(&page).map_err(|e| rpc_err("SERIALIZE_ERROR", e.to_string()))?;
    Ok(json!({"services": services_json, "total": total, "limit": limit, "offset": offset}))
}

async fn rpc_add_service(params: &Value) -> RpcResult {
    let host = require_str(params, "host")?;
    let port_raw = params.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
    if port_raw == 0 || port_raw > 65535 {
        return Err(rpc_err("INVALID_INPUT", "port must be 1-65535"));
    }
    let port = port_raw as u16;
    let service_name = require_str(params, "service_name")?;
    let protocol = params.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp");
    let version = params.get("version").and_then(|v| v.as_str());

    if host.len() > 256 || host.chars().any(|c| c.is_control()) {
        return Err(rpc_err("INVALID_INPUT", "host too long or contains control chars"));
    }
    if protocol.len() > 256 || protocol.chars().any(|c| c.is_control()) {
        return Err(rpc_err("INVALID_INPUT", "protocol too long or contains control chars"));
    }
    if service_name.len() > 256 || service_name.chars().any(|c| c.is_control()) {
        return Err(rpc_err("INVALID_INPUT", "service_name too long or contains control chars"));
    }
    if version.is_some_and(|v| v.len() > 256 || v.chars().any(|c| c.is_control())) {
        return Err(rpc_err("INVALID_INPUT", "version too long or contains control chars"));
    }

    crate::workspace::WORKSPACE.add_service(host, port, protocol, service_name, version).await;
    Ok(json!({"added": format!("{}:{}", host, port)}))
}

async fn rpc_delete_service(params: &Value) -> RpcResult {
    let host = require_str(params, "host")?;
    let port_raw = params.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
    if port_raw == 0 || port_raw > 65535 {
        return Err(rpc_err("INVALID_INPUT", "port must be 1-65535"));
    }
    let port = port_raw as u16;
    if crate::workspace::WORKSPACE.delete_service(host, port).await {
        Ok(json!({"deleted": format!("{}:{}", host, port)}))
    } else {
        Err(rpc_err("NOT_FOUND", format!("Service {}:{} not found", host, port)))
    }
}

// ── Loot ─────────────────────────────────────────────────────────────

async fn rpc_list_loot(params: &Value) -> RpcResult {
    let all = crate::loot::LOOT_STORE.list().await;
    let filter_host = params.get("host").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    let filter_type = params.get("loot_type").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    let filter_search = params.get("search").and_then(|v| v.as_str()).filter(|s| !s.is_empty());

    let filtered: Vec<_> = all.into_iter().filter(|l| {
        if filter_host.is_some_and(|h| !l.host.contains(h)) { return false; }
        if filter_type.is_some_and(|t| !l.loot_type.contains(t)) { return false; }
        if let Some(q) = filter_search {
            let q = q.to_lowercase();
            if !l.host.to_lowercase().contains(&q) && !l.description.to_lowercase().contains(&q) { return false; }
        }
        true
    }).collect();

    let total = filtered.len();
    let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(50).min(1000) as usize;
    let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let page: Vec<_> = filtered.into_iter().skip(offset).take(limit).collect();

    let loot_json = serde_json::to_value(&page).map_err(|e| rpc_err("SERIALIZE_ERROR", e.to_string()))?;
    Ok(json!({"loot": loot_json, "total": total, "limit": limit, "offset": offset}))
}

async fn rpc_add_loot(params: &Value) -> RpcResult {
    let host = require_str(params, "host")?;
    let loot_type = require_str(params, "loot_type")?;
    let data = require_str(params, "data")?;
    let description = params.get("description").and_then(|v| v.as_str()).unwrap_or("");
    let source = params.get("source_module").and_then(|v| v.as_str()).unwrap_or("ws");

    if host.len() > 256 || loot_type.len() > 256 {
        return Err(rpc_err("INVALID_INPUT", "host or loot_type too long (max 256)"));
    }
    if description.len() > 4096 {
        return Err(rpc_err("INVALID_INPUT", "description too long (max 4096)"));
    }
    const MAX_LOOT_DATA: usize = 100 * 1024 * 1024;
    if data.len() > MAX_LOOT_DATA {
        return Err(rpc_err("INVALID_INPUT", format!("Data too large ({} bytes, max {} MB)", data.len(), MAX_LOOT_DATA / 1024 / 1024)));
    }

    match crate::loot::LOOT_STORE.add_text(host, loot_type, description, data, source).await {
        Some(id) => Ok(json!({"id": id})),
        None => Err(rpc_err("STORE_ERROR", "Failed to store loot (limit or I/O error)")),
    }
}

async fn rpc_delete_loot(params: &Value) -> RpcResult {
    let id = require_str(params, "id")?;
    if crate::loot::LOOT_STORE.delete(id).await {
        Ok(json!({"deleted": id}))
    } else {
        Err(rpc_err("NOT_FOUND", format!("Loot '{}' not found", id)))
    }
}

async fn rpc_search_loot(params: &Value) -> RpcResult {
    let query = require_str(params, "q")?;
    if query.len() > 256 {
        return Err(rpc_err("INVALID_INPUT", "Search query too long (max 256)"));
    }
    let results = crate::loot::LOOT_STORE.search(query).await;
    let results_json = serde_json::to_value(&results).map_err(|e| rpc_err("SERIALIZE_ERROR", e.to_string()))?;
    Ok(json!({"results": results_json, "total": results.len()}))
}

async fn rpc_clear_loot() -> RpcResult {
    crate::loot::LOOT_STORE.clear().await;
    Ok(json!({"cleared": true}))
}

// ── Workspace ────────────────────────────────────────────────────────

async fn rpc_get_workspace() -> RpcResult {
    let name = crate::workspace::WORKSPACE.current_name().await;
    let hosts = crate::workspace::WORKSPACE.hosts().await;
    let services = crate::workspace::WORKSPACE.services().await;
    Ok(json!({
        "name": name,
        "host_count": hosts.len(),
        "service_count": services.len(),
    }))
}

async fn rpc_switch_workspace(params: &Value) -> RpcResult {
    let name = require_str(params, "name")?;
    if name.len() > 64 || name.chars().any(|c| !c.is_alphanumeric() && c != '_' && c != '-') {
        return Err(rpc_err("INVALID_INPUT", "Workspace name must be 1-64 alphanumeric chars, dashes, or underscores"));
    }
    crate::workspace::WORKSPACE.switch(name).await;
    Ok(json!({"workspace": name}))
}

async fn rpc_list_workspaces() -> RpcResult {
    let workspaces = crate::workspace::WORKSPACE.list_workspaces().await;
    Ok(json!({"workspaces": workspaces}))
}

// ── Jobs ─────────────────────────────────────────────────────────────

async fn rpc_list_jobs() -> RpcResult {
    let jobs = crate::jobs::JOB_MANAGER.list();
    let items: Vec<Value> = jobs.iter().map(|(id, module, target, started, status)| {
        json!({"id": id, "module": module, "target": target, "started": started, "status": status})
    }).collect();
    Ok(json!({
        "jobs": items,
        "total": items.len(),
        "running": crate::jobs::JOB_MANAGER.running_count(),
        "max_running": crate::jobs::JOB_MANAGER.get_max_running(),
    }))
}

async fn rpc_get_job(params: &Value) -> RpcResult {
    let id = params.get("id").and_then(|v| v.as_u64())
        .ok_or_else(|| rpc_err("INVALID_INPUT", "Missing required parameter: id"))? as u32;
    let from = params.get("from").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    match crate::jobs::JOB_MANAGER.get_detail(id) {
        Some((module, target, started, status, progress)) => {
            let output = progress.get_output(from);
            Ok(json!({
                "id": id,
                "module": module,
                "target": target,
                "started": started,
                "status": status,
                "output": output,
                "output_offset": from + output.len(),
                "success_count": progress.success_count.load(Ordering::Relaxed),
                "fail_count": progress.fail_count.load(Ordering::Relaxed),
                "total_targets": progress.total_targets.load(Ordering::Relaxed),
            }))
        }
        None => Err(rpc_err("NOT_FOUND", format!("Job {} not found", id))),
    }
}

async fn rpc_kill_job(params: &Value) -> RpcResult {
    let id = params.get("id").and_then(|v| v.as_u64())
        .ok_or_else(|| rpc_err("INVALID_INPUT", "Missing required parameter: id"))? as u32;
    if crate::jobs::JOB_MANAGER.kill(id) {
        Ok(json!({"killed": id}))
    } else {
        Err(rpc_err("NOT_FOUND", format!("Job {} not found", id)))
    }
}

async fn rpc_set_job_limit(params: &Value) -> RpcResult {
    let limit = params.get("limit").and_then(|v| v.as_u64())
        .ok_or_else(|| rpc_err("INVALID_INPUT", "Missing required parameter: limit"))? as u32;
    if limit == 0 || limit > 100 {
        return Err(rpc_err("INVALID_INPUT", "limit must be 1-100"));
    }
    crate::jobs::JOB_MANAGER.set_max_running(limit);
    Ok(json!({"max_running": limit}))
}

// ── Spool ────────────────────────────────────────────────────────────

async fn rpc_spool_status() -> RpcResult {
    let active = crate::spool::SPOOL.is_active();
    let filename = crate::spool::SPOOL.current_file();
    Ok(json!({"active": active, "filename": filename}))
}

async fn rpc_spool_start(params: &Value) -> RpcResult {
    let filename = require_str(params, "filename")?;
    if filename.len() > 255 {
        return Err(rpc_err("INVALID_INPUT", "Filename too long (max 255)"));
    }
    if !filename.is_ascii() {
        return Err(rpc_err("INVALID_INPUT", "Filename must be ASCII"));
    }
    if filename.contains('/') || filename.contains('\\') || filename.contains("..")
        || filename.contains('\0') || filename.starts_with('.')
    {
        return Err(rpc_err("INVALID_INPUT", "Filename contains invalid characters or path traversal"));
    }
    if !filename.chars().all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.')) {
        return Err(rpc_err("INVALID_INPUT", "Filename must be alphanumeric with _ - . only"));
    }
    match crate::spool::SPOOL.start(filename) {
        Ok(_) => Ok(json!({"started": filename})),
        Err(e) => Err(rpc_err("SPOOL_ERROR", e)),
    }
}

async fn rpc_spool_stop() -> RpcResult {
    match crate::spool::SPOOL.stop() {
        Some(name) => Ok(json!({"stopped": name})),
        None => Err(rpc_err("SPOOL_ERROR", "Spool is not active")),
    }
}

// ── Results ──────────────────────────────────────────────────────────

async fn rpc_list_results() -> RpcResult {
    let results_dir = crate::config::results_dir();
    if !results_dir.exists() {
        return Ok(json!({"files": [], "total": 0}));
    }
    let mut files = Vec::new();
    let entries = match std::fs::read_dir(&results_dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("Failed to read results directory: {}", e);
            return Ok(json!({"files": [], "total": 0}));
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!("Skipping unreadable entry: {}", e);
                continue;
            }
        };
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".txt") && crate::api::validate_result_filename(&name) {
            let meta = entry.metadata();
            files.push(json!({
                "filename": name,
                "size": meta.as_ref().map(|m| m.len()).unwrap_or(0),
            }));
        }
    }
    Ok(json!({"files": files, "total": files.len()}))
}

async fn rpc_get_result(params: &Value) -> RpcResult {
    let filename = require_str(params, "filename")?;
    if !crate::api::validate_result_filename(filename) {
        return Err(rpc_err("INVALID_INPUT", "Invalid result filename"));
    }
    let path = crate::config::results_dir().join(filename);
    if !path.exists() {
        return Err(rpc_err("NOT_FOUND", format!("Result file '{}' not found", filename)));
    }
    let meta = std::fs::symlink_metadata(&path)
        .map_err(|e| rpc_err("IO_ERROR", e.to_string()))?;
    if meta.file_type().is_symlink() {
        return Err(rpc_err("SECURITY", "Symlink result files are not allowed"));
    }
    let content = tokio::fs::read_to_string(&path).await
        .map_err(|e| rpc_err("IO_ERROR", e.to_string()))?;
    Ok(json!({"filename": filename, "content": content, "size": content.len()}))
}

// ── Export ────────────────────────────────────────────────────────────

async fn rpc_export(params: &Value) -> RpcResult {
    let format = params.get("format").and_then(|v| v.as_str()).unwrap_or("json");
    match format {
        "json" => {
            let data = crate::export::export_json_string().await
                .map_err(|e| rpc_err("EXPORT_ERROR", e.to_string()))?;
            Ok(json!({"format": "json", "data": data}))
        }
        "csv" => {
            let csv = crate::export::export_csv_string().await
                .map_err(|e| rpc_err("EXPORT_ERROR", e.to_string()))?;
            Ok(json!({"format": "csv", "data": csv}))
        }
        "summary" => {
            let summary = crate::export::export_summary_string().await
                .map_err(|e| rpc_err("EXPORT_ERROR", e.to_string()))?;
            Ok(json!({"format": "summary", "data": summary}))
        }
        _ => Err(rpc_err("INVALID_INPUT", "format must be json, csv, or summary")),
    }
}

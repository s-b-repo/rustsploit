//! Axum middleware for transparent PQ encryption/decryption on all API routes.
//!
//! - If `X-PQ-Session` header → decrypt request, encrypt response
//! - If absent → reject with 401 (PQ is mandatory)
//! - `POST /pq/handshake` → establish new PQ session

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{HeaderValue, Request, Response, StatusCode},
    middleware::Next,
};
use base64::Engine;
use tokio::sync::Mutex;

use crate::pq_channel::{
    decrypt_request, encrypt_response, process_handshake,
    ClientPublicIdentity, HandshakeRequest, HandshakeResponse, HostIdentity, SessionStore,
};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Shared PQ state — passed via Axum extension, not State extractor.
pub struct PqSharedState {
    pub sessions: SessionStore,
    pub host_identity: Arc<HostIdentity>,
    pub authorized_keys: Arc<Vec<ClientPublicIdentity>>,
    pub handshake_rate_limiter: HandshakeRateLimiter,
}

const MAX_PQ_SESSIONS: usize = 1000;
const HANDSHAKE_RATE_WINDOW_SECS: u64 = 60;
const HANDSHAKE_RATE_MAX_PER_IP: usize = 10;

pub type HandshakeRateLimiter = Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>;

pub fn new_handshake_rate_limiter() -> HandshakeRateLimiter {
    Arc::new(Mutex::new(HashMap::new()))
}

/// POST /pq/handshake — establish new PQ session
pub async fn handshake_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::Extension(pq): axum::Extension<Arc<PqSharedState>>,
    axum::Json(request): axum::Json<HandshakeRequest>,
) -> Result<axum::Json<HandshakeResponse>, (StatusCode, String)> {
    let client_ip = addr.ip();
    let now = Instant::now();
    let window = std::time::Duration::from_secs(HANDSHAKE_RATE_WINDOW_SECS);
    {
        let mut limiter = pq.handshake_rate_limiter.lock().await;
        let timestamps = limiter.entry(client_ip).or_default();
        timestamps.retain(|t| now.duration_since(*t) < window);
        if timestamps.len() >= HANDSHAKE_RATE_MAX_PER_IP {
            tracing::debug!("PQ handshake rate-limited for {}: {}/{} in window", client_ip, timestamps.len(), HANDSHAKE_RATE_MAX_PER_IP);
            return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string()));
        }
        timestamps.push(now);
    }

    let tenant_id = &request.client_name;

    let (response, session) = process_handshake(
        &request,
        &pq.host_identity,
        &pq.authorized_keys,
        tenant_id,
    )
    .map_err(|e| {
        tracing::warn!("PQ handshake failed for tenant {}: {}", tenant_id, e);
        (StatusCode::BAD_REQUEST, format!("Handshake failed: {e}"))
    })?;

    let mut store = pq.sessions.write().await;
    if store.len() >= MAX_PQ_SESSIONS {
        if let Some(oldest_id) = store.iter()
            .min_by_key(|(_, s)| s.last_activity)
            .map(|(id, _)| *id)
        {
            store.remove(&oldest_id);
        }
    }
    store.insert(session.session_id, session);

    Ok(axum::Json(response))
}

/// Middleware layer — wraps all /api/* routes. PQ is mandatory.
pub async fn pq_middleware(
    axum::Extension(pq): axum::Extension<Arc<PqSharedState>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    let pq_header = match request.headers().get("X-PQ-Session") {
        Some(h) => h.clone(),
        None => {
            tracing::debug!("PQ middleware rejected request missing X-PQ-Session header");
            // PQ is mandatory — reject unencrypted requests
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let session_id_b64 = pq_header.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
    let session_id_vec = B64.decode(session_id_b64).map_err(|_| StatusCode::BAD_REQUEST)?;
    let session_id: [u8; 16] = session_id_vec.try_into().map_err(|_| StatusCode::BAD_REQUEST)?;

    let nonce_b64 = request.headers().get("X-PQ-Nonce")
        .and_then(|v| v.to_str().ok()).ok_or(StatusCode::BAD_REQUEST)?.to_string();
    let nonce: [u8; 12] = B64.decode(&nonce_b64).map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into().map_err(|_| StatusCode::BAD_REQUEST)?;

    let epoch: u64 = request.headers().get("X-PQ-Epoch")
        .and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let rekey_pub: Option<[u8; 32]> = request.headers().get("X-PQ-Rekey")
        .and_then(|v| v.to_str().ok()).and_then(|v| B64.decode(v).ok())
        .and_then(|v| v.try_into().ok());

    let method = request.method().as_str().to_string();
    let path = request.uri().path().to_string();
    let aad = format!("{method}|{path}|{epoch}|{session_id_b64}");

    let (parts, body) = request.into_parts();
    let body_bytes = axum::body::to_bytes(body, 1024 * 1024)
        .await.map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;

    let plaintext = {
        let mut store = pq.sessions.write().await;
        let session = store.get_mut(&session_id).ok_or(StatusCode::UNAUTHORIZED)?;
        decrypt_request(session, &body_bytes, &nonce, aad.as_bytes(), rekey_pub.as_ref())
            .map_err(|_| StatusCode::BAD_REQUEST)?
    };

    let decrypted: serde_json::Value = serde_json::from_slice(&plaintext)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let inner_body = decrypted.get("body").map(|v| {
        if v.is_string() { v.as_str().unwrap_or("").to_string() } else { v.to_string() }
    }).unwrap_or_default();

    let mut new_req = Request::from_parts(parts, Body::from(inner_body));
    new_req.headers_mut().insert("Content-Type", HeaderValue::from_static("application/json"));
    for h in ["X-PQ-Session", "X-PQ-Nonce", "X-PQ-Epoch", "X-PQ-Rekey"] {
        new_req.headers_mut().remove(h);
    }

    let response = next.run(new_req).await;

    let (resp_parts, resp_body) = response.into_parts();
    let resp_bytes = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        axum::body::to_bytes(resp_body, 10 * 1024 * 1024),
    )
        .await
        .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let resp_aad = format!("{}|{epoch}|{session_id_b64}", resp_parts.status.as_u16());

    let (ct, resp_nonce, rekey) = {
        let mut store = pq.sessions.write().await;
        let session = store.get_mut(&session_id).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        encrypt_response(session, &resp_bytes, resp_aad.as_bytes())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };

    let mut resp = Response::new(Body::from(ct));
    *resp.status_mut() = resp_parts.status;
    resp.headers_mut().insert("Content-Type", HeaderValue::from_static("application/octet-stream"));
    resp.headers_mut().insert("X-PQ-Nonce",
        HeaderValue::from_str(&B64.encode(resp_nonce)).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
    resp.headers_mut().insert("X-PQ-Epoch",
        HeaderValue::from_str(&epoch.to_string()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);

    if let Some(pub_key) = rekey {
        resp.headers_mut().insert("X-PQ-Rekey",
            HeaderValue::from_str(&B64.encode(pub_key.as_bytes())).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
    }

    Ok(resp)
}

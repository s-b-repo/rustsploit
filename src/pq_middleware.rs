//! Axum middleware for transparent PQ encryption/decryption on all API routes.
//!
//! - If `X-PQ-Session` header → decrypt request, encrypt response
//! - If absent → reject with 401 (PQ is mandatory)
//! - `POST /pq/handshake` → establish new PQ session

use axum::{
    body::Body,
    http::{HeaderValue, Request, Response, StatusCode},
    middleware::Next,
};
use base64::Engine;
use std::sync::Arc;

use crate::pq_channel::{
    decrypt_request, encrypt_response, process_handshake,
    HandshakeRequest, HandshakeResponse, HostIdentity, ClientPublicIdentity, SessionStore,
};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Shared PQ state — passed via Axum extension, not State extractor.
pub struct PqSharedState {
    pub sessions: SessionStore,
    pub host_identity: Arc<HostIdentity>,
    pub authorized_keys: Arc<Vec<ClientPublicIdentity>>,
}

/// POST /pq/handshake — establish new PQ session
pub async fn handshake_handler(
    axum::Extension(pq): axum::Extension<Arc<PqSharedState>>,
    axum::Json(request): axum::Json<HandshakeRequest>,
) -> Result<axum::Json<HandshakeResponse>, (StatusCode, String)> {
    let tenant_id = &request.client_name;

    let (response, session) = process_handshake(
        &request,
        &pq.host_identity,
        &pq.authorized_keys,
        tenant_id,
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("Handshake failed: {e}")))?;

    let mut store = pq.sessions.write().await;
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
    let resp_bytes = axum::body::to_bytes(resp_body, 10 * 1024 * 1024)
        .await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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

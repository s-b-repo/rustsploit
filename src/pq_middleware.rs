//! Axum middleware for transparent PQ encryption/decryption on all API routes.
//!
//! - If `X-PQ-Session` header → decrypt request, encrypt response
//! - If absent → reject with 401 (PQ is mandatory)
//! - `POST /pq/handshake` → establish new PQ session

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{HeaderValue, Request, Response, StatusCode},
    middleware::Next,
};
use base64::Engine;
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, RwLock};

use crate::pq_channel::{
    decrypt_request, encrypt_response, process_handshake, remove_authorized_key,
    upsert_authorized_key, ClientPublicIdentity, HandshakeRequest, HandshakeResponse,
    HostIdentity, PqSession, SessionStore,
};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Shared PQ state — passed via Axum extension, not State extractor.
pub struct PqSharedState {
    pub sessions: SessionStore,
    pub host_identity: Arc<HostIdentity>,
    /// Mutable so `/pq/register-key` can append a new client at runtime
    /// without restarting the server.
    pub authorized_keys: RwLock<Vec<ClientPublicIdentity>>,
    pub authorized_keys_path: PathBuf,
    pub handshake_rate_limiter: HandshakeRateLimiter,
    /// One-time enrollment token printed at startup. Set to `Some(_)` until
    /// the first successful `/pq/register-key` consumes it; `None` thereafter
    /// (further key changes must use the established PQ session). Compared
    /// in constant time. `None` makes the endpoint return 403.
    pub enrollment_token: Mutex<Option<String>>,
}

const MAX_PQ_SESSIONS: usize = 1000;
const HANDSHAKE_RATE_WINDOW_SECS: u64 = 60;
const HANDSHAKE_RATE_MAX_PER_IP: usize = 10;

/// Identity proven by AEAD on the current request. Injected as a request
/// extension by `pq_middleware`; handlers should prefer this over any
/// header- or body-supplied identity claim.
#[derive(Clone, Debug)]
pub struct AuthenticatedIdentity {
    pub client_name: String,
}

pub type HandshakeRateLimiter = Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>;

pub fn new_handshake_rate_limiter() -> HandshakeRateLimiter {
    Arc::new(Mutex::new(HashMap::new()))
}

/// POST /pq/handshake — establish new PQ session
pub async fn handshake_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::Extension(pq): axum::Extension<Arc<PqSharedState>>,
    axum::Json(request): axum::Json<HandshakeRequest>,
) -> Result<axum::Json<HandshakeResponse>, (StatusCode, String)> {
    // P1-9: when the operator launched with --trust-proxy, prefer the
    // leftmost X-Forwarded-For value over the TCP peer. Without the flag we
    // ignore the header so a malicious client can't lie its way past the
    // rate limit.
    let client_ip = if crate::utils::network::get_global_trust_proxy() {
        let xff = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim())
            .and_then(|s| s.parse::<std::net::IpAddr>().ok());
        xff.unwrap_or_else(|| addr.ip())
    } else {
        addr.ip()
    };
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
        // Evict stale entries (IPs with no recent timestamps) to prevent unbounded growth
        let before = limiter.len();
        limiter.retain(|ip, ts| {
            let keep = !ts.is_empty();
            if !keep {
                tracing::trace!("Evicting stale rate-limit entry for {}", ip);
            }
            keep
        });
        let evicted = before.saturating_sub(limiter.len());
        if evicted > 0 {
            tracing::debug!("Rate limiter: evicted {} stale IP entries, {} remaining", evicted, limiter.len());
        }
    }

    let tenant_id = &request.client_name;

    let (response, session) = {
        let keys = pq.authorized_keys.read().await;
        process_handshake(
            &request,
            &pq.host_identity,
            keys.as_slice(),
            tenant_id,
        )
        .map_err(|e| {
            tracing::warn!("PQ handshake failed for tenant {}: {}", tenant_id, e);
            crate::events::emit(crate::events::ModuleEvent::PqHandshakeRejected {
                reason: format!("{e}"),
                peer: client_ip.to_string(),
            });
            (StatusCode::BAD_REQUEST, format!("Handshake failed: {e}"))
        })?
    };

    let new_session_client_name = session.client_name.clone();

    let mut store = pq.sessions.write().await;
    if store.len() >= MAX_PQ_SESSIONS {
        // Eviction: pick the session with the oldest last_activity. This
        // requires briefly locking each session to read the field; holding
        // the write lock on the map while we acquire per-session locks is
        // safe because no other code path holds a session lock while
        // waiting for the map.
        let mut oldest: Option<([u8; 16], std::time::Instant, String)> = None;
        for (id, sess_arc) in store.iter() {
            if let Ok(sess) = sess_arc.try_lock() {
                let la = sess.last_activity;
                if oldest.as_ref().map(|(_, ts, _)| la < *ts).unwrap_or(true) {
                    oldest = Some((*id, la, sess.client_name.clone()));
                }
            }
        }
        // Fallback: if every session was locked at this instant, pick an
        // arbitrary key to evict so the cap is still honoured. Otherwise
        // a burst of concurrent registrations could grow the store
        // unboundedly while their per-session mutexes were busy.
        let evict_pair = oldest
            .map(|(id, _, name)| (id, Some(name)))
            .or_else(|| store.keys().next().copied().map(|id| (id, None)));
        if let Some((id, evicted_name)) = evict_pair {
            store.remove(&id);
            crate::events::emit(crate::events::ModuleEvent::PqSessionEvicted {
                client_name: evicted_name.unwrap_or_else(|| "<unknown>".to_string()),
            });
        }
    }
    store.insert(session.session_id, Arc::new(tokio::sync::Mutex::new(session)));
    drop(store);

    crate::events::emit(crate::events::ModuleEvent::PqHandshakeAccepted {
        client_name: new_session_client_name,
    });

    Ok(axum::Json(response))
}

#[derive(serde::Deserialize)]
pub struct RegisterKeyRequest {
    /// One-time enrollment token, printed at server startup.
    pub token: String,
    /// Logical client name (commonly the tenant id).
    pub name: String,
    /// Base64-encoded X25519 long-lived public key (32 raw bytes).
    pub x25519_pub: String,
    /// Base64-encoded ML-KEM-768 encapsulation key (1184 raw bytes).
    pub mlkem_ek: String,
}

#[derive(serde::Serialize)]
pub struct RegisterKeyResponse {
    pub registered: bool,
    pub fingerprint: String,
}

/// `POST /pq/register-key` — bootstrap a remote panel without filesystem
/// access on the server. Authenticated by a one-time enrollment token
/// printed at startup.
pub async fn register_key_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::Extension(pq): axum::Extension<Arc<PqSharedState>>,
    axum::Json(request): axum::Json<RegisterKeyRequest>,
) -> Result<axum::Json<RegisterKeyResponse>, (StatusCode, String)> {
    // Validate the input shape FIRST so we can fail fast without taking the
    // token lock. Costs nothing to do this before authentication.
    if request.name.is_empty() || request.name.len() > 64
        || !request.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err((StatusCode::BAD_REQUEST, "name must be 1-64 [a-zA-Z0-9_-]".into()));
    }
    let x25519_bytes = B64.decode(&request.x25519_pub)
        .map_err(|e| { tracing::debug!("x25519_pub is not base64: {e:?}"); (StatusCode::BAD_REQUEST, "x25519_pub is not base64".into()) })?;
    let x25519_pub: [u8; 32] = x25519_bytes.try_into()
        .map_err(|e: Vec<u8>| { tracing::debug!("x25519_pub must decode to 32 bytes (got {} bytes)", e.len()); (StatusCode::BAD_REQUEST, "x25519_pub must decode to 32 bytes".into()) })?;
    let mlkem_ek = B64.decode(&request.mlkem_ek)
        .map_err(|e| { tracing::debug!("mlkem_ek is not base64: {e:?}"); (StatusCode::BAD_REQUEST, "mlkem_ek is not base64".into()) })?;
    // ML-KEM-768 encapsulation key is exactly 1184 bytes.
    if mlkem_ek.len() != 1184 {
        return Err((StatusCode::BAD_REQUEST, format!("mlkem_ek must be 1184 bytes, got {}", mlkem_ek.len())));
    }

    // Token check + atomic consume. Holding the lock across the persist
    // step is intentional — it prevents two concurrent callers with the
    // same token both succeeding.
    let mut tok_slot = pq.enrollment_token.lock().await;
    let expected = match tok_slot.as_deref() {
        Some(t) => t,
        None => {
            // Token already consumed; the panel must use its established PQ
            // session for any further key rotation.
            return Err((
                StatusCode::FORBIDDEN,
                "Enrollment token already used; rotate via the PQ session instead".into(),
            ));
        }
    };
    // P1-13: equalize the comparison cost regardless of supplied length so
    // the response time can't be used to learn the expected token length.
    // Pad both sides to the longer of the two and run `ct_eq` over the full
    // padded buffer; the mismatched-length case ends up false but in
    // constant time relative to the supplied input.
    let supplied = request.token.as_bytes();
    let expected_b = expected.as_bytes();
    let max_len = supplied.len().max(expected_b.len());
    let mut padded_supplied = vec![0u8; max_len];
    let mut padded_expected = vec![0u8; max_len];
    padded_supplied[..supplied.len()].copy_from_slice(supplied);
    padded_expected[..expected_b.len()].copy_from_slice(expected_b);
    let bytes_match = padded_supplied.ct_eq(&padded_expected).unwrap_u8() == 1;
    let token_ok = bytes_match && supplied.len() == expected_b.len();
    if !token_ok {
        // Reuse the handshake rate limiter so brute-forcers eat the same
        // per-IP budget that hammering /pq/handshake would.
        let mut limiter = pq.handshake_rate_limiter.lock().await;
        let timestamps = limiter.entry(addr.ip()).or_default();
        let now = Instant::now();
        timestamps.retain(|t| now.duration_since(*t) < std::time::Duration::from_secs(HANDSHAKE_RATE_WINDOW_SECS));
        timestamps.push(now);
        tracing::warn!("Rejected /pq/register-key from {} (bad token)", addr);
        return Err((StatusCode::UNAUTHORIZED, "Invalid enrollment token".into()));
    }

    let new_key = ClientPublicIdentity {
        name: request.name.clone(),
        x25519_public: x25519_pub,
        mlkem_ek,
    };
    let fp = crate::pq_channel::fingerprint(&new_key.x25519_public, &new_key.mlkem_ek);

    // Persist to disk first so a restart doesn't lose the registration. If
    // persist fails, do NOT consume the token — the operator can retry.
    if let Err(e) = upsert_authorized_key(&pq.authorized_keys_path, &new_key) {
        tracing::error!("Failed to persist authorized key for {}: {}", new_key.name, e);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("persist failed: {e}")));
    }

    let mut keys = pq.authorized_keys.write().await;
    keys.retain(|k| k.name != new_key.name);
    keys.push(new_key.clone());
    drop(keys);

    // Consume the token: subsequent registrations must use the PQ-session
    // path. Zeroize the in-memory copy on the way out.
    use zeroize::Zeroize;
    if let Some(mut t) = tok_slot.take() {
        t.zeroize();
    }

    tracing::info!("Registered PQ client '{}' ({}) from {}; enrollment token consumed", new_key.name, fp, addr);
    Ok(axum::Json(RegisterKeyResponse { registered: true, fingerprint: fp }))
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

    let session_id_b64 = pq_header.to_str().map_err(|e| { tracing::debug!("X-PQ-Session header not valid UTF-8: {e:?}"); StatusCode::BAD_REQUEST })?;
    let session_id_vec = B64.decode(session_id_b64).map_err(|e| { tracing::debug!("X-PQ-Session not valid base64: {e:?}"); StatusCode::BAD_REQUEST })?;
    let session_id: [u8; 16] = session_id_vec.try_into().map_err(|e: Vec<u8>| { tracing::debug!("session ID wrong length: got {} bytes", e.len()); StatusCode::BAD_REQUEST })?;

    let nonce_b64 = request.headers().get("X-PQ-Nonce")
        .and_then(|v| v.to_str().ok()).ok_or(StatusCode::BAD_REQUEST)?.to_string();
    let nonce: [u8; 12] = B64.decode(&nonce_b64).map_err(|e| { tracing::debug!("X-PQ-Nonce not valid base64: {e:?}"); StatusCode::BAD_REQUEST })?
        .try_into().map_err(|e: Vec<u8>| { tracing::debug!("X-PQ-Nonce wrong length: got {} bytes", e.len()); StatusCode::BAD_REQUEST })?;

    // X-PQ-Epoch is informational on the request side (the AAD is built
    // from the post-ratchet session epoch on both sides; AEAD verification
    // covers the rest). We still parse it for trace logging.
    let header_epoch: Option<u64> = request.headers().get("X-PQ-Epoch")
        .and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());

    let rekey_pub: Option<[u8; 32]> = request.headers().get("X-PQ-Rekey")
        .and_then(|v| v.to_str().ok()).and_then(|v| B64.decode(v).ok())
        .and_then(|v| v.try_into().ok());

    // The wire HTTP method is always POST (Node forbids GET-with-body), so the
    // *semantic* method the client used to compute its AAD comes from the
    // X-PQ-Method header. Falling back to the wire method keeps us compatible
    // with non-Node clients that send GET/PUT/DELETE directly.
    let semantic_method = request
        .headers()
        .get("X-PQ-Method")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_uppercase())
        .unwrap_or_else(|| request.method().as_str().to_string());
    // The client's AAD path includes the query string (it builds AAD from the
    // exact path it passes to fetch). Use path_and_query for parity.
    let path_aad = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    let (mut parts, body) = request.into_parts();
    // Symmetric with the response side at line ~341: a slow/malicious peer
    // can otherwise hold this read open indefinitely.
    let body_bytes = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        axum::body::to_bytes(body, 1024 * 1024),
    )
        .await
        .map_err(|e| { tracing::debug!("PQ request body read timed out: {e:?}"); StatusCode::REQUEST_TIMEOUT })?
        .map_err(|e| { tracing::debug!("PQ request body too large: {e:?}"); StatusCode::PAYLOAD_TOO_LARGE })?;

    // Look up the per-session mutex via a SHORT read lock on the map. Hold
    // an Arc clone so the session survives concurrent registrations. The
    // actual crypto state is then locked separately, so concurrent requests
    // for **different** tenants don't serialize through one map lock.
    let session_arc = {
        let store = pq.sessions.read().await;
        store
            .get(&session_id)
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)?
    };

    let (plaintext, authenticated_identity) = {
        let mut session = session_arc.lock().await;
        // AAD is built INSIDE decrypt_request using the post-ratchet epoch
        // so that, when this very message carries a rekey_pub, the AAD lines
        // up with what the sender computed (also post-ratchet).
        let session_id_b64_for_aad = session_id_b64.to_string();
        let path_aad_for_aad = path_aad.clone();
        let semantic_method_for_aad = semantic_method.clone();
        let pt = decrypt_request(
            &mut session,
            &body_bytes,
            &nonce,
            move |epoch| {
                format!("{semantic_method_for_aad}|{path_aad_for_aad}|{epoch}|{session_id_b64_for_aad}")
                    .into_bytes()
            },
            rekey_pub.as_ref(),
        )
        .map_err(|e| {
            tracing::debug!(?header_epoch, "PQ decrypt failed: {}", e);
            StatusCode::BAD_REQUEST
        })?;
        // The session's `client_name` was bound at handshake time from the
        // matching authorized_keys entry; surfacing it here lets handlers
        // ACL on the identity proven by AEAD rather than trusting any
        // client-supplied header or path component.
        let identity = AuthenticatedIdentity { client_name: session.client_name.clone() };
        (pt, identity)
        // session lock released here, BEFORE next.run — so the application
        // handler is free to call back into the middleware (or other
        // requests on the same session can proceed if the user issues
        // them concurrently).
    };

    let decrypted: serde_json::Value = serde_json::from_slice(&plaintext)
        .map_err(|e| { tracing::debug!("PQ decrypted body is not valid JSON: {e:?}"); StatusCode::BAD_REQUEST })?;

    let inner_body = decrypted.get("body").map(|v| {
        if v.is_string() { v.as_str().unwrap_or("").to_string() } else { v.to_string() }
    }).unwrap_or_default();

    // Restore the original semantic HTTP method so the inner router matches
    // GET/PUT/DELETE handlers — the wire request was always POST so without
    // this restore, only POST routes would dispatch.
    if let Ok(restored) = semantic_method.parse::<axum::http::Method>() {
        parts.method = restored;
    }

    let mut new_req = Request::from_parts(parts, Body::from(inner_body));
    new_req.headers_mut().insert("Content-Type", HeaderValue::from_static("application/json"));
    for h in ["X-PQ-Session", "X-PQ-Nonce", "X-PQ-Epoch", "X-PQ-Rekey", "X-PQ-Method"] {
        new_req.headers_mut().remove(h);
    }
    // Inject the AEAD-authenticated identity so handlers can `Extension(id)`
    // it. This is the only trustworthy way to know who the request is from.
    new_req.extensions_mut().insert(authenticated_identity);

    let response = next.run(new_req).await;

    let (resp_parts, resp_body) = response.into_parts();
    let resp_bytes = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        axum::body::to_bytes(resp_body, 10 * 1024 * 1024),
    )
        .await
        .map_err(|e| { tracing::debug!("PQ response body read timed out: {e:?}"); StatusCode::GATEWAY_TIMEOUT })?
        .map_err(|e| { tracing::debug!("PQ response body read failed: {e:?}"); StatusCode::INTERNAL_SERVER_ERROR })?;

    let session_id_b64_for_aad = session_id_b64.to_string();
    let status_code = resp_parts.status.as_u16();

    let (ct, resp_nonce, rekey, effective_epoch) = {
        // Re-lock the same per-session mutex (the map may have evicted us
        // in the meantime, in which case we error cleanly). No write lock
        // on the global map for this path.
        let mut session = session_arc.lock().await;
        encrypt_response(&mut session, &resp_bytes, move |ep| {
            format!("{status_code}|{ep}|{session_id_b64_for_aad}").into_bytes()
        })
            .map_err(|e| { tracing::debug!("PQ response encryption failed: {e:?}"); StatusCode::INTERNAL_SERVER_ERROR })?
    };

    let mut resp = Response::new(Body::from(ct));
    *resp.status_mut() = resp_parts.status;
    resp.headers_mut().insert("Content-Type", HeaderValue::from_static("application/octet-stream"));
    resp.headers_mut().insert("X-PQ-Nonce",
        HeaderValue::from_str(&B64.encode(resp_nonce)).map_err(|e| { tracing::debug!("X-PQ-Nonce header value invalid: {e:?}"); StatusCode::INTERNAL_SERVER_ERROR })?);
    // Surface the post-encryption (post-ratchet, if rekey fired) epoch so the
    // client can sanity-check against its session state.
    resp.headers_mut().insert("X-PQ-Epoch",
        HeaderValue::from_str(&effective_epoch.to_string()).map_err(|e| { tracing::debug!("X-PQ-Epoch header value invalid: {e:?}"); StatusCode::INTERNAL_SERVER_ERROR })?);

    if let Some(pub_key) = rekey {
        resp.headers_mut().insert("X-PQ-Rekey",
            HeaderValue::from_str(&B64.encode(pub_key.as_bytes())).map_err(|e| { tracing::debug!("X-PQ-Rekey header value invalid: {e:?}"); StatusCode::INTERNAL_SERVER_ERROR })?);
    }

    Ok(resp)
}

#[derive(serde::Deserialize)]
pub struct RevokeKeyRequest {
    /// Logical client name to revoke. Must match an existing entry in
    /// `authorized_keys`.
    pub name: String,
}

#[derive(serde::Serialize)]
pub struct RevokeKeyResponse {
    pub revoked: bool,
    /// `true` if any active PQ sessions were torn down as part of the
    /// revocation. The caller can use this to detect whether the revoked
    /// identity was actively connected.
    pub sessions_terminated: usize,
}

/// `POST /api/pq/revoke-key` — revoke an authorized key. Lives behind the
/// PQ middleware so the request is AEAD-authenticated; only an existing
/// authorized client can revoke. Refuses to let a client revoke its own
/// only key (would brick the deployment with no recovery short of restart
/// + re-enrollment-token).
pub async fn revoke_key_handler(
    axum::Extension(pq): axum::Extension<Arc<PqSharedState>>,
    axum::Extension(caller): axum::Extension<AuthenticatedIdentity>,
    axum::Json(request): axum::Json<RevokeKeyRequest>,
) -> Result<axum::Json<RevokeKeyResponse>, (StatusCode, String)> {
    let target = request.name.trim();
    if target.is_empty() || target.len() > 64
        || !target.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err((StatusCode::BAD_REQUEST, "name must be 1-64 [a-zA-Z0-9_-]".into()));
    }

    // Don't let a caller revoke a key while it's the only one left — that
    // would lock everyone out (the enrollment token is one-shot).
    {
        let keys = pq.authorized_keys.read().await;
        if keys.len() <= 1 && keys.iter().any(|k| k.name == target) {
            return Err((
                StatusCode::CONFLICT,
                "Refusing to revoke the last remaining authorized key".into(),
            ));
        }
    }

    // Persist to disk first; if that fails, refuse to mutate in-memory state
    // (otherwise a restart would resurrect the revoked key).
    let removed = match remove_authorized_key(&pq.authorized_keys_path, target) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to persist key revocation for {}: {}", target, e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("persist failed: {e}"),
            ));
        }
    };

    if !removed {
        return Err((
            StatusCode::NOT_FOUND,
            format!("No authorized key named '{}'", target),
        ));
    }

    // Drop from in-memory list so future handshakes from this identity are
    // rejected immediately.
    {
        let mut keys = pq.authorized_keys.write().await;
        keys.retain(|k| k.name != target);
    }

    // Tear down any live sessions belonging to the revoked identity. Without
    // this, an in-flight session would keep working until idle-eviction or
    // restart — the whole point of revocation is that it takes effect now.
    //
    // We hold the map write lock and `lock().await` per session so a session
    // that is currently mid-decrypt cannot slip through revocation. The lock
    // order matches the rest of the codebase (map first, then per-session)
    // because no other path holds a per-session mutex while reaching for the
    // map. Worst case the revoke briefly serialises behind one in-flight
    // request — that's the correct trade-off for "revocation takes effect now".
    let mut terminated = 0usize;
    {
        let mut store = pq.sessions.write().await;
        let mut to_remove: Vec<[u8; 16]> = Vec::new();
        // Snapshot the (id, Arc) pairs first so we don't iterate `store` while
        // also awaiting per-session locks (the borrow checker forbids that).
        let candidates: Vec<([u8; 16], std::sync::Arc<tokio::sync::Mutex<PqSession>>)> =
            store.iter().map(|(id, arc)| (*id, arc.clone())).collect();
        for (id, sess_arc) in candidates {
            let s = sess_arc.lock().await;
            if s.client_name == target {
                to_remove.push(id);
            }
        }
        for id in &to_remove {
            store.remove(id);
            terminated += 1;
        }
    }

    tracing::info!(
        "PQ key revoked: name='{}' by caller='{}' (sessions terminated: {})",
        target,
        caller.client_name,
        terminated,
    );

    crate::events::emit(crate::events::ModuleEvent::PqIdentityRevoked {
        name: target.to_string(),
        by: caller.client_name.clone(),
        sessions_terminated: terminated,
    });

    Ok(axum::Json(RevokeKeyResponse {
        revoked: true,
        sessions_terminated: terminated,
    }))
}

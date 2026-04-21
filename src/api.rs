use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    response::Json,
    routing::{get, post},
    Router,
};
use colored::*;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

// ─── Validation Helpers ─────────────────────────────────────────────

pub(crate) fn validate_module_name(module: &str) -> bool {
    !module.is_empty()
        && module.len() <= 256
        && module.chars().all(|c| matches!(c, 'a'..='z' | '0'..='9' | '/' | '_' | '-'))
}

pub(crate) fn validate_target(target: &str) -> bool {
    !target.is_empty() && target.len() <= 2048 && !target.chars().any(|c| c.is_control())
}

pub(crate) fn is_blocked_target(target: &str) -> bool {
    const MASS_SCAN_KEYWORDS: &[&str] = &["random", "0.0.0.0", "0.0.0.0/0"];
    if MASS_SCAN_KEYWORDS.contains(&target) {
        return false;
    }

    let lower = target.to_lowercase();

    // Try proper URL parsing first — handles @, port, scheme correctly
    let host_no_port = if let Ok(parsed) = url::Url::parse(&lower) {
        // Percent-decode the host and check it
        parsed.host_str().map(|h| {
            percent_decode_host(h)
        })
    } else {
        None
    };

    // If URL parsing succeeded, check the extracted host
    if let Some(ref host) = host_no_port {
        if check_blocked_hostname(host) {
            return true;
        }
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return is_blocked_ip(ip);
        }
    }

    // Fallback: manual extraction for bare hostnames/IPs (no scheme)
    let host_part = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
        .or_else(|| lower.strip_prefix("ftp://"))
        .or_else(|| lower.strip_prefix("gopher://"))
        .unwrap_or(&lower);
    // Strip userinfo (everything before @)
    let host_part = if let Some(at_pos) = host_part.find('@') {
        &host_part[at_pos + 1..]
    } else {
        host_part
    };
    let host_part = host_part.split('/').next().unwrap_or(host_part);
    let host_part = host_part.split('?').next().unwrap_or(host_part);
    let host_part = host_part.split('#').next().unwrap_or(host_part);

    // Strip port from host
    let bare_host: &str = if host_part.starts_with('[') {
        host_part
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(host_part)
    } else if host_part.matches(':').count() == 1 {
        host_part.split(':').next().unwrap_or(host_part)
    } else {
        host_part
    };

    let decoded = percent_decode_host(bare_host);

    if check_blocked_hostname(&decoded) {
        return true;
    }
    if let Ok(ip) = decoded.parse::<std::net::IpAddr>() {
        return is_blocked_ip(ip);
    }
    if let Ok(ip) = bare_host.parse::<std::net::IpAddr>() {
        return is_blocked_ip(ip);
    }

    // Block file:// scheme entirely
    if lower.starts_with("file://") {
        return true;
    }

    false
}

fn percent_decode_host(host: &str) -> String {
    let mut result = String::with_capacity(host.len());
    let bytes = host.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                hex_val(bytes[i + 1]),
                hex_val(bytes[i + 2]),
            ) {
                result.push((hi << 4 | lo) as char);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn check_blocked_hostname(host: &str) -> bool {
    const BLOCKED_HOST_SUFFIXES: &[&str] = &[
        "metadata.google.internal",
        "metadata.goog",
        "metadata.internal",
        "metadata.azure.com",
        "metadata.oraclecloud.com",
    ];
    const BLOCKED_HOST_EXACT: &[&str] = &[
        "metadata",
        "instance-data",
    ];
    const BLOCKED_WILDCARD_SUFFIXES: &[&str] = &[
        ".sslip.io",
        ".nip.io",
        ".xip.io",
        ".traefik.me",
        ".local.gd",
    ];

    for suffix in BLOCKED_HOST_SUFFIXES {
        if host == *suffix || host.ends_with(&format!(".{}", suffix)) {
            return true;
        }
    }
    for exact in BLOCKED_HOST_EXACT {
        if host == *exact {
            return true;
        }
    }
    for wildcard in BLOCKED_WILDCARD_SUFFIXES {
        if host.ends_with(wildcard) {
            return true;
        }
    }
    false
}

fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() { return true; }
            let segs = v6.segments();
            if segs[0] == 0xfd00 && segs[1] == 0x0ec2 { return true; }
            if segs[0] & 0xfe00 == 0xfc00 { return true; }
            if segs[0] & 0xffc0 == 0xfe80 { return true; }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ipv4(v4);
            }
            false
        }
        std::net::IpAddr::V4(v4) => is_blocked_ipv4(v4),
    }
}

fn is_blocked_ipv4(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o == [0, 0, 0, 0]
        || o[0] == 127
        || o[0] == 10
        || (o[0] == 172 && (o[1] & 0xf0) == 16)
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 169 && o[1] == 254)
        || o == [168, 63, 129, 16]
        || o == [100, 100, 100, 200]
}

pub(crate) async fn is_blocked_target_resolved(target: &str) -> bool {
    const MASS_SCAN_KEYWORDS: &[&str] = &["random", "0.0.0.0", "0.0.0.0/0"];
    if MASS_SCAN_KEYWORDS.contains(&target) {
        return false;
    }

    if is_blocked_target(target) {
        return true;
    }
    let lower = target.to_lowercase();
    let host_part = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
        .unwrap_or(&lower);
    let host_part = host_part.split('/').next().unwrap_or(host_part);
    let lookup_addr = if host_part.contains(':') {
        host_part.to_string()
    } else {
        format!("{}:80", host_part)
    };
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host(&lookup_addr),
    ).await {
        Ok(Ok(addrs)) => {
            for addr in addrs {
                if is_blocked_ip(addr.ip()) {
                    return true;
                }
            }
            false
        }
        Ok(Err(_)) | Err(_) => true,
    }
}

pub(crate) fn contains_shell_metacharacters(input: &str) -> bool {
    input.chars().any(|c| matches!(c, '&' | '|' | ';' | '`' | '$' | '>' | '<' | '\n' | '\r' | '(' | ')' | '{' | '}'))
        || input.contains("$(")
        || input.contains("${")
}

pub(crate) fn validate_result_filename(name: &str) -> bool {
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

// ─── Health Endpoint ────────────────────────────────────────────────

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
    }))
}

// ─── Server Entry Point ─────────────────────────────────────────────

pub async fn start_api_server(
    bind_address: &str,
    _verbose: bool,
    host_key_path: &std::path::Path,
    authorized_keys_path: &std::path::Path,
) -> Result<()> {
    let host_identity = crate::pq_channel::HostIdentity::load_or_generate(host_key_path)
        .context("Failed to load/generate PQ host key")?;

    let authorized_keys = crate::pq_channel::load_authorized_keys(authorized_keys_path)
        .context("Failed to load authorized keys")?;

    let pq_sessions = crate::pq_channel::new_session_store();

    let n_plugins = crate::commands::plugin_count();
    if n_plugins > 0 {
        eprintln!("{}", "[!] WARNING: Third-party plugins loaded. RustSploit is NOT responsible for third-party plugin behavior.".red().bold());
        eprintln!("[!] Loaded plugins: {}", n_plugins);
    }

    println!("Starting RustSploit WS server (PQ-encrypted)...");
    println!("Binding to: {}", bind_address);
    println!("Host key fingerprint: {}", host_identity.fingerprint());
    println!("Authorized clients: {}", authorized_keys.len());
    for key in &authorized_keys {
        println!("  {} ({})",
            key.name,
            crate::pq_channel::fingerprint(&key.x25519_public, &key.mlkem_ek));
    }

    let pq_state = Arc::new(crate::pq_middleware::PqSharedState {
        sessions: pq_sessions,
        host_identity: Arc::new(host_identity),
        authorized_keys: Arc::new(authorized_keys),
        handshake_rate_limiter: crate::pq_middleware::new_handshake_rate_limiter(),
    });

    let cleanup_sessions = pq_state.sessions.clone();
    let cleanup_rate_limiter = pq_state.handshake_rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            let mut store = cleanup_sessions.write().await;
            let before = store.len();
            store.retain(|_, s| s.last_activity.elapsed() < std::time::Duration::from_secs(3600));
            let removed = before - store.len();
            if removed > 0 {
                tracing::info!("PQ session cleanup: removed {} idle sessions ({} remaining)", removed, store.len());
            }
            drop(store);

            let mut limiter = cleanup_rate_limiter.lock().await;
            limiter.retain(|_, timestamps| {
                timestamps.retain(|t| t.elapsed() < std::time::Duration::from_secs(120));
                !timestamps.is_empty()
            });
        }
    });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/pq/handshake", post(crate::pq_middleware::handshake_handler))
        .route("/pq/ws", get(crate::ws::ws_upgrade))
        .layer(axum::Extension(pq_state))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http()),
        );

    println!("Server running on http://{}", bind_address);
    println!("Transport: Post-Quantum encryption (ML-KEM-768 + X25519 + ChaCha20-Poly1305)");
    println!("Endpoints: GET /health, POST /pq/handshake, GET /pq/ws");

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

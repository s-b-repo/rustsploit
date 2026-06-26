use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::Path as AxumPath,
    http::{Method, StatusCode, Uri},
    response::{IntoResponse, Json, Response},
    routing::{any, get, post},
    Router,
};
use colored::*;
use serde_json::{json, Value};
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
    // Multi-target (comma-separated): block if ANY element is blocked, so a
    // benign-looking list like "8.8.8.8,127.0.0.1" can't smuggle a blocked
    // host past the filter. Mirrors Target::parse's multi-target handling.
    if target.contains(',') {
        return target
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .any(is_blocked_target);
    }
    // Mass-scan keywords are deliberately allowed — this function exists for
    // SSRF mitigation, not for restricting scan scope. Modules that opt in
    // to mass-scan mode parse these keywords themselves.
    // M45: "0.0.0.0" alone resolves to localhost and must NOT be allowlisted.
    // Only "0.0.0.0/0" (full-internet CIDR) and "random" are genuine
    // mass-scan keywords that modules parse themselves.
    const MASS_SCAN_KEYWORDS: &[&str] = &["random", "0.0.0.0/0"];
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
        .unwrap_or_else(|| {
            // Generic scheme stripping for any other protocol (e.g. dict://, tftp://)
            if let Some(idx) = lower.find("://") {
                &lower[idx + 3..]
            } else {
                &lower
            }
        });
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
        if bytes[i] == b'%' && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (
                hex_val(bytes[i + 1]),
                hex_val(bytes[i + 2]),
            ) {
                result.push((hi << 4 | lo) as char);
                i += 3;
                continue;
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
    // Each entry is `(exact, dotted_suffix)`. Pre-built so the per-call hot
    // path is just two `eq`/`ends_with` checks per entry instead of a
    // `format!(".{suffix}")` allocation each time.
    const BLOCKED_HOST_SUFFIXES: &[(&str, &str)] = &[
        ("metadata.google.internal", ".metadata.google.internal"),
        ("metadata.goog", ".metadata.goog"),
        ("metadata.internal", ".metadata.internal"),
        ("metadata.azure.com", ".metadata.azure.com"),
        ("metadata.oraclecloud.com", ".metadata.oraclecloud.com"),
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

    for (exact, dotted) in BLOCKED_HOST_SUFFIXES {
        if host == *exact || host.ends_with(dotted) {
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
            // Use to_ipv4() (not to_ipv4_mapped()) so both IPv4-mapped
            // (::ffff:a.b.c.d) and the deprecated IPv4-compatible (::a.b.c.d)
            // forms are unwrapped — otherwise ::127.0.0.1 bypasses the filter.
            if let Some(v4) = v6.to_ipv4() {
                return is_blocked_ipv4(v4);
            }
            false
        }
        std::net::IpAddr::V4(v4) => is_blocked_ipv4(v4),
    }
}

fn is_blocked_ipv4(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 0                                   // 0.0.0.0/8 ("this network"; routes to localhost on Linux)
        || o[0] == 127                          // 127.0.0.0/8 loopback
        || o[0] == 10                           // 10.0.0.0/8 RFC1918
        || (o[0] == 172 && (o[1] & 0xf0) == 16) // 172.16.0.0/12 RFC1918
        || (o[0] == 192 && o[1] == 168)         // 192.168.0.0/16 RFC1918
        || (o[0] == 169 && o[1] == 254)         // 169.254.0.0/16 link-local
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
        || o == [168, 63, 129, 16]              // Azure wireserver metadata
        || o == [100, 100, 100, 200]            // Alibaba metadata
}

/// SSRF/resolution gate: resolve `target` and verify no resolved IP is blocked.
/// On failure, distinguishes a genuine SSRF block from a mere DNS failure so
/// callers don't report an unresolvable/slow host as a 403 SSRF block (which
/// violates "failures must be distinguishable from negatives" and makes real
/// engagement failures undebuggable). Returns `(error_code, message)`:
/// `SSRF_BLOCKED` for a real block, `TARGET_ERROR` for resolution failure.
pub(crate) async fn ssrf_gate(target: &str) -> Result<(), (&'static str, String)> {
    match resolve_and_check(target).await {
        Ok(_) => Ok(()),
        Err(msg) if msg.contains("blocked") => Err(("SSRF_BLOCKED", msg)),
        Err(msg) => Err(("TARGET_ERROR", msg)),
    }
}

/// Resolve a hostname and verify none of the returned IPs are blocked.
/// Returns the resolved addresses on success, or an error if blocked / unresolvable.
/// Callers should connect to the returned addresses directly (not re-resolve)
/// to prevent DNS rebinding attacks.
pub(crate) async fn resolve_and_check(target: &str) -> Result<Vec<std::net::SocketAddr>, String> {
    // Multi-target (comma-separated): resolve and SSRF-check each element
    // individually; the whole list is rejected if any element is blocked or
    // fails to resolve. Without this, the list is fed to lookup_host as one
    // string, which always fails DNS and rejects even legitimate lists.
    if target.contains(',') {
        let mut all = Vec::new();
        for part in target.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            all.extend(Box::pin(resolve_and_check(part)).await?);
        }
        return Ok(all);
    }
    // M45: "0.0.0.0" alone resolves to localhost — must not be allowlisted.
    const MASS_SCAN_KEYWORDS: &[&str] = &["random", "0.0.0.0/0"];
    if MASS_SCAN_KEYWORDS.contains(&target) {
        return Ok(vec![]);
    }

    if is_blocked_target(target) {
        return Err("target blocked by SSRF filter".to_string());
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
            let resolved: Vec<std::net::SocketAddr> = addrs.collect();
            for addr in &resolved {
                if is_blocked_ip(addr.ip()) {
                    return Err(format!("resolved IP {} is blocked", addr.ip()));
                }
            }
            // Pin the validated IPs to the bare hostname so the subsequent module
            // connect reuses exactly these addresses instead of re-resolving the
            // name (which a rebinding attacker could point at a blocked IP after
            // this check passes). reqwest clients built via build_http_client_with
            // consult these pins. IP-literal targets are not resolved by reqwest,
            // so pinning them is a harmless no-op.
            // Strip a trailing numeric :port to get the bare hostname for pinning.
            // Spelled out with explicit branches (no wildcard arm) so every case
            // is handled visibly and nothing is folded away.
            let host_only: &str = if let Some((host, port)) = host_part.rsplit_once(':') {
                if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
                    // "host:port" — pin the hostname, drop the numeric port.
                    host
                } else {
                    // A ':' is present but the suffix is not a numeric port (e.g. an
                    // IPv6 literal like "::1"); use the whole string. IP literals are
                    // never resolved by reqwest, so pinning them is simply unused.
                    host_part
                }
            } else {
                // No ':' present — already a bare hostname.
                host_part
            };
            crate::utils::network::pin_resolved_ips(
                host_only,
                &resolved.iter().map(|s| s.ip()).collect::<Vec<_>>(),
            );
            Ok(resolved)
        }
        Ok(Err(e)) => {
            tracing::debug!(target = lookup_addr, "SSRF resolve failed → blocking: {}", e);
            Err(format!("DNS resolution failed: {}", e))
        }
        Err(e) => {
            tracing::debug!(target = lookup_addr, "SSRF resolve timed out (5s) → blocking: {e}");
            Err(format!("DNS resolution timed out: {e}"))
        }
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

// ─── HTTP → JSON-RPC Adapter ────────────────────────────────────────
//
// Maps the REST surface (GET/POST/PUT/DELETE on `/api/<resource>[/<id>...]`)
// onto the existing `crate::ws::dispatch_rpc` handlers so we keep one
// canonical dispatch table for both transports.
//
// The middleware in `pq_middleware::pq_middleware` has already decrypted the
// body, restored the original semantic HTTP method (from `X-PQ-Method`), and
// scrubbed the PQ envelope headers by the time these handlers run.

fn rpc_status(code: &str) -> StatusCode {
    match code {
        "INVALID_INPUT" | "INVALID_OUTPUT_FILE" | "INVALID_JOB_ID" | "PARSE_ERROR"
        | "INVALID_PORT" | "INVALID_CONCURRENCY" => {
            StatusCode::BAD_REQUEST
        }
        "NOT_FOUND" | "MODULE_NOT_FOUND" | "METHOD_NOT_FOUND" => StatusCode::NOT_FOUND,
        "SSRF_BLOCKED" | "SECURITY" => StatusCode::FORBIDDEN,
        "TENANT_REJECTED" => StatusCode::SERVICE_UNAVAILABLE,
        // Genuine capacity/limit conflicts the caller can retry later.
        "JOB_LIMIT" | "OPTION_LIMIT" | "SUB_LIMIT" | "SPOOL_BUSY" => {
            StatusCode::CONFLICT
        }
        "RATE_LIMIT" => StatusCode::TOO_MANY_REQUESTS,
        // Module / IO / serialization / persistence failures are server-side
        // runtime failures, not client conflicts. `OPTION_ERROR`/`TARGET_ERROR`/
        // `STORE_ERROR` mean "failed to persist", so they belong here (500), not
        // 409 — a 409 wrongly tells the client its request conflicts with state.
        "MODULE_ERROR"
        | "EXPORT_ERROR"
        | "SPOOL_ERROR"
        | "IO_ERROR"
        | "STORE_ERROR"
        | "OPTION_ERROR"
        | "TARGET_ERROR"
        | "SERIALIZE_ERROR" => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn ok(value: Value) -> Response {
    Json(value).into_response()
}

fn err_resp(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({ "error": message, "code": code }))).into_response()
}

fn parse_query(query: &str) -> std::collections::BTreeMap<String, String> {
    url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// Run a single RPC call and turn its result into an HTTP response with a
/// uniform `{ data: ... }` envelope on success and `{ error, code }` on
/// failure. This is the single canonical shape every REST client sees.
async fn invoke_rpc(method: &str, params: Value) -> Response {
    match crate::ws::dispatch_rpc(method, &params).await {
        Ok(data) => ok(json!({ "data": data })),
        Err((code, msg)) => err_resp(rpc_status(&code), &code, &msg),
    }
}

/// The single catch-all `/api/{*tail}` handler. Parses the path tail,
/// method, query string, and JSON body into a `(rpc_method, params)` pair
/// and forwards to `crate::ws::dispatch_rpc`.
async fn api_dispatcher(
    method: Method,
    AxumPath(tail): AxumPath<String>,
    uri: Uri,
    axum::Extension(identity): axum::Extension<crate::pq_middleware::AuthenticatedIdentity>,
    body: Bytes,
) -> Response {
    let path = format!("/{}", tail.trim_start_matches('/'));
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let head = segments.first().copied().unwrap_or("");
    let sub = segments.get(1).copied();
    let third = segments.get(2).copied();

    let body_value: Value = if body.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice::<Value>(&body) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("API JSON parse error: {e}");
                return err_resp(
                    StatusCode::BAD_REQUEST,
                    "PARSE_ERROR",
                    "Request body is not valid JSON",
                );
            }
        }
    };
    let body_obj = body_value.as_object().cloned().unwrap_or_default();
    let query = parse_query(uri.query().unwrap_or(""));

    let mut params = serde_json::Map::new();

    macro_rules! merge_query {
        ($params:ident, $query:ident, [$($key:literal),* $(,)?]) => {
            $(
                if let Some(v) = $query.get($key) {
                    $params.insert($key.to_string(), Value::String(v.clone()));
                }
            )*
        };
    }
    macro_rules! merge_query_int {
        ($params:ident, $query:ident, [$($key:literal),* $(,)?]) => {
            $(
                if let Some(v) = $query.get($key).and_then(|s| s.parse::<u64>().ok()) {
                    $params.insert($key.to_string(), Value::Number(v.into()));
                }
            )*
        };
    }
    macro_rules! body_into_params {
        ($params:ident, $body:ident) => {
            for (k, v) in $body.iter() {
                $params.insert(k.clone(), v.clone());
            }
        };
    }

    let rpc_method: &str = match (method.as_str(), head, sub, third) {
        // ── Health ──────────────────────────────────────────────────
        ("GET", "health", None, _) => "health",

        // ── Modules ─────────────────────────────────────────────────
        ("GET", "modules", None, _) => "list_modules",
        ("GET", "modules", Some("enriched"), _) => "list_modules_enriched",
        ("GET", "modules", Some("search"), _) => {
            merge_query!(params, query, ["q"]);
            "search_modules"
        }
        ("GET", "module", Some(_), _) => {
            // /api/module/<modulepath...> — everything after /module/ is the module path.
            let module_path = &path["/module/".len()..];
            params.insert("path".to_string(), Value::String(module_path.to_string()));
            "module_info"
        }

        // ── Run / Check / Honeypot ──────────────────────────────────
        ("POST", "run", None, _) => {
            body_into_params!(params, body_obj);
            "run_module"
        }
        ("POST", "run", Some("all"), _) | ("POST", "run_all", None, _) => {
            // There is no multi-module runner; these routes previously aliased
            // run_module (which needs a single `module`), so they advertised a
            // capability that does not exist. Be explicit rather than misleading.
            return err_resp(
                StatusCode::NOT_IMPLEMENTED,
                "NOT_IMPLEMENTED",
                "Multi-module run is not implemented. POST /api/run with an explicit `module` per request (enumerate via GET /api/modules and loop client-side).",
            );
        }
        ("POST", "honeypot-check", None, _) => {
            body_into_params!(params, body_obj);
            "honeypot_check"
        }

        // ── Target ──────────────────────────────────────────────────
        ("GET", "target", None, _) => "get_target",
        ("POST", "target", None, _) => {
            body_into_params!(params, body_obj);
            "set_target"
        }
        ("DELETE", "target", None, _) => "clear_target",

        // ── Options ─────────────────────────────────────────────────
        ("GET", "options", None, _) => "list_options",
        ("POST", "options", None, _) => {
            // set_option takes the multi-key body directly.
            body_into_params!(params, body_obj);
            "set_option"
        }
        ("DELETE", "options", None, _) => {
            let tenant_name = identity.client_name.clone();
            // Fail closed, same as the main dispatcher.
            if let Err(e) = crate::tenant::resolve_for(&tenant_name) {
                return err_resp(StatusCode::SERVICE_UNAVAILABLE, "TENANT_REJECTED", &e);
            }
            if body_obj.is_empty() {
                return err_resp(StatusCode::BAD_REQUEST, "INVALID_INPUT", "Request body must list at least one option key to delete");
            }
            let mut deleted = Vec::new();
            let mut errors = Vec::new();
            for k in body_obj.keys() {
                let single = json!({ "key": k });
                let tn = tenant_name.clone();
                let result = crate::tenant::CURRENT_TENANT
                    .scope(tn, crate::ws::dispatch_rpc("delete_option", &single))
                    .await;
                match result {
                    Ok(v) => deleted.push(v),
                    Err((code, msg)) => errors.push(json!({"key": k, "code": code, "error": msg})),
                }
            }
            // If nothing was deleted and everything errored, surface a non-2xx
            // so a client can't mistake an all-failed delete for success.
            if deleted.is_empty() && !errors.is_empty() {
                let all_not_found = errors
                    .iter()
                    .all(|e| e.get("code").and_then(|c| c.as_str()) == Some("NOT_FOUND"));
                let status = if all_not_found { StatusCode::NOT_FOUND } else { StatusCode::CONFLICT };
                return (status, Json(json!({ "data": { "deleted": deleted, "errors": errors } }))).into_response();
            }
            return ok(json!({
                "data": { "deleted": deleted, "errors": errors }
            }));
        }

        // ── Credentials ─────────────────────────────────────────────
        ("GET", "creds", None, _) => {
            merge_query!(params, query, ["host", "service", "search"]);
            merge_query_int!(params, query, ["limit", "offset"]);
            if let Some(v) = query.get("reveal")
                && (v == "1" || v.eq_ignore_ascii_case("true")) {
                    params.insert("reveal".to_string(), Value::Bool(true));
                }
            "list_creds"
        }
        ("GET", "creds", Some("search"), _) => {
            merge_query!(params, query, ["q"]);
            "search_creds"
        }
        ("POST", "creds", None, _) => {
            body_into_params!(params, body_obj);
            "add_cred"
        }
        ("DELETE", "creds", None, _) => {
            body_into_params!(params, body_obj);
            "delete_cred"
        }
        ("POST", "creds", Some("clear"), _) => "clear_creds",

        // ── Hosts ───────────────────────────────────────────────────
        ("GET", "hosts", None, _) => {
            merge_query!(params, query, ["os", "search"]);
            merge_query_int!(params, query, ["limit", "offset"]);
            "list_hosts"
        }
        ("POST" | "PUT", "hosts", None, _) => {
            body_into_params!(params, body_obj);
            "add_host"
        }
        ("DELETE", "hosts", None, _) => {
            body_into_params!(params, body_obj);
            "delete_host"
        }
        ("POST", "hosts", Some("notes"), _) => {
            body_into_params!(params, body_obj);
            "add_host_note"
        }
        ("POST", "hosts", Some("clear"), _) => "clear_hosts",

        // ── Services ────────────────────────────────────────────────
        ("GET", "services", None, _) => {
            merge_query!(params, query, ["host", "search"]);
            merge_query_int!(params, query, ["port", "limit", "offset"]);
            "list_services"
        }
        ("POST", "services", None, _) => {
            body_into_params!(params, body_obj);
            "add_service"
        }
        ("DELETE", "services", None, _) => {
            body_into_params!(params, body_obj);
            "delete_service"
        }

        // ── Loot ────────────────────────────────────────────────────
        ("GET", "loot", None, _) => {
            merge_query!(params, query, ["host", "loot_type", "search"]);
            merge_query_int!(params, query, ["limit", "offset"]);
            "list_loot"
        }
        ("GET", "loot", Some("search"), _) => {
            merge_query!(params, query, ["q"]);
            "search_loot"
        }
        ("POST", "loot", None, _) => {
            body_into_params!(params, body_obj);
            "add_loot"
        }
        ("DELETE", "loot", None, _) => {
            body_into_params!(params, body_obj);
            "delete_loot"
        }
        ("POST", "loot", Some("clear"), _) => "clear_loot",

        // ── Workspace ───────────────────────────────────────────────
        ("GET", "workspace", None, _) => "get_workspace",
        ("POST", "workspace", None, _) => {
            body_into_params!(params, body_obj);
            "switch_workspace"
        }
        ("GET", "workspaces", None, _) => "list_workspaces",

        // ── Jobs ────────────────────────────────────────────────────
        ("GET", "jobs", None, _) => "list_jobs",
        ("POST", "jobs", Some("limit"), _) => {
            body_into_params!(params, body_obj);
            "set_job_limit"
        }
        ("GET", "jobs", Some(id), _) => {
            if let Ok(n) = id.parse::<u64>() {
                params.insert("id".to_string(), Value::Number(n.into()));
            } else {
                return err_resp(StatusCode::BAD_REQUEST, "INVALID_INPUT", "job id must be numeric");
            }
            merge_query_int!(params, query, ["from"]);
            "get_job"
        }
        ("DELETE", "jobs", Some(id), _) => {
            if let Ok(n) = id.parse::<u64>() {
                params.insert("id".to_string(), Value::Number(n.into()));
            } else {
                return err_resp(StatusCode::BAD_REQUEST, "INVALID_INPUT", "job id must be numeric");
            }
            "kill_job"
        }
        ("DELETE", "jobs", None, _) => {
            // Body-style {id: N} — accept either a number or a numeric string.
            if let Some(id_val) = body_obj.get("id") {
                if let Some(n) = id_val.as_u64() {
                    params.insert("id".to_string(), Value::Number(n.into()));
                } else if let Some(s) = id_val.as_str().and_then(|s| s.parse::<u64>().ok()) {
                    params.insert("id".to_string(), Value::Number(s.into()));
                } else {
                    return err_resp(StatusCode::BAD_REQUEST, "INVALID_INPUT", "invalid job id");
                }
            } else {
                return err_resp(StatusCode::BAD_REQUEST, "INVALID_INPUT", "job id is required");
            }
            "kill_job"
        }

        // ── Spool ───────────────────────────────────────────────────
        ("GET", "spool", None, _) => "spool_status",
        ("POST", "spool", None, _) => {
            // Body shape: {action: "start"|"stop", filename?: ...}
            let action = body_obj
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match action {
                "start" => {
                    if let Some(f) = body_obj.get("filename") {
                        params.insert("filename".to_string(), f.clone());
                    }
                    "spool_start"
                }
                "stop" => "spool_stop",
                _ => {
                    return err_resp(
                        StatusCode::BAD_REQUEST,
                        "INVALID_INPUT",
                        "action must be 'start' or 'stop'",
                    );
                }
            }
        }

        // ── Results ─────────────────────────────────────────────────
        ("GET", "results", None, _) => "list_results",
        ("GET", "results", Some(name), _) => {
            params.insert("filename".to_string(), Value::String(name.to_string()));
            "get_result"
        }

        // ── Export ──────────────────────────────────────────────────
        ("GET", "export", None, _) => {
            merge_query!(params, query, ["format"]);
            "export"
        }

        // ── Shell (intentionally not exposed via REST until ACL design lands) ─
        ("POST", "shell", None, _) => {
            return err_resp(
                StatusCode::NOT_IMPLEMENTED,
                "NOT_IMPLEMENTED",
                "Shell-over-API is disabled; use individual RPC methods (set_target, run_module, …)",
            );
        }

        // ── Default: nothing matched ────────────────────────────────
        _ => {
            return err_resp(
                StatusCode::NOT_FOUND,
                "ROUTE_NOT_FOUND",
                &format!("No mapping for {} /api/{}", method, tail),
            );
        }
    };

    // Fail closed, mirroring the WS dispatch guard (ws.rs): only run under a
    // tenant that still resolves. `tenant::resolve()` silently falls back to the
    // process-global stores when the registry rejects a tenant (e.g. the
    // MAX_TENANTS cap is hit), which would otherwise let a REST caller read and
    // write another tenant's loot/creds/options/jobs.
    if let Err(e) = crate::tenant::resolve_for(&identity.client_name) {
        return err_resp(StatusCode::SERVICE_UNAVAILABLE, "TENANT_REJECTED", &e);
    }
    crate::tenant::CURRENT_TENANT
        .scope(
            identity.client_name,
            invoke_rpc(rpc_method, Value::Object(params)),
        )
        .await
}

// ─── Server Entry Point ─────────────────────────────────────────────

pub async fn start_api_server(
    bind_address: &str,
    verbose: bool,
    host_key_path: &std::path::Path,
    authorized_keys_path: &std::path::Path,
    passphrase: Option<&str>,
) -> Result<()> {
    if verbose {
        tracing::info!("Starting API server in verbose mode");
    }
    // We don't refuse any bind address. The bootstrap path is gated by a
    // one-time enrollment token printed at startup (see /pq/register-key),
    // not by the bind interface — the token is the sole authority that
    // permits the very first authorized_keys entry.
    let host_identity = crate::pq_channel::HostIdentity::load_or_generate(host_key_path, passphrase)
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
            crate::pq_channel::fingerprint(&[&key.x25519_public, &key.mlkem_ek, &key.mceliece_public]));
    }

    // Generate a one-time enrollment token. Operators bootstrap remote
    // clients by POSTing their PQ public keys to /pq/register-key with this
    // token. The token is printed at startup, held only in memory, and
    // consumed on first successful registration. Subsequent key changes
    // must use the established PQ session.
    let enrollment_token = crate::pq_channel::generate_enrollment_token();
    let enrollment_token_print = enrollment_token.clone();

    let pq_state = Arc::new(crate::pq_middleware::PqSharedState {
        sessions: pq_sessions,
        host_identity: Arc::new(host_identity),
        authorized_keys: tokio::sync::RwLock::new(authorized_keys),
        authorized_keys_path: authorized_keys_path.to_path_buf(),
        handshake_rate_limiter: crate::pq_middleware::new_handshake_rate_limiter(),
        enrollment_token: tokio::sync::Mutex::new(Some(enrollment_token)),
    });

    let cleanup_sessions = pq_state.sessions.clone();
    let cleanup_rate_limiter = pq_state.handshake_rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            // Two-phase cleanup: first take a SHORT read lock to scan
            // last_activity (locking each session's mutex non-blockingly),
            // then take the write lock only to remove the doomed entries.
            // This keeps the map readable during the bulk of the work.
            let doomed: Vec<[u8; 16]> = {
                let store = cleanup_sessions.read().await;
                let mut out = Vec::new();
                for (id, sess_arc) in store.iter() {
                    if let Ok(sess) = sess_arc.try_lock()
                        && sess.last_activity.elapsed() >= std::time::Duration::from_secs(3600) {
                            out.push(*id);
                        }
                }
                out
            };
            let removed_n = if !doomed.is_empty() {
                let mut store = cleanup_sessions.write().await;
                let mut n = 0usize;
                for id in &doomed {
                    if store.remove(id).is_some() { n += 1; }
                }
                n
            } else { 0 };
            if removed_n > 0 {
                let remaining = cleanup_sessions.read().await.len();
                tracing::info!("PQ session cleanup: removed {} idle sessions ({} remaining)", removed_n, remaining);
            }

            let mut limiter = cleanup_rate_limiter.lock().await;
            limiter.retain(|_, timestamps| {
                timestamps.retain(|t| t.elapsed() < std::time::Duration::from_secs(120));
                !timestamps.is_empty()
            });
        }
    });

    // The PQ middleware MUST be the outermost wrapper for /api/* so it can
    // see the encrypted body before any extractor tries to parse it. Mount
    // it as a `route_layer` so it only runs on the /api/* surface and not
    // on /health, /pq/handshake, /pq/ws which speak their own protocols.
    let api_router: Router = Router::new()
        // Specific routes BEFORE the catch-all so the dispatcher doesn't
        // swallow them. Identity revocation lives behind the PQ middleware
        // so the request is AEAD-authenticated by an existing client.
        .route("/api/pq/revoke-key", post(crate::pq_middleware::revoke_key_handler))
        .route("/api/{*tail}", any(api_dispatcher))
        .route_layer(axum::middleware::from_fn(crate::pq_middleware::pq_middleware));

    // Cap the JSON request body explicitly. Axum's default is 2 MiB, but we
    // pin it here so a future caller can't disable it upstream by accident.
    const MAX_REQUEST_BODY: usize = 2 * 1024 * 1024;

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/pq/handshake", post(crate::pq_middleware::handshake_handler))
        .route("/pq/register-key", post(crate::pq_middleware::register_key_handler))
        .route("/pq/ws", get(crate::ws::ws_upgrade))
        .merge(api_router)
        .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST_BODY))
        .layer(axum::Extension(pq_state))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http()),
        );

    println!("Server running on http://{}", bind_address);
    println!("Transport: Post-Quantum encryption (ML-KEM-768 + X25519 + ChaCha20-Poly1305)");
    println!(
        "Endpoints: GET /health, POST /pq/handshake, POST /pq/register-key, GET /pq/ws, ALL /api/*"
    );
    println!();
    println!("{}", "═══════════════════════════════════════════════════════════════".cyan());
    println!("{} {}", "ENROLLMENT TOKEN (one-time, prints once):".yellow().bold(), enrollment_token_print.bright_white().bold());
    println!("{}", "Bootstrap a client by POSTing its PQ public keys + this".dimmed());
    println!("{}", "token to POST /pq/register-key:".dimmed());
    println!("{}", "  { token, name, x25519_pub, mlkem_ek }".dimmed());
    println!("{}", "After first successful registration the token is consumed; further".dimmed());
    println!("{}", "key changes must go through the established PQ session.".dimmed());
    println!("{}", "═══════════════════════════════════════════════════════════════".cyan());
    println!();

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

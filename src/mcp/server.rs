use anyhow::Context;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use super::types::{
    InitializeResult, JsonRpcRequest, JsonRpcResponse, ResourcesCapability, ServerCapabilities,
    ServerInfo, ToolsCapability,
};

// You can place this function in src/mcp/server.rs or a shared utility module
fn errno() -> i32 {
    unsafe {
        #[cfg(any(target_os = "freebsd", target_os = "macos"))]
        { *libc::__error() }

        #[cfg(target_os = "linux")]
        { *libc::__errno_location() }

        // Add fallbacks for other OSes if needed
        #[cfg(not(any(target_os = "freebsd", target_os = "macos", target_os = "linux")))]
        { 0 } // Or compile_error! to force checking for a new OS
    }
}

fn isolate_protocol_stdout() -> anyhow::Result<tokio::fs::File> {
    use std::os::fd::FromRawFd;
    unsafe {
        let saved_fd = libc::dup(1);
        if saved_fd < 0 {
            anyhow::bail!("dup(1) failed: errno {}", errno());
        }
        let null_path = b"/dev/null\0";
        let null_fd = libc::open(null_path.as_ptr() as *const libc::c_char, libc::O_WRONLY);
        if null_fd < 0 {
            libc::close(saved_fd);
            anyhow::bail!("open(/dev/null) failed: errno {}", errno());
        }
        if libc::dup2(null_fd, 1) < 0 {
            libc::close(null_fd);
            libc::close(saved_fd);
            anyhow::bail!("dup2(null, 1) failed: errno {}", errno());
        }
        libc::close(null_fd);
        let std_file = std::fs::File::from_raw_fd(saved_fd);
        Ok(tokio::fs::File::from_std(std_file))
    }
}

/// Run the MCP server over newline-delimited JSON on stdio.
///
/// * **stdin**  — reads one JSON-RPC 2.0 request per line.
/// * **stdout** — writes one JSON-RPC 2.0 response per line.
/// * **stderr** — diagnostic logging (stdout is the protocol channel).
pub async fn run_mcp_server() -> anyhow::Result<()> {
    let mut protocol_out = isolate_protocol_stdout()
        .context("Cannot isolate protocol stdout — aborting to prevent JSON-RPC corruption")?;

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line_buf: Vec<u8> = Vec::new();

    const MAX_LINE_BYTES: usize = 1024 * 1024;

    eprintln!("[MCP] RustSploit MCP server started (stdio transport)");
    eprintln!("[MCP] Protocol stdout isolated — module output is captured via OUTPUT_BUFFER only");

    loop {
        line_buf.clear();
        let n = (&mut reader)
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut line_buf)
            .await
            .context("failed to read from stdin")?;
        if n == 0 {
            eprintln!("[MCP] stdin closed, shutting down");
            break;
        }
        if line_buf.len() > MAX_LINE_BYTES {
            eprintln!(
                "[MCP] line exceeded {} bytes without newline — rejecting and closing",
                MAX_LINE_BYTES
            );
            let resp = JsonRpcResponse::error(
                None,
                -32600,
                format!("Request exceeds {} byte line limit", MAX_LINE_BYTES),
            );
            write_response(&mut protocol_out, &resp).await?;
            break;
        }

        let line = match std::str::from_utf8(&line_buf) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[MCP] non-UTF-8 input on stdin: {}", e);
                let resp = JsonRpcResponse::error(
                    None,
                    -32700,
                    format!("Parse error: input is not valid UTF-8: {}", e),
                );
                write_response(&mut protocol_out, &resp).await?;
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[MCP] parse error: {}", e);
                let resp = JsonRpcResponse::error(None, -32700, format!("Parse error: {}", e));
                write_response(&mut protocol_out, &resp).await?;
                continue;
            }
        };

        eprintln!("[MCP] <- method={}", request.method);

        let response = handle_request(request).await;
        if let Some(resp) = response {
            write_response(&mut protocol_out, &resp).await?;
        }
    }

    Ok(())
}

/// Serialize a response as a single JSON line on the protocol channel.
async fn write_response(
    out: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
    resp: &JsonRpcResponse,
) -> anyhow::Result<()> {
    let mut json = serde_json::to_vec(resp).context("failed to serialize response")?;
    json.push(b'\n');
    out.write_all(&json).await.context("failed to write response")?;
    out.flush().await.context("failed to flush protocol channel")?;
    Ok(())
}

/// Route a parsed request to the appropriate handler.
async fn handle_request(req: JsonRpcRequest) -> Option<JsonRpcResponse> {
    match req.method.as_str() {
        "initialize" => Some(handle_initialize(req.id)),
        "initialized" | "notifications/initialized" => {
            // Notification — no response.
            eprintln!("[MCP] Client initialized");
            None
        }
        "tools/list" => Some(handle_tools_list(req.id)),
        "tools/call" => Some(handle_tools_call(req.id, req.params).await),
        "resources/list" => Some(handle_resources_list(req.id)),
        "resources/read" => Some(handle_resources_read(req.id, req.params).await),
        other if other.starts_with("notifications/") => {
            eprintln!("[MCP] Ignoring notification: {}", other);
            None
        }
        other => Some(JsonRpcResponse::error(
            req.id,
            -32601,
            format!("Method not found: {}", other),
        ))
    }
}

// ---------------------------------------------------------------------------
// Handler implementations
// ---------------------------------------------------------------------------

fn handle_initialize(id: Option<Value>) -> JsonRpcResponse {
    let result = InitializeResult {
        protocol_version: "2024-11-05".to_string(),
        capabilities: ServerCapabilities {
            tools: Some(ToolsCapability {}),
            resources: Some(ResourcesCapability {}),
        },
        server_info: ServerInfo {
            name: "rustsploit-mcp".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
    };

    match serde_json::to_value(&result) {
        Ok(v) => JsonRpcResponse::success(id, v),
        Err(e) => JsonRpcResponse::error(id, -32603, format!("Internal error: {}", e)),
    }
}

fn handle_tools_list(id: Option<Value>) -> JsonRpcResponse {
    let tools = super::tools::all_tools();
    match serde_json::to_value(&tools) {
        Ok(v) => JsonRpcResponse::success(id, serde_json::json!({ "tools": v })),
        Err(e) => JsonRpcResponse::error(id, -32603, format!("Internal error: {}", e)),
    }
}

async fn handle_tools_call(id: Option<Value>, params: Option<Value>) -> JsonRpcResponse {
    let (name, arguments) = match extract_tool_call_params(&params) {
        Ok(pair) => pair,
        Err(msg) => return JsonRpcResponse::error(id, -32602, msg),
    };

    let result = super::tools::call_tool(&name, arguments).await;
    match serde_json::to_value(&result) {
        Ok(v) => JsonRpcResponse::success(id, v),
        Err(e) => JsonRpcResponse::error(id, -32603, format!("Internal error: {}", e)),
    }
}

fn handle_resources_list(id: Option<Value>) -> JsonRpcResponse {
    let resources = super::resources::all_resources();
    match serde_json::to_value(&resources) {
        Ok(v) => JsonRpcResponse::success(id, serde_json::json!({ "resources": v })),
        Err(e) => JsonRpcResponse::error(id, -32603, format!("Internal error: {}", e)),
    }
}

async fn handle_resources_read(id: Option<Value>, params: Option<Value>) -> JsonRpcResponse {
    let uri = match extract_resource_uri(&params) {
        Ok(u) => u,
        Err(msg) => return JsonRpcResponse::error(id, -32602, msg),
    };

    let result = super::resources::read_resource(&uri).await;
    // The MCP spec (2024-11-05) requires `resources/read` to return
    // `{ contents: [ { uri, mimeType, text } ] }` — a list, not a bare content
    // object. Claude's client rejects the bare shape silently.
    match serde_json::to_value(&result) {
        Ok(v) => JsonRpcResponse::success(id, serde_json::json!({ "contents": [v] })),
        Err(e) => JsonRpcResponse::error(id, -32603, format!("Internal error: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// Param extraction helpers
// ---------------------------------------------------------------------------

/// Pull `name` (String) and `arguments` (Object) out of the `tools/call` params.
fn extract_tool_call_params(params: &Option<Value>) -> Result<(String, Value), String> {
    let obj = params
        .as_ref()
        .and_then(|v| v.as_object())
        .ok_or_else(|| "Invalid params: expected object with 'name' and 'arguments'".to_string())?;

    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing or invalid 'name' in params".to_string())?
        .to_string();

    let arguments = obj
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    Ok((name, arguments))
}

/// Pull `uri` (String) out of the `resources/read` params.
fn extract_resource_uri(params: &Option<Value>) -> Result<String, String> {
    let obj = params
        .as_ref()
        .and_then(|v| v.as_object())
        .ok_or_else(|| "Invalid params: expected object with 'uri'".to_string())?;

    let uri = obj
        .get("uri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing or invalid 'uri' in params".to_string())?
        .to_string();

    Ok(uri)
}

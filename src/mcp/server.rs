use anyhow::Context;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::types::{
    InitializeResult, JsonRpcRequest, JsonRpcResponse, ServerCapabilities, ServerInfo,
    ResourcesCapability, ToolsCapability,
};

/// Run the MCP server over newline-delimited JSON on stdio.
///
/// * **stdin**  — reads one JSON-RPC 2.0 request per line.
/// * **stdout** — writes one JSON-RPC 2.0 response per line.
/// * **stderr** — diagnostic logging (stdout is the protocol channel).
pub async fn run_mcp_server() -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    eprintln!("[MCP] RustSploit MCP server started (stdio transport)");

    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .context("failed to read from stdin")?;
        if n == 0 {
            // EOF — client closed the pipe.
            eprintln!("[MCP] stdin closed, shutting down");
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[MCP] parse error: {}", e);
                let resp = JsonRpcResponse::error(None, -32700, format!("Parse error: {}", e));
                write_response(&mut stdout, &resp).await?;
                continue;
            }
        };

        eprintln!("[MCP] <- method={}", request.method);

        let response = handle_request(request).await;
        if let Some(resp) = response {
            write_response(&mut stdout, &resp).await?;
        }
    }

    Ok(())
}

/// Serialize a response as a single JSON line on stdout.
/// Combines serialization + newline into one write to minimize syscalls.
async fn write_response(
    stdout: &mut tokio::io::Stdout,
    resp: &JsonRpcResponse,
) -> anyhow::Result<()> {
    let mut json = serde_json::to_vec(resp).context("failed to serialize response")?;
    json.push(b'\n');
    stdout.write_all(&json).await.context("failed to write response")?;
    stdout.flush().await.context("failed to flush stdout")?;
    Ok(())
}

/// Route a parsed request to the appropriate handler.
async fn handle_request(req: JsonRpcRequest) -> Option<JsonRpcResponse> {
    match req.method.as_str() {
        "initialize" => Some(handle_initialize(req.id)),
        "initialized" => {
            // Notification — no response.
            eprintln!("[MCP] Client initialized");
            None
        }
        "tools/list" => Some(handle_tools_list(req.id)),
        "tools/call" => Some(handle_tools_call(req.id, req.params).await),
        "resources/list" => Some(handle_resources_list(req.id)),
        "resources/read" => Some(handle_resources_read(req.id, req.params).await),
        other => Some(JsonRpcResponse::error(
            req.id,
            -32601,
            format!("Method not found: {}", other),
        )),
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
    match serde_json::to_value(&result) {
        Ok(v) => JsonRpcResponse::success(id, v),
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

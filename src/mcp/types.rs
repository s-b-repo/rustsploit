use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 core types
// ---------------------------------------------------------------------------

/// Incoming JSON-RPC 2.0 request (or notification when `id` is `None`).
#[derive(Deserialize)]
pub struct JsonRpcRequest {
    #[serde(default = "default_jsonrpc")]
    pub jsonrpc: String,
    /// `None` means this is a notification (no response expected).
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

fn default_jsonrpc() -> String {
    "2.0".to_string()
}

/// Outgoing JSON-RPC 2.0 response.
#[derive(Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    /// Build a successful response carrying `result`.
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Build an error response.
    pub fn error(id: Option<Value>, code: i64, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: None,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// MCP capability negotiation
// ---------------------------------------------------------------------------

/// Returned as the result of the `initialize` method.
#[derive(Serialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

#[derive(Serialize)]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
}

#[derive(Serialize)]
pub struct ToolsCapability {}

#[derive(Serialize)]
pub struct ResourcesCapability {}

#[derive(Serialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

/// Descriptor returned by `tools/list`.
#[derive(Serialize, Clone)]
pub struct Tool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// Result payload returned by `tools/call`.
#[derive(Serialize)]
pub struct ToolResult {
    pub content: Vec<ToolContent>,
    #[serde(rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

/// A single content block inside a `ToolResult`.
#[derive(Serialize)]
pub struct ToolContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

impl ToolResult {
    /// Plain-text result.
    pub fn text(s: String) -> Self {
        Self {
            content: vec![ToolContent {
                content_type: "text".to_string(),
                text: s,
            }],
            is_error: None,
        }
    }

    /// Serialize any `Serialize` value into pretty-printed JSON text.
    pub fn json(v: &impl Serialize) -> Self {
        let text = serde_json::to_string_pretty(v).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e));
        Self {
            content: vec![ToolContent {
                content_type: "text".to_string(),
                text,
            }],
            is_error: None,
        }
    }

    /// Error result — sets `isError` to `true`.
    pub fn error(msg: String) -> Self {
        Self {
            content: vec![ToolContent {
                content_type: "text".to_string(),
                text: msg,
            }],
            is_error: Some(true),
        }
    }
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

/// Descriptor returned by `resources/list`.
#[derive(Serialize, Clone)]
pub struct Resource {
    pub uri: String,
    pub name: String,
    pub description: String,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
}

/// Content payload returned by `resources/read`.
#[derive(Serialize)]
pub struct ResourceContent {
    pub uri: String,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    pub text: String,
}

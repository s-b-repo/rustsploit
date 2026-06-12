use std::sync::Arc;

use anyhow::Context;
use serde_json::{Map, Value};

use rmcp::{
    ErrorData as McpError, ServerHandler, serve_server,
    model::{
        AnnotateAble, CallToolRequestParams, CallToolResult, Content, Implementation,
        InitializeResult, ListResourcesResult, ListToolsResult, PaginatedRequestParams, RawResource,
        ReadResourceRequestParams, ReadResourceResult, Resource, ResourceContents,
        ServerCapabilities, ServerInfo, Tool,
    },
    service::{RequestContext, RoleServer},
};

/// Read the libc errno value for the current thread, in a portable way.
fn errno() -> i32 {
    // SAFETY: `__errno_location` / `__error` return a valid pointer to a
    // thread-local int that remains valid for the duration of the thread; a
    // single `*ptr` read of a primitive `c_int` cannot violate any invariant.
    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    unsafe { *libc::__error() }

    #[cfg(target_os = "linux")]
    // SAFETY: see comment above; `__errno_location` mirrors the BSD `__error`.
    unsafe { *libc::__errno_location() }

    // Fallback for other Unixes: errno isn't reliably accessible without a
    // platform-specific symbol, so callers will see `0`.
    #[cfg(not(any(target_os = "freebsd", target_os = "macos", target_os = "linux")))]
    { 0 }
}

/// Save the original stdout (fd 1) into a new fd, then redirect fd 1 to
/// `/dev/null`. The returned tokio file is the *only* remaining handle to the
/// original stdout — used by the MCP server to emit JSON-RPC responses on a
/// channel that user-mode `println!` calls can no longer corrupt.
fn isolate_protocol_stdout() -> anyhow::Result<tokio::fs::File> {
    use std::os::fd::FromRawFd;

    // SAFETY: `dup(1)` is a no-arg syscall that returns either a fresh valid
    // fd or -1. We immediately check the return value before doing anything
    // that depends on its validity.
    let saved_fd = unsafe { libc::dup(1) };
    if saved_fd < 0 {
        anyhow::bail!("dup(1) failed: errno {}", errno());
    }

    let null_path = b"/dev/null\0";
    // SAFETY: `null_path` is a NUL-terminated, statically-allocated byte
    // string with a pointer valid for the duration of the call; `O_WRONLY` is
    // a libc-defined constant. `open` returns -1 on failure, checked below.
    let null_fd = unsafe {
        libc::open(null_path.as_ptr() as *const libc::c_char, libc::O_WRONLY)
    };
    if null_fd < 0 {
        // SAFETY: `saved_fd` is a valid open fd we just received from `dup`.
        unsafe { libc::close(saved_fd); }
        anyhow::bail!("open(/dev/null) failed: errno {}", errno());
    }

    // SAFETY: `null_fd` and `1` are both valid open fds (1 is stdout; the
    // dup above proved it is open and non-error). `dup2` either succeeds and
    // installs `null_fd` as fd 1, or returns -1.
    let dup2_ret = unsafe { libc::dup2(null_fd, 1) };
    if dup2_ret < 0 {
        // SAFETY: both fds are valid open descriptors at this point.
        unsafe {
            libc::close(null_fd);
            libc::close(saved_fd);
        }
        anyhow::bail!("dup2(null, 1) failed: errno {}", errno());
    }
    // SAFETY: `null_fd` is a valid open fd; closing the source after a
    // successful `dup2` is the standard idiom — fd 1 keeps the kernel-side
    // open file description alive.
    unsafe { libc::close(null_fd); }

    // SAFETY: `saved_fd` is owned by us (returned by `dup`, never close()d
    // here, never given to anyone else); transferring it into a `File` makes
    // that file the sole owner so the eventual Drop closes it exactly once.
    let std_file = unsafe { std::fs::File::from_raw_fd(saved_fd) };
    Ok(tokio::fs::File::from_std(std_file))
}

/// Per-tool-call execution budget. A single hung/slow tool must not be able to
/// wedge the server forever, so `tools/call` dispatch is bounded by this
/// timeout and returns a JSON-RPC error on expiry. Override via the
/// `RUSTSPLOIT_MCP_TIMEOUT_SECS` env var (0 disables the cap).
fn module_timeout() -> Option<std::time::Duration> {
    match std::env::var("RUSTSPLOIT_MCP_TIMEOUT_SECS") {
        Ok(v) => match v.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(secs) => Some(std::time::Duration::from_secs(secs)),
            // Unparseable override falls back to the default rather than panicking.
            Err(_) => Some(std::time::Duration::from_secs(300)),
        },
        Err(_) => Some(std::time::Duration::from_secs(300)),
    }
}

/// Run the MCP server over the official `rmcp` SDK on a stdio transport.
///
/// The protocol channel (JSON-RPC over the original stdout) is isolated from
/// fd 1 first, so stray `println!` from library code cannot corrupt the stream;
/// fd 1 is redirected to `/dev/null` and the saved descriptor becomes the
/// transport's writer. Module output is captured through `OUTPUT_BUFFER`.
pub async fn run_mcp_server() -> anyhow::Result<()> {
    let protocol_out = isolate_protocol_stdout()
        .context("Cannot isolate protocol stdout — aborting to prevent JSON-RPC corruption")?;

    eprintln!("[MCP] RustSploit MCP server started (rmcp SDK, stdio transport)");
    eprintln!("[MCP] Protocol stdout isolated — module output is captured via OUTPUT_BUFFER only");

    // `(reader, writer)` is an rmcp async-RW transport. stdin is the request
    // stream; the saved real-stdout file is the response sink.
    let transport = (tokio::io::stdin(), protocol_out);

    let service = serve_server(RustsploitHandler, transport)
        .await
        .context("MCP server initialization (initialize handshake) failed")?;

    // Block until the client disconnects (stdin EOF) or the connection ends.
    let quit_reason = service
        .waiting()
        .await
        .context("MCP server task failed to join cleanly")?;

    eprintln!("[MCP] server stopped: {quit_reason:?}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Handler — adapts the existing tool/resource registry to rmcp's traits.
// ---------------------------------------------------------------------------

/// Stateless MCP handler. All state lives behind the per-tenant stores reached
/// inside `tools::call_tool` / `resources::read_resource`, so this is a unit.
#[derive(Clone)]
struct RustsploitHandler;

impl ServerHandler for RustsploitHandler {
    fn get_info(&self) -> ServerInfo {
        let capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_resources()
            .build();

        InitializeResult::new(capabilities)
            .with_server_info(Implementation::new(
                "rustsploit-mcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "RustSploit offensive-security framework over MCP. Discover modules with \
                 `list_modules` / `search_modules` / `module_info`, set a scope with \
                 `set_target`, then execute with `run_module` (set `background: true` for \
                 long-running scans and poll `list_jobs`). Live engagement state is exposed \
                 as resources under the `rustsploit:///` URI scheme.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let tools = super::tools::all_tools()
            .into_iter()
            .map(to_rmcp_tool)
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let name = request.name.to_string();
        // rmcp delivers arguments as `Option<JsonObject>`; the existing
        // dispatcher expects a JSON `Value` (defaulting to `{}` when absent).
        let arguments = match request.arguments {
            Some(map) => Value::Object(map),
            None => Value::Object(Map::new()),
        };

        // Bound execution so one hung tool cannot wedge the server. On expiry,
        // surface a JSON-RPC error instead of blocking the connection.
        let result = match module_timeout() {
            Some(dur) => {
                match tokio::time::timeout(dur, super::tools::call_tool(&name, arguments)).await {
                    Ok(r) => r,
                    Err(_) => {
                        eprintln!(
                            "[MCP] tool '{}' exceeded {}s timeout — aborting call",
                            name,
                            dur.as_secs()
                        );
                        return Err(McpError::internal_error(
                            format!("Tool '{}' timed out after {} seconds", name, dur.as_secs()),
                            None,
                        ));
                    }
                }
            }
            None => super::tools::call_tool(&name, arguments).await,
        };

        Ok(to_rmcp_tool_result(result))
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let resources = super::resources::all_resources()
            .into_iter()
            .map(to_rmcp_resource)
            .collect();
        Ok(ListResourcesResult::with_all_items(resources))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        let content = super::resources::read_resource(&request.uri).await;
        let contents = ResourceContents::TextResourceContents {
            uri: content.uri,
            mime_type: Some(content.mime_type),
            text: content.text,
            meta: None,
        };
        Ok(ReadResourceResult::new(vec![contents]))
    }
}

// ---------------------------------------------------------------------------
// Mapping helpers: internal registry types -> rmcp model types.
// ---------------------------------------------------------------------------

/// Map an internal tool descriptor to an rmcp `Tool`. The hand-authored
/// `inputSchema` JSON is reused verbatim (rmcp expects a JSON-Schema object).
fn to_rmcp_tool(t: super::types::Tool) -> Tool {
    let schema: Map<String, Value> = match t.input_schema {
        Value::Object(map) => map,
        // A non-object schema is malformed; advertise an empty object rather
        // than panicking so the rest of the tool list still loads.
        _ => Map::new(),
    };
    Tool::new(t.name, t.description, Arc::new(schema))
}

/// Map an internal tool result to rmcp's `CallToolResult`. All internal content
/// blocks are text; `is_error` selects the error vs. success constructor.
fn to_rmcp_tool_result(r: super::types::ToolResult) -> CallToolResult {
    let content: Vec<Content> = r
        .content
        .into_iter()
        .map(|c| Content::text(c.text))
        .collect();
    if r.is_error == Some(true) {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    }
}

/// Map an internal resource descriptor to an rmcp `Resource`.
fn to_rmcp_resource(res: super::types::Resource) -> Resource {
    RawResource::new(res.uri, res.name)
        .with_description(res.description)
        .with_mime_type(res.mime_type)
        .no_annotation()
}

use std::process::Stdio;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// MCP client that communicates with an external MCP server over stdio JSON-RPC.
pub struct McpClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl McpClient {
    /// Spawn an MCP server subprocess and prepare for JSON-RPC communication.
    pub async fn connect(command: &str, args: &[&str]) -> Result<Self> {
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("Failed to spawn MCP server: {} {:?}", command, args))?;

        let stdin = child
            .stdin
            .take()
            .context("Failed to capture child stdin")?;
        let stdout_raw = child
            .stdout
            .take()
            .context("Failed to capture child stdout")?;
        let stdout = BufReader::new(stdout_raw);

        Ok(Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        })
    }

    /// Send the `initialize` handshake and return the server capabilities.
    pub async fn initialize(&mut self) -> Result<Value> {
        let id = self.next_id();
        send_request(
            &mut self.stdin,
            &mut self.stdout,
            id,
            "initialize",
            Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "rustsploit-mcp-client",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
        )
        .await
    }

    /// List all tools offered by the remote server.
    pub async fn list_tools(&mut self) -> Result<Vec<Value>> {
        let id = self.next_id();
        let result = send_request(&mut self.stdin, &mut self.stdout, id, "tools/list", None).await?;
        let tools = result
            .get("tools")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(tools)
    }

    /// Call a tool on the remote server (30s timeout).
    pub async fn call_tool(&mut self, name: &str, args: Value) -> Result<Value> {
        let id = self.next_id();
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            send_request(
                &mut self.stdin,
                &mut self.stdout,
                id,
                "tools/call",
                Some(json!({
                    "name": name,
                    "arguments": args
                })),
            ),
        )
        .await
        .context("MCP tool call timed out after 30s")?
    }

    /// List all resources offered by the remote server.
    pub async fn list_resources(&mut self) -> Result<Vec<Value>> {
        let id = self.next_id();
        let result =
            send_request(&mut self.stdin, &mut self.stdout, id, "resources/list", None).await?;
        let resources = result
            .get("resources")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(resources)
    }

    /// Read a resource by URI from the remote server.
    pub async fn read_resource(&mut self, uri: &str) -> Result<Value> {
        let id = self.next_id();
        send_request(
            &mut self.stdin,
            &mut self.stdout,
            id,
            "resources/read",
            Some(json!({ "uri": uri })),
        )
        .await
    }

    /// Shut down the MCP server subprocess gracefully.
    pub async fn close(mut self) -> Result<()> {
        drop(self.stdin);
        match tokio::time::timeout(std::time::Duration::from_secs(5), self.child.wait()).await {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) => {
                eprintln!("[!] MCP server wait error: {}", e);
            }
            Err(_) => {
                eprintln!("[!] MCP server did not exit within 5s, killing");
            }
        }
        if let Err(e) = self.child.kill().await {
            eprintln!("[!] Failed to kill MCP server: {}", e);
        }
        Ok(())
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

/// Send a JSON-RPC 2.0 request and read the response.
async fn send_request(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<ChildStdout>,
    id: u64,
    method: &str,
    params: Option<Value>,
) -> Result<Value> {
    // Build the JSON-RPC request object
    let mut request = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
    });
    if let Some(p) = params {
        if let Some(obj) = request.as_object_mut() {
            obj.insert("params".to_string(), p);
        }
    }

    // Serialize and send as a single line
    let line = serde_json::to_string(&request).context("Failed to serialize JSON-RPC request")?;
    stdin
        .write_all(line.as_bytes())
        .await
        .context("Failed to write to child stdin")?;
    stdin
        .write_all(b"\n")
        .await
        .context("Failed to write newline")?;
    stdin.flush().await.context("Failed to flush child stdin")?;

    // Read response lines until we get one with a matching id.
    // Servers may emit notifications (no id) interleaved with responses.
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = stdout
            .read_line(&mut buf)
            .await
            .context("Failed to read from child stdout")?;
        if n == 0 {
            anyhow::bail!("MCP server closed stdout before responding to request {}", id);
        }

        let trimmed = buf.trim();
        if trimmed.is_empty() {
            continue;
        }

        let response: Value =
            serde_json::from_str(trimmed).context("Failed to parse JSON-RPC response")?;

        // Check if this is a response (has "id") matching our request
        if let Some(resp_id) = response.get("id") {
            if resp_id.as_u64() == Some(id) {
                // Check for error
                if let Some(error) = response.get("error") {
                    let msg = error
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown error");
                    let code = error.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
                    anyhow::bail!("MCP server error (code {}): {}", code, msg);
                }
                // Return the result field
                return Ok(response.get("result").cloned().unwrap_or(Value::Null));
            }
        }
        // Not our response (notification or different id) -- skip and keep reading
    }
}

# MCP Integration

Rustsploit includes a built-in MCP (Model Context Protocol) server that enables integration with Claude Desktop and other MCP-compatible clients. The server communicates via JSON-RPC 2.0 over stdio (stdin/stdout), with no network listener.

---

## Starting the MCP Server

```bash
cargo run -- --mcp
```

The server reads one JSON-RPC 2.0 request per line from stdin and writes one response per line to stdout. Diagnostic messages go to stderr.

---

## Protocol

- **Transport**: Newline-delimited JSON over stdio
- **Protocol version**: `2024-11-05`
- **Capabilities**: `tools`, `resources`
- **Server name**: `rustsploit-mcp`

### Supported JSON-RPC Methods

| Method | Type | Description |
|--------|------|-------------|
| `initialize` | Request | Capability negotiation handshake |
| `initialized` | Notification | Client acknowledgement (no response) |
| `tools/list` | Request | List all available tools |
| `tools/call` | Request | Execute a tool by name |
| `resources/list` | Request | List all available resources |
| `resources/read` | Request | Read a resource by URI |

---

## Tools (30)

### Module Tools

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_modules` | List all available modules, optionally filtered by category | -- |
| `search_modules` | Search modules by keyword (case-insensitive substring match) | `query` |
| `module_info` | Get metadata for a specific module (name, description, authors, references, rank) | `module_path` |
| `check_module` | Run a non-destructive vulnerability check against a target | `module_path`, `target` |

### Target Tools

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `set_target` | Set the global target (IP, hostname, CIDR, or comma-separated list) | `target` |
| `get_target` | Get the current global target, size, and subnet status | -- |
| `clear_target` | Clear the global target | -- |

### Execution

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `run_module` | Execute a module against a target, returning captured output | `module_path`, `target` |

Optional params for `run_module`: `port` (integer), `verbose` (boolean), `prompts` (object of key-value string overrides).

### Credential Tools

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_creds` | List all stored credentials | -- |
| `search_creds` | Search credentials by host, service, or username | `query` |
| `add_cred` | Add a credential to the store | `host`, `username`, `secret` |
| `delete_cred` | Delete a credential by its ID | `id` |

Optional params for `add_cred`: `port` (integer), `service` (string), `cred_type` (password/hash/key/token).

### Workspace Host and Service Tools

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_hosts` | List all tracked hosts in the current workspace | -- |
| `add_host` | Add or update a host in the workspace | `ip` |
| `delete_host` | Delete a host (and its services) from the workspace | `ip` |
| `list_services` | List all tracked services in the current workspace | -- |
| `add_service` | Add or update a service in the workspace | `host`, `port`, `service_name` |
| `delete_service` | Delete a service by host and port | `host`, `port` |

Optional params for `add_host`: `hostname`, `os_guess`. Optional params for `add_service`: `protocol` (default: tcp), `version`.

### Loot Tools

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_loot` | List all stored loot entries | -- |
| `search_loot` | Search loot by host, type, or description | `query` |
| `add_loot` | Store a loot entry (text data) | `host`, `loot_type`, `data` |
| `delete_loot` | Delete a loot entry by ID | `id` |

Optional params for `add_loot`: `description`.

### Global Options Tools

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_options` | List all persistent global options (setg values) | -- |
| `set_option` | Set a persistent global option | `key`, `value` |
| `unset_option` | Remove a persistent global option | `key` |

### Job Tools

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_jobs` | List active background jobs | -- |
| `kill_job` | Kill a background job by ID | `id` (integer) |

### Workspace Management Tools

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_workspaces` | List all available workspaces | -- |
| `switch_workspace` | Switch to a different workspace (creates if needed) | `name` |

### Export

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `export_data` | Export full engagement data as JSON | -- |

---

## Resources (7)

Resources provide read-only access to framework state.

| URI | Name | Description | MIME Type |
|-----|------|-------------|-----------|
| `rustsploit:///modules` | Module Catalog | Full module list with `info()` metadata | `application/json` |
| `rustsploit:///workspace` | Current Workspace | Tracked hosts and services | `application/json` |
| `rustsploit:///credentials` | Credentials | Credential list with secrets redacted | `application/json` |
| `rustsploit:///loot` | Loot Catalog | Loot metadata (no file content) | `application/json` |
| `rustsploit:///options` | Global Options | Persistent setg key-value pairs | `application/json` |
| `rustsploit:///target` | Current Target | Target value, size, and subnet flag | `application/json` |
| `rustsploit:///status` | Framework Status | Module count, workspace, host/cred/loot counts | `application/json` |

---

## Claude Desktop Configuration

Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "rustsploit": {
      "command": "/path/to/rustsploit",
      "args": ["--mcp"]
    }
  }
}
```

Replace `/path/to/rustsploit` with the absolute path to your compiled binary (e.g., `target/release/rustsploit`).

---

## Security

- **Stdio transport only** -- no network listener, no authentication needed (single-user process)
- **Target injection prevention** -- `run_module` strips any `target` key from the `prompts` object to prevent SSRF via prompt injection
- **Module validation** -- module paths are verified against the build-time discovered module list before execution
- **Credential redaction** -- the `rustsploit:///credentials` resource shows only the first 3 characters of each secret
- **No file system writes** -- MCP tools return data inline; no direct file read/write operations are exposed
- **Concurrency bounded** -- module execution is limited by the framework's semaphore (CPU count, minimum 4 concurrent)

---

## Architecture

```
src/mcp/
  mod.rs         -- Module re-exports
  types.rs       -- JSON-RPC 2.0 types, MCP capability structs, Tool/Resource/ToolResult types
  server.rs      -- Stdio event loop, request routing, response serialization
  tools.rs       -- 30 tool definitions and dispatch handlers
  resources.rs   -- 7 resource definitions and read handlers
  client.rs      -- MCP client implementation (for connecting to external MCP servers)
```

### Request Flow

1. `server.rs` reads a JSON line from stdin
2. Parses it as a `JsonRpcRequest`
3. Routes by method name: `initialize`, `tools/list`, `tools/call`, `resources/list`, `resources/read`
4. Handler extracts typed parameters from `params`
5. Calls framework APIs (same functions used by the REST API and interactive shell)
6. Returns a `JsonRpcResponse` serialized as a single JSON line on stdout

---

## Example Session

```
-> {"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
<- {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{},"resources":{}},"serverInfo":{"name":"rustsploit-mcp","version":"0.4.8"}}}

-> {"jsonrpc":"2.0","method":"initialized","params":{}}

-> {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
<- {"jsonrpc":"2.0","id":2,"result":{"tools":[...]}}

-> {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"set_target","arguments":{"target":"192.168.1.1"}}}
<- {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Target set to: 192.168.1.1"}]}}

-> {"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"rustsploit:///status"}}
<- {"jsonrpc":"2.0","id":4,"result":{"uri":"rustsploit:///status","mimeType":"application/json","text":"{...}"}}
```

---

> The MCP server uses the same framework internals as the REST API and interactive shell. Module execution, credential storage, workspace tracking, and all other operations produce identical results regardless of the interface used.

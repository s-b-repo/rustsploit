use std::collections::HashMap;

use once_cell::sync::Lazy;
use serde_json::{json, Value};

use super::types::{Tool, ToolResult};

/// Cached tool definitions — built once, reused on every tools/list call.
static TOOL_DEFINITIONS: Lazy<Vec<Tool>> = Lazy::new(build_tool_definitions);

/// Return definitions for all MCP tools (cached).
pub fn all_tools() -> Vec<Tool> {
    TOOL_DEFINITIONS.clone()
}

fn build_tool_definitions() -> Vec<Tool> {
    vec![
        // ── Module tools ──────────────────────────────────────────────
        Tool {
            name: "list_modules".into(),
            description: "List all available modules, optionally filtered by category".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "category": { "type": "string", "description": "Filter by category (exploits, scanners, creds, plugins)" }
                }
            }),
        },
        Tool {
            name: "search_modules".into(),
            description: "Search modules by keyword (case-insensitive substring match)".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Search query" }
                },
                "required": ["query"]
            }),
        },
        Tool {
            name: "module_info".into(),
            description: "Get metadata for a specific module (name, description, authors, references, rank)".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "module_path": { "type": "string", "description": "Full module path, e.g. exploits/router_exploit" }
                },
                "required": ["module_path"]
            }),
        },
        Tool {
            name: "check_module".into(),
            description: "Run a non-destructive vulnerability check against a target".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "module_path": { "type": "string", "description": "Full module path" },
                    "target": { "type": "string", "description": "Target IP, hostname, or CIDR" }
                },
                "required": ["module_path", "target"]
            }),
        },
        // ── Target tools ──────────────────────────────────────────────
        Tool {
            name: "set_target".into(),
            description: "Set the global target (IP, hostname, CIDR subnet, or comma-separated list)".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target value" }
                },
                "required": ["target"]
            }),
        },
        Tool {
            name: "get_target".into(),
            description: "Get the current global target, its size, and whether it is a subnet".into(),
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "clear_target".into(),
            description: "Clear the global target".into(),
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        // ── Execution ─────────────────────────────────────────────────
        Tool {
            name: "run_module".into(),
            description: "Execute a module against a target, returning captured output".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "module_path": { "type": "string", "description": "Full module path" },
                    "target": { "type": "string", "description": "Target IP, hostname, or CIDR" },
                    "port": { "type": "integer", "description": "Optional port override" },
                    "verbose": { "type": "boolean", "description": "Enable verbose output" },
                    "prompts": {
                        "type": "object",
                        "description": "Key-value prompt overrides (e.g. {\"port\": \"8080\", \"timeout\": \"5\"})",
                        "additionalProperties": { "type": "string" }
                    }
                },
                "required": ["module_path", "target"]
            }),
        },
        // ── Credentials ───────────────────────────────────────────────
        Tool {
            name: "list_creds".into(),
            description: "List all stored credentials".into(),
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "search_creds".into(),
            description: "Search credentials by host, service, or username".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Search query" }
                },
                "required": ["query"]
            }),
        },
        Tool {
            name: "add_cred".into(),
            description: "Add a credential to the store".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "host": { "type": "string" },
                    "username": { "type": "string" },
                    "secret": { "type": "string" },
                    "port": { "type": "integer", "default": 0 },
                    "service": { "type": "string", "default": "unknown" },
                    "cred_type": { "type": "string", "enum": ["password", "hash", "key", "token"], "default": "password" }
                },
                "required": ["host", "username", "secret"]
            }),
        },
        Tool {
            name: "delete_cred".into(),
            description: "Delete a credential by its ID".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "description": "Credential ID" }
                },
                "required": ["id"]
            }),
        },
        // ── Workspace hosts & services ────────────────────────────────
        Tool {
            name: "list_hosts".into(),
            description: "List all tracked hosts in the current workspace".into(),
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "add_host".into(),
            description: "Add or update a host in the workspace".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "ip": { "type": "string" },
                    "hostname": { "type": "string" },
                    "os_guess": { "type": "string" }
                },
                "required": ["ip"]
            }),
        },
        Tool {
            name: "delete_host".into(),
            description: "Delete a host (and its services) from the workspace".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "ip": { "type": "string" }
                },
                "required": ["ip"]
            }),
        },
        Tool {
            name: "list_services".into(),
            description: "List all tracked services in the current workspace".into(),
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "add_service".into(),
            description: "Add or update a service in the workspace".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "host": { "type": "string" },
                    "port": { "type": "integer" },
                    "service_name": { "type": "string" },
                    "protocol": { "type": "string", "default": "tcp" },
                    "version": { "type": "string" }
                },
                "required": ["host", "port", "service_name"]
            }),
        },
        Tool {
            name: "delete_service".into(),
            description: "Delete a service by host and port".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "host": { "type": "string" },
                    "port": { "type": "integer" }
                },
                "required": ["host", "port"]
            }),
        },
        // ── Loot ──────────────────────────────────────────────────────
        Tool {
            name: "list_loot".into(),
            description: "List all stored loot entries".into(),
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "search_loot".into(),
            description: "Search loot by host, type, or description".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                },
                "required": ["query"]
            }),
        },
        Tool {
            name: "add_loot".into(),
            description: "Store a loot entry (text data)".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "host": { "type": "string" },
                    "loot_type": { "type": "string", "description": "e.g. config, password_file, hash, firmware" },
                    "data": { "type": "string", "description": "Loot content (text)" },
                    "description": { "type": "string" }
                },
                "required": ["host", "loot_type", "data"]
            }),
        },
        Tool {
            name: "delete_loot".into(),
            description: "Delete a loot entry by ID".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" }
                },
                "required": ["id"]
            }),
        },
        // ── Global options ────────────────────────────────────────────
        Tool {
            name: "list_options".into(),
            description: "List all persistent global options (setg values)".into(),
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "set_option".into(),
            description: "Set a persistent global option".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "key": { "type": "string" },
                    "value": { "type": "string" }
                },
                "required": ["key", "value"]
            }),
        },
        Tool {
            name: "unset_option".into(),
            description: "Remove a persistent global option".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "key": { "type": "string" }
                },
                "required": ["key"]
            }),
        },
        // ── Jobs ──────────────────────────────────────────────────────
        Tool {
            name: "list_jobs".into(),
            description: "List active background jobs".into(),
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "kill_job".into(),
            description: "Kill a background job by ID".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "integer" }
                },
                "required": ["id"]
            }),
        },
        // ── Workspace management ──────────────────────────────────────
        Tool {
            name: "list_workspaces".into(),
            description: "List all available workspaces".into(),
            input_schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "switch_workspace".into(),
            description: "Switch to a different workspace (creates it if it does not exist)".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" }
                },
                "required": ["name"]
            }),
        },
        // ── Export ────────────────────────────────────────────────────
        Tool {
            name: "export_data".into(),
            description: "Export full engagement data (workspace, hosts, services, credentials, loot) as JSON".into(),
            input_schema: json!({ "type": "object", "properties": {} }),
        },
    ]
}

// ===========================================================================
// Tool dispatch
// ===========================================================================

/// Dispatch a tool call by name.
pub async fn call_tool(name: &str, args: Value) -> ToolResult {
    match name {
        // ── Module tools ──────────────────────────────────────────
        "list_modules" => handle_list_modules(&args),
        "search_modules" => handle_search_modules(&args),
        "module_info" => handle_module_info(&args),
        "check_module" => handle_check_module(&args).await,

        // ── Target tools ──────────────────────────────────────────
        "set_target" => handle_set_target(&args).await,
        "get_target" => handle_get_target(),
        "clear_target" => handle_clear_target(),

        // ── Execution ─────────────────────────────────────────────
        "run_module" => handle_run_module(&args).await,

        // ── Credentials ───────────────────────────────────────────
        "list_creds" => handle_list_creds().await,
        "search_creds" => handle_search_creds(&args).await,
        "add_cred" => handle_add_cred(&args).await,
        "delete_cred" => handle_delete_cred(&args).await,

        // ── Workspace hosts & services ────────────────────────────
        "list_hosts" => handle_list_hosts().await,
        "add_host" => handle_add_host(&args).await,
        "delete_host" => handle_delete_host(&args).await,
        "list_services" => handle_list_services().await,
        "add_service" => handle_add_service(&args).await,
        "delete_service" => handle_delete_service(&args).await,

        // ── Loot ──────────────────────────────────────────────────
        "list_loot" => handle_list_loot().await,
        "search_loot" => handle_search_loot(&args).await,
        "add_loot" => handle_add_loot(&args).await,
        "delete_loot" => handle_delete_loot(&args).await,

        // ── Global options ────────────────────────────────────────
        "list_options" => handle_list_options().await,
        "set_option" => handle_set_option(&args).await,
        "unset_option" => handle_unset_option(&args).await,

        // ── Jobs ──────────────────────────────────────────────────
        "list_jobs" => handle_list_jobs(),
        "kill_job" => handle_kill_job(&args),

        // ── Workspace management ──────────────────────────────────
        "list_workspaces" => handle_list_workspaces().await,
        "switch_workspace" => handle_switch_workspace(&args).await,

        // ── Export ────────────────────────────────────────────────
        "export_data" => handle_export_data().await,

        _ => ToolResult::error(format!("Unknown tool: {}", name)),
    }
}

// ===========================================================================
// Helpers to extract typed values from serde_json::Value
// ===========================================================================

/// Extract a required string parameter, returning ToolResult::error if missing.
macro_rules! require_str {
    ($args:expr, $key:expr) => {
        match str_param($args, $key) {
            Some(v) => v,
            None => return ToolResult::error(format!("Missing required parameter: {}", $key)),
        }
    };
}

fn str_param<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str())
}

fn u16_param(args: &Value, key: &str) -> Option<u16> {
    args.get(key).and_then(|v| v.as_u64()).map(|n| n as u16)
}

fn u32_param(args: &Value, key: &str) -> Option<u32> {
    args.get(key).and_then(|v| v.as_u64()).map(|n| n as u32)
}

fn bool_param(args: &Value, key: &str) -> Option<bool> {
    args.get(key).and_then(|v| v.as_bool())
}

fn prompts_param(args: &Value) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(obj) = args.get("prompts").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                map.insert(k.clone(), s.to_string());
            }
        }
    }
    map
}

// ===========================================================================
// Individual tool handlers
// ===========================================================================

// ── Module tools ──────────────────────────────────────────────────────────

fn handle_list_modules(args: &Value) -> ToolResult {
    let modules = crate::commands::discover_modules();
    let filtered: Vec<&String> = if let Some(cat) = str_param(args, "category") {
        let prefix = format!("{}/", cat);
        modules.iter().filter(|m| m.starts_with(&prefix)).collect()
    } else {
        modules.iter().collect()
    };
    ToolResult::json(&filtered)
}

fn handle_search_modules(args: &Value) -> ToolResult {
    let query = require_str!(args, "query");
    let q_lower = query.to_lowercase();
    let modules = crate::commands::discover_modules();
    let matched: Vec<&String> = modules
        .iter()
        .filter(|m| m.to_lowercase().contains(&q_lower))
        .collect();
    ToolResult::json(&matched)
}

fn handle_module_info(args: &Value) -> ToolResult {
    let path = require_str!(args, "module_path");
    if !crate::api::validate_module_name(path) {
        return ToolResult::error("Invalid module name".into());
    }
    match crate::commands::module_info(path) {
        Some(info) => ToolResult::json(&info),
        None => ToolResult::error(format!("No info available for module '{}'", path)),
    }
}

async fn handle_check_module(args: &Value) -> ToolResult {
    let path = require_str!(args, "module_path");
    let target = require_str!(args, "target");
    if !crate::api::validate_module_name(path) {
        return ToolResult::error("Invalid module name".into());
    }
    if !crate::api::validate_target(target) {
        return ToolResult::error("Invalid target format".into());
    }
    if crate::api::is_blocked_target(target) {
        return ToolResult::error("Target matches blocked address range".into());
    }
    if crate::api::is_blocked_target_resolved(target).await {
        return ToolResult::error("Target resolves to a blocked metadata/link-local address".into());
    }
    match crate::commands::check_module(path, target).await {
        Some(result) => ToolResult::json(&result),
        None => ToolResult::error(format!("Module '{}' does not support check", path)),
    }
}

// ── Target tools ──────────────────────────────────────────────────────────

async fn handle_set_target(args: &Value) -> ToolResult {
    let target = require_str!(args, "target");
    if !crate::api::validate_target(target) {
        return ToolResult::error("Invalid target format".into());
    }
    if crate::api::is_blocked_target(target) {
        return ToolResult::error("Target matches blocked address range".into());
    }
    if crate::api::is_blocked_target_resolved(target).await {
        return ToolResult::error("Target resolves to blocked address".into());
    }
    match crate::config::GLOBAL_CONFIG.set_target(target) {
        Ok(()) => ToolResult::text(format!("Target set to: {}", target)),
        Err(e) => ToolResult::error(format!("Failed to set target: {}", e)),
    }
}

fn handle_get_target() -> ToolResult {
    let target = crate::config::GLOBAL_CONFIG.get_target();
    let size = crate::config::GLOBAL_CONFIG.get_target_size();
    let is_subnet = crate::config::GLOBAL_CONFIG.is_subnet();
    ToolResult::json(&json!({
        "target": target,
        "size": size,
        "is_subnet": is_subnet,
    }))
}

fn handle_clear_target() -> ToolResult {
    crate::config::GLOBAL_CONFIG.clear_target();
    ToolResult::text("Target cleared".into())
}

// ── Execution ─────────────────────────────────────────────────────────────

async fn handle_run_module(args: &Value) -> ToolResult {
    let module_path = require_str!(args, "module_path").to_string();
    let target = require_str!(args, "target").to_string();
    let verbose = bool_param(args, "verbose").unwrap_or(false);

    if !crate::api::validate_module_name(&module_path) {
        return ToolResult::error("Invalid module name".into());
    }
    if !crate::api::validate_target(&target) {
        return ToolResult::error("Invalid target format".into());
    }
    if crate::api::is_blocked_target(&target) {
        return ToolResult::error("Target matches blocked address range".into());
    }
    if crate::api::is_blocked_target_resolved(&target).await {
        return ToolResult::error("Target resolves to a blocked metadata/link-local address".into());
    }

    if !crate::commands::discover_modules().contains(&module_path) {
        return ToolResult::error(format!("Module '{}' not found", module_path));
    }

    let mut prompts = prompts_param(args);
    // Inject port into prompts if provided as a top-level parameter
    if let Some(port) = u16_param(args, "port") {
        prompts.entry("port".into()).or_insert_with(|| port.to_string());
    }
    // Strip "target" from prompts to prevent SSRF bypass via prompt injection
    prompts.remove("target");

    let module_config = crate::config::ModuleConfig {
        api_mode: true,
        custom_prompts: prompts,
        ..Default::default()
    };

    let output_buf = crate::output::OutputBuffer::new();
    let buf_clone = output_buf.clone();

    let (result, _ctx) = crate::context::run_with_context_target(
        module_config,
        target.clone(),
        || async {
            crate::output::OUTPUT_BUFFER
                .scope(buf_clone, async {
                    crate::commands::run_module(&module_path, &target, verbose).await
                })
                .await
        },
    )
    .await;

    let stdout = output_buf.drain_stdout();
    let stderr = output_buf.drain_stderr();

    match result {
        Ok(()) => {
            let mut text = stdout;
            if !stderr.is_empty() {
                text.push_str("\n--- stderr ---\n");
                text.push_str(&stderr);
            }
            if text.is_empty() {
                text = "Module completed successfully (no output captured)".into();
            }
            ToolResult::text(text)
        }
        Err(e) => {
            let mut msg = format!("Module error: {}\n", e);
            if !stdout.is_empty() {
                msg.push_str("\n--- stdout ---\n");
                msg.push_str(&stdout);
            }
            if !stderr.is_empty() {
                msg.push_str("\n--- stderr ---\n");
                msg.push_str(&stderr);
            }
            ToolResult::error(msg)
        }
    }
}

// ── Credentials ───────────────────────────────────────────────────────────

async fn handle_list_creds() -> ToolResult {
    let creds = crate::cred_store::CRED_STORE.list().await;
    ToolResult::json(&creds)
}

async fn handle_search_creds(args: &Value) -> ToolResult {
    let query = require_str!(args, "query");
    let results = crate::cred_store::CRED_STORE.search(query).await;
    ToolResult::json(&results)
}

async fn handle_add_cred(args: &Value) -> ToolResult {
    let host = require_str!(args, "host");
    let username = require_str!(args, "username");
    let secret = require_str!(args, "secret");
    let port = match u16_param(args, "port") {
        Some(0) => return ToolResult::error("Port must be between 1 and 65535".into()),
        Some(p) => p,
        None => return ToolResult::error("Missing required parameter: port".into()),
    };
    let service = str_param(args, "service").unwrap_or("unknown");
    if host.len() > 4096 || host.chars().any(|c| c.is_control()) {
        return ToolResult::error("host too long (max 4096) or contains control characters".into());
    }
    if username.len() > 4096 || username.chars().any(|c| c.is_control()) {
        return ToolResult::error("username too long (max 4096) or contains control characters".into());
    }
    if secret.len() > 4096 {
        return ToolResult::error("secret too long (max 4096 chars)".into());
    }
    if service.len() > 4096 || service.chars().any(|c| c.is_control()) {
        return ToolResult::error("service too long (max 4096) or contains control characters".into());
    }
    let cred_type = match str_param(args, "cred_type").unwrap_or("password") {
        "hash" => crate::cred_store::CredType::Hash,
        "key" => crate::cred_store::CredType::Key,
        "token" => crate::cred_store::CredType::Token,
        _ => crate::cred_store::CredType::Password,
    };

    match crate::cred_store::CRED_STORE
        .add(host, port, service, username, secret, cred_type, "mcp")
        .await
    {
        Some(id) => ToolResult::json(&json!({ "id": id, "status": "added" })),
        None => ToolResult::error("Failed to add credential (store limit reached or I/O error)".into()),
    }
}

async fn handle_delete_cred(args: &Value) -> ToolResult {
    let id = require_str!(args, "id");
    if crate::cred_store::CRED_STORE.delete(id).await {
        ToolResult::text(format!("Credential {} deleted", id))
    } else {
        ToolResult::error(format!("Credential {} not found", id))
    }
}

// ── Workspace hosts & services ────────────────────────────────────────────

async fn handle_list_hosts() -> ToolResult {
    let hosts = crate::workspace::WORKSPACE.hosts().await;
    ToolResult::json(&hosts)
}

async fn handle_add_host(args: &Value) -> ToolResult {
    let ip = require_str!(args, "ip");
    if ip.len() > 256 || ip.chars().any(|c| c.is_control()) {
        return ToolResult::error("IP too long (max 256) or contains control characters".into());
    }
    let hostname = str_param(args, "hostname");
    if let Some(h) = hostname {
        if h.len() > 256 || h.chars().any(|c| c.is_control()) {
            return ToolResult::error("hostname too long (max 256) or contains control characters".into());
        }
    }
    let os_guess = str_param(args, "os_guess");
    if let Some(o) = os_guess {
        if o.len() > 256 || o.chars().any(|c| c.is_control()) {
            return ToolResult::error("os_guess too long (max 256) or contains control characters".into());
        }
    }
    crate::workspace::WORKSPACE
        .add_host(ip, hostname, os_guess)
        .await;
    ToolResult::text(format!("Host {} added/updated", ip))
}

async fn handle_delete_host(args: &Value) -> ToolResult {
    let ip = require_str!(args, "ip");
    if crate::workspace::WORKSPACE.delete_host(ip).await {
        ToolResult::text(format!("Host {} deleted", ip))
    } else {
        ToolResult::error(format!("Host {} not found", ip))
    }
}

async fn handle_list_services() -> ToolResult {
    let services = crate::workspace::WORKSPACE.services().await;
    ToolResult::json(&services)
}

async fn handle_add_service(args: &Value) -> ToolResult {
    let host = require_str!(args, "host");
    let port = match u16_param(args, "port") {
        Some(0) => return ToolResult::error("Port must be between 1 and 65535".into()),
        Some(v) => v,
        None => return ToolResult::error("Missing required parameter: port".into()),
    };
    if host.len() > 256 || host.chars().any(|c| c.is_control()) {
        return ToolResult::error("host too long (max 256) or contains control characters".into());
    }
    let service_name = require_str!(args, "service_name");
    let protocol = str_param(args, "protocol").unwrap_or("tcp");
    if protocol.len() > 256 || protocol.chars().any(|c| c.is_control()) {
        return ToolResult::error("protocol too long (max 256) or contains control characters".into());
    }
    let version = str_param(args, "version");
    crate::workspace::WORKSPACE
        .add_service(host, port, protocol, service_name, version)
        .await;
    ToolResult::text(format!("Service {}:{} ({}) added/updated", host, port, service_name))
}

async fn handle_delete_service(args: &Value) -> ToolResult {
    let host = require_str!(args, "host");
    let port = match u16_param(args, "port") {
        Some(v) => v,
        None => return ToolResult::error("Missing required parameter: port".into()),
    };
    if crate::workspace::WORKSPACE.delete_service(host, port).await {
        ToolResult::text(format!("Service {}:{} deleted", host, port))
    } else {
        ToolResult::error(format!("Service {}:{} not found", host, port))
    }
}

// ── Loot ──────────────────────────────────────────────────────────────────

async fn handle_list_loot() -> ToolResult {
    let loot = crate::loot::LOOT_STORE.list().await;
    ToolResult::json(&loot)
}

async fn handle_search_loot(args: &Value) -> ToolResult {
    let query = require_str!(args, "query");
    let results = crate::loot::LOOT_STORE.search(query).await;
    ToolResult::json(&results)
}

async fn handle_add_loot(args: &Value) -> ToolResult {
    let host = require_str!(args, "host");
    let loot_type = require_str!(args, "loot_type");
    let data = require_str!(args, "data");
    let description = str_param(args, "description").unwrap_or("");

    if host.len() > 256 || loot_type.len() > 256 {
        return ToolResult::error("host or loot_type too long (max 256)".into());
    }
    if description.len() > 4096 {
        return ToolResult::error("description too long (max 4096)".into());
    }
    const MAX_LOOT_DATA: usize = 100 * 1024 * 1024;
    if data.len() > MAX_LOOT_DATA {
        return ToolResult::error(format!("data too large ({} bytes, max {} MB)", data.len(), MAX_LOOT_DATA / 1024 / 1024));
    }

    match crate::loot::LOOT_STORE
        .add_text(host, loot_type, description, data, "mcp")
        .await
    {
        Some(id) => ToolResult::json(&json!({ "id": id, "status": "stored" })),
        None => ToolResult::error("Failed to store loot (validation or I/O error)".into()),
    }
}

async fn handle_delete_loot(args: &Value) -> ToolResult {
    let id = require_str!(args, "id");
    if crate::loot::LOOT_STORE.delete(id).await {
        ToolResult::text(format!("Loot {} deleted", id))
    } else {
        ToolResult::error(format!("Loot {} not found", id))
    }
}

// ── Global options ────────────────────────────────────────────────────────

async fn handle_list_options() -> ToolResult {
    let opts = crate::global_options::GLOBAL_OPTIONS.all().await;
    ToolResult::json(&opts)
}

async fn handle_set_option(args: &Value) -> ToolResult {
    let key = require_str!(args, "key");
    let value = require_str!(args, "value");
    if !crate::global_options::GLOBAL_OPTIONS.set(key, value).await {
        return ToolResult::error(format!("Failed to set '{}': key/value too long or entry limit reached", key));
    }
    ToolResult::text(format!("{} => {}", key, value))
}

async fn handle_unset_option(args: &Value) -> ToolResult {
    let key = require_str!(args, "key");
    if crate::global_options::GLOBAL_OPTIONS.unset(key).await {
        ToolResult::text(format!("Option '{}' removed", key))
    } else {
        ToolResult::error(format!("Option '{}' not found", key))
    }
}

// ── Jobs ──────────────────────────────────────────────────────────────────

fn handle_list_jobs() -> ToolResult {
    let jobs = crate::jobs::JOB_MANAGER.list();
    let entries: Vec<Value> = jobs
        .into_iter()
        .map(|(id, module, target, started, status)| {
            json!({
                "id": id,
                "module": module,
                "target": target,
                "started": started,
                "status": status,
            })
        })
        .collect();
    ToolResult::json(&entries)
}

fn handle_kill_job(args: &Value) -> ToolResult {
    let id = match u32_param(args, "id") {
        Some(v) => v,
        None => return ToolResult::error("Missing required parameter: id (integer)".into()),
    };
    if crate::jobs::JOB_MANAGER.kill(id) {
        ToolResult::text(format!("Job {} killed", id))
    } else {
        ToolResult::error(format!("Job {} not found", id))
    }
}

// ── Workspace management ──────────────────────────────────────────────────

async fn handle_list_workspaces() -> ToolResult {
    let workspaces = crate::workspace::WORKSPACE.list_workspaces().await;
    let current = crate::workspace::WORKSPACE.current_name().await;
    ToolResult::json(&json!({
        "workspaces": workspaces,
        "current": current,
    }))
}

async fn handle_switch_workspace(args: &Value) -> ToolResult {
    let name = require_str!(args, "name");
    if name.is_empty() || name.len() > 64
        || name.chars().any(|c| !c.is_alphanumeric() && c != '_' && c != '-')
    {
        return ToolResult::error("Workspace name must be 1-64 alphanumeric chars, dashes, or underscores".into());
    }
    crate::workspace::WORKSPACE.switch(name).await;
    ToolResult::text(format!("Switched to workspace: {}", name))
}

// ── Export ─────────────────────────────────────────────────────────────────

async fn handle_export_data() -> ToolResult {
    let workspace_name = crate::workspace::WORKSPACE.current_name().await;
    let workspace_data = crate::workspace::WORKSPACE.get_data().await;
    let creds = crate::cred_store::CRED_STORE.list().await;
    let loot = crate::loot::LOOT_STORE.list().await;

    ToolResult::json(&json!({
        "workspace": workspace_name,
        "exported_at": chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        "hosts": workspace_data.hosts,
        "services": workspace_data.services,
        "credentials": creds,
        "loot": loot,
    }))
}

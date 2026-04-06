use serde_json::json;

use super::types::{Resource, ResourceContent};

/// Return the list of all resources exposed by this MCP server.
pub fn all_resources() -> Vec<Resource> {
    vec![
        Resource {
            uri: "rustsploit:///modules".into(),
            name: "Module Catalog".into(),
            description: "Full list of available modules with info() metadata where available".into(),
            mime_type: "application/json".into(),
        },
        Resource {
            uri: "rustsploit:///workspace".into(),
            name: "Current Workspace".into(),
            description: "Current workspace data including tracked hosts and services".into(),
            mime_type: "application/json".into(),
        },
        Resource {
            uri: "rustsploit:///credentials".into(),
            name: "Credentials".into(),
            description: "Credential list with secrets redacted (first 3 chars + ***)".into(),
            mime_type: "application/json".into(),
        },
        Resource {
            uri: "rustsploit:///loot".into(),
            name: "Loot Catalog".into(),
            description: "Loot entry metadata (no file content, just index data)".into(),
            mime_type: "application/json".into(),
        },
        Resource {
            uri: "rustsploit:///options".into(),
            name: "Global Options".into(),
            description: "Persistent global options (setg key-value pairs)".into(),
            mime_type: "application/json".into(),
        },
        Resource {
            uri: "rustsploit:///target".into(),
            name: "Current Target".into(),
            description: "Current global target, size, and subnet status".into(),
            mime_type: "application/json".into(),
        },
        Resource {
            uri: "rustsploit:///status".into(),
            name: "Framework Status".into(),
            description: "Summary: module count, workspace name, host count, credential count, loot count".into(),
            mime_type: "application/json".into(),
        },
    ]
}

/// Read a resource by URI.
pub async fn read_resource(uri: &str) -> ResourceContent {
    match uri {
        "rustsploit:///modules" => read_modules().await,
        "rustsploit:///workspace" => read_workspace().await,
        "rustsploit:///credentials" => read_credentials().await,
        "rustsploit:///loot" => read_loot().await,
        "rustsploit:///options" => read_options().await,
        "rustsploit:///target" => read_target(),
        "rustsploit:///status" => read_status().await,
        _ => ResourceContent {
            uri: uri.to_string(),
            mime_type: "text/plain".into(),
            text: format!("Unknown resource: {}", uri),
        },
    }
}

// ===========================================================================
// Individual resource readers
// ===========================================================================

async fn read_modules() -> ResourceContent {
    let modules = crate::commands::discover_modules();

    // Build a catalog entry for each module, including info() metadata when available
    let catalog: Vec<serde_json::Value> = modules
        .iter()
        .map(|path| {
            let info = crate::commands::module_info(path);
            match info {
                Some(i) => json!({
                    "path": path,
                    "name": i.name,
                    "description": i.description,
                    "authors": i.authors,
                    "references": i.references,
                    "disclosure_date": i.disclosure_date,
                    "rank": format!("{}", i.rank),
                }),
                None => json!({
                    "path": path,
                }),
            }
        })
        .collect();

    let text = serde_json::to_string_pretty(&catalog).unwrap_or_else(|_| "[]".into());

    ResourceContent {
        uri: "rustsploit:///modules".into(),
        mime_type: "application/json".into(),
        text,
    }
}

async fn read_workspace() -> ResourceContent {
    let name = crate::workspace::WORKSPACE.current_name().await;
    let data = crate::workspace::WORKSPACE.get_data().await;

    let text = serde_json::to_string_pretty(&json!({
        "workspace": name,
        "hosts": data.hosts,
        "services": data.services,
    }))
    .unwrap_or_else(|_| "{}".into());

    ResourceContent {
        uri: "rustsploit:///workspace".into(),
        mime_type: "application/json".into(),
        text,
    }
}

async fn read_credentials() -> ResourceContent {
    let creds = crate::cred_store::CRED_STORE.list().await;

    // Redact secrets: show first 3 characters then ***
    let redacted: Vec<serde_json::Value> = creds
        .iter()
        .map(|c| {
            let redacted_secret = if c.secret.len() > 3 {
                format!("{}***", &c.secret[..3])
            } else {
                "***".into()
            };
            json!({
                "id": c.id,
                "host": c.host,
                "port": c.port,
                "service": c.service,
                "username": c.username,
                "secret": redacted_secret,
                "cred_type": format!("{}", c.cred_type),
                "source_module": c.source_module,
                "timestamp": c.timestamp,
                "valid": c.valid,
            })
        })
        .collect();

    let text = serde_json::to_string_pretty(&redacted).unwrap_or_else(|_| "[]".into());

    ResourceContent {
        uri: "rustsploit:///credentials".into(),
        mime_type: "application/json".into(),
        text,
    }
}

async fn read_loot() -> ResourceContent {
    let loot = crate::loot::LOOT_STORE.list().await;

    // Return metadata only (no file content)
    let entries: Vec<serde_json::Value> = loot
        .iter()
        .map(|l| {
            json!({
                "id": l.id,
                "host": l.host,
                "loot_type": l.loot_type,
                "filename": l.filename,
                "description": l.description,
                "source_module": l.source_module,
                "timestamp": l.timestamp,
            })
        })
        .collect();

    let text = serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".into());

    ResourceContent {
        uri: "rustsploit:///loot".into(),
        mime_type: "application/json".into(),
        text,
    }
}

async fn read_options() -> ResourceContent {
    let opts = crate::global_options::GLOBAL_OPTIONS.all().await;

    let text = serde_json::to_string_pretty(&opts).unwrap_or_else(|_| "{}".into());

    ResourceContent {
        uri: "rustsploit:///options".into(),
        mime_type: "application/json".into(),
        text,
    }
}

fn read_target() -> ResourceContent {
    let target = crate::config::GLOBAL_CONFIG.get_target();
    let size = crate::config::GLOBAL_CONFIG.get_target_size();
    let is_subnet = crate::config::GLOBAL_CONFIG.is_subnet();

    let text = serde_json::to_string_pretty(&json!({
        "target": target,
        "size": size,
        "is_subnet": is_subnet,
    }))
    .unwrap_or_else(|_| "{}".into());

    ResourceContent {
        uri: "rustsploit:///target".into(),
        mime_type: "application/json".into(),
        text,
    }
}

async fn read_status() -> ResourceContent {
    // Use get_data() for a single lock acquisition instead of separate hosts()/services() calls
    let workspace_name = crate::workspace::WORKSPACE.current_name().await;
    let ws_data = crate::workspace::WORKSPACE.get_data().await;
    let cred_count = crate::cred_store::CRED_STORE.list().await.len();
    let loot_count = crate::loot::LOOT_STORE.list().await.len();
    let module_count = crate::commands::discover_modules().len();
    let target = crate::config::GLOBAL_CONFIG.get_target();
    let job_count = crate::jobs::JOB_MANAGER.list().len();

    let text = serde_json::to_string_pretty(&json!({
        "module_count": module_count,
        "workspace": workspace_name,
        "host_count": ws_data.hosts.len(),
        "service_count": ws_data.services.len(),
        "credential_count": cred_count,
        "loot_count": loot_count,
        "active_jobs": job_count,
        "target": target,
    }))
    .unwrap_or_else(|_| "{}".into());

    ResourceContent {
        uri: "rustsploit:///status".into(),
        mime_type: "application/json".into(),
        text,
    }
}

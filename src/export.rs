use anyhow::{Result, Context};
use serde::Serialize;
use colored::*;
use std::io::Write;

/// Write data to a file, rejecting symlinks atomically with O_NOFOLLOW.
fn safe_write(path: &str, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .context(format!("Failed to open '{}' (symlinks not allowed)", path))?;
        file.write_all(data)
            .context(format!("Failed to write to '{}'", path))?;
        file.flush()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data).context(format!("Failed to write to '{}'", path))?;
        Ok(())
    }
}

/// Full engagement data for export.
#[derive(Serialize)]
struct EngagementExport {
    workspace: String,
    exported_at: String,
    hosts: Vec<crate::workspace::HostEntry>,
    services: Vec<crate::workspace::ServiceEntry>,
    credentials: Vec<crate::cred_store::CredEntry>,
    loot: Vec<crate::loot::LootEntry>,
}

/// Gather all engagement data atomically.
/// Workspace data is snapshotted in a single read to avoid mixing data
/// across concurrent workspace switches.
async fn gather_data() -> EngagementExport {
    let workspace_name = crate::workspace::WORKSPACE.current_name().await;
    let workspace_data = crate::workspace::WORKSPACE.get_data().await;
    EngagementExport {
        workspace: workspace_name,
        exported_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        hosts: workspace_data.hosts,
        services: workspace_data.services,
        credentials: crate::cred_store::CRED_STORE.list().await,
        loot: crate::loot::LOOT_STORE.list().await,
    }
}

/// Return engagement data as a JSON string.
pub async fn export_json_string() -> Result<String> {
    let data = gather_data().await;
    serde_json::to_string_pretty(&data).context("Failed to serialize engagement data")
}

/// Export all engagement data to a JSON file.
pub async fn export_json(path: &str) -> Result<()> {
    validate_export_path(path)?;
    let json = export_json_string().await?;
    safe_write(path, json.as_bytes())?;
    crate::mprintln!("{}", format!("[+] Exported JSON to '{}'", path).green());
    Ok(())
}

/// Return engagement data as a CSV string.
pub async fn export_csv_string() -> Result<String> {
    let data = gather_data().await;
    let mut output = String::new();

    output.push_str("# Hosts\n");
    output.push_str("ip,hostname,os_guess,first_seen,last_seen,notes_count\n");
    for h in &data.hosts {
        output.push_str(&format!("{},{},{},{},{},{}\n",
            csv_escape(&h.ip),
            csv_escape(h.hostname.as_deref().unwrap_or("")),
            csv_escape(h.os_guess.as_deref().unwrap_or("")),
            csv_escape(&h.first_seen),
            csv_escape(&h.last_seen),
            h.notes.len()));
    }
    output.push('\n');

    output.push_str("# Services\n");
    output.push_str("host,port,protocol,service,version\n");
    for s in &data.services {
        output.push_str(&format!("{},{},{},{},{}\n",
            csv_escape(&s.host), s.port, csv_escape(&s.protocol),
            csv_escape(&s.service_name), csv_escape(s.version.as_deref().unwrap_or(""))));
    }
    output.push('\n');

    output.push_str("# Credentials\n");
    output.push_str("id,host,port,service,username,secret,type,source,valid\n");
    for c in &data.credentials {
        output.push_str(&format!("{},{},{},{},{},{},{},{},{}\n",
            csv_escape(&c.id), csv_escape(&c.host), c.port,
            csv_escape(&c.service), csv_escape(&c.username),
            csv_escape(&c.secret), c.cred_type,
            csv_escape(&c.source_module), c.valid));
    }
    output.push('\n');

    output.push_str("# Loot\n");
    output.push_str("id,host,type,description,filename,source\n");
    for l in &data.loot {
        output.push_str(&format!("{},{},{},{},{},{}\n",
            csv_escape(&l.id), csv_escape(&l.host), csv_escape(&l.loot_type),
            csv_escape(&l.description), csv_escape(&l.filename),
            csv_escape(&l.source_module)));
    }

    Ok(output)
}

/// Export engagement data to a CSV file.
pub async fn export_csv(path: &str) -> Result<()> {
    validate_export_path(path)?;
    let output = export_csv_string().await?;
    safe_write(path, output.as_bytes())?;
    crate::mprintln!("{}", format!("[+] Exported CSV to '{}'", path).green());
    Ok(())
}

/// Return a human-readable summary report as a string.
pub async fn export_summary_string() -> Result<String> {
    let data = gather_data().await;
    let mut report = String::new();

    report.push_str("============================================================\n");
    report.push_str("                 RustSploit Engagement Report\n");
    report.push_str("============================================================\n\n");
    report.push_str(&format!("Workspace: {}\n", data.workspace));
    report.push_str(&format!("Generated: {}\n\n", data.exported_at));

    report.push_str("--- Summary ---\n");
    report.push_str(&format!("Hosts discovered:     {}\n", data.hosts.len()));
    report.push_str(&format!("Services found:       {}\n", data.services.len()));
    report.push_str(&format!("Credentials obtained: {}\n", data.credentials.len()));
    report.push_str(&format!("Loot collected:       {}\n\n", data.loot.len()));

    if !data.hosts.is_empty() {
        report.push_str("--- Hosts ---\n");
        for h in &data.hosts {
            report.push_str(&format!("  {} ({})\n", h.ip, h.hostname.as_deref().unwrap_or("unknown")));
            if let Some(ref os) = h.os_guess { report.push_str(&format!("    OS: {}\n", os)); }
            if !h.notes.is_empty() {
                report.push_str("    Notes:\n");
                for note in &h.notes { report.push_str(&format!("      - {}\n", note)); }
            }
        }
        report.push('\n');
    }
    if !data.services.is_empty() {
        report.push_str("--- Services ---\n");
        for s in &data.services {
            report.push_str(&format!("  {}:{}/{} - {} {}\n", s.host, s.port, s.protocol, s.service_name, s.version.as_deref().unwrap_or("")));
        }
        report.push('\n');
    }
    if !data.credentials.is_empty() {
        report.push_str("--- Credentials ---\n");
        for c in &data.credentials {
            report.push_str(&format!("  {}@{}:{} ({}) - {} [{}]\n", c.username, c.host, c.port, c.service, c.cred_type, if c.valid { "valid" } else { "invalid" }));
        }
        report.push('\n');
    }
    if !data.loot.is_empty() {
        report.push_str("--- Loot ---\n");
        for l in &data.loot {
            report.push_str(&format!("  [{}] {} from {} - {}\n", l.loot_type, l.filename, l.host, l.description));
        }
        report.push('\n');
    }
    report.push_str("============================================================\n");
    report.push_str("Generated by RustSploit (https://github.com/thekiaboys/rustsploit)\n");
    Ok(report)
}

/// Export a human-readable summary report to a file.
pub async fn export_summary(path: &str) -> Result<()> {
    validate_export_path(path)?;
    let report = export_summary_string().await?;
    safe_write(path, report.as_bytes())?;
    crate::mprintln!("{}", format!("[+] Exported summary report to '{}'", path).green());
    Ok(())
}

fn csv_escape(s: &str) -> String {
    let mut val = s.to_string();
    // Prevent CSV injection — prefix formula-triggering characters and always
    // quote the result so parsers treat the prefix as literal text.
    let needs_formula_guard = val.starts_with('=')
        || val.starts_with('+')
        || val.starts_with('@')
        || val.starts_with('-')
        || val.starts_with('\t')
        || val.starts_with('\r');
    if needs_formula_guard {
        val = format!("'{}", val);
    }
    if needs_formula_guard || val.contains(',') || val.contains('"') || val.contains('\n') {
        format!("\"{}\"", val.replace('"', "\"\""))
    } else {
        val
    }
}

pub fn validate_export_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > 255 {
        return Err(anyhow::anyhow!("Invalid export path length (max 255 chars)"));
    }
    if path.contains("..") || path.contains('\0') {
        return Err(anyhow::anyhow!("Path traversal not allowed in export path"));
    }
    // Reject absolute paths and any directory separators — basename only
    if path.starts_with('/') || path.starts_with('\\') || path.contains('/') || path.contains('\\') {
        return Err(anyhow::anyhow!("Only filenames are allowed for export (no directory separators). Use a relative filename like 'report.json'."));
    }
    // Reject hidden files
    if path.starts_with('.') {
        return Err(anyhow::anyhow!("Hidden files not allowed for export"));
    }
    Ok(())
}

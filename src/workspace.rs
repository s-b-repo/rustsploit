use std::path::{Path, PathBuf};

use colored::*;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

/// A tracked host discovered during an engagement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEntry {
    pub ip: String,
    pub hostname: Option<String>,
    pub os_guess: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub notes: Vec<String>,
}

/// A tracked service on a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub service_name: String,
    pub version: Option<String>,
    pub first_seen: String,
}

/// Workspace data container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkspaceData {
    pub hosts: Vec<HostEntry>,
    pub services: Vec<ServiceEntry>,
}

/// A named workspace with hosts and services.
pub struct Workspace {
    name: RwLock<String>,
    data: RwLock<WorkspaceData>,
    base_dir: PathBuf,
    save_mutex: Mutex<()>,
}

impl Workspace {
    /// Sync constructor for use in Lazy static init.
    /// File I/O here uses std::fs since this runs during lazy initialization
    /// before the tokio runtime may be fully available for blocking.
    fn new() -> Self {
        let base = home::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".rustsploit");
        Self::with_base_dir(base)
    }

    /// Create a workspace rooted under a custom base directory.
    /// Used by the tenant registry for per-tenant isolation.
    pub(crate) fn with_base_dir(base: PathBuf) -> Self {
        let base_dir = base.join("workspaces");
        use std::os::unix::fs::DirBuilderExt;
        if let Err(e) = std::fs::DirBuilder::new().mode(0o700).recursive(true).create(&base_dir) {
            eprintln!("[!] Failed to create workspaces directory {}: {}", base_dir.display(), e);
        }

        let data = Self::load_sync(&base_dir, "default");
        Self {
            name: RwLock::new("default".to_string()),
            data: RwLock::new(data),
            base_dir,
            save_mutex: Mutex::new(()),
        }
    }

    fn file_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{}.json", name))
    }

    /// Sync load used only during initial construction (Lazy init).
    fn load_sync(base_dir: &Path, name: &str) -> WorkspaceData {
        let path = base_dir.join(format!("{}.json", name));
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(contents) => match serde_json::from_str(&contents) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("[!] Warning: Workspace '{}' is corrupted ({}). Creating backup.", name, e);
                        let backup = path.with_extension("json.bak");
                        if let Err(e) = std::fs::copy(&path, &backup) {
                            eprintln!("[!] Failed to backup corrupted workspace '{}': {}", name, e);
                        }
                        WorkspaceData::default()
                    }
                },
                Err(e) => {
                    eprintln!("[!] Failed to read workspace '{}': {}. Preserving original.", name, e);
                    let backup = path.with_extension("json.unreadable");
                    if let Err(e) = std::fs::rename(&path, &backup) {
                        eprintln!("[!] Rename failed: {}", e);
                    }
                    WorkspaceData::default()
                }
            }
        } else {
            WorkspaceData::default()
        }
    }

    /// Load a workspace from disk (or create empty).
    /// Updates name first, then data, so they stay consistent.
    /// On I/O failure, starts with empty data for the new workspace
    /// rather than leaving stale data from the old one.
    async fn load(&self, name: &str) {
        let path = self.file_path(name);
        let data = if path.exists() {
            match tokio::fs::read_to_string(&path).await {
                Ok(contents) => match serde_json::from_str(&contents) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("[!] Warning: Workspace '{}' is corrupted ({}). Creating backup.", name, e);
                        let backup = path.with_extension("json.bak");
                        if let Err(e) = tokio::fs::copy(&path, &backup).await {
                            eprintln!("[!] Failed to backup corrupted workspace '{}': {}", name, e);
                        }
                        WorkspaceData::default()
                    }
                },
                Err(e) => {
                    // Read errors (EACCES/EIO) leave the original file
                    // intact. Move it aside so a subsequent successful
                    // start doesn't silently overwrite the original.
                    eprintln!("[!] Warning: Failed to read workspace '{}': {}. Preserving original.", name, e);
                    let backup = path.with_extension("json.unreadable");
                    if let Err(e) = tokio::fs::rename(&path, &backup).await {
                        eprintln!("[!] Rename failed: {}", e);
                    }
                    WorkspaceData::default()
                }
            }
        } else {
            WorkspaceData::default()
        };
        // Update name and data together to maintain consistency.
        // Name is updated AFTER data is successfully loaded/defaulted.
        *self.name.write().await = name.to_string();
        *self.data.write().await = data;
    }

    /// Save current workspace to disk.
    /// P1-1: serialize disk writes via `save_mutex` so concurrent mutators
    /// cannot land their saves out of order. The snapshot is taken under
    /// the read lock *while holding* the save mutex, guaranteeing the
    /// on-disk file always matches a real in-memory state.
    async fn save(&self) {
        let _save_guard = self.save_mutex.lock().await;
        let name = self.current_name().await;
        let path = self.file_path(&name);
        let data_snapshot = self.data.read().await.clone();
        let tmp = path.with_extension("json.tmp");
        let json = match serde_json::to_string_pretty(&data_snapshot) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("[!] Failed to serialize workspace data: {}", e);
                return;
            }
        };
        // P1-7: open the temp file atomically with mode 0o600 + O_NOFOLLOW so
        // (a) the file is never visible at world-readable mode (no
        // truncate-then-chmod window), and (b) a symlink raced into place
        // between create and write can't redirect the write to a privileged
        // path.
        use tokio::fs::OpenOptions;
        use tokio::io::AsyncWriteExt;
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        #[cfg(unix)]
        {
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = match opts.open(&tmp).await {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[!] Failed to open workspace tmp file: {}", e);
                return;
            }
        };
        if let Err(e) = file.write_all(json.as_bytes()).await {
            eprintln!("[!] Failed to write workspace tmp file: {}", e);
            return;
        }
        if let Err(e) = file.flush().await {
            eprintln!("[!] Failed to flush workspace tmp file: {}", e);
            return;
        }
        drop(file);
        if let Err(e) = tokio::fs::rename(&tmp, &path).await {
            eprintln!("[!] Failed to save workspace: {}", e);
        }
    }

    /// Get current workspace name.
    pub async fn current_name(&self) -> String {
        self.name.read().await.clone()
    }

    /// Switch to a different workspace.
    pub async fn switch(&self, name: &str) {
        self.save().await;
        self.load(name).await;
    }

    /// List available workspaces.
    pub async fn list_workspaces(&self) -> Vec<String> {
        let mut names = Vec::new();
        let mut entries = match tokio::fs::read_dir(&self.base_dir).await {
            Ok(entries) => entries,
            Err(e) => {
                eprintln!("[!] Failed to read workspaces directory {}: {}", self.base_dir.display(), e);
                names.push("default".to_string());
                return names;
            }
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Some(fname) = entry.path().file_stem().and_then(|s| s.to_str()) {
                names.push(fname.to_string());
            }
        }
        if names.is_empty() {
            names.push("default".to_string());
        }
        names.sort();
        names
    }

    /// Add or update a host.
    ///
    /// `ip` may be a bare IPv4/IPv6 address or a hostname (the same shapes
    /// that `extract_ip_from_target` produces). Anything that fails both an
    /// IpAddr parse and the conservative hostname charset (alphanum + `.-_`)
    /// is rejected so junk like `not_an_ip` cannot land in the tracked-host
    /// list.
    pub async fn add_host(&self, ip: &str, hostname: Option<&str>, os_guess: Option<&str>) {
        // Input validation
        if ip.is_empty() || ip.len() > 256 {
            return;
        }
        if ip.chars().any(|c| c.is_control()) {
            return;
        }
        let is_ip = ip.parse::<std::net::IpAddr>().is_ok();
        let is_hostname = !is_ip
            && ip.contains('.')
            && ip.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
        if !is_ip && !is_hostname {
            tracing::debug!(ip, "workspace add_host rejected: not a valid IP or hostname shape");
            return;
        }
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        {
            let mut data = self.data.write().await;
            if let Some(existing) = data.hosts.iter_mut().find(|h| h.ip == ip) {
                existing.last_seen = now;
                if let Some(hn) = hostname {
                    existing.hostname = Some(hn.to_string());
                }
                if let Some(os) = os_guess {
                    existing.os_guess = Some(os.to_string());
                }
            } else {
                data.hosts.push(HostEntry {
                    ip: ip.to_string(),
                    hostname: hostname.map(|s| s.to_string()),
                    os_guess: os_guess.map(|s| s.to_string()),
                    first_seen: now.clone(),
                    last_seen: now,
                    notes: Vec::new(),
                });
            }
        }
        self.save().await;
    }

    /// Add a note to a host.
    pub async fn add_note(&self, ip: &str, note: &str) -> bool {
        let found = {
            let mut data = self.data.write().await;
            if let Some(host) = data.hosts.iter_mut().find(|h| h.ip == ip) {
                host.notes.push(note.to_string());
                true
            } else {
                false
            }
        };
        if found {
            self.save().await;
        }
        found
    }

    /// Add or update a service. Updates service_name and version if the
    /// host:port/protocol already exists.
    pub async fn add_service(&self, host: &str, port: u16, protocol: &str, service_name: &str, version: Option<&str>) {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        {
            let mut data = self.data.write().await;
            if let Some(existing) = data.services.iter_mut().find(|s| s.host == host && s.port == port && s.protocol == protocol) {
                // Update service name and version on re-discovery
                existing.service_name = service_name.to_string();
                if version.is_some() {
                    existing.version = version.map(|s| s.to_string());
                }
            } else {
                data.services.push(ServiceEntry {
                    host: host.to_string(),
                    port,
                    protocol: protocol.to_string(),
                    service_name: service_name.to_string(),
                    version: version.map(|s| s.to_string()),
                    first_seen: now,
                });
            }
        }
        self.save().await;
    }

    /// Delete a host by IP. Returns true if found and removed.
    pub async fn delete_host(&self, ip: &str) -> bool {
        let removed = {
            let mut data = self.data.write().await;
            let before = data.hosts.len();
            data.hosts.retain(|h| h.ip != ip);
            // Also remove services associated with this host
            data.services.retain(|s| s.host != ip);
            data.hosts.len() < before
        };
        if removed {
            self.save().await;
        }
        removed
    }

    /// Delete a service by host and port. Returns true if found and removed.
    pub async fn delete_service(&self, host: &str, port: u16) -> bool {
        let removed = {
            let mut data = self.data.write().await;
            let before = data.services.len();
            data.services.retain(|s| !(s.host == host && s.port == port));
            data.services.len() < before
        };
        if removed {
            self.save().await;
        }
        removed
    }

    /// Clear all hosts and services from the current workspace.
    pub async fn clear_hosts(&self) {
        {
            let mut data = self.data.write().await;
            data.hosts.clear();
            data.services.clear();
        }
        self.save().await;
    }

    /// Get all hosts.
    pub async fn hosts(&self) -> Vec<HostEntry> {
        self.data.read().await.hosts.clone()
    }

    /// Get all services.
    pub async fn services(&self) -> Vec<ServiceEntry> {
        self.data.read().await.services.clone()
    }

    /// Get full workspace data for export.
    pub async fn get_data(&self) -> WorkspaceData {
        self.data.read().await.clone()
    }

    /// Display hosts table.
    pub async fn display_hosts(&self) {
        let hosts = self.hosts().await;
        if hosts.is_empty() {
            println!("{}", "No hosts tracked. Use 'hosts add <ip>' to add one.".dimmed());
            return;
        }
        let name = self.current_name().await;
        println!();
        println!("{}", format!("Hosts ({} total) - Workspace: {}", hosts.len(), name).bold().underline());
        println!();
        println!("  {:<18} {:<25} {:<15} {:<20} {}",
            "IP".bold(), "Hostname".bold(), "OS".bold(), "Last Seen".bold(), "Notes".bold());
        println!("  {}", "-".repeat(90).dimmed());
        for h in &hosts {
            println!("  {:<18} {:<25} {:<15} {:<20} {}",
                h.ip.green(),
                h.hostname.as_deref().unwrap_or("-"),
                h.os_guess.as_deref().unwrap_or("-"),
                &h.last_seen,
                h.notes.len());
        }
        println!();
    }

    /// Display services table.
    pub async fn display_services(&self) {
        let services = self.services().await;
        if services.is_empty() {
            println!("{}", "No services tracked. Use 'services add' to add one.".dimmed());
            return;
        }
        let name = self.current_name().await;
        println!();
        println!("{}", format!("Services ({} total) - Workspace: {}", services.len(), name).bold().underline());
        println!();
        println!("  {:<18} {:<8} {:<8} {:<15} {}",
            "Host".bold(), "Port".bold(), "Proto".bold(), "Service".bold(), "Version".bold());
        println!("  {}", "-".repeat(70).dimmed());
        for s in &services {
            println!("  {:<18} {:<8} {:<8} {:<15} {}",
                s.host.green(), s.port, s.protocol, s.service_name,
                s.version.as_deref().unwrap_or("-"));
        }
        println!();
    }
}

pub static WORKSPACE: Lazy<Workspace> = Lazy::new(Workspace::new);

/// Convenience functions for modules to auto-populate workspace data.
/// Routes through the tenant registry when in a tenant context (API mode),
/// otherwise uses the global singleton (shell mode). Also emits a
/// `ModuleEvent::Finding` so panel / MCP / WS subscribers see the
/// discovery in real time without each module having to call
/// `events::emit` itself.
pub async fn track_host(ip: &str, hostname: Option<&str>, os_guess: Option<&str>) {
    let s = crate::tenant::resolve();
    s.workspace().add_host(ip, hostname, os_guess).await;
    crate::events::emit(crate::events::ModuleEvent::Finding {
        module: emitting_module(),
        target: ip.to_string(),
        kind: "host".to_string(),
        message: match (hostname, os_guess) {
            (Some(h), Some(o)) => format!("host up — hostname={h} os={o}"),
            (Some(h), None) => format!("host up — hostname={h}"),
            (None, Some(o)) => format!("host up — os={o}"),
            (None, None) => "host up".to_string(),
        },
    });
}

pub async fn track_service(
    host: &str,
    port: u16,
    protocol: &str,
    service_name: &str,
    version: Option<&str>,
) {
    let s = crate::tenant::resolve();
    s.workspace().add_service(host, port, protocol, service_name, version).await;
    let version_str = version.map(|v| format!(" {v}")).unwrap_or_default();
    crate::events::emit(crate::events::ModuleEvent::Finding {
        module: emitting_module(),
        target: format!("{host}:{port}"),
        kind: "service".to_string(),
        message: format!("{protocol}/{service_name}{version_str}"),
    });
}

pub async fn add_note(host: &str, note: &str) {
    let s = crate::tenant::resolve();
    s.workspace().add_note(host, note).await;
    crate::events::emit(crate::events::ModuleEvent::Finding {
        module: emitting_module(),
        target: host.to_string(),
        kind: "note".to_string(),
        message: note.to_string(),
    });
}

/// The module path that produced this finding. Resolved from the active
/// `RunContext` set by the scheduler before invoking the module. Falls
/// back to a generic `"workspace"` when called outside a scheduled run
/// (CLI / shell utility paths).
fn emitting_module() -> String {
    let path = crate::context::current_module_path();
    if path.is_empty() {
        "workspace".to_string()
    } else {
        path
    }
}

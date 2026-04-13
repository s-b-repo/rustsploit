use std::path::PathBuf;
use tokio::sync::RwLock;
use std::sync::LazyLock as Lazy;
use serde::{Serialize, Deserialize};
use colored::*;

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
}

impl Workspace {
    /// Sync constructor for use in Lazy static init.
    /// File I/O here uses std::fs since this runs during lazy initialization
    /// before the tokio runtime may be fully available for blocking.
    fn new() -> Self {
        let base_dir = home::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".rustsploit")
            .join("workspaces");
        use std::os::unix::fs::DirBuilderExt;
        if let Err(e) = std::fs::DirBuilder::new().mode(0o700).recursive(true).create(&base_dir) { crate::meprintln!("[!] Directory creation error: {}", e); }

        let data = Self::load_sync(&base_dir, "default");
        Self {
            name: RwLock::new("default".to_string()),
            data: RwLock::new(data),
            base_dir,
        }
    }

    fn file_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{}.json", name))
    }

    /// Sync load used only during initial construction (Lazy init).
    fn load_sync(base_dir: &PathBuf, name: &str) -> WorkspaceData {
        let path = base_dir.join(format!("{}.json", name));
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(contents) => match serde_json::from_str(&contents) {
                    Ok(data) => data,
                    Err(e) => {
                        crate::meprintln!("[!] Warning: Workspace '{}' is corrupted ({}). Creating backup.", name, e);
                        let backup = path.with_extension("json.bak");
                        if let Err(e) = std::fs::copy(&path, &backup) { crate::meprintln!("[!] Backup copy error: {}", e); }
                        WorkspaceData::default()
                    }
                },
                Err(_) => WorkspaceData::default(),
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
                        crate::meprintln!("[!] Warning: Workspace '{}' is corrupted ({}). Creating backup.", name, e);
                        let backup = path.with_extension("json.bak");
                        if let Err(e) = tokio::fs::copy(&path, &backup).await { crate::meprintln!("[!] Copy error: {}", e); }
                        WorkspaceData::default()
                    }
                },
                Err(e) => {
                    crate::meprintln!("[!] Warning: Failed to read workspace '{}': {}. Starting empty.", name, e);
                    WorkspaceData::default()
                }
            }
        } else {
            WorkspaceData::default()
        };
        // Update data FIRST, then name, to maintain consistency (BUG 23 fix).
        // A reader between these two lines sees old name + new data,
        // which is safer than new name + old data (stale workspace).
        *self.data.write().await = data;
        *self.name.write().await = name.to_string();
    }

    /// Save current workspace to disk.
    /// Clones data before releasing lock to avoid holding lock during I/O.
    async fn save(&self) {
        let name = self.current_name().await;
        let path = self.file_path(&name);
        // Clone data to release lock before file I/O
        let data_snapshot = self.data.read().await.clone();
        let tmp = path.with_extension("json.tmp");
        if let Ok(json) = serde_json::to_string_pretty(&data_snapshot) {
            if tokio::fs::write(&tmp, &json).await.is_ok() {
                if let Err(e) = tokio::fs::rename(&tmp, &path).await {
                    crate::meprintln!("[!] Failed to save workspace: {}", e);
                } else {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(e) = tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await {
                        crate::meprintln!("[!] Permission error on {}: {}", path.display(), e);
                    }
                }
            }
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
            Err(_) => {
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
    pub async fn add_host(&self, ip: &str, hostname: Option<&str>, os_guess: Option<&str>) {
        // Input validation
        if ip.is_empty() || ip.len() > 256 {
            return;
        }
        if ip.chars().any(|c| c.is_control()) {
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

    /// Maximum notes per host to prevent unbounded growth (BUG 25 fix).
    const MAX_NOTES_PER_HOST: usize = 10_000;

    /// Add a note to a host.
    pub async fn add_note(&self, ip: &str, note: &str) -> bool {
        let found = {
            let mut data = self.data.write().await;
            if let Some(host) = data.hosts.iter_mut().find(|h| h.ip == ip) {
                if host.notes.len() >= Self::MAX_NOTES_PER_HOST {
                    crate::meprintln!("[!] Maximum notes per host reached ({}).", Self::MAX_NOTES_PER_HOST);
                    return false;
                }
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
            crate::mprintln!("{}", "No hosts tracked. Use 'hosts add <ip>' to add one.".dimmed());
            return;
        }
        let name = self.current_name().await;
        crate::mprintln!();
        crate::mprintln!("{}", format!("Hosts ({} total) - Workspace: {}", hosts.len(), name).bold().underline());
        crate::mprintln!();
        crate::mprintln!("  {:<18} {:<25} {:<15} {:<20} {}",
            "IP".bold(), "Hostname".bold(), "OS".bold(), "Last Seen".bold(), "Notes".bold());
        crate::mprintln!("  {}", "-".repeat(90).dimmed());
        for h in &hosts {
            crate::mprintln!("  {:<18} {:<25} {:<15} {:<20} {}",
                h.ip.green(),
                h.hostname.as_deref().unwrap_or("-"),
                h.os_guess.as_deref().unwrap_or("-"),
                &h.last_seen,
                h.notes.len());
        }
        crate::mprintln!();
    }

    /// Display services table.
    pub async fn display_services(&self) {
        let services = self.services().await;
        if services.is_empty() {
            crate::mprintln!("{}", "No services tracked. Use 'services add' to add one.".dimmed());
            return;
        }
        let name = self.current_name().await;
        crate::mprintln!();
        crate::mprintln!("{}", format!("Services ({} total) - Workspace: {}", services.len(), name).bold().underline());
        crate::mprintln!();
        crate::mprintln!("  {:<18} {:<8} {:<8} {:<15} {}",
            "Host".bold(), "Port".bold(), "Proto".bold(), "Service".bold(), "Version".bold());
        crate::mprintln!("  {}", "-".repeat(70).dimmed());
        for s in &services {
            crate::mprintln!("  {:<18} {:<8} {:<8} {:<15} {}",
                s.host.green(), s.port, s.protocol, s.service_name,
                s.version.as_deref().unwrap_or("-"));
        }
        crate::mprintln!();
    }
}

pub static WORKSPACE: Lazy<Workspace> = Lazy::new(Workspace::new);

/// Mutex to coordinate workspace switching across all stores atomically.
static SWITCH_MUTEX: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

/// Switch all stores (workspace, credentials, options) atomically.
/// Prevents race conditions when concurrent requests switch workspaces.
pub async fn switch_all(name: &str) {
    let _lock = SWITCH_MUTEX.lock().await;
    WORKSPACE.switch(name).await;
    crate::cred_store::CRED_STORE.switch_workspace(name).await;
    crate::global_options::GLOBAL_OPTIONS.switch_workspace(name).await;
}

/// Convenience functions for modules to auto-populate workspace data.
pub async fn track_host(ip: &str, hostname: Option<&str>, os_guess: Option<&str>) {
    WORKSPACE.add_host(ip, hostname, os_guess).await;
}

pub async fn track_service(host: &str, port: u16, protocol: &str, service_name: &str, version: Option<&str>) {
    WORKSPACE.add_service(host, port, protocol, service_name, version).await;
}

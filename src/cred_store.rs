use std::path::PathBuf;
use tokio::sync::RwLock;
use std::sync::LazyLock as Lazy;
use serde::{Serialize, Deserialize};
use colored::*;

/// Type of credential stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredType {
    Password,
    Hash,
    Key,
    Token,
}

impl std::fmt::Display for CredType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredType::Password => write!(f, "password"),
            CredType::Hash => write!(f, "hash"),
            CredType::Key => write!(f, "key"),
            CredType::Token => write!(f, "token"),
        }
    }
}

/// A single credential entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredEntry {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub service: String,
    pub username: String,
    pub secret: String,
    pub cred_type: CredType,
    pub source_module: String,
    pub timestamp: String,
    pub valid: bool,
}

/// Credential store backed by a per-workspace JSON file.
/// Each workspace gets its own credential store at
/// `~/.rustsploit/workspaces/{workspace}_creds.json`.
pub struct CredStore {
    entries: RwLock<Vec<CredEntry>>,
    base_dir: PathBuf,
    workspace: RwLock<String>,
}

impl CredStore {
    fn new() -> Self {
        let base_dir = home::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".rustsploit")
            .join("workspaces");

        let workspace = "default".to_string();
        let file_path = base_dir.join(format!("{}_creds.json", workspace));

        // Synchronous load at init time (called once from Lazy)
        let entries = Self::load_from_file_sync(&file_path);

        // Migrate legacy global creds.json into default workspace if it exists
        let legacy_path = home::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".rustsploit")
            .join("creds.json");
        if legacy_path.exists() && entries.is_empty() {
            let legacy = Self::load_from_file_sync(&legacy_path);
            if !legacy.is_empty() {
                crate::meprintln!("[*] Migrating {} credentials from legacy creds.json to workspace 'default'", legacy.len());
                if let Ok(json) = serde_json::to_string_pretty(&legacy) {
                    let _ = std::fs::create_dir_all(&base_dir);
                    let _ = std::fs::write(&file_path, &json);
                }
                // Rename legacy file so migration only happens once
                let _ = std::fs::rename(&legacy_path, legacy_path.with_extension("json.migrated"));
                return Self {
                    entries: RwLock::new(legacy),
                    base_dir,
                    workspace: RwLock::new(workspace),
                };
            }
        }

        Self {
            entries: RwLock::new(entries),
            base_dir,
            workspace: RwLock::new(workspace),
        }
    }

    fn load_from_file_sync(file_path: &PathBuf) -> Vec<CredEntry> {
        if file_path.exists() {
            match std::fs::read_to_string(file_path) {
                Ok(contents) => match serde_json::from_str(&contents) {
                    Ok(data) => data,
                    Err(e) => {
                        crate::meprintln!("[!] Warning: {} is corrupted ({}). Starting fresh.", file_path.display(), e);
                        let backup = file_path.with_extension("json.bak");
                        if let Err(e) = std::fs::copy(file_path, &backup) { crate::meprintln!("[!] Backup copy error: {}", e); }
                        Vec::new()
                    }
                },
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        }
    }

    fn file_path_for(&self, workspace: &str) -> PathBuf {
        self.base_dir.join(format!("{}_creds.json", workspace))
    }

    /// Switch to a different workspace's credential store.
    /// Saves current, loads target workspace creds.
    pub async fn switch_workspace(&self, name: &str) {
        // Save current workspace creds
        let snapshot = self.entries.read().await.clone();
        let current = self.workspace.read().await.clone();
        let current_path = self.file_path_for(&current);
        self.save_to_path(&current_path, &snapshot).await;

        // Load new workspace creds
        let new_path = self.file_path_for(name);
        let new_entries = if new_path.exists() {
            match tokio::fs::read_to_string(&new_path).await {
                Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };
        *self.entries.write().await = new_entries;
        *self.workspace.write().await = name.to_string();
    }

    /// Maximum length for credential fields to prevent memory abuse.
    const MAX_FIELD_LEN: usize = 4096;

    /// Add a credential. Returns the generated ID (empty string on validation failure).
    pub async fn add(
        &self,
        host: &str,
        port: u16,
        service: &str,
        username: &str,
        secret: &str,
        cred_type: CredType,
        source_module: &str,
    ) -> String {
        // Input validation (BUG 19 fix: also validate service and source_module)
        if host.is_empty() || host.len() > Self::MAX_FIELD_LEN {
            return String::new();
        }
        if secret.len() > Self::MAX_FIELD_LEN || username.len() > Self::MAX_FIELD_LEN {
            return String::new();
        }
        if service.len() > Self::MAX_FIELD_LEN || source_module.len() > Self::MAX_FIELD_LEN {
            return String::new();
        }
        let id = uuid::Uuid::new_v4().simple().to_string();
        let entry = CredEntry {
            id: id.clone(),
            host: host.to_string(),
            port,
            service: service.to_string(),
            username: username.to_string(),
            secret: secret.to_string(),
            cred_type,
            source_module: source_module.to_string(),
            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            valid: true,
        };
        let snapshot = {
            let mut entries = self.entries.write().await;
            entries.push(entry);
            entries.clone()
        };
        if !self.save_locked(&snapshot).await {
            // Rollback: remove from in-memory store since disk write failed
            let mut entries = self.entries.write().await;
            entries.retain(|e| e.id != id);
            crate::meprintln!("[!] Credential add rolled back — save to disk failed");
            return String::new();
        }
        id
    }

    /// List all credentials.
    pub async fn list(&self) -> Vec<CredEntry> {
        self.entries.read().await.clone()
    }

    /// Search credentials by host.
    pub async fn search(&self, query: &str) -> Vec<CredEntry> {
        let q = query.to_lowercase();
        self.list().await.into_iter().filter(|e| {
            e.host.to_lowercase().contains(&q)
                || e.service.to_lowercase().contains(&q)
                || e.username.to_lowercase().contains(&q)
        }).collect()
    }

    /// Delete a credential by ID.
    pub async fn delete(&self, id: &str) -> bool {
        let snapshot = {
            let mut entries = self.entries.write().await;
            let before = entries.len();
            entries.retain(|e| e.id != id);
            if entries.len() < before {
                Some(entries.clone())
            } else {
                None
            }
        };
        if let Some(data) = snapshot {
            if !self.save_locked(&data).await {
                crate::meprintln!("[!] Warning: credential delete index save failed");
            }
            return true;
        }
        false
    }

    /// Clear all credentials.
    pub async fn clear(&self) {
        {
            self.entries.write().await.clear();
        }
        if !self.save_locked(&[]).await {
            crate::meprintln!("[!] Warning: credential clear index save failed");
        }
    }

    /// Save to disk. Returns false if the write failed so callers can rollback.
    async fn save_locked(&self, entries: &[CredEntry]) -> bool {
        let workspace = self.workspace.read().await.clone();
        let path = self.file_path_for(&workspace);
        self.save_to_path(&path, entries).await
    }

    async fn save_to_path(&self, path: &PathBuf, entries: &[CredEntry]) -> bool {
        if let Some(parent) = path.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                crate::meprintln!("[!] Warning: Failed to create creds directory: {}", e);
                return false;
            }
        }
        let tmp = path.with_extension("json.tmp");
        let json = match serde_json::to_string_pretty(entries) {
            Ok(j) => j,
            Err(e) => {
                crate::meprintln!("[!] Warning: Failed to serialize credentials: {}", e);
                return false;
            }
        };
        if let Err(e) = tokio::fs::write(&tmp, &json).await {
            crate::meprintln!("[!] Warning: Failed to write creds temp file: {}", e);
            return false;
        }
        if let Err(e) = tokio::fs::rename(&tmp, path).await {
            crate::meprintln!("[!] Warning: Failed to save credentials (rename): {}", e);
            return false;
        }
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await {
            crate::meprintln!("[!] Warning: Failed to set permissions on creds file: {}", e);
        }
        true
    }

    /// Display all credentials in a formatted table.
    pub async fn display(&self) {
        let entries = self.list().await;
        if entries.is_empty() {
            crate::mprintln!("{}", "No credentials stored. Use 'creds add' to add one.".dimmed());
            return;
        }
        crate::mprintln!();
        crate::mprintln!("{}", format!("Credentials ({} total):", entries.len()).bold().underline());
        crate::mprintln!();
        crate::mprintln!("  {:<10} {:<18} {:<6} {:<10} {:<16} {:<20} {:<10} {}",
            "ID".bold(), "Host".bold(), "Port".bold(), "Service".bold(),
            "Username".bold(), "Secret".bold(), "Type".bold(), "Valid".bold());
        crate::mprintln!("  {}", "-".repeat(100).dimmed());
        for e in &entries {
            let valid_str = if e.valid { "yes".green() } else { "no".red() };
            crate::mprintln!("  {:<10} {:<18} {:<6} {:<10} {:<16} {:<20} {:<10} {}",
                e.id, e.host, e.port, e.service, e.username,
                if e.secret.len() > 8 { format!("{}...", &e.secret[..5]) } else { e.secret.clone() },
                e.cred_type, valid_str);
        }
        crate::mprintln!();
    }

    /// Display search results.
    pub fn display_results(&self, results: &[CredEntry]) {
        if results.is_empty() {
            crate::mprintln!("{}", "No matching credentials found.".dimmed());
            return;
        }
        crate::mprintln!();
        crate::mprintln!("{}", format!("Found {} credential(s):", results.len()).bold());
        crate::mprintln!();
        for e in results {
            crate::mprintln!("  [{}] {}@{}:{} ({}) - {} [{}]",
                e.id.yellow(), e.username.green(), e.host, e.port,
                e.service, e.cred_type,
                if e.valid { "valid".green() } else { "invalid".red() });
        }
        crate::mprintln!();
    }
}

pub static CRED_STORE: Lazy<CredStore> = Lazy::new(CredStore::new);

/// Convenience function for modules to store a discovered credential.
pub async fn store_credential(
    host: &str,
    port: u16,
    service: &str,
    username: &str,
    secret: &str,
    cred_type: CredType,
    source_module: &str,
) -> String {
    CRED_STORE.add(host, port, service, username, secret, cred_type, source_module).await
}

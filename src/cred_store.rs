use std::path::PathBuf;
use tokio::sync::RwLock;
use once_cell::sync::Lazy;
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

/// Credential store backed by a JSON file.
pub struct CredStore {
    entries: RwLock<Vec<CredEntry>>,
    file_path: PathBuf,
}

impl CredStore {
    fn new() -> Self {
        let file_path = home::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".rustsploit")
            .join("creds.json");

        // Synchronous load at init time (called once from Lazy)
        let entries = if file_path.exists() {
            match std::fs::read_to_string(&file_path) {
                Ok(contents) => match serde_json::from_str(&contents) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("[!] Warning: creds.json is corrupted ({}). Starting fresh.", e);
                        let backup = file_path.with_extension("json.bak");
                        let _ = std::fs::copy(&file_path, &backup);
                        Vec::new()
                    }
                },
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };

        Self {
            entries: RwLock::new(entries),
            file_path,
        }
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
        // Input validation
        if host.is_empty() || host.len() > Self::MAX_FIELD_LEN {
            return String::new();
        }
        if secret.len() > Self::MAX_FIELD_LEN || username.len() > Self::MAX_FIELD_LEN {
            return String::new();
        }
        let id = uuid::Uuid::new_v4().simple().to_string()[..16].to_string();
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
        self.save_locked(&snapshot).await;
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
            self.save_locked(&data).await;
            return true;
        }
        false
    }

    /// Clear all credentials.
    pub async fn clear(&self) {
        {
            self.entries.write().await.clear();
        }
        self.save_locked(&[]).await;
    }

    async fn save_locked(&self, entries: &[CredEntry]) {
        if let Some(parent) = self.file_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let tmp = self.file_path.with_extension("json.tmp");
        if let Ok(json) = serde_json::to_string_pretty(entries) {
            if tokio::fs::write(&tmp, &json).await.is_ok() {
                let _ = tokio::fs::rename(&tmp, &self.file_path).await;
                use std::os::unix::fs::PermissionsExt;
                let _ = tokio::fs::set_permissions(&self.file_path, std::fs::Permissions::from_mode(0o600)).await;
            }
        }
    }

    /// Display all credentials in a formatted table.
    pub async fn display(&self) {
        let entries = self.list().await;
        if entries.is_empty() {
            println!("{}", "No credentials stored. Use 'creds add' to add one.".dimmed());
            return;
        }
        println!();
        println!("{}", format!("Credentials ({} total):", entries.len()).bold().underline());
        println!();
        println!("  {:<10} {:<18} {:<6} {:<10} {:<16} {:<20} {:<10} {}",
            "ID".bold(), "Host".bold(), "Port".bold(), "Service".bold(),
            "Username".bold(), "Secret".bold(), "Type".bold(), "Valid".bold());
        println!("  {}", "-".repeat(100).dimmed());
        for e in &entries {
            let valid_str = if e.valid { "yes".green() } else { "no".red() };
            println!("  {:<10} {:<18} {:<6} {:<10} {:<16} {:<20} {:<10} {}",
                e.id, e.host, e.port, e.service, e.username,
                if e.secret.len() > 18 { format!("{}...", &e.secret[..15]) } else { e.secret.clone() },
                e.cred_type, valid_str);
        }
        println!();
    }

    /// Display search results.
    pub fn display_results(&self, results: &[CredEntry]) {
        if results.is_empty() {
            println!("{}", "No matching credentials found.".dimmed());
            return;
        }
        println!();
        println!("{}", format!("Found {} credential(s):", results.len()).bold());
        println!();
        for e in results {
            println!("  [{}] {}@{}:{} ({}) - {} [{}]",
                e.id.yellow(), e.username.green(), e.host, e.port,
                e.service, e.cred_type,
                if e.valid { "valid".green() } else { "invalid".red() });
        }
        println!();
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

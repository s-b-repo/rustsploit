use std::path::PathBuf;

use colored::*;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

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

/// Parameters for adding a new credential.
pub struct NewCred<'a> {
    pub host: &'a str,
    pub port: u16,
    pub service: &'a str,
    pub username: &'a str,
    pub secret: &'a str,
    pub cred_type: CredType,
    pub source_module: &'a str,
}

/// Credential store backed by a JSON file.
pub struct CredStore {
    entries: RwLock<Vec<CredEntry>>,
    file_path: PathBuf,
}

impl CredStore {
    fn new() -> Self {
        let base = home::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".rustsploit");
        Self::with_base_dir(base)
    }

    /// Create a credential store under a custom base directory.
    pub(crate) fn with_base_dir(base: PathBuf) -> Self {
        let file_path = base.join("creds.json");

        // Synchronous load at init time
        let entries = if file_path.exists() {
            match std::fs::read_to_string(&file_path) {
                Ok(contents) => match serde_json::from_str(&contents) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("[!] Warning: creds.json is corrupted ({}). Starting fresh.", e);
                        let backup = file_path.with_extension("json.bak");
                        if let Err(e) = std::fs::copy(&file_path, &backup) {
                            eprintln!("[!] Failed to backup corrupted creds.json: {}", e);
                        }
                        Vec::new()
                    }
                },
                Err(e) => {
                    // Read errors here are typically EACCES/EIO — back up the
                    // unreadable file so we don't silently overwrite a user's
                    // creds with an empty store.
                    eprintln!("[!] Failed to read creds.json: {}. Preserving original.", e);
                    let backup = file_path.with_extension("json.unreadable");
                    if let Err(e) = std::fs::rename(&file_path, &backup) {
                        eprintln!("[!] Rename failed: {}", e);
                    }
                    Vec::new()
                }
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

    /// Runaway-entry cap (mirrors loot's `MAX_LOOT_ENTRIES`) so a buggy loop
    /// can't grow the store unbounded.
    const MAX_CRED_ENTRIES: usize = 100_000;

    /// Add a credential. Returns `Some(id)` on success, `None` on validation failure.
    pub async fn add(&self, cred: NewCred<'_>) -> Option<String> {
        // Input validation. Bound EVERY free-text field, not just host/secret/
        // username — `service` and `source_module` can carry attacker-influenced
        // banner text, and leaving them unbounded defeats the memory-abuse guard
        // this cap is here to provide.
        if cred.host.is_empty() || cred.host.len() > Self::MAX_FIELD_LEN {
            return None;
        }
        if cred.secret.len() > Self::MAX_FIELD_LEN
            || cred.username.len() > Self::MAX_FIELD_LEN
            || cred.service.len() > Self::MAX_FIELD_LEN
            || cred.source_module.len() > Self::MAX_FIELD_LEN
        {
            return None;
        }
        // Scrub control/ANSI bytes from host + non-secret metadata before
        // storage so a credential captured from a hostile banner can't inject
        // terminal escapes on `creds list` / CSV export — matching loot and the
        // workspace. `username`/`secret` are kept verbatim so the stored
        // credential stays an exact match for the real one.
        let host = crate::utils::scrub_stored_text(cred.host);
        let service = crate::utils::scrub_stored_text(cred.service);
        let source_module = crate::utils::scrub_stored_text(cred.source_module);
        let username = cred.username.to_string();
        let secret = cred.secret.to_string();
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        // P1-1: hold the write lock across the disk save. Previous code
        // released the lock before calling `save_locked`, letting two
        // concurrent writers land disk writes in the wrong order — disk
        // and in-memory state could diverge after restart.
        {
            let mut entries = self.entries.write().await;
            // Dedup: re-running a brute against the same target shouldn't append
            // an identical row each time. If the exact same credential tuple
            // already exists, refresh its timestamp + valid flag and return its
            // id instead of pushing a duplicate.
            if let Some(existing) = entries.iter_mut().find(|e| {
                e.host == host
                    && e.port == cred.port
                    && e.service == service
                    && e.username == username
                    && e.secret == secret
            }) {
                existing.timestamp = now;
                existing.valid = true;
                let id = existing.id.clone();
                let snapshot = entries.clone();
                self.save_locked(&snapshot).await;
                return Some(id);
            }
            // Runaway-entry cap, re-checked under the write lock.
            if entries.len() >= Self::MAX_CRED_ENTRIES {
                eprintln!(
                    "[!] Credential store full ({} entries) — clear creds before adding more",
                    Self::MAX_CRED_ENTRIES
                );
                return None;
            }
            let id = uuid::Uuid::new_v4().simple().to_string()[..16].to_string();
            entries.push(CredEntry {
                id: id.clone(),
                host,
                port: cred.port,
                service,
                username,
                secret,
                cred_type: cred.cred_type,
                source_module,
                timestamp: now,
                valid: true,
            });
            let snapshot = entries.clone();
            self.save_locked(&snapshot).await;
            Some(id)
        }
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
        // P1-1: same lock-during-save fix as `add()`. Holding the write
        // lock through the disk write keeps in-memory and on-disk state in
        // agreement under concurrent ops.
        let mut entries = self.entries.write().await;
        let before = entries.len();
        entries.retain(|e| e.id != id);
        if entries.len() < before {
            let snapshot = entries.clone();
            self.save_locked(&snapshot).await;
            return true;
        }
        false
    }

    /// Mark a credential valid/invalid by id (e.g. after a re-test shows the
    /// password was rotated). Returns true if the id was found. This is what
    /// makes the valid/invalid column shown by `display`/CSV actually settable.
    pub async fn set_valid(&self, id: &str, valid: bool) -> bool {
        let mut entries = self.entries.write().await;
        if let Some(e) = entries.iter_mut().find(|e| e.id == id) {
            e.valid = valid;
            let snapshot = entries.clone();
            self.save_locked(&snapshot).await;
            true
        } else {
            false
        }
    }

    /// Clear all credentials.
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
        self.save_locked(&entries).await;
    }

    async fn save_locked(&self, entries: &[CredEntry]) {
        if let Some(parent) = self.file_path.parent()
            && let Err(e) = tokio::fs::create_dir_all(parent).await {
                eprintln!("[!] Failed to create creds directory: {}", e);
                return;
            }
        let tmp = self.file_path.with_extension("json.tmp");
        let json = match serde_json::to_string_pretty(entries) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("[!] Failed to serialize credentials: {}", e);
                return;
            }
        };
        {
            // P1-7: O_NOFOLLOW + create-with-mode atomically. A symlink raced
            // into place between create and open would otherwise redirect the
            // write to a privileged path with the credentials' contents.
            let mut opts = tokio::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true).mode(0o600);
            #[cfg(unix)]
            {
                opts.custom_flags(libc::O_NOFOLLOW);
            }
            let file = match opts.open(&tmp).await {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[!] Failed to write temp creds file: {}", e);
                    return;
                }
            };
            let mut file = file;
            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut file, json.as_bytes()).await {
                eprintln!("[!] Failed to write temp creds file: {}", e);
                return;
            }
            if let Err(e) = file.sync_all().await {
                eprintln!("[!] Failed to fsync temp creds file: {}", e);
                return;
            }
        }
        if let Err(e) = tokio::fs::rename(&tmp, &self.file_path).await {
            eprintln!("[!] Failed to rename creds file: {}", e);
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
                if e.secret.chars().count() > 18 { format!("{}...", e.secret.chars().take(15).collect::<String>()) } else { e.secret.clone() },
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
/// Routes through the tenant registry when in a tenant context (API mode).
pub async fn store_credential(cred: NewCred<'_>) -> Option<String> {
    let s = crate::tenant::resolve();
    s.cred_store().add(cred).await
}

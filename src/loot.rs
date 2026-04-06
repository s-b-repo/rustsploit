use std::path::PathBuf;
use tokio::sync::RwLock;
use once_cell::sync::Lazy;
use serde::{Serialize, Deserialize};
use colored::*;

/// Metadata for a stored loot item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LootEntry {
    pub id: String,
    pub host: String,
    pub loot_type: String,
    pub filename: String,
    pub description: String,
    pub source_module: String,
    pub timestamp: String,
}

/// Loot store backed by JSON index + file directory.
pub struct LootStore {
    entries: RwLock<Vec<LootEntry>>,
    index_path: PathBuf,
    loot_dir: PathBuf,
}

impl LootStore {
    fn new() -> Self {
        let base = home::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".rustsploit");

        let loot_dir = base.join("loot");
        use std::os::unix::fs::DirBuilderExt;
        let _ = std::fs::DirBuilder::new().mode(0o700).recursive(true).create(&loot_dir);

        let index_path = base.join("loot_index.json");
        let entries = if index_path.exists() {
            match std::fs::read_to_string(&index_path) {
                Ok(contents) => match serde_json::from_str(&contents) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("[!] Warning: loot_index.json is corrupted ({}). Creating backup.", e);
                        let backup = index_path.with_extension("json.bak");
                        let _ = std::fs::copy(&index_path, &backup);
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
            index_path,
            loot_dir,
        }
    }

    /// Maximum loot file size (100 MB).
    const MAX_LOOT_SIZE: usize = 100 * 1024 * 1024;

    /// Store loot data and return the entry ID.
    pub async fn add(
        &self,
        host: &str,
        loot_type: &str,
        description: &str,
        data: &[u8],
        source_module: &str,
    ) -> Option<String> {
        // Validate size
        if data.len() > Self::MAX_LOOT_SIZE {
            eprintln!("[!] Loot too large: {} bytes (max {} MB)", data.len(), Self::MAX_LOOT_SIZE / 1024 / 1024);
            return None;
        }
        // Validate inputs
        if host.is_empty() || host.len() > 256 {
            return None;
        }

        let id = uuid::Uuid::new_v4().simple().to_string()[..16].to_string();
        let ext = match loot_type {
            "config" => "conf",
            "password_file" => "txt",
            "firmware" => "bin",
            "hash" => "txt",
            _ => "dat",
        };
        // Sanitize loot_type — only allow alphanumeric and underscore
        let safe_type: String = loot_type.chars()
            .filter(|c| c.is_alphanumeric() || *c == '_')
            .take(64)
            .collect();
        let safe_type = if safe_type.is_empty() { "unknown".to_string() } else { safe_type };

        let filename = format!("{}_{}.{}", id, safe_type, ext);
        let file_path = self.loot_dir.join(&filename);

        // Verify the resolved path is within loot_dir (prevent traversal)
        if !file_path.starts_with(&self.loot_dir) {
            eprintln!("[!] Loot path escapes loot directory");
            return None;
        }

        if tokio::fs::write(&file_path, data).await.is_err() {
            return None;
        }
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600)).await;

        let entry = LootEntry {
            id: id.clone(),
            host: host.to_string(),
            loot_type: loot_type.to_string(),
            filename,
            description: description.to_string(),
            source_module: source_module.to_string(),
            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        };

        let snapshot = {
            let mut entries = self.entries.write().await;
            entries.push(entry);
            entries.clone()
        };
        self.save_locked(&snapshot).await;
        Some(id)
    }

    /// Add loot from a string (convenience).
    pub async fn add_text(
        &self,
        host: &str,
        loot_type: &str,
        description: &str,
        text: &str,
        source_module: &str,
    ) -> Option<String> {
        self.add(host, loot_type, description, text.as_bytes(), source_module).await
    }

    /// List all loot entries.
    pub async fn list(&self) -> Vec<LootEntry> {
        self.entries.read().await.clone()
    }

    /// Search loot by host or type.
    pub async fn search(&self, query: &str) -> Vec<LootEntry> {
        let q = query.to_lowercase();
        self.list().await.into_iter().filter(|e| {
            e.host.to_lowercase().contains(&q)
                || e.loot_type.to_lowercase().contains(&q)
                || e.description.to_lowercase().contains(&q)
        }).collect()
    }

    /// Delete a loot entry by ID. Also removes the loot file from disk.
    pub async fn delete(&self, id: &str) -> bool {
        let (removed, filename) = {
            let mut entries = self.entries.write().await;
            let before = entries.len();
            let fname = entries.iter().find(|e| e.id == id).map(|e| e.filename.clone());
            entries.retain(|e| e.id != id);
            if entries.len() < before {
                let snapshot = entries.clone();
                drop(entries);
                self.save_locked(&snapshot).await;
                (true, fname)
            } else {
                (false, None)
            }
        };
        if let Some(fname) = filename {
            if let Some(path) = self.file_path(&fname) {
                let _ = tokio::fs::remove_file(&path).await;
            }
        }
        removed
    }

    /// Clear all loot entries and remove loot files from disk.
    pub async fn clear(&self) {
        let filenames: Vec<String> = {
            let mut entries = self.entries.write().await;
            let names: Vec<String> = entries.iter().map(|e| e.filename.clone()).collect();
            entries.clear();
            names
        };
        self.save_locked(&[]).await;
        for fname in filenames {
            if let Some(path) = self.file_path(&fname) {
                let _ = tokio::fs::remove_file(&path).await;
            }
        }
    }

    /// Get the full path to a loot file.
    /// Returns None if the filename contains path separators or traversal.
    pub fn file_path(&self, filename: &str) -> Option<PathBuf> {
        if filename.contains('/') || filename.contains('\\') || filename.contains("..") || filename.contains('\0') {
            return None;
        }
        let path = self.loot_dir.join(filename);
        if !path.starts_with(&self.loot_dir) {
            return None;
        }
        Some(path)
    }

    /// Get the loot directory path.
    pub fn loot_directory(&self) -> &PathBuf {
        &self.loot_dir
    }

    async fn save_locked(&self, entries: &[LootEntry]) {
        let tmp = self.index_path.with_extension("json.tmp");
        if let Ok(json) = serde_json::to_string_pretty(entries) {
            if tokio::fs::write(&tmp, &json).await.is_ok() {
                let _ = tokio::fs::rename(&tmp, &self.index_path).await;
                use std::os::unix::fs::PermissionsExt;
                let _ = tokio::fs::set_permissions(&self.index_path, std::fs::Permissions::from_mode(0o600)).await;
            }
        }
    }

    /// Display loot table.
    pub async fn display(&self) {
        let entries = self.list().await;
        if entries.is_empty() {
            println!("{}", "No loot stored.".dimmed());
            return;
        }
        println!();
        println!("{}", format!("Loot ({} items):", entries.len()).bold().underline());
        println!();
        println!("  {:<10} {:<18} {:<15} {:<30} {}",
            "ID".bold(), "Host".bold(), "Type".bold(), "Description".bold(), "Module".bold());
        println!("  {}", "-".repeat(90).dimmed());
        for e in &entries {
            let desc = if e.description.len() > 28 {
                format!("{}...", &e.description[..25])
            } else {
                e.description.clone()
            };
            println!("  {:<10} {:<18} {:<15} {:<30} {}",
                e.id.yellow(), e.host.green(), e.loot_type, desc, e.source_module);
        }
        println!();
    }
}

pub static LOOT_STORE: Lazy<LootStore> = Lazy::new(LootStore::new);

/// Convenience function for modules to store loot.
pub async fn store_loot(
    host: &str,
    loot_type: &str,
    description: &str,
    data: &[u8],
    source_module: &str,
) -> Option<String> {
    LOOT_STORE.add(host, loot_type, description, data, source_module).await
}

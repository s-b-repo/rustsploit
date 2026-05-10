use std::path::PathBuf;

use colored::*;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

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
        Self::with_base_dir(base)
    }

    /// Create a loot store under a custom base directory.
    pub(crate) fn with_base_dir(base: PathBuf) -> Self {
        let loot_dir = base.join("loot");
        use std::os::unix::fs::DirBuilderExt;
        if let Err(e) = std::fs::DirBuilder::new().mode(0o700).recursive(true).create(&loot_dir) {
            eprintln!("[!] Failed to create loot directory {}: {}", loot_dir.display(), e);
        }

        let index_path = base.join("loot_index.json");
        let entries = if index_path.exists() {
            match std::fs::read_to_string(&index_path) {
                Ok(contents) => match serde_json::from_str(&contents) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("[!] Warning: loot_index.json is corrupted ({}). Creating backup.", e);
                        let backup = index_path.with_extension("json.bak");
                        if let Err(e) = std::fs::copy(&index_path, &backup) {
                            eprintln!("[!] Failed to backup corrupted loot index: {}", e);
                        }
                        Vec::new()
                    }
                },
                Err(e) => {
                    eprintln!("[!] Failed to read loot_index.json: {}. Preserving original.", e);
                    let backup = index_path.with_extension("json.unreadable");
                    let _ = std::fs::rename(&index_path, &backup);
                    Vec::new()
                }
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
    /// P2-A6: cap on the total number of loot entries to bound disk + index
    /// growth. 10k entries × 100 MB max each = ~1 TB worst case, which is
    /// well past any realistic engagement; the per-entry cap is the real
    /// limit, this catches runaway-loop bugs.
    const MAX_LOOT_ENTRIES: usize = 10_000;

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
        // P2-A6: refuse to insert past the global entry cap.
        if self.entries.read().await.len() >= Self::MAX_LOOT_ENTRIES {
            eprintln!(
                "[!] Loot store full ({} entries) — delete or clear loot before adding more",
                Self::MAX_LOOT_ENTRIES
            );
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

        {
            // P1-7: O_NOFOLLOW + create-with-mode atomically. A symlink raced
            // into the loot dir would otherwise redirect the write outside it.
            let mut opts = tokio::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true).mode(0o600);
            #[cfg(unix)]
            {
                opts.custom_flags(libc::O_NOFOLLOW);
            }
            let file = match opts.open(&file_path).await {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[!] Failed to create loot file: {}", e);
                    return None;
                }
            };
            let mut file = file;
            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut file, data).await {
                eprintln!("[!] Failed to write loot data: {}", e);
                return None;
            }
        }

        let entry = LootEntry {
            id: id.clone(),
            host: host.to_string(),
            loot_type: loot_type.to_string(),
            filename,
            description: description.to_string(),
            source_module: source_module.to_string(),
            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        };

        // P1-1: hold the write lock across the disk save.
        {
            let mut entries = self.entries.write().await;
            entries.push(entry);
            let snapshot = entries.clone();
            self.save_locked(&snapshot).await;
        }
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
    /// File removal happens BEFORE the index is rewritten, so that a failed
    /// `unlink` (EACCES, EBUSY, etc.) does not orphan the file on disk while
    /// the index forgets about it.
    pub async fn delete(&self, id: &str) -> bool {
        // Look up the filename without mutating the index yet.
        let filename = {
            let entries = self.entries.read().await;
            entries.iter().find(|e| e.id == id).map(|e| e.filename.clone())
        };
        let Some(fname) = filename else {
            return false;
        };

        // Try to remove the file first. ENOENT is fine — the index will be
        // cleaned up either way. Any other error aborts the delete so the
        // caller can see the entry is still present and retry.
        if let Some(path) = self.file_path(&fname) {
            match tokio::fs::remove_file(&path).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    tracing::debug!(path = %path.display(), "loot file already gone, removing index entry");
                }
                Err(e) => {
                    eprintln!("[!] Failed to remove loot file {}: {} — index entry preserved", path.display(), e);
                    return false;
                }
            }
        }

        // File is gone (or the path was malformed) — now drop the index entry.
        // P1-1: lock-during-save so the index file stays consistent with
        // the in-memory entries under concurrent ops.
        let mut entries = self.entries.write().await;
        let before = entries.len();
        entries.retain(|e| e.id != id);
        if entries.len() == before {
            return false;
        }
        let snapshot = entries.clone();
        self.save_locked(&snapshot).await;
        true
    }

    /// Clear all loot entries and remove loot files from disk.
    pub async fn clear(&self) {
        let filenames: Vec<String> = {
            let mut entries = self.entries.write().await;
            let names: Vec<String> = entries.iter().map(|e| e.filename.clone()).collect();
            entries.clear();
            self.save_locked(&entries).await;
            names
        };
        for fname in filenames {
            if let Some(path) = self.file_path(&fname)
                && let Err(e) = tokio::fs::remove_file(&path).await {
                    eprintln!("[!] Failed to remove loot file {}: {}", path.display(), e);
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
        let json = match serde_json::to_string_pretty(entries) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("[!] Failed to serialize loot index: {}", e);
                return;
            }
        };
        // P1-7: O_NOFOLLOW + create-with-mode atomically.
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        #[cfg(unix)]
        {
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let file = match opts.open(&tmp).await {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[!] Failed to write loot index: {}", e);
                return;
            }
        };
        let mut file = file;
        if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut file, json.as_bytes()).await {
            eprintln!("[!] Failed to write loot index data: {}", e);
            return;
        }
        if let Err(e) = tokio::fs::rename(&tmp, &self.index_path).await {
            eprintln!("[!] Failed to rename loot index: {}", e);
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
/// Routes through the tenant registry when in a tenant context (API mode).
/// Also emits a `ModuleEvent::LootStored` and a `Finding` so panel / MCP /
/// WS subscribers see the discovery without each module having to call
/// `events::emit` manually.
pub async fn store_loot(
    host: &str,
    loot_type: &str,
    description: &str,
    data: &[u8],
    source_module: &str,
) -> Option<String> {
    let s = crate::tenant::resolve();
    let id = s.loot_store().add(host, loot_type, description, data, source_module).await;
    if let Some(id_str) = id.as_deref() {
        crate::events::emit(crate::events::ModuleEvent::LootStored {
            id: id_str.to_string(),
            host: host.to_string(),
            kind: loot_type.to_string(),
        });
    }
    crate::events::emit(crate::events::ModuleEvent::Finding {
        module: source_module.to_string(),
        target: host.to_string(),
        kind: loot_type.to_string(),
        message: description.to_string(),
    });
    id
}

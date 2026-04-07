use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::RwLock;
use once_cell::sync::Lazy;
use colored::*;

/// Persistent global options that apply across all modules.
/// Like Metasploit's `setg` — values are checked by `cfg_prompt_*`
/// after custom_prompts but before interactive stdin.
pub struct GlobalOptions {
    options: RwLock<HashMap<String, String>>,
    file_path: PathBuf,
}

impl GlobalOptions {
    fn new() -> Self {
        let file_path = home::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".rustsploit")
            .join("global_options.json");

        let options = if file_path.exists() {
            match std::fs::read_to_string(&file_path) {
                Ok(contents) => match serde_json::from_str(&contents) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("[!] Warning: global_options.json is corrupted ({}). Starting fresh.", e);
                        let backup = file_path.with_extension("json.bak");
                        let _ = std::fs::copy(&file_path, &backup);
                        HashMap::new()
                    }
                },
                Err(_) => HashMap::new(),
            }
        } else {
            HashMap::new()
        };

        Self {
            options: RwLock::new(options),
            file_path,
        }
    }

    /// Set a global option. Persists to disk.
    pub async fn set(&self, key: &str, value: &str) {
        let snapshot = {
            let mut opts = self.options.write().await;
            opts.insert(key.to_string(), value.to_string());
            opts.clone()
        };
        self.save_locked(&snapshot).await;
    }

    /// Remove a global option. Persists to disk.
    pub async fn unset(&self, key: &str) -> bool {
        let snapshot = {
            let mut opts = self.options.write().await;
            let removed = opts.remove(key).is_some();
            if removed { Some(opts.clone()) } else { None }
        };
        if let Some(data) = snapshot {
            self.save_locked(&data).await;
            return true;
        }
        false
    }

    /// Get a global option value.
    pub async fn get(&self, key: &str) -> Option<String> {
        self.options.read().await.get(key).cloned()
    }

    /// Synchronous non-blocking get for use in blocking/sync contexts.
    /// Returns `None` if the lock is currently held by a writer.
    pub fn try_get(&self, key: &str) -> Option<String> {
        self.options.try_read().ok().and_then(|guard| guard.get(key).cloned())
    }

    /// Get all global options.
    pub async fn all(&self) -> HashMap<String, String> {
        self.options.read().await.clone()
    }

    /// Save to disk using atomic write (write to temp, then rename).
    async fn save_locked(&self, opts: &HashMap<String, String>) {
        if let Some(parent) = self.file_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let tmp = self.file_path.with_extension("json.tmp");
        if let Ok(json) = serde_json::to_string_pretty(opts) {
            if tokio::fs::write(&tmp, &json).await.is_ok() {
                let _ = tokio::fs::rename(&tmp, &self.file_path).await;
                use std::os::unix::fs::PermissionsExt;
                let _ = tokio::fs::set_permissions(&self.file_path, std::fs::Permissions::from_mode(0o600)).await;
            }
        }
    }

    /// Display all global options in a formatted table.
    pub async fn display(&self) {
        let opts = self.all().await;
        if opts.is_empty() {
            println!("{}", "No global options set. Use 'setg <key> <value>' to set one.".dimmed());
            return;
        }
        println!();
        println!("{}", "Global Options:".bold().underline());
        println!();
        println!("  {:<30} {}", "Key".bold(), "Value".bold());
        println!("  {:<30} {}", "---".dimmed(), "-----".dimmed());
        let mut keys: Vec<_> = opts.keys().collect();
        keys.sort();
        for key in keys {
            if let Some(val) = opts.get(key) {
                println!("  {:<30} {}", key.green(), val);
            }
        }
        println!();
    }
}

pub static GLOBAL_OPTIONS: Lazy<GlobalOptions> = Lazy::new(GlobalOptions::new);

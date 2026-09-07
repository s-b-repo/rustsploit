use std::collections::HashMap;
use std::path::PathBuf;

use colored::*;
use once_cell::sync::Lazy;
use tokio::sync::RwLock;

/// Persistent global options that apply across all modules.
/// Like Metasploit's `setg` — values are checked by `cfg_prompt_*`
/// after custom_prompts but before interactive stdin.
pub struct GlobalOptions {
    options: RwLock<HashMap<String, String>>,
    file_path: PathBuf,
}

impl GlobalOptions {
    fn new() -> Self {
        let base = home::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".rustsploit");
        Self::with_base_dir(base)
    }

    /// Create a global options store under a custom base directory.
    pub(crate) fn with_base_dir(base: PathBuf) -> Self {
        let file_path = base.join("global_options.json");

        let options = if file_path.exists() {
            match std::fs::read_to_string(&file_path) {
                Ok(contents) => match serde_json::from_str(&contents) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!(
                            "[!] Warning: global_options.json is corrupted ({}). Starting fresh.",
                            e
                        );
                        let backup = file_path.with_extension("json.bak");
                        if let Err(e) = std::fs::copy(&file_path, &backup) {
                            eprintln!("[!] Failed to backup corrupted global_options.json: {}", e);
                        }
                        HashMap::new()
                    }
                },
                Err(e) => {
                    eprintln!("[!] Failed to read global_options.json: {}", e);
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

        Self {
            options: RwLock::new(options),
            file_path,
        }
    }

    const MAX_KEY_LEN: usize = 256;
    const MAX_VALUE_LEN: usize = 4096;
    const MAX_ENTRIES: usize = 1024;

    /// Set a global option. Persists to disk.
    /// Returns false if key/value exceed size limits or entry cap reached.
    pub async fn set(&self, key: &str, value: &str) -> bool {
        if key.is_empty() || key.len() > Self::MAX_KEY_LEN || value.len() > Self::MAX_VALUE_LEN {
            return false;
        }
        let snapshot = {
            let mut opts = self.options.write().await;
            if opts.len() >= Self::MAX_ENTRIES && !opts.contains_key(key) {
                return false;
            }
            opts.insert(key.to_string(), value.to_string());
            opts.clone()
        };
        self.save_locked(&snapshot).await;
        true
    }

    pub async fn unset(&self, key: &str) -> bool {
        let snapshot = {
            let mut opts = self.options.write().await;
            let removed = opts.remove(key).is_some();
            if removed {
                let snap = opts.clone();
                drop(opts);
                snap
            } else {
                return false;
            }
        };
        self.save_locked(&snapshot).await;
        true
    }

    /// Get a global option value.
    pub async fn get(&self, key: &str) -> Option<String> {
        self.options.read().await.get(key).cloned()
    }

    /// Synchronous blocking get for use in non-async contexts.
    /// Spins briefly if a writer holds the lock, so user-set values
    /// are never silently replaced by defaults during a concurrent save.
    /// If all retries are exhausted (only possible if a long-running writer
    /// holds the lock), logs a debug warning so the silent-default fallback
    /// is observable in tracing.
    pub fn try_get(&self, key: &str) -> Option<String> {
        for _ in 0..50 {
            if let Ok(guard) = self.options.try_read() {
                return guard.get(key).cloned();
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        tracing::debug!(
            key,
            "global_options try_get gave up after 50ms — caller will fall back to default"
        );
        None
    }

    /// Get all global options.
    pub async fn all(&self) -> HashMap<String, String> {
        self.options.read().await.clone()
    }

    /// Save to disk using atomic write (write to temp, then rename).
    async fn save_locked(&self, opts: &HashMap<String, String>) {
        if let Err(e) = crate::utils::persistence::atomic_write_json(&self.file_path, opts).await {
            eprintln!("[!] Failed to persist options: {}", e);
        }
    }

    /// Display all global options in a formatted table.
    pub async fn display(&self) {
        let opts = self.all().await;
        if opts.is_empty() {
            println!(
                "{}",
                "No global options set. Use 'setg <key> <value>' to set one.".dimmed()
            );
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

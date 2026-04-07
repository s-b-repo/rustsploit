use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::RwLock;
use std::sync::LazyLock as Lazy;
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
                        crate::meprintln!("[!] Warning: global_options.json is corrupted ({}). Starting fresh.", e);
                        let backup = file_path.with_extension("json.bak");
                        if let Err(e) = std::fs::copy(&file_path, &backup) { crate::meprintln!("[!] Backup copy error: {}", e); }
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

    /// Maximum key length for global options.
    const MAX_KEY_LEN: usize = 256;
    /// Maximum value length for global options.
    const MAX_VALUE_LEN: usize = 4096;
    /// Maximum number of global options to prevent memory abuse.
    const MAX_OPTIONS: usize = 1000;

    /// Set a global option. Persists to disk.
    /// Returns false if validation fails (BUG 16 fix).
    pub async fn set(&self, key: &str, value: &str) -> bool {
        if key.is_empty() || key.len() > Self::MAX_KEY_LEN {
            crate::meprintln!("[!] Option key too long (max {} chars)", Self::MAX_KEY_LEN);
            return false;
        }
        if value.len() > Self::MAX_VALUE_LEN {
            crate::meprintln!("[!] Option value too long (max {} chars)", Self::MAX_VALUE_LEN);
            return false;
        }
        let mut opts = self.options.write().await;
        if opts.len() >= Self::MAX_OPTIONS && !opts.contains_key(key) {
            crate::meprintln!("[!] Too many global options (max {}). Unset some first.", Self::MAX_OPTIONS);
            return false;
        }
        opts.insert(key.to_string(), value.to_string());
        let snapshot = opts.clone();
        drop(opts);
        self.save_locked(&snapshot).await;
        true
    }

    /// Remove a global option. Persists to disk.
    pub async fn unset(&self, key: &str) -> bool {
        let mut opts = self.options.write().await;
        let removed = opts.remove(key).is_some();
        if removed {
            let snapshot = opts.clone();
            drop(opts);
            self.save_locked(&snapshot).await;
        }
        removed
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
    /// Logs warnings on failure instead of silently ignoring (BUG 15 fix).
    async fn save_locked(&self, opts: &HashMap<String, String>) {
        if let Some(parent) = self.file_path.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                crate::meprintln!("[!] Warning: Failed to create config directory: {}", e);
                return;
            }
        }
        let tmp = self.file_path.with_extension("json.tmp");
        let json = match serde_json::to_string_pretty(opts) {
            Ok(j) => j,
            Err(e) => {
                crate::meprintln!("[!] Warning: Failed to serialize global options: {}", e);
                return;
            }
        };
        if let Err(e) = tokio::fs::write(&tmp, &json).await {
            crate::meprintln!("[!] Warning: Failed to write global options temp file: {}", e);
            return;
        }
        if let Err(e) = tokio::fs::rename(&tmp, &self.file_path).await {
            crate::meprintln!("[!] Warning: Failed to save global options (rename): {}", e);
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = tokio::fs::set_permissions(&self.file_path, std::fs::Permissions::from_mode(0o600)).await {
            crate::meprintln!("[!] Warning: Failed to set permissions on global_options.json: {}", e);
        }
    }

    /// Display all global options in a formatted table.
    pub async fn display(&self) {
        let opts = self.all().await;
        if opts.is_empty() {
            crate::mprintln!("{}", "No global options set. Use 'setg <key> <value>' to set one.".dimmed());
            return;
        }
        crate::mprintln!();
        crate::mprintln!("{}", "Global Options:".bold().underline());
        crate::mprintln!();
        crate::mprintln!("  {:<30} {}", "Key".bold(), "Value".bold());
        crate::mprintln!("  {:<30} {}", "---".dimmed(), "-----".dimmed());
        let mut keys: Vec<_> = opts.keys().collect();
        keys.sort();
        for key in keys {
            if let Some(val) = opts.get(key) {
                crate::mprintln!("  {:<30} {}", key.green(), val);
            }
        }
        crate::mprintln!();
    }
}

pub static GLOBAL_OPTIONS: Lazy<GlobalOptions> = Lazy::new(GlobalOptions::new);

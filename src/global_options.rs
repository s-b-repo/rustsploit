use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::RwLock;
use std::sync::LazyLock as Lazy;
use colored::*;

/// Per-workspace options that apply across all modules within a workspace.
/// Like Metasploit's `setg` — values are checked by `cfg_prompt_*`
/// after custom_prompts but before interactive stdin.
/// Each workspace gets its own options file at
/// `~/.rustsploit/workspaces/{workspace}_options.json`.
pub struct GlobalOptions {
    options: RwLock<HashMap<String, String>>,
    base_dir: PathBuf,
    workspace: RwLock<String>,
}

impl GlobalOptions {
    fn new() -> Self {
        let base_dir = home::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".rustsploit")
            .join("workspaces");

        let workspace = "default".to_string();
        let file_path = base_dir.join(format!("{}_options.json", workspace));

        let options = Self::load_from_file_sync(&file_path);

        // Migrate legacy global_options.json into default workspace
        let legacy_path = home::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".rustsploit")
            .join("global_options.json");
        if legacy_path.exists() && options.is_empty() {
            let legacy = Self::load_from_file_sync(&legacy_path);
            if !legacy.is_empty() {
                crate::meprintln!("[*] Migrating {} options from legacy global_options.json to workspace 'default'", legacy.len());
                if let Ok(json) = serde_json::to_string_pretty(&legacy) {
                    let _ = std::fs::create_dir_all(&base_dir);
                    let _ = std::fs::write(&file_path, &json);
                }
                let _ = std::fs::rename(&legacy_path, legacy_path.with_extension("json.migrated"));
                return Self {
                    options: RwLock::new(legacy),
                    base_dir,
                    workspace: RwLock::new(workspace),
                };
            }
        }

        Self {
            options: RwLock::new(options),
            base_dir,
            workspace: RwLock::new(workspace),
        }
    }

    fn load_from_file_sync(file_path: &PathBuf) -> HashMap<String, String> {
        if file_path.exists() {
            match std::fs::read_to_string(file_path) {
                Ok(contents) => match serde_json::from_str(&contents) {
                    Ok(data) => data,
                    Err(e) => {
                        crate::meprintln!("[!] Warning: {} is corrupted ({}). Starting fresh.", file_path.display(), e);
                        let backup = file_path.with_extension("json.bak");
                        if let Err(e) = std::fs::copy(file_path, &backup) { crate::meprintln!("[!] Backup copy error: {}", e); }
                        HashMap::new()
                    }
                },
                Err(_) => HashMap::new(),
            }
        } else {
            HashMap::new()
        }
    }

    fn file_path_for(&self, workspace: &str) -> PathBuf {
        self.base_dir.join(format!("{}_options.json", workspace))
    }

    /// Switch to a different workspace's options.
    pub async fn switch_workspace(&self, name: &str) {
        // Save current
        let snapshot = self.options.read().await.clone();
        let current = self.workspace.read().await.clone();
        self.save_to_path(&self.file_path_for(&current), &snapshot).await;

        // Load new
        let new_path = self.file_path_for(name);
        let new_opts = if new_path.exists() {
            match tokio::fs::read_to_string(&new_path).await {
                Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
                Err(_) => HashMap::new(),
            }
        } else {
            HashMap::new()
        };
        *self.options.write().await = new_opts;
        *self.workspace.write().await = name.to_string();
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
    async fn save_locked(&self, opts: &HashMap<String, String>) {
        let workspace = self.workspace.read().await.clone();
        let path = self.file_path_for(&workspace);
        self.save_to_path(&path, opts).await;
    }

    async fn save_to_path(&self, path: &PathBuf, opts: &HashMap<String, String>) {
        if let Some(parent) = path.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                crate::meprintln!("[!] Warning: Failed to create config directory: {}", e);
                return;
            }
        }
        let tmp = path.with_extension("json.tmp");
        let json = match serde_json::to_string_pretty(opts) {
            Ok(j) => j,
            Err(e) => {
                crate::meprintln!("[!] Warning: Failed to serialize options: {}", e);
                return;
            }
        };
        if let Err(e) = tokio::fs::write(&tmp, &json).await {
            crate::meprintln!("[!] Warning: Failed to write options temp file: {}", e);
            return;
        }
        if let Err(e) = tokio::fs::rename(&tmp, path).await {
            crate::meprintln!("[!] Warning: Failed to save options (rename): {}", e);
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await {
            crate::meprintln!("[!] Warning: Failed to set permissions on options file: {}", e);
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

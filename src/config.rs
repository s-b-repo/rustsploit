use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use ipnetwork::IpNetwork;
use regex::Regex;

/// Maximum length for target strings
const MAX_TARGET_LENGTH: usize = 2048;

/// Maximum length for hostname
const MAX_HOSTNAME_LENGTH: usize = 253;

/// Global configuration for the framework
#[derive(Clone, Debug)]
pub struct GlobalConfig {
    /// Global target - can be a single IP or CIDR subnet
    target: Arc<RwLock<Option<TargetConfig>>>,
}

#[derive(Clone, Debug)]
pub enum TargetConfig {
    /// Single IP address or hostname
    Single(String),
    /// CIDR subnet (e.g., "192.168.1.0/24")
    Subnet(IpNetwork),
}

impl GlobalConfig {
    /// Create a new global configuration
    pub fn new() -> Self {
        Self {
            target: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the global target (IP, hostname, or CIDR subnet)
    pub fn set_target(&self, target: &str) -> Result<()> {
        let trimmed = target.trim();
        
        // Basic validation
        if trimmed.is_empty() {
            return Err(anyhow!("Target cannot be empty"));
        }
        
        // Length check
        if trimmed.len() > MAX_TARGET_LENGTH {
            return Err(anyhow!(
                "Target too long (max {} characters)",
                MAX_TARGET_LENGTH
            ));
        }
        
        // Check for control characters
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(anyhow!("Target cannot contain control characters"));
        }
        
        // Check for path traversal attempts
        if trimmed.contains("..") || trimmed.contains("//") {
            return Err(anyhow!("Target contains invalid characters (path traversal)"));
        }

        // Try to parse as CIDR subnet first
        if let Ok(network) = trimmed.parse::<IpNetwork>() {
            // No size limit enforced here - user can set 0.0.0.0/0 if they want.
            // Consumers (looping logic) must handle large subnets responsibly (e.g. via iterators).
            let mut target_guard = self.target.write().map_err(|_| anyhow!("Config lock poisoned"))?;
            *target_guard = Some(TargetConfig::Subnet(network));
            return Ok(());
        }

        // Validate hostname/IP format
        Self::validate_hostname_or_ip(trimmed)?;

        // Otherwise, treat as single IP or hostname
        let mut target_guard = self.target.write().map_err(|_| anyhow!("Config lock poisoned"))?;
        *target_guard = Some(TargetConfig::Single(trimmed.to_string()));
        Ok(())
    }
    
    /// Validates a hostname or IP address format
    fn validate_hostname_or_ip(target: &str) -> Result<()> {
        // Length check for hostname
        if target.len() > MAX_HOSTNAME_LENGTH {
            return Err(anyhow!(
                "Hostname too long (max {} characters)",
                MAX_HOSTNAME_LENGTH
            ));
        }
        
        // Check for valid characters
        // Allow: a-z, A-Z, 0-9, '.', '-', '_', ':', '[', ']' (for IPv6)
        let valid_chars = Regex::new(r"^[a-zA-Z0-9.\-_:\[\]]+$").expect("Regex compilation failed");
        if !valid_chars.is_match(target) {
            return Err(anyhow!(
                "Target contains invalid characters. Allowed: letters, numbers, '.', '-', '_', ':', '[', ']'"
            ));
        }
        
        // Check for spaces
        if target.contains(' ') {
            return Err(anyhow!("Target cannot contain spaces"));
        }
        
        // Basic hostname format check (not starting/ending with special chars)
        if target.starts_with('.') || target.starts_with('-') {
            return Err(anyhow!("Target cannot start with '.' or '-'"));
        }
        
        if target.ends_with('.') && !target.ends_with("..") {
            // Allow trailing dot for FQDN, but not double dots
        }
        
        // Check for consecutive dots (invalid in hostnames)
        if target.contains("..") {
            return Err(anyhow!("Target cannot contain consecutive dots"));
        }
        
        Ok(())
    }

    /// Get the global target as a single string (for display)
    pub fn get_target(&self) -> Option<String> {
        let guard = self.target.read().ok()?;
        guard.as_ref().map(|t| match t {
            TargetConfig::Single(ip) => ip.clone(),
            TargetConfig::Subnet(net) => net.to_string(),
        })
    }

    /// Get a single IP address from the global target
    /// For subnets, returns the network address (first IP)
    pub fn get_single_target_ip(&self) -> Result<String> {
        let guard = self.target.read().map_err(|_| anyhow!("Config lock poisoned"))?;
        
        match guard.as_ref() {
            Some(TargetConfig::Single(ip)) => {
                Ok(ip.clone())
            }
            Some(TargetConfig::Subnet(net)) => {
                // Return the network address (first IP in the subnet)
                Ok(net.network().to_string())
            }
            None => Err(anyhow!("No global target set")),
        }
    }


    /// Check if global target is set
    pub fn has_target(&self) -> bool {
        self.target.read().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Check if global target is a subnet
    pub fn is_subnet(&self) -> bool {
        self.target.read().map(|g| matches!(g.as_ref(), Some(TargetConfig::Subnet(_)))).unwrap_or(false)
    }

    /// Get the target subnet if set
    pub fn get_target_subnet(&self) -> Option<IpNetwork> {
        let guard = self.target.read().ok()?;
        match guard.as_ref() {
            Some(TargetConfig::Subnet(net)) => Some(*net),
            _ => None,
        }
    }

    /// Get the size of the target (number of IPs)
    /// For single IPs, returns 1
    /// For subnets, returns the subnet size without expanding
    pub fn get_target_size(&self) -> Option<u64> {
        let target_guard = self.target.read().ok()?;
        match target_guard.as_ref() {
            Some(TargetConfig::Single(_)) => Some(1),
            Some(TargetConfig::Subnet(net)) => {
                // Calculate size from prefix length
                let size = match net {
                    IpNetwork::V4(net4) => {
                        let prefix = net4.prefix() as u32;
                        if prefix >= 32 {
                            1u64
                        } else {
                            2u64.pow(32 - prefix)
                        }
                    }
                    IpNetwork::V6(net6) => {
                        let prefix = net6.prefix() as u32;
                        if prefix >= 128 {
                            1u64
                        } else {
                            let exp = 128u32.saturating_sub(prefix);
                            if exp > 63 {
                                u64::MAX
                            } else {
                                2u64.pow(exp)
                            }
                        }
                    }
                };
                Some(size)
            }
            None => None,
        }
    }

    /// Clear the global target
    pub fn clear_target(&self) {
        if let Ok(mut target_guard) = self.target.write() {
             *target_guard = None;
        }
    }
}

/// Global configuration instance
use once_cell::sync::Lazy;

pub static GLOBAL_CONFIG: Lazy<GlobalConfig> = Lazy::new(|| GlobalConfig::new());

/// Module-level configuration for API-driven execution
/// This is set by the API before running a module and read by modules
/// to get pre-configured values instead of prompting the user
#[derive(Clone, Debug)]
pub struct ModuleConfig {
    pub port: Option<u16>,
    pub username_wordlist: Option<String>,
    pub password_wordlist: Option<String>,
    pub concurrency: Option<usize>,
    pub stop_on_success: Option<bool>,
    pub save_results: Option<bool>,
    pub output_file: Option<String>,
    pub verbose: Option<bool>,
    pub combo_mode: Option<bool>,
    /// Generic key→value prompt overrides.
    /// When set, `cfg_prompt_*` functions in utils.rs return these values
    /// instead of prompting stdin. Keys match prompt names like "port", "mode", etc.
    pub custom_prompts: HashMap<String, String>,
    /// When true, cfg_prompt_* will return an error instead of falling back
    /// to stdin. This prevents the API server from blocking on interactive prompts.
    pub api_mode: bool,
}

impl ModuleConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all settings
    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

impl Default for ModuleConfig {
    fn default() -> Self {
        Self {
            port: None,
            username_wordlist: None,
            password_wordlist: None,
            concurrency: None,
            stop_on_success: None,
            save_results: None,
            output_file: None,
            verbose: None,
            combo_mode: None,
            custom_prompts: HashMap::new(),
            api_mode: false,
        }
    }
}

/// Global module config instance (API-provided configuration)
pub static MODULE_CONFIG: Lazy<Arc<RwLock<ModuleConfig>>> = Lazy::new(|| {
    Arc::new(RwLock::new(ModuleConfig::new()))
});

/// Set module config from API request
pub fn set_module_config(config: ModuleConfig) {
    if let Ok(mut guard) = MODULE_CONFIG.write() {
        *guard = config;
    }
}

/// Get a clone of the current module config
pub fn get_module_config() -> ModuleConfig {
    MODULE_CONFIG.read()
        .map(|g| g.clone())
        .unwrap_or_default()
}

/// Clear module config (should be called after module execution)
pub fn clear_module_config() {
    if let Ok(mut guard) = MODULE_CONFIG.write() {
        guard.clear();
    }
}

/// Get the results directory (~/.rustsploit/results/) — creates it if needed.
/// Module output files are stored here when running via API.
pub fn results_dir() -> std::path::PathBuf {
    let dir = home::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".rustsploit")
        .join("results");
    if !dir.exists() {
        let _ = std::fs::create_dir_all(&dir);
    }
    dir
}

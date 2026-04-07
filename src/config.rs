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
    /// Comma-separated list of targets (IPs, hostnames, and/or CIDRs)
    Multi(Vec<String>),
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

        // Mass scan keywords: "random", "0.0.0.0" — store as-is
        if trimmed == "random" || trimmed == "0.0.0.0" {
            let mut target_guard = self.target.write().map_err(|_| anyhow!("Config lock poisoned"))?;
            *target_guard = Some(TargetConfig::Single(trimmed.to_string()));
            return Ok(());
        }

        // File-based target list: resolve canonical path to prevent traversal,
        // then store if the file exists. This check must come before the ".."
        // rejection so relative file paths like "../targets.txt" work.
        let path = std::path::Path::new(trimmed);
        if path.exists() && path.is_file() {
            // Resolve to canonical path (eliminates .., symlinks, etc.)
            let canonical = path.canonicalize()
                .map_err(|e| anyhow!("Failed to resolve file path '{}': {}", trimmed, e))?;
            let canonical_str = canonical.to_string_lossy().to_string();
            let mut target_guard = self.target.write().map_err(|_| anyhow!("Config lock poisoned"))?;
            *target_guard = Some(TargetConfig::Single(canonical_str));
            return Ok(());
        }

        // Check for path traversal attempts (only for non-file targets)
        if trimmed.contains("..") || trimmed.contains("//") {
            return Err(anyhow!("Target contains invalid characters (path traversal)"));
        }

        // Comma-separated multi-target: "10.0.0.1, 192.168.1.0/24, example.com"
        if trimmed.contains(',') {
            let targets: Vec<String> = trimmed
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();
            if targets.is_empty() {
                return Err(anyhow!("No valid targets in comma-separated list"));
            }
            if targets.len() == 1 {
                // Single target after parsing — recurse without comma
                return self.set_target(&targets[0]);
            }
            // Validate each individual target, canonicalizing file paths
            const MASS_SCAN_KEYWORDS: &[&str] = &["random", "0.0.0.0", "0.0.0.0/0"];
            let mut validated_targets = Vec::with_capacity(targets.len());
            for t in &targets {
                // Allow mass scan keywords, CIDRs, file paths, and hostnames/IPs
                if MASS_SCAN_KEYWORDS.contains(&t.as_str()) {
                    validated_targets.push(t.clone());
                    continue;
                }
                let path = std::path::Path::new(t.as_str());
                if path.exists() && path.is_file() {
                    // Canonicalize file paths to prevent traversal
                    let canonical = path.canonicalize()
                        .map_err(|e| anyhow!("Failed to resolve file path '{}': {}", t, e))?;
                    validated_targets.push(canonical.to_string_lossy().to_string());
                    continue;
                }
                if t.parse::<IpNetwork>().is_ok() {
                    validated_targets.push(t.clone());
                    continue;
                }
                Self::validate_hostname_or_ip(t)?;
                validated_targets.push(t.clone());
            }
            let mut target_guard = self.target.write().map_err(|_| anyhow!("Config lock poisoned"))?;
            *target_guard = Some(TargetConfig::Multi(validated_targets));
            return Ok(());
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
        static VALID_CHARS: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"^[a-zA-Z0-9.\-_:\[\]]+$").expect("hardcoded regex must compile")
        });
        let valid_chars = &*VALID_CHARS;
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
            TargetConfig::Multi(targets) => targets.join(", "),
        })
    }

    /// Check if global target is set
    pub fn has_target(&self) -> bool {
        self.target.read().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Check if global target is a subnet
    pub fn is_subnet(&self) -> bool {
        self.target.read().map(|g| matches!(g.as_ref(), Some(TargetConfig::Subnet(_)) | Some(TargetConfig::Multi(_)))).unwrap_or(false)
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
                Some(Self::network_size(net))
            }
            Some(TargetConfig::Multi(targets)) => {
                let mut total = 0u64;
                for t in targets {
                    if let Ok(net) = t.parse::<IpNetwork>() {
                        total = total.saturating_add(Self::network_size(&net));
                    } else {
                        total = total.saturating_add(1);
                    }
                }
                Some(total)
            }
            None => None,
        }
    }

    /// Calculate the number of IPs in a network
    fn network_size(net: &IpNetwork) -> u64 {
        match net {
            IpNetwork::V4(net4) => {
                let prefix = net4.prefix() as u32;
                if prefix >= 32 { 1u64 } else { 2u64.pow(32 - prefix) }
            }
            IpNetwork::V6(net6) => {
                let prefix = net6.prefix() as u32;
                if prefix >= 128 {
                    1u64
                } else {
                    let exp = 128u32.saturating_sub(prefix);
                    if exp > 63 { u64::MAX } else { 2u64.pow(exp) }
                }
            }
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
use std::sync::LazyLock as Lazy;

pub static GLOBAL_CONFIG: Lazy<GlobalConfig> = Lazy::new(|| GlobalConfig::new());

/// Module-level configuration for API-driven execution
/// This is set by the API before running a module and read by modules
/// to get pre-configured values instead of prompting the user
///
/// # Unified Prompt Keys
///
/// These are the standardized `custom_prompts` keys used across all
/// scanner modules (via `cfg_prompt_*` in utils.rs). Supply them in the
/// JSON `"prompts"` object of an API `/api/run` request.
///
/// ## Common Keys (used by many modules)
/// | Key               | Type   | Description                                    |
/// |-------------------|--------|------------------------------------------------|
/// | `port`            | u16    | Target service port                            |
/// | `timeout`         | int    | Connection/request timeout (seconds or ms)     |
/// | `verbose`         | y/n    | Verbose output                                 |
/// | `save_results`    | y/n    | Save results to file                           |
/// | `output_file`     | string | Output filename for results                    |
/// | `concurrency`     | int    | Number of concurrent threads/tasks             |
/// | `threads`         | int    | Alias for concurrency (some modules)           |
/// | `wordlist`        | path   | Path to wordlist file                          |
/// | `target_file`     | path   | Path to file containing targets                |
/// | `additional_targets` | string | Comma-separated additional targets           |
/// | `mode`            | string | Operation mode selector (1, 2, 3, etc.)        |
///
/// ## Scanner-Specific Keys
///
/// ### Port Scanner (`scanners/port_scanner`)
/// `port_range`, `scan_method`, `show_only_open`, `ttl`, `source_port`, `data_length`
///
/// ### SSH Scanner (`scanners/ssh_scanner`)
/// `load_from_file`, `target_file`
///
/// ### DNS Recursion (`scanners/dns_recursion`)
/// `domain`, `record_type`
///
/// ### SMTP User Enum (`scanners/smtp_user_enum`)
/// `timeout_ms`, `save_valid`, `valid_output`, `save_unknown`, `unknown_output`
///
/// ### Ping Sweep (`scanners/ping_sweep`)
/// `add_manual_targets`, `manual_target`, `load_from_file`, `save_up_hosts`,
/// `up_hosts_file`, `save_down_hosts`, `down_hosts_file`, `use_icmp`, `use_tcp`,
/// `tcp_ports`, `use_syn`, `syn_ports`, `use_ack`, `ack_ports`
///
/// ### HTTP Title Scanner (`scanners/http_title_scanner`)
/// `check_http`, `check_https`, `use_ports`, `ports`
///
/// ### HTTP Method Scanner (`scanners/http_method_scanner`)
/// `scheme`, `use_ports`, `ports`
///
/// ### Dir Brute (`scanners/dir_brute`)
/// `scan_mode`, `delay_ms`, `random_agent`, `custom_cookies`, `cookies`,
/// `use_https`, `base_path`, `template_name`, `template_file`, `sort_by`
///
/// ### Sequential Fuzzer (`scanners/sequential_fuzzer`)
/// `min_length`, `max_length`, `charset`, `custom_charset`, `encoding`,
/// `add_cookies`, `cookies`, `append_slash`, `template_name`, `template_file`, `target_url`
///
/// ### API Endpoint Scanner (`scanners/api_endpoint_scanner`)
/// `output_dir`, `use_spoofing`, `use_generic_payload`, `enable_delete`,
/// `enable_extended_methods`, `modules`, `enum_mode`, `id_start`, `id_end`,
/// `id_file`, `endpoint_source`, `base_path`, `endpoint_file`
///
/// ### IPMI Enum/Exploit (`scanners/ipmi_enum_exploit`)
/// `cidr`, `target`, `test_cipher_zero`, `test_anonymous`, `test_default_creds`,
/// `test_rakp_hash`, `continue_large_scan`, `destroy_confirm`
///
/// ### SSDP MSearch (`scanners/ssdp_msearch`)
/// `retries`, `search_target`
///
/// ### Sample Scanner (`scanners/sample_scanner`)
/// `check_http`, `check_https`
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

/// Get a clone of the current module config.
/// Checks the task-local RunContext first (for concurrent API runs),
/// then falls back to the global MODULE_CONFIG.
pub fn get_module_config() -> ModuleConfig {
    // Try task-local context first (set by API handler per-request)
    let task_local = crate::context::RUN_CONTEXT.try_with(|ctx| ctx.config.clone());
    if let Ok(config) = task_local {
        return config;
    }
    // Fallback to global (for CLI/shell mode)
    MODULE_CONFIG.read()
        .map(|g| g.clone())
        .unwrap_or_default()
}

/// Get the per-request target from the task-local RunContext, if set.
/// Returns `None` in shell/CLI mode or when no context is active.
pub fn get_run_target() -> Option<String> {
    crate::context::RUN_CONTEXT
        .try_with(|ctx| ctx.target.clone())
        .ok()
        .flatten()
}

/// Get the results directory (~/.rustsploit/results/) — creates it if needed.
/// Module output files are stored here when running via API.
pub fn results_dir() -> std::path::PathBuf {
    let dir = home::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".rustsploit")
        .join("results");
    if !dir.exists() {
        use std::os::unix::fs::DirBuilderExt;
        if let Err(e) = std::fs::DirBuilder::new().mode(0o700).recursive(true).create(&dir) { crate::meprintln!("[!] Directory creation error: {}", e); }
    }
    dir
}

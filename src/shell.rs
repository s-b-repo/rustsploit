use crate::commands;
use crate::utils;
use crate::config;
use anyhow::{Context, Result};
use colored::*;
use std::io::{self, Write};
use url::Url;
use ipnetwork::IpNetwork;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Config, Editor, Helper};

const MAX_INPUT_LENGTH: usize = 4096;
const MAX_COMMAND_CHAIN_LENGTH: usize = 10;
const MAX_URL_LENGTH: usize = 2048;

const MAX_PROMPT_INPUT_LENGTH: usize = 1024;

/// IPv6 prefix threshold for size calculations (prefixes > this use u64 formula, otherwise u64::MAX)
const IPV6_PREFIX_THRESHOLD: u8 = 64;

/// Shell commands available for tab completion.
const SHELL_COMMANDS: &[&str] = &[
    "help", "modules", "find", "use", "set target", "set subnet",
    "set port", "set source_port",
    "show_target", "clear_target", "run", "run_all", "back", "exit", "quit",
    "info", "check", "setg", "unsetg", "show options",
    "creds", "creds add", "creds search", "creds delete", "creds clear",
    "spool", "spool off", "resource", "makerc",
    "hosts", "hosts add", "hosts delete", "hosts clear",
    "services", "services add", "services delete", "notes", "workspace",
    "loot", "loot add", "loot search", "loot delete", "loot clear",
    "export json", "export csv", "export summary",
    "jobs", "jobs -k", "jobs clean",
];

/// Tab-completion helper for the interactive shell.
struct RsfCompleter {
    module_paths: Vec<String>,
}

impl RsfCompleter {
    fn new() -> Self {
        // Use build-time registry for reliable module discovery
        let modules = crate::commands::discover_modules();
        Self { module_paths: modules }
    }
}

impl Completer for RsfCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let line_up_to_cursor = &line[..pos];

        // After "use " or "u ", complete module paths
        let module_prefix = if let Some(rest) = line_up_to_cursor.strip_prefix("use ") {
            Some(rest)
        } else if let Some(rest) = line_up_to_cursor.strip_prefix("u ") {
            Some(rest)
        } else if let Some(rest) = line_up_to_cursor.strip_prefix("info ") {
            Some(rest)
        } else if let Some(rest) = line_up_to_cursor.strip_prefix("check ") {
            Some(rest)
        } else {
            None
        };

        if let Some(prefix) = module_prefix {
            let start = pos - prefix.len();
            let matches: Vec<Pair> = self
                .module_paths
                .iter()
                .filter(|m| m.starts_with(prefix))
                .map(|m| Pair {
                    display: m.clone(),
                    replacement: m.clone(),
                })
                .collect();
            return Ok((start, matches));
        }

        // Otherwise complete commands
        let matches: Vec<Pair> = SHELL_COMMANDS
            .iter()
            .filter(|cmd| cmd.starts_with(line_up_to_cursor))
            .map(|cmd| Pair {
                display: cmd.to_string(),
                replacement: cmd.to_string(),
            })
            .collect();
        Ok((0, matches))
    }
}

impl Hinter for RsfCompleter {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &rustyline::Context<'_>) -> Option<String> {
        if pos < line.len() {
            return None;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }

        // After "use " or "u ", hint module paths
        let module_prefix = if let Some(rest) = trimmed.strip_prefix("use ") {
            Some(rest)
        } else if let Some(rest) = trimmed.strip_prefix("u ") {
            Some(rest)
        } else {
            None
        };

        if let Some(prefix) = module_prefix {
            if let Some(m) = self.module_paths.iter().find(|m| m.starts_with(prefix) && *m != prefix) {
                return Some(m[prefix.len()..].to_string());
            }
            return None;
        }

        // Hint shell commands
        if let Some(cmd) = SHELL_COMMANDS.iter().find(|c| c.starts_with(trimmed) && **c != trimmed) {
            return Some(cmd[trimmed.len()..].to_string());
        }

        None
    }
}
impl Highlighter for RsfCompleter {}
impl Validator for RsfCompleter {}
impl Helper for RsfCompleter {}

/// Path to persistent command history file.
fn history_path() -> std::path::PathBuf {
    let dir = home::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".rustsploit");
    use std::os::unix::fs::DirBuilderExt;
    if let Err(e) = std::fs::DirBuilder::new().mode(0o700).recursive(true).create(&dir) { crate::meprintln!("[!] Directory creation error: {}", e); }
    dir.join("history.txt")
}

/// Simple interactive shell context
struct ShellContext {
    current_module: Option<String>,
    verbose: bool,
    /// Current resource script nesting depth (prevents infinite recursion).
    resource_depth: usize,
}

impl ShellContext {
    fn new(verbose: bool) -> Self {
        ShellContext {
            current_module: None,
            verbose,
            resource_depth: 0,
        }
    }
}

pub async fn interactive_shell_with_resource(verbose: bool, resource_file: Option<&str>) -> Result<()> {
    interactive_shell_inner(verbose, resource_file).await
}

pub async fn interactive_shell(verbose: bool) -> Result<()> {
    interactive_shell_inner(verbose, None).await
}

async fn interactive_shell_inner(verbose: bool, resource_file: Option<&str>) -> Result<()> {
    crate::mprintln!("Welcome to RustSploit Shell (inspired by RouterSploit)");
    crate::mprintln!("Type 'help' for a list of commands. Type 'exit' or 'quit' to leave.");

    // Show global target if set
    if config::GLOBAL_CONFIG.has_target() {
        let target_str = match config::GLOBAL_CONFIG.get_target() {
            Some(t) => t,
            None => String::new(),
        };
        if let Some(size) = config::GLOBAL_CONFIG.get_target_size() {
            if size > 1 {
                crate::mprintln!("{}", format!("[*] Global target set: {} ({} IPs)", target_str, size).cyan());
            } else {
                crate::mprintln!("{}", format!("[*] Global target set: {}", target_str).cyan());
            }
        } else {
            crate::mprintln!("{}", format!("[*] Global target set: {}", target_str).cyan());
        }
    }

    // Check for third-party plugins
    let n_plugins = crate::commands::plugin_count();
    if n_plugins > 0 {
        crate::mprintln!();
        crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════════════════╗".red());
        crate::mprintln!("{}", "║                  WARNING: THIRD-PARTY PLUGINS DETECTED                  ║".red().bold());
        crate::mprintln!("{}", "╠══════════════════════════════════════════════════════════════════════════╣".red());
        crate::mprintln!("{}", "║  This instance has loaded third-party plugin modules from the           ║".red());
        crate::mprintln!("{}", "║  plugins/ directory. These modules are NOT developed, maintained,       ║".red());
        crate::mprintln!("{}", "║  reviewed, or endorsed by the RustSploit project.                       ║".red());
        crate::mprintln!("{}", "║                                                                         ║".red());
        crate::mprintln!("{}", "║  DISCLAIMER:                                                            ║".red());
        crate::mprintln!("{}", "║  - Third-party plugins may contain malicious code, backdoors, or        ║".red());
        crate::mprintln!("{}", "║    vulnerabilities that could compromise your system or network.         ║".red());
        crate::mprintln!("{}", "║  - The RustSploit developers are NOT responsible or liable for any      ║".red());
        crate::mprintln!("{}", "║    damage, data loss, unauthorized access, legal consequences, or       ║".red());
        crate::mprintln!("{}", "║    other harm caused by third-party plugins.                            ║".red());
        crate::mprintln!("{}", "║  - Use third-party plugins entirely at your own risk.                   ║".red());
        crate::mprintln!("{}", "║  - Only install plugins from sources you trust and have audited.        ║".red());
        crate::mprintln!("{}", "║  - Plugins have full access to your system with the same privileges     ║".red());
        crate::mprintln!("{}", "║    as RustSploit itself.                                                ║".red());
        crate::mprintln!("{}",  format!("║  Loaded plugins: {:<56}║", n_plugins).red());
        crate::mprintln!("{}", "║  To disable: remove files from src/modules/plugins/ and rebuild.        ║".red());
        crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════════════════╝".red());
        crate::mprintln!();
    }

    // Show global options count if any are set
    let gopts = crate::global_options::GLOBAL_OPTIONS.all().await;
    if !gopts.is_empty() {
        crate::mprintln!("{}", format!("[*] {} global option(s) loaded (use 'show options' to view)", gopts.len()).cyan());
    }

    let mut ctx = ShellContext::new(verbose);

    let rl_config = Config::builder()
        .max_history_size(1000)
        .context("Failed to configure shell history size")?
        .auto_add_history(true)
        .build();
    let mut rl = Editor::with_config(rl_config)?;
    rl.set_helper(Some(RsfCompleter::new()));
    let hist = history_path();
    if let Err(e) = rl.load_history(&hist) { crate::meprintln!("[!] History load error: {}", e); }

    // Auto-load startup.rc if it exists
    let startup_rc = home::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".rustsploit")
        .join("startup.rc");
    if startup_rc.exists() {
        crate::mprintln!("{}", format!("[*] Loading startup script: {}", startup_rc.display()).cyan());
        execute_resource_file_inner(&mut ctx, &startup_rc.to_string_lossy(), 0).await;
    }

    // Execute CLI-provided resource file (-r flag)
    if let Some(rc_file) = resource_file {
        crate::mprintln!("{}", format!("[*] Loading resource script: {}", rc_file).cyan());
        execute_resource_file_inner(&mut ctx, rc_file, 0).await;
    }

    'main_loop: loop {
        let raw_input = match rl.readline(&format!("{}", "rsf> ".cyan().bold())) {
            Ok(line) => line,
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => break 'main_loop,
            Err(e) => return Err(e.into()),
        };

        if raw_input.len() > MAX_INPUT_LENGTH {
            crate::mprintln!(
                "{}",
                format!(
                    "[!] Input length exceeds {} characters and was ignored.",
                    MAX_INPUT_LENGTH
                )
                    .yellow()
            );
            continue;
        }
        let trimmed = raw_input.trim();

        if trimmed.is_empty() {
            continue;
        }

        // Support command chaining with & separator
        let commands: Vec<&str> = trimmed
        .split('&')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .take(MAX_COMMAND_CHAIN_LENGTH)
        .collect();

        if trimmed.split('&').count() > MAX_COMMAND_CHAIN_LENGTH {
            crate::mprintln!(
                "{}",
                format!("[!] Command chain exceeds maximum length of {}. Truncating.", MAX_COMMAND_CHAIN_LENGTH)
                    .yellow()
            );
        }

        for cmd_input in commands {
            if cmd_input.is_empty() {
                continue;
            }

            let should_break = execute_single_command(&mut ctx, cmd_input).await;
            // Spool the command
            crate::spool::SPOOL.write_line(&format!("rsf> {}", cmd_input));
            if should_break {
                break 'main_loop;
            }
        }
    }

    if let Err(e) = rl.save_history(&hist) { crate::meprintln!("[!] History save error: {}", e); }
    Ok(())
}

/// Execute a single shell command. Returns true if the shell should exit.
async fn execute_single_command(ctx: &mut ShellContext, cmd_input: &str) -> bool {
    // Normalize compound commands: "show options" → "show_options", "show target" → "show_target"
    let normalized = if cmd_input.starts_with("show ") {
        cmd_input.replacen("show ", "show_", 1)
    } else if cmd_input.starts_with("clear ") {
        cmd_input.replacen("clear ", "clear_", 1)
    } else {
        cmd_input.to_string()
    };
    let cmd_input = normalized.as_str();

    let (cmd, rest) = split_command(cmd_input);
    if cmd.is_empty() {
        return false;
    }
    let command_key = resolve_command(&cmd);
    match command_key.as_str() {
                "exit" => {
                    crate::mprintln!("Exiting...");
                    return true;
                }
                "back" => {
                    ctx.current_module = None;
                    config::GLOBAL_CONFIG.clear_target();
                    crate::mprintln!("{}", "Cleared current module and target.".green());
                }
                "show_target" | "target" => {
                    if config::GLOBAL_CONFIG.has_target() {
                        let target_str = match config::GLOBAL_CONFIG.get_target() {
                            Some(t) => t,
                            None => String::new(),
                        };
                        let is_multi = target_str.contains(',');
                        let is_subnet = config::GLOBAL_CONFIG.is_subnet() && !is_multi;
                        if let Some(size) = config::GLOBAL_CONFIG.get_target_size() {
                            if is_multi {
                                let count = target_str.split(',').count();
                                crate::mprintln!("{}", format!("Target (multi): {} ({} entries, ~{} IPs)", target_str, count, size).green());
                            } else if size > 1 && is_subnet {
                                crate::mprintln!("{}", format!("Target (subnet): {} ({} IPs)", target_str, size).green());
                            } else {
                                crate::mprintln!("{}", format!("Target: {}", target_str).green());
                            }
                        } else {
                            crate::mprintln!("{}", format!("Target: {}", target_str).green());
                        }
                    } else {
                        crate::mprintln!("{}", "No target set.".dimmed());
                    }
                    // Show port settings if set
                    if let Some(port) = crate::global_options::GLOBAL_OPTIONS.get("port").await {
                        crate::mprintln!("{}", format!("Port:        {}", port).green());
                    }
                    if let Some(sport) = crate::global_options::GLOBAL_OPTIONS.get("source_port").await {
                        crate::mprintln!("{}", format!("Source Port: {}", sport).green());
                    }
                }
                "clear_target" => {
                    config::GLOBAL_CONFIG.clear_target();
                    crate::mprintln!("{}", "Cleared target.".green());
                }
                "help" => render_help(),
                "modules" => utils::list_all_modules(),
                "find" => {
                    if rest.is_empty() {
                        crate::mprintln!("{}", "Usage: find <keyword>".yellow());
                    } else {
                        utils::find_modules(&rest);
                    }
                }

                "use" => {
                    if rest.is_empty() {
                        crate::mprintln!("{}", "Usage: use <module_path>".yellow());
                    } else if let Some(safe_path) = sanitize_module_path(&rest) {
                        if utils::module_exists(&safe_path) {
                            ctx.current_module = Some(safe_path.clone());
                            crate::mprintln!("{}", format!("Module '{}' selected.", safe_path).green());
                        } else {
                            crate::mprintln!("{}", format!("Module '{}' not found.", rest).red());
                        }
                    } else {
                        crate::mprintln!(
                            "{}",
                            "Module path contains invalid characters or traversal attempts."
                            .red()
                        );
                    }
                }
                "set" => {
                    // Handle "set port <val>" and "set source_port <val>" as global option shortcuts
                    if let Some(val) = rest.strip_prefix("port ") {
                        let val = val.trim();
                        match val.parse::<u16>() {
                            Ok(p) if p > 0 => {
                                crate::global_options::GLOBAL_OPTIONS.set("port", val).await;
                                crate::mprintln!("{}", format!("Global port set to: {}", val).green());
                            }
                            _ => crate::mprintln!("{}", "Invalid port. Must be 1-65535.".yellow()),
                        }
                    } else if let Some(val) = rest.strip_prefix("source_port ") {
                        let val = val.trim();
                        if val == "0" || val.is_empty() {
                            crate::global_options::GLOBAL_OPTIONS.unset("source_port").await;
                            crate::mprintln!("{}", "Source port cleared (will use OS-assigned).".green());
                        } else {
                            match val.parse::<u16>() {
                                Ok(p) if p > 0 => {
                                    crate::global_options::GLOBAL_OPTIONS.set("source_port", val).await;
                                    crate::mprintln!("{}", format!("Global source port set to: {}", val).green());
                                }
                                _ => crate::mprintln!("{}", "Invalid source port. Must be 1-65535 (or 0 to clear).".yellow()),
                            }
                        }
                    } else {
                    // Handle shortcuts: "target <val>", "t <val>", "set target <val>", "set t <val>"
                    let raw_value = if cmd == "target" || cmd == "t" {
                        &rest
                    } else if let Some(val) = rest.strip_prefix("target ") {
                        val
                    } else if let Some(val) = rest.strip_prefix("t ") {
                        val
                    } else {
                        ""
                    };

                    let raw_value = raw_value.trim();

                    if raw_value.is_empty() {
                        crate::mprintln!("{}", "Usage: set target <value>".yellow());
                        crate::mprintln!("{}", "  Shortcuts: t <value>, target <value>".dimmed());
                        crate::mprintln!("{}", "  For subnets: set subnet <CIDR> or sn <CIDR>".dimmed());
                        crate::mprintln!("{}", "  set port <1-65535>    — Set target port for all modules".dimmed());
                        crate::mprintln!("{}", "  set source_port <val> — Set source port (0 to clear)".dimmed());
                        crate::mprintln!("{}", "  Examples:".dimmed());
                        crate::mprintln!("{}", "    t 192.168.1.1".dimmed());
                        crate::mprintln!("{}", "    t 10.0.0.1, 192.168.1.1, 172.16.0.5".dimmed());
                        crate::mprintln!("{}", "    t 10.0.0.0/24, 192.168.1.1".dimmed());
                        crate::mprintln!("{}", "    sn 10.16.0.0/24".dimmed());
                        crate::mprintln!("{}", "    set target example.com".dimmed());
                        crate::mprintln!("{}", "    set target random".dimmed());
                        crate::mprintln!("{}", "    set target /path/to/targets.txt".dimmed());
                        crate::mprintln!("{}", "    set port 8080".dimmed());
                        crate::mprintln!("{}", "    set source_port 31337".dimmed());
                    } else {
                        match sanitize_target(raw_value) {
                            Ok(valid_target) => {
                                // Check if target is a domain — offer protocol/port selection
                                // Skip domain prompt for multi-target (comma-separated)
                                let final_target = if !valid_target.contains(',') && utils::is_domain(&valid_target) {
                                    match utils::prompt_domain_target(&valid_target).await {
                                        Ok((resolved, _url)) => resolved,
                                        Err(e) => {
                                            crate::mprintln!("{}", format!("[!] Domain targeting failed: {}", e).red());
                                            crate::mprintln!("{}", "[*] Falling back to raw target".yellow());
                                            valid_target.clone()
                                        }
                                    }
                                } else {
                                    valid_target.clone()
                                };

                                match config::GLOBAL_CONFIG.set_target(&final_target) {
                                    Ok(_) => {
                                        if final_target.contains(',') {
                                            let count = final_target.split(',').count();
                                            if let Some(size) = config::GLOBAL_CONFIG.get_target_size() {
                                                crate::mprintln!("{}", format!("Target set to: {} ({} entries, ~{} IPs)", final_target, count, size).green());
                                            } else {
                                                crate::mprintln!("{}", format!("Target set to: {} ({} entries)", final_target, count).green());
                                            }
                                        } else if final_target.contains('/') {
                                            let ip_part = final_target.split('/').next().unwrap_or(&final_target);
                                            let prefix = final_target.split('/').nth(1).unwrap_or("");
                                            crate::mprintln!("{}", format!("Target set to: {} (subnet: /{})", ip_part, prefix).green());
                                        } else {
                                            crate::mprintln!("{}", format!("Target set to: {}", final_target).green());
                                        }
                                    }
                                    Err(e) => {
                                        crate::mprintln!("{}", format!("[!] Failed to set target: {}", e).red());
                                    }
                                }
                            }
                            Err(reason) => {
                                crate::mprintln!("{}", format!("[!] {}", reason).yellow());
                            }
                        }
                    }
                    } // end of else (port/source_port/target handling)
                }
                "set_subnet" => {
                    // Handle shortcuts: "subnet <val>", "sn <val>", "set subnet <val>", "set sn <val>"
                    let raw_value = if cmd == "subnet" || cmd == "sn" {
                        &rest
                    } else if let Some(val) = rest.strip_prefix("subnet ") {
                        val
                    } else if let Some(val) = rest.strip_prefix("sn ") {
                        val
                    } else {
                        ""
                    };

                    let raw_value = raw_value.trim();

                    if raw_value.is_empty() {
                        crate::mprintln!("{}", "Usage: set subnet <CIDR>".yellow());
                        crate::mprintln!("{}", "  Shortcuts: sn <CIDR>, subnet <CIDR>".dimmed());
                        crate::mprintln!("{}", "  Examples:".dimmed());
                        crate::mprintln!("{}", "    sn 192.168.1.0/24".dimmed());
                        crate::mprintln!("{}", "    set subnet 10.0.0.0/16".dimmed());
                    } else {
                        // Validate it's a CIDR subnet, not a plain IP
                        if !raw_value.contains('/') {
                            crate::mprintln!("{}", "[!] Not a subnet. Use CIDR notation (e.g. 192.168.1.0/24).".yellow());
                            crate::mprintln!("{}", "    For single IPs, use: set target <IP>".dimmed());
                        } else {
                            match sanitize_target(raw_value) {
                                Ok(valid_target) => {
                                    // Verify it actually parses as CIDR
                                    if valid_target.parse::<IpNetwork>().is_err() {
                                        crate::mprintln!("{}", format!("[!] Invalid CIDR notation: {}", valid_target).red());
                                    } else {
                                        match config::GLOBAL_CONFIG.set_target(&valid_target) {
                                            Ok(_) => {
                                                if let Some(size) = config::GLOBAL_CONFIG.get_target_size() {
                                                    crate::mprintln!("{}", format!("Subnet set to: {} ({} IPs)", valid_target, size).green());
                                                } else {
                                                    crate::mprintln!("{}", format!("Subnet set to: {}", valid_target).green());
                                                }
                                            }
                                            Err(e) => {
                                                crate::mprintln!("{}", format!("[!] Failed to set subnet: {}", e).red());
                                            }
                                        }
                                    }
                                }
                                Err(reason) => {
                                    crate::mprintln!("{}", format!("[!] {}", reason).yellow());
                                }
                            }
                        }
                    }
                }

                // ═══════════════════════════════════════════════
                // INFO command (Feature 1)
                // ═══════════════════════════════════════════════
                "info" => {
                    let module_path = if !rest.is_empty() {
                        Some(rest.clone())
                    } else {
                        ctx.current_module.clone()
                    };

                    if let Some(ref path) = module_path {
                        if let Some(info) = commands::module_info(path) {
                            crate::module_info::display_module_info(path, &info);
                        } else {
                            crate::mprintln!("{}", format!("No metadata available for '{}'.", path).dimmed());
                            crate::mprintln!("{}", "Modules can provide metadata by adding a pub fn info() -> ModuleInfo function.".dimmed());
                        }
                    } else {
                        crate::mprintln!("{}", "No module selected. Use 'info <module_path>' or select a module first.".yellow());
                    }
                }

                // ═══════════════════════════════════════════════
                // CHECK command (Feature 6)
                // ═══════════════════════════════════════════════
                "check" => {
                    let module_path = ctx.current_module.clone();
                    if let Some(ref path) = module_path {
                        let target = config::GLOBAL_CONFIG.get_target();
                        if let Some(ref t) = target {
                            crate::mprintln!("{}", format!("[*] Checking {} against {}...", path, t).cyan());
                            match commands::check_module(path, t).await {
                                Some(result) => {
                                    use crate::module_info::CheckResult;
                                    match &result {
                                        CheckResult::Vulnerable(msg) => crate::mprintln!("{}", format!("[+] VULNERABLE: {}", msg).green().bold()),
                                        CheckResult::NotVulnerable(msg) => crate::mprintln!("{}", format!("[-] Not vulnerable: {}", msg).red()),
                                        CheckResult::Unknown(msg) => crate::mprintln!("{}", format!("[?] Unknown: {}", msg).yellow()),
                                        CheckResult::Error(msg) => crate::mprintln!("{}", format!("[!] Error: {}", msg).red()),
                                    }
                                }
                                None => crate::mprintln!("{}", format!("Module '{}' does not support the check method.", path).dimmed()),
                            }
                        } else {
                            crate::mprintln!("{}", "No target set. Use 'set target <value>' first.".yellow());
                        }
                    } else {
                        crate::mprintln!("{}", "No module selected. Use 'use <module>' first.".yellow());
                    }
                }

                // ═══════════════════════════════════════════════
                // GLOBAL OPTIONS (Feature 2)
                // ═══════════════════════════════════════════════
                "setg" => {
                    if let Some((key, value)) = rest.split_once(char::is_whitespace) {
                        let key = key.trim();
                        let value = value.trim();
                        if key.is_empty() || value.is_empty() {
                            crate::mprintln!("{}", "Usage: setg <key> <value>".yellow());
                        } else {
                            crate::global_options::GLOBAL_OPTIONS.set(key, value).await;
                            crate::mprintln!("{}", format!("{} => {}", key.green(), value).to_string());
                        }
                    } else {
                        crate::mprintln!("{}", "Usage: setg <key> <value>".yellow());
                        crate::mprintln!("{}", "  Example: setg port 8080".dimmed());
                    }
                }
                "unsetg" => {
                    let key = rest.trim();
                    if key.is_empty() {
                        crate::mprintln!("{}", "Usage: unsetg <key>".yellow());
                    } else if crate::global_options::GLOBAL_OPTIONS.unset(key).await {
                        crate::mprintln!("{}", format!("Unset global option '{}'", key).green());
                    } else {
                        crate::mprintln!("{}", format!("Global option '{}' was not set.", key).dimmed());
                    }
                }
                "show_options" => {
                    crate::global_options::GLOBAL_OPTIONS.display().await;
                }

                // ═══════════════════════════════════════════════
                // CREDENTIALS (Feature 3)
                // ═══════════════════════════════════════════════
                "creds" => {
                    if rest.is_empty() {
                        crate::cred_store::CRED_STORE.display().await;
                    } else if rest == "add" {
                        // Interactive cred add
                        let host = match utils::prompt_required("Host").await { Ok(v) => v, Err(_) => return false };
                        let port_str = match utils::prompt_default("Port", "0").await { Ok(v) => v, Err(_) => return false };
                        let port: u16 = match port_str.parse() {
                            Ok(p) if p > 0 => p,
                            Ok(_) => 0, // port 0 = unknown, acceptable for creds
                            Err(_) => { crate::mprintln!("{}", "[!] Invalid port number.".red()); return false; }
                        };
                        let service = match utils::prompt_default("Service", "unknown").await { Ok(v) => v, Err(_) => return false };
                        let username = match utils::prompt_required("Username").await { Ok(v) => v, Err(_) => return false };
                        let secret = match utils::prompt_required("Password/Hash/Key").await { Ok(v) => v, Err(_) => return false };
                        let ctype = match utils::prompt_default("Type (password/hash/key/token)", "password").await { Ok(v) => v, Err(_) => return false };
                        let cred_type = match ctype.as_str() {
                            "hash" => crate::cred_store::CredType::Hash,
                            "key" => crate::cred_store::CredType::Key,
                            "token" => crate::cred_store::CredType::Token,
                            _ => crate::cred_store::CredType::Password,
                        };
                        let id = crate::cred_store::CRED_STORE.add(&host, port, &service, &username, &secret, cred_type, "manual").await;
                        crate::mprintln!("{}", format!("[+] Credential stored (ID: {})", id).green());
                    } else if let Some(query) = rest.strip_prefix("search ") {
                        let results = crate::cred_store::CRED_STORE.search(query.trim()).await;
                        crate::cred_store::CRED_STORE.display_results(&results);
                    } else if let Some(id) = rest.strip_prefix("delete ") {
                        if crate::cred_store::CRED_STORE.delete(id.trim()).await {
                            crate::mprintln!("{}", format!("[+] Credential '{}' deleted.", id.trim()).green());
                        } else {
                            crate::mprintln!("{}", format!("[-] Credential '{}' not found.", id.trim()).red());
                        }
                    } else if rest == "clear" {
                        crate::cred_store::CRED_STORE.clear().await;
                        crate::mprintln!("{}", "[+] All credentials cleared.".green());
                    } else {
                        crate::mprintln!("{}", "Usage: creds [add|search <query>|delete <id>|clear]".yellow());
                    }
                }

                // ═══════════════════════════════════════════════
                // SPOOL (Feature 4)
                // ═══════════════════════════════════════════════
                "spool" => {
                    if rest.is_empty() {
                        crate::spool::display_status();
                    } else if rest == "off" {
                        if let Some(name) = crate::spool::SPOOL.stop() {
                            crate::mprintln!("{}", format!("[+] Spool stopped. Output saved to '{}'", name).green());
                        } else {
                            crate::mprintln!("{}", "Spool was not active.".dimmed());
                        }
                    } else {
                        match crate::spool::SPOOL.start(&rest) {
                            Ok(()) => crate::mprintln!("{}", format!("[+] Spooling output to '{}'", rest).green()),
                            Err(e) => crate::mprintln!("{}", format!("[!] Failed to start spool: {}", e).red()),
                        }
                    }
                }

                // ═══════════════════════════════════════════════
                // RESOURCE SCRIPTS (Feature 5)
                // ═══════════════════════════════════════════════
                "resource" => {
                    if rest.is_empty() {
                        crate::mprintln!("{}", "Usage: resource <script_file>".yellow());
                    } else {
                        let fname = rest.trim();
                        // Validate path — reject traversal and null bytes
                        if fname.contains('\0') || fname.contains("..") {
                            crate::mprintln!("{}", "[!] Invalid resource script path (path traversal not allowed).".red());
                        } else if fname.len() > 4096 {
                            crate::mprintln!("{}", "[!] Resource script path too long.".red());
                        } else {
                            // Warn if script is from outside ~/.rustsploit/
                            if std::path::Path::new(fname).is_absolute() {
                                let rustsploit_dir = home::home_dir()
                                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                                    .join(".rustsploit");
                                if !fname.starts_with(&rustsploit_dir.to_string_lossy().as_ref()) {
                                    crate::mprintln!("{}", format!("[*] Warning: executing script from outside ~/.rustsploit/: {}", fname).yellow());
                                }
                            }
                            let depth = ctx.resource_depth;
                            ctx.resource_depth += 1;
                            execute_resource_file_inner(ctx, fname, depth).await;
                            ctx.resource_depth = depth;
                        }
                    }
                }
                "makerc" => {
                    if rest.is_empty() {
                        crate::mprintln!("{}", "Usage: makerc <output_file>".yellow());
                    } else {
                        // Validate path — reject absolute paths, traversal, and directory separators
                        let fname = rest.trim();
                        if fname.contains("..") || fname.contains('\0') || fname.starts_with('/') || fname.starts_with('\\') || fname.contains('/') || fname.contains('\\') || fname.starts_with('.') {
                            crate::mprintln!("{}", "[!] Invalid filename. Use a simple filename like 'session.rc' (no paths or traversal).".red());
                        } else if fname.len() > 255 {
                            crate::mprintln!("{}", "[!] Filename too long (max 255 chars).".red());
                        } else {
                            let hist_path = history_path();
                            match std::fs::read_to_string(&hist_path) {
                                Ok(contents) => {
                                    match std::fs::write(fname, &contents) {
                                        Ok(_) => crate::mprintln!("{}", format!("[+] Command history saved to '{}'", fname).green()),
                                        Err(e) => crate::mprintln!("{}", format!("[!] Failed to write: {}", e).red()),
                                    }
                                }
                                Err(e) => crate::mprintln!("{}", format!("[!] Failed to read history: {}", e).red()),
                            }
                        }
                    }
                }

                // ═══════════════════════════════════════════════
                // HOSTS / SERVICES / WORKSPACE (Feature 7)
                // ═══════════════════════════════════════════════
                "hosts" => {
                    if rest.is_empty() {
                        crate::workspace::WORKSPACE.display_hosts().await;
                    } else if let Some(ip) = rest.strip_prefix("add ") {
                        let ip = ip.trim();
                        if ip.is_empty() {
                            crate::mprintln!("{}", "Usage: hosts add <ip>".yellow());
                        } else {
                            crate::workspace::WORKSPACE.add_host(ip, None, None).await;
                            crate::mprintln!("{}", format!("[+] Host '{}' added to workspace.", ip).green());
                        }
                    } else if let Some(ip) = rest.strip_prefix("delete ") {
                        let ip = ip.trim();
                        if ip.is_empty() {
                            crate::mprintln!("{}", "Usage: hosts delete <ip>".yellow());
                        } else if crate::workspace::WORKSPACE.delete_host(ip).await {
                            crate::mprintln!("{}", format!("[+] Host '{}' and its services removed.", ip).green());
                        } else {
                            crate::mprintln!("{}", format!("[-] Host '{}' not found.", ip).red());
                        }
                    } else if rest == "clear" {
                        crate::workspace::WORKSPACE.clear_hosts().await;
                        crate::mprintln!("{}", "[+] All hosts and services cleared.".green());
                    } else {
                        crate::mprintln!("{}", "Usage: hosts [add <ip>|delete <ip>|clear]".yellow());
                    }
                }
                "services" => {
                    if rest.is_empty() {
                        crate::workspace::WORKSPACE.display_services().await;
                    } else if rest == "add" {
                        let host = match utils::prompt_required("Host IP").await { Ok(v) => v, Err(_) => return false };
                        let port_str = match utils::prompt_required("Port").await { Ok(v) => v, Err(_) => return false };
                        let port: u16 = match port_str.parse() {
                            Ok(p) if p > 0 => p,
                            _ => { crate::mprintln!("{}", "[!] Invalid port number (must be 1-65535).".red()); return false; }
                        };
                        let proto = match utils::prompt_default("Protocol", "tcp").await { Ok(v) => v, Err(_) => return false };
                        let svc = match utils::prompt_required("Service name").await { Ok(v) => v, Err(_) => return false };
                        let ver = match utils::prompt_default("Version", "").await { Ok(v) => v, Err(_) => return false };
                        let version = if ver.is_empty() { None } else { Some(ver.as_str()) };
                        crate::workspace::WORKSPACE.add_service(&host, port, &proto, &svc, version).await;
                        crate::mprintln!("{}", format!("[+] Service {}:{}/{} added.", host, port, svc).green());
                    } else if let Some(args) = rest.strip_prefix("delete ") {
                        let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
                        if parts.len() < 2 {
                            crate::mprintln!("{}", "Usage: services delete <host> <port>".yellow());
                        } else {
                            let host = parts[0].trim();
                            match parts[1].trim().parse::<u16>() {
                                Ok(port) if port > 0 => {
                                    if crate::workspace::WORKSPACE.delete_service(host, port).await {
                                        crate::mprintln!("{}", format!("[+] Service {}:{} removed.", host, port).green());
                                    } else {
                                        crate::mprintln!("{}", format!("[-] Service {}:{} not found.", host, port).red());
                                    }
                                }
                                _ => crate::mprintln!("{}", "Invalid port number.".yellow()),
                            }
                        }
                    } else {
                        crate::mprintln!("{}", "Usage: services [add|delete <host> <port>]".yellow());
                    }
                }
                "notes" => {
                    if let Some((ip, note)) = rest.split_once(char::is_whitespace) {
                        let ip = ip.trim();
                        let note = note.trim();
                        if ip.is_empty() || note.is_empty() {
                            crate::mprintln!("{}", "Usage: notes <ip> <note text>".yellow());
                        } else if crate::workspace::WORKSPACE.add_note(ip, note).await {
                            crate::mprintln!("{}", format!("[+] Note added to host '{}'.", ip).green());
                        } else {
                            crate::mprintln!("{}", format!("[-] Host '{}' not found. Add it first with 'hosts add {}'.", ip, ip).red());
                        }
                    } else {
                        crate::mprintln!("{}", "Usage: notes <ip> <note text>".yellow());
                    }
                }
                "workspace" => {
                    if rest.is_empty() {
                        let current = crate::workspace::WORKSPACE.current_name().await;
                        let workspaces = crate::workspace::WORKSPACE.list_workspaces().await;
                        crate::mprintln!();
                        crate::mprintln!("{}", "Workspaces:".bold().underline());
                        for ws in &workspaces {
                            if *ws == current {
                                crate::mprintln!("  {} {}", "*".green().bold(), ws.green().bold());
                            } else {
                                crate::mprintln!("    {}", ws);
                            }
                        }
                        crate::mprintln!();
                    } else {
                        let name = rest.trim();
                        if name.is_empty() || name.len() > 64 {
                            crate::mprintln!("{}", "Workspace name must be 1-64 characters.".red());
                        } else if name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
                            crate::workspace::WORKSPACE.switch(name).await;
                            crate::mprintln!("{}", format!("[+] Switched to workspace '{}'", name).green());
                        } else {
                            crate::mprintln!("{}", "Workspace name must be alphanumeric (with _ and -).".red());
                        }
                    }
                }

                // ═══════════════════════════════════════════════
                // LOOT (Feature 8)
                // ═══════════════════════════════════════════════
                "loot" => {
                    if rest.is_empty() {
                        crate::loot::LOOT_STORE.display().await;
                    } else if rest == "add" {
                        let host = match utils::prompt_required("Host").await { Ok(v) => v, Err(_) => return false };
                        let ltype = match utils::prompt_default("Type (config/password_file/firmware/hash/other)", "other").await { Ok(v) => v, Err(_) => return false };
                        let desc = match utils::prompt_required("Description").await { Ok(v) => v, Err(_) => return false };
                        let data = match utils::prompt_required("Data/content").await { Ok(v) => v, Err(_) => return false };
                        if let Some(id) = crate::loot::LOOT_STORE.add_text(&host, &ltype, &desc, &data, "manual").await {
                            crate::mprintln!("{}", format!("[+] Loot stored (ID: {})", id).green());
                        } else {
                            crate::mprintln!("{}", "[!] Failed to store loot.".red());
                        }
                    } else if let Some(query) = rest.strip_prefix("search ") {
                        let results = crate::loot::LOOT_STORE.search(query.trim()).await;
                        if results.is_empty() {
                            crate::mprintln!("{}", "No matching loot found.".dimmed());
                        } else {
                            for l in &results {
                                crate::mprintln!("  [{}] {} ({}) from {} - {}", l.id.yellow(), l.loot_type, l.host.green(), l.source_module, l.description);
                            }
                        }
                    } else if let Some(id) = rest.strip_prefix("delete ") {
                        let id = id.trim();
                        if id.is_empty() {
                            crate::mprintln!("{}", "Usage: loot delete <id>".yellow());
                        } else if crate::loot::LOOT_STORE.delete(id).await {
                            crate::mprintln!("{}", format!("[+] Loot '{}' deleted.", id).green());
                        } else {
                            crate::mprintln!("{}", format!("[-] Loot '{}' not found.", id).red());
                        }
                    } else if rest == "clear" {
                        crate::loot::LOOT_STORE.clear().await;
                        crate::mprintln!("{}", "[+] All loot cleared.".green());
                    } else {
                        crate::mprintln!("{}", "Usage: loot [add|search <query>|delete <id>|clear]".yellow());
                    }
                }

                // ═══════════════════════════════════════════════
                // EXPORT (Feature 9)
                // ═══════════════════════════════════════════════
                "export" => {
                    if let Some((fmt, path)) = rest.split_once(char::is_whitespace) {
                        let path = path.trim();
                        if let Err(e) = crate::export::validate_export_path(path) {
                            crate::mprintln!("{}", format!("[!] {}", e).red());
                        } else {
                            match fmt.trim() {
                                "json" => {
                                    if let Err(e) = crate::export::export_json(path).await {
                                        crate::mprintln!("{}", format!("[!] Export failed: {}", e).red());
                                    }
                                }
                                "csv" => {
                                    if let Err(e) = crate::export::export_csv(path).await {
                                        crate::mprintln!("{}", format!("[!] Export failed: {}", e).red());
                                    }
                                }
                                "summary" => {
                                    if let Err(e) = crate::export::export_summary(path).await {
                                        crate::mprintln!("{}", format!("[!] Export failed: {}", e).red());
                                    }
                                }
                                _ => crate::mprintln!("{}", "Usage: export <json|csv|summary> <filename>".yellow()),
                            }
                        }
                    } else {
                        crate::mprintln!("{}", "Usage: export <json|csv|summary> <filename>".yellow());
                    }
                }

                // ═══════════════════════════════════════════════
                // JOBS (Feature 10)
                // ═══════════════════════════════════════════════
                "jobs" => {
                    if rest.is_empty() {
                        crate::jobs::JOB_MANAGER.display();
                    } else if let Some(id_str) = rest.strip_prefix("-k ") {
                        if let Ok(id) = id_str.trim().parse::<u32>() {
                            if crate::jobs::JOB_MANAGER.kill(id) {
                                crate::mprintln!("{}", format!("[+] Job {} cancelled.", id).green());
                            } else {
                                crate::mprintln!("{}", format!("[-] Job {} not found.", id).red());
                            }
                        } else {
                            crate::mprintln!("{}", "Usage: jobs -k <id>".yellow());
                        }
                    } else if rest == "clean" {
                        crate::jobs::JOB_MANAGER.cleanup();
                        crate::mprintln!("{}", "[+] Finished jobs cleaned up.".green());
                    } else {
                        crate::mprintln!("{}", "Usage: jobs [-k <id>|clean]".yellow());
                    }
                }

                // ═══════════════════════════════════════════════
                // RUN (with -j background support)
                // ═══════════════════════════════════════════════
                "run" => {
                    let background = rest.trim() == "-j" || rest.trim() == "--job";

                    if let Some(ref module_path) = ctx.current_module {
                        // Get target from global config
                        let target = if config::GLOBAL_CONFIG.has_target() {
                            match config::GLOBAL_CONFIG.get_target() {
                                Some(t) => {
                                    crate::mprintln!("{}", format!("[*] Using target: {}", t).cyan());
                                    Some(t)
                                }
                                None => {
                                    crate::mprintln!("{}", "[!] Error getting target".red());
                                    None
                                }
                            }
                        } else {
                            None
                        };

                        // Interactive prompt if no target is set
                        let target = if target.is_none() {
                            crate::mprintln!("{}", "[!] Warning: No target set.".yellow());

                            match utils::prompt_yes_no("Do you want to provide a target address?", true).await {
                                Ok(true) => {
                                    match prompt_string_default("Enter target", "").await.map_err(|e| anyhow::anyhow!("{}", e)) {
                                        Ok(input) => {
                                            match sanitize_target(&input) {
                                                Ok(valid_target) => {
                                                    if let Err(e) = config::GLOBAL_CONFIG.set_target(&valid_target) {
                                                         crate::mprintln!("{}", format!("[!] Failed to set target: {}", e).red());
                                                         None
                                                    } else {
                                                         crate::mprintln!("{}", format!("[*] Target set to '{}'", valid_target).green());
                                                         Some(valid_target)
                                                    }
                                                },
                                                Err(e) => {
                                                    crate::mprintln!("{}", format!("[!] Invalid target: {}", e).red());
                                                    None
                                                }
                                            }
                                        },
                                        Err(e) => {
                                            crate::mprintln!("{}", format!("[!] Error reading input: {}", e).red());
                                            None
                                        }
                                    }
                                },
                                Ok(false) => {
                                    match utils::prompt_yes_no("Continue with localhost (127.0.0.1)?", false).await {
                                        Ok(true) => Some("127.0.0.1".to_string()),
                                        _ => {
                                            crate::mprintln!("{}", "[!] Execution aborted.".red());
                                            None
                                        }
                                    }
                                },
                                Err(_) => None,
                            }
                        } else {
                            target
                        };

                        if let Some(ref t) = target {
                            if background {
                                // Run as background job
                                let job_id = crate::jobs::JOB_MANAGER.spawn(
                                    module_path.clone(),
                                    t.clone(),
                                    ctx.verbose,
                                );
                                crate::mprintln!("{}", format!("[*] Job {} started: {} against {}", job_id, module_path, t).cyan());
                            } else {
                                // Normal foreground execution
                                let is_mass_scan = crate::modules::creds::utils::is_mass_scan_target(t);

                                // Honeypot detection — enabled by default, disable with: setg honeypot_detection n
                                let honeypot_on = crate::global_options::GLOBAL_OPTIONS
                                    .try_get("honeypot_detection")
                                    .map(|v| !matches!(v.to_lowercase().as_str(), "n"|"no"|"false"|"0"|"off"|"disabled"))
                                    .unwrap_or(true);

                                let mut skip_target = false;
                                if honeypot_on && !is_mass_scan {
                                    if crate::utils::network::quick_honeypot_check(t).await {
                                        crate::mprintln!("{}", format!(
                                            "[!] Target {} appears to be a honeypot (11+ common ports open)",
                                            t
                                        ).red().bold());
                                        let proceed = utils::prompt_yes_no(
                                            "Skip this honeypot?",
                                            true,
                                        ).await.unwrap_or(true);
                                        if proceed {
                                            crate::mprintln!("{}", "[*] Skipping honeypot target.".yellow());
                                            skip_target = true;
                                        }
                                    }
                                }

                                if !skip_target {
                                    crate::mprintln!("Running module '{}' against target '{}'", module_path, t);
                                    if let Err(e) = commands::run_module(module_path, t, ctx.verbose).await {
                                        crate::meprintln!("[!] Module failed: {:?}", e);
                                    }
                                }
                            }
                        } else {
                            crate::mprintln!("{}", "No target set. Use 'set target <value>' (or 't <value>') first.".yellow());
                            crate::mprintln!("{}", "  Examples:".dimmed());
                            crate::mprintln!("{}", "    set target 192.168.1.1".dimmed());
                            crate::mprintln!("{}", "    set target 192.168.1.0/24".dimmed());
                        }
                    } else {
                        crate::mprintln!("{}", "No module selected. Use 'use <module>' first.".yellow());
                    }
                }
                "run_all" => {
                    if let Some(ref module_path) = ctx.current_module {
                        if !config::GLOBAL_CONFIG.has_target() {
                            crate::mprintln!("{}", "No global target set. Use 'set target <ip/subnet>' first.".yellow());
                        } else if !config::GLOBAL_CONFIG.is_subnet() {
                            crate::mprintln!("{}", "Global target is not a subnet. Use 'run' for single targets.".yellow());
                        } else {
                            match config::GLOBAL_CONFIG.get_target_subnet() {
                                Some(subnet) => {
                                    let total_size = match subnet {
                                        IpNetwork::V4(net) => 2u64.pow(32 - net.prefix() as u32),
                                        IpNetwork::V6(net) => {
                                             let prefix = net.prefix();
                                             if prefix > IPV6_PREFIX_THRESHOLD { 2u64.pow(128 - prefix as u32) } else { u64::MAX }
                                        }
                                    };

                                    crate::mprintln!("{}", format!("[*] Running module '{}' against subnet {}", module_path, subnet).cyan().bold());
                                    if total_size > 1000000 {
                                         crate::mprintln!("{}", format!("[!] Warning: Subnet is very large (~{} IPs). This will take a long time.", total_size).yellow());
                                    }

                                    let mut success_count = 0;
                                    let mut fail_count = 0;
                                    let mut idx = 0u64;

                                    let hp_on = crate::global_options::GLOBAL_OPTIONS
                                        .try_get("honeypot_detection")
                                        .map(|v| !matches!(v.to_lowercase().as_str(), "n"|"no"|"false"|"0"|"off"|"disabled"))
                                        .unwrap_or(true);

                                    for ip in subnet.iter() {
                                        idx += 1;
                                        let ip_str = ip.to_string();
                                        crate::mprintln!("\n{}", format!("[{}/{}] Running against: {}", idx, total_size, ip_str).yellow());

                                        if hp_on && crate::utils::network::quick_honeypot_check(&ip_str).await {
                                            crate::mprintln!("{}", format!("[!] {} — honeypot detected, skipping", ip_str).red());
                                            fail_count += 1;
                                            continue;
                                        }

                                        match commands::run_module(module_path, &ip_str, ctx.verbose).await {
                                            Ok(_) => success_count += 1,
                                            Err(e) => {
                                                crate::meprintln!("[!] Module failed: {:?}", e);
                                                fail_count += 1;
                                            }
                                        }
                                    }

                                    crate::mprintln!("\n{}", "=== Run All Summary ===".cyan().bold());
                                    crate::mprintln!("{}", format!("Total IPs: {}", total_size).green());
                                    crate::mprintln!("{}", format!("Successful: {}", success_count).green());
                                    crate::mprintln!("{}", format!("Failed: {}", fail_count).red());
                                }
                                None => {
                                     crate::mprintln!("{}", "[!] Error retrieving subnet configuration.".red());
                                }
                            }
                        }
                    } else {
                        crate::mprintln!("{}", "No module selected. Use 'use <module>' first.".yellow());
                    }
                }
                _ => {
                    crate::mprintln!("{}", format!("Unknown command: '{}'. Type 'help' or '?' for usage.", cmd_input).red());
                }
            }
    false
}

/// Maximum resource script nesting depth to prevent infinite recursion.
const MAX_RESOURCE_DEPTH: usize = 16;

/// Execute commands from a resource script file.
/// Uses Box::pin to handle async recursion (resource scripts can call resource).
/// Depth parameter prevents infinite recursion from self-referencing scripts.
fn execute_resource_file_inner<'a>(ctx: &'a mut ShellContext, path: &'a str, depth: usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
    Box::pin(async move {
        if depth >= MAX_RESOURCE_DEPTH {
            crate::mprintln!("{}", format!("[!] Resource script nesting too deep (max {}). Aborting to prevent infinite recursion.", MAX_RESOURCE_DEPTH).red());
            return;
        }
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let mut count = 0;
                for line in contents.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
                    crate::mprintln!("{}", format!("[rc] {}", trimmed).dimmed());
                    let should_exit = execute_single_command(ctx, trimmed).await;
                    count += 1;
                    if should_exit { break; }
                }
                crate::mprintln!("{}", format!("[+] Resource script complete ({} commands executed)", count).green());
            }
            Err(e) => {
                crate::mprintln!("{}", format!("[!] Failed to read resource file '{}': {}", path, e).red());
            }
        }
    })
}


fn split_command(input: &str) -> (String, String) {
    let mut parts = input.splitn(2, char::is_whitespace);
    let cmd = parts.next().unwrap_or("").to_lowercase();
    let rest = parts.next().unwrap_or("").trim().to_string();
    (cmd, rest)
}

pub fn resolve_command(cmd: &str) -> String {
    match cmd {
        "?" | "help" | "h" => "help",
        "modules" | "list" | "ls" | "m" => "modules",
        "find" | "search" | "f" | "f1" => "find",

        "use" | "u" => "use",
        "set" | "target" | "t" => "set",
        "subnet" | "sn" => "set_subnet",
        "show_target" | "showtarget" | "st" => "show_target",
        "clear_target" | "cleartarget" | "ct" => "clear_target",
        "run" | "go" | "exec" => "run",
        "run_all" | "runall" | "ra" => "run_all",
        "back" | "b" | "clear" | "reset" => "back",
        "exit" | "quit" | "q" => "exit",

        // New commands
        "info" | "i" => "info",
        "check" | "ch" => "check",
        "setg" | "sg" => "setg",
        "unsetg" | "ug" => "unsetg",
        "show_options" | "showoptions" | "so" => "show_options",
        "creds" | "credentials" => "creds",
        "spool" => "spool",
        "resource" | "rc" => "resource",
        "makerc" => "makerc",
        "hosts" => "hosts",
        "services" | "svcs" => "services",
        "notes" => "notes",
        "workspace" | "ws" => "workspace",
        "loot" => "loot",
        "export" => "export",
        "jobs" | "j" => "jobs",

        other => other,
    }
    .to_string()
}

pub fn sanitize_module_path(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains("..") || trimmed.contains('\\') {
        return None;
    }
    let valid = trimmed.chars().all(|c| {
        matches!(
            c,
            'a'..='z'
        | 'A'..='Z'
        | '0'..='9'
        | '/'
        | '_'
        | '-'
        )
    });
    if valid {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// Delegate to utils for consistent target validation across the codebase
fn sanitize_target(input: &str) -> std::result::Result<String, &'static str> {
    utils::sanitize_target_simple(input)
}

fn render_help() {
    crate::mprintln!();
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║                      RustSploit Command Reference                       ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();

    // --- Navigation & Discovery ---
    crate::mprintln!("  {}", "Navigation & Discovery".bold().underline());
    crate::mprintln!();
    crate::mprintln!("    {:<20} {:<24} {}", "help".green(), "h | ?".dimmed(), "Show this screen");
    crate::mprintln!("    {:<20} {:<24} {}", "modules".green(), "ls | m".dimmed(), "List all available modules");
    crate::mprintln!("    {:<20} {:<24} {}", "find <kw>".green(), "f1 <kw>".dimmed(), "Search modules by keyword");
    crate::mprintln!("    {:<20} {:<24} {}", "use <path>".green(), "u <path>".dimmed(), "Select a module to load");
    crate::mprintln!("    {:<20} {:<24} {}", "info [path]".green(), "i".dimmed(), "Show module metadata (CVE, author, rank)");
    crate::mprintln!("    {:<20} {:<24} {}", "back".green(), "b | clear".dimmed(), "Deselect current module and target");
    crate::mprintln!();

    // --- Targeting ---
    crate::mprintln!("  {}", "Targeting".bold().underline());
    crate::mprintln!();
    crate::mprintln!("    {:<20} {:<24} {}", "set target".green(), "t <val>".dimmed(), "Set global target (IP, domain, CIDR, or comma-separated)");
    crate::mprintln!("    {:<20} {:<24} {}", "set subnet".green(), "sn <CIDR>".dimmed(), "Set target to a CIDR subnet");
    crate::mprintln!("    {:<20} {:<24} {}", "set port".green(), "".dimmed(), "Set target port for all modules");
    crate::mprintln!("    {:<20} {:<24} {}", "set source_port".green(), "".dimmed(), "Set source port (0 to clear)");
    crate::mprintln!("    {:<20} {:<24} {}", "show_target".green(), "st".dimmed(), "Display current targets");
    crate::mprintln!("    {:<20} {:<24} {}", "clear_target".green(), "ct".dimmed(), "Clear all targets");
    crate::mprintln!();

    // --- Execution ---
    crate::mprintln!("  {}", "Execution".bold().underline());
    crate::mprintln!();
    crate::mprintln!("    {:<20} {:<24} {}", "run".green(), "go".dimmed(), "Execute the selected module");
    crate::mprintln!("    {:<20} {:<24} {}", "run -j".green(), "".dimmed(), "Run module as background job");
    crate::mprintln!("    {:<20} {:<24} {}", "run_all".green(), "ra".dimmed(), "Run module against all IPs in subnet");
    crate::mprintln!("    {:<20} {:<24} {}", "check".green(), "ch".dimmed(), "Non-destructive vulnerability check");
    crate::mprintln!();

    // --- Global Options ---
    crate::mprintln!("  {}", "Global Options".bold().underline());
    crate::mprintln!();
    crate::mprintln!("    {:<20} {:<24} {}", "setg <k> <v>".green(), "sg".dimmed(), "Set a global option (persists across modules)");
    crate::mprintln!("    {:<20} {:<24} {}", "unsetg <key>".green(), "ug".dimmed(), "Remove a global option");
    crate::mprintln!("    {:<20} {:<24} {}", "show options".green(), "so".dimmed(), "Display all global options");
    crate::mprintln!();

    // --- Data Management ---
    crate::mprintln!("  {}", "Data Management".bold().underline());
    crate::mprintln!();
    crate::mprintln!("    {:<20} {:<24} {}", "creds".green(), "".dimmed(), "List stored credentials");
    crate::mprintln!("    {:<20} {:<24} {}", "creds add".green(), "".dimmed(), "Add a credential interactively");
    crate::mprintln!("    {:<20} {:<24} {}", "creds search <q>".green(), "".dimmed(), "Search credentials");
    crate::mprintln!("    {:<20} {:<24} {}", "hosts".green(), "".dimmed(), "List tracked hosts");
    crate::mprintln!("    {:<20} {:<24} {}", "hosts add <ip>".green(), "".dimmed(), "Add a host to workspace");
    crate::mprintln!("    {:<20} {:<24} {}", "services".green(), "svcs".dimmed(), "List tracked services");
    crate::mprintln!("    {:<20} {:<24} {}", "notes <ip> <text>".green(), "".dimmed(), "Add a note to a host");
    crate::mprintln!("    {:<20} {:<24} {}", "loot".green(), "".dimmed(), "List collected loot");
    crate::mprintln!("    {:<20} {:<24} {}", "workspace [name]".green(), "ws".dimmed(), "Show/switch workspaces");
    crate::mprintln!();

    // --- Automation & Export ---
    crate::mprintln!("  {}", "Automation & Export".bold().underline());
    crate::mprintln!();
    crate::mprintln!("    {:<20} {:<24} {}", "resource <file>".green(), "rc".dimmed(), "Execute a resource script");
    crate::mprintln!("    {:<20} {:<24} {}", "makerc <file>".green(), "".dimmed(), "Save command history to file");
    crate::mprintln!("    {:<20} {:<24} {}", "spool <file>".green(), "".dimmed(), "Log console output to file");
    crate::mprintln!("    {:<20} {:<24} {}", "spool off".green(), "".dimmed(), "Stop console logging");
    crate::mprintln!("    {:<20} {:<24} {}", "export json <f>".green(), "".dimmed(), "Export all data to JSON");
    crate::mprintln!("    {:<20} {:<24} {}", "export csv <f>".green(), "".dimmed(), "Export all data to CSV");
    crate::mprintln!("    {:<20} {:<24} {}", "export summary <f>".green(), "".dimmed(), "Export human-readable report");
    crate::mprintln!();

    // --- Jobs ---
    crate::mprintln!("  {}", "Background Jobs".bold().underline());
    crate::mprintln!();
    crate::mprintln!("    {:<20} {:<24} {}", "jobs".green(), "j".dimmed(), "List background jobs");
    crate::mprintln!("    {:<20} {:<24} {}", "jobs -k <id>".green(), "".dimmed(), "Kill a background job");
    crate::mprintln!("    {:<20} {:<24} {}", "jobs clean".green(), "".dimmed(), "Clean up finished jobs");
    crate::mprintln!();

    // --- Other ---
    crate::mprintln!("    {:<20} {:<24} {}", "exit".green(), "quit | q".dimmed(), "Leave the shell");
    crate::mprintln!();

    // --- Tips ---
    crate::mprintln!("{}", "┌──────────────────────────────────────────────────────────────────────────┐".dimmed());
    crate::mprintln!("{}", "│  Tips                                                                    │".dimmed());
    crate::mprintln!("{}",  "├──────────────────────────────────────────────────────────────────────────┤".dimmed());
    crate::mprintln!("  {} Chain commands with {}: {}",
        ">>".dimmed(),
        "&".cyan().bold(),
        format!("set target 10.0.0.1 & use scanners/smtp_user_enum & run").cyan());
    crate::mprintln!("  {} Use {} to set options that apply to all modules.",
        ">>".dimmed(), "setg".cyan().bold());
    crate::mprintln!("  {} Use {} to save engagement data.",
        ">>".dimmed(), "export json report.json".cyan().bold());
    crate::mprintln!("  {} Max {} chained commands per line.",
        ">>".dimmed(),
        MAX_COMMAND_CHAIN_LENGTH);
    crate::mprintln!("{}", "└──────────────────────────────────────────────────────────────────────────┘".dimmed());
    crate::mprintln!();
}


async fn prompt_string_default(message: &str, default: &str) -> io::Result<String> {
    print!("{} [{}]: ", message, default);
    io::stdout().flush()?;
    let input = tokio::task::spawn_blocking(|| {
        let mut s = String::new();
        io::stdin().read_line(&mut s).map(|_| s)
    })
    .await
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
    ?;

    // Length check
    if input.len() > MAX_PROMPT_INPUT_LENGTH {
        crate::mprintln!("{}", format!("Input too long (max {} characters). Using default.", MAX_PROMPT_INPUT_LENGTH).yellow());
        return Ok(default.to_string());
    }

    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Ok(default.to_string());
    }

    // Check for control characters
    if trimmed.chars().any(|c| c.is_control()) {
        crate::mprintln!("{}", "Input cannot contain control characters. Using default.".yellow());
        return Ok(default.to_string());
    }

    // If this looks like a URL, validate it
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        if trimmed.len() > MAX_URL_LENGTH {
            crate::mprintln!("{}", format!("URL too long (max {} characters). Using default.", MAX_URL_LENGTH).yellow());
            return Ok(default.to_string());
        }

        if Url::parse(trimmed).is_err() {
            crate::mprintln!("{}", "Invalid URL format. Using default.".yellow());
            return Ok(default.to_string());
        }
    }

    Ok(trimmed.to_string())
}

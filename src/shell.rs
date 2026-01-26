use crate::commands;
use crate::utils;
use crate::config;
use anyhow::Result;
use colored::*;
use std::io::{self, Write};
use url::Url;

const MAX_INPUT_LENGTH: usize = 4096;
const MAX_TARGET_LENGTH: usize = 512;
const MAX_COMMAND_CHAIN_LENGTH: usize = 10;
const MAX_URL_LENGTH: usize = 2048;

const MAX_PROMPT_INPUT_LENGTH: usize = 1024;

/// Simple interactive shell context
struct ShellContext {
    current_module: Option<String>,
    current_target: Option<String>,
    verbose: bool,
}

impl ShellContext {
    fn new(verbose: bool) -> Self {
        ShellContext {
            current_module: None,
            current_target: None,
            verbose,
        }
    }
}

pub async fn interactive_shell(verbose: bool) -> Result<()> {
    println!("Welcome to RustSploit Shell (inspired by RouterSploit)");
    println!("Type 'help' for a list of commands. Type 'exit' or 'quit' to leave.");
    
    // Show global target if set
    if config::GLOBAL_CONFIG.has_target() {
        let target_str = config::GLOBAL_CONFIG.get_target().unwrap_or_default();
        if let Some(size) = config::GLOBAL_CONFIG.get_target_size() {
            if size > 1 {
                println!("{}", format!("[*] Global target set: {} ({} IPs)", target_str, size).cyan());
            } else {
                println!("{}", format!("[*] Global target set: {}", target_str).cyan());
            }
        } else {
            println!("{}", format!("[*] Global target set: {}", target_str).cyan());
        }
    }

    let mut ctx = ShellContext::new(verbose);

    'main_loop: loop {
        print!("{}", "rsf> ".cyan().bold());
        io::stdout().flush()?;

        let mut raw_input = String::new();
        io::stdin().read_line(&mut raw_input)?;

        if raw_input.len() > MAX_INPUT_LENGTH {
            println!(
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
            println!(
                "{}",
                format!("[!] Command chain exceeds maximum length of {}. Truncating.", MAX_COMMAND_CHAIN_LENGTH)
                    .yellow()
            );
        }

        for cmd_input in commands {
            if cmd_input.is_empty() {
                continue;
            }

            match split_command(cmd_input) {
                Some((cmd, rest)) => {
                    let command_key = resolve_command(&cmd);
                    match command_key.as_str() {
                        "exit" => {
                            println!("Exiting...");
                            println!("Exiting...");
                            break 'main_loop;
                        }
                        "back" => {
                            ctx.current_module = None;
                            ctx.current_target = None;
                            println!("{}", "Cleared current module and target.".green());
                        }
                        "show_target" | "target" => {
                            if let Some(ref t) = ctx.current_target {
                                println!("{}", format!("Local target: {}", t).cyan());
                            } else {
                                println!("{}", "No local target set.".dimmed());
                            }
                            if config::GLOBAL_CONFIG.has_target() {
                                let target_str = config::GLOBAL_CONFIG.get_target().unwrap_or_default();
                                if let Some(size) = config::GLOBAL_CONFIG.get_target_size() {
                                    if size > 1 {
                                        println!("{}", format!("Global target (subnet): {} ({} IPs)", target_str, size).green());
                                    } else {
                                        println!("{}", format!("Global target: {}", target_str).green());
                                    }
                                } else {
                                    println!("{}", format!("Global target: {}", target_str).green());
                                }
                            } else {
                                println!("{}", "No global target set.".dimmed());
                            }
                        }
                        "clear_target" => {
                            ctx.current_target = None;
                            config::GLOBAL_CONFIG.clear_target();
                            println!("{}", "Cleared local and global targets.".green());
                        }
                        "help" => render_help(),
                        "modules" => utils::list_all_modules(),
                        "find" => {
                            if rest.is_empty() {
                                println!("{}", "Usage: find <keyword>".yellow());
                            } else {
                                utils::find_modules(&rest);
                            }
                        }

                        "use" => {
                            if rest.is_empty() {
                                println!("{}", "Usage: use <module_path>".yellow());
                            } else if let Some(safe_path) = sanitize_module_path(&rest) {
                                if utils::module_exists(&safe_path) {
                                    ctx.current_module = Some(safe_path.clone());
                                    println!("{}", format!("Module '{}' selected.", safe_path).green());
                                } else {
                                    println!("{}", format!("Module '{}' not found.", rest).red());
                                }
                            } else {
                                println!(
                                    "{}",
                                    "Module path contains invalid characters or traversal attempts."
                                    .red()
                                );
                            }
                        }
                        "set" => {
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
                                println!("{}", "Usage: set target <value>".yellow());
                                println!("{}", "  Shortcuts: t <value>, target <value>".dimmed());
                                println!("{}", "  Examples:".dimmed());
                                println!("{}", "    t 192.168.1.1".dimmed());
                                println!("{}", "    set target example.com".dimmed());
                                continue;
                            }

                            match sanitize_target(raw_value) {
                                Ok(valid_target) => {
                                    // Set both local context and global config
                                    ctx.current_target = Some(valid_target.clone());
                                    match config::GLOBAL_CONFIG.set_target(&valid_target) {
                                        Ok(_) => {
                                            if config::GLOBAL_CONFIG.is_subnet() {
                                                println!("{}", format!("Global target set to subnet: {}", valid_target).green());
                                            } else {
                                                println!("{}", format!("Global target set to: {}", valid_target).green());
                                            }
                                            println!("{}", format!("Local target set to: {}", valid_target).green());
                                        }
                                        Err(e) => {
                                            println!("{}", format!("[!] Failed to set global target: {}", e).red());
                                            // Still set local target
                                            println!("{}", format!("Local target set to: {}", valid_target).green());
                                        }
                                    }
                                }
                                Err(reason) => {
                                    println!("{}", format!("[!] {}", reason).yellow());
                                }
                            }
                        }
                        "run" => {
                            if let Some(ref module_path) = ctx.current_module {
                                // Try to get target from local context, then global config
                                let target = if let Some(ref t) = ctx.current_target {
                                    Some(t.clone())
                                } else if config::GLOBAL_CONFIG.has_target() {
                                    // Use single IP from global target (handles subnets intelligently)
                                    match config::GLOBAL_CONFIG.get_single_target_ip() {
                                        Ok(ip) => {
                                            println!("{}", format!("[*] Using global target: {}", config::GLOBAL_CONFIG.get_target().unwrap_or_default()).cyan());
                                            Some(ip)
                                        }
                                        Err(e) => {
                                            println!("{}", format!("[!] Error getting global target: {}", e).red());
                                            None
                                        }
                                    }
                                } else {
                                    None
                                };

                                // Interactive prompt if no target is set
                                let target = if target.is_none() {
                                    println!("{}", "[!] Warning: No target set.".yellow());
                                    
                                    // Option 1: Manually set target
                                    match utils::prompt_yes_no("Do you want to provide a target address?", true) {
                                        Ok(true) => {
                                            match prompt_string_default("Enter target", "").map_err(|e| anyhow::anyhow!("{}", e)) {
                                                Ok(input) => {
                                                    match sanitize_target(&input) {
                                                        Ok(valid_target) => {
                                                            // Set it for future use too
                                                            ctx.current_target = Some(valid_target.clone());
                                                            // Try to set global but don't fail if it errors (e.g. strict subnet rules), just warn
                                                            if let Err(e) = config::GLOBAL_CONFIG.set_target(&valid_target) {
                                                                 println!("{}", format!("[*] Local target set to '{}', but failed to set global: {}", valid_target, e).dimmed());
                                                            } else {
                                                                 println!("{}", format!("[*] Target set to '{}'", valid_target).green());
                                                            }
                                                            Some(valid_target)
                                                        },
                                                        Err(e) => {
                                                            println!("{}", format!("[!] Invalid target: {}", e).red());
                                                            None
                                                        }
                                                    }
                                                },
                                                Err(e) => {
                                                    println!("{}", format!("[!] Error reading input: {}", e).red());
                                                    None
                                                }
                                            }
                                        },
                                        Ok(false) => {
                                            // Option 2: Fallback to localhost
                                            match utils::prompt_yes_no("Continue with localhost (127.0.0.1)?", false) {
                                                Ok(true) => Some("127.0.0.1".to_string()),
                                                _ => {
                                                    println!("{}", "[!] Execution aborted.".red());
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
                                    // Perform honeypot check before running module
                                    // Skip check for mass scan targets (CIDR, random, 0.0.0.0, or file lists)
                                    let is_mass_scan = t.contains('/') || t == "random" || t == "0.0.0.0" || std::path::Path::new(t).is_file();
                                    
                                    if !is_mass_scan {
                                        utils::basic_honeypot_check(t).await;
                                    }
                                    
                                    println!("Running module '{}' against target '{}'", module_path, t);
                                    if let Err(e) = commands::run_module(module_path, t, ctx.verbose).await {
                                        eprintln!("[!] Module failed: {:?}", e);
                                    }
                                } else {
                                    println!("{}", "No target set. Use 'set target <value>' (or 't <value>') first.".yellow());
                                    println!("{}", "  Examples:".dimmed());
                                    println!("{}", "    set target 192.168.1.1".dimmed());
                                    println!("{}", "    set target 192.168.1.0/24".dimmed());
                                }
                            } else {
                                println!("{}", "No module selected. Use 'use <module>' first.".yellow());
                            }
                        }
                        "run_all" => {
                            if let Some(ref module_path) = ctx.current_module {
                                // Check if we have a subnet target
                                if !config::GLOBAL_CONFIG.has_target() {
                                    println!("{}", "No global target set. Use 'set target <ip/subnet>' first.".yellow());
                                    continue;
                                }

                                if !config::GLOBAL_CONFIG.is_subnet() {
                                    println!("{}", "Global target is not a subnet. Use 'run' for single targets.".yellow());
                                    continue;
                                }

                                // Get all IPs from the subnet
                                match config::GLOBAL_CONFIG.get_target_ips() {
                                    Ok(ips) => {
                                        let total = ips.len();
                                        println!("{}", format!("[*] Running module '{}' against all {} IPs in subnet", module_path, total).cyan().bold());
                                        println!("{}", format!("[*] Subnet: {}", config::GLOBAL_CONFIG.get_target().unwrap_or_default()).cyan());
                                        
                                        let mut success_count = 0;
                                        let mut fail_count = 0;

                                        for (idx, ip) in ips.iter().enumerate() {
                                            println!("\n{}", format!("[{}/{}] Running against: {}", idx + 1, total, ip).yellow());
                                            
                                            // Perform honeypot check before running module
                                            // Perform honeypot check before running module
                                            utils::basic_honeypot_check(ip).await;
                                            
                                            match commands::run_module(module_path, ip, ctx.verbose).await {
                                                Ok(_) => success_count += 1,
                                                Err(e) => {
                                                    eprintln!("[!] Module failed: {:?}", e);
                                                    fail_count += 1;
                                                }
                                            }
                                        }

                                        println!("\n{}", "=== Run All Summary ===".cyan().bold());
                                        println!("{}", format!("Total IPs: {}", total).green());
                                        println!("{}", format!("Successful: {}", success_count).green());
                                        println!("{}", format!("Failed: {}", fail_count).red());
                                    }
                                    Err(e) => {
                                        println!("{}", format!("[!] Error getting target IPs: {}", e).red());
                                        println!("{}", "Note: Subnets larger than 65536 IPs are not supported for run_all. Use a smaller subnet.".yellow());
                                    }
                                }
                            } else {
                                println!("{}", "No module selected. Use 'use <module>' first.".yellow());
                            }
                        }
                        _ => {
                            println!("{}", format!("Unknown command: '{}'. Type 'help' or '?' for usage.", cmd_input).red());
                        }
                    }
                }
                None => {
                    println!("{}", format!("Unknown command: '{}'. Type 'help' or '?' for usage.", cmd_input).red());
                }
            }
        }
    }

    Ok(())
}



fn split_command(input: &str) -> Option<(String, String)> {
    let mut parts = input.splitn(2, char::is_whitespace);
    let cmd = parts.next()?.to_lowercase();
    let rest = parts.next().unwrap_or("").trim().to_string();
    Some((cmd, rest))
}

fn resolve_command(cmd: &str) -> String {
    match cmd {
        "?" | "help" | "h" => "help",
        "modules" | "list" | "ls" | "m" => "modules",
        "find" | "search" | "f" | "f1" => "find",

        "use" | "u" => "use",
        "set" | "target" | "t" => "set",
        "show_target" | "showtarget" | "st" => "show_target",
        "clear_target" | "cleartarget" | "ct" => "clear_target",
                        "run" | "go" | "exec" => "run",
                        "run_all" | "runall" | "ra" => "run_all",
        "back" | "b" | "clear" | "reset" => "back",
        "exit" | "quit" | "q" => "exit",
        other => other,
    }
    .to_string()
}

fn sanitize_module_path(input: &str) -> Option<String> {
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

fn sanitize_target(input: &str) -> std::result::Result<String, &'static str> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Target cannot be empty.");
    }
    if trimmed.len() > MAX_TARGET_LENGTH {
        return Err("Target value is too long.");
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("Target cannot contain control characters.");
    }
    Ok(trimmed.to_string())
}

fn render_help() {
    println!();
    println!("{}", "RustSploit Command Palette".bold().underline());
    println!(
        "{}",
        "Shortcuts are case-insensitive. Example: `f1 ssh` searches for SSH modules."
        .dimmed()
    );
    println!();

    let entries = vec![
        ("help", "help | h | ?", "Show this screen"),
        ("modules", "modules | ls | m", "List available modules"),
        ("find", "find <kw> | f1 <kw>", "Search modules by keyword"),
        ("use", "use <path> | u <path>", "Select a module to run"),
        ("set target", "set target <val> | t <val>", "Set global target (IP/subnet)"),
        ("show_target", "show_target | st", "Show current local and global targets"),
        ("clear_target", "clear_target", "Clear local and global targets"),
        ("run", "run | go", "Execute selected module (with proxy rotation)"),
        ("run_all", "run_all | runall | ra", "Run module against all IPs in subnet (max 65536)"),
        ("back", "back | b | clear | reset", "Clear current module and target"),
        ("exit", "exit | quit | q", "Leave the shell"),
    ];

    println!("{}", format!("{:<16} {:<25} {}", "Command", "Shortcuts", "Description").bold());
    println!("{}", "-".repeat(72).dimmed());
    for (cmd, shortcuts, desc) in entries {
        println!("{:<16} {:<25} {}", cmd.green(), shortcuts.cyan(), desc);
    }
    println!();
    println!("{}", "Shell extras & command combining:".bold());
    println!(
        "  - Commands can be chained with '&' and are executed left-to-right (max {}).",
        MAX_COMMAND_CHAIN_LENGTH
    );
    println!("  - Example: {}", "set target 10.0.0.1 & use scanners/smtp_user_enum & run".cyan());
    println!("  - Spacing around '&' is optional: {}", "use exploits/sample&run".cyan());
    println!("  - Targets and paths must not contain control characters or '..' (basic safety checks).");

    println!("  - Honeypot detection runs automatically before module execution to warn about suspicious targets.");
    println!("  - Target normalization supports IPv4, IPv6, hostnames, URLs, and CIDR notation.");
    println!();
    println!(
        "{}",
        "Need more context? Try `modules`, then `use category/module_name`, and finally `run`."
        .dimmed()
    );
    println!();
}





fn prompt_string_default(message: &str, default: &str) -> io::Result<String> {
    print!("{} [{}]: ", message, default);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    // Length check
    if input.len() > MAX_PROMPT_INPUT_LENGTH {
        println!("{}", format!("Input too long (max {} characters). Using default.", MAX_PROMPT_INPUT_LENGTH).yellow());
        return Ok(default.to_string());
    }
    
    let trimmed = input.trim();
    
    if trimmed.is_empty() {
        return Ok(default.to_string());
    }
    
    // Check for control characters
    if trimmed.chars().any(|c| c.is_control()) {
        println!("{}", "Input cannot contain control characters. Using default.".yellow());
        return Ok(default.to_string());
    }
    
    // If this looks like a URL, validate it
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        if trimmed.len() > MAX_URL_LENGTH {
            println!("{}", format!("URL too long (max {} characters). Using default.", MAX_URL_LENGTH).yellow());
            return Ok(default.to_string());
        }
        
        if Url::parse(trimmed).is_err() {
            println!("{}", "Invalid URL format. Using default.".yellow());
            return Ok(default.to_string());
        }
    }
    
    Ok(trimmed.to_string())
}







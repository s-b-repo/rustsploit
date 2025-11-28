use crate::commands;
use crate::utils;
use crate::config;
use anyhow::Result;
use colored::*;
use rand::prelude::*;
use std::env;
use std::io::{self, Write};
use std::collections::HashSet;
use std::sync::Mutex;
use url::Url;

const MAX_INPUT_LENGTH: usize = 4096;
const MAX_PROXY_LIST_SIZE: usize = 10_000;
const MAX_TARGET_LENGTH: usize = 512;
const MAX_COMMAND_CHAIN_LENGTH: usize = 10;
const MAX_URL_LENGTH: usize = 2048;
const MAX_PATH_LENGTH: usize = 4096;
const MAX_PROMPT_INPUT_LENGTH: usize = 1024;

/// Simple interactive shell context
struct ShellContext {
    current_module: Option<String>,
    current_target: Option<String>,
    proxy_list: Vec<String>,
    proxy_enabled: bool,
}

impl ShellContext {
    fn new() -> Self {
        ShellContext {
            current_module: None,
            current_target: None,
            proxy_list: Vec::new(),
            proxy_enabled: false,
        }
    }
}

pub async fn interactive_shell() -> Result<()> {
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

    let mut ctx = ShellContext::new();

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
                            clear_proxy_env_vars();
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
                        "proxy_load" => {
                            let file_path = if rest.is_empty() {
                                match prompt_for_path("Path to proxy list file: ") {
                                    Ok(path) => path,
                                    Err(e) => {
                                        println!("{}", format!("[!] Error reading input: {}", e).red());
                                        continue;
                                    }
                                }
                            } else {
                                rest.to_string()
                            };

                            match utils::load_proxies_from_file(&file_path) {
                                Ok(summary) => {
                                    let mut unique = HashSet::new();
                                    let mut deduped = Vec::new();
                                    for proxy in summary.proxies.iter() {
                                        if unique.insert(proxy.clone()) {
                                            deduped.push(proxy.clone());
                                        }
                                    }

                                    if deduped.len() > MAX_PROXY_LIST_SIZE {
                                        println!(
                                            "{}",
                                            format!(
                                                "[!] Loaded proxy list exceeded {} entries. Truncating.",
                                                MAX_PROXY_LIST_SIZE
                                            )
                                                .yellow()
                                        );
                                        deduped.truncate(MAX_PROXY_LIST_SIZE);
                                    }

                                    let removed = summary.proxies.len().saturating_sub(deduped.len());
                                    if removed > 0 {
                                        println!(
                                            "{}",
                                            format!(
                                                "[*] Removed {} duplicate proxy entr{}.",
                                                removed,
                                                if removed == 1 { "y" } else { "ies" }
                                            )
                                                .dimmed()
                                        );
                                    }

                                    ctx.proxy_list = deduped;
                                    println!(
                                        "Loaded {} proxies from '{}'.",
                                        ctx.proxy_list.len(),
                                             file_path
                                    );

                                    if !summary.skipped.is_empty() {
                                        println!(
                                            "{}",
                                            format!(
                                                "Skipped {} invalid entr{}:",
                                                summary.skipped.len(),
                                                    if summary.skipped.len() == 1 { "y" } else { "ies" }
                                            )
                                                .yellow()
                                        );
                                        for failure in summary.skipped.iter().take(10) {
                                            println!(
                                                "  [line {}] {} ({})",
                                                     failure.line_number,
                                                     failure.content,
                                                     failure.reason
                                            );
                                        }
                                        if summary.skipped.len() > 10 {
                                            println!(
                                                "  ... {} additional entr{} skipped.",
                                                summary.skipped.len() - 10,
                                                     if summary.skipped.len() - 10 == 1 {
                                                         "y"
                                                     } else {
                                                         "ies"
                                                     }
                                            );
                                        }
                                    }

                                    match prompt_yes_no("Test connectivity of loaded proxies? (recommended)", true) {
                                        Ok(true) => {
                                            if let Err(e) = test_current_proxies(&mut ctx).await {
                                                println!("{}", format!("[!] Proxy testing failed: {}", e).red());
                                            }
                                        }
                                        Ok(false) => {}
                                        Err(e) => {
                                            println!("{}", format!("[!] Error reading input: {}", e).red());
                                        }
                                    }
                                }
                                Err(e) => {
                                    println!("Failed to load proxies: {}", e);
                                }
                            }
                        }
                        "proxy_on" => {
                            ctx.proxy_enabled = true;
                            println!("Proxy usage enabled.");
                        }
                        "proxy_off" => {
                            ctx.proxy_enabled = false;
                            println!("Proxy usage disabled.");
                            clear_proxy_env_vars();
                        }
                        "proxy_test" => {
                            if let Err(e) = test_current_proxies(&mut ctx).await {
                                println!("{}", format!("[!] Proxy testing failed: {}", e).red());
                            }
                        }
                        "show_proxies" => {
                            if ctx.proxy_list.is_empty() {
                                println!("No proxies loaded. Use 'proxy_load <file>' to load them.");
                            } else {
                                println!("Loaded proxies ({}):", ctx.proxy_list.len());
                                for p in &ctx.proxy_list {
                                    println!("  {}", p);
                                }
                            }
                            println!("Proxy is currently {}.", if ctx.proxy_enabled { "ON" } else { "OFF" });
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
                            // Handle "set target <value>" - require "target " prefix with space
                            if rest.starts_with("target ") {
                                let raw_value = rest.strip_prefix("target ").unwrap().trim();
                                if raw_value.is_empty() {
                                    println!("{}", "Usage: set target <value>".yellow());
                                    println!("{}", "  Examples:".dimmed());
                                    println!("{}", "    set target 192.168.1.1".dimmed());
                                    println!("{}", "    set target 192.168.1.0/24".dimmed());
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
                            } else {
                                println!("{}", "Usage: set target <value>".yellow());
                                println!("{}", "  Examples:".dimmed());
                                println!("{}", "    set target 192.168.1.1".dimmed());
                                println!("{}", "    set target 192.168.1.0/24".dimmed());
                                println!("{}", "    set target example.com".dimmed());
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

                                if let Some(ref t) = target {
                                    if ctx.proxy_enabled && !ctx.proxy_list.is_empty() {
                                        let mut tried_proxies = HashSet::new();
                                        let mut success = false;

                                        while tried_proxies.len() < ctx.proxy_list.len() {
                                            let chosen_proxy = pick_random_untried_proxy(&ctx.proxy_list, &tried_proxies);
                                            set_all_proxy_env(&chosen_proxy);
                                            println!("[*] Using proxy: {}", chosen_proxy);

                                            println!("Running module '{}' against target '{}'", module_path, t);
                                            match commands::run_module(module_path, t).await {
                                                Ok(_) => {
                                                    success = true;
                                                    break;
                                                }
                                                Err(e) => {
                                                    eprintln!("[!] Module failed with error: {:?}", e);
                                                    eprintln!("    Retrying with a new proxy...");
                                                    tried_proxies.insert(chosen_proxy);
                                                }
                                            }
                                        }

                                        if !success {
                                            println!("[!] All proxies failed. Trying direct connection...");
                                            clear_proxy_env_vars();
                                            if let Err(e) = commands::run_module(module_path, t).await {
                                                eprintln!("[!] Final direct attempt also failed: {:?}", e);
                                            }
                                        }
                                    } else if ctx.proxy_enabled && ctx.proxy_list.is_empty() {
                                        println!("[!] No proxies loaded, but proxy is ON. Doing direct attempt...");
                                        clear_proxy_env_vars();
                                        if let Err(e) = commands::run_module(module_path, t).await {
                                            eprintln!("[!] Module failed: {:?}", e);
                                        }
                                    } else {
                                        clear_proxy_env_vars();
                                        if let Err(e) = commands::run_module(module_path, t).await {
                                            eprintln!("[!] Module failed: {:?}", e);
                                        }
                                    }
                                } else {
                                    println!("{}", "No target set. Use 'set target <value>' first.".yellow());
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
                                            
                                            if ctx.proxy_enabled && !ctx.proxy_list.is_empty() {
                                                let mut tried_proxies = HashSet::new();
                                                let mut success = false;

                                                while tried_proxies.len() < ctx.proxy_list.len() {
                                                    let chosen_proxy = pick_random_untried_proxy(&ctx.proxy_list, &tried_proxies);
                                                    set_all_proxy_env(&chosen_proxy);

                                                    match commands::run_module(module_path, ip).await {
                                                        Ok(_) => {
                                                            success = true;
                                                            success_count += 1;
                                                            break;
                                                        }
                                                        Err(e) => {
                                                            if tried_proxies.is_empty() {
                                                                eprintln!("[!] Module failed: {:?}", e);
                                                            }
                                                            tried_proxies.insert(chosen_proxy);
                                                        }
                                                    }
                                                }

                                                if !success {
                                                    fail_count += 1;
                                                    if ctx.proxy_list.len() == tried_proxies.len() {
                                                        println!("{}", "[!] All proxies failed for this target".red());
                                                    }
                                                }
                                            } else {
                                                clear_proxy_env_vars();
                                                match commands::run_module(module_path, ip).await {
                                                    Ok(_) => success_count += 1,
                                                    Err(e) => {
                                                        eprintln!("[!] Module failed: {:?}", e);
                                                        fail_count += 1;
                                                    }
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

/// Picks a random proxy from `proxy_list` that is NOT in `tried_proxies`.
fn pick_random_untried_proxy(proxy_list: &[String], tried_proxies: &HashSet<String>) -> String {
    let mut rng = rand::rng();
    let choices: Vec<&String> = proxy_list
    .iter()
    .filter(|p| !tried_proxies.contains(*p))
    .collect();

    if let Some(choice) = choices.choose(&mut rng) {
        (*choice).clone()
    } else {
        // Fallback if all have been tried
        proxy_list.choose(&mut rng)
        .map(|s| s.clone())
        .unwrap_or_else(|| proxy_list[0].clone())
    }
}

// Thread-safe environment variable access
static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// Sets ALL_PROXY so reqwest uses it for all requests (including socks4, socks5, http, https)
/// Thread-safe wrapper around env::set_var
fn set_all_proxy_env(proxy: &str) {
    let _guard = ENV_MUTEX.lock().unwrap();
    unsafe {
        env::set_var("ALL_PROXY", proxy);
    }
}

/// Clears environment variables for direct connection
/// Thread-safe wrapper around env::remove_var
fn clear_proxy_env_vars() {
    let _guard = ENV_MUTEX.lock().unwrap();
    unsafe {
        env::remove_var("ALL_PROXY");
        env::remove_var("HTTP_PROXY");
        env::remove_var("HTTPS_PROXY");
    }
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
        "proxy_load" | "proxyload" | "pl" | "load_proxy" | "loadproxies" => "proxy_load",
        "proxy_on" | "pon" | "proxyon" => "proxy_on",
        "proxy_off" | "poff" | "proxyoff" => "proxy_off",
        "proxy_test" | "ptest" | "proxycheck" | "check_proxies" => "proxy_test",
        "show_proxies" | "proxies" | "pshow" | "proxy_show" => "show_proxies",
        "use" | "u" => "use",
        "set" | "target" => "set",
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
        ("set target", "set target <value>", "Set global target (IP/subnet) for all modules"),
        ("show_target", "show_target | target", "Show current local and global targets"),
        ("clear_target", "clear_target", "Clear local and global targets"),
        ("run", "run | go", "Execute selected module (with proxy rotation)"),
        ("run_all", "run_all | runall | ra", "Run module against all IPs in subnet (max 65536)"),
        ("back", "back | b | clear | reset", "Clear current module and target"),
        ("proxy_load", "proxy_load [file] | pl", "Load proxy list from file"),
        ("proxy_on", "proxy_on | pon", "Enable proxy usage"),
        ("proxy_off", "proxy_off | poff", "Disable proxy usage"),
        ("proxy_test", "proxy_test | ptest", "Validate loaded proxies"),
        ("show_proxies", "show_proxies | proxies", "Display proxy status"),
        ("exit", "exit | quit | q", "Leave the shell"),
    ];

    println!("{}", format!("{:<16} {:<25} {}", "Command", "Shortcuts", "Description").bold());
    println!("{}", "-".repeat(72).dimmed());
    for (cmd, shortcuts, desc) in entries {
        println!("{:<16} {:<25} {}", cmd.green(), shortcuts.cyan(), desc);
    }
    println!();
    println!(
        "{}",
        "Need more context? Try `modules`, then `use category/module_name`, and finally `run`."
        .dimmed()
    );
    println!();
}

async fn test_current_proxies(ctx: &mut ShellContext) -> Result<()> {
    if ctx.proxy_list.is_empty() {
        println!("No proxies loaded to test.");
        return Ok(());
    }

    let total = ctx.proxy_list.len();
    let test_url = prompt_string_default("Proxy test URL", "https://example.com")?;
    let timeout_secs = prompt_u64("Proxy test timeout (seconds)", 5)?;
    let max_parallel = prompt_usize("Max concurrent proxy tests", 10)?;

    println!(
        "[*] Testing {} proxy entr{} (timeout: {}s, concurrency: {})",
             total,
             if total == 1 { "y" } else { "ies" },
                 timeout_secs,
             max_parallel
    );

    let summary = utils::test_proxies(&ctx.proxy_list, &test_url, timeout_secs, max_parallel).await;
    let working_count = summary.working.len();
    let failed = summary.failed;
    let working = summary.working;

    if working_count == 0 {
        println!("{}", "[-] No proxies passed the connectivity test.".red());
    } else {
        println!(
            "{}",
            format!("[+] {} proxies passed the connectivity test.", working_count).green()
        );
    }

    if !failed.is_empty() {
        println!(
            "{}",
            format!("[-] {} proxies failed validation:", failed.len()).yellow()
        );
        for failure in &failed {
            println!("    {} -> {}", failure.proxy, failure.reason);
        }
    }

    ctx.proxy_list = working;

    if ctx.proxy_enabled && ctx.proxy_list.is_empty() {
        println!("[!] Proxy list is empty after testing. Disabling proxy usage.");
        ctx.proxy_enabled = false;
        clear_proxy_env_vars();
    }

    Ok(())
}

fn prompt_for_path(message: &str) -> io::Result<String> {
    loop {
        print!("{}", message);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        // Length check
        if input.len() > MAX_PATH_LENGTH {
            println!("{}", format!("Path too long (max {} characters).", MAX_PATH_LENGTH).yellow());
            continue;
        }
        
        let value = input.trim();
        
        if value.is_empty() {
            println!("Path cannot be empty. Please try again.");
            continue;
        }
        
        // Check for control characters
        if value.chars().any(|c| c.is_control()) {
            println!("{}", "Path cannot contain control characters.".yellow());
            continue;
        }
        
        // Basic path traversal check
        if value.contains("..") {
            println!("{}", "Path cannot contain '..' (path traversal).".yellow());
            continue;
        }
        
        return Ok(value.to_string());
    }
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

fn prompt_yes_no(message: &str, default_yes: bool) -> io::Result<bool> {
    let default_hint = if default_yes { "Y/n" } else { "y/N" };
    let mut attempts = 0;
    const MAX_ATTEMPTS: u8 = 10;
    
    loop {
        attempts += 1;
        if attempts > MAX_ATTEMPTS {
            println!("{}", "Too many invalid attempts. Using default.".yellow());
            return Ok(default_yes);
        }
        
        print!("{} [{}]: ", message, default_hint);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        // Length check - y/n should be very short
        if input.len() > 10 {
            println!("{}", "Please answer with 'y' or 'n'.".yellow());
            continue;
        }
        
        let trimmed = input.trim().to_lowercase();
        match trimmed.as_str() {
            "" => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please answer with 'y' or 'n'."),
        }
    }
}

fn prompt_u64(message: &str, default: u64) -> io::Result<u64> {
    let mut attempts = 0;
    const MAX_ATTEMPTS: u8 = 10;
    
    loop {
        attempts += 1;
        if attempts > MAX_ATTEMPTS {
            println!("{}", "Too many invalid attempts. Using default.".yellow());
            return Ok(default);
        }
        
        print!("{} [{}]: ", message, default);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        // Length check - numbers shouldn't be too long
        if input.len() > 20 {
            println!("{}", "Number too long. Please enter a valid positive integer.".yellow());
            continue;
        }
        
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(default);
        }
        
        // Only allow digits
        if !trimmed.chars().all(|c| c.is_ascii_digit()) {
            println!("Invalid number. Please enter a positive integer.");
            continue;
        }
        
        match trimmed.parse::<u64>() {
            Ok(value) if value > 0 => return Ok(value),
            Ok(_) => println!("Number must be greater than 0."),
            Err(_) => println!("Number too large. Please enter a smaller value."),
        }
    }
}

fn prompt_usize(message: &str, default: usize) -> io::Result<usize> {
    let mut attempts = 0;
    const MAX_ATTEMPTS: u8 = 10;
    
    loop {
        attempts += 1;
        if attempts > MAX_ATTEMPTS {
            println!("{}", "Too many invalid attempts. Using default.".yellow());
            return Ok(default);
        }
        
        print!("{} [{}]: ", message, default);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        // Length check - numbers shouldn't be too long
        if input.len() > 20 {
            println!("{}", "Number too long. Please enter a valid positive integer.".yellow());
            continue;
        }
        
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(default);
        }
        
        // Only allow digits
        if !trimmed.chars().all(|c| c.is_ascii_digit()) {
            println!("Invalid number. Please enter a positive integer.");
            continue;
        }
        
        match trimmed.parse::<usize>() {
            Ok(value) if value > 0 => return Ok(value),
            Ok(_) => println!("Number must be greater than 0."),
            Err(_) => println!("Number too large. Please enter a smaller value."),
        }
    }
}

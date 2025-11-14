use crate::commands;
use crate::utils;
use anyhow::Result;
use colored::*;
use rand::prelude::*; // rand 0.9 prelude provides rng() and SliceRandom
use std::env;
use std::io::{self, Write};
use std::collections::HashSet;

const MAX_INPUT_LENGTH: usize = 4096;
const MAX_PROXY_LIST_SIZE: usize = 10_000;
const MAX_TARGET_LENGTH: usize = 512;

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

    let mut ctx = ShellContext::new();

    loop {
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

        match split_command(trimmed) {
            Some((cmd, rest)) => {
                let command_key = resolve_command(&cmd);
                match command_key.as_str() {
                    "exit" => {
                        println!("Exiting...");
                        clear_proxy_env_vars();
                        break;
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
                            prompt_for_path("Path to proxy list file: ")? 
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

                                if prompt_yes_no("Test connectivity of loaded proxies? (recommended)", true)? {
                                    test_current_proxies(&mut ctx).await?;
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
                        test_current_proxies(&mut ctx).await?;
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
                        if let Some(raw_value) = rest.strip_prefix("target").map(|s| s.trim()) {
                            match sanitize_target(raw_value) {
                                Ok(valid_target) => {
                                    ctx.current_target = Some(valid_target.clone());
                                    println!("{}", format!("Target set to {}", valid_target).green());
                                }
                                Err(reason) => {
                                    println!("{}", format!("[!] {}", reason).yellow());
                                }
                            }
                        } else {
                            println!("{}", "Usage: set target <value>".yellow());
                        }
                    }
                    "run" => {
                        if let Some(ref module_path) = ctx.current_module {
                            if let Some(ref t) = ctx.current_target {
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
                            }
                        } else {
                            println!("{}", "No module selected. Use 'use <module>' first.".yellow());
                        }
                    }
                    _ => {
                        println!("{}", format!("Unknown command: '{}'. Type 'help' or '?' for usage.", trimmed).red());
                    }
                }
            }
            None => {
                println!("{}", format!("Unknown command: '{}'. Type 'help' or '?' for usage.", trimmed).red());
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
        choice.to_string()
    } else {
        proxy_list.choose(&mut rng).unwrap().to_string()
    }
}

/// Sets ALL_PROXY so reqwest uses it for all requests (including socks4, socks5, http, https)
fn set_all_proxy_env(proxy: &str) {
    env::set_var("ALL_PROXY", proxy);
}

/// Clears environment variables for direct connection
fn clear_proxy_env_vars() {
    env::remove_var("ALL_PROXY");
    env::remove_var("HTTP_PROXY");
    env::remove_var("HTTPS_PROXY");
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
        "run" | "go" | "exec" => "run",
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
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("Target cannot contain whitespace or control characters.");
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
        ("set target", "set target <value>", "Set current target host/IP"),
        ("run", "run | go", "Execute selected module (with proxy rotation)"),
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
        let value = input.trim();
        if !value.is_empty() {
            return Ok(value.to_string());
        }
        println!("Path cannot be empty. Please try again.");
    }
}

fn prompt_string_default(message: &str, default: &str) -> io::Result<String> {
    print!("{} [{}]: ", message, default);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn prompt_yes_no(message: &str, default_yes: bool) -> io::Result<bool> {
    let default_hint = if default_yes { "Y/n" } else { "y/N" };
    loop {
        print!("{} [{}]: ", message, default_hint);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
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
    loop {
        print!("{} [{}]: ", message, default);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(default);
        }
        match trimmed.parse::<u64>() {
            Ok(value) => return Ok(value),
            Err(_) => println!("Invalid number. Please enter a positive integer."),
        }
    }
}

fn prompt_usize(message: &str, default: usize) -> io::Result<usize> {
    loop {
        print!("{} [{}]: ", message, default);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(default);
        }
        match trimmed.parse::<usize>() {
            Ok(value) if value > 0 => return Ok(value),
            _ => println!("Invalid number. Please enter a positive integer."),
        }
    }
}

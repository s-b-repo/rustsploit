use crate::commands;
use crate::utils;
use anyhow::Result;
use rand::prelude::*;  // Updated for rand 0.10
use std::env;
use std::io::{self, Write};
use std::collections::HashSet;

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
        print!("rsf> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        match input {
            "exit" | "quit" => {
                println!("Exiting...");
                break;
            },
            "help" => {
                println!("Available commands:");
                println!("  use <module_path>   - Select a module (e.g. 'use exploits/sample_exploit')");
                println!("  set target <value>  - Set the target IP/host");
                println!("  run                 - Run the current module (with proxy retries if enabled)");
                println!("  modules             - List available modules");
                println!("  find <keyword>      - Search for a module by keyword");
                println!("  proxy_load <file>   - Load a list of proxies (http://ip:port, socks5://ip:port, etc)");
                println!("  proxy_on            - Enable proxy usage");
                println!("  proxy_off           - Disable proxy usage");
                println!("  show_proxies        - Show loaded proxies & current proxy status");
                println!("  exit, quit          - Exit the shell");
            },
            "modules" => {
                utils::list_all_modules();
            },
            cmd if cmd.starts_with("find ") => {
                let keyword = cmd.trim_start_matches("find ").trim();
                if keyword.is_empty() {
                    println!("Usage: find <keyword>");
                } else {
                    utils::find_modules(keyword);
                }
            },
            cmd if cmd.starts_with("proxy_load ") => {
                let file = cmd.trim_start_matches("proxy_load ").trim();
                match utils::load_proxies_from_file(file) {
                    Ok(list) => {
                        ctx.proxy_list = list;
                        println!("Loaded {} proxies from '{}'.", ctx.proxy_list.len(), file);
                    }
                    Err(e) => {
                        println!("Failed to load proxies: {}", e);
                    }
                }
            },
            "proxy_on" => {
                ctx.proxy_enabled = true;
                println!("Proxy usage enabled.");
            },
            "proxy_off" => {
                ctx.proxy_enabled = false;
                println!("Proxy usage disabled.");
                clear_proxy_env_vars();
            },
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
            },
            cmd if cmd.starts_with("use ") => {
                let module_path = cmd.trim_start_matches("use ").trim();
                if utils::module_exists(module_path) {
                    ctx.current_module = Some(module_path.to_string());
                    println!("Module '{}' selected.", module_path);
                } else {
                    println!("Module '{}' not found.", module_path);
                }
            },
            cmd if cmd.starts_with("set ") => {
                let parts: Vec<&str> = cmd.split_whitespace().collect();
                if parts.len() >= 3 && parts[1] == "target" {
                    ctx.current_target = Some(parts[2].to_string());
                    println!("Target set to {}", parts[2]);
                } else {
                    println!("Usage: set target <value>");
                }
            },
            "run" => {
                if let Some(ref module_path) = ctx.current_module {
                    if let Some(ref t) = ctx.current_target {
                        // -----------------------------
                        // NEW: Proxy Retry Logic
                        // -----------------------------
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
                        println!("No target set. Use 'set target <value>' first.");
                    }
                } else {
                    println!("No module selected. Use 'use <module>' first.");
                }
            },
            _ => {
                println!("Unknown command: '{}'. Type 'help' for usage.", input);
            },
        }
    }

    Ok(())
}

/// Picks a random proxy from `proxy_list` that is NOT in `tried_proxies`.
fn pick_random_untried_proxy(proxy_list: &[String], tried_proxies: &HashSet<String>) -> String {
    let untried: Vec<&String> = proxy_list.iter()
        .filter(|p| !tried_proxies.contains(*p))
        .collect();

    if untried.is_empty() {
        // Fall back if somehow there's nothing untried
        let mut rng = rand::rng();
        let idx = rng.random_range(0..proxy_list.len());
        return proxy_list[idx].clone();
    }

    let mut rng = rand::rng();
    let idx = rng.random_range(0..untried.len());
    untried[idx].clone()
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

use crate::commands;
use crate::utils;
use anyhow::Result;
use std::io::{self, Write};

pub async fn interactive_shell() -> Result<()> {
    println!("Welcome to RustSploit Shell (inspired by RouterSploit)");
    println!("Type 'help' for a list of commands. Type 'exit' or 'quit' to leave.");

    let mut current_module: Option<String> = None;
    let mut current_target: Option<String> = None;

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
                println!("  run                 - Run the current module");
                println!("  modules             - List available modules");
                println!("  exit, quit          - Exit the shell");
            },
            "modules" => {
                utils::list_all_modules();
            },
            c if c.starts_with("use ") => {
                let module_path = c.trim_start_matches("use ").trim();
                if utils::module_exists(module_path) {
                    current_module = Some(module_path.to_string());
                    println!("Module '{}' selected.", module_path);
                } else {
                    println!("Module '{}' not found.", module_path);
                }
            },
            c if c.starts_with("set ") => {
                // Example: set target 192.168.1.1
                let parts: Vec<&str> = c.split_whitespace().collect();
                if parts.len() >= 3 && parts[1] == "target" {
                    current_target = Some(parts[2].to_string());
                    println!("Target set to {}", parts[2]);
                } else {
                    println!("Usage: set target <value>");
                }
            },
            "run" => {
                if let Some(ref module_path) = current_module {
                    if let Some(ref t) = current_target {
                        println!("Running module '{}' against target '{}'", module_path, t);
                        commands::run_module(module_path, t).await?;
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

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use colored::*;
use std::net::SocketAddr;
use std::process;

mod cli;
mod shell;
mod commands;
mod modules;
mod utils;
mod api;
mod config;

/// Maximum length for API key to prevent memory exhaustion
const MAX_API_KEY_LENGTH: usize = 256;

/// Maximum length for interface/bind address
const MAX_BIND_ADDRESS_LENGTH: usize = 128;


/// Validates the bind address format
fn validate_bind_address(addr: &str) -> Result<String> {
    let trimmed = addr.trim();

    if trimmed.is_empty() {
        return Err(anyhow!("Bind address cannot be empty"));
    }
    if trimmed.len() > MAX_BIND_ADDRESS_LENGTH {
        return Err(anyhow!("Bind address too long (max {} characters)", MAX_BIND_ADDRESS_LENGTH));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(anyhow!("Bind address cannot contain control characters"));
    }

    let with_port = if trimmed.contains(':') {
        trimmed.to_string()
    } else {
        format!("{}:8080", trimmed)
    };

    with_port
        .parse::<SocketAddr>()
        .map_err(|e| anyhow!("Invalid bind address '{}': {}", with_port, e))?;

    Ok(with_port)
}

/// Validates API key format
fn validate_api_key(key: &str) -> Result<String> {
    let trimmed = key.trim();

    if trimmed.is_empty() {
        return Err(anyhow!("API key cannot be empty"));
    }
    if trimmed.len() > MAX_API_KEY_LENGTH {
        return Err(anyhow!("API key too long (max {} characters)", MAX_API_KEY_LENGTH));
    }
    if !trimmed.chars().all(|c| c.is_ascii_graphic()) {
        return Err(anyhow!("API key must contain only printable ASCII characters"));
    }

    Ok(trimmed.to_string())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{} {}", "❌".red(), e);
        process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli_args = cli::Cli::parse();

    utils::verbose_log(cli_args.verbose, "CLI arguments parsed successfully");

    // Handle list_modules flag
    if cli_args.list_modules {
        utils::verbose_log(cli_args.verbose, "Listing all modules...");
        utils::list_all_modules();
        return Ok(());
    }

    // API server mode
    if cli_args.api {
        let api_key_raw = cli_args
            .api_key
            .as_ref()
            .ok_or_else(|| anyhow!("--api-key is required when using --api mode"))?;

        let api_key = validate_api_key(api_key_raw).context("Invalid API key")?;
        let interface = cli_args.interface.clone().unwrap_or_else(|| "127.0.0.1".to_string());
        let bind_address = validate_bind_address(&interface).context("Invalid bind address")?;

        utils::verbose_log(cli_args.verbose, &format!("Starting API server on {}...", bind_address));
        api::start_api_server(&bind_address, api_key, cli_args.verbose).await?;
        return Ok(());
    }

    // Validate target if provided
    if let Some(ref target) = cli_args.target {
        if let Err(e) = utils::normalize_target(target) {
            return Err(anyhow!("Invalid target '{}': {}", target, e));
        }
    }

    // Set global target if provided
    if let Some(ref target) = cli_args.set_target {
        utils::verbose_log(cli_args.verbose, &format!("Setting global target to: {}", target));
        config::GLOBAL_CONFIG.set_target(target)?;
        println!("{} Global target set to: {}", "✓".green(), target);
    }

    // Handle subcommands from CLI
    if let Some(cmd) = &cli_args.command {
        utils::verbose_log(cli_args.verbose, &format!("Executing subcommand: {}", cmd));
        commands::handle_command(cmd, &cli_args).await?;
    }
    // Run module directly if both -m and -t are provided
    else if let Some(ref module) = cli_args.module {
        if let Some(ref target) = cli_args.target {
            utils::verbose_log(cli_args.verbose, &format!("Running module '{}' against '{}'", module, target));
            commands::run_module(module, target, cli_args.verbose).await?;
        } else if config::GLOBAL_CONFIG.has_target() {
            let target = config::GLOBAL_CONFIG.get_target().unwrap_or_default();
            utils::verbose_log(cli_args.verbose, &format!("Running module '{}' against global target '{}'", module, target));
            commands::run_module(module, &target, cli_args.verbose).await?;
        } else {
            eprintln!("{}", "⚠ Warning: --module specified without --target. Launching shell...".yellow());
            utils::verbose_log(cli_args.verbose, "Launching interactive shell...");
            shell::interactive_shell(cli_args.verbose).await?;
        }
    }
    // Launch interactive shell
    else {
        utils::verbose_log(cli_args.verbose, "Launching interactive shell...");
        shell::interactive_shell(cli_args.verbose).await?;
    }

    Ok(())
}

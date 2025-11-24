use anyhow::{Context, Result};
use clap::Parser;

mod cli;
mod shell;
mod commands;
mod modules;
mod utils;
mod api;
mod config;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let cli_args = cli::Cli::parse();

    // Check if API mode is requested
    if cli_args.api {
        let api_key = cli_args
        .api_key
        .context("--api-key is required when using --api mode")?;

        let interface = cli_args.interface.unwrap_or_else(|| "0.0.0.0".to_string());

        // If interface already contains a port (has ':'), use it as-is, otherwise add default port
        let bind_address = if interface.contains(':') {
            interface
        } else {
            format!("{}:8080", interface)
        };

        let harden = cli_args.harden;
        let ip_limit = cli_args.ip_limit.unwrap_or(10);

        api::start_api_server(&bind_address, api_key, harden, ip_limit).await?;
        return Ok(());
    }

    // Set global target if provided
    if let Some(ref target) = cli_args.set_target {
        config::GLOBAL_CONFIG.set_target(target)?;
        println!("✓ Global target set to: {}", target);
    }

    // If user provided subcommands (e.g., "exploit", "scan", etc.) from CLI, handle them directly:
    if let Some(cmd) = &cli_args.command {
        commands::handle_command(cmd, &cli_args).await?;
    }
    // Otherwise, launch the interactive shell
    else {
        shell::interactive_shell().await?;
    }

    Ok(())
}

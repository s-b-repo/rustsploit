use anyhow::Result;
use clap::Parser;

mod cli;
mod shell;
mod commands;
mod modules;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let cli_args = cli::Cli::parse();

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

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use colored::*;
use std::net::SocketAddr;
use std::process;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

mod cli;
mod shell;
mod commands;
mod modules;
mod utils;
mod api;
mod config;
mod context;
mod native;
pub mod output;
pub mod module_info;
pub mod global_options;
pub mod cred_store;
pub mod spool;
pub mod workspace;
pub mod loot;
pub mod export;
pub mod jobs;
pub mod mcp;
pub mod pq_channel;
pub mod pq_middleware;


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

/// Returns the path to the PQ host key file.
fn pq_host_key_path(custom: Option<&str>) -> std::path::PathBuf {
    if let Some(p) = custom {
        std::path::PathBuf::from(p)
    } else {
        home::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".rustsploit")
            .join("pq_host_key")
    }
}

/// Returns the path to the PQ authorized keys file.
fn pq_authorized_keys_path(custom: Option<&str>) -> std::path::PathBuf {
    if let Some(p) = custom {
        std::path::PathBuf::from(p)
    } else {
        home::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".rustsploit")
            .join("pq_authorized_keys")
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{} {}", "❌".red(), e);
        process::exit(1);
    }
}

async fn run() -> Result<()> {
    // Initialize structured logging — console + file
    let filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new("warn")
    };

    let log_dir = home::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".rustsploit")
        .join("logs");
    let _ = std::fs::create_dir_all(&log_dir);

    // Daily rolling log file: rustsploit.YYYY-MM-DD.log
    let file_appender = tracing_appender::rolling::daily(&log_dir, "rustsploit.log");
    let (non_blocking, _log_guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .with_target(false)
                .with_writer(std::io::stderr),
        )
        .with(
            fmt::layer()
                .with_target(true)
                .with_ansi(false)
                .with_writer(non_blocking),
        )
        .init();

    let cli_args = cli::Cli::parse();

    tracing::debug!("CLI arguments parsed successfully");

    // Handle list_modules flag
    if cli_args.list_modules {
        tracing::debug!("Listing all modules...");
        utils::list_all_modules();
        return Ok(());
    }

    // API server mode — PQ-encrypted, no TLS, no API keys
    if cli_args.api {
        let host_key_path = pq_host_key_path(cli_args.pq_host_key.as_deref());
        let auth_keys_path = pq_authorized_keys_path(cli_args.pq_authorized_keys.as_deref());

        let interface = cli_args.interface.clone().unwrap_or_else(|| "127.0.0.1".to_string());
        let bind_address = validate_bind_address(&interface).context("Invalid bind address")?;

        tracing::debug!("Starting PQ-encrypted API server on {}...", bind_address);
        api::start_api_server(
            &bind_address,
            cli_args.verbose,
            &host_key_path,
            &auth_keys_path,
        )
        .await?;
        return Ok(());
    }

    // MCP server mode
    if cli_args.mcp {
        tracing::debug!("Starting MCP server on stdio...");
        mcp::run_mcp_server().await?;
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
        tracing::debug!("Setting global target to: {}", target);
        config::GLOBAL_CONFIG.set_target(target)?;
        println!("{} Global target set to: {}", "✓".green(), target);
    }

    // Handle subcommands from CLI
    if let Some(cmd) = &cli_args.command {
        tracing::debug!("Executing subcommand: {}", cmd);
        commands::handle_command(cmd, &cli_args).await?;
    }
    // Run module directly if both -m and -t are provided
    else if let Some(ref module) = cli_args.module {
        if let Some(ref target) = cli_args.target {
            tracing::debug!("Running module '{}' against '{}'", module, target);
            commands::run_module(module, target, cli_args.verbose).await?;
        } else if config::GLOBAL_CONFIG.has_target() {
            let target = config::GLOBAL_CONFIG.get_target().unwrap_or_default();
            tracing::debug!("Running module '{}' against global target '{}'", module, target);
            commands::run_module(module, &target, cli_args.verbose).await?;
        } else {
            eprintln!("{}", "⚠ Warning: --module specified without --target. Launching shell...".yellow());
            tracing::debug!("Launching interactive shell...");
            if let Some(ref rc) = cli_args.resource {
                shell::interactive_shell_with_resource(cli_args.verbose, Some(rc)).await?;
            } else {
                shell::interactive_shell(cli_args.verbose).await?;
            }
        }
    }
    // Launch interactive shell
    else {
        tracing::debug!("Launching interactive shell...");
        if let Some(ref rc) = cli_args.resource {
            shell::interactive_shell_with_resource(cli_args.verbose, Some(rc)).await?;
        } else {
            shell::interactive_shell(cli_args.verbose).await?;
        }
    }

    Ok(())
}

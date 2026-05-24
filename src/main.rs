use std::net::SocketAddr;
use std::process;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use colored::*;
use tracing_subscriber::EnvFilter;

mod api;
mod cli;
mod commands;
mod config;
mod context;
mod modules;
mod native;
mod shell;
mod utils;

pub mod checkpoint;
pub mod cred_store;
pub mod events;
pub mod exclusions;
pub mod tenant;
pub mod export;
pub mod global_options;
pub mod jobs;
pub mod loot;
pub mod mcp;
pub mod module;
pub mod module_info;
pub mod output;
pub mod pq_channel;
pub mod pq_middleware;
pub mod prescan;
pub mod rate_limit;
pub mod scheduler;
pub mod spool;
pub mod workspace;
pub mod ws;


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
        .with_context(|| format!("Invalid bind address '{}'", with_port))?;

    Ok(with_port)
}

/// Returns the path to the PQ host key file.
fn pq_host_key_path(custom: Option<&str>) -> std::path::PathBuf {
    if let Some(p) = custom {
        std::path::PathBuf::from(p)
    } else {
        // Refuse to fall back to CWD for security-sensitive key material —
        // CWD may be world-readable or an attacker-controlled directory.
        let home = home::home_dir().unwrap_or_else(|| {
            eprintln!("[!] $HOME not set — PQ host key will use /tmp/.rustsploit (insecure fallback)");
            std::path::PathBuf::from("/tmp")
        });
        home.join(".rustsploit").join("pq_host_key")
    }
}

/// Returns the path to the PQ authorized keys file.
fn pq_authorized_keys_path(custom: Option<&str>) -> std::path::PathBuf {
    if let Some(p) = custom {
        std::path::PathBuf::from(p)
    } else {
        let home = home::home_dir().unwrap_or_else(|| {
            eprintln!("[!] $HOME not set — PQ authorized keys will use /tmp/.rustsploit (insecure fallback)");
            std::path::PathBuf::from("/tmp")
        });
        home.join(".rustsploit").join("pq_authorized_keys")
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
    // Initialize structured logging
    let filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new("warn")
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let cli_args = cli::Cli::parse();

    tracing::debug!("CLI arguments parsed successfully");

    // P0-2: propagate the strict-TLS flag to the framework's HTTP-client
    // builder so `permissive()` callers automatically pick up the operator's
    // policy. Modules that *legitimately* need to talk to self-signed
    // devices still opt in explicitly via `HttpClientOpts {
    // accept_invalid_certs: true, .. }`. P1-9: same plumbing for the
    // proxy-trust flag used by the handshake rate limiter.
    utils::network::set_global_strict_tls(cli_args.strict_tls);
    utils::network::set_global_trust_proxy(cli_args.trust_proxy);
    if !cli_args.strict_tls {
        tracing::warn!(
            "TLS verification permissive by default for HTTPS exploit modules. \
             Pass --strict-tls to flip the default to strict."
        );
    }

    // Handle list_modules flag
    if cli_args.list_modules {
        tracing::debug!("Listing all modules...");
        utils::list_all_modules();
        return Ok(());
    }

    // Regenerate docs/Module-Catalog.md from the live registry
    if cli_args.gen_module_catalog {
        let md = module::render_catalog_markdown();
        let out = std::path::Path::new("docs/Module-Catalog.md");
        tokio::fs::write(out, md).await.context("Failed to write docs/Module-Catalog.md")?;
        println!("{} Wrote {} ({} modules)",
            "✓".green(), out.display(), module::count());
        return Ok(());
    }

    // List on-disk scan checkpoints
    if cli_args.list_checkpoints {
        match checkpoint::list_checkpoints() {
            Ok(list) if list.is_empty() => {
                println!("No checkpoints found.");
            }
            Ok(list) => {
                println!("Active checkpoints (resume by re-running the same module + target):\n");
                for cp in list {
                    println!("  {}", cp);
                }
            }
            Err(e) => {
                return Err(anyhow!("Failed to enumerate checkpoints: {e:#}"));
            }
        }
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
            cli_args.pq_key_passphrase.as_deref(),
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
    if let Some(ref target) = cli_args.target
        && let Err(e) = utils::normalize_target(target) {
            return Err(anyhow!("Invalid target '{}': {}", target, e));
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

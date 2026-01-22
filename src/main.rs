use anyhow::{anyhow, Context, Result};
use clap::Parser;
use std::net::SocketAddr;

mod cli;
mod shell;
mod commands;
mod modules;
mod utils;
mod api;
mod config;
mod core;

/// Maximum length for API key to prevent memory exhaustion
const MAX_API_KEY_LENGTH: usize = 256;

/// Maximum length for interface/bind address
const MAX_BIND_ADDRESS_LENGTH: usize = 128;

/// Maximum IP limit for hardening mode
const MAX_IP_LIMIT: u32 = 10000;

/// Validates the bind address format for security
fn validate_bind_address(addr: &str) -> Result<String> {
    let trimmed = addr.trim();
    
    // Length check
    if trimmed.is_empty() {
        return Err(anyhow!("Bind address cannot be empty"));
    }
    
    if trimmed.len() > MAX_BIND_ADDRESS_LENGTH {
        return Err(anyhow!(
            "Bind address too long (max {} characters)",
            MAX_BIND_ADDRESS_LENGTH
        ));
    }
    
    // Check for control characters
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(anyhow!("Bind address cannot contain control characters"));
    }
    
    // Add port if missing
    let with_port = if trimmed.contains(':') {
        trimmed.to_string()
    } else {
        format!("{}:8080", trimmed)
    };
    
    // Validate socket address format
    with_port.parse::<SocketAddr>()
        .map_err(|e| anyhow!("Invalid bind address '{}': {}", with_port, e))?;
    
    Ok(with_port)
}

/// Validates API key format for security
fn validate_api_key(key: &str) -> Result<String> {
    let trimmed = key.trim();
    
    if trimmed.is_empty() {
        return Err(anyhow!("API key cannot be empty"));
    }
    
    if trimmed.len() > MAX_API_KEY_LENGTH {
        return Err(anyhow!(
            "API key too long (max {} characters)",
            MAX_API_KEY_LENGTH
        ));
    }
    
    // Only allow printable ASCII characters
    if !trimmed.chars().all(|c| c.is_ascii_graphic()) {
        return Err(anyhow!("API key must contain only printable ASCII characters"));
    }
    
    Ok(trimmed.to_string())
}

/// Validates IP limit for hardening mode
fn validate_ip_limit(limit: u32) -> Result<u32> {
    if limit == 0 {
        return Err(anyhow!("IP limit must be greater than 0"));
    }
    
    if limit > MAX_IP_LIMIT {
        return Err(anyhow!(
            "IP limit too high (max {})",
            MAX_IP_LIMIT
        ));
    }
    
    Ok(limit)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let cli_args = cli::Cli::parse();

    // Check if API mode is requested
    if cli_args.api {
        let api_key_raw = cli_args
            .api_key
            .context("--api-key is required when using --api mode")?;
        
        // Validate API key
        let api_key = validate_api_key(&api_key_raw)
            .context("Invalid API key")?;

        let interface = cli_args.interface.unwrap_or_else(|| "0.0.0.0".to_string());
        
        // Validate and normalize bind address
        let bind_address = validate_bind_address(&interface)
            .context("Invalid bind address")?;

        let harden = cli_args.harden;
        
        // Validate IP limit
        let ip_limit_raw = cli_args.ip_limit.unwrap_or(10);
        let ip_limit = validate_ip_limit(ip_limit_raw)
            .context("Invalid IP limit")?;

        api::start_api_server(&bind_address, api_key, harden, ip_limit).await?;
        return Ok(());
    }

    // Set global target if provided
    if let Some(ref target) = cli_args.set_target {
        // Target validation is done in config::set_target
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
// test comment

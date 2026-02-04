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
mod totp_config;
mod job_archive;

/// Custom error types for CLI operations
#[derive(Debug)]
pub enum CliError {
    InvalidFlagCombination { flag1: String, flag2: String, message: String },
    // MissingRequiredFlag is handled by clap, but we can wrap validaton errors
    ValidationFailed { field: String, reason: String },
    ModuleNotFound { module: String, suggestions: Vec<String> },
    TargetInvalid { target: String, reason: String },
    ApiError { message: String },
    Generic { message: String },
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::InvalidFlagCombination { flag1, flag2, message } => {
                 write!(f, "{} Invalid flag combination detected: {} + {}\n  {}", "❌".red(), flag1.yellow(), flag2.yellow(), message)
            },
            CliError::ValidationFailed { field, reason } => {
                 write!(f, "{} Validation failed for '{}': {}", "❌".red(), field.yellow(), reason)
            },
            CliError::ModuleNotFound { module, suggestions } => {
                writeln!(f, "{} Module '{}' not found.", "❌".red(), module.yellow())?;
                if !suggestions.is_empty() {
                    writeln!(f, "  Did you mean:")?;
                    for s in suggestions {
                        writeln!(f, "    - {}", s.green())?;
                    }
                }
                Ok(())
            },
            CliError::TargetInvalid { target, reason } => {
                 write!(f, "{} Invalid target '{}': {}", "❌".red(), target.yellow(), reason)
            },
            CliError::ApiError { message } => {
                 write!(f, "{} API Server Error: {}", "❌".red(), message)
            },
            CliError::Generic { message } => {
                 write!(f, "{} Error: {}", "❌".red(), message)
            }
        }
    }
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Generic { .. } => 1,
            CliError::InvalidFlagCombination { .. } => 2,
            CliError::ValidationFailed { .. } => 2,
            CliError::ModuleNotFound { .. } => 3,
            CliError::TargetInvalid { .. } => 4,
            CliError::ApiError { .. } => 5,
        }
    }
}

/// Maximum length for API key to prevent memory exhaustion
const MAX_API_KEY_LENGTH: usize = 256;

/// Maximum length for interface/bind address
const MAX_BIND_ADDRESS_LENGTH: usize = 128;

/// Maximum IP limit for hardening mode
const MAX_IP_LIMIT: u32 = 10000;

/// Prints CLI usage hint
fn print_usage_hint() {
    eprintln!("{}", "Usage hints:".yellow().bold());
    eprintln!("  {} Launch interactive shell", "cargo run".cyan());
    eprintln!("  {} Run module on target", "cargo run -- -m <module> -t <target>".cyan());
    eprintln!("  {} Start API server", "cargo run -- --api --api-key <key>".cyan());
    eprintln!("  {} List all modules in shell", "cargo run (then type 'modules')".cyan());
    eprintln!();
    eprintln!("{}", "For more help: cargo run -- --help".dimmed());
}

/// Validates CLI flag combinations and prints warnings for common mistakes
fn validate_cli_flags(cli_args: &cli::Cli) -> Result<()> {
    // Warning: -m without -t
    if cli_args.module.is_some() && cli_args.target.is_none() {
        eprintln!();
        eprintln!("{}", "⚠ Warning: --module (-m) specified without --target (-t)".yellow().bold());
        eprintln!("{}", "  The module requires a target to run against.".yellow());
        eprintln!();
        print_usage_hint();
        eprintln!();
        eprintln!("{}", "Launching interactive shell instead...".cyan());
        eprintln!();
    }

    // Warning: -t without -m (not an error, but inform user)
    if cli_args.target.is_some() && cli_args.module.is_none() && cli_args.command.is_none() {
        eprintln!();
        eprintln!("{}", "ℹ Note: --target (-t) specified without --module (-m)".blue().bold());
        eprintln!("{}", "  Target will be available in interactive shell.".blue());
        eprintln!();
    }

    // Warning: --harden without --api
    if cli_args.harden && !cli_args.api {
        eprintln!();
        eprintln!("{}", "⚠ Warning: --harden requires --api mode".yellow().bold());
        eprintln!("{}", "  Hardening features are only active in API server mode.".yellow());
        eprintln!();
        print_usage_hint();
        return Err(anyhow!(CliError::InvalidFlagCombination { 
            flag1: "--harden".to_string(), 
            flag2: "no --api".to_string(), 
            message: "Harden mode requires API mode".to_string() 
        }));
    }


    // Note: --ip-limit requires --harden is enforced by clap's requires attribute

    // Warning: --interface without --api
    if let Some(ref iface) = cli_args.interface {
        if !cli_args.api && iface != "0.0.0.0" {  // Ignore default value
            eprintln!();
            eprintln!("{}", "⚠ Warning: --interface requires --api mode".yellow().bold());
            eprintln!("{}", "  Interface binding is only used in API server mode.".yellow());
            eprintln!();
        }
    }

    Ok(())
}

/// Validates the bind address format for security
fn validate_bind_address(addr: &str) -> Result<String> {
    let trimmed = addr.trim();
    
    // Length check
    if trimmed.is_empty() {
        return Err(anyhow!(CliError::ValidationFailed { 
            field: "bind_address".to_string(), 
            reason: "Address cannot be empty".to_string() 
        }));
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
        return Err(anyhow!(CliError::ValidationFailed { 
            field: "ip_limit".to_string(), 
            reason: "Must be greater than 0".to_string() 
        }));
    }
    
    if limit > MAX_IP_LIMIT {
        return Err(anyhow!(
            "IP limit too high (max {})",
            MAX_IP_LIMIT
        ));
    }
    
    Ok(limit)
}

/// TOTP setup wizard - runs interactively to configure TOTP for API authentication
async fn run_totp_setup_wizard() -> Result<()> {
    use std::io::{self, Write};
    
    println!();
    println!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan().bold());
    println!("{}", "║           TOTP AUTHENTICATION SETUP WIZARD                   ║".cyan().bold());
    println!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan().bold());
    println!();
    
    let mut config = totp_config::TotpConfig::load()
        .context("Failed to load TOTP configuration")?;
    
    loop {
        // Show menu
        println!("{}", "Options:".yellow().bold());
        println!("  {} List existing TOTP accounts", "1.".cyan());
        println!("  {} Add new TOTP (link to API token)", "2.".cyan());
        println!("  {} Remove TOTP account", "3.".cyan());
        println!("  {} Exit", "4.".cyan());
        println!();
        
        print!("{}", "Enter choice [1-4]: ".cyan().bold());
        io::stdout().flush()?;
        
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        let choice = choice.trim();
        
        match choice {
            "1" => {
                // List accounts
                let accounts = config.list_accounts();
                if accounts.is_empty() {
                    println!();
                    println!("{}", "No TOTP accounts configured.".yellow());
                } else {
                    println!();
                    println!("{}", "Configured TOTP accounts:".green().bold());
                    for (short_hash, entry) in &accounts {
                        let status = if entry.enabled { "✓ Enabled" } else { "✗ Disabled" };
                        println!("  {} Token: {} | Label: {} | Created: {} | {}",
                            "•".green(),
                            short_hash.cyan(),
                            entry.label,
                            entry.created_at,
                            status
                        );
                    }
                }
                println!();
            }
            "2" => {
                // Add new TOTP
                println!();
                println!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan().bold());
                println!("{}", "║                    ADD NEW TOTP ACCOUNT                      ║".cyan().bold());
                println!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan().bold());
                println!();
                println!("{}", "Enter the API token to link this TOTP to:".cyan());
                println!("{}", "  (This is the token you'll use with --api-key)".dimmed());
                print!("{}", "API Token: ".cyan().bold());
                io::stdout().flush()?;
                
                let mut token_input = String::new();
                io::stdin().read_line(&mut token_input)?;
                let token = token_input.trim();
                
                if token.is_empty() {
                    println!("{}", "Token cannot be empty.".red());
                    continue;
                }
                
                // Check if already exists
                if config.is_configured_for_token(token) {
                    println!("{}", "TOTP already exists for this token. Remove it first.".red());
                    continue;
                }
                
                print!("{}", "Label (e.g., 'admin@server1') [default]: ".cyan());
                io::stdout().flush()?;
                
                let mut label_input = String::new();
                io::stdin().read_line(&mut label_input)?;
                let label = label_input.trim();
                let label = if label.is_empty() {
                    format!("RustSploit-{}", &totp_config::TotpConfig::hash_token(token)[..8])
                } else {
                    label.to_string()
                };
                
                println!();
                println!("{}", "Generating TOTP secret...".green());
                
                match config.generate_secret_for_token(token, &label) {
                    Ok((secret, _url, token_hash)) => {
                        // Generate QR code
                        let qr_path = std::env::current_dir()
                            .unwrap_or_else(|_| std::path::PathBuf::from("."))
                            .join(format!("totp_qr_{}.png", &token_hash[..8]));
                        
                        match config.generate_qr_png_for_token(token) {
                            Ok(png_data) => {
                                if let Err(e) = std::fs::write(&qr_path, &png_data) {
                                    eprintln!("{}", format!("[WARN] Failed to save QR: {}", e).yellow());
                                } else {
                                    println!();
                                    println!("{}", format!("QR Code saved: {}", qr_path.display()).green().bold());
                                    println!("{}", "Scan with Google Authenticator, Authy, etc.".cyan());
                                }
                            }
                            Err(e) => eprintln!("{}", format!("[WARN] QR generation failed: {}", e).yellow()),
                        }
                        
                        println!();
                        println!("{}", "Or enter this secret manually:".cyan());
                        println!("  {}", secret.green().bold());
                        println!();
                        println!("{}", format!("Token hash: {}...", &token_hash[..16]).dimmed());
                        println!();
                        
                        // Verification loop
                        loop {
                            print!("{}", "Enter 6-digit code to verify: ".cyan().bold());
                            io::stdout().flush()?;
                            
                            let mut code_input = String::new();
                            io::stdin().read_line(&mut code_input)?;
                            let code = code_input.trim();
                            
                            if code.eq_ignore_ascii_case("cancel") || code.eq_ignore_ascii_case("q") {
                                println!("{}", "Setup cancelled.".red());
                                let _ = config.remove_entry_by_token(token);
                                break;
                            }
                            
                            match config.verify_code_for_token(token, code) {
                                Ok(true) => {
                                    println!();
                                    println!("{}", "╔══════════════════════════════════════════════════════════════╗".green().bold());
                                    println!("{}", "║  ✓ TOTP SETUP SUCCESSFUL!                                   ║".green().bold());
                                    println!("{}", "╚══════════════════════════════════════════════════════════════╝".green().bold());
                                    println!();
                                    println!("{}", "IMPORTANT:".yellow().bold());
                                    println!("  • This TOTP is linked to THIS specific API token");
                                    println!("  • TOTP required every 30 minutes when using --harden-totp");
                                    println!("  • Use X-TOTP-Code header in API requests");
                                    println!();
                                    println!("{}", "Example:".dimmed());
                                    println!("{}", format!("  cargo run -- --api --api-key \"{}\" --harden-totp", 
                                        if token.len() > 20 { format!("{}...", &token[..20]) } else { token.to_string() }
                                    ).dimmed());
                                    println!("{}", "  curl -H 'Authorization: Bearer YOUR_TOKEN' -H 'X-TOTP-Code: 123456' ...".dimmed());
                                    
                                    // Clean up QR
                                    if qr_path.exists() {
                                        let _ = std::fs::remove_file(&qr_path);
                                        println!();
                                        println!("{}", format!("QR deleted: {}", qr_path.display()).dimmed());
                                    }
                                    break;
                                }
                                Ok(false) => println!("{}", "Invalid code. Try again or type 'cancel'.".red()),
                                Err(e) => println!("{}", format!("Error: {}", e).red()),
                            }
                        }
                    }
                    Err(e) => println!("{}", format!("Failed to generate TOTP: {}", e).red()),
                }
                println!();
            }
            "3" => {
                // Remove TOTP
                let hashes = config.get_all_token_hashes();
                if hashes.is_empty() {
                    println!();
                    println!("{}", "No TOTP accounts to remove.".yellow());
                    println!();
                    continue;
                }
                
                println!();
                println!("{}", "Select account to remove:".yellow().bold());
                for (i, hash) in hashes.iter().enumerate() {
                    if let Some(entry) = config.get_entry_by_hash(hash) {
                        println!("  {} {}... ({})", format!("{}.", i + 1).cyan(), &hash[..12], entry.label);
                    }
                }
                println!("  {} Cancel", format!("{}.", hashes.len() + 1).cyan());
                println!();
                
                print!("{}", "Choice: ".cyan().bold());
                io::stdout().flush()?;
                
                let mut rm_choice = String::new();
                io::stdin().read_line(&mut rm_choice)?;
                
                if let Ok(idx) = rm_choice.trim().parse::<usize>() {
                    if idx > 0 && idx <= hashes.len() {
                        let hash = &hashes[idx - 1];
                        match config.remove_entry_by_hash(hash) {
                            Ok(true) => println!("{}", "Account removed successfully.".green()),
                            Ok(false) => println!("{}", "Account not found.".yellow()),
                            Err(e) => println!("{}", format!("Error: {}", e).red()),
                        }
                    }
                }
                println!();
            }
            "4" | "q" | "exit" => {
                println!("{}", "Exiting TOTP wizard.".cyan());
                break;
            }
            _ => println!("{}", "Invalid choice.".red()),
        }
    }
    
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        // Check if downcast to CliError works
        if let Some(cli_error) = e.downcast_ref::<CliError>() {
             eprintln!("{}", cli_error);
             process::exit(cli_error.exit_code());
        } else {
             // Fallback for generic anyhow errors
             eprintln!("{} {}", "❌".red(), e);
             process::exit(1);
        }
    }
}

async fn run() -> Result<()> {
    // Parse command-line arguments
    let cli_args = cli::Cli::parse();

    utils::verbose_log(cli_args.verbose, "CLI arguments parsed successfully");

    // Validate CLI flag combinations (prints warnings for common mistakes)
    utils::verbose_log(cli_args.verbose, "Validating CLI flags...");
    validate_cli_flags(&cli_args)?;

    // Handle list_modules flag
    if cli_args.list_modules {
        utils::verbose_log(cli_args.verbose, "Listing all modules...");
        utils::list_all_modules();
        return Ok(());
    }

    // Handle TOTP setup wizard
    if cli_args.setup_totp {
        utils::verbose_log(cli_args.verbose, "Starting TOTP setup wizard...");
        return run_totp_setup_wizard().await;
    }

    // Check if API mode is requested
    if cli_args.api {
        let api_key_raw = cli_args
            .api_key
            .as_ref()
            .ok_or_else(|| anyhow!("--api-key is required when using --api mode"))?;
        
        // Validate API key
        let api_key = validate_api_key(api_key_raw)
            .context("Invalid API key")?;

        let interface = cli_args.interface.clone().unwrap_or_else(|| "127.0.0.1".to_string());
        
        // Validate and normalize bind address
        let bind_address = validate_bind_address(&interface)
            .context("Invalid bind address")?;

        let harden = cli_args.harden;
        
        // Validate IP limit
        let ip_limit_raw = cli_args.ip_limit.unwrap_or(10);
        let ip_limit = validate_ip_limit(ip_limit_raw)
            .context("Invalid IP limit")?;

        utils::verbose_log(cli_args.verbose, &format!("Starting API server on {}...", bind_address));
        api::start_api_server(
            &bind_address,
            api_key,
            harden,
            cli_args.harden_totp,
            cli_args.harden_rate_limit,
            cli_args.harden_ip_tracking,
            ip_limit,
            cli_args.verbose,
            cli_args.queue_size,
            cli_args.workers,
        ).await?;
        return Ok(());
    }

    // Validate target if provided (fail fast on invalid input)
    if let Some(ref target) = cli_args.target {
        if let Err(e) = utils::normalize_target(target) {
             return Err(anyhow!(CliError::TargetInvalid { 
                target: target.clone(), 
                reason: e.to_string() 
            }));
        }
    }

    // Set global target if provided
    if let Some(ref target) = cli_args.set_target {
        utils::verbose_log(cli_args.verbose, &format!("Setting global target to: {}", target));
        // Target validation is done in config::set_target
        config::GLOBAL_CONFIG.set_target(target)?;
        println!("{} Global target set to: {}", "✓".green(), target);
    }

    // If user provided subcommands (e.g., "exploit", "scan", etc.) from CLI, handle them directly:
    if let Some(cmd) = &cli_args.command {
        utils::verbose_log(cli_args.verbose, &format!("Executing subcommand: {}", cmd));
        commands::handle_command(cmd, &cli_args).await?;
    }
    // Improved module+target handling: Run module directly if both -m and -t (or global target) are present
    else if let Some(ref module) = cli_args.module {
         if let Some(ref target) = cli_args.target {
             utils::verbose_log(cli_args.verbose, &format!("Running module '{}' against '{}'", module, target));
             commands::run_module(module, target, cli_args.verbose).await?;
         } else if config::GLOBAL_CONFIG.has_target() {
             let target = match config::GLOBAL_CONFIG.get_target() {
                 Some(t) => t,
                 None => String::new(),
             };
             utils::verbose_log(cli_args.verbose, &format!("Running module '{}' against global target '{}'", module, target));
             commands::run_module(module, &target, cli_args.verbose).await?;
         } else {
             // If only -m: Show warning, launch shell with module preselected (Phase 3 mostly, but good fallback)
             eprintln!("{}", "⚠ Warning: --module specified without --target. Launching shell...".yellow());
             utils::verbose_log(cli_args.verbose, "Launching interactive shell...");
             shell::interactive_shell(cli_args.verbose).await?;
         }
    }
    // Otherwise, launch the interactive shell
    else {
        utils::verbose_log(cli_args.verbose, "Launching interactive shell...");
        shell::interactive_shell(cli_args.verbose).await?;
    }

    Ok(())
}


use clap::{ArgGroup, Parser};

/// Simple RouterSploit-like CLI in Rust
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[clap(group(
    ArgGroup::new("mode")
        .required(false)
        .args(&["command", "api", "setup_totp"])
))]
pub struct Cli {
    /// Subcommand to run (e.g. "exploit", "scanner", "creds")
    pub command: Option<String>,

    /// Target IP or hostname
    #[arg(short, long)]
    pub target: Option<String>,

    /// Module name to use
    #[arg(short, long)]
    pub module: Option<String>,

    /// Launch API server mode
    #[arg(long)]
    pub api: bool,

    /// API key for authentication (required when --api is used)
    #[arg(long, requires = "api")]
    pub api_key: Option<String>,

    /// Enable all hardening features (TOTP + rate limit + IP tracking)
    #[arg(long, requires = "api")]
    pub harden: bool,

    /// Enable TOTP authentication for API (requires --api)
    #[arg(long, requires = "api")]
    pub harden_totp: bool,

    /// Enable rate limiting for API (requires --api)
    #[arg(long, requires = "api")]
    pub harden_rate_limit: bool,

    /// Enable IP tracking for API (requires --api)
    #[arg(long, requires = "api")]
    pub harden_ip_tracking: bool,

    /// Network interface to bind API server to (default: 0.0.0.0)
    #[arg(long, requires = "api", default_value = "0.0.0.0")]
    pub interface: Option<String>,

    /// IP limit for hardening mode (default: 10 unique IPs)
    #[arg(long, default_value = "10")]
    pub ip_limit: Option<u32>,

    /// Set global target IP/subnet for all modules
    #[arg(long)]
    pub set_target: Option<String>,

    /// Enable verbose output (shows detailed operation logs)
    #[arg(short, long)]
    pub verbose: bool,

    /// List all available modules and exit
    #[arg(long)]
    pub list_modules: bool,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    pub output_format: Option<String>,

    /// API job queue size (default: 100)
    #[arg(long, default_value_t = 100)]
    pub queue_size: usize,

    /// Number of worker threads for API jobs (default: 10)
    #[arg(long, default_value_t = 10)]
    pub workers: usize,

    /// Set up TOTP authentication (interactive wizard)
    #[arg(long)]
    pub setup_totp: bool,
}


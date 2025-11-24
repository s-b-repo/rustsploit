use clap::{ArgGroup, Parser};

/// Simple RouterSploit-like CLI in Rust
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[clap(group(
    ArgGroup::new("mode")
        .required(false)
        .args(&["command", "api"])
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

    /// Enable hardening mode (auto-rotate API key on suspicious activity)
    #[arg(long, requires = "api")]
    pub harden: bool,

    /// Network interface to bind API server to (default: 0.0.0.0)
    #[arg(long, requires = "api", default_value = "0.0.0.0")]
    pub interface: Option<String>,

    /// IP limit for hardening mode (default: 10 unique IPs)
    #[arg(long, requires = "harden", default_value = "10")]
    pub ip_limit: Option<u32>,

    /// Set global target IP/subnet for all modules
    #[arg(long)]
    pub set_target: Option<String>,
}

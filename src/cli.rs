use clap::Parser;

/// Simple RouterSploit-like CLI in Rust
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
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

    /// Network interface to bind API server to (default: 127.0.0.1)
    #[arg(long, requires = "api", default_value = "127.0.0.1")]
    pub interface: Option<String>,

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
}

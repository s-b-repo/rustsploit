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

    /// Path to PQ authorized keys file (default: ~/.rustsploit/pq_authorized_keys)
    #[arg(long, requires = "api")]
    pub pq_authorized_keys: Option<String>,

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

    /// Execute a resource script file on startup
    #[arg(short = 'r', long = "resource")]
    pub resource: Option<String>,

    /// Path to PQ host key file (default: ~/.rustsploit/pq_host_key)
    #[arg(long, requires = "api")]
    pub pq_host_key: Option<String>,

    /// Launch MCP (Model Context Protocol) server over stdio
    #[arg(long)]
    pub mcp: bool,
}

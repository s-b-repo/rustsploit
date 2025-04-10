use clap::{ArgGroup, Parser};

/// Simple RouterSploit-like CLI in Rust
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[clap(group(
    ArgGroup::new("mode")
        .required(false)
        .args(&["command"])
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
}

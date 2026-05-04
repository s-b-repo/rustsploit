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

    /// Enable strict TLS verification for all modules. Without this flag, the
    /// framework's `permissive()` HTTP client builder accepts self-signed
    /// certs (historical behavior — many target devices use self-signed
    /// certs). Setting this flag flips the default to verifying TLS, matching
    /// the standard browser/curl posture. Modules that legitimately need
    /// permissive TLS can still opt in explicitly.
    #[arg(long)]
    pub strict_tls: bool,

    /// Trust X-Forwarded-For (and similar) for client-IP attribution in
    /// rate limiting. Off by default — only enable when the daemon is behind
    /// a proxy you trust to scrub the header. Without this flag, the
    /// per-IP handshake limiter uses the TCP peer address.
    #[arg(long, requires = "api")]
    pub trust_proxy: bool,

    /// Passphrase for encrypting/decrypting the PQ host key at rest.
    /// When set, the host key file is encrypted with argon2id + ChaCha20-Poly1305.
    /// If omitted in API mode, the operator is prompted interactively on first run.
    #[arg(long, requires = "api")]
    pub pq_key_passphrase: Option<String>,
}

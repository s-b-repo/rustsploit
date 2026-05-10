//! Telnet credential probe — wordlist-driven sibling of `telnet_hose`. The
//! latter only tries default creds; this iterates user-supplied wordlists.
//!
//! For the actual telnet state machine (IAC negotiation, banner detection,
//! shell-prompt heuristics) we delegate to the proven helper in
//! `telnet_hose` — keeps both modules consistent.

use anyhow::{Context, Result};
use crate::module::{ModuleCtx, ModuleOutcome};

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::creds_helper::{self, CredsRun};
use crate::utils::LoginResult;

const DEFAULT_PORT: u16 = 23;

/// Defaults overlap with `telnet_hose` so this module is also useful as a
/// "wordlist + defaults" probe, not strictly default-only.
const DEFAULTS: &[(&str, &str)] = &[
    ("root", "root"),
    ("root", "admin"),
    ("root", ""),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("user", "user"),
    ("guest", "guest"),
];

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Telnet Bruteforce".to_string(),
        description:
            "Wordlist-driven Telnet credential probe with IAC handling. Single-target — \
             scheduler does fan-out."
                .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: ModuleRank::Normal,
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("telnet_bruteforce requires a single-host target")?;
    creds_helper::run(
        target,
        CredsRun {
            service_name: "telnet",
            default_port: DEFAULT_PORT,
            source_module: "creds/generic/telnet_bruteforce",
            defaults: DEFAULTS,
            password_only: false,
        },
        |host, port, user, pass| async move { probe(&host, port, &user, &pass).await },
    )
    .await
}

async fn probe(host: &str, port: u16, user: &str, pass: &str) -> LoginResult {
    use std::net::SocketAddr;
    use std::time::Duration;

    let socket: SocketAddr = match format!("{}:{}", host, port).parse() {
        Ok(sa) => sa,
        Err(_) => match tokio::net::lookup_host(format!("{}:{}", host, port)).await {
            Ok(mut iter) => match iter.next() {
                Some(sa) => sa,
                None => {
                    return LoginResult::Error {
                        message: "no DNS results".to_string(),
                        retryable: false,
                    }
                }
            },
            Err(e) => {
                return LoginResult::Error {
                    message: format!("dns: {e}"),
                    retryable: false,
                }
            }
        },
    };

    let _ = Duration::from_secs(5); // (kept for future per-attempt tuning)

    // Reuse the helper: it implements the full IAC + banner + login state
    // machine. Returns Ok(true) on success, Ok(false) on auth fail or
    // closed port. Errors propagate as retryable.
    use super::telnet_hose;
    match telnet_hose::try_login(&socket, user, pass).await {
        Ok(true) => LoginResult::Success,
        Ok(false) => LoginResult::AuthFailed,
        Err(e) => LoginResult::Error {
            message: format!("telnet: {e:#}"),
            retryable: true,
        },
    }
}

crate::register_native_module!(crate::module::Category::Creds, "generic/telnet_bruteforce", native);

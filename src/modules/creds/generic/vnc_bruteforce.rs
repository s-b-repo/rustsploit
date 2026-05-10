//! VNC password probe — RFB 3.x DES challenge-response (security type 2).
//!
//! VNC passwords are password-only (no usernames) and silently truncated
//! to 8 bytes by the server.

use anyhow::{Context, Result};
use crate::module::{ModuleCtx, ModuleOutcome};
use std::time::Duration;

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::creds_helper::{self, CredsRun};
use crate::utils::LoginResult;

const DEFAULT_PORT: u16 = 5900;

const DEFAULTS: &[(&str, &str)] = &[
    ("", "password"),
    ("", "vnc"),
    ("", "admin"),
    ("", "12345678"),
    ("", "1234"),
    ("", "qwerty"),
    ("", "letmein"),
    ("", "default"),
    ("", "secret"),
];

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "VNC Password Bruteforce".to_string(),
        description:
            "Tests VNC RFB 3.x security-type 2 (DES challenge-response). Password-only — \
             server silently truncates to 8 bytes. Single-target — scheduler does fan-out."
                .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec!["https://www.rfc-editor.org/rfc/rfc6143".to_string()],
        disclosure_date: None,
        rank: ModuleRank::Normal,
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("vnc_bruteforce requires a single-host target")?;
    creds_helper::run(
        target,
        CredsRun {
            service_name: "vnc",
            default_port: DEFAULT_PORT,
            source_module: "creds/generic/vnc_bruteforce",
            defaults: DEFAULTS,
            password_only: true,
        },
        |host, port, _user, pass| async move { probe(&host, port, &pass).await },
    )
    .await
}

async fn probe(host: &str, port: u16, pass: &str) -> LoginResult {
    use cipher::{BlockCipherEncrypt, KeyInit};
    use des::Des;
    use tokio::io::AsyncWriteExt;

    let timeout = Duration::from_secs(5);
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

    // Server sends 12-byte protocol-version banner (e.g. "RFB 003.008\n").
    let mut banner = [0u8; 12];
    if let Err(e) =
        crate::utils::creds_helper::read_exact_with_timeout(&mut stream, &mut banner, timeout)
            .await
    {
        return LoginResult::Error {
            message: format!("read banner: {e}"),
            retryable: true,
        };
    }
    if !banner.starts_with(b"RFB ") {
        return LoginResult::Error {
            message: "not VNC (no RFB banner)".to_string(),
            retryable: false,
        };
    }
    if let Err(e) = stream.write_all(b"RFB 003.008\n").await {
        return LoginResult::Error {
            message: format!("write banner: {e}"),
            retryable: true,
        };
    }

    // Server: 1-byte security-type count, then count bytes of types.
    let mut nsec = [0u8; 1];
    if let Err(e) =
        crate::utils::creds_helper::read_exact_with_timeout(&mut stream, &mut nsec, timeout).await
    {
        return LoginResult::Error {
            message: format!("read sec count: {e}"),
            retryable: true,
        };
    }
    if nsec[0] == 0 {
        // Failure reason follows (4-byte len + string). Treat as auth fail.
        return LoginResult::AuthFailed;
    }
    let mut sec_types = vec![0u8; nsec[0] as usize];
    if let Err(e) = crate::utils::creds_helper::read_exact_with_timeout(
        &mut stream,
        &mut sec_types,
        timeout,
    )
    .await
    {
        return LoginResult::Error {
            message: format!("read sec types: {e}"),
            retryable: true,
        };
    }
    if !sec_types.contains(&2u8) {
        return LoginResult::Error {
            message: "server doesn't offer VNC auth (type 2)".to_string(),
            retryable: false,
        };
    }
    if let Err(e) = stream.write_all(&[2u8]).await {
        return LoginResult::Error {
            message: format!("write sec choice: {e}"),
            retryable: true,
        };
    }

    // 16-byte challenge.
    let mut challenge = [0u8; 16];
    if let Err(e) =
        crate::utils::creds_helper::read_exact_with_timeout(&mut stream, &mut challenge, timeout)
            .await
    {
        return LoginResult::Error {
            message: format!("read challenge: {e}"),
            retryable: true,
        };
    }

    // VNC DES key: pad/truncate password to 8 bytes, then bit-reverse each byte.
    let mut key = [0u8; 8];
    let pw_bytes = pass.as_bytes();
    for i in 0..8 {
        let b = if i < pw_bytes.len() { pw_bytes[i] } else { 0 };
        key[i] = b.reverse_bits();
    }
    let cipher = match Des::new_from_slice(&key) {
        Ok(c) => c,
        Err(_) => {
            return LoginResult::Error {
                message: "DES init failed".to_string(),
                retryable: false,
            }
        }
    };
    let mut response = [0u8; 16];
    response.copy_from_slice(&challenge);
    for chunk in response.chunks_exact_mut(8) {
        let block: cipher::array::Array<u8, _> = match cipher::array::Array::try_from(&chunk[..]) {
            Ok(b) => b,
            Err(_) => {
                return LoginResult::Error {
                    message: "DES block build failed".to_string(),
                    retryable: false,
                }
            }
        };
        let mut block = block;
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(block.as_ref());
    }
    if let Err(e) = stream.write_all(&response).await {
        return LoginResult::Error {
            message: format!("write response: {e}"),
            retryable: true,
        };
    }

    // 4-byte SecurityResult (0 = OK, 1 = failed).
    let mut sec_result = [0u8; 4];
    if let Err(e) = crate::utils::creds_helper::read_exact_with_timeout(
        &mut stream,
        &mut sec_result,
        timeout,
    )
    .await
    {
        return LoginResult::Error {
            message: format!("read result: {e}"),
            retryable: true,
        };
    }
    match u32::from_be_bytes(sec_result) {
        0 => LoginResult::Success,
        1 => LoginResult::AuthFailed,
        other => LoginResult::Error {
            message: format!("unknown SecurityResult {other}"),
            retryable: false,
        },
    }
}

crate::register_native_module!(crate::module::Category::Creds, "generic/vnc_bruteforce", native);

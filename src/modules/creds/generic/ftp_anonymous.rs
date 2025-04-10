use anyhow::{Context, Result};
use std::net::TcpStream;
use std::io::{BufRead, BufReader, Write};
use std::time::Duration;

/// Checks if anonymous FTP login is allowed on a target.
///
/// Example usage from shell:
/// ```
/// rsf> use creds/ftp_anonymous
/// rsf> set target 192.168.1.1
/// rsf> run
/// ```
pub async fn run(target: &str) -> Result<()> {
    let port = 21;
    let address = format!("{}:{}", target, port);

    println!("[*] Connecting to FTP service on {}...", address);

    // Connect with a short timeout
    let stream = TcpStream::connect_timeout(
        &address.parse().context("Invalid address")?,
        Duration::from_secs(5),
    )
    .context("Connection failed")?;

    // Clone reader/writer
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    // Read initial banner
    let mut banner = String::new();
    reader.read_line(&mut banner)?;
    print!("[<] {}", banner);

    // Send USER anonymous
    writer.write_all(b"USER anonymous\r\n")?;
    writer.flush()?;

    let mut response = String::new();
    reader.read_line(&mut response)?;
    print!("[<] {}", response);

    if !response.starts_with("3") && !response.contains("password") {
        println!("[-] Server does not accept 'anonymous' user.");
        return Ok(());
    }

    // Send PASS anything (or empty)
    writer.write_all(b"PASS anonymous\r\n")?;
    writer.flush()?;

    response.clear();
    reader.read_line(&mut response)?;
    print!("[<] {}", response);

    if response.starts_with("2") {
        println!("[+] Anonymous login successful!");
    } else {
        println!("[-] Anonymous login failed.");
    }

    Ok(())
}

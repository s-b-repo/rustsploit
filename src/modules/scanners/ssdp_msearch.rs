use anyhow::{Result};
use regex::Regex;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

pub async fn run(target_ip: &str) -> Result<()> {
    let port = 1900;
    println!("[*] Sending SSDP M-SEARCH to {}:{}...", target_ip, port);

    let addr = format!("{}:{}", target_ip, port);
    let local_bind: SocketAddr = "0.0.0.0:0".parse()?;
    let socket = UdpSocket::bind(local_bind).await?;
    socket.connect(&addr).await?;

    let request = format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {}:{}\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 2\r\n\
         ST: upnp:rootdevice\r\n\r\n",
        target_ip, port
    );

    socket.send(request.as_bytes()).await?;

    let mut buf = vec![0u8; 2048];
    match timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
        Ok(Ok(size)) => {
            let response = String::from_utf8_lossy(&buf[..size]);
            parse_ssdp_response(&response, target_ip, port);
        }
        _ => {
            println!("[-] Target did not respond to M-SEARCH request");
        }
    }

    Ok(())
}

fn parse_ssdp_response(response: &str, target_ip: &str, port: u16) {
    let regexps = vec![
        ("server", r"(?i)Server:\s*(.*?)\r\n"),
        ("location", r"(?i)Location:\s*(.*?)\r\n"),
        ("usn", r"(?i)USN:\s*(.*?)\r\n"),
    ];

    let mut results: HashMap<&str, String> = HashMap::new();

    for (key, pattern) in regexps {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(response) {
                results.insert(key, caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string());
            } else {
                results.insert(key, String::from(""));
            }
        }
    }

    println!(
        "[+] {}:{} | {} | {} | {}",
        target_ip,
        port,
        results.get("server").unwrap_or(&"".to_string()),
        results.get("location").unwrap_or(&"".to_string()),
        results.get("usn").unwrap_or(&"".to_string())
    );
}

use anyhow::{Result};
use colored::*;
use regex::Regex;
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

pub async fn run(target: &str) -> Result<()> {
    let port = prompt_port().unwrap_or(1900);

    let target = clean_ipv6_brackets(target);

    let addr = normalize_target(&target, port)?;

    println!("[*] Sending SSDP M-SEARCH to {}...", addr);

    let local_bind: SocketAddr = "0.0.0.0:0".parse()?;
    let socket = UdpSocket::bind(local_bind).await?;
    socket.connect(&addr).await?;

    let request = format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {}:{}\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 2\r\n\
         ST: upnp:rootdevice\r\n\r\n",
        target, port
    );

    socket.send(request.as_bytes()).await?;

    let mut buf = vec![0u8; 2048];
    match timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
        Ok(Ok(size)) => {
            let response = String::from_utf8_lossy(&buf[..size]);
            parse_ssdp_response(&response, &target, port);
        }
        _ => {
            println!("[-] Target did not respond to M-SEARCH request");
        }
    }

    Ok(())
}

/// Normalize the target: IPv6 -> [ipv6]:port, IPv4 stays as ipv4:port
fn normalize_target(target: &str, port: u16) -> Result<String> {
    let addr = if target.contains(':') && !target.contains(']') {
        // Plain IPv6 without brackets
        format!("[{}]:{}", target, port)
    } else if target.contains('[') {
        // Already bracketed IPv6 (sanitize just in case)
        format!("[{}]:{}", target.trim_matches(&['[', ']'][..]), port)
    } else {
        // IPv4 or hostname
        format!("{}:{}", target, port)
    };
    Ok(addr)
}

/// Cleans up accidental double or triple brackets like [[::1]] → ::1
fn clean_ipv6_brackets(ip: &str) -> String {
    ip.trim_start_matches('[')
      .trim_end_matches(']')
      .to_string()
}

/// Ask user for port (optional), fallback to 1900 if empty
fn prompt_port() -> Option<u16> {
    print!("{}", "[*] Enter custom port (default 1900): ".cyan().bold());
    std::io::stdout().flush().ok();
    let mut input = String::new();
    if let Ok(_) = std::io::stdin().read_line(&mut input) {
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

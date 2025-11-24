use anyhow::{Context, Result};
use colored::*;
use regex::Regex;
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout as tokio_timeout, Duration};

/// SSDP Search Target types
#[derive(Clone, Debug)]
enum SearchTarget {
    RootDevice,
    All,
    Custom(String),
}

impl SearchTarget {
    fn st_header(&self) -> &str {
        match self {
            SearchTarget::RootDevice => "upnp:rootdevice",
            SearchTarget::All => "ssdp:all",
            SearchTarget::Custom(st) => st,
        }
    }
}

pub async fn run(target: &str) -> Result<()> {
    let port = prompt_port().unwrap_or(1900);
    let timeout_secs = prompt_timeout().unwrap_or(3);
    let retries = prompt_retries().unwrap_or(1);
    let verbose = prompt_verbose().unwrap_or(false);

    let target = clean_ipv6_brackets(target);
    // Validate target format
    let _ = normalize_target(&target, port)
        .with_context(|| format!("Failed to normalize target '{}'", target))?;

    // Determine search targets
    let search_targets = prompt_search_targets()?;

    println!("{}", format!("[*] Sending SSDP M-SEARCH to {}:{}...", target, port).bold());

    let mut found_any = false;

    for (idx, st) in search_targets.iter().enumerate() {
        if search_targets.len() > 1 {
            println!(
                "{}",
                format!("[*] Trying ST: {} ({}/{})", st.st_header(), idx + 1, search_targets.len())
                    .cyan()
            );
        }

        for attempt in 1..=retries {
            if retries > 1 {
                println!("  [*] Attempt {}/{}", attempt, retries);
            }

            match send_ssdp_request(&target, port, st, Duration::from_secs(timeout_secs), verbose).await {
                Ok(Some(response)) => {
                    found_any = true;
                    parse_ssdp_response(&response, &target, port, st.st_header());
                    break; // Success, no need to retry
                }
                Ok(None) => {
                    if verbose {
                        println!("  {} No response received", "[-]".dimmed());
                    }
                }
                Err(e) => {
                    if verbose {
                        eprintln!("  {} Error: {}", "[!]".yellow(), e);
                    }
                }
            }

            // Small delay between retries
            if attempt < retries {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }

    if !found_any {
        println!("{}", "[-] Target did not respond to any M-SEARCH requests".yellow());
    }

    Ok(())
}

async fn send_ssdp_request(
    target: &str,
    port: u16,
    st: &SearchTarget,
    timeout: Duration,
    verbose: bool,
) -> Result<Option<String>> {
    let local_bind: SocketAddr = "0.0.0.0:0".parse()
        .context("Failed to parse local bind address")?;
    
    let socket = UdpSocket::bind(local_bind).await
        .context("Failed to bind UDP socket")?;
    
    let remote_addr: SocketAddr = format!("{}:{}", target, port).parse()
        .with_context(|| format!("Failed to parse remote address {}:{}", target, port))?;
    
    socket.connect(&remote_addr).await
        .with_context(|| format!("Failed to connect to {}:{}", target, port))?;

    let request = format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {}:{}\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: {}\r\n\
         ST: {}\r\n\
         USER-AGENT: RustSploit/1.0\r\n\r\n",
        target,
        port,
        timeout.as_secs().max(1),
        st.st_header()
    );

    if verbose {
        println!("  [*] Sending request:\n{}", request.dimmed());
    }

    socket.send(request.as_bytes()).await
        .context("Failed to send SSDP request")?;

    let mut buf = vec![0u8; 4096]; // Increased buffer size for larger responses
    match tokio_timeout(timeout, socket.recv(&mut buf)).await {
        Ok(Ok(size)) => {
            let response = String::from_utf8_lossy(&buf[..size]).to_string();
            Ok(Some(response))
        }
        Ok(Err(e)) => Err(anyhow::anyhow!("Failed to receive response: {}", e)),
        Err(_) => Ok(None), // Timeout
    }
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
    if std::io::stdin().read_line(&mut input).is_ok() {
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

/// Ask user for timeout in seconds
fn prompt_timeout() -> Option<u64> {
    print!("{}", "[*] Enter timeout in seconds (default 3): ".cyan().bold());
    std::io::stdout().flush().ok();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_ok() {
        let input = input.trim();
        if input.is_empty() {
            return None;
        }
        if let Ok(t) = input.parse::<u64>() {
            if t > 0 && t <= 60 {
                return Some(t);
            }
        }
    }
    None
}

/// Ask user for number of retries
fn prompt_retries() -> Option<u32> {
    print!("{}", "[*] Enter number of retries (default 1): ".cyan().bold());
    std::io::stdout().flush().ok();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_ok() {
        let input = input.trim();
        if input.is_empty() {
            return None;
        }
        if let Ok(r) = input.parse::<u32>() {
            if r > 0 && r <= 10 {
                return Some(r);
            }
        }
    }
    None
}

/// Ask user for verbose mode
fn prompt_verbose() -> Option<bool> {
    print!("{}", "[*] Verbose output? [y/N]: ".cyan().bold());
    std::io::stdout().flush().ok();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_ok() {
        let input = input.trim().to_lowercase();
        match input.as_str() {
            "y" | "yes" => return Some(true),
            "n" | "no" | "" => return Some(false),
            _ => {}
        }
    }
    None
}

/// Ask user for search targets
fn prompt_search_targets() -> Result<Vec<SearchTarget>> {
    let mut targets = Vec::new();

    println!("{}", "[*] Select SSDP Search Targets:".cyan().bold());
    println!("  1. upnp:rootdevice (default)");
    println!("  2. ssdp:all");
    println!("  3. Custom ST");
    println!("  4. All of the above");

    print!("{}", "Enter choice [1-4, default 1]: ".cyan().bold());
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();

    match input.trim() {
        "1" | "" => {
            targets.push(SearchTarget::RootDevice);
        }
        "2" => {
            targets.push(SearchTarget::All);
        }
        "3" => {
            print!("{}", "Enter custom ST: ".cyan().bold());
            std::io::stdout().flush().ok();
            let mut st_input = String::new();
            std::io::stdin().read_line(&mut st_input).ok();
            let st = st_input.trim().to_string();
            if !st.is_empty() {
                targets.push(SearchTarget::Custom(st));
            } else {
                targets.push(SearchTarget::RootDevice);
            }
        }
        "4" => {
            targets.push(SearchTarget::RootDevice);
            targets.push(SearchTarget::All);
        }
        _ => {
            targets.push(SearchTarget::RootDevice);
        }
    }

    if targets.is_empty() {
        targets.push(SearchTarget::RootDevice);
    }

    Ok(targets)
}

fn parse_ssdp_response(response: &str, target_ip: &str, port: u16, st: &str) {
    let regexps = vec![
        ("server", r"(?i)Server:\s*(.*?)\r\n"),
        ("location", r"(?i)Location:\s*(.*?)\r\n"),
        ("usn", r"(?i)USN:\s*(.*?)\r\n"),
        ("st", r"(?i)ST:\s*(.*?)\r\n"),
        ("nt", r"(?i)NT:\s*(.*?)\r\n"),
        ("cache-control", r"(?i)Cache-Control:\s*(.*?)\r\n"),
        ("ext", r"(?i)EXT:\s*(.*?)\r\n"),
    ];

    let mut results: HashMap<&str, String> = HashMap::new();

    for (key, pattern) in regexps {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(response) {
                let value = caps.get(1)
                    .map(|m| m.as_str().trim())
                    .unwrap_or("")
                    .to_string();
                results.insert(key, value);
            } else {
                results.insert(key, String::new());
            }
        }
    }

    // Check HTTP status
    let status_line = response.lines().next().unwrap_or("");
    let status_ok = status_line.contains("200") || status_line.contains("HTTP/1.1");

    if status_ok {
        println!(
            "{}",
            format!(
                "[+] {}:{} | ST: {} | Server: {} | Location: {} | USN: {}",
                target_ip,
                port,
                results.get("st").or(results.get("nt")).unwrap_or(&st.to_string()),
                results.get("server").unwrap_or(&String::new()),
                results.get("location").unwrap_or(&String::new()),
                results.get("usn").unwrap_or(&String::new())
            )
            .green()
        );

        // Show additional headers if present
        if let Some(cache) = results.get("cache-control") {
            if !cache.is_empty() {
                println!("  {} Cache-Control: {}", "  |".dimmed(), cache.dimmed());
            }
        }
    } else {
        println!(
            "{}",
            format!("[!] {}:{} | Unexpected response: {}", target_ip, port, status_line)
                .yellow()
        );
    }
}

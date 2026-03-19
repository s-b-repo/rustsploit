use anyhow::{Context, Result};
use colored::*;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

use std::net::SocketAddr;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::time::{timeout as tokio_timeout, Duration};
use crate::utils::{
    cfg_prompt_port, cfg_prompt_int_range, cfg_prompt_yes_no, cfg_prompt_default,
};

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

fn display_banner() {
    println!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   SSDP M-SEARCH Scanner                                      ║".cyan());
    println!("{}", "║   Discovers UPnP devices via SSDP protocol                   ║".cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    println!();
}

pub async fn run(target: &str) -> Result<()> {
    display_banner();
    
    println!("{}", format!("[*] Target: {}", target).cyan());
    
    let port = cfg_prompt_port("port", "Enter custom port", 1900)?;
    let timeout_secs = cfg_prompt_int_range("timeout", "Timeout in seconds", 3, 1, 60)? as u64;
    let retries = cfg_prompt_int_range("retries", "Number of retries", 1, 1, 10)? as u32;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose output?", false)?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", false)?;

    let target = clean_ipv6_brackets(target);
    // Validate target format
    let _ = normalize_target(&target, port)
        .with_context(|| format!("Failed to normalize target '{}'", target))?;

    // Determine search targets
    let search_target_choice = cfg_prompt_default("search_target", "SSDP Search Target (1=rootdevice, 2=all, 3=custom, 4=both)", "1")?;
    let search_targets = match search_target_choice.as_str() {
        "2" => vec![SearchTarget::All],
        "3" => {
            let custom_st = cfg_prompt_default("custom_st", "Enter custom ST", "upnp:rootdevice")?;
            vec![SearchTarget::Custom(custom_st)]
        },
        "4" => vec![SearchTarget::RootDevice, SearchTarget::All],
        _ => vec![SearchTarget::RootDevice],
    };

    println!();
    println!("{}", format!("[*] Sending SSDP M-SEARCH to {}:{}...", target, port).bold());

    let mut found_any = false;
    let mut results = Vec::new();
    let start_time = Instant::now();

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
                    let result = parse_ssdp_response(&response, &target, port, st.st_header());
                    if let Some(r) = result {
                        results.push(r);
                    }
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

    let elapsed = start_time.elapsed();

    // Print statistics
    println!();
    println!("{}", "=== Scan Statistics ===".bold());
    println!("  Target:           {}:{}", target, port);
    println!("  Search types:     {}", search_targets.len());
    println!("  Retries:          {}", retries);
    println!("  Devices found:    {}", if found_any { 
        results.len().to_string().green().to_string() 
    } else { 
        "0".red().to_string() 
    });
    println!("  Duration:         {:.2}s", elapsed.as_secs_f64());

    if !found_any {
        println!();
        println!("{}", "[-] Target did not respond to any M-SEARCH requests".yellow());
    }

    // Save results if requested
    if save_results && !results.is_empty() {
        let filename = format!("ssdp_scan_{}.txt", target.replace([':', '.', '[', ']'], "_"));
        if let Ok(mut file) = File::create(&filename) {
            writeln!(file, "SSDP M-SEARCH Scan Results").ok();
            writeln!(file, "Target: {}:{}", target, port).ok();
            writeln!(file, "Duration: {:.2}s", elapsed.as_secs_f64()).ok();
            writeln!(file).ok();
            for result in &results {
                writeln!(file, "{}", result).ok();
            }
            println!("{}", format!("[+] Results saved to '{}'", filename).green());
        }
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

fn parse_ssdp_response(response: &str, target_ip: &str, port: u16, st: &str) -> Option<String> {
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
        let st_value = results.get("st").or(results.get("nt")).unwrap_or(&st.to_string()).clone();
        let server = results.get("server").unwrap_or(&String::new()).clone();
        let location = results.get("location").unwrap_or(&String::new()).clone();
        let usn = results.get("usn").unwrap_or(&String::new()).clone();
        
        let result_line = format!(
            "{}:{} | ST: {} | Server: {} | Location: {} | USN: {}",
            target_ip, port, st_value, server, location, usn
        );
        
        println!("{}", format!("[+] {}", result_line).green());

        // Show additional headers if present
        if let Some(cache) = results.get("cache-control") {
            if !cache.is_empty() {
                println!("  {} Cache-Control: {}", "  |".dimmed(), cache.dimmed());
            }
        }
        
        Some(result_line)
    } else {
        println!(
            "{}",
            format!("[!] {}:{} | Unexpected response: {}", target_ip, port, status_line)
                .yellow()
        );
        None
    }
}

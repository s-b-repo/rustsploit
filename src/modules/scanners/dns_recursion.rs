use anyhow::{anyhow, Context, Result};
use colored::*;

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use tokio::time::{timeout, Duration};
use crate::utils::{
    prompt_default, prompt_port,
};

use hickory_client::client::{Client, ClientHandle};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::udp::UdpClientStream;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;

#[derive(Clone, Debug)]
struct TargetSpec {
    input: String,
    host: String,
    port: Option<u16>,
}

fn display_banner() {
    println!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   DNS Recursion & Amplification Scanner                      ║".cyan());
    println!("{}", "║   Detects open resolvers that may be abused for DoS attacks  ║".cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    println!();
}

/// Scan DNS resolvers for open recursion with improved input validation.
pub async fn run(initial_target: &str) -> Result<()> {
    display_banner();

    let mut targets = vec![
        TargetSpec {
            input: initial_target.to_string(),
            host: initial_target.to_string(),
            port: None,
        }
    ];

    let needs_default_port = targets.iter().any(|t| t.port.is_none());
    let default_port = if needs_default_port {
        prompt_port("Default DNS port", 53).await?
    } else {
        53
    };

    let query_name_input = prompt_default("Domain to query", "google.com").await?;
    let query_name = validate_domain_input(&query_name_input)?;

    let record_input =
        prompt_default("Record type (A, AAAA, ANY, DNSKEY, TXT, MX)", "ANY").await?;
    let record_type = parse_record_type(&record_input)?;

    println!(
        "[*] Prepared {} query for {} across {} target(s)",
        record_type,
        query_name,
        targets.len()
    );

    let name = Name::from_str_relaxed(&query_name)
        .with_context(|| format!("Invalid domain name '{}'", query_name))?;

    let mut any_success = false;
    let mut last_error: Option<anyhow::Error> = None;
    let mut vulnerable_count = 0usize;
    let mut tested_count = 0usize;
    let start_time = std::time::Instant::now();

    println!();

    for spec in targets.drain(..) {
        let port = spec.port.unwrap_or(default_port);
        let display = format_endpoint(&spec.host, port);
        println!(
            "\n[*] Processing target {} (input: {})",
            display.cyan(),
            spec.input
        );

        tested_count += 1;
        
        match resolve_target(&spec.host, port).await {
            Ok((socket_addr, resolved_display)) => {
                println!("{}", format!("[*] Target resolver: {}", resolved_display).cyan());
                match query_target(socket_addr, &resolved_display, &name, record_type, &mut vulnerable_count).await {
                    Ok(()) => any_success = true,
                    Err(err) => {
                        eprintln!(
                            "{}",
                            format!("[!] Query failed for {}: {}", resolved_display, err).red()
                        );
                        last_error = Some(err);
                    }
                }
            }
            Err(err) => {
                eprintln!(
                    "{}",
                    format!("[!] Failed to resolve {}: {}", spec.input, err).red()
                );
                last_error = Some(err);
            }
        }
    }

    let elapsed = start_time.elapsed();

    // Print statistics
    println!();
    println!("{}", "=== Scan Statistics ===".bold());
    println!("  Targets tested:       {}", tested_count);
    println!("  Vulnerable (open):    {}", if vulnerable_count > 0 { 
        vulnerable_count.to_string().red().bold().to_string() 
    } else { 
        "0".green().to_string() 
    });
    println!("  Duration:             {:.2}s", elapsed.as_secs_f64());

    if vulnerable_count > 0 {
        println!();
        println!("{}", "[!] WARNING: Open recursive DNS resolvers detected!".red().bold());
        println!("{}", "    These can be abused for DNS amplification attacks.".yellow());
    }

    if any_success {
        Ok(())
    } else {
        Err(last_error.unwrap_or_else(|| anyhow!("All targets failed.")))
    }
}

async fn query_target(
    socket_addr: SocketAddr,
    display_target: &str,
    name: &Name,
    record_type: RecordType,
    vulnerable_count: &mut usize,
) -> Result<()> {
    println!(
        "[*] Sending {} query (timeout 5s) to {}",
        record_type, display_target
    );

    let stream = UdpClientStream::builder(socket_addr, TokioRuntimeProvider::new())
        .build();
    
    let (mut client, bg) =
        Client::connect(stream).await.context("Failed to initiate DNS client")?;
    tokio::spawn(bg);

    let response: DnsResponse = timeout(
        Duration::from_secs(5),
        client.query(name.clone(), DNSClass::IN, record_type),
    )
    .await
    .context("DNS query timed out")?
    .with_context(|| format!("DNS query to {} failed", display_target))?;

    let (message, _) = response.into_parts();
    let is_vulnerable = report_result(&message, display_target, record_type);
    
    if is_vulnerable {
        *vulnerable_count += 1;
    }

    Ok(())
}

fn report_result(message: &Message, display_target: &str, record_type: RecordType) -> bool {
    let recursion_available = message.recursion_available();
    let recursion_desired = message.recursion_desired();
    let authoritative = message.authoritative();
    let truncated = message.truncated();
    let rcode = message.response_code();

    println!();
    println!(
        "{}",
        format!(
            "[*] Response code: {:?} | Answers: {} | Authority: {} | Additional: {}",
            rcode,
            message.answers().len(),
            message.name_servers().len(),
            message.additionals().len()
        ).dimmed()
    );

    if truncated {
        println!("{}", "[!] Response was truncated (TC flag set).".yellow());
    }

    println!(
        "{}",
        format!("[*] Flags: RD={} RA={} AA={}", recursion_desired, recursion_available, authoritative).dimmed()
    );

    if recursion_available && rcode != ResponseCode::Refused {
        println!(
            "{}",
            format!(
                "[+] {} appears to allow recursion (RA flag set) for {} {} queries.",
                display_target,
                record_type,
                if authoritative { "(authoritative data returned)" } else { "" }
            )
            .green()
            .bold()
        );
        println!(
            "{}",
            "    This resolver may be abused for reflection/amplification attacks (ANY/DNSSEC)."
                .yellow()
        );
        true
    } else if recursion_available && rcode == ResponseCode::Refused {
        println!(
            "{}",
            format!(
                "[-] {} reports recursion available but refused the request (likely ACL protected).",
                display_target
            )
            .yellow()
        );
        false
    } else {
        println!(
            "{}",
            format!(
                "[-] {} does not appear to allow recursion (RA flag unset or query refused).",
                display_target
            )
            .dimmed()
        );
        false
    }
}

fn parse_record_type(input: &str) -> Result<RecordType> {
    match input.trim().to_uppercase().as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::AAAA),
        "ANY" => Ok(RecordType::ANY),
        "DNSKEY" => Ok(RecordType::DNSKEY),
        "TXT" => Ok(RecordType::TXT),
        "MX" => Ok(RecordType::MX),
        other => Err(anyhow!("Unsupported record type '{}'", other)),
    }
}

async fn resolve_target(host: &str, port: u16) -> Result<(SocketAddr, String)> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, port);
        return Ok((addr, format_endpoint(host, port)));
    }

    let mut addrs_iter = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("Unable to resolve '{}:{}'", host, port))?;
    let addr = addrs_iter
        .next()
        .ok_or_else(|| anyhow!("No socket addresses resolved for '{}:{}'", host, port))?;
    Ok((addr, addr.to_string()))
}

// random_test_domain removed per request

// Unused local functions removed

fn format_endpoint(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{}]:{}", host, port),
        _ => format!("{}:{}", host, port),
    }
}

fn validate_domain_input(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Domain cannot be empty"));
    }
    if trimmed.len() > 253 {
        return Err(anyhow!(
            "Domain '{}' is too long (maximum 253 characters)",
            trimmed
        ));
    }
    let without_dot = trimmed.trim_end_matches('.');
    if without_dot.is_empty() {
        return Err(anyhow!("Domain cannot be empty"));
    }
    if without_dot
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'))
    {
        return Err(anyhow!(
            "Domain '{}' contains invalid characters. Allowed: A-Z, 0-9, '-', '_', '.'",
            trimmed
        ));
    }
    Ok(without_dot.to_lowercase())
}
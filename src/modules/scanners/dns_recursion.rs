use anyhow::{anyhow, Context, Result};
use colored::*;
use rand::Rng;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;
use hickory_client::client::{AsyncClient, ClientHandle};
use hickory_client::proto::op::ResponseCode;
use hickory_client::rr::{DNSClass, Name, RecordType};
use hickory_client::udp::UdpClientStream;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;
use tokio::net::UdpSocket;

#[derive(Clone, Debug)]
struct TargetSpec {
    input: String,
    host: String,
    port: Option<u16>,
}

/// Scan DNS resolvers for open recursion with improved input validation.
pub async fn run(initial_target: &str) -> Result<()> {
    println!("\n=== DNS Recursion & Amplification Scanner ===");

    let mut targets = collect_targets(initial_target)?;
    if targets.is_empty() {
        return Err(anyhow!(
            "No valid targets provided. Supply at least one IP/hostname."
        ));
    }

    let needs_default_port = targets.iter().any(|t| t.port.is_none());
    let default_port = if needs_default_port {
        prompt_port("Default DNS port for targets without port", 53)?
    } else {
        53
    };

    let default_domain = random_test_domain();
    let query_name_input = prompt_default("Domain to query", &default_domain)?;
    let query_name = validate_domain_input(&query_name_input)?;

    let record_input =
        prompt_default("Record type (A, AAAA, ANY, DNSKEY, TXT, MX)", "ANY")?;
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

    for spec in targets.drain(..) {
        let port = spec.port.unwrap_or(default_port);
        let display = format_endpoint(&spec.host, port);
        println!(
            "\n[*] Processing target {} (input: {})",
            display.cyan(),
            spec.input
        );

        match resolve_target(&spec.host, port).await {
            Ok((socket_addr, resolved_display)) => {
                println!("[*] Target resolver: {}", resolved_display);
                match query_target(socket_addr, &resolved_display, &name, record_type).await {
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
) -> Result<()> {
    println!(
        "[*] Sending {} query (timeout 5s) to {}",
        record_type, display_target
    );

    let timeout = Duration::from_secs(5);
    let stream = UdpClientStream::<UdpSocket>::with_timeout(socket_addr, timeout);
    let (mut client, bg) =
        AsyncClient::connect(stream).await.context("Failed to initiate DNS client")?;
    tokio::spawn(bg);

    let response: DnsResponse = client
        .query(name.clone(), DNSClass::IN, record_type)
        .await
        .with_context(|| format!("DNS query to {} failed", display_target))?;

    let (message, _) = response.into_parts();
    report_result(&message, display_target, record_type);

    Ok(())
}

fn report_result(message: &Message, display_target: &str, record_type: RecordType) {
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
        )
    );

    if truncated {
        println!("[!] Response was truncated (TC flag set).");
    }

    println!(
        "[*] Flags: RD={} RA={} AA={}",
        recursion_desired, recursion_available, authoritative
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
        );
        println!(
            "{}",
            "    This resolver may be abused for reflection/amplification attacks (ANY/DNSSEC)."
                .yellow()
        );
    } else if recursion_available && rcode == ResponseCode::Refused {
        println!(
            "{}",
            format!(
                "[-] {} reports recursion available but refused the request (likely ACL protected).",
                display_target
            )
            .yellow()
        );
    } else {
        println!(
            "{}",
            format!(
                "[-] {} does not appear to allow recursion (RA flag unset or query refused).",
                display_target
            )
            .red()
        );
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

fn random_test_domain() -> String {
    let mut rng = rand::rng();
    let random_label: String = (0..12)
        .map(|_| {
            let n = rng.random_range(0..36);
            if n < 10 {
                (b'0' + n) as char
            } else {
                (b'a' + (n - 10)) as char
            }
        })
        .collect();
    format!("{}.rustsploit.test", random_label)
}

fn prompt_default(message: &str, default: &str) -> Result<String> {
    print!("{} [{}]: ", message, default);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let trimmed = buf.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else if trimmed.len() > 255 {
        Err(anyhow!("Input too long"))
    } else {
        Ok(trimmed.to_string())
    }
}

fn prompt_port(message: &str, default: u16) -> Result<u16> {
    loop {
        let prompt = format!("{} [{}]: ", message, default);
        print!("{}", prompt);
        io::stdout().flush()?;
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            return Ok(default);
        }
        if let Ok(value) = trimmed.parse::<u16>() {
            if value > 0 {
                return Ok(value);
            }
        }
        println!("Please provide a valid port between 1 and 65535.");
    }
}

fn prompt_line(message: &str) -> Result<String> {
    print!("{}", message);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let trimmed = buf.trim();
    if trimmed.len() > 255 {
        return Err(anyhow!("Input too long (max 255 characters)."));
    }
    Ok(trimmed.to_string())
}

fn prompt_yes_no(message: &str, default_yes: bool) -> Result<bool> {
    let hint = if default_yes { "Y/n" } else { "y/N" };
    loop {
        let prompt = format!("{} [{}]: ", message, hint);
        print!("{}", prompt);
        io::stdout().flush()?;
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        let trimmed = buf.trim().to_lowercase();
        match trimmed.as_str() {
            "" => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            "stop" => return Ok(false),
            _ => println!("{}", "Please answer with 'y' or 'n'.".yellow()),
        }
    }
}

fn collect_targets(initial: &str) -> Result<Vec<TargetSpec>> {
    let mut targets = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let trimmed_initial = initial.trim();
    if !trimmed_initial.is_empty() {
        let added = parse_targets_from_str(trimmed_initial, "cli", &mut seen, &mut targets);
        if added == 0 && Path::new(trimmed_initial).is_file() {
            println!(
                "{}",
                format!("[*] Loading targets from file '{}'", trimmed_initial).cyan()
            );
            match parse_targets_from_file(trimmed_initial, &mut seen, &mut targets) {
                Ok(count) => {
                    if count == 0 {
                        println!("{}", "    No valid targets found in file.".yellow());
                    } else {
                        println!(
                            "{}",
                            format!(
                                "    Loaded {} target(s) from '{}'",
                                count, trimmed_initial
                            )
                            .green()
                        );
                    }
                }
                Err(err) => {
                    eprintln!(
                        "{}",
                        format!(
                            "    Failed to read '{}': {}",
                            trimmed_initial, err
                        )
                        .red()
                    );
                }
            }
        }
    }

    if prompt_yes_no(
        "Add additional targets manually? (type 'stop' to finish)",
        targets.is_empty(),
    )? {
        loop {
            let entry = prompt_line("Target (IP/host[:port], 'stop' to finish): ")?;
            if entry.is_empty() {
                continue;
            }
            if entry.eq_ignore_ascii_case("stop") {
                break;
            }
            add_target_token(&entry, "interactive", &mut seen, &mut targets);
        }
    }

    if prompt_yes_no("Load targets from file?", false)? {
        loop {
            let path_input = prompt_line("Path to file ('stop' to finish): ")?;
            if path_input.is_empty() {
                continue;
            }
            if path_input.eq_ignore_ascii_case("stop") {
                break;
            }
            match parse_targets_from_file(&path_input, &mut seen, &mut targets) {
                Ok(count) => {
                    if count == 0 {
                        println!(
                            "{}",
                            format!("    No valid targets parsed from '{}'", path_input).yellow()
                        );
                    } else {
                        println!(
                            "{}",
                            format!(
                                "    Loaded {} target(s) from '{}'",
                                count, path_input
                            )
                            .green()
                        );
                    }
                }
                Err(err) => eprintln!(
                    "{}",
                    format!("    Failed to read '{}': {}", path_input, err).red()
                ),
            }
        }
    }

    Ok(targets)
}

fn parse_targets_from_str(
    input: &str,
    context: &str,
    seen: &mut HashSet<String>,
    targets: &mut Vec<TargetSpec>,
) -> usize {
    let mut added = 0usize;
    for token in input
        .split(|c: char| c == ',' || c.is_ascii_whitespace())
        .filter_map(|segment| {
            let trimmed = segment.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
    {
        if add_target_token(token, context, seen, targets) {
            added += 1;
        }
    }
    added
}

fn parse_targets_from_file(
    path: &str,
    seen: &mut HashSet<String>,
    targets: &mut Vec<TargetSpec>,
) -> Result<usize> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open target file '{}'", path))?;
    let reader = BufReader::new(file);
    let mut added = 0usize;

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let content = line.split('#').next().unwrap_or("").trim();
        if content.is_empty() {
            continue;
        }
        let ctx = format!("file:{}:{}", path, idx + 1);
        added += parse_targets_from_str(content, &ctx, seen, targets);
    }

    Ok(added)
}

fn add_target_token(
    token: &str,
    context: &str,
    seen: &mut HashSet<String>,
    targets: &mut Vec<TargetSpec>,
) -> bool {
    if token.eq_ignore_ascii_case("stop") {
        return false;
    }

    match parse_target_spec(token) {
        Ok(spec) => {
            let key = format!("{}:{}", spec.host, spec.port.unwrap_or(0));
            if seen.insert(key) {
                println!(
                    "{}",
                    format!("    [{}] Added target {}", context, spec.input).cyan()
                );
                targets.push(spec);
                true
            } else {
                println!(
                    "{}",
                    format!("    [{}] Duplicate target '{}' skipped", context, token).dimmed()
                );
                false
            }
        }
        Err(err) => {
            eprintln!(
                "{}",
                format!(
                    "    [{}] Skipping invalid target '{}': {}",
                    context, token, err
                )
                .yellow()
            );
            false
        }
    }
}

fn parse_target_spec(token: &str) -> Result<TargetSpec> {
    let sanitized = sanitize_target_input(token)?;
    let (host, port) = split_host_port(&sanitized)?;
    Ok(TargetSpec {
        input: sanitized.clone(),
        host: host.to_lowercase(),
        port,
    })
}

fn sanitize_target_input(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Target cannot be empty"));
    }
    if trimmed.len() > 255 {
        return Err(anyhow!(
            "Target '{}' is too long (maximum 255 characters)",
            trimmed
        ));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || ".-_:[]".contains(c))
    {
        return Err(anyhow!(
            "Target '{}' contains invalid characters. Allowed: A-Z, 0-9, '.', '-', '_', ':', '[', ']'",
            trimmed
        ));
    }
    Ok(trimmed.to_string())
}

fn split_host_port(value: &str) -> Result<(String, Option<u16>)> {
    if value.is_empty() {
        return Err(anyhow!("Target cannot be empty"));
    }

    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), Some(addr.port())));
    }

    if value.starts_with('[') {
        let end = value
            .find(']')
            .ok_or_else(|| anyhow!("Malformed IPv6 target '{}': missing ']'", value))?;
        let host = value[1..end].to_string();
        if value.len() == end + 1 {
            return Ok((host, None));
        }
        if !value[end + 1..].starts_with(':') {
            return Err(anyhow!(
                "Malformed IPv6 target '{}': expected ':' after ']'",
                value
            ));
        }
        let port_part = &value[end + 2..];
        if port_part.is_empty() {
            return Err(anyhow!("Missing port after IPv6 address in '{}'", value));
        }
        let port = port_part
            .parse::<u16>()
            .with_context(|| format!("Invalid port '{}' in target '{}'", port_part, value))?;
        if port == 0 {
            return Err(anyhow!("Port must be between 1 and 65535"));
        }
        return Ok((host, Some(port)));
    }

    if value.ends_with(':') {
        return Err(anyhow!(
            "Invalid target '{}': trailing ':' without port",
            value
        ));
    }

    let colon_count = value.matches(':').count();
    if colon_count == 1 {
        let idx = value.rfind(':').unwrap();
        let host_part = &value[..idx];
        let port_part = &value[idx + 1..];
        if host_part.is_empty() {
            return Err(anyhow!("Host cannot be empty in target '{}'", value));
        }
        if !port_part.chars().all(|c| c.is_ascii_digit()) {
            return Err(anyhow!(
                "Invalid port '{}' in target '{}'",
                port_part,
                value
            ));
        }
        let port = port_part
            .parse::<u16>()
            .with_context(|| format!("Invalid port '{}' in target '{}'", port_part, value))?;
        if port == 0 {
            return Err(anyhow!("Port must be between 1 and 65535"));
        }
        return Ok((host_part.to_string(), Some(port)));
    }

    if colon_count >= 2 {
        let ip = value.parse::<IpAddr>().with_context(|| {
            format!(
                "Invalid IPv6 address '{}' (use [addr]:port for scoped ports)",
                value
            )
        })?;
        return Ok((ip.to_string(), None));
    }

    Ok((value.to_string(), None))
}

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
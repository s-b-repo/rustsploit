use anyhow::{anyhow, Result};
use colored::*;
use rand::Rng;
use std::io::{self, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use tokio::process::Command;

struct TargetSpec {
    host: String,
    port: Option<u16>,
}

pub async fn run(target: &str) -> Result<()> {
    println!("\n{}", "=== DNS Recursion & Amplification Scanner ===".cyan().bold());
    
    // Check if dig is installed
    check_dig_installed()?;
    
    // Sanitize and collect targets
    let sanitized = sanitize_target_input(target)?;
    let mut targets = Vec::new();
    
    // Check if it's a file path or target string
    if sanitized.starts_with('/') || sanitized.starts_with('.') {
        let path = Path::new(&sanitized);
        if path.exists() {
            parse_targets_from_file(path, &mut targets)?;
        } else {
            parse_targets_from_str(&sanitized, &mut targets)?;
        }
    } else {
        parse_targets_from_str(&sanitized, &mut targets)?;
    }
    
    // If no targets from parsing, try direct collection
    if targets.is_empty() {
        targets = collect_targets(&sanitized)?;
    }
    
    if targets.is_empty() {
        return Err(anyhow!("No valid targets found"));
    }
    
    println!("[*] Found {} target(s)", targets.len());
    
    // Prompt for domain to query (optional - uses random test domain if empty)
    let default_domain = random_test_domain();
    let query_domain = prompt_default("Domain to query (press Enter for random test domain)", &default_domain)?;
    let validated_domain = if query_domain.trim().is_empty() {
        default_domain
    } else {
        validate_domain_input(&query_domain)?
    };
    
    // Prompt for record type
    let record_type_input = prompt_default("Record type (A, AAAA, ANY, DNSKEY, TXT, MX)", "ANY")?;
    let record_type = parse_record_type(&record_type_input)?;
    
    // Prompt for default port if needed
    let needs_port = targets.iter().any(|t| t.port.is_none());
    let default_port = if needs_port {
        prompt_port("Default DNS port", 53)?
    } else {
        53
    };
    
    // Ask if user wants verbose output
    let verbose = prompt_yes_no("Enable verbose output", false)?;
    
    // Ask if user wants to save results
    let save_results = prompt_yes_no("Save results to file", false)?;
    let output_file = if save_results {
        Some(prompt_line("Output filename")?)
    } else {
        None
    };
    
    println!("\n[*] Starting DNS recursion scan...");
    println!("[*] Query: {} ({})", validated_domain, record_type);
    if verbose {
        println!("[*] Verbose mode: enabled");
    }
    
    let mut success_count = 0;
    let mut total_queries = 0;
    
    // Process each target
    for target_spec in &targets {
        let port = target_spec.port.unwrap_or(default_port);
        let endpoint = format_endpoint(&target_spec.host, port);
        
        println!("\n[*] Testing: {}", endpoint.cyan());
        
        // Resolve target
        let (socket_addr, resolved_display) = match resolve_target(&target_spec.host, port) {
            Ok(addr) => addr,
            Err(e) => {
                println!("{}", format!("[-] Failed to resolve: {}", e).red());
                continue;
            }
        };
        
        println!("[*] Resolved to: {}", resolved_display);
        
        // Query target
        total_queries += 1;
        match query_target(&validated_domain, &socket_addr.ip().to_string(), &record_type).await {
            Ok((status, answer_count, authority_count, additional_count, truncated, recursion_desired, recursion_available, authoritative)) => {
                let edns_supported = additional_count > 0;
                let dnssec_supported = status.contains("NOERROR") && authority_count > 0;
                let recursion_allowed = recursion_available && recursion_desired;
                
                let extra_info = format!(
                    "Status: {}, Answers: {}, Authority: {}, Additional: {}, Truncated: {}, Authoritative: {}",
                    status, answer_count, authority_count, additional_count, truncated, authoritative
                );
                
                if verbose {
                    report_result(
                        &validated_domain,
                        &endpoint,
                        recursion_allowed,
                        edns_supported,
                        dnssec_supported,
                        &extra_info,
                    );
                } else {
                    println!("[*] Status: {}, Recursion: {}", 
                        status, 
                        if recursion_allowed { "ALLOWED".red().bold() } else { "DENIED".green() }
                    );
                }
                
                if recursion_allowed {
                    println!("{}", "[!] WARNING: Open recursion detected!".yellow().bold());
                    success_count += 1;
                }
            }
            Err(e) => {
                if verbose {
                    println!("{}", format!("[-] Query failed: {}", e).red());
                } else {
                    println!("{}", format!("[-] Query failed: {}", e).red());
                }
            }
        }
    }
    
    println!("\n{}", "=== Scan Summary ===".cyan().bold());
    println!("[*] Total targets: {}", targets.len());
    println!("[*] Queries sent: {}", total_queries);
    println!("[*] Open recursion found: {}", success_count);
    
    // Save results if requested
    if let Some(ref filename) = output_file {
        if let Err(e) = std::fs::write(filename, format!(
            "DNS Recursion Scan Results\n\
            Domain: {}\n\
            Record Type: {}\n\
            Total Targets: {}\n\
            Queries Sent: {}\n\
            Open Recursion Found: {}\n",
            validated_domain, record_type, targets.len(), total_queries, success_count
        )) {
            println!("{}", format!("[!] Failed to save results: {}", e).yellow());
        } else {
            println!("[*] Results saved to: {}", filename);
        }
    }
    
    Ok(())
}

fn check_dig_installed() -> Result<()> {
    if which::which("dig").is_err() {
        eprintln!("\n{}", "⚠️  WARNING: 'dig' command not found!".yellow().bold());
        eprintln!("{}", "   Please install dig before using this module:".yellow());
        eprintln!("   {} {}", "   • Debian/Ubuntu:".cyan(), "sudo apt-get install dnsutils".white());
        eprintln!("   {} {}", "   • RHEL/CentOS:".cyan(), "sudo yum install bind-utils".white());
        eprintln!("   {} {}", "   • Arch Linux:".cyan(), "sudo pacman -S bind-tools".white());
        eprintln!("   {} {}", "   • macOS:".cyan(), "brew install bind".white());
        eprintln!();
        return Err(anyhow!("dig command not found. Please install dnsutils/bind-utils package."));
    }
    Ok(())
}

async fn query_target(
    domain: &str,
    server: &str,
    record: &str,
) -> Result<(String, usize, usize, usize, bool, bool, bool, bool)> {
    let output = Command::new("dig")
        .arg(format!("@{}", server))
        .arg(domain)
        .arg(record)
        .arg("+time=5")
        .arg("+tries=1")
        .arg("+stats")
        .arg("+norecurse")
        .output()
        .await
        .map_err(|e| anyhow!("Failed to execute dig command: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let exit_code = output.status.code().unwrap_or(-1);
        
        let error_msg = if !stderr.is_empty() {
            format!("dig failed (exit code {}): {}", exit_code, stderr.trim())
        } else if !stdout.is_empty() {
            format!("dig failed (exit code {}): {}", exit_code, stdout.trim())
        } else {
            format!("dig failed with exit code {} (no error output)", exit_code)
        };
        
        return Err(anyhow!("{}", error_msg));
    }

    let out = String::from_utf8_lossy(&output.stdout);
    if out.trim().is_empty() {
        return Err(anyhow!("dig command returned empty output"));
    }
    
    Ok(parse_dig_output(&out))
}

fn parse_dig_output(output: &str) -> (String, usize, usize, usize, bool, bool, bool, bool) {
    let mut status = String::new();
    let mut answer_count = 0;
    let mut authority_count = 0;
    let mut additional_count = 0;
    let mut truncated = false;
    let mut recursion_desired = false;
    let mut recursion_available = false;
    let mut authoritative = false;

    for line in output.lines() {
        if line.starts_with(";; ->>HEADER<<-") {
            if let Some(s) = line.split("status: ").nth(1) {
                status = s.split(',').next().unwrap_or("").trim().to_string();
            }
        } else if line.starts_with(";; flags:") {
            if let Some(flags_and_sections) = line.split(";; flags: ").nth(1) {
                if let Some((flags_part, sections_part)) = flags_and_sections.split_once(';') {
                    let flags = flags_part.trim();
                    truncated = flags.contains("tc");
                    recursion_desired = flags.contains("rd");
                    recursion_available = flags.contains("ra");
                    authoritative = flags.contains("aa");

                    let sections = sections_part.trim();
                    for section in sections.split(',') {
                        let trimmed = section.trim();
                        if trimmed.starts_with("ANSWER:") {
                            if let Some(count_str) = trimmed.split("ANSWER: ").nth(1) {
                                answer_count = count_str.trim().parse().unwrap_or(0);
                            }
                        } else if trimmed.starts_with("AUTHORITY:") {
                            if let Some(count_str) = trimmed.split("AUTHORITY: ").nth(1) {
                                authority_count = count_str.trim().parse().unwrap_or(0);
                            }
                        } else if trimmed.starts_with("ADDITIONAL:") {
                            if let Some(count_str) = trimmed.split("ADDITIONAL: ").nth(1) {
                                additional_count = count_str.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                }
            }
        }
    }

    (status, answer_count, authority_count, additional_count, truncated, recursion_desired, recursion_available, authoritative)
}

fn report_result(
    domain: &str,
    server: &str,
    recursion_allowed: bool,
    edns_supported: bool,
    dnssec_supported: bool,
    extra_info: &str,
) {
    println!("\n{}", "=== RESULT ===".green().bold());
    println!("Domain: {}", domain);
    println!("Server: {}", server);
    let recursion_status = if recursion_allowed { "ALLOWED".red().bold() } else { "DENIED".green() };
    println!("Recursion: {}", recursion_status);
    println!("EDNS: {}", if edns_supported { "YES".yellow() } else { "NO".normal() });
    println!("DNSSEC: {}", if dnssec_supported { "YES".yellow() } else { "NO".normal() });
    println!("Info: {}", extra_info);
}

fn parse_record_type(input: &str) -> Result<String> {
    let upper = input.trim().to_uppercase();
    match upper.as_str() {
        "A" | "AAAA" | "ANY" | "DNSKEY" | "TXT" | "MX" | "NS" | "SOA" | "CNAME" => Ok(upper),
        _ => Err(anyhow!("Invalid record type: {}. Valid types: A, AAAA, ANY, DNSKEY, TXT, MX, NS, SOA, CNAME", input)),
    }
}

fn resolve_target(host: &str, port: u16) -> Result<(SocketAddr, String)> {
    // Try parsing as IP first
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let addr = SocketAddr::new(ip, port);
        return Ok((addr, format_endpoint(host, port)));
    }
    
    // Otherwise resolve hostname
    let addr = format!("{}:{}", host, port);
    let sock = addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("Failed to resolve '{}:{}'", host, port))?;
    Ok((sock, format_endpoint(host, port)))
}

fn random_test_domain() -> String {
    let mut rng = rand::rng();
    let mut out = String::new();
    for _ in 0..12 {
        let n: u8 = rng.random_range(0..36);
        if n < 10 {
            out.push(char::from_digit(n as u32, 10).unwrap());
        } else {
            out.push(char::from_digit((n - 10 + 10) as u32, 36).unwrap());
        }
    }
    format!("{}.rustsploit.test", out)
}

fn prompt_default(message: &str, default: &str) -> Result<String> {
    print!("{} [{}]: ", message, default);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let inp = buf.trim();
    if inp.is_empty() { 
        Ok(default.into()) 
    } else { 
        Ok(inp.into()) 
    }
}

fn prompt_port(message: &str, default: u16) -> Result<u16> {
    print!("{} [{}]: ", message, default);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let inp = buf.trim();
    if inp.is_empty() { 
        Ok(default) 
    } else { 
        inp.parse::<u16>()
            .map_err(|e| anyhow!("Invalid port number: {}", e))
    }
}

fn prompt_line(message: &str) -> Result<String> {
    print!("{}: ", message);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().into())
}

fn prompt_yes_no(message: &str, default_yes: bool) -> Result<bool> {
    let def = if default_yes { "Y/n" } else { "y/N" };
    print!("{} [{}]: ", message, def);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let inp = buf.trim().to_lowercase();
    if inp.is_empty() { 
        Ok(default_yes) 
    } else { 
        Ok(inp == "y" || inp == "yes") 
    }
}

fn collect_targets(initial: &str) -> Result<Vec<TargetSpec>> {
    let mut out = Vec::new();
    for part in initial.split(&[',', ' ', '\n', '\t'][..]) {
        let trimmed = part.trim();
        if !trimmed.is_empty() {
            let (host, port) = split_host_port(trimmed)?;
            out.push(TargetSpec { host, port });
        }
    }
    Ok(out)
}

fn parse_targets_from_str(
    value: &str,
    out: &mut Vec<TargetSpec>,
) -> Result<()> {
    for token in value.split(&[',', ' ', '\n', '\t'][..]) {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            add_target_token(trimmed, out)?;
        }
    }
    Ok(())
}

fn parse_targets_from_file(
    path: &Path,
    out: &mut Vec<TargetSpec>,
) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("Failed to read file {}: {}", path.display(), e))?;
    
    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            add_target_token(trimmed, out)?;
        }
    }
    Ok(())
}

fn add_target_token(
    token: &str,
    targets: &mut Vec<TargetSpec>,
) -> Result<()> {
    let spec = parse_target_spec(token)?;
    targets.push(spec);
    Ok(())
}

fn parse_target_spec(token: &str) -> Result<TargetSpec> {
    let (host, port) = split_host_port(token)?;
    Ok(TargetSpec { host, port })
}

fn sanitize_target_input(input: &str) -> Result<String> {
    Ok(input.trim().to_string())
}

fn split_host_port(value: &str) -> Result<(String, Option<u16>)> {
    let trimmed = value.trim();
    if trimmed.contains(':') {
        let mut parts = trimmed.split(':');
        let host = parts.next()
            .ok_or_else(|| anyhow!("Invalid host:port format"))?
            .trim()
            .to_string();
        let port_str = parts.next()
            .ok_or_else(|| anyhow!("Invalid host:port format"))?
            .trim();
        let port = port_str.parse::<u16>()
            .map_err(|e| anyhow!("Invalid port number '{}': {}", port_str, e))?;
        Ok((host, Some(port)))
    } else {
        Ok((trimmed.to_string(), None))
    }
}

fn format_endpoint(host: &str, port: u16) -> String {
    format!("{}:{}", host, port)
}

fn validate_domain_input(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Domain name cannot be empty"));
    }
    if trimmed.len() > 253 {
        return Err(anyhow!("Domain name too long (max 253 characters)"));
    }
    Ok(trimmed.to_string())
}

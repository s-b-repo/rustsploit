use anyhow::{anyhow, Context, Result};
use colored::*;
use ipnet::IpNet;
use std::{
    collections::HashSet,
    fs::File,
    io::{self, BufRead, BufReader, Write},
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::{net::TcpStream, process::Command, sync::Semaphore, time::Duration};

#[derive(Clone, Debug)]
struct PingConfig {
    targets: Vec<IpNet>,
    methods: Vec<PingMethod>,
    concurrency: usize,
    timeout_secs: u64,
    verbose: bool,
}

#[derive(Clone, Debug)]
enum PingMethod {
    Icmp,
    Tcp { ports: Vec<u16> },
}

impl PingMethod {
    fn describe(&self) -> String {
        match self {
            PingMethod::Icmp => "ICMP".to_string(),
            PingMethod::Tcp { ports } => {
                if ports.len() == 1 {
                    format!("TCP/{}", ports[0])
                } else {
                    format!(
                        "TCP [{}]",
                        ports
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join(",")
                    )
                }
            }
        }
    }

    fn label(&self) -> &'static str {
        match self {
            PingMethod::Icmp => "ICMP",
            PingMethod::Tcp { .. } => "TCP",
        }
    }

    async fn probe(&self, ip: &IpAddr, timeout: Duration) -> Result<Vec<String>> {
        match self {
            PingMethod::Icmp => icmp_probe(ip, timeout).await,
            PingMethod::Tcp { ports } => tcp_probe(ip, ports, timeout).await,
        }
    }
}

/// Main entry point triggered via the dispatcher
pub async fn run(initial_target: &str) -> Result<()> {
    let config = gather_configuration(initial_target)?;
    execute_ping_sweep(&config).await
}

fn parse_target(input: &str) -> Result<IpNet> {
    if let Ok(net) = input.parse::<IpNet>() {
        return Ok(net);
    }

    if let Ok(ip) = input.parse::<IpAddr>() {
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let cidr = format!("{}/{}", ip, prefix);
        let net = cidr
            .parse::<IpNet>()
            .context("failed to convert host to /32 or /128 network")?;
        return Ok(net);
    }

    Err(anyhow!("Invalid target '{}'. Use IP or IP/CIDR.", input))
}

fn gather_configuration(initial: &str) -> Result<PingConfig> {
    println!("{}", "=== Ping Sweep Configuration ===".bold());

    let mut nets: Vec<IpNet> = Vec::new();

    let initial_trimmed = initial.trim();
    if !initial_trimmed.is_empty() {
        match parse_target(initial_trimmed) {
            Ok(net) => {
                println!(
                    "{}",
                    format!("[*] Loaded initial target {}", net).green()
                );
                nets.push(net);
            }
            Err(e) => {
                eprintln!(
                    "{}",
                    format!("    Initial target '{}' skipped: {}", initial_trimmed, e)
                        .yellow()
                );
            }
        }
    }

    if prompt_yes_no("Add additional targets manually?", false)? {
        loop {
            let entry = prompt_line(
                "Enter target (IP or CIDR, leave blank to stop): ",
                true,
            )?;
            if entry.is_empty() {
                break;
            }
            match parse_target(&entry) {
                Ok(net) => {
                    println!("{}", format!("    + {}", net).cyan());
                    nets.push(net);
                }
                Err(e) => {
                    eprintln!("{}", format!("    ! {}", e).red());
                }
            }
        }
    }

    if prompt_yes_no("Load targets from file?", false)? {
        let path = prompt_line("Path to file: ", false)?;
        let file_targets = load_targets_from_file(&path)?;
        if file_targets.is_empty() {
            println!("{}", "    No targets parsed from file.".yellow());
        } else {
            println!(
                "{}",
                format!(
                    "    Loaded {} targets from '{}'",
                    file_targets.len(),
                    path
                )
                .green()
            );
            nets.extend(file_targets);
        }
    }

    if nets.is_empty() {
        return Err(anyhow!(
            "No valid targets supplied. Provide at least one IP or subnet."
        ));
    }

    // Deduplicate targets
    let mut unique: HashSet<IpNet> = HashSet::new();
    for net in nets {
        unique.insert(net);
    }
    let targets: Vec<IpNet> = unique.into_iter().collect();

    let timeout_secs =
        prompt_u64("Probe timeout (seconds)", 3, Some(1), Some(60))?;
    let concurrency =
        prompt_usize("Max concurrent hosts", 100, Some(1), Some(10_000))?;
    let verbose = prompt_yes_no("Verbose output (show down hosts/errors)?", false)?;

    let methods = loop {
        let mut methods = Vec::new();

        if prompt_yes_no("Use ICMP ping (system ping/ping6)?", true)? {
            methods.push(PingMethod::Icmp);
        }

        if prompt_yes_no("Use TCP connect probes?", false)? {
            let default_ports = "80,443";
            let port_input =
                prompt_with_default("TCP ports (comma separated)", default_ports)?;
            let ports = parse_ports(&port_input)?;
            if ports.is_empty() {
                println!("{}", "    No valid ports provided.".yellow());
            } else {
                methods.push(PingMethod::Tcp { ports });
            }
        }

        if methods.is_empty() {
            println!("{}", "Select at least one method.".red().bold());
            continue;
        }
        break methods;
    };

    println!(
        "{}",
        format!(
            "\n[*] Targets: {} | Methods: {} | Concurrency: {} | Timeout: {}s",
            targets.len(),
            methods_summary(&methods),
            concurrency,
            timeout_secs
        )
        .bold()
    );

    Ok(PingConfig {
        targets,
        methods,
        concurrency,
        timeout_secs,
        verbose,
    })
}

fn load_targets_from_file(path: &str) -> Result<Vec<IpNet>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open target file '{}'", path))?;
    let reader = BufReader::new(file);
    let mut nets = Vec::new();

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let mut content = line.split('#').next().unwrap_or("").trim().to_string();
        if content.is_empty() {
            continue;
        }
        content = content.replace(',', " ");
        for token in content.split_whitespace() {
            match parse_target(token) {
                Ok(net) => nets.push(net),
                Err(e) => {
                    eprintln!(
                        "{}",
                        format!("    [file:{}] skipped '{}': {}", idx + 1, token, e)
                            .yellow()
                    );
                }
            }
        }
    }

    Ok(nets)
}

fn methods_summary(methods: &[PingMethod]) -> String {
    methods
        .iter()
        .map(PingMethod::describe)
        .collect::<Vec<_>>()
        .join(", ")
}

async fn execute_ping_sweep(config: &PingConfig) -> Result<()> {
    let mut host_set: HashSet<IpAddr> = HashSet::new();
    for net in &config.targets {
        for host in net.hosts() {
            host_set.insert(host);
        }
    }

    if host_set.is_empty() {
        println!("{}", "No host addresses derived from supplied targets.".yellow());
        return Ok(());
    }

    let mut hosts: Vec<IpAddr> = host_set.into_iter().collect();
    hosts.sort();

    let total_hosts = hosts.len();
    println!(
        "{}",
        format!(
            "\n[*] Beginning sweep of {} hosts using {} method(s)...",
            total_hosts,
            config.methods.len()
        )
        .bold()
    );

    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let methods = Arc::new(config.methods.clone());
    let timeout = Duration::from_secs(config.timeout_secs.max(1));
    let verbose = config.verbose;
    let success_counter = Arc::new(AtomicUsize::new(0));

    let processed_counter = Arc::new(AtomicUsize::new(0));
    let start_time = std::time::Instant::now();
    let mut tasks = Vec::new();
    
    for ip in hosts {
        let sem = semaphore.clone();
        let methods_clone = methods.clone();
        let success_clone = success_counter.clone();
        let processed_clone = processed_counter.clone();
        tasks.push(tokio::spawn(async move {
            let permit = match sem.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let ip_string = ip.to_string();
            let mut successes = Vec::new();

            for method in methods_clone.iter() {
                match method.probe(&ip, timeout).await {
                    Ok(mut labels) => successes.append(&mut labels),
                    Err(err) => {
                        if verbose {
                            eprintln!(
                                "{}",
                                format!(
                                    "[!] {} ({}) error: {}",
                                    ip_string,
                                    method.label(),
                                    err
                                )
                                .yellow()
                            );
                        }
                    }
                }
            }

            drop(permit);
            
            let processed = processed_clone.fetch_add(1, Ordering::Relaxed) + 1;
            
            // Progress indicator every 100 hosts or at completion
            if processed % 100 == 0 || processed == total_hosts {
                let elapsed = start_time.elapsed().as_secs();
                let rate = if elapsed > 0 { (processed as u64) / elapsed } else { 0 };
                print!(
                    "\r{}",
                    format!(
                        "[*] Progress: {}/{} hosts ({:.1}%) | Up: {} | Rate: {}/s",
                        processed,
                        total_hosts,
                        (processed as f64 / total_hosts as f64) * 100.0,
                        success_clone.load(Ordering::Relaxed),
                        rate
                    )
                    .dimmed()
                );
                io::stdout().flush().ok();
            }

            if !successes.is_empty() {
                success_clone.fetch_add(1, Ordering::Relaxed);
                println!(
                    "\r{}",
                    format!(
                        "[+] Host {} is up ({})",
                        ip_string,
                        successes.join(", ")
                    )
                    .green()
                );
            } else if verbose {
                println!("\r{}", format!("[-] Host {} is down", ip_string).dimmed());
            }
        }));
    }

    for task in tasks {
        let _ = task.await;
    }
    
    // Clear progress line
    print!("\r{}\r", " ".repeat(80));
    io::stdout().flush().ok();

    let up_hosts = success_counter.load(Ordering::Relaxed);
    println!(
        "{}",
        format!(
            "\n[*] Sweep complete: {}/{} hosts responded.",
            up_hosts, total_hosts
        )
        .bold()
    );

    Ok(())
}

async fn icmp_probe(ip: &IpAddr, timeout: Duration) -> Result<Vec<String>> {
    // Try to detect the OS and use appropriate ping command
    let wait_secs = timeout.as_secs().max(1).to_string();
    let ip_str = ip.to_string();
    
    let (cmd, args_vec) = if ip.is_ipv4() {
        // Try ping first, fallback to ping6 for IPv4 if ping doesn't exist
        if which::which("ping").is_ok() {
            ("ping", vec!["-c", "1", "-W", &wait_secs, &ip_str])
        } else if which::which("ping6").is_ok() {
            ("ping6", vec!["-c", "1", "-W", &wait_secs, &ip_str])
        } else {
            return Err(anyhow!("Neither 'ping' nor 'ping6' command found. Install ping utility."));
        }
    } else {
        // IPv6
        if which::which("ping6").is_ok() {
            ("ping6", vec!["-c", "1", "-W", &wait_secs, &ip_str])
        } else if which::which("ping").is_ok() {
            // Some systems use ping -6 for IPv6
            ("ping", vec!["-6", "-c", "1", "-W", &wait_secs, &ip_str])
        } else {
            return Err(anyhow!("Neither 'ping' nor 'ping6' command found. Install ping utility."));
        }
    };

    let result = tokio::time::timeout(
        timeout,
        Command::new(cmd)
            .args(args_vec)
            .output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => {
            if output.status.success() {
                Ok(vec!["ICMP".to_string()])
            } else {
                Ok(Vec::new())
            }
        }
        Ok(Err(err)) => Err(anyhow!("Ping command failed: {}", err)),
        Err(_) => Ok(Vec::new()),
    }
}

async fn tcp_probe(ip: &IpAddr, ports: &[u16], timeout: Duration) -> Result<Vec<String>> {
    // Probe ports in parallel for better performance
    let mut tasks = Vec::new();
    
    for port in ports {
        let ip = *ip;
        let port = *port;
        let timeout = timeout;
        
        tasks.push(tokio::spawn(async move {
            let socket = SocketAddr::new(ip, port);
            match tokio::time::timeout(timeout, TcpStream::connect(socket)).await {
                Ok(Ok(_stream)) => {
                    // Connection successful - drop stream immediately
                    Some(format!("TCP/{}", port))
                }
                Ok(Err(_)) => None,
                Err(_) => None,
            }
        }));
    }
    
    let mut successes = Vec::new();
    for task in tasks {
        if let Ok(Some(label)) = task.await {
            successes.push(label);
        }
    }
    
    Ok(successes)
}

fn prompt_line(message: &str, allow_empty: bool) -> Result<String> {
    print!("{}", message.cyan().bold());
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_string();
    if !allow_empty && trimmed.is_empty() {
        return Err(anyhow!("Input cannot be empty."));
    }
    Ok(trimmed)
}

fn prompt_with_default(message: &str, default: &str) -> Result<String> {
    print!(
        "{}",
        format!("{} [{}]: ", message, default).cyan().bold()
    );
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn prompt_yes_no(message: &str, default_yes: bool) -> Result<bool> {
    let default_hint = if default_yes { "Y/n" } else { "y/N" };
    loop {
        print!(
            "{}",
            format!("{} [{}]: ", message, default_hint).cyan().bold()
        );
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_lowercase();
        match trimmed.as_str() {
            "" => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("{}", "Please answer with 'y' or 'n'.".yellow()),
        }
    }
}

fn prompt_usize(
    message: &str,
    default: usize,
    min: Option<usize>,
    max: Option<usize>,
) -> Result<usize> {
    loop {
        let response = prompt_with_default(message, &default.to_string())?;
        match response.parse::<usize>() {
            Ok(value) => {
                if let Some(minimum) = min {
                    if value < minimum {
                        println!(
                            "{}",
                            format!("Value must be >= {}", minimum).yellow()
                        );
                        continue;
                    }
                }
                if let Some(maximum) = max {
                    if value > maximum {
                        println!(
                            "{}",
                            format!("Value must be <= {}", maximum).yellow()
                        );
                        continue;
                    }
                }
                return Ok(value);
            }
            Err(_) => println!("{}", "Enter a valid positive integer.".yellow()),
        }
    }
}

fn prompt_u64(
    message: &str,
    default: u64,
    min: Option<u64>,
    max: Option<u64>,
) -> Result<u64> {
    loop {
        let response = prompt_with_default(message, &default.to_string())?;
        match response.parse::<u64>() {
            Ok(value) => {
                if let Some(minimum) = min {
                    if value < minimum {
                        println!(
                            "{}",
                            format!("Value must be >= {}", minimum).yellow()
                        );
                        continue;
                    }
                }
                if let Some(maximum) = max {
                    if value > maximum {
                        println!(
                            "{}",
                            format!("Value must be <= {}", maximum).yellow()
                        );
                        continue;
                    }
                }
                return Ok(value);
            }
            Err(_) => println!("{}", "Enter a valid positive integer.".yellow()),
        }
    }
}

fn parse_ports(input: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for token in input.replace(',', " ").split_whitespace() {
        match token.parse::<u16>() {
            Ok(port) => ports.push(port),
            Err(_) => {
                println!(
                    "{}",
                    format!("    Skipping invalid port '{}'", token).yellow()
                );
            }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

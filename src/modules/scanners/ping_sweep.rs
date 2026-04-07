use anyhow::{anyhow, Context, Result};
use colored::*;
use ipnetwork::IpNetwork;
use libc;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{self, MutableIpv4Packet};
use pnet_packet::tcp::{self, MutableTcpPacket, TcpFlags};
use pnet_packet::Packet;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tokio::{net::TcpStream, process::Command, sync::Semaphore, task, time::Duration};

use rand::RngExt;
use std::io::Read;
use crate::utils::{
    cfg_prompt_yes_no, cfg_prompt_default, cfg_prompt_int_range,
};

#[derive(Clone, Debug)]
struct PingConfig {
    targets: Vec<IpNetwork>,
    methods: Vec<PingMethod>,
    concurrency: usize,
    timeout_secs: u64,
    verbose: bool,
    save_up_hosts: Option<String>,
    save_down_hosts: Option<String>,
}

#[derive(Clone, Debug)]
enum PingMethod {
    Icmp,
    Tcp { ports: Vec<u16> },
    Syn { ports: Vec<u16> },
    Ack { ports: Vec<u16> },
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
            PingMethod::Syn { ports } => {
                if ports.len() == 1 {
                    format!("SYN/{}", ports[0])
                } else {
                    format!(
                        "SYN [{}]",
                        ports
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join(",")
                    )
                }
            }
            PingMethod::Ack { ports } => {
                if ports.len() == 1 {
                    format!("ACK/{}", ports[0])
                } else {
                    format!(
                        "ACK [{}]",
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
            PingMethod::Syn { .. } => "SYN",
            PingMethod::Ack { .. } => "ACK",
        }
    }

    async fn probe(&self, ip: &IpAddr, timeout: Duration) -> Result<Vec<String>> {
        match self {
            PingMethod::Icmp => icmp_probe(ip, timeout).await,
            PingMethod::Tcp { ports } => tcp_probe(ip, ports, timeout).await,
            PingMethod::Syn { ports } => syn_probe(ip, ports, timeout).await,
            PingMethod::Ack { ports } => ack_probe(ip, ports, timeout).await,
        }
    }
}

/// Main entry point triggered via the dispatcher
pub async fn run(initial_target: &str) -> Result<()> {
    let config = gather_configuration(initial_target).await?;
    execute_ping_sweep(&config).await
}

fn parse_target(input: &str) -> Result<IpNetwork> {
    if let Ok(net) = input.parse::<IpNetwork>() {
        return Ok(net);
    }

    if let Ok(ip) = input.parse::<IpAddr>() {
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let cidr = format!("{}/{}", ip, prefix);
        let net = cidr
            .parse::<IpNetwork>()
            .context("failed to convert host to /32 or /128 network")?;
        return Ok(net);
    }

    Err(anyhow!("Invalid target '{}'. Use IP or IP/CIDR.", input))
}

async fn gather_configuration(initial: &str) -> Result<PingConfig> {
    crate::mprintln!("{}", "=== Ping Sweep Configuration ===".bold());

    let mut nets: Vec<IpNetwork> = Vec::new();

    let initial_trimmed = initial.trim();
    if !initial_trimmed.is_empty() {
        match parse_target(initial_trimmed) {
            Ok(net) => {
                crate::mprintln!(
                    "{}",
                    format!("[*] Loaded initial target {}", net).green()
                );
                nets.push(net);
            }
            Err(e) => {
                crate::meprintln!(
                    "{}",
                    format!("    Initial target '{}' skipped: {}", initial_trimmed, e)
                        .yellow()
                );
            }
        }
    }

    if cfg_prompt_yes_no("add_manual_targets", "Add additional targets manually?", false).await? {
        loop {
            let entry = cfg_prompt_default("manual_target", "Enter target (IP or CIDR, leave blank to stop)", "").await?;
            if entry.is_empty() {
                break;
            }
            match parse_target(&entry) {
                Ok(net) => {
                    crate::mprintln!("{}", format!("    + {}", net).cyan());
                    nets.push(net);
                }
                Err(e) => {
                    crate::meprintln!("{}", format!("    ! {}", e).red());
                }
            }
        }
    }

    if cfg_prompt_yes_no("load_from_file", "Load targets from file?", false).await? {
        let path = cfg_prompt_default("target_file", "Path to file", "").await?;
        if !path.is_empty() {
            let file_targets = load_targets_from_file(&path)?;
            if file_targets.is_empty() {
                crate::mprintln!("{}", "    No targets parsed from file.".yellow());
            } else {
                crate::mprintln!(
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
    }

    if nets.is_empty() {
        return Err(anyhow!(
            "No valid targets supplied. Provide at least one IP or subnet."
        ));
    }

    // Deduplicate targets
    let mut unique: HashSet<IpNetwork> = HashSet::new();
    for net in nets {
        unique.insert(net);
    }
    let targets: Vec<IpNetwork> = unique.into_iter().collect();

    let timeout_secs =
        cfg_prompt_int_range("timeout", "Probe timeout (seconds)", 3, 1, 60).await? as u64;
    let concurrency =
        cfg_prompt_int_range("concurrency", "Max concurrent hosts", 100, 1, 10000).await? as usize;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose output (show down hosts/errors)?", false).await?;

    // Ask about saving results
    let save_up_hosts = if cfg_prompt_yes_no("save_up_hosts", "Save up hosts to file?", false).await? {
        let default_file = "ping_sweep_up_hosts.txt";
        let file_path = cfg_prompt_default("up_hosts_file", "Output file for up hosts", default_file).await?;
        Some(file_path)
    } else {
        None
    };

    let save_down_hosts = if cfg_prompt_yes_no("save_down_hosts", "Save down hosts to file?", false).await? {
        let default_file = "ping_sweep_down_hosts.txt";
        let file_path = cfg_prompt_default("down_hosts_file", "Output file for down hosts", default_file).await?;
        Some(file_path)
    } else {
        None
    };

    let methods = loop {
        let mut methods = Vec::new();

        if cfg_prompt_yes_no("use_icmp", "Use ICMP ping (system ping/ping6)?", true).await? {
            methods.push(PingMethod::Icmp);
        }

        if cfg_prompt_yes_no("use_tcp", "Use TCP connect probes?", false).await? {
            let default_ports = "80,443";
            let port_input =
                cfg_prompt_default("tcp_ports", "TCP ports (comma separated)", default_ports).await?;
            let ports = parse_ports(&port_input)?;
            if ports.is_empty() {
                crate::mprintln!("{}", "    No valid ports provided.".yellow());
            } else {
                methods.push(PingMethod::Tcp { ports });
            }
        }

        if cfg_prompt_yes_no("use_syn", "Use SYN scan (stealth scan, requires root)?", false).await? {
            let default_ports = "80,443";
            let port_input =
                cfg_prompt_default("syn_ports", "TCP ports for SYN scan (comma separated)", default_ports).await?;
            let ports = parse_ports(&port_input)?;
            if ports.is_empty() {
                crate::mprintln!("{}", "    No valid ports provided.".yellow());
            } else {
                methods.push(PingMethod::Syn { ports });
            }
        }

        if cfg_prompt_yes_no("use_ack", "Use ACK scan (filter detection, requires root)?", false).await? {
            let default_ports = "80,443";
            let port_input =
                cfg_prompt_default("ack_ports", "TCP ports for ACK scan (comma separated)", default_ports).await?;
            let ports = parse_ports(&port_input)?;
            if ports.is_empty() {
                crate::mprintln!("{}", "    No valid ports provided.".yellow());
            } else {
                methods.push(PingMethod::Ack { ports });
            }
        }

        if methods.is_empty() {
            crate::mprintln!("{}", "Select at least one method.".red().bold());
            continue;
        }
        break methods;
    };

    crate::mprintln!(
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
        save_up_hosts,
        save_down_hosts,
    })
}

fn load_targets_from_file(path: &str) -> Result<Vec<IpNetwork>> {
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
                    crate::meprintln!(
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
        for host in net.iter() {
            host_set.insert(host);
        }
    }

    if host_set.is_empty() {
        crate::mprintln!("{}", "No host addresses derived from supplied targets.".yellow());
        return Ok(());
    }

    let mut hosts: Vec<IpAddr> = host_set.into_iter().collect();
    hosts.sort();

    let total_hosts = hosts.len();
    crate::mprintln!(
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
    
    // Collections for saving results
    let up_hosts_list = Arc::new(Mutex::new(Vec::<String>::new()));
    let down_hosts_list = Arc::new(Mutex::new(Vec::<String>::new()));
    
    let mut tasks = Vec::new();
    
    for ip in hosts {
        let sem = semaphore.clone();
        let methods_clone = methods.clone();
        let success_clone = success_counter.clone();
        let processed_clone = processed_counter.clone();
        let up_list = up_hosts_list.clone();
        let down_list = down_hosts_list.clone();
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
                            crate::meprintln!(
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
                crate::mprint!(
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
                if let Err(e) = std::io::Write::flush(&mut std::io::stdout()) { eprintln!("[!] Flush error: {}", e); }
            }

            if !successes.is_empty() {
                success_clone.fetch_add(1, Ordering::Relaxed);
                crate::mprintln!(
                    "\r{}",
                    format!(
                        "[+] Host {} is up ({})",
                        ip_string,
                        successes.join(", ")
                    )
                    .green()
                );
                // Add to up hosts list
                if let Ok(mut list) = up_list.lock() {
                    list.push(ip_string.clone());
                }
            } else {
                // Add to down hosts list
                if let Ok(mut list) = down_list.lock() {
                    list.push(ip_string.clone());
                }
                if verbose {
                    crate::mprintln!("\r{}", format!("[-] Host {} is down", ip_string).dimmed());
                }
            }
        }));
    }

    for task in tasks {
        if let Err(e) = task.await { crate::meprintln!("[!] Task error: {}", e); }
    }
    
    // Clear progress line
    crate::mprint!("\r{}\r", " ".repeat(80));
    if let Err(e) = std::io::Write::flush(&mut std::io::stdout()) { eprintln!("[!] Flush error: {}", e); }

    let up_hosts = success_counter.load(Ordering::Relaxed);
    crate::mprintln!(
        "{}",
        format!(
            "\n[*] Sweep complete: {}/{} hosts responded.",
            up_hosts, total_hosts
        )
        .bold()
    );

    // Save results to files if requested
    if let Some(ref up_file) = config.save_up_hosts {
        let up_list = up_hosts_list.lock().unwrap_or_else(|e| e.into_inner());
        if !up_list.is_empty() {
            match save_hosts_to_file(&up_list, up_file) {
                Ok(_) => {
                    crate::mprintln!("{}", format!("[+] Saved {} up hosts to '{}'", up_list.len(), up_file).green());
                }
                Err(e) => {
                    crate::meprintln!("{}", format!("[!] Failed to save up hosts to '{}': {}", up_file, e).red());
                }
            }
        } else {
            crate::mprintln!("{}", format!("[*] No up hosts to save to '{}'", up_file).yellow());
        }
    }

    if let Some(ref down_file) = config.save_down_hosts {
        let down_list = down_hosts_list.lock().unwrap_or_else(|e| e.into_inner());
        if !down_list.is_empty() {
            match save_hosts_to_file(&down_list, down_file) {
                Ok(_) => {
                    crate::mprintln!("{}", format!("[+] Saved {} down hosts to '{}'", down_list.len(), down_file).green());
                }
                Err(e) => {
                    crate::meprintln!("{}", format!("[!] Failed to save down hosts to '{}': {}", down_file, e).red());
                }
            }
        } else {
            crate::mprintln!("{}", format!("[*] No down hosts to save to '{}'", down_file).yellow());
        }
    }

    Ok(())
}

fn save_hosts_to_file(hosts: &[String], file_path: &str) -> Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(file_path)
        .with_context(|| format!("Failed to create file '{}'", file_path))?;
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(file_path, std::fs::Permissions::from_mode(0o600)) {
        crate::meprintln!("[!] Permission error on {}: {}", file_path, e);
    }

    for host in hosts {
        writeln!(file, "{}", host)
            .with_context(|| format!("Failed to write to file '{}'", file_path))?;
    }
    
    file.flush()
        .with_context(|| format!("Failed to flush file '{}'", file_path))?;
    
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

async fn syn_probe(ip: &IpAddr, ports: &[u16], timeout: Duration) -> Result<Vec<String>> {
    // SYN scan only works with IPv4
    let ipv4 = match ip {
        IpAddr::V4(addr) => *addr,
        IpAddr::V6(_) => {
            return Err(anyhow!("SYN scan only supports IPv4 addresses"));
        }
    };

    let mut successes = Vec::new();
    
    for port in ports {
        match syn_probe_single(&ipv4, *port, timeout).await {
            Ok(true) => successes.push(format!("SYN/{}", port)),
            Ok(false) => {}
            Err(e) => {
                // Silently continue on errors (permission denied, etc.)
                if e.to_string().contains("Permission denied") {
                    return Err(anyhow!("SYN scan requires root privileges. Run with sudo or use TCP connect scan instead."));
                }
            }
        }
    }
    
    Ok(successes)
}

async fn syn_probe_single(ip: &Ipv4Addr, port: u16, timeout: Duration) -> Result<bool> {
    use std::net::Ipv4Addr as StdIpv4Addr;
    use std::net::IpAddr as StdIpAddr;
    
    // Create raw socket for sending
    let sender = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(libc::IPPROTO_RAW)),
    )
    .context("Failed to create raw socket for SYN scan")?;
    
    sender
        .set_header_included_v4(true)
        .context("Failed to set IP_HDRINCL")?;
    
    // Create raw socket for receiving TCP responses
    let receiver = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::TCP),
    )
    .context("Failed to create receiver socket for SYN scan")?;
    
    receiver
        .set_read_timeout(Some(timeout))
        .context("Failed to set read timeout")?;
    
    // Get source IP (use a dummy IP if we can't determine it)
    let src_ip = get_local_ipv4().unwrap_or_else(|| Ipv4Addr::new(127, 0, 0, 1));
    
    // Craft SYN packet - generate all random values before any await
    let (src_port, seq_num, ip_id) = {
        let mut rng = rand::rng();
        (
            rng.random_range(49152..=65535),
            rng.random::<u32>(),
            rng.random::<u16>(),
        )
    };
    
    let tcp_header_len = 20;
    let mut tcp_buf = vec![0u8; tcp_header_len];
    let mut tcp_pkt = MutableTcpPacket::new(&mut tcp_buf).ok_or_else(|| anyhow!("Failed to create TCP packet"))?;
    tcp_pkt.set_source(src_port);
    tcp_pkt.set_destination(port);
    tcp_pkt.set_sequence(seq_num);
    tcp_pkt.set_acknowledgement(0);
    tcp_pkt.set_data_offset(5);
    tcp_pkt.set_flags(TcpFlags::SYN);
    tcp_pkt.set_window(65535);
    tcp_pkt.set_urgent_ptr(0);
    
    let tcp_immutable = tcp_pkt.to_immutable();
    tcp_pkt.set_checksum(tcp::ipv4_checksum(&tcp_immutable, &src_ip, ip));
    
    // Craft IP packet
    const IPV4_HEADER_LEN: usize = 20;
    let total_len = (IPV4_HEADER_LEN + tcp_header_len) as u16;
    let mut ip_buf = vec![0u8; total_len as usize];
    let mut ip_pkt = MutableIpv4Packet::new(&mut ip_buf).ok_or_else(|| anyhow!("Failed to create IP packet"))?;
    ip_pkt.set_version(4);
    ip_pkt.set_header_length(5);
    ip_pkt.set_total_length(total_len);
    ip_pkt.set_identification(ip_id);
    ip_pkt.set_ttl(64);
    ip_pkt.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_pkt.set_source(src_ip);
    ip_pkt.set_destination(*ip);
    ip_pkt.set_flags(ipv4::Ipv4Flags::DontFragment);
    ip_pkt.set_payload(tcp_pkt.packet());
    ip_pkt.set_checksum(ipv4::checksum(&ip_pkt.to_immutable()));
    
    // Send packet (blocking operation)
    let dst_addr = SocketAddr::new(StdIpAddr::V4(StdIpv4Addr::from(*ip)), 0);
    sender
        .send_to(ip_pkt.packet(), &dst_addr.into())
        .context("Failed to send SYN packet")?;
    
    // Listen for response using spawn_blocking for async compatibility
    let receiver_arc = Arc::new(receiver);
    let start = std::time::Instant::now();
    
    while start.elapsed() < timeout {
        let sock_clone = receiver_arc.try_clone().map_err(|e| anyhow!("Failed to clone socket: {}", e))?;
        let ip_clone = *ip;
        let port_clone = port;
        let src_ip_clone = src_ip;
        let src_port_clone = src_port;
        
        let recv_result = task::spawn_blocking(move || -> Result<Option<Vec<u8>>, std::io::Error> {
            let mut buf = [0u8; 1500];
            let mut sock = sock_clone;
            match Read::read(&mut sock, &mut buf) {
                Ok(len) => Ok(Some(buf[..len].to_vec())),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await
        .context("Blocking task for recv failed")?;
        
        match recv_result {
            Ok(Some(data)) => {
                if data.len() < IPV4_HEADER_LEN {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
                
                // Parse IP header
                if let Some(ip_recv) = ipv4::Ipv4Packet::new(&data) {
                    if ip_recv.get_source() == ip_clone && ip_recv.get_destination() == src_ip_clone {
                        // Parse TCP header
                        let tcp_offset = (ip_recv.get_header_length() as usize) * 4;
                        if data.len() >= tcp_offset + 20 {
                            if let Some(tcp_recv) = tcp::TcpPacket::new(&data[tcp_offset..]) {
                                if tcp_recv.get_source() == port_clone && tcp_recv.get_destination() == src_port_clone {
                                    let flags = tcp_recv.get_flags();
                                    // SYN-ACK means port is open
                                    if flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
                                        return Ok(true);
                                    }
                                    // RST means port is closed but host is up
                                    if flags & TcpFlags::RST == TcpFlags::RST {
                                        return Ok(true); // Host is up
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(None) => {
                // Timeout or would block - continue waiting
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
    
    Ok(false)
}

async fn ack_probe(ip: &IpAddr, ports: &[u16], timeout: Duration) -> Result<Vec<String>> {
    // ACK scan only works with IPv4
    let ipv4 = match ip {
        IpAddr::V4(addr) => *addr,
        IpAddr::V6(_) => {
            return Err(anyhow!("ACK scan only supports IPv4 addresses"));
        }
    };

    let mut successes = Vec::new();
    
    for port in ports {
        match ack_probe_single(&ipv4, *port, timeout).await {
            Ok(true) => successes.push(format!("ACK/{}", port)),
            Ok(false) => {}
            Err(e) => {
                // Silently continue on errors (permission denied, etc.)
                if e.to_string().contains("Permission denied") {
                    return Err(anyhow!("ACK scan requires root privileges. Run with sudo or use TCP connect scan instead."));
                }
            }
        }
    }
    
    Ok(successes)
}

async fn ack_probe_single(ip: &Ipv4Addr, port: u16, timeout: Duration) -> Result<bool> {
    use std::net::Ipv4Addr as StdIpv4Addr;
    use std::net::IpAddr as StdIpAddr;
    
    // Create raw socket for sending
    let sender = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(libc::IPPROTO_RAW)),
    )
    .context("Failed to create raw socket for ACK scan")?;
    
    sender
        .set_header_included_v4(true)
        .context("Failed to set IP_HDRINCL")?;
    
    // Create raw socket for receiving TCP responses
    let receiver = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::TCP),
    )
    .context("Failed to create receiver socket for ACK scan")?;
    
    receiver
        .set_read_timeout(Some(timeout))
        .context("Failed to set read timeout")?;
    
    // Get source IP
    let src_ip = get_local_ipv4().unwrap_or_else(|| Ipv4Addr::new(127, 0, 0, 1));
    
    // Craft ACK packet - generate all random values before any await
    let (src_port, seq_num, ip_id) = {
        let mut rng = rand::rng();
        (
            rng.random_range(49152..=65535),
            rng.random::<u32>(),
            rng.random::<u16>(),
        )
    };
    
    let tcp_header_len = 20;
    let mut tcp_buf = vec![0u8; tcp_header_len];
    let mut tcp_pkt = MutableTcpPacket::new(&mut tcp_buf).ok_or_else(|| anyhow!("Failed to create TCP packet"))?;
    tcp_pkt.set_source(src_port);
    tcp_pkt.set_destination(port);
    tcp_pkt.set_sequence(seq_num);
    tcp_pkt.set_acknowledgement(0);
    tcp_pkt.set_data_offset(5);
    tcp_pkt.set_flags(TcpFlags::ACK);
    tcp_pkt.set_window(65535);
    tcp_pkt.set_urgent_ptr(0);
    
    let tcp_immutable = tcp_pkt.to_immutable();
    tcp_pkt.set_checksum(tcp::ipv4_checksum(&tcp_immutable, &src_ip, ip));
    
    // Craft IP packet
    const IPV4_HEADER_LEN: usize = 20;
    let total_len = (IPV4_HEADER_LEN + tcp_header_len) as u16;
    let mut ip_buf = vec![0u8; total_len as usize];
    let mut ip_pkt = MutableIpv4Packet::new(&mut ip_buf).ok_or_else(|| anyhow!("Failed to create IP packet"))?;
    ip_pkt.set_version(4);
    ip_pkt.set_header_length(5);
    ip_pkt.set_total_length(total_len);
    ip_pkt.set_identification(ip_id);
    ip_pkt.set_ttl(64);
    ip_pkt.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_pkt.set_source(src_ip);
    ip_pkt.set_destination(*ip);
    ip_pkt.set_flags(ipv4::Ipv4Flags::DontFragment);
    ip_pkt.set_payload(tcp_pkt.packet());
    ip_pkt.set_checksum(ipv4::checksum(&ip_pkt.to_immutable()));
    
    // Send packet (blocking operation)
    let dst_addr = SocketAddr::new(StdIpAddr::V4(StdIpv4Addr::from(*ip)), 0);
    sender
        .send_to(ip_pkt.packet(), &dst_addr.into())
        .context("Failed to send ACK packet")?;
    
    // Listen for response using spawn_blocking for async compatibility
    let receiver_arc = Arc::new(receiver);
    let start = std::time::Instant::now();
    
    while start.elapsed() < timeout {
        let sock_clone = receiver_arc.try_clone().map_err(|e| anyhow!("Failed to clone socket: {}", e))?;
        let ip_clone = *ip;
        let port_clone = port;
        let src_ip_clone = src_ip;
        let src_port_clone = src_port;
        
        let recv_result = task::spawn_blocking(move || -> Result<Option<Vec<u8>>, std::io::Error> {
            let mut buf = [0u8; 1500];
            let mut sock = sock_clone;
            match Read::read(&mut sock, &mut buf) {
                Ok(len) => Ok(Some(buf[..len].to_vec())),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await
        .context("Blocking task for recv failed")?;
        
        match recv_result {
            Ok(Some(data)) => {
                if data.len() < IPV4_HEADER_LEN {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
                
                // Parse IP header
                if let Some(ip_recv) = ipv4::Ipv4Packet::new(&data) {
                    if ip_recv.get_source() == ip_clone && ip_recv.get_destination() == src_ip_clone {
                        // Parse TCP header
                        let tcp_offset = (ip_recv.get_header_length() as usize) * 4;
                        if data.len() >= tcp_offset + 20 {
                            if let Some(tcp_recv) = tcp::TcpPacket::new(&data[tcp_offset..]) {
                                if tcp_recv.get_source() == port_clone && tcp_recv.get_destination() == src_port_clone {
                                    let flags = tcp_recv.get_flags();
                                    // RST means port is unfiltered (host is up)
                                    if flags & TcpFlags::RST == TcpFlags::RST {
                                        return Ok(true);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(None) => {
                // Timeout or would block - continue waiting
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
    
    Ok(false)
}

fn get_local_ipv4() -> Option<Ipv4Addr> {
    // Robust implementation using pnet::datalink
    // logic: find first non-loopback, up, IPv4 interface
    use pnet::datalink;
    
    for iface in datalink::interfaces() {
        // Skip loopback and down interfaces
        if iface.is_loopback() || !iface.is_up() {
            continue;
        }
        
        for ip in iface.ips {
            if let IpAddr::V4(ipv4) = ip.ip() {
                // Return the first valid non-loopback IPv4
                return Some(ipv4);
            }
        }
    }
    
    // Fallback to UDP connection trick if pnet fails
    use std::net::UdpSocket;
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(local_addr) = socket.local_addr() {
                if let IpAddr::V4(ipv4) = local_addr.ip() {
                    return Some(ipv4);
                }
            }
        }
    }
    
    None
}

fn parse_ports(input: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for token in input.replace(',', " ").split_whitespace() {
        match token.parse::<u16>() {
            Ok(port) => ports.push(port),
            Err(_) => {
                crate::mprintln!(
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

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "ICMP Ping Sweep".to_string(),
        description: "Network host discovery via ICMP echo, TCP connect, SYN, and ACK probes with CIDR range support.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

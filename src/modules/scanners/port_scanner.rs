use anyhow::{Result, anyhow};
use colored::*;
use std::{
    fs::File,
    io::{Write, BufWriter},
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::Semaphore,
    time::{timeout, Duration},
};
use rand::{RngExt, rng};
use socket2::{Socket, Domain, Type, Protocol};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_int_range, cfg_prompt_yes_no, cfg_prompt_output_file,
};
use crate::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanMethod {
    TcpConnect,
    Udp,
    Both,
}

#[derive(Debug, Clone)]
pub struct ScanSettings {
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub show_only_open: bool,
    pub verbose: bool,
    pub scan_method: ScanMethod,
    pub output_file: String,
    pub port_range: PortRange,
    pub ttl: Option<u32>,
    pub data_length: Option<usize>,
    pub source_port: Option<u16>,
}

#[derive(Debug, Clone)]
pub enum PortRange {
    All,
    Custom { start: u16, end: u16 },
    Common,
    Top1000,
}

impl PortRange {
    fn get_ports(&self) -> Vec<u16> {
        match self {
            PortRange::All => (1..=65535).collect(),
            PortRange::Custom { start, end } => (*start..=*end).collect(),
            PortRange::Common => COMMON_PORTS.to_vec(),
            PortRange::Top1000 => (1..=1000).collect(),
        }
    }
}

// Common ports list
const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
];

// Service detection map
fn get_service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        111 => "RPC",
        135 => "MSRPC",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        993 => "IMAPS",
        995 => "POP3S",
        1723 => "PPTP",
        3306 => "MySQL",
        3389 => "RDP",
        5900 => "VNC",
        8080 => "HTTP-Proxy",
        _ => "",
    }
}

/// Interactive config prompt
pub async fn prompt_settings() -> Result<ScanSettings> {
    if !crate::utils::is_batch_mode() {
        crate::mprintln!("{}", "\n=== Port Scanner Configuration ===".cyan().bold());
    }
    
    // Port range selection
    let range_choice_str = cfg_prompt_default("port_range", "Port Range (1=All, 2=Common, 3=Top1000, 4=Custom)", "1").await?;
    let range_choice: usize = range_choice_str.parse().unwrap_or(1);
    let port_range = match range_choice {
        1 | 0 => PortRange::All,
        2 => PortRange::Common,
        3 => PortRange::Top1000,
        4 => {
            let start_val = cfg_prompt_int_range("port_start", "Start port", 1, 1, 65535).await? as usize;
            let end_val = cfg_prompt_int_range("port_end", "End port", 65535, 1, 65535).await? as usize;
            
            let start: u16 = start_val.try_into().map_err(|_| anyhow!("Invalid start port"))?;
            let end: u16 = end_val.try_into().map_err(|_| anyhow!("Invalid end port"))?;
            
            if start > end {
                return Err(anyhow!("Start port must be <= end port"));
            }
            PortRange::Custom { start, end }
        }
        _ => PortRange::All,
    };
    
    let ports = port_range.get_ports();
    crate::mprintln!("{}", format!("[*] Selected {} ports to scan", ports.len()).green());
    
    // Scan Method Selection
    let method_choice_str = cfg_prompt_default("scan_method", "Scan Method (1=TCP, 2=UDP, 3=Both)", "1").await?;
    let method_choice: usize = method_choice_str.parse().unwrap_or(1);
    let scan_method = match method_choice {
        2 => ScanMethod::Udp,
        3 => ScanMethod::Both,
        _ => ScanMethod::TcpConnect,
    };

    // Advanced Options
    let ttl = if cfg_prompt_yes_no("enable_ttl", "Enable custom TTL?", false).await? {
        Some(cfg_prompt_int_range("ttl", "TTL value", 64, 1, 255).await? as u32)
    } else {
        None
    };

    let source_port = if crate::utils::get_global_source_port().await.is_some() {
        // Use globally configured source port
        crate::utils::get_global_source_port().await
    } else if cfg_prompt_yes_no("enable_source_port", "Enable custom Source Port?", false).await? {
        Some(cfg_prompt_int_range("source_port", "Source Port", 12345, 1, 65535).await? as u16)
    } else {
        None
    };

    let data_length = if cfg_prompt_yes_no("enable_data_padding", "Enable garbage data / payload padding?", false).await? {
        Some(cfg_prompt_int_range("data_length", "Data length (bytes)", 0, 0, 65535).await? as usize)
    } else {
        None
    };

    Ok(ScanSettings {
        concurrency: cfg_prompt_int_range("concurrency", "Concurrency", 100, 1, 10000).await? as usize,
        timeout_secs: cfg_prompt_int_range("timeout", "Timeout (in seconds)", 3, 1, 120).await? as u64,
        show_only_open: cfg_prompt_yes_no("show_only_open", "Show only open ports?", true).await?,
        verbose: cfg_prompt_yes_no("verbose", "Verbose output?", false).await?,
        scan_method,
        output_file: cfg_prompt_output_file("output_file", "Output filename", "scan_results.txt").await?,
        port_range,
        ttl,
        source_port,
        data_length,
    })
}

/// Main entrypoint for interactive CLI mode
pub async fn run_interactive(target: &str) -> Result<()> {
    let settings = prompt_settings().await?;
    run_with_settings(
        target,
        settings.concurrency,
        settings.timeout_secs,
        settings.show_only_open,
        settings.verbose,
        settings.scan_method,
        &settings.output_file,
        settings.port_range,
        settings.ttl,
        settings.source_port,
        settings.data_length,
    )
    .await
}

pub async fn run(target: &str) -> Result<()> {
    if is_mass_scan_target(target) {
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "PortScan",
            default_port: 80,
            state_file: "port_scanner_mass_state.log",
            default_output: "port_scanner_mass_results.txt",
            default_concurrency: 500,
        }, move |ip, port| {
            async move {
                if crate::utils::tcp_port_open(ip, port, std::time::Duration::from_secs(3)).await {
                    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                    Some(format!("[{}] {}:{} PortScan open\n", ts, ip, port))
                } else {
                    None
                }
            }
        }).await;
    }

    run_interactive(target).await
}

/// === Core Scanner Logic ===
pub async fn run_with_settings(
    target: &str,
    concurrency: usize,
    timeout_secs: u64,
    _show_only_open: bool,
    verbose: bool,
    scan_method: ScanMethod,
    output_file: &str,
    port_range: PortRange,
    ttl: Option<u32>,
    source_port: Option<u16>,
    data_length: Option<usize>,
) -> Result<()> {
    let start_time = Instant::now();
    let (resolved_ip_str, resolved_ip) = resolve_target(target)?;
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let file = {
        let f = File::create(output_file)?;
        if let Err(e) = crate::utils::set_secure_permissions(output_file, 0o600) {
            crate::meprintln!("[!] Failed to chmod 0o600 on {}: {} — file may be world-readable", output_file, e);
        }
        Arc::new(Mutex::new(BufWriter::new(f)))
    };
    
    let ports = port_range.get_ports();
    let total_ports = ports.len() * (if scan_method == ScanMethod::Both { 2 } else { 1 });
    
    let stats = Arc::new(Mutex::new(ScanStats::new()));
    let progress = Arc::new(Mutex::new(ProgressTracker::new(total_ports)));
    
    let verbose = verbose; // capture for move into async tasks
    crate::mprintln!("\n{}", format!("[*] Starting scan for target: {} (resolved: {})", target, resolved_ip_str).cyan().bold());
    crate::mprintln!("{}", format!("[*] Scanning {} ports with concurrency: {}", total_ports, concurrency).cyan());
    writeln!(file.lock().unwrap_or_else(|e| e.into_inner()), "Port Scan Results for {} ({})\n", target, resolved_ip_str)?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    writeln!(file.lock().unwrap_or_else(|e| e.into_inner()), "Scan started at: {}\n", timestamp)?;

    // TCP Scan
    let mut tcp_tasks = vec![];
    
    if scan_method == ScanMethod::TcpConnect || scan_method == ScanMethod::Both {
        crate::mprintln!("{}", "\n[*] Starting TCP scan...".yellow());
        for port in &ports {
            let permit = semaphore.clone().acquire_owned().await?;
            let file = file.clone();
            let stats = stats.clone();
            let progress = progress.clone();
            let ip = resolved_ip;
            let ip_str = resolved_ip_str.clone();
            let port = *port;
            let verbose = verbose;

            let handle = tokio::spawn(async move {
                let _permit = permit;
                let result = scan_tcp(&ip, port, timeout_secs, ttl, source_port, data_length).await;
                
                let mut stats_guard = stats.lock().unwrap_or_else(|e| e.into_inner());
                let mut progress_guard = progress.lock().unwrap_or_else(|e| e.into_inner());
                
                if let Some((status, banner, service)) = result {
                    match status.as_str() {
                        "OPEN" => {
                            stats_guard.tcp_open += 1;
                            let service_name = if service.is_empty() { get_service_name(port) } else { &service };
                            let line = format!("[TCP] {}:{} ({}) => {}", ip_str, port, service_name, status.green());
                            
                            let output_line = if !banner.is_empty() {
                                format!("{} | Banner: {}", line, banner.trim().bright_black())
                            } else {
                                line
                            };
                            
                            let _ = writeln!(file.lock().unwrap_or_else(|e| e.into_inner()), "{}", output_line);
                            crate::mprintln!("{}", output_line);
                        }
                        "CLOSED" => {
                            stats_guard.tcp_closed += 1;
                            if verbose {
                                crate::mprintln!("  {} TCP {}:{} CLOSED", "✗".red(), ip_str, port);
                            }
                        }
                        "TIMEOUT" | "FILTERED" => {
                            stats_guard.tcp_filtered += 1;
                            if verbose {
                                crate::mprintln!("  {} TCP {}:{} FILTERED", "~".yellow(), ip_str, port);
                            }
                        }
                        _ => {} // ignore any other status variants
                    }
                }
                
                progress_guard.increment(&start_time);
                if progress_guard.should_print() {
                    progress_guard.print_progress();
                }
            });
            tcp_tasks.push(handle);
        }
    }

    // UDP Scan
    let mut udp_tasks = vec![];
    if scan_method == ScanMethod::Udp || scan_method == ScanMethod::Both {
        crate::mprintln!("{}", "\n[*] Starting UDP scan...".yellow());
        for port in &ports {
            let permit = semaphore.clone().acquire_owned().await?;
            let file = file.clone();
            let stats = stats.clone();
            let progress = progress.clone();
            let ip = resolved_ip;
            let ip_str = resolved_ip_str.clone();
            let port = *port;

            let handle = tokio::spawn(async move {
                let _permit = permit;
                let result = scan_udp(&ip, port, timeout_secs, ttl, source_port, data_length).await;
                
                let mut stats_guard = stats.lock().unwrap_or_else(|e| e.into_inner());
                let mut progress_guard = progress.lock().unwrap_or_else(|e| e.into_inner());
                
                if let Some(status) = result {
                    match status.as_str() {
                        "OPEN" => {
                            stats_guard.udp_open += 1;
                            let service_name = get_service_name(port);
                            let line = format!("[UDP] {}:{} ({}) => {}", ip_str, port, service_name, status.green());
                            
                            let _ = writeln!(file.lock().unwrap_or_else(|e| e.into_inner()), "{}", line);
                            crate::mprintln!("{}", line);
                        }
                        "CLOSED" => stats_guard.udp_closed += 1,
                        "FILTERED" => stats_guard.udp_filtered += 1,
                        _ => {}
                    }
                }
                
                progress_guard.increment(&start_time);
                if progress_guard.should_print() {
                    progress_guard.print_progress();
                }
            });
            udp_tasks.push(handle);
        }
    }

    // Await all tasks
    for task in tcp_tasks {
        let _ = task.await;
    }
    for task in udp_tasks {
        let _ = task.await;
    }

    let elapsed = start_time.elapsed();
    let stats = stats.lock().unwrap_or_else(|e| e.into_inner());
    
    // Print summary
    crate::mprintln!("\n{}", "=== Scan Summary ===".cyan().bold());
    crate::mprintln!("{}", format!("Scan duration: {:.2} seconds", elapsed.as_secs_f64()).green());
    crate::mprintln!("\n{}", "TCP Ports:".yellow());
    crate::mprintln!("  {} Open: {}", "✓".green(), stats.tcp_open.to_string().green().bold());
    crate::mprintln!("  {} Closed: {}", "✗".red(), stats.tcp_closed);
    crate::mprintln!("  {} Filtered/Timeout: {}", "~".yellow(), stats.tcp_filtered);
    
    if scan_method == ScanMethod::Udp || scan_method == ScanMethod::Both {
        crate::mprintln!("\n{}", "UDP Ports:".yellow());
        crate::mprintln!("  {} Open: {}", "✓".green(), stats.udp_open.to_string().green().bold());
        crate::mprintln!("  {} Closed: {}", "✗".red(), stats.udp_closed);
        crate::mprintln!("  {} Filtered: {}", "~".yellow(), stats.udp_filtered);
    }
    
    crate::mprintln!("\n{}", format!("[*] Results saved to {}", output_file).cyan());
    
    // Write summary to file
    writeln!(file.lock().unwrap_or_else(|e| e.into_inner()), "\n=== Scan Summary ===")?;
    writeln!(file.lock().unwrap_or_else(|e| e.into_inner()), "Scan duration: {:.2} seconds", elapsed.as_secs_f64())?;
    writeln!(file.lock().unwrap_or_else(|e| e.into_inner()), "\nTCP Ports:")?;
    writeln!(file.lock().unwrap_or_else(|e| e.into_inner()), "  Open: {}", stats.tcp_open)?;
    writeln!(file.lock().unwrap_or_else(|e| e.into_inner()), "  Closed: {}", stats.tcp_closed)?;
    writeln!(file.lock().unwrap_or_else(|e| e.into_inner()), "  Filtered/Timeout: {}", stats.tcp_filtered)?;
    if scan_method == ScanMethod::Udp || scan_method == ScanMethod::Both {
        writeln!(file.lock().unwrap_or_else(|e| e.into_inner()), "\nUDP Ports:")?;
        writeln!(file.lock().unwrap_or_else(|e| e.into_inner()), "  Open: {}", stats.udp_open)?;
        writeln!(file.lock().unwrap_or_else(|e| e.into_inner()), "  Closed: {}", stats.udp_closed)?;
        writeln!(file.lock().unwrap_or_else(|e| e.into_inner()), "  Filtered: {}", stats.udp_filtered)?;
    }
    
    Ok(())
}

/// === TCP Port Scanner with Enhanced Banner Grabbing ===
async fn scan_tcp(
    ip: &std::net::IpAddr, 
    port: u16, 
    timeout_secs: u64,
    ttl: Option<u32>,
    source_port: Option<u16>,
    data_length: Option<usize>
) -> Option<(String, String, String)> {
    let addr = SocketAddr::new(*ip, port);
    
    // Create socket using socket2
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = match Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) {
        Ok(s) => s,
        Err(_) => return Some(("ERROR".into(), "".into(), "".into())),
    };
    
    // Set options
    if let Some(ttl_val) = ttl {
        if domain == Domain::IPV4 {
            let _ = socket.set_ttl_v4(ttl_val);
        } else {
            let _ = socket.set_unicast_hops_v6(ttl_val);
        }
    }
    
    let _ = socket.set_nonblocking(true);
    let _ = socket.set_tcp_nodelay(true);

    // Bind to custom source port if configured
    if let Some(src_port) = source_port {
        let bind_addr = if addr.is_ipv4() {
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), src_port)
        } else {
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), src_port)
        };
        let _ = socket.bind(&bind_addr.into());
    }

    // Connect (non-blocking). On Linux EINPROGRESS is the expected "in progress"
    // signal; modern Rust maps it to ErrorKind::InProgress, which does NOT
    // match WouldBlock — whitelist it explicitly.
    let connect_res = socket.connect(&addr.into());
    match connect_res {
        Ok(_) => {},
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {},
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {},
        Err(_) => return Some(("CLOSED".into(), "".into(), "".into())),
    }

    // Convert to Tokio TcpStream
    let std_stream: std::net::TcpStream = socket.into();
    let stream_res = TcpStream::from_std(std_stream);
    
    match stream_res {
        Ok(mut stream) => {
            // Wait for connection to complete
            if let Ok(_) = timeout(Duration::from_secs(timeout_secs), stream.writable()).await {
                // Check for socket error
                if let Ok(None) = stream.take_error() {
                    // Send garbage data if configured
                    if let Some(len) = data_length {
                        if len > 0 {
                            let payload: Vec<u8> = {
                                let mut rng = rng();
                                (0..len).map(|_| rng.random()).collect()
                            };
                            if stream.write_all(&payload).await.is_err() {
                                // Probe write failed — proceed to banner grab anyway
                            }
                        }
                    }
                    
                    // Try service-specific probes
                    let (banner, service) = grab_banner(&mut stream, port).await;
                    Some(("OPEN".into(), banner, service))
                } else {
                    Some(("CLOSED".into(), "".into(), "".into()))
                }
            } else {
                Some(("TIMEOUT".into(), "".into(), "".into()))
            }
        }
        Err(_) => Some(("CLOSED".into(), "".into(), "".into())),
    }
}

/// Enhanced banner grabbing with service-specific probes
async fn grab_banner(stream: &mut TcpStream, port: u16) -> (String, String) {
    let mut buf = [0u8; 2048];
    
    // Try to read initial banner (works for FTP, SMTP, POP3, etc.)
    match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
            let service = detect_service_from_banner(&banner, port);
            return (banner, service);
        }
        _ => {}
    }
    
    // Service-specific probes
    match port {
        80 | 8080 => {
            // HTTP probe
            if let Ok(_) = stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await {
                if let Ok(Ok(n)) = timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
                    if n > 0 {
                        let response = String::from_utf8_lossy(&buf[..n]);
                        if let Some(server) = extract_http_server(&response) {
                            return (response.trim().to_string(), format!("HTTP ({})", server));
                        }
                        return (response.trim().to_string(), "HTTP".into());
                    }
                }
            }
        }
        443 => {
            // HTTPS - can't easily probe without TLS, just return empty
            return ("".into(), "HTTPS".into());
        }
        22 => {
            // SSH - read SSH banner
            if let Ok(Ok(n)) = timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
                if n > 0 {
                    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                    return (banner, "SSH".into());
                }
            }
        }
        _ => {
            // Try reading again for other services
            if let Ok(Ok(n)) = timeout(Duration::from_secs(1), stream.read(&mut buf)).await {
                if n > 0 {
                    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                    let service = detect_service_from_banner(&banner, port);
                    return (banner, service);
                }
            }
        }
    }
    
    ("".into(), "".into())
}

fn detect_service_from_banner(banner: &str, port: u16) -> String {
    let banner_lower = banner.to_lowercase();
    
    if banner_lower.contains("ssh") {
        "SSH".into()
    } else if banner_lower.contains("ftp") {
        "FTP".into()
    } else if banner_lower.contains("smtp") {
        "SMTP".into()
    } else if banner_lower.contains("pop3") {
        "POP3".into()
    } else if banner_lower.contains("imap") {
        "IMAP".into()
    } else if banner_lower.contains("http") {
        "HTTP".into()
    } else if banner_lower.contains("mysql") {
        "MySQL".into()
    } else {
        get_service_name(port).to_string()
    }
}

fn extract_http_server(response: &str) -> Option<String> {
    for line in response.lines() {
        if line.to_lowercase().starts_with("server:") {
            return Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
        }
    }
    None
}

/// === UDP Port Scanner ===
async fn scan_udp(
    ip: &std::net::IpAddr, 
    port: u16, 
    timeout_secs: u64,
    ttl: Option<u32>,
    source_port: Option<u16>,
    data_length: Option<usize>
) -> Option<String> {
    // Bind address (source port logic)
    let sock = if let Some(src_port) = source_port {
        let bind_addr = if ip.is_ipv4() {
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), src_port)
        } else {
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), src_port)
        };
        match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(_) => return Some("ERROR".into()),
        }
    } else {
        match crate::utils::udp_bind(None).await {
            Ok(s) => s,
            Err(_) => return Some("ERROR".into()),
        }
    };
    
    // Set TTL if configured
    if let Some(ttl_val) = ttl {
        let _ = sock.set_ttl(ttl_val);
    }

    let target = SocketAddr::new(*ip, port);
    
    // Payload generation
    let payload = if let Some(len) = data_length {
        if len > 0 {
            let mut rng = rng();
            (0..len).map(|_| rng.random()).collect()
        } else {
            b"\x00\x00\x10\x10".to_vec()
        }
    } else {
        b"\x00\x00\x10\x10".to_vec()
    };
    
    let _ = sock.send_to(&payload, target).await;
    
    let mut buf = [0u8; 1500];
    match timeout(Duration::from_secs(timeout_secs), sock.recv_from(&mut buf)).await {
        Ok(Ok((_len, _src))) => Some("OPEN".into()),
        Ok(Err(_)) => Some("CLOSED".into()),
        Err(_) => Some("FILTERED".into()),
    }
}

/// === Target Resolution ===
fn resolve_target(input: &str) -> Result<(String, std::net::IpAddr)> {
    let cleaned = input.trim().trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<_> = (cleaned, 0).to_socket_addrs()?.collect();
    if let Some(addr) = addrs.iter().find(|a| a.is_ipv4()) {
        Ok((addr.ip().to_string(), addr.ip()))
    } else if let Some(addr) = addrs.first() {
        Ok((addr.ip().to_string(), addr.ip()))
    } else {
        Err(anyhow!("Could not resolve target '{}'", input))
    }
}

/// === Scan Statistics ===
struct ScanStats {
    tcp_open: usize,
    tcp_closed: usize,
    tcp_filtered: usize,
    udp_open: usize,
    udp_closed: usize,
    udp_filtered: usize,
}

impl ScanStats {
    fn new() -> Self {
        ScanStats {
            tcp_open: 0,
            tcp_closed: 0,
            tcp_filtered: 0,
            udp_open: 0,
            udp_closed: 0,
            udp_filtered: 0,
        }
    }
}

/// === Progress Tracker ===
struct ProgressTracker {
    total: usize,
    current: usize,
    last_print: usize,
    start_time: Option<Instant>,
}

impl ProgressTracker {
    fn new(total: usize) -> Self {
        ProgressTracker {
            total,
            current: 0,
            last_print: 0,
            start_time: None,
        }
    }
    
    fn increment(&mut self, start_time: &Instant) {
        if self.start_time.is_none() {
            self.start_time = Some(*start_time);
        }
        self.current += 1;
    }
    
    fn should_print(&self) -> bool {
        let diff = self.current - self.last_print;
        diff >= 100 || self.current == self.total
    }
    
    fn print_progress(&mut self) {
        if self.current == 0 {
            return;
        }
        
        let percentage = (self.current as f64 / self.total as f64) * 100.0;
        let elapsed = match self.start_time {
            Some(s) => s.elapsed(),
            None => std::time::Duration::ZERO,
        };
        
        let rate = if elapsed.as_secs() > 0 {
            self.current as f64 / elapsed.as_secs() as f64
        } else {
            0.0
        };
        
        let remaining = if rate > 0.0 {
            (self.total - self.current) as f64 / rate
        } else {
            0.0
        };
        
        crate::mprint!("\r{}", format!(
            "[*] Progress: {}/{} ({:.1}%) | Rate: {:.0} ports/sec | ETA: {:.0}s",
            self.current,
            self.total,
            percentage,
            rate,
            remaining
        ).cyan());
        // Note: This is in a sync context (ProgressTracker), so we use blocking flush
        // The ProgressTracker is called from async context but uses sync printing
        let _ = std::io::Write::flush(&mut std::io::stdout());
        
        if self.current == self.total {
            crate::mprintln!();
        }
        
        self.last_print = self.current;
    }
}

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "TCP Port Scanner".to_string(),
        description: "Concurrent TCP and UDP port scanner with service detection, banner grabbing, and configurable scan ranges.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

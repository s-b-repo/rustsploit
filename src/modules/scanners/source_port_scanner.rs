use anyhow::{Result, anyhow};
use colored::*;
use std::{
    fs::File,
    io::{Write, BufWriter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use socket2::{Socket, Domain, Type, Protocol};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_int_range, cfg_prompt_yes_no, cfg_prompt_output_file,
    cfg_prompt_port,
};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::modules::creds::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};

/// Module metadata for `info` command.
pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Source Port Scanner".into(),
        description: "Firewall bypass scanner that discovers which source ports are allowed \
            to connect to a target IP and destination port. Useful for identifying firewall \
            rules that permit traffic from specific source ports (e.g., DNS/53, HTTP/80). \
            Supports parallel scanning with configurable concurrency."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec![
            "https://nmap.org/book/firewall-subversion.html".into(),
            "https://book.hacktricks.wiki/en/generic-hacking/pentesting-network/firewall-ids-evasion.html".into(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

#[derive(Debug, Clone)]
struct ScanSettings {
    dest_port: u16,
    source_start: u16,
    source_end: u16,
    concurrency: usize,
    timeout_secs: u64,
    verbose: bool,
    output_file: String,
    scan_udp: bool,
}

/// Main module entrypoint.
pub async fn run(target: &str) -> Result<()> {
    // Mass scan support: CIDR subnets, random IPs, file-based target lists
    if is_mass_scan_target(target) {
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "SrcPortScan",
            default_port: 80,
            state_file: "source_port_scanner_mass_state.log",
            default_output: "source_port_scanner_mass_results.txt",
            default_concurrency: 200,
        }, move |ip, port| {
            async move {
                // Quick TCP connect probe from a few well-known bypass source ports
                let bypass_ports: &[u16] = &[20, 53, 67, 80, 88, 443, 500, 8080];
                let mut hits = Vec::new();
                for &src in bypass_ports {
                    let dest = SocketAddr::new(ip, port);
                    let bind = if ip.is_ipv4() {
                        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), src)
                    } else {
                        SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), src)
                    };
                    let domain = if ip.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
                    if let Ok(sock) = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP)) {
                        let _ = sock.set_reuse_address(true);
                        let _ = sock.set_nonblocking(true);
                        if sock.bind(&bind.into()).is_ok() {
                            let _ = sock.connect(&dest.into());
                            let std_stream: std::net::TcpStream = sock.into();
                            if let Ok(stream) = tokio::net::TcpStream::from_std(std_stream) {
                                if let Ok(Ok(())) = tokio::time::timeout(
                                    std::time::Duration::from_secs(3), stream.writable()
                                ).await {
                                    if let Ok(None) = stream.take_error() {
                                        hits.push(src);
                                    }
                                }
                            }
                        }
                    }
                }
                if hits.is_empty() {
                    None
                } else {
                    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                    let ports_str: Vec<String> = hits.iter().map(|p| p.to_string()).collect();
                    Some(format!("[{}] {}:{} SrcPortScan allowed_src_ports=[{}]\n",
                        ts, ip, port, ports_str.join(",")))
                }
            }
        }).await;
    }

    print_banner();

    let settings = prompt_settings().await?;

    let (ip_str, ip) = resolve_target(target)?;

    // Warn about privileged ports requiring root
    if settings.source_start < 1024 {
        let is_root = unsafe { libc::geteuid() } == 0;
        if !is_root {
            let priv_end = std::cmp::min(settings.source_end, 1023);
            crate::mprintln!("{}", format!(
                "[!] Warning: Source ports {}-{} are privileged (< 1024). \
                 Binding requires root or CAP_NET_BIND_SERVICE. \
                 These ports will show as errors without elevated privileges.",
                settings.source_start, priv_end
            ).yellow().bold());
        }
    }

    let source_ports: Vec<u16> = (settings.source_start..=settings.source_end).collect();
    let total = source_ports.len();
    let protocol_label = if settings.scan_udp { "UDP" } else { "TCP" };

    crate::mprintln!("\n{}", format!(
        "[*] Scanning {} source ports ({}-{}) against {}:{} via {}",
        total, settings.source_start, settings.source_end, ip_str, settings.dest_port, protocol_label
    ).cyan().bold());
    crate::mprintln!("{}", format!("[*] Concurrency: {} | Timeout: {}s", settings.concurrency, settings.timeout_secs).cyan());

    let semaphore = Arc::new(Semaphore::new(settings.concurrency));
    let allowed_ports: Arc<Mutex<Vec<SourcePortResult>>> = Arc::new(Mutex::new(Vec::new()));
    let progress = Arc::new(Mutex::new(ProgressTracker::new(total)));
    let start_time = Instant::now();

    let mut tasks = Vec::with_capacity(total);

    for src_port in source_ports {
        let permit = semaphore.clone().acquire_owned().await?;
        let allowed = allowed_ports.clone();
        let prog = progress.clone();
        let verbose = settings.verbose;
        let dest_port = settings.dest_port;
        let timeout_secs = settings.timeout_secs;
        let scan_udp = settings.scan_udp;
        let ip_str = ip_str.clone();

        let handle = tokio::spawn(async move {
            let _permit = permit;

            let result = if scan_udp {
                probe_udp(ip, dest_port, src_port, timeout_secs).await
            } else {
                probe_tcp(ip, dest_port, src_port, timeout_secs).await
            };

            match result {
                ProbeResult::Allowed { banner } => {
                    let entry = SourcePortResult {
                        source_port: src_port,
                        banner: banner.clone(),
                    };
                    allowed.lock().unwrap_or_else(|e| e.into_inner()).push(entry);

                    let proto = if scan_udp { "UDP" } else { "TCP" };
                    let line = if banner.is_empty() {
                        format!("[{}] src:{} -> {}:{} => {}", proto, src_port, ip_str, dest_port, "ALLOWED".green().bold())
                    } else {
                        format!("[{}] src:{} -> {}:{} => {} | Banner: {}",
                            proto, src_port, ip_str, dest_port, "ALLOWED".green().bold(), banner.trim().bright_black())
                    };
                    crate::mprintln!("{}", line);
                }
                ProbeResult::Denied => {
                    if verbose {
                        crate::mprintln!("  {} src:{} -> DENIED", "✗".red(), src_port);
                    }
                }
                ProbeResult::Timeout => {
                    if verbose {
                        crate::mprintln!("  {} src:{} -> FILTERED/TIMEOUT", "~".yellow(), src_port);
                    }
                }
                ProbeResult::Error(e) => {
                    if verbose {
                        crate::mprintln!("  {} src:{} -> ERROR: {}", "!".red(), src_port, e);
                    }
                }
            }

            let mut pg = prog.lock().unwrap_or_else(|e| e.into_inner());
            pg.increment();
            if pg.should_print() {
                pg.print_progress(&start_time);
            }
        });
        tasks.push(handle);
    }

    for task in tasks {
        let _ = task.await;
    }

    let elapsed = start_time.elapsed();
    let mut results = allowed_ports.lock().unwrap_or_else(|e| e.into_inner()).clone();
    results.sort_by_key(|r| r.source_port);

    // Print summary
    crate::mprintln!("\n{}", "=== Source Port Scan Summary ===".cyan().bold());
    crate::mprintln!("{}", format!("Target: {}:{} ({})", ip_str, settings.dest_port, protocol_label).white());
    crate::mprintln!("{}", format!("Duration: {:.2}s", elapsed.as_secs_f64()).green());
    crate::mprintln!("{}", format!("Scanned: {} source ports ({}-{})", total, settings.source_start, settings.source_end).white());
    crate::mprintln!("{}", format!("Allowed: {}", results.len()).green().bold());

    if results.is_empty() {
        crate::mprintln!("\n{}", "[!] No source ports were allowed through. The destination port may be fully firewalled.".yellow());
    } else {
        crate::mprintln!("\n{}", "Allowed source ports:".yellow().bold());
        for r in &results {
            let well_known = well_known_source_port(r.source_port);
            let label = if well_known.is_empty() {
                format!("  {} port {}", "✓".green(), r.source_port)
            } else {
                format!("  {} port {} ({})", "✓".green(), r.source_port, well_known.cyan())
            };
            if r.banner.is_empty() {
                crate::mprintln!("{}", label);
            } else {
                crate::mprintln!("{} | Banner: {}", label, r.banner.trim().bright_black());
            }
        }
    }

    // Save results
    if !settings.output_file.is_empty() {
        let file = File::create(&settings.output_file)?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&settings.output_file, std::fs::Permissions::from_mode(0o600));
        let mut writer = BufWriter::new(file);
        writeln!(writer, "Source Port Scan Results")?;
        writeln!(writer, "Target: {}:{} ({})", ip_str, settings.dest_port, protocol_label)?;
        writeln!(writer, "Range: {}-{}", settings.source_start, settings.source_end)?;
        writeln!(writer, "Duration: {:.2}s", elapsed.as_secs_f64())?;
        writeln!(writer, "Allowed: {}/{}\n", results.len(), total)?;
        for r in &results {
            let wk = well_known_source_port(r.source_port);
            if wk.is_empty() {
                writeln!(writer, "ALLOWED src:{} -> {}:{}", r.source_port, ip_str, settings.dest_port)?;
            } else {
                writeln!(writer, "ALLOWED src:{} ({}) -> {}:{}", r.source_port, wk, ip_str, settings.dest_port)?;
            }
            if !r.banner.is_empty() {
                writeln!(writer, "  Banner: {}", r.banner.trim())?;
            }
        }
        crate::mprintln!("\n{}", format!("[*] Results saved to {}", settings.output_file).cyan());
    }

    Ok(())
}

fn print_banner() {
    crate::mprintln!("{}", r#"
╔══════════════════════════════════════════════════════════╗
║              Source Port Scanner                          ║
║  Discover which source ports bypass firewall rules       ║
╚══════════════════════════════════════════════════════════╝"#.cyan());
}

async fn prompt_settings() -> Result<ScanSettings> {
    crate::mprintln!("{}", "\n=== Source Port Scanner Configuration ===".cyan().bold());

    let dest_port = cfg_prompt_port("dest_port", "Destination port to test against", 80).await?;

    let range_choice = cfg_prompt_default(
        "source_range",
        "Source port range (1=All 1-65535, 2=Privileged 1-1023, 3=Ephemeral 49152-65535, 4=Custom)",
        "1",
    ).await?;

    let (source_start, source_end) = match range_choice.trim() {
        "2" => (1u16, 1023u16),
        "3" => (49152, 65535),
        "4" => {
            let s = cfg_prompt_int_range("source_start", "Start source port", 1, 1, 65535).await? as u16;
            let e = cfg_prompt_int_range("source_end", "End source port", 65535, 1, 65535).await? as u16;
            if s > e {
                return Err(anyhow!("Start port must be <= end port"));
            }
            (s, e)
        }
        _ => (1, 65535),
    };

    let total = (source_end as u32) - (source_start as u32) + 1;
    crate::mprintln!("{}", format!("[*] Will scan {} source ports ({}-{})", total, source_start, source_end).green());

    let scan_udp = cfg_prompt_yes_no("scan_udp", "Use UDP instead of TCP?", false).await?;
    let concurrency = cfg_prompt_int_range("concurrency", "Concurrency (parallel probes)", 500, 1, 10000).await? as usize;
    let timeout_secs = cfg_prompt_int_range("timeout", "Connection timeout (seconds)", 3, 1, 60).await? as u64;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose output (show denied/filtered)?", false).await?;
    let output_file = cfg_prompt_output_file("output_file", "Output filename", "source_port_results.txt").await?;

    Ok(ScanSettings {
        dest_port,
        source_start,
        source_end,
        concurrency,
        timeout_secs,
        verbose,
        output_file,
        scan_udp,
    })
}

#[derive(Debug)]
enum ProbeResult {
    Allowed { banner: String },
    Denied,
    Timeout,
    Error(String),
}

/// Attempt a TCP connection from a specific source port to target:dest_port.
async fn probe_tcp(ip: IpAddr, dest_port: u16, src_port: u16, timeout_secs: u64) -> ProbeResult {
    let dest = SocketAddr::new(ip, dest_port);
    let domain = if ip.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };

    let socket = match Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) {
        Ok(s) => s,
        Err(e) => return ProbeResult::Error(e.to_string()),
    };

    let _ = socket.set_reuse_address(true);
    let _ = socket.set_nonblocking(true);
    let _ = socket.set_tcp_nodelay(true);

    // Bind to the specific source port
    let bind_addr = if ip.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), src_port)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), src_port)
    };

    if let Err(e) = socket.bind(&bind_addr.into()) {
        return ProbeResult::Error(format!("bind src:{}: {}", src_port, e));
    }

    // Non-blocking connect
    let connect_res = socket.connect(&dest.into());
    match connect_res {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(_) => return ProbeResult::Denied,
    }

    // Convert to tokio TcpStream and wait for writable
    let std_stream: std::net::TcpStream = socket.into();
    match tokio::net::TcpStream::from_std(std_stream) {
        Ok(stream) => {
            match timeout(Duration::from_secs(timeout_secs), stream.writable()).await {
                Ok(Ok(())) => {
                    // Check for socket error to confirm real connection
                    match stream.take_error() {
                        Ok(None) => {
                            // Connection succeeded — try a quick banner grab
                            let banner = quick_banner(&stream, timeout_secs).await;
                            ProbeResult::Allowed { banner }
                        }
                        Ok(Some(_)) => ProbeResult::Denied,
                        Err(_) => ProbeResult::Denied,
                    }
                }
                Ok(Err(_)) => ProbeResult::Denied,
                Err(_) => ProbeResult::Timeout,
            }
        }
        Err(_) => ProbeResult::Denied,
    }
}

/// Attempt a UDP probe from a specific source port.
async fn probe_udp(ip: IpAddr, dest_port: u16, src_port: u16, timeout_secs: u64) -> ProbeResult {
    let bind_addr = if ip.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), src_port)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), src_port)
    };

    let sock = match tokio::net::UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => return ProbeResult::Error(format!("bind src:{}: {}", src_port, e)),
    };

    let dest = SocketAddr::new(ip, dest_port);
    let probe_payload = b"\x00\x00\x10\x10";

    if let Err(e) = sock.send_to(probe_payload, dest).await {
        return ProbeResult::Error(e.to_string());
    }

    let mut buf = [0u8; 512];
    match timeout(Duration::from_secs(timeout_secs), sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => {
            let banner = if n > 0 {
                String::from_utf8_lossy(&buf[..n]).to_string()
            } else {
                String::new()
            };
            ProbeResult::Allowed { banner }
        }
        Ok(Err(_)) => ProbeResult::Denied,
        Err(_) => ProbeResult::Timeout,
    }
}

/// Quick banner read after successful TCP connect.
async fn quick_banner(stream: &tokio::net::TcpStream, _timeout_secs: u64) -> String {
    let mut buf = [0u8; 1024];
    match timeout(Duration::from_millis(800), stream.readable()).await {
        Ok(Ok(())) => {
            match stream.try_read(&mut buf) {
                Ok(n) if n > 0 => String::from_utf8_lossy(&buf[..n]).trim().to_string(),
                _ => String::new(),
            }
        }
        _ => String::new(),
    }
}

fn resolve_target(input: &str) -> Result<(String, IpAddr)> {
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

fn well_known_source_port(port: u16) -> &'static str {
    match port {
        20 => "FTP-Data",
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 => "DHCP-Server",
        68 => "DHCP-Client",
        80 => "HTTP",
        88 => "Kerberos",
        110 => "POP3",
        123 => "NTP",
        143 => "IMAP",
        161 => "SNMP",
        443 => "HTTPS",
        445 => "SMB",
        500 => "IKE/IPSec",
        514 => "Syslog",
        993 => "IMAPS",
        995 => "POP3S",
        1723 => "PPTP",
        3306 => "MySQL",
        3389 => "RDP",
        5060 => "SIP",
        8080 => "HTTP-Alt",
        _ => "",
    }
}

#[derive(Debug, Clone)]
struct SourcePortResult {
    source_port: u16,
    banner: String,
}

struct ProgressTracker {
    total: usize,
    current: usize,
    last_print: usize,
}

impl ProgressTracker {
    fn new(total: usize) -> Self {
        Self { total, current: 0, last_print: 0 }
    }

    fn increment(&mut self) {
        self.current += 1;
    }

    fn should_print(&self) -> bool {
        let diff = self.current - self.last_print;
        diff >= 200 || self.current == self.total
    }

    fn print_progress(&mut self, start: &Instant) {
        if self.current == 0 {
            return;
        }
        let pct = (self.current as f64 / self.total as f64) * 100.0;
        let elapsed = start.elapsed();
        let rate = if elapsed.as_secs() > 0 {
            self.current as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        let eta = if rate > 0.0 {
            (self.total - self.current) as f64 / rate
        } else {
            0.0
        };

        crate::mprint!("\r{}", format!(
            "[*] Progress: {}/{} ({:.1}%) | {:.0} probes/sec | ETA: {:.0}s",
            self.current, self.total, pct, rate, eta
        ).cyan());
        let _ = std::io::Write::flush(&mut std::io::stdout());

        if self.current == self.total {
            crate::mprintln!();
        }
        self.last_print = self.current;
    }
}

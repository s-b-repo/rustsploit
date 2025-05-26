use anyhow::{Result, anyhow};
use std::{
    fs::File,
    io::{self, Write, BufWriter},
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex},
};
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::Semaphore,
    time::{timeout, Duration},
};

#[derive(Debug)]
pub struct ScanSettings {
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub show_only_open: bool,
    pub verbose: bool,
    pub scan_udp_enabled: bool,
    pub output_file: String,
}

/// Interactive config prompt
pub fn prompt_settings() -> Result<ScanSettings> {
    Ok(ScanSettings {
        concurrency: prompt_usize("Concurrency: ")?,
        timeout_secs: prompt_usize("Timeout (in seconds): ")? as u64,
        show_only_open: prompt_bool("Show only open ports? (y/n): ")?,
        verbose: prompt_bool("Verbose output? (y/n): ")?,
        scan_udp_enabled: prompt_bool("Include UDP scan? (y/n): ")?,
        output_file: prompt("Output filename: ")?,
    })
}

/// Main entrypoint for interactive CLI mode
pub async fn run_interactive(target: &str) -> Result<()> {
    let settings = prompt_settings()?;
    run_with_settings(
        target,
        settings.concurrency,
        settings.timeout_secs,
        settings.show_only_open,
        settings.verbose,
        settings.scan_udp_enabled,
        &settings.output_file,
    )
    .await
}

pub async fn run(target: &str) -> Result<()> {
    run_interactive(target).await
}

/// === Core Scanner Logic ===
pub async fn run_with_settings(
    target: &str,
    concurrency: usize,
    timeout_secs: u64,
    show_only_open: bool,
    verbose: bool,
    scan_udp_enabled: bool,
    output_file: &str,
) -> Result<()> {
    // Resolve domain or IP
    let (resolved_ip_str, resolved_ip) = resolve_target(target)?;
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let file = Arc::new(Mutex::new(BufWriter::new(File::create(output_file)?)));
    let mut tasks = vec![];

    println!("[*] Starting scan for target: {} (resolved: {})", target, resolved_ip_str);
    writeln!(file.lock().unwrap(), "Scan Results for {} ({})\n", target, resolved_ip_str)?;

    let progress_bar = Arc::new(Mutex::new(ProgressBar::new(65535 * (1 + scan_udp_enabled as usize))));

    // TCP Scan loop
    println!("[*] Starting TCP scan...");
    for port in 1..=65535u16 {
        let permit = semaphore.clone().acquire_owned().await?;
        let file = file.clone();
        let progress_bar = progress_bar.clone();
        let ip = resolved_ip;
        let ip_str = resolved_ip_str.clone();

        let handle = tokio::spawn(async move {
            let _permit = permit;
            if let Some((status, banner)) = scan_tcp(&ip, port, timeout_secs).await {
                let line = format!("[TCP] {}:{} => {}", ip_str, port, status);
                if status == "OPEN" || !show_only_open {
                    if !banner.is_empty() {
                        let _ = writeln!(file.lock().unwrap(), "{} | Banner: {}", line, banner);
                        if verbose {
                            println!("{} | Banner: {}", line, banner);
                        }
                    } else {
                        let _ = writeln!(file.lock().unwrap(), "{}", line);
                        if verbose {
                            println!("{}", line);
                        }
                    }
                }
            }
            progress_bar.lock().unwrap().increment();
        });
        tasks.push(handle);
    }

    // UDP Scan loop
    if scan_udp_enabled {
        println!("[*] Starting UDP scan...");
        for port in 1..=65535u16 {
            let permit = semaphore.clone().acquire_owned().await?;
            let file = file.clone();
            let progress_bar = progress_bar.clone();
            let ip = resolved_ip;
            let ip_str = resolved_ip_str.clone();

            let handle = tokio::spawn(async move {
                let _permit = permit;
                if let Some(status) = scan_udp(&ip, port, timeout_secs).await {
                    let line = format!("[UDP] {}:{} => {}", ip_str, port, status);
                    if status == "OPEN" || !show_only_open {
                        let _ = writeln!(file.lock().unwrap(), "{}", line);
                        if verbose {
                            println!("{}", line);
                        }
                    }
                }
                progress_bar.lock().unwrap().increment();
            });
            tasks.push(handle);
        }
    }

    // Await all tasks
    for task in tasks {
        let _ = task.await;
    }

    println!("[*] Scan complete. Results saved to {}", output_file);
    Ok(())
}

/// === TCP Port Scanner (Banner Grab) ===
async fn scan_tcp(ip: &std::net::IpAddr, port: u16, timeout_secs: u64) -> Option<(String, String)> {
    let addr = SocketAddr::new(*ip, port);
    match timeout(Duration::from_secs(timeout_secs), TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            let mut buf = [0u8; 1024];
            // Try reading immediately if service gives banner (FTP, SMTP, HTTP, etc)
            match timeout(Duration::from_secs(2), stream.readable()).await {
                Ok(Ok(())) => match stream.try_read(&mut buf) {
                    Ok(n) if n > 0 => {
                        let banner = String::from_utf8_lossy(&buf[..n]).to_string();
                        Some(("OPEN".into(), banner))
                    }
                    _ => Some(("OPEN".into(), "".into())),
                },
                _ => Some(("OPEN".into(), "".into())),
            }
        }
        Ok(Err(_)) => Some(("CLOSED".into(), "".into())),
        Err(_) => Some(("TIMEOUT".into(), "".into())),
    }
}

/// === UDP Port Scanner (Stateless "Fire-and-Forget") ===
async fn scan_udp(ip: &std::net::IpAddr, port: u16, timeout_secs: u64) -> Option<String> {
    // We bind to a random UDP port on localhost
    let bind_addr = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(_) => return Some("ERROR".into()),
    };

    let target = SocketAddr::new(*ip, port);
    let payload = b"\x00\x00\x10\x10"; // Random small packet
    let _ = sock.send_to(payload, target).await;
    // Set a timeout: if port is closed, we should get "Connection refused"
    let mut buf = [0u8; 512];
    match timeout(Duration::from_secs(timeout_secs), sock.recv_from(&mut buf)).await {
        Ok(Ok((_len, _src))) => Some("OPEN".into()),  // Got a response!
        Ok(Err(_)) => Some("CLOSED".into()),         // ICMP port unreachable
        Err(_) => Some("FILTERED".into()),           // No response
    }
}

/// === Target Resolution ===
fn resolve_target(input: &str) -> Result<(String, std::net::IpAddr)> {
    let cleaned = input.trim().trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<_> = (cleaned, 0).to_socket_addrs()?.collect();
    // Prefer IPv4, else fallback to first address
    if let Some(addr) = addrs.iter().find(|a| a.is_ipv4()) {
        Ok((addr.ip().to_string(), addr.ip()))
    } else if let Some(addr) = addrs.first() {
        Ok((addr.ip().to_string(), addr.ip()))
    } else {
        Err(anyhow!("Could not resolve target '{}'", input))
    }
}

/// === Prompt Utilities ===
fn prompt(message: &str) -> Result<String> {
    print!("{}", message);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn prompt_bool(message: &str) -> Result<bool> {
    loop {
        let input = prompt(message)?;
        match input.to_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please enter 'y' or 'n'."),
        }
    }
}

fn prompt_usize(message: &str) -> Result<usize> {
    loop {
        let input = prompt(message)?;
        if let Ok(n) = input.parse::<usize>() {
            return Ok(n);
        }
        println!("Please enter a valid number.");
    }
}

/// === Progress Bar Struct ===
struct ProgressBar {
    total: usize,
    current: usize,
}
impl ProgressBar {
    fn new(total: usize) -> Self {
        ProgressBar { total, current: 0 }
    }
    fn increment(&mut self) {
        self.current += 1;
        if self.current % 1000 == 0 || self.current == self.total {
            println!("[*] Progress: {}/{}", self.current, self.total);
        }
    }
}

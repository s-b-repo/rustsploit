// src/utils/network.rs
//
// Network utility functions: honeypot detection, TCP connection with source port, etc.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use colored::*;
use tokio::net::TcpStream;

use super::target::extract_ip_from_target;

/// Get the globally configured source port (from `setg source_port` or `set source_port`).
/// Returns `None` if not set or invalid.
pub async fn get_global_source_port() -> Option<u16> {
    crate::global_options::GLOBAL_OPTIONS.get("source_port").await
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|&p| p > 0)
}

/// Synchronous version of `get_global_source_port` for use in blocking contexts.
/// Uses `try_read()` which returns immediately without awaiting.
pub fn get_global_source_port_sync() -> Option<u16> {
    crate::global_options::GLOBAL_OPTIONS.try_get("source_port")
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|&p| p > 0)
}

/// Create a TCP connection to `addr` with an optional source port binding.
/// Checks the global `source_port` option automatically.
/// Falls back to OS-assigned source port if none is configured.
pub async fn tcp_connect(addr: &str, timeout: Duration) -> std::io::Result<TcpStream> {
    tcp_connect_with_source(addr, timeout, get_global_source_port().await).await
}

/// Create a TCP connection to `addr` with an explicit source port override.
/// If `source_port` is `None`, uses the global option or OS-assigned port.
pub async fn tcp_connect_with_source(
    addr: &str,
    timeout: Duration,
    source_port: Option<u16>,
) -> std::io::Result<TcpStream> {
    // Resolve the source port: explicit arg > global option > OS-assigned
    let src_port = match source_port {
        Some(_) => source_port,
        None => get_global_source_port().await,
    };

    if let Some(port) = src_port {
        // Use socket2 to bind source port before connecting
        let dest: SocketAddr = addr.to_socket_addrs()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
            .next()
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Cannot resolve address: {}", addr),
            ))?;

        let domain = if dest.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };

        let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;

        let bind_addr = if dest.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
        };
        socket.bind(&bind_addr.into())?;

        // Initiate non-blocking connect
        let _ = socket.connect(&dest.into());
        let std_stream: std::net::TcpStream = socket.into();
        let stream = TcpStream::from_std(std_stream)?;

        // Wait for connection to complete with timeout
        tokio::time::timeout(timeout, stream.writable()).await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Connection timed out"))??;

        // Check for connection errors
        if let Some(err) = stream.take_error()? {
            return Err(err);
        }

        Ok(stream)
    } else {
        // Standard connect without source port binding — try all resolved addresses
        let addrs: Vec<SocketAddr> = addr.to_socket_addrs()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
            .collect();
        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Cannot resolve address: {}", addr),
            ));
        }
        let mut last_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "all addresses failed");
        for sa in &addrs {
            match tokio::time::timeout(timeout, TcpStream::connect(sa)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => last_err = e,
                Err(_) => last_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "Connection timed out"),
            }
        }
        Err(last_err)
    }
}

/// Create a TCP connection to a resolved `SocketAddr` with optional source port binding.
/// Skips DNS resolution — use this when you already have an IP address.
#[inline]
pub async fn tcp_connect_addr(addr: SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
    let src_port = get_global_source_port().await;

    if let Some(port) = src_port {
        let domain = if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };

        let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;

        let bind_addr = if addr.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
        };
        socket.bind(&bind_addr.into())?;

        let _connect = socket.connect(&addr.into());
        let std_stream: std::net::TcpStream = socket.into();
        let stream = TcpStream::from_std(std_stream)?;

        tokio::time::timeout(timeout, stream.writable()).await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Connection timed out"))??;

        if let Some(err) = stream.take_error()? {
            return Err(err);
        }

        Ok(stream)
    } else {
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Connection timed out")),
        }
    }
}

/// Quick TCP port open check with global source port support.
/// Uses zero-alloc SocketAddr path — no format!() or DNS resolution.
#[inline]
pub async fn tcp_port_open(ip: std::net::IpAddr, port: u16, timeout: Duration) -> bool {
    tcp_connect_addr(SocketAddr::new(ip, port), timeout).await.is_ok()
}

/// Convenience wrapper: resolve a "host:port" string (or bare IP+port) via
/// `ToSocketAddrs` and then delegate to [`tcp_connect_addr`]. Exploit modules
/// that accept hostnames from user input should prefer this over raw
/// `TcpStream::connect(&str)` so they still get source-port binding and
/// consistent EINPROGRESS handling.
pub async fn tcp_connect_str(addr_str: &str, timeout: Duration) -> std::io::Result<TcpStream> {
    use tokio::net::lookup_host;
    let first = lookup_host(addr_str)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput,
            format!("DNS resolve '{}': {}", addr_str, e)))?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput,
            format!("no address resolved for '{}'", addr_str)))?;
    tcp_connect_addr(first, timeout).await
}

/// Blocking TCP connection with automatic global source port binding.
/// Drop-in replacement for `std::net::TcpStream::connect_timeout()`.
/// Used by SSH modules, blocking protocol modules (SMTP, POP3, Heartbleed, etc.).
pub fn blocking_tcp_connect(addr: &SocketAddr, timeout: Duration) -> std::io::Result<std::net::TcpStream> {
    blocking_tcp_connect_with_source(addr, timeout, get_global_source_port_sync())
}

/// Blocking TCP connection with explicit source port override.
pub fn blocking_tcp_connect_with_source(
    addr: &SocketAddr,
    timeout: Duration,
    source_port: Option<u16>,
) -> std::io::Result<std::net::TcpStream> {
    let src_port = source_port.or_else(get_global_source_port_sync);

    if let Some(port) = src_port {
        let domain = if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };

        let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
        socket.set_reuse_address(true)?;

        let bind_addr = if addr.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
        };
        socket.bind(&bind_addr.into())?;
        socket.connect_timeout(&(*addr).into(), timeout)?;

        Ok(socket.into())
    } else {
        std::net::TcpStream::connect_timeout(addr, timeout)
    }
}

/// Async UDP socket with automatic global source port binding.
/// Pass `Some(ip)` to select IPv4 vs IPv6 address family; `None` defaults to IPv4.
pub async fn udp_bind(target_ip: Option<IpAddr>) -> std::io::Result<tokio::net::UdpSocket> {
    let is_v6 = matches!(target_ip, Some(IpAddr::V6(_)));
    let any_addr: IpAddr = if is_v6 { IpAddr::V6(Ipv6Addr::UNSPECIFIED) } else { IpAddr::V4(Ipv4Addr::UNSPECIFIED) };
    let domain = if is_v6 { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 };

    if let Some(port) = get_global_source_port().await {
        let bind_addr = SocketAddr::new(any_addr, port);
        // Try binding to the source port, fall back to SO_REUSEPORT on failure
        match tokio::net::UdpSocket::bind(bind_addr).await {
            Ok(sock) => return Ok(sock),
            Err(_) => {
                let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
                socket.set_reuse_address(true)?;
                #[cfg(target_os = "linux")]
                socket.set_reuse_port(true)?;
                socket.set_nonblocking(true)?;
                socket.bind(&bind_addr.into())?;
                let std_sock: std::net::UdpSocket = socket.into();
                return tokio::net::UdpSocket::from_std(std_sock);
            }
        }
    }
    tokio::net::UdpSocket::bind(SocketAddr::new(any_addr, 0)).await
}

/// Blocking UDP socket with automatic global source port binding.
/// Pass `Some(ip)` to select IPv4 vs IPv6 address family; `None` defaults to IPv4.
pub fn blocking_udp_bind(target_ip: Option<IpAddr>) -> std::io::Result<std::net::UdpSocket> {
    let is_v6 = matches!(target_ip, Some(IpAddr::V6(_)));
    let any_addr: IpAddr = if is_v6 { IpAddr::V6(Ipv6Addr::UNSPECIFIED) } else { IpAddr::V4(Ipv4Addr::UNSPECIFIED) };
    let domain = if is_v6 { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 };

    if let Some(port) = get_global_source_port_sync() {
        let bind_addr = SocketAddr::new(any_addr, port);
        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        #[cfg(target_os = "linux")]
        socket.set_reuse_port(true)?;
        socket.bind(&bind_addr.into())?;
        return Ok(socket.into());
    }
    std::net::UdpSocket::bind(SocketAddr::new(any_addr, 0))
}



/// Optional knobs for [`build_http_client_with`]. Use `HttpClientOpts::default()`
/// for the plain "accept invalid certs, no cookies, no redirects" client.
#[derive(Default, Clone)]
pub struct HttpClientOpts {
    /// Enable persistent cookie jar across requests on the same client.
    pub cookie_store: bool,
    /// Follow HTTP 3xx redirects (reqwest default is 10-hop; we default to OFF
    /// so exploit modules see the raw response they asked for).
    pub follow_redirects: bool,
    /// Override the default User-Agent header.
    pub user_agent: Option<String>,
    /// Default headers applied to every request from this client.
    pub default_headers: Option<reqwest::header::HeaderMap>,
    /// Disable TLS cert verification (default: true, matching historical
    /// build_http_client behaviour). Set to false if you want strict TLS.
    pub accept_invalid_certs: bool,
}

impl HttpClientOpts {
    /// Convenience: HttpClientOpts with `accept_invalid_certs: true` (the
    /// historical build_http_client default).
    pub fn permissive() -> Self {
        Self {
            accept_invalid_certs: true,
            ..Default::default()
        }
    }
}

/// Build a standard reqwest HTTP client with common defaults (permissive TLS,
/// no cookies, no redirects). Prints a one-time info notice if source_port is
/// set (reqwest doesn't support it).
pub fn build_http_client(timeout: Duration) -> Result<reqwest::Client, reqwest::Error> {
    build_http_client_with(timeout, HttpClientOpts::permissive())
}

/// Build a reqwest HTTP client with extended options. Every exploit module
/// should go through this function (or the simpler [`build_http_client`])
/// instead of rolling its own `reqwest::Client::builder()` so that source-port
/// warnings, TLS defaults, and redirect policy stay centralised.
pub fn build_http_client_with(
    timeout: Duration,
    opts: HttpClientOpts,
) -> Result<reqwest::Client, reqwest::Error> {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if get_global_source_port_sync().is_some()
        && !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed)
    {
        crate::mprintln!(
            "{}",
            "[*] Note: source_port is set but HTTP (reqwest) does not support source port binding. TCP/UDP/SSH modules will use the configured source port.".yellow()
        );
    }

    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(opts.accept_invalid_certs);

    if opts.cookie_store {
        builder = builder.cookie_store(true);
    }

    builder = if opts.follow_redirects {
        builder.redirect(reqwest::redirect::Policy::limited(10))
    } else {
        builder.redirect(reqwest::redirect::Policy::none())
    };

    if let Some(ua) = opts.user_agent {
        builder = builder.user_agent(ua);
    }

    if let Some(headers) = opts.default_headers {
        builder = builder.default_headers(headers);
    }

    builder.build()
}

/// Pre-check a random IP before dispatching a module in mass-scan mode.
/// Returns `true` if the IP should be scanned, `false` if it should be skipped.
///
/// Checks performed (in order, fastest to slowest):
/// 1. **Port pre-check** — if `service_port` is Some, verifies TCP port is open (3s timeout).
///    Skips 90%+ of random IPs that don't run the target service.
/// 2. **Honeypot detection** — if `honeypot_check` is true, checks for 11+ open ports.
///
/// Designed to be called from the framework mass-scan loop in `commands/mod.rs`.
pub async fn mass_scan_precheck(
    ip: std::net::IpAddr,
    service_port: Option<u16>,
    honeypot_check: bool,
) -> bool {
    if let Some(port) = service_port {
        if !tcp_port_open(ip, port, Duration::from_secs(3)).await {
            return false;
        }
    }
    if honeypot_check {
        let ip_str = ip.to_string();
        if quick_honeypot_check(&ip_str).await {
            return false;
        }
    }
    true
}

/// Fast parallel honeypot check for a single IP. Returns true if likely honeypot.
/// Uses a smaller port set (30 ports) and shorter timeout for speed.
/// Designed to be called concurrently for many IPs during mass/subnet scans.
pub async fn quick_honeypot_check(ip: &str) -> bool {
    let parsed_ip = match extract_ip_from_target(ip) {
        Some(ip) => ip,
        None => return false,
    };

    // Skip check for hostnames (only check bare IPs)
    if parsed_ip.contains(|c: char| c.is_alphabetic() && c != ':') && !parsed_ip.contains(':') {
        return false;
    }

    const QUICK_PORTS: &[u16] = &[
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 993, 995, 1433, 1723, 3306, 3389,
        5432, 5900, 6379, 8080, 8443, 8888, 9090,
        11211, 27017, 1521, 161, 389,
    ];

    let scan_timeout = Duration::from_millis(200);
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(30));
    let open_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut tasks = Vec::with_capacity(QUICK_PORTS.len());

    for &port in QUICK_PORTS {
        let ip_clone = parsed_ip.clone();
        let sem = semaphore.clone();
        let count = open_count.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(permit) => permit,
                Err(_) => return,
            };
            let addr = format!("{}:{}", ip_clone, port);
            if tcp_connect(&addr, scan_timeout).await.is_ok() {
                count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }));
    }

    for task in tasks {
        let _ = task.await;
    }

    open_count.load(std::sync::atomic::Ordering::Relaxed) >= 11
}


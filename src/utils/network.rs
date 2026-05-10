// src/utils/network.rs
//
// Network utility functions: honeypot detection, TCP connection with source port, etc.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use colored::*;
use tokio::net::TcpStream;

use super::target::extract_ip_from_target;

/// True if a non-blocking `connect()` returned the platform's "in progress"
/// indicator (Unix: EINPROGRESS, Windows: WSAEWOULDBLOCK → ErrorKind::WouldBlock).
/// Used to distinguish a real connect failure from the expected async-pending
/// state when binding a source port via socket2.
#[inline]
fn is_in_progress(e: &std::io::Error) -> bool {
    if e.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(unix)]
    {
        if e.raw_os_error() == Some(libc::EINPROGRESS) {
            return true;
        }
    }
    false
}

/// P1-4: gate destructive DoS modules so an operator can't accidentally
/// flood `127.0.0.1`, RFC1918 ranges, or cloud-metadata addresses.
///
/// Returns `Ok(())` if the target is fine to attack. If the target resolves
/// to a blocked range, prints a strong warning and forces an explicit
/// "I HAVE AUTHORIZATION" prompt; if the operator can't produce that, we
/// return an error and the module bails before sending a single packet.
///
/// Modules call this once at the top of `run()` after they've parsed the
/// target. Mass-scan / random-IP / file-list targets are intentionally not
/// passed in here — those have their own per-IP gates downstream.
pub async fn assert_dos_target_authorized(target: &str) -> anyhow::Result<()> {
    // Reuse the API-side blocklist: cloud metadata + IPv6 link-local
    // unconditionally; loopback/RFC1918 only when running in production.
    if !crate::api::is_blocked_target(target) {
        return Ok(());
    }
    crate::mprintln!(
        "{}",
        "!!! DoS TARGET WARNING !!!".on_red().white().bold()
    );
    crate::mprintln!(
        "{}",
        format!("Target {} resolves to a private / loopback / metadata address.", target).red().bold()
    );
    crate::mprintln!(
        "{}",
        "Flooding this address can take down YOUR OWN infrastructure or hit cloud metadata services.".red()
    );
    let confirm = crate::utils::cfg_prompt_required(
        "dos_target_ack",
        "Type 'I HAVE AUTHORIZATION' to proceed against this target",
    ).await?;
    if confirm.trim() != "I HAVE AUTHORIZATION" {
        anyhow::bail!(
            "DoS target authorization not confirmed — aborting before any packets are sent."
        );
    }
    Ok(())
}

/// Get the globally configured source port (from `setg source_port` or `set source_port`).
/// Returns `None` if not set or invalid.
pub async fn get_global_source_port() -> Option<u16> {
    crate::tenant::resolve().global_options().get("source_port").await
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|&p| p > 0)
}

/// Synchronous version of `get_global_source_port` for use in blocking contexts.
/// Uses `try_read()` which returns immediately without awaiting.
pub fn get_global_source_port_sync() -> Option<u16> {
    crate::tenant::resolve().global_options().try_get("source_port")
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

        // Initiate non-blocking connect — returns EINPROGRESS on success.
        // Surface anything else (EACCES from a privileged source port,
        // EAFNOSUPPORT, etc.) so the caller doesn't block forever on writable().
        if let Err(e) = socket.connect(&dest.into())
            && !is_in_progress(&e) {
                return Err(e);
            }
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
        // Standard connect without source port binding — try all resolved addresses.
        // Cap the resolved address list: a malicious DNS responder can hand back
        // hundreds of A/AAAA records and force us to try them all serially.
        const MAX_RESOLVED_ADDRS: usize = 16;
        let addrs: Vec<SocketAddr> = addr.to_socket_addrs()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
            .take(MAX_RESOLVED_ADDRS)
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

        // Non-blocking connect — returns EINPROGRESS, which we surface only if
        // it's a synchronous failure (EACCES, EAFNOSUPPORT, etc.). Real connect
        // result is checked via take_error() once the socket becomes writable.
        if let Err(e) = socket.connect(&addr.into())
            && !is_in_progress(&e) {
                return Err(e);
            }
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
    // Cap the resolved address list — a malicious DNS responder can hand back
    // hundreds of A/AAAA records and force us to try them all serially.
    const MAX_RESOLVED_ADDRS: usize = 16;
    let addrs: Vec<SocketAddr> = lookup_host(addr_str)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput,
            format!("DNS resolve '{}': {}", addr_str, e)))?
        .take(MAX_RESOLVED_ADDRS)
        .collect();
    if addrs.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
            format!("no address resolved for '{}'", addr_str)));
    }
    let mut last_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "all addresses failed");
    for sa in addrs {
        match tcp_connect_addr(sa, timeout).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                tracing::trace!(addr_str, candidate = %sa, "tcp_connect_str candidate failed: {}", e);
                last_err = e;
            }
        }
    }
    Err(last_err)
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
            Err(e) => {
                tracing::debug!(
                    bind = %bind_addr,
                    "UDP plain bind failed ({}), retrying with SO_REUSEADDR/SO_REUSEPORT",
                    e
                );
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



/// Optional knobs for [`build_http_client_with`]. Use `HttpClientOpts::permissive()`
/// for the standard pentest client that respects `--strict-tls`.
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
    /// Disable TLS hostname verification on top of cert verification —
    /// useful when targets present a cert valid for the wrong hostname
    /// (common on devices with self-signed certs hardcoded to a vendor
    /// hostname). Independent of `accept_invalid_certs` per reqwest's API.
    pub accept_invalid_hostnames: bool,
    /// Override `pool_max_idle_per_host` (reqwest default: usize::MAX). DoS
    /// modules and high-concurrency scanners can pass a smaller cap, or
    /// `Some(0)` to fully disable the connection pool.
    pub pool_max_idle_per_host: Option<usize>,
}

impl HttpClientOpts {
    /// Convenience: lab-permissive HTTP client — accepts self-signed certs.
    ///
    /// P0-2: when the operator launched with `--strict-tls`, this returns a
    /// strict-TLS configuration instead. Modules that genuinely need
    /// permissive TLS (e.g. testing a self-signed Fortinet appliance on a
    /// closed lab network) should construct `HttpClientOpts` directly with
    /// the explicit field set, or call `permissive_unconditional()` below.
    pub fn permissive() -> Self {
        Self {
            accept_invalid_certs: !get_global_strict_tls(),
            ..Default::default()
        }
    }

    /// Convenience: full pentest-permissive — invalid certs + invalid
    /// hostnames + cookie jar. Same `--strict-tls` honoring as
    /// `permissive()`.
    pub fn pentest_session() -> Self {
        let lab_mode = !get_global_strict_tls();
        Self {
            accept_invalid_certs: lab_mode,
            accept_invalid_hostnames: lab_mode,
            cookie_store: true,
            ..Default::default()
        }
    }

    /// Force-permissive — ignores `--strict-tls`. Use only for modules that
    /// literally cannot work without permissive TLS (e.g. talking to a
    /// device that hardcodes a vendor-issued self-signed cert with the
    /// wrong hostname). Document the reason at the call site.
    pub fn permissive_unconditional() -> Self {
        Self {
            accept_invalid_certs: true,
            accept_invalid_hostnames: true,
            cookie_store: true,
            ..Default::default()
        }
    }
}

/// P0-2 strict-TLS toggle. Set once at startup from the CLI flag; consulted
/// every time a module asks for a "permissive" client. `Lazy<AtomicBool>`
/// keeps the read path branchless after init.
static GLOBAL_STRICT_TLS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn set_global_strict_tls(on: bool) {
    GLOBAL_STRICT_TLS.store(on, std::sync::atomic::Ordering::SeqCst);
}

pub fn get_global_strict_tls() -> bool {
    GLOBAL_STRICT_TLS.load(std::sync::atomic::Ordering::SeqCst)
}

/// P1-9 proxy-trust toggle for the handshake rate limiter. Off by default
/// so the limiter uses the TCP peer address; flip on when behind a proxy
/// the operator trusts to scrub `X-Forwarded-For`.
static GLOBAL_TRUST_PROXY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn set_global_trust_proxy(on: bool) {
    GLOBAL_TRUST_PROXY.store(on, std::sync::atomic::Ordering::SeqCst);
}

pub fn get_global_trust_proxy() -> bool {
    GLOBAL_TRUST_PROXY.load(std::sync::atomic::Ordering::SeqCst)
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

    // reqwest is built with `rustls-no-provider`, so a CryptoProvider must be
    // installed before the first TLS handshake or rustls panics with
    // "No provider set". Install the ring provider once, lazily.
    static PROVIDER: std::sync::Once = std::sync::Once::new();
    PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(opts.accept_invalid_certs);

    if opts.accept_invalid_hostnames {
        builder = builder.danger_accept_invalid_hostnames(true);
    }
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

    if let Some(cap) = opts.pool_max_idle_per_host {
        builder = builder.pool_max_idle_per_host(cap);
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
    if let Some(port) = service_port
        && !tcp_port_open(ip, port, Duration::from_secs(3)).await {
            return false;
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

/// HTTP probe helper used by exploit modules.
///
/// Sends a `GET` and returns `(status_code, body_text)` on success. Any
/// transport or body-decode failure is propagated as `anyhow::Error` with a
/// descriptive `Context` so callers can do
///   `let (status, body) = http_get_status_body(&client, &url).await?;`
/// in `run()`, or branch via `match` in `check()`. The intent is to give
/// modules a single call that surfaces both kinds of failure explicitly
/// rather than silently swallowing them.
pub async fn http_get_status_body(
    client: &reqwest::Client,
    url: &str,
) -> anyhow::Result<(u16, String)> {
    use anyhow::Context;
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {} failed", url))?;
    let status = resp.status().as_u16();
    let body = resp
        .text()
        .await
        .with_context(|| format!("decode body of {}", url))?;
    Ok((status, body))
}

/// Same as [`http_get_status_body`] but returns the body and the response
/// headers (so callers can inspect e.g. `Server`/`X-Powered-By`).
pub async fn http_get_status_headers_body(
    client: &reqwest::Client,
    url: &str,
) -> anyhow::Result<(u16, reqwest::header::HeaderMap, String)> {
    use anyhow::Context;
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {} failed", url))?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp
        .text()
        .await
        .with_context(|| format!("decode body of {}", url))?;
    Ok((status, headers, body))
}

/// Read a HTTP response header as an owned `String`.
///
/// Returns the empty string when the header is absent, or the sentinel
/// `"<non-utf8>"` when the value is present but not valid UTF-8 — so the
/// non-utf8 case shows up in module output rather than being silently
/// turned into "" the way `.to_str().ok().unwrap_or("")` does. Callers that
/// need to distinguish non-utf8 from absent should use `headers.get(name)`
/// directly and match on `to_str()` themselves.
pub fn header_string(headers: &reqwest::header::HeaderMap, name: &str) -> String {
    match headers.get(name) {
        None => String::new(),
        Some(v) => match v.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => String::from("<non-utf8>"),
        },
    }
}


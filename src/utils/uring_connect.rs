//! io_uring-backed TCP connect probe + stream service (feature = "io_uring").
//!
//! The framework runs on a multi-thread Tokio runtime where all module futures
//! must be `Send`. tokio_uring's I/O types are `!Send` and can only live inside
//! a `tokio_uring::start` current-thread `LocalSet`, so uring futures cannot be
//! embedded in module futures.
//!
//! We run io_uring on a **pool of dedicated threads** — one ring per thread,
//! count = min(cores, 16), round-robin dispatch — and bridge to the main runtime
//! with `Send` channel API. Only `SocketAddr` / `Duration` / verdicts cross the
//! boundary. Operations:
//!
//!   - [`probe`] — port-open boolean check (mass-scan precheck)
//!   - [`connect`] — full TCP stream connect, returns `io::Result<StdTcpStream>`
//!     converted from io_uring fd via dup(2); caller wraps in `TcpStream::from_std`
//!   - [`blocking_connect`] — synchronous bridge for `blocking_tcp_connect` in
//!     `spawn_blocking` contexts; submits to ring and blocks on oneshot
//!
//! All functions self-heal: `None` → caller falls back to tokio/blocking path.

use std::io;
use std::net::{SocketAddr, TcpStream as StdTcpStream};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

// =========================================================================
// Request types
// =========================================================================

enum RingRequest {
    Probe {
        addr: SocketAddr,
        timeout: Duration,
        reply: oneshot::Sender<Option<bool>>,
    },
    Connect {
        addr: SocketAddr,
        timeout: Duration,
        reply: oneshot::Sender<io::Result<StdTcpStream>>,
    },
}

// =========================================================================
// Ring thread pool
// =========================================================================

struct Pool {
    rings: Vec<mpsc::UnboundedSender<RingRequest>>,
    next: AtomicUsize,
}

impl Pool {
    fn pick(&self) -> Option<&mpsc::UnboundedSender<RingRequest>> {
        let len = self.rings.len();
        if len == 0 {
            return None;
        }
        let i = self.next.fetch_add(1, Ordering::Relaxed) % len;
        self.rings.get(i)
    }
}

pub fn ring_count() -> usize {
    const DEFAULT_MAX_RINGS: usize = 16;
    match std::env::var("RUSTSPLOIT_URING_RINGS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        Some(n) if n > 0 => n,
        _ => std::thread::available_parallelism()
            .map(|n| n.get().min(DEFAULT_MAX_RINGS))
            .unwrap_or(1),
    }
}

fn pool() -> Option<&'static Pool> {
    static POOL: OnceLock<Option<Pool>> = OnceLock::new();
    POOL.get_or_init(|| {
        let n = ring_count();
        let mut rings = Vec::with_capacity(n);
        for idx in 0..n {
            match spawn_ring_thread(idx) {
                Ok(tx) => rings.push(tx),
                Err(e) => tracing::warn!("io_uring ring {idx} failed to start ({e})"),
            }
        }
        if rings.is_empty() {
            tracing::warn!("io_uring: no rings available; using tokio connect");
            None
        } else {
            tracing::debug!(
                "io_uring connect service started with {} ring(s)",
                rings.len()
            );
            Some(Pool {
                rings,
                next: AtomicUsize::new(0),
            })
        }
    })
    .as_ref()
}

fn spawn_ring_thread(idx: usize) -> io::Result<mpsc::UnboundedSender<RingRequest>> {
    let (tx, mut rx) = mpsc::unbounded_channel::<RingRequest>();
    std::thread::Builder::new()
        .name(format!("io_uring-connect-{idx}"))
        .spawn(move || {
            tokio_uring::start(async move {
                while let Some(req) = rx.recv().await {
                    match req {
                        RingRequest::Probe {
                            addr,
                            timeout,
                            reply,
                        } => {
                            tokio_uring::spawn(async move {
                                let verdict = probe_once(addr, timeout).await;
                                if reply.send(verdict).is_err() {
                                    tracing::trace!(addr = %addr, "io_uring probe reply dropped");
                                }
                            });
                        }
                        RingRequest::Connect {
                            addr,
                            timeout,
                            reply,
                        } => {
                            tokio_uring::spawn(async move {
                                let result = connect_stream_once(addr, timeout).await;
                                if reply.send(result).is_err() {
                                    tracing::trace!(addr = %addr, "io_uring connect reply dropped");
                                }
                            });
                        }
                    }
                }
            });
        })?;
    Ok(tx)
}

// =========================================================================
// Ring-thread connect operations
// =========================================================================

async fn probe_once(addr: SocketAddr, timeout: Duration) -> Option<bool> {
    use std::io::ErrorKind;
    use tokio_uring::net::TcpStream;
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            drop(stream);
            Some(true)
        }
        Ok(Err(e)) => match e.kind() {
            ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::TimedOut
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable => Some(false),
            other => {
                tracing::debug!(%addr, kind = ?other,
                    "io_uring connect ring-level failure ({e}); caller will fall back");
                None
            }
        },
        Err(e) => {
            tracing::trace!(%addr, "io_uring connect probe timed out: {e}");
            Some(false)
        }
    }
}

async fn connect_stream_once(addr: SocketAddr, timeout: Duration) -> io::Result<StdTcpStream> {
    use tokio_uring::net::TcpStream;
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("io_uring connect timed out: {e}"),
            )
        })??;
    let raw_fd = stream.as_raw_fd();
    // SAFETY: dup(2) creates a new fd referring to the same kernel socket.
    // The original fd is closed when `stream` drops; the dup survives.
    let dup_fd = unsafe { libc::dup(raw_fd) };
    if dup_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    drop(stream);
    // SAFETY: dup_fd is a valid, connected TCP socket fd.
    Ok(unsafe { StdTcpStream::from_raw_fd(dup_fd) })
}

// =========================================================================
// Async Public API (Send-safe, called from main runtime)
// =========================================================================

pub async fn probe(addr: SocketAddr, timeout: Duration) -> Option<bool> {
    let tx = pool()?.pick()?;
    let (reply_tx, reply_rx) = oneshot::channel();
    if tx
        .send(RingRequest::Probe {
            addr,
            timeout,
            reply: reply_tx,
        })
        .is_err()
    {
        tracing::debug!(%addr, "io_uring ring stopped; falling back to tokio");
        return None;
    }
    match reply_rx.await {
        Ok(verdict) => verdict,
        Err(e) => {
            tracing::debug!(%addr, "io_uring probe reply lost ({e}); falling back to tokio");
            None
        }
    }
}

pub async fn connect(addr: SocketAddr, timeout: Duration) -> Option<io::Result<StdTcpStream>> {
    let tx = pool()?.pick()?;
    let (reply_tx, reply_rx) = oneshot::channel();
    if tx
        .send(RingRequest::Connect {
            addr,
            timeout,
            reply: reply_tx,
        })
        .is_err()
    {
        tracing::debug!(%addr, "io_uring ring stopped; falling back to tokio");
        return None;
    }
    match reply_rx.await {
        Ok(result) => Some(result),
        Err(e) => {
            tracing::debug!(%addr, "io_uring connect reply lost ({e}); falling back to tokio");
            None
        }
    }
}

// =========================================================================
// Blocking Public API — for use inside spawn_blocking contexts
// =========================================================================

/// Blocking bridge: submit a Connect request to the io_uring ring pool and
/// block the calling thread on the oneshot. Returns `None` if the ring service
/// is unavailable (caller falls back to `std::net::TcpStream::connect_timeout`).
///
/// Must only be called from a `spawn_blocking` thread (has a tokio runtime
/// handle), never from a bare OS thread.
pub fn blocking_connect(addr: SocketAddr, timeout: Duration) -> Option<io::Result<StdTcpStream>> {
    let tx = pool()?.pick()?;
    let (reply_tx, reply_rx) = oneshot::channel();
    if tx
        .send(RingRequest::Connect {
            addr,
            timeout,
            reply: reply_tx,
        })
        .is_err()
    {
        tracing::debug!(%addr, "io_uring ring stopped; falling back to blocking connect");
        return None;
    }
    // Block the current spawn_blocking thread on the async oneshot.
    // This is safe because the blocking thread pool is designed for blocking
    // operations; the main runtime is unaffected.
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.block_on(reply_rx) {
            Ok(result) => Some(result),
            Err(e) => {
                tracing::debug!(%addr, "io_uring blocking connect reply lost ({e}); falling back");
                None
            }
        },
        Err(e) => {
            tracing::debug!(%addr, "no tokio runtime in blocking_connect ({e}); falling back");
            None
        }
    }
}

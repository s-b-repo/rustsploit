// src/native/network.rs
//
// Native raw-socket FFI helpers shared across the DoS modules.
//
// Centralising these in one place collapses what used to be 8 near-duplicate
// copies of `make_dst_sockaddr` / `send_one_raw` into a single audited
// implementation, so every `unsafe` block in the project's raw-packet send
// path lives here.
//
// Three layers of API:
//
//   1. IPv4 fast path — `make_dst_sockaddr(Ipv4Addr) -> sockaddr_in` and
//      `send_one_raw(fd, buf, &sockaddr_in)`. The historical surface that
//      the 8 DoS modules already use; smallest unsafe footprint.
//
//   2. IPv6 fast path — `make_dst_sockaddr_v6(Ipv6Addr, scope_id) ->
//      sockaddr_in6` and `send_one_raw_v6(fd, buf, &sockaddr_in6)`. Same
//      shape as IPv4 but for AF_INET6 sockets / sockaddr_in6.
//
//   3. Family-agnostic wrapper — `DstAddr` enum + `make_dst_sockaddr_any`
//      + `send_one_raw_any`. Pick this when the module accepts both IPv4
//      and IPv6 targets and you don't want to fork the call site.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Default send-timeout for raw DoS sockets. Without this, a single congested
/// or blackholed route can wedge a worker thread inside `sendto(2)`
/// indefinitely, draining the worker pool and silently degrading throughput.
/// 5s is long enough that healthy networks never trip it but short enough
/// that a stuck send returns control to the worker quickly.
pub const DEFAULT_RAW_SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// Apply `SO_SNDTIMEO` to a `socket2::Socket`. Errors are ignored — the
/// timeout is a defensive hint, not a correctness requirement, and some
/// kernels reject it on raw sockets without root. Callers should invoke this
/// once after creating a raw socket and before handing it to worker threads.
#[inline]
pub fn apply_raw_send_timeout(socket: &socket2::Socket) {
    let _ = socket.set_write_timeout(Some(DEFAULT_RAW_SEND_TIMEOUT));
}

// ============================================================================
// SYSTEM LIMITS (RLIMIT_NOFILE, RLIMIT_NPROC) — native getrlimit/setrlimit
// ============================================================================
//
// DoS modules open thousands of sockets / spawn thousands of worker threads.
// Without first checking and raising the per-process resource limits, the
// operator typically hits one of two failure modes:
//
//   * `EMFILE` ("too many open files") halfway through the run, after which
//     the module silently transitions from "flooding the target" to "flooding
//     itself with errno spam".
//   * Thread spawn failures (`EAGAIN` from `clone(2)`) once `RLIMIT_NPROC`
//     is hit, leaving the operator with a fraction of the requested workers
//     and no clear error.
//
// Both of those eat your *own* host's headroom — the user reported that on
// older runs they actually exhausted their workstation. So every raw-packet
// DoS module now calls `prepare_dos_limits(needed_fds)` before it allocates
// sockets or spawns threads. The helper:
//
//   1. Reads the current `(soft, hard)` for `RLIMIT_NOFILE` and
//      `RLIMIT_NPROC` via `getrlimit(2)`.
//   2. Computes a requested soft floor as `needed_fds + RESERVED_FDS`
//      (default headroom for stdio/tokio/log handles).
//   3. If the current soft is below that floor, calls `setrlimit(2)` to
//      raise it — first up to `hard`, and (when running as root) raising
//      `hard` to match if necessary.
//   4. Returns a struct describing what the new effective ceiling is so the
//      caller can clamp `worker_count` / `max_concurrent_fds` accordingly.
//
// Everything below uses `libc::getrlimit` / `libc::setrlimit` directly — no
// extra crate, and the unsafe lives in this single file alongside the rest
// of the FFI surface.

/// Headroom reserved for tokio internals, log file handles, /dev/urandom,
/// and the framework's own bookkeeping. Subtracted from the rlimit soft cap
/// before we report a "usable" budget back to the caller.
pub const RESERVED_FDS: u64 = 256;

/// Snapshot of the per-process resource limits relevant to DoS modules.
/// `usable_fds` is the FD budget the module is allowed to consume after we
/// account for `RESERVED_FDS`; modules should clamp `worker_count` /
/// `max_concurrent_fds` to this value.
#[derive(Clone, Copy, Debug)]
pub struct DosLimits {
    pub nofile_soft: u64,
    pub nofile_hard: u64,
    pub nproc_soft: u64,
    pub nproc_hard: u64,
    /// Soft FD limit minus `RESERVED_FDS`, saturating at zero.
    pub usable_fds: u64,
    /// True if `prepare_dos_limits` actually raised at least one rlimit on
    /// this call (so the caller can log "raised to N" rather than just "N").
    pub raised: bool,
}

#[cfg(unix)]
fn getrlimit_native(resource: libc::__rlimit_resource_t) -> std::io::Result<(u64, u64)> {
    // SAFETY: `rlimit` is a POD struct of two integers; we zero-initialise
    // it before passing the pointer to `getrlimit(2)`, which fills it in
    // and returns 0 on success.
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::getrlimit(resource, &mut rl) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((rl.rlim_cur as u64, rl.rlim_max as u64))
}

#[cfg(unix)]
fn setrlimit_native(resource: libc::__rlimit_resource_t, soft: u64, hard: u64) -> std::io::Result<()> {
    let rl = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: hard as libc::rlim_t,
    };
    // SAFETY: `&rl` points to a fully initialised `rlimit` POD on the stack;
    // `setrlimit(2)` reads two integers and either succeeds (returns 0) or
    // fails with errno set.
    let ret = unsafe { libc::setrlimit(resource, &rl) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Read the current `(soft, hard)` limits for `RLIMIT_NOFILE` /
/// `RLIMIT_NPROC` without modifying them. Returns `None` on platforms /
/// configurations where the syscall fails.
#[cfg(unix)]
pub fn read_dos_limits() -> Option<DosLimits> {
    let (no_soft, no_hard) = getrlimit_native(libc::RLIMIT_NOFILE).ok()?;
    // RLIMIT_NPROC is BSD/Linux; some libc targets won't define it, but on
    // every Unix we ship for it does. If the syscall fails (rare), we fall
    // back to "unlimited" so we don't block a run on a missing knob.
    let (np_soft, np_hard) = getrlimit_native(libc::RLIMIT_NPROC)
        .unwrap_or((u64::MAX, u64::MAX));
    Some(DosLimits {
        nofile_soft: no_soft,
        nofile_hard: no_hard,
        nproc_soft: np_soft,
        nproc_hard: np_hard,
        usable_fds: no_soft.saturating_sub(RESERVED_FDS),
        raised: false,
    })
}

#[cfg(not(unix))]
pub fn read_dos_limits() -> Option<DosLimits> { None }

#[cfg(unix)]
#[inline]
fn is_root() -> bool {
    // SAFETY: `geteuid(2)` is signal-safe and has no preconditions; it just
    // returns the effective UID.
    unsafe { libc::geteuid() == 0 }
}

/// Inspect the current `RLIMIT_NOFILE` / `RLIMIT_NPROC` and raise them as
/// needed so a DoS module can safely use `needed_fds` file descriptors and
/// `needed_threads` worker threads without exhausting the operator's own
/// host. Returns the post-adjustment snapshot; callers should clamp their
/// concurrency to `result.usable_fds`.
///
/// Behaviour:
///
/// * If the current soft `NOFILE` already covers `needed_fds + RESERVED_FDS`,
///   nothing is changed.
/// * Otherwise we raise the soft limit toward the hard limit (or to the
///   target, whichever is smaller). When running as root we additionally
///   raise the hard limit so the soft can follow.
/// * Same logic applies to `NPROC` against `needed_threads`.
/// * Failures to raise are non-fatal — we return whatever ceiling we ended
///   up with so the caller can clamp instead of bailing.
#[cfg(unix)]
pub fn prepare_dos_limits(needed_fds: u64, needed_threads: u64) -> std::io::Result<DosLimits> {
    let (mut no_soft, mut no_hard) = getrlimit_native(libc::RLIMIT_NOFILE)?;
    let (mut np_soft, mut np_hard) = getrlimit_native(libc::RLIMIT_NPROC)
        .unwrap_or((u64::MAX, u64::MAX));

    let target_no_soft = needed_fds.saturating_add(RESERVED_FDS);
    let target_np_soft = needed_threads.saturating_add(64);
    let mut raised = false;
    let root = is_root();

    // RLIMIT_NOFILE
    if no_soft < target_no_soft {
        // Root can push the hard cap up first; non-root can only ride it up
        // to the existing hard cap.
        if root && no_hard < target_no_soft {
            let new_hard = target_no_soft;
            if setrlimit_native(libc::RLIMIT_NOFILE, new_hard, new_hard).is_ok() {
                no_soft = new_hard;
                no_hard = new_hard;
                raised = true;
            }
        }
        if no_soft < target_no_soft {
            let new_soft = target_no_soft.min(no_hard);
            if new_soft > no_soft && setrlimit_native(libc::RLIMIT_NOFILE, new_soft, no_hard).is_ok() {
                no_soft = new_soft;
                raised = true;
            }
        }
    }

    // RLIMIT_NPROC — only meaningful if we have a finite hard cap. If NPROC
    // is unlimited (often the case for root) we leave it alone.
    if np_hard != u64::MAX && np_soft < target_np_soft {
        if root && np_hard < target_np_soft {
            let new_hard = target_np_soft;
            if setrlimit_native(libc::RLIMIT_NPROC, new_hard, new_hard).is_ok() {
                np_soft = new_hard;
                np_hard = new_hard;
                raised = true;
            }
        }
        if np_soft < target_np_soft {
            let new_soft = target_np_soft.min(np_hard);
            if new_soft > np_soft && setrlimit_native(libc::RLIMIT_NPROC, new_soft, np_hard).is_ok() {
                np_soft = new_soft;
                raised = true;
            }
        }
    }

    Ok(DosLimits {
        nofile_soft: no_soft,
        nofile_hard: no_hard,
        nproc_soft: np_soft,
        nproc_hard: np_hard,
        usable_fds: no_soft.saturating_sub(RESERVED_FDS),
        raised,
    })
}

#[cfg(not(unix))]
pub fn prepare_dos_limits(_needed_fds: u64, _needed_threads: u64) -> std::io::Result<DosLimits> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "rlimit not supported on this platform"))
}

/// Convenience wrapper used by every DoS module: print a one-line status
/// line, raise the limits, clamp `requested_workers` to whatever the host
/// actually allows, and return the clamped value plus the snapshot. If the
/// host's hard cap simply can't accommodate the request, the returned worker
/// count will be smaller than `requested_workers` — log it and continue
/// rather than aborting the run.
///
/// `module` is just a label used in the log line ("syn_ack_flood" etc).
/// `fds_per_worker` lets reflection floods (1 socket per worker) and
/// connection floods (1 FD per in-flight connection per worker) ask for
/// the right amount of headroom.
pub fn ensure_dos_capacity(
    module: &str,
    requested_workers: usize,
    fds_per_worker: usize,
) -> (usize, Option<DosLimits>) {
    let needed_fds = (requested_workers as u64).saturating_mul(fds_per_worker.max(1) as u64);
    let needed_threads = requested_workers as u64;

    // Snapshot the starting state so operators can see what the host gave us
    // before any raise. This is the same data the kernel will use to gate
    // socket() / clone() failures, so logging it eliminates the "why did my
    // flood stall at exactly N workers?" guessing game.
    if let Some(initial) = read_dos_limits() {
        crate::mprintln!(
            "[*] {}: starting ulimits — RLIMIT_NOFILE soft={} hard={} | RLIMIT_NPROC soft={} hard={} | needed: {} fds, {} threads",
            module, initial.nofile_soft, initial.nofile_hard,
            initial.nproc_soft, initial.nproc_hard,
            needed_fds, needed_threads,
        );
    }

    let limits = match prepare_dos_limits(needed_fds, needed_threads) {
        Ok(l) => l,
        Err(e) => {
            crate::mprintln!(
                "{}",
                format!(
                    "[!] {}: could not query/raise system limits ({}); proceeding with current ulimit.",
                    module, e
                )
            );
            return (requested_workers, None);
        }
    };

    let max_workers_by_fd = (limits.usable_fds / fds_per_worker.max(1) as u64) as usize;
    let max_workers_by_proc = if limits.nproc_hard == u64::MAX {
        usize::MAX
    } else {
        limits.nproc_soft.saturating_sub(64) as usize
    };
    let cap = max_workers_by_fd.min(max_workers_by_proc).max(1);
    let clamped = requested_workers.min(cap);

    if limits.raised {
        crate::mprintln!(
            "[*] {}: raised RLIMIT_NOFILE to {} (hard {}) / RLIMIT_NPROC to {} (hard {})",
            module, limits.nofile_soft, limits.nofile_hard,
            limits.nproc_soft, limits.nproc_hard,
        );
    }
    if clamped < requested_workers {
        crate::mprintln!(
            "[!] {}: clamped workers {} -> {} to fit usable_fds={} (fds_per_worker={}) / nproc_soft={}",
            module, requested_workers, clamped, limits.usable_fds,
            fds_per_worker, limits.nproc_soft,
        );
    }
    (clamped, Some(limits))
}

/// Build a `sockaddr_in` for an IPv4 destination, ready to hand to libc.
///
/// The returned struct is a POSIX POD value with `sin_family = AF_INET` and
/// `sin_addr` populated from the supplied `Ipv4Addr`. `sin_port` and
/// `sin_zero` are left zero — appropriate for raw `sendto`/`sendmmsg` calls
/// where the L4 port lives inside the user-built packet, not the sockaddr.
#[inline]
pub fn make_dst_sockaddr(ip: Ipv4Addr) -> libc::sockaddr_in {
    // SAFETY: `sockaddr_in` is a POSIX POD struct with no Rust-side
    // invariants. The all-zero value is the canonical "uninitialized" state;
    // we then populate `sin_family` and `sin_addr` before any libc call
    // observes it.
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(ip.octets()),
    };
    addr
}

/// Build a `sockaddr_in6` for an IPv6 destination.
///
/// `scope_id` is required for link-local addresses (`fe80::/10`); pass `0`
/// for global unicast. `sin6_flowinfo` is left zero. As with the IPv4
/// variant, `sin6_port` is left zero — for raw sockets the L4 port lives
/// in the user-built packet, not the sockaddr.
#[inline]
#[allow(dead_code)] // public helper for IPv6-aware DoS modules
pub fn make_dst_sockaddr_v6(ip: Ipv6Addr, scope_id: u32) -> libc::sockaddr_in6 {
    // SAFETY: `sockaddr_in6` is a POSIX POD struct; same reasoning as the
    // IPv4 variant — we zero-initialise then populate the fields the kernel
    // actually reads.
    let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    addr.sin6_addr = libc::in6_addr {
        s6_addr: ip.octets(),
    };
    addr.sin6_scope_id = scope_id;
    addr
}

/// Family-agnostic destination wrapper. Carries the family + the right
/// sockaddr variant + the `socklen_t` value the kernel expects for a given
/// `sendto` call. Use with [`make_dst_sockaddr_any`] / [`send_one_raw_any`]
/// when the module needs to support both IPv4 and IPv6 targets.
#[allow(dead_code)] // public helper, used by family-agnostic modules
pub enum DstAddr {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
}

impl DstAddr {
    /// Pointer + length the kernel needs for `sendto`. The lifetime ties
    /// the pointer to `&self`, so it's only valid for the duration of the
    /// borrow — which is exactly what `sendto` needs.
    #[inline]
    #[allow(dead_code)]
    pub fn as_ptr_len(&self) -> (*const libc::sockaddr, libc::socklen_t) {
        match self {
            DstAddr::V4(a) => (
                a as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ),
            DstAddr::V6(a) => (
                a as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ),
        }
    }
}

/// Family-agnostic builder. For IPv6 link-local targets where `scope_id`
/// matters, build the `sockaddr_in6` directly with [`make_dst_sockaddr_v6`]
/// and wrap with [`DstAddr::V6`] — this convenience uses `scope_id = 0`.
#[inline]
#[allow(dead_code)]
pub fn make_dst_sockaddr_any(ip: IpAddr) -> DstAddr {
    match ip {
        IpAddr::V4(v4) => DstAddr::V4(make_dst_sockaddr(v4)),
        IpAddr::V6(v6) => DstAddr::V6(make_dst_sockaddr_v6(v6, 0)),
    }
}

/// Send a single raw datagram via `sendto(2)` to an IPv4 destination.
///
/// Returns the number of bytes the kernel accepted on success, or the
/// underlying I/O error on failure. The caller is responsible for owning
/// `fd` and for matching `dst.sin_family` to whatever socket family `fd`
/// was opened with (this helper assumes AF_INET).
#[inline]
pub fn send_one_raw(
    fd: i32,
    buf: &[u8],
    dst: &libc::sockaddr_in,
) -> std::io::Result<usize> {
    // SAFETY: caller owns `fd` (a valid open socket); `buf` is a Rust slice
    // so the `(ptr, len)` pair points to `buf.len()` initialised bytes;
    // `dst` is a valid `&sockaddr_in` whose layout is ABI-compatible with
    // `sockaddr` for `sin_family == AF_INET` (POSIX guarantees the prefix
    // layout).
    let ret = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            0,
            dst as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

/// IPv6 counterpart of [`send_one_raw`]. Caller is responsible for the
/// `fd` being an AF_INET6 raw socket.
#[inline]
#[allow(dead_code)]
pub fn send_one_raw_v6(
    fd: i32,
    buf: &[u8],
    dst: &libc::sockaddr_in6,
) -> std::io::Result<usize> {
    // SAFETY: identical contract to `send_one_raw` but for the IPv6 sockaddr.
    let ret = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            0,
            dst as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

/// Family-agnostic `sendto`. The right `socklen_t` is computed from the
/// `DstAddr` variant — caller doesn't have to remember IPv4 vs IPv6 sizes.
#[inline]
#[allow(dead_code)]
pub fn send_one_raw_any(
    fd: i32,
    buf: &[u8],
    dst: &DstAddr,
) -> std::io::Result<usize> {
    let (ptr, len) = dst.as_ptr_len();
    // SAFETY: same reasoning as `send_one_raw` but length comes from
    // `DstAddr::as_ptr_len`, which returns the exact `socklen_t` the
    // kernel expects for the wrapped sockaddr family.
    let ret = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            0,
            ptr,
            len,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

use std::os::fd::FromRawFd;

/// Read the libc errno value for the current thread, in a portable way.
pub fn errno() -> i32 {
    // SAFETY: `__errno_location` / `__error` return a valid pointer to a
    // thread-local int that remains valid for the duration of the thread; a
    // single `*ptr` read of a primitive `c_int` cannot violate any invariant.
    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    unsafe {
        *libc::__error()
    }

    #[cfg(target_os = "linux")]
    // SAFETY: see comment above; `__errno_location` mirrors the BSD `__error`.
    unsafe {
        *libc::__errno_location()
    }

    // Fallback for other Unixes: errno isn't reliably accessible without a
    // platform-specific symbol, so callers will see `0`.
    #[cfg(not(any(target_os = "freebsd", target_os = "macos", target_os = "linux")))]
    {
        0
    }
}

/// Save the original stdout (fd 1) into a new fd, then redirect fd 1 to
/// `/dev/null`. The returned tokio file is the *only* remaining handle to the
/// original stdout — used by the MCP server to emit JSON-RPC responses on a
/// channel that user-mode `println!` calls can no longer corrupt.
pub fn isolate_protocol_stdout() -> anyhow::Result<tokio::fs::File> {
    // SAFETY: `dup(1)` is a no-arg syscall that returns either a fresh valid
    // fd or -1. We immediately check the return value before doing anything
    // that depends on its validity.
    let saved_fd = unsafe { libc::dup(1) };
    if saved_fd < 0 {
        anyhow::bail!("dup(1) failed: errno {}", errno());
    }

    let null_path = b"/dev/null\0";
    // SAFETY: `null_path` is a NUL-terminated, statically-allocated byte
    // string with a pointer valid for the duration of the call; `O_WRONLY` is
    // a libc-defined constant. `open` returns -1 on failure, checked below.
    let null_fd = unsafe { libc::open(null_path.as_ptr() as *const libc::c_char, libc::O_WRONLY) };
    if null_fd < 0 {
        // SAFETY: `saved_fd` is a valid open fd we just received from `dup`.
        unsafe {
            libc::close(saved_fd);
        }
        anyhow::bail!("open(/dev/null) failed: errno {}", errno());
    }

    // SAFETY: `null_fd` and `1` are both valid open fds (1 is stdout; the
    // dup above proved it is open and non-error). `dup2` either succeeds and
    // installs `null_fd` as fd 1, or returns -1.
    let dup2_ret = unsafe { libc::dup2(null_fd, 1) };
    if dup2_ret < 0 {
        // SAFETY: both fds are valid open descriptors at this point.
        unsafe {
            libc::close(null_fd);
            libc::close(saved_fd);
        }
        anyhow::bail!("dup2(null, 1) failed: errno {}", errno());
    }
    // SAFETY: `null_fd` is a valid open fd; closing the source after a
    // successful `dup2` is the standard idiom — fd 1 keeps the kernel-side
    // open file description alive.
    unsafe {
        libc::close(null_fd);
    }

    // SAFETY: `saved_fd` is owned by us (returned by `dup`, never close()d
    // here, never given to anyone else); transferring it into a `File` makes
    // that file the sole owner so the eventual Drop closes it exactly once.
    let std_file = unsafe { std::fs::File::from_raw_fd(saved_fd) };
    Ok(tokio::fs::File::from_std(std_file))
}

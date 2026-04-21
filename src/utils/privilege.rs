// src/utils/privilege.rs
//
// Helper for modules that need elevated privileges (raw sockets, ICMP, etc.).
// Rather than letting the underlying socket bind fail with a cryptic
// "permission denied", modules call `require_root("context")` at the top of
// `run()` and get back a clean `anyhow::Error` if the current euid isn't 0.

use anyhow::{bail, Result};

/// Returns `Ok(())` if the current effective UID is root (0), otherwise a
/// friendly error mentioning the context (e.g. "icmp raw socket") so the
/// caller knows why root was required.
pub fn require_root(context: &str) -> Result<()> {
    // SAFETY: `geteuid` is a simple syscall with no args and no unsafe state.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        Ok(())
    } else {
        bail!(
            "{} requires root privileges (current euid={}). Re-run with sudo.",
            context,
            euid
        );
    }
}

/// Set file permissions (mode bits) for security-sensitive files.
/// Thin wrapper over `std::fs::set_permissions` that uses the unix mode bits
/// directly. Callers MUST handle the returned `Result` — a silent chmod
/// failure leaves the file world-readable.
pub fn set_secure_permissions<P: AsRef<std::path::Path>>(path: P, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Async variant of `set_secure_permissions` for tokio contexts.
pub async fn set_secure_permissions_async<P: AsRef<std::path::Path>>(path: P, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await
}

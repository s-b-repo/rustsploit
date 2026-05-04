use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use anyhow::{anyhow, Context, Result};
use colored::*;
use once_cell::sync::Lazy;

/// Global spool state for console logging.
pub struct SpoolState {
    file: RwLock<Option<(File, String)>>, // (file handle, filename)
}

impl SpoolState {
    fn new() -> Self {
        Self {
            file: RwLock::new(None),
        }
    }

    /// Start spooling to a file.
    /// Path is validated against traversal, absolute paths, and symlinks.
    pub fn start(&self, path: &str) -> Result<()> {
        // Reject path traversal
        if path.contains("..") || path.contains('\0') {
            return Err(anyhow!("Path traversal not allowed in spool path {:?}", path));
        }
        // Reject absolute paths — spool files must be relative to CWD
        let p = Path::new(path);
        if p.is_absolute() {
            return Err(anyhow!(
                "Absolute paths not allowed for spool files. Use a relative path. Got: {:?}",
                path
            ));
        }
        // Reject paths with directory components to prevent writing outside CWD
        if let Some(parent) = p.parent() {
            if parent != Path::new("") {
                // Ensure parent directory exists
                let resolved = resolve_spool_path(path)?;
                return self.start_at_path(&resolved, path);
            }
        }
        // Simple filename — write in CWD
        self.start_at_path(&PathBuf::from(path), path)
    }

    fn start_at_path(&self, resolved: &Path, display_name: &str) -> Result<()> {
        let mut guard = self
            .file
            .write()
            .map_err(|e| anyhow!("Failed to acquire spool lock: {}", e))?;

        use std::fs::OpenOptions;
        #[cfg(unix)]
        let open_result = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(resolved)
        };
        #[cfg(not(unix))]
        let open_result = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(resolved);
        let mut file = open_result
            .with_context(|| format!("Failed to create spool file at {:?}", resolved))?;
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        if let Err(e) = writeln!(file, "# RustSploit Console Log - Started {}", ts) {
            eprintln!("[!] Spool write error: {}", e);
        }
        if let Err(e) = writeln!(file, "# ==========================================") {
            eprintln!("[!] Spool write error: {}", e);
        }
        if let Err(e) = writeln!(file) {
            eprintln!("[!] Spool write error: {}", e);
        }
        if let Err(e) = file.flush() {
            eprintln!("[!] Flush error: {}", e);
        }
        *guard = Some((file, display_name.to_string()));
        Ok(())
    }

    /// Stop spooling.
    pub fn stop(&self) -> Option<String> {
        let mut guard = match self.file.write() {
            Ok(g) => g,
            Err(e) => {
                eprintln!("[!] Spool stop: lock poisoned: {}", e);
                return None;
            }
        };
        let (mut file, name) = guard.take()?;
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        if let Err(e) = writeln!(file) {
            eprintln!("[!] Spool write error: {}", e);
        }
        if let Err(e) = writeln!(file, "# Spool ended {}", ts) {
            eprintln!("[!] Spool write error: {}", e);
        }
        if let Err(e) = file.flush() {
            eprintln!("[!] Flush error: {}", e);
        }
        Some(name)
    }

    /// Check if spooling is active.
    pub fn is_active(&self) -> bool {
        match self.file.read() {
            Ok(g) => g.is_some(),
            Err(e) => {
                eprintln!("[!] Spool is_active: lock poisoned: {}", e);
                false
            }
        }
    }

    /// Get the current spool filename.
    pub fn current_file(&self) -> Option<String> {
        let g = self.file.read().ok()?;
        g.as_ref().map(|(_, name)| name.clone())
    }

    /// Write a line to the spool file (if active).
    /// Format the line outside the lock, then issue a single write_all under
    /// the lock so we minimise lock-hold time (every console print routes
    /// through here). `File::flush` is a no-op on `std::fs::File`; durability
    /// comes from the write syscall itself.
    pub fn write_line(&self, msg: &str) -> Result<(), std::io::Error> {
        // Fast-path: skip lock entirely if no spool file is active.
        if let Ok(g) = self.file.read() {
            if g.is_none() {
                return Ok(());
            }
        }
        let mut buf = String::with_capacity(msg.len() + 1);
        buf.push_str(msg);
        buf.push('\n');
        let mut guard = match self.file.write() {
            Ok(g) => g,
            Err(_) => return Ok(()), // poisoned: silently no-op
        };
        if let Some((ref mut file, _)) = *guard {
            file.write_all(buf.as_bytes())?;
        }
        Ok(())
    }
}

fn resolve_spool_path(path: &str) -> Result<PathBuf> {
    let p = PathBuf::from(path);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            if !parent.exists() {
                return Err(anyhow!(
                    "Parent directory '{}' does not exist",
                    parent.display()
                ));
            }
            // Bug #96: O_NOFOLLOW on the target file is not enough — if the
            // parent directory is itself a symlink (e.g. `./logs` → /tmp/evil),
            // the spool file gets written inside the symlink target. Reject
            // symlinked parents so spool files stay in the intended CWD subtree.
            match std::fs::symlink_metadata(parent) {
                Ok(md) if md.file_type().is_symlink() => {
                    return Err(anyhow!(
                        "Parent directory '{}' is a symlink — refusing to spool through it",
                        parent.display()
                    ));
                }
                Ok(_) => {}
                Err(e) => {
                    return Err(anyhow!(
                        "Failed to stat parent directory '{}': {}",
                        parent.display(),
                        e
                    ));
                }
            }
        }
    }
    Ok(p)
}

pub static SPOOL: Lazy<SpoolState> = Lazy::new(SpoolState::new);

/// Write a message to both stdout and the spool file.
pub fn sprintln(msg: &str) {
    println!("{}", msg);
    if let Err(e) = SPOOL.write_line(msg) {
        eprintln!("[!] Spool write error: {}", e);
    }
}

/// Display spool status.
pub fn display_status() {
    if let Some(name) = SPOOL.current_file() {
        println!("{}", format!("Spool active: writing to '{}'", name).green());
    } else {
        println!("{}", "Spool is not active.".dimmed());
    }
}

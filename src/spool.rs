use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::LazyLock as Lazy;
use colored::*;

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
    pub fn start(&self, path: &str) -> Result<(), String> {
        // Reject path traversal
        if path.contains("..") || path.contains('\0') {
            return Err("Path traversal not allowed".to_string());
        }
        // Reject absolute paths — spool files must be relative to CWD
        let p = Path::new(path);
        if p.is_absolute() {
            return Err("Absolute paths not allowed for spool files. Use a relative path.".to_string());
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

    fn start_at_path(&self, resolved: &Path, display_name: &str) -> Result<(), String> {
        // Acquire lock FIRST (before creating file) to prevent orphaned files
        let mut guard = self.file.write().map_err(|_| "Failed to acquire spool lock".to_string())?;

        // Open file with O_NOFOLLOW to atomically reject symlinks.
        // This prevents the TOCTOU race where an attacker swaps the file
        // with a symlink between the check and open().
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
        let open_result = OpenOptions::new().write(true).create(true).truncate(true).open(resolved);
        match open_result {
            Ok(f) => {
                let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                let mut file = f;
                if let Err(e) = writeln!(file, "# RustSploit Console Log - Started {}", ts) { eprintln!("[!] Spool write error: {}", e); }
                if let Err(e) = writeln!(file, "# ==========================================") { eprintln!("[!] Spool write error: {}", e); }
                if let Err(e) = writeln!(file) { eprintln!("[!] Spool write error: {}", e); }
                if let Err(e) = file.flush() { eprintln!("[!] Flush error: {}", e); }
                *guard = Some((file, display_name.to_string()));
                Ok(())
            }
            Err(e) => Err(format!("Failed to create spool file: {}", e)),
        }
    }

    /// Stop spooling.
    pub fn stop(&self) -> Option<String> {
        if let Ok(mut guard) = self.file.write() {
            if let Some((mut file, name)) = guard.take() {
                let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                if let Err(e) = writeln!(file) { eprintln!("[!] Spool write error: {}", e); }
                if let Err(e) = writeln!(file, "# Spool ended {}", ts) { eprintln!("[!] Spool write error: {}", e); }
                if let Err(e) = file.flush() { eprintln!("[!] Flush error: {}", e); }
                return Some(name);
            }
        }
        None
    }

    /// Check if spooling is active.
    pub fn is_active(&self) -> bool {
        self.file.read().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Get the current spool filename.
    pub fn current_file(&self) -> Option<String> {
        self.file.read().ok()?.as_ref().map(|(_, name)| name.clone())
    }

    /// Write a line to the spool file (if active). Flushes after write (BUG 11 fix).
    pub fn write_line(&self, msg: &str) {
        if let Ok(mut guard) = self.file.write() {
            if let Some((ref mut file, _)) = *guard {
                if let Err(e) = writeln!(file, "{}", msg) {
                    eprintln!("[!] Spool write error: {}", e);
                } else {
                    if let Err(e) = file.flush() { eprintln!("[!] Flush error: {}", e); }
                }
            }
        }
    }
}

fn resolve_spool_path(path: &str) -> Result<PathBuf, String> {
    let p = PathBuf::from(path);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            if !parent.exists() {
                return Err(format!("Parent directory '{}' does not exist", parent.display()));
            }
            // Bug #96: O_NOFOLLOW on the target file is not enough — if the
            // parent directory is itself a symlink (e.g. `./logs` → /tmp/evil),
            // the spool file gets written inside the symlink target. Reject
            // symlinked parents so spool files stay in the intended CWD subtree.
            match std::fs::symlink_metadata(parent) {
                Ok(md) if md.file_type().is_symlink() => {
                    return Err(format!(
                        "Parent directory '{}' is a symlink — refusing to spool through it",
                        parent.display()
                    ));
                }
                Ok(_) => {}
                Err(e) => {
                    return Err(format!(
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
    SPOOL.write_line(msg);
}

/// Display spool status.
pub fn display_status() {
    if let Some(name) = SPOOL.current_file() {
        println!("{}", format!("Spool active: writing to '{}'", name).green());
    } else {
        println!("{}", "Spool is not active.".dimmed());
    }
}

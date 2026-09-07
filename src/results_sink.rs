// src/results_sink.rs
//
// Per-run auto-save. When active, every console line a module emits is appended
// to `~/.rustsploit/loot/<module> <time> results.txt`. This mirrors the
// global-write pattern of `crate::spool` (so output from spawned per-host tasks
// in a mass scan is captured too), but it APPENDS rather than truncates and
// writes under the loot directory with an auto-generated, per-run filename.
//
// The caller (`commands::run_module`) scopes this to interactive console / CLI
// runs only — those are sequential, so a single global handle is race-free.
// API / MCP runs already return their captured output to the caller via
// `OUTPUT_BUFFER`, so they are not auto-saved here.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::RwLock;

use once_cell::sync::Lazy;

/// The active per-run results file, or `None` when no run is being saved.
static SINK: Lazy<RwLock<Option<File>>> = Lazy::new(|| RwLock::new(None));

/// Warn at most once if appends start failing (e.g. disk full), so a broken
/// sink can't flood the console with one error per output line.
static WRITE_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn warn_once(e: std::io::Error) {
    if !WRITE_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!("[!] Results auto-save write failed (further errors suppressed): {e}");
    }
}

/// Acquire the sink write lock, recovering from a poisoned lock rather than
/// panicking — the guarded value is just an `Option<File>` with no broken
/// invariant a prior panic could have left behind.
fn sink_write() -> std::sync::RwLockWriteGuard<'static, Option<File>> {
    match SINK.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn sink_read() -> std::sync::RwLockReadGuard<'static, Option<File>> {
    match SINK.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Begin auto-saving the current run's output. Opens (in APPEND mode) the
/// per-run file `<loot>/<module> <YYYY-MM-DD_HH-MM-SS> results.txt` and makes it
/// the active sink. Failure is non-fatal: the run continues, just unsaved.
pub fn begin(module_path: &str) {
    // Tenant-scoped loot directory (falls back to the global ~/.rustsploit/loot
    // store in shell/CLI mode); the store creates the directory if needed.
    let loot_dir = crate::tenant::resolve()
        .loot_store()
        .loot_directory()
        .clone();

    // Module paths contain `/` (e.g. "scanners/service_scanner"); flatten them so
    // the result is a single file rather than a nested path.
    let safe_module = module_path.replace(['/', '\\'], "_");
    let ts = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
    let file_name = format!("{safe_module} {ts} results.txt");
    let path = loot_dir.join(&file_name);

    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut file) => {
            let stamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            if let Err(e) = writeln!(file, "\n# === {module_path} @ {stamp} ===") {
                warn_once(e);
            }
            *sink_write() = Some(file);
        }
        Err(e) => {
            crate::meprintln!("[!] Could not open results file {}: {e}", path.display());
        }
    }
}

/// Stop auto-saving the current run and drop the file handle.
pub fn end() {
    *sink_write() = None;
}

/// Append a line (with newline) to the active sink, if any. Invoked from the
/// console output routing functions next to the real stdout/stderr write.
pub fn write_line(text: &str) {
    let guard = sink_read();
    if let Some(file) = guard.as_ref() {
        // `impl Write for &File` lets concurrent tasks append through a shared
        // read guard without taking the write lock per line.
        let mut handle: &File = file;
        if let Err(e) = writeln!(handle, "{text}") {
            warn_once(e);
        }
    }
}

/// Append raw text (no trailing newline) to the active sink, if any.
pub fn write_raw(text: &str) {
    let guard = sink_read();
    if let Some(file) = guard.as_ref() {
        let mut handle: &File = file;
        if let Err(e) = write!(handle, "{text}") {
            warn_once(e);
        }
    }
}

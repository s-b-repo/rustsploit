// src/output.rs
//
// Per-task output capture system. Replaces process-global gag::BufferRedirect
// with a task-local buffer so multiple API requests can run modules concurrently.
//
// Shell mode: macros write to real stdout/stderr + spool.
// API mode:   macros write to a task-local OutputBuffer.

use std::sync::{Arc, Mutex};

use serde::Serialize;

// ============================================================
// OUTPUT BUFFER (task-local text capture)
// ============================================================

/// Thread-safe text buffer for capturing module output.
/// Uses std::sync::Mutex (not tokio) so it works in both sync and async contexts.
#[derive(Debug, Clone, Default)]
pub struct OutputBuffer {
    stdout: Arc<Mutex<Vec<String>>>,
    stderr: Arc<Mutex<Vec<String>>>,
}

impl OutputBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    const MAX_BUFFER_LINES: usize = 100_000;

    /// Warn once when a buffer hits capacity.
    fn warn_truncated(label: &str) {
        static STDOUT_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        static STDERR_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        let flag = match label {
            "stdout" => &STDOUT_WARNED,
            _ => &STDERR_WARNED,
        };
        if !flag.swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!("[!] Output buffer ({}) reached {} lines — further output truncated", label, Self::MAX_BUFFER_LINES);
        }
    }

    pub fn push_stdout(&self, text: String) {
        let mut guard = self.stdout.lock().unwrap_or_else(|e| e.into_inner());
        if guard.len() < Self::MAX_BUFFER_LINES {
            guard.push(text);
        } else {
            Self::warn_truncated("stdout");
        }
    }

    pub fn push_stderr(&self, text: String) {
        let mut guard = self.stderr.lock().unwrap_or_else(|e| e.into_inner());
        if guard.len() < Self::MAX_BUFFER_LINES {
            guard.push(text);
        } else {
            Self::warn_truncated("stderr");
        }
    }

    pub fn drain_stdout(&self) -> String {
        let mut guard = self.stdout.lock().unwrap_or_else(|e| e.into_inner());
        let mut result = String::new();
        for line in guard.drain(..) {
            result.push_str(&line);
        }
        result
    }

    pub fn drain_stderr(&self) -> String {
        let mut guard = self.stderr.lock().unwrap_or_else(|e| e.into_inner());
        let mut result = String::new();
        for line in guard.drain(..) {
            result.push_str(&line);
        }
        result
    }
}

tokio::task_local! {
    /// When set, mprintln!/meprintln!/mprint!/meprint! write here instead
    /// of real stdout/stderr. Set by the API handler before module execution.
    pub static OUTPUT_BUFFER: OutputBuffer;
}

// ============================================================
// MACROS — drop-in replacements for println!/eprintln!/print!/eprint!
// ============================================================

/// Write a line to the output buffer (API mode) or stdout + spool (shell mode).
#[macro_export]
macro_rules! mprintln {
    () => { $crate::output::_mprint_newline() };
    ($($arg:tt)*) => {{
        $crate::output::_mprint_line(&format!($($arg)*))
    }};
}

/// Write a line to the output buffer (API mode) or stderr (shell mode).
#[macro_export]
macro_rules! meprintln {
    () => { $crate::output::_meprint_newline() };
    ($($arg:tt)*) => {{
        $crate::output::_meprint_line(&format!($($arg)*))
    }};
}

/// Write multiple lines atomically — concurrent tasks cannot interleave.
/// Usage: `mprintln_block!("line1", "line2", "line3");`
#[macro_export]
macro_rules! mprintln_block {
    ($($line:expr),+ $(,)?) => {{
        $crate::output::_mprint_block(&[$(& $line.to_string()),+])
    }};
}

/// Write text without newline to the buffer (API) or stdout (shell).
#[macro_export]
macro_rules! mprint {
    ($($arg:tt)*) => {{
        $crate::output::_mprint_raw(&format!($($arg)*))
    }};
}

/// Write text without newline to the buffer (API) or stderr (shell).
#[macro_export]
macro_rules! meprint {
    ($($arg:tt)*) => {{
        $crate::output::_meprint_raw(&format!($($arg)*))
    }};
}

// ============================================================
// INTERNAL ROUTING FUNCTIONS (called by macros)
// ============================================================

/// Global stdout lock for atomic multi-line output in shell mode.
/// Prevents concurrent tasks from interleaving lines within a block.
static STDOUT_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

static SPOOL_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn handle_spool_error(e: std::io::Error) {
    if !SPOOL_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!("[!] Spool write failed (further errors suppressed): {}", e);
    }
}

/// Route a line to buffer (stdout channel) or real stdout + spool.
pub fn _mprint_line(text: &str) {
    let buffered = OUTPUT_BUFFER.try_with(|buf| {
        buf.push_stdout(format!("{}\n", text));
    });
    if buffered.is_err() {
        println!("{}", text);
        if let Err(e) = crate::spool::SPOOL.write_line(text) {
            handle_spool_error(e);
        }
    }
}

/// Route a bare newline.
pub fn _mprint_newline() {
    let buffered = OUTPUT_BUFFER.try_with(|buf| {
        buf.push_stdout("\n".to_string());
    });
    if buffered.is_err() {
        println!();
        if let Err(e) = crate::spool::SPOOL.write_line("") {
            handle_spool_error(e);
        }
    }
}

/// Route raw text (no newline) to buffer or stdout + spool.
pub fn _mprint_raw(text: &str) {
    let buffered = OUTPUT_BUFFER.try_with(|buf| {
        buf.push_stdout(text.to_string());
    });
    if buffered.is_err() {
        use std::io::Write;
        print!("{}", text);
        let _ = std::io::stdout().flush();
        if let Err(e) = crate::spool::SPOOL.write_line(text) {
            handle_spool_error(e);
        }
    }
}

/// Write multiple lines atomically so concurrent tasks cannot interleave.
/// Each element is printed as a separate line. In API/buffer mode, lines are
/// pushed individually (the buffer is already per-task).
pub fn _mprint_block(lines: &[&str]) {
    let buffered = OUTPUT_BUFFER.try_with(|buf| {
        for line in lines {
            buf.push_stdout(format!("{}\n", line));
        }
    });
    if buffered.is_err() {
        let _guard = STDOUT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        for line in lines {
            println!("{}", line);
            if let Err(e) = crate::spool::SPOOL.write_line(line) {
                handle_spool_error(e);
            }
        }
    }
}

/// Route a line to buffer (stderr channel) or real stderr.
pub fn _meprint_line(text: &str) {
    let buffered = OUTPUT_BUFFER.try_with(|buf| {
        buf.push_stderr(format!("{}\n", text));
    });
    if buffered.is_err() {
        eprintln!("{}", text);
    }
}

/// Route a bare stderr newline.
pub fn _meprint_newline() {
    let buffered = OUTPUT_BUFFER.try_with(|buf| {
        buf.push_stderr("\n".to_string());
    });
    if buffered.is_err() {
        eprintln!();
    }
}

/// Route raw stderr text (no newline).
pub fn _meprint_raw(text: &str) {
    let buffered = OUTPUT_BUFFER.try_with(|buf| {
        buf.push_stderr(text.to_string());
    });
    if buffered.is_err() {
        use std::io::Write;
        eprint!("{}", text);
        let _ = std::io::stderr().flush();
    }
}

// ============================================================
// STRUCTURED MODULE OUTPUT
// ============================================================

/// Classification of a finding.
#[derive(Debug, Clone, Serialize)]
pub enum FindingType {
    Vulnerability,
    Misconfiguration,
    InfoDisclosure,
    OpenPort,
    ServiceDetected,
    CredentialFound,
    ExploitSuccess,
}

/// Severity of a finding.
#[derive(Debug, Clone, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// A structured finding from module execution.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub finding_type: FindingType,
    pub host: String,
    pub port: Option<u16>,
    pub detail: String,
    pub severity: Severity,
}

/// Accumulated structured output from a module run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ModuleOutput {
    pub findings: Vec<Finding>,
}

/// Accumulator stored in RunContext for structured output.
/// Modules call `output::add_finding()` to populate this.
#[derive(Debug, Default)]
pub struct OutputAccumulator {
    inner: Mutex<ModuleOutput>,
}

impl OutputAccumulator {
    const MAX_FINDINGS: usize = 10_000;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_finding(&self, finding: Finding) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if guard.findings.len() < Self::MAX_FINDINGS {
            guard.findings.push(finding);
        }
    }

    pub fn take(&self) -> ModuleOutput {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *guard)
    }
}

// ============================================================
// CONVENIENCE FUNCTIONS (use task-local RunContext)
// ============================================================

/// Record a structured finding. Silently no-ops if no RunContext is active.
pub fn add_finding(finding: Finding) {
    let _ = crate::context::RUN_CONTEXT.try_with(|ctx| {
        ctx.output.add_finding(finding);
    });
}

// ============================================================
// TESTS
// ============================================================


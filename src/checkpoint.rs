// src/checkpoint.rs
//
// Crash-resumable checkpoints for long-running mass scans.
//
// The scheduler periodically writes the set of already-processed targets to
// `~/.rustsploit/checkpoints/<scan_id>.json`. On restart, `--resume <scan_id>`
// loads the file, skips processed targets, and continues from where the
// crash interrupted.
//
// Format (append-only, line-delimited):
//   line 1:  {"scan_id":"...","module":"scanners/port_scanner","target":"10.0.0.0/16","started":"2026-05-07T..."}
//   line 2+: one processed target per line ("10.0.0.1", "10.0.0.2", ...)
//
// Each flush *appends* only the newly-processed targets rather than
// re-serializing the entire (potentially multi-million entry) set, so the
// total bytes written over a scan is O(n) instead of O(n²). Bounded by
// `MAX_CHECKPOINT_ENTRIES` to keep memory + disk usage in check on huge scans.
// A crash may leave a partial trailing line; the loader simply ignores any
// line that isn't a valid entry.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

const MAX_CHECKPOINT_ENTRIES: usize = 10_000_000;
const FLUSH_EVERY_N: usize = 200;

/// In-memory / returned representation of a checkpoint.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    pub scan_id: String,
    pub module: String,
    pub target: String,
    pub started: String,
    pub processed: Vec<String>,
}

/// On-disk header line (everything except the processed entries, which are
/// stored one-per-line after it).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckpointHeader {
    scan_id: String,
    module: String,
    target: String,
    started: String,
}

/// Read an append-only checkpoint file into a `Checkpoint`. The first line is
/// the JSON header; each subsequent non-empty line is a processed target.
/// Malformed lines (e.g. a torn final line after a crash) are skipped.
fn load_from_path(path: &Path) -> Result<Checkpoint> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let mut lines = raw.lines();
    let header_line = lines.next().unwrap_or("");
    let header: CheckpointHeader = serde_json::from_str(header_line)
        .with_context(|| format!("parse header of {}", path.display()))?;
    let processed: Vec<String> = lines
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect();
    Ok(Checkpoint {
        scan_id: header.scan_id,
        module: header.module,
        target: header.target,
        started: header.started,
        processed,
    })
}

/// Live writer for an in-progress scan. Tracks processed targets in memory
/// (bounded by `MAX_CHECKPOINT_ENTRIES`) and flushes to disk every
/// `FLUSH_EVERY_N` records or when explicitly requested.
pub struct CheckpointWriter {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    cp: Checkpoint,
    seen: HashSet<String>,
    pending_writes: usize,
    /// Count of `cp.processed` entries already appended to disk.
    persisted: usize,
    /// Whether the header line has been written (true for resumed files).
    header_written: bool,
    /// Set once the entry cap is hit, so the "records dropped" warning is
    /// emitted a single time rather than per-record.
    cap_warned: bool,
    path: PathBuf,
    closed: bool,
}

impl CheckpointWriter {
    /// Create or resume a checkpoint. If `~/.rustsploit/checkpoints/<scan_id>.json`
    /// already exists, the previously-processed set is loaded.
    pub fn open(scan_id: &str, module: &str, target: &str) -> Result<Self> {
        let path = checkpoint_path(scan_id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        let exists = path.exists();
        let cp = if exists {
            load_from_path(&path)?
        } else {
            Checkpoint {
                scan_id: scan_id.to_string(),
                module: module.to_string(),
                target: target.to_string(),
                started: chrono::Utc::now().to_rfc3339(),
                processed: Vec::new(),
            }
        };
        let seen: HashSet<String> = cp.processed.iter().cloned().collect();
        let persisted = cp.processed.len();
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                cp,
                seen,
                pending_writes: 0,
                persisted,
                header_written: exists,
                cap_warned: false,
                path,
                closed: false,
            })),
        })
    }

    /// True if the given target was already processed in a prior run.
    pub async fn already_processed(&self, target: &str) -> bool {
        let g = self.inner.lock().await;
        g.seen.contains(target)
    }

    /// Mark a target processed. Triggers a disk flush every `FLUSH_EVERY_N`.
    pub async fn record(&self, target: &str) -> Result<()> {
        let mut g = self.inner.lock().await;
        if g.seen.len() >= MAX_CHECKPOINT_ENTRIES {
            // Past the cap we can no longer persist progress; targets recorded
            // from here on will be re-scanned on resume. Surface this once
            // instead of silently dropping records (which would look identical
            // to "successfully checkpointed").
            if !g.cap_warned {
                g.cap_warned = true;
                tracing::warn!(
                    "checkpoint entry cap ({}) reached — further targets will not be persisted and may be re-scanned on resume",
                    MAX_CHECKPOINT_ENTRIES
                );
            }
            return Ok(());
        }
        if !g.seen.insert(target.to_string()) {
            return Ok(());
        }
        g.cp.processed.push(target.to_string());
        g.pending_writes += 1;
        if g.pending_writes >= FLUSH_EVERY_N {
            flush_locked(&mut g).await?;
        }
        Ok(())
    }

    /// Force a flush to disk (call before exiting cleanly).
    pub async fn flush(&self) -> Result<()> {
        let mut g = self.inner.lock().await;
        if !g.closed {
            flush_locked(&mut g).await?;
        }
        Ok(())
    }

    /// Mark the checkpoint complete and remove the file.
    pub async fn finish(&self) -> Result<()> {
        let mut g = self.inner.lock().await;
        g.closed = true;
        if g.path.exists() {
            tokio::fs::remove_file(&g.path).await
                .with_context(|| format!("rm {}", g.path.display()))?;
        }
        Ok(())
    }

    /// Number of targets already processed.
    pub async fn count(&self) -> usize {
        self.inner.lock().await.seen.len()
    }
}

async fn flush_locked(g: &mut tokio::sync::MutexGuard<'_, Inner>) -> Result<()> {
    // Build only the not-yet-persisted suffix so each flush is O(batch).
    let mut buf = String::new();
    if !g.header_written {
        let header = CheckpointHeader {
            scan_id: g.cp.scan_id.clone(),
            module: g.cp.module.clone(),
            target: g.cp.target.clone(),
            started: g.cp.started.clone(),
        };
        buf.push_str(&serde_json::to_string(&header)?);
        buf.push('\n');
    }
    for entry in &g.cp.processed[g.persisted..] {
        // Entries are IPs/hostnames; guard against any stray newline so the
        // line-delimited format stays parseable.
        buf.push_str(&entry.replace(['\n', '\r'], ""));
        buf.push('\n');
    }

    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&g.path)
        .await
        .with_context(|| format!("open {} for append", g.path.display()))?;
    file.write_all(buf.as_bytes())
        .await
        .with_context(|| format!("append {}", g.path.display()))?;
    // Propagate flush failures: if the bytes did not reach the OS we must NOT
    // advance `persisted`/`header_written` below, or those entries would never
    // be re-appended and the checkpoint would silently lose processed hosts.
    file.flush()
        .await
        .with_context(|| format!("flush {}", g.path.display()))?;

    g.header_written = true;
    g.persisted = g.cp.processed.len();
    g.pending_writes = 0;
    Ok(())
}

/// Base checkpoints directory for the current tenant.
///
/// In multi-tenant API mode each tenant gets its own namespace
/// (`~/.rustsploit/checkpoints/tenants/<tenant>/`) so concurrent tenants
/// scanning the same module+target do not share one checkpoint file (which
/// would cross-leak processed targets, interleave appends, and let one
/// tenant's `finish()` delete the file out from under another). Shell mode
/// (no tenant context) keeps the historical process-global path
/// (`~/.rustsploit/checkpoints/`) for backwards compatibility.
fn checkpoints_base_dir() -> PathBuf {
    let base = home::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".rustsploit")
        .join("checkpoints");
    match crate::context::current_tenant_id() {
        Some(tid) => {
            let tid = sanitize(&tid);
            if tid.is_empty() {
                base
            } else {
                base.join("tenants").join(tid)
            }
        }
        None => base,
    }
}

fn checkpoint_path(scan_id: &str) -> PathBuf {
    checkpoints_base_dir().join(format!("{}.json", sanitize(scan_id)))
}

// ---- Sequential-scan high-water-mark resume -----------------------------
//
// A sequential full-public-IPv4 sweep can dispatch billions of addresses, so
// the per-target set used by random/CIDR scans does not scale. Sequential scans
// instead store a single high-water IPv4 (as a u32) — the last dispatched
// address — and resume from `hi + 1`.

fn seq_marker_path(scan_id: &str) -> PathBuf {
    checkpoints_base_dir().join(format!("{}.seq", sanitize(scan_id)))
}

/// Read the sequential resume point (last dispatched IPv4 as u32), if any.
pub fn read_seq_marker(scan_id: &str) -> Option<u32> {
    let path = seq_marker_path(scan_id);
    match std::fs::read_to_string(&path) {
        Ok(s) => match s.trim().parse::<u32>() {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::debug!("seq marker {} unparseable: {e}", path.display());
                None
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::debug!("seq marker read {} failed: {e}", path.display());
            None
        }
    }
}

/// Persist the sequential high-water IPv4 (best-effort; logs at debug on error).
pub fn write_seq_marker(scan_id: &str, ip: u32) {
    let path = seq_marker_path(scan_id);
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        tracing::debug!("seq marker mkdir {} failed: {e}", parent.display());
        return;
    }
    if let Err(e) = std::fs::write(&path, ip.to_string()) {
        tracing::debug!("seq marker write {} failed: {e}", path.display());
    }
}

/// Remove the sequential marker on clean completion (best-effort).
pub fn clear_seq_marker(scan_id: &str) {
    let path = seq_marker_path(scan_id);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::debug!("seq marker remove {} failed: {e}", path.display()),
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Collect `*.json` checkpoints directly inside `dir` into `out` (non-recursive).
fn collect_checkpoints_in(dir: &Path, out: &mut Vec<Checkpoint>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => { tracing::debug!("skipping checkpoint dir {}: {e}", dir.display()); return; }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match load_from_path(&path) {
            Ok(cp) => out.push(cp),
            Err(e) => { tracing::debug!("skipping unreadable checkpoint {}: {e}", path.display()); }
        }
    }
}

/// List all on-disk checkpoints (for `rustsploit --list-checkpoints`).
///
/// Includes the process-global checkpoints (shell mode) plus every
/// per-tenant namespace under `checkpoints/tenants/<tenant>/`, so the
/// listing is complete regardless of which tenant wrote each one.
pub fn list_checkpoints() -> Result<Vec<Checkpoint>> {
    let dir = home::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".rustsploit")
        .join("checkpoints");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    // Process-global (shell-mode) checkpoints.
    collect_checkpoints_in(&dir, &mut out);
    // Per-tenant namespaces.
    let tenants_dir = dir.join("tenants");
    if tenants_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&tenants_dir) {
            for entry in entries.flatten() {
                let tpath = entry.path();
                if tpath.is_dir() {
                    collect_checkpoints_in(&tpath, &mut out);
                }
            }
        }
    }
    out.sort_by(|a, b| a.started.cmp(&b.started));
    Ok(out)
}

/// Generate a default scan_id from the module + target — deterministic so
/// resuming works without the operator remembering an ID.
pub fn auto_scan_id(module: &str, target: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(module.as_bytes());
    h.update(b"\0");
    h.update(target.as_bytes());
    let digest = h.finalize();
    format!("{}-{}", module.replace('/', "_"), &hex::encode(digest)[..8])
}

/// True if a checkpoint exists for the (module, target) pair.
pub fn has_existing(module: &str, target: &str) -> bool {
    let id = auto_scan_id(module, target);
    checkpoint_path(&id).exists()
}

/// Public helper for callers that just want the path without opening.
pub fn path_for(scan_id: &str) -> PathBuf {
    checkpoint_path(scan_id)
}

/// Trivially-readable summary line.
impl std::fmt::Display for Checkpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}  module={} target={}  processed={}  started={}",
            self.scan_id,
            self.module,
            self.target,
            self.processed.len(),
            self.started,
        )
    }
}


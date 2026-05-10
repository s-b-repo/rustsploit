// src/checkpoint.rs
//
// Crash-resumable checkpoints for long-running mass scans.
//
// The scheduler periodically writes the set of already-processed targets to
// `~/.rustsploit/checkpoints/<scan_id>.json`. On restart, `--resume <scan_id>`
// loads the file, skips processed targets, and continues from where the
// crash interrupted.
//
// Format (JSON):
//   { "scan_id": "...", "module": "scanners/port_scanner", "target": "10.0.0.0/16",
//     "started": "2026-05-07T...", "processed": ["10.0.0.1", "10.0.0.2", ...] }
//
// Atomicity: writes to `<file>.tmp`, then `rename`. Bounded by
// `MAX_CHECKPOINT_ENTRIES` to keep memory + disk usage in check on huge scans.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

const MAX_CHECKPOINT_ENTRIES: usize = 10_000_000;
const FLUSH_EVERY_N: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub scan_id: String,
    pub module: String,
    pub target: String,
    pub started: String,
    pub processed: Vec<String>,
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
        let cp = if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            serde_json::from_str::<Checkpoint>(&raw)
                .with_context(|| format!("parse {}", path.display()))?
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
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                cp,
                seen,
                pending_writes: 0,
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
            std::fs::remove_file(&g.path)
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
    let json = serde_json::to_string_pretty(&g.cp)?;
    let tmp = g.path.with_extension("json.tmp");
    tokio::fs::write(&tmp, &json)
        .await
        .with_context(|| format!("write {}", tmp.display()))?;
    tokio::fs::rename(&tmp, &g.path)
        .await
        .with_context(|| format!("rename {}", g.path.display()))?;
    g.pending_writes = 0;
    Ok(())
}

fn checkpoint_path(scan_id: &str) -> PathBuf {
    let base = home::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".rustsploit")
        .join("checkpoints");
    base.join(format!("{}.json", sanitize(scan_id)))
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

/// List all on-disk checkpoints (for `rustsploit --list-checkpoints`).
pub fn list_checkpoints() -> Result<Vec<Checkpoint>> {
    let dir = home::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".rustsploit")
        .join("checkpoints");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if let Ok(cp) = serde_json::from_str::<Checkpoint>(&raw) {
            out.push(cp);
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


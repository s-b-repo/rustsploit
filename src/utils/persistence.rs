// src/utils/persistence.rs
//
// Shared JSON file persistence helpers: atomic write + corruption-safe load.
// Eliminates ~320 lines of duplicated boilerplate across cred_store, loot,
// global_options, workspace, and export.

use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;

/// Atomically write JSON-serializable data to `path`.
/// Writes to a unique `<path>.tmp.<pid>.<seq>`, then renames to `path`.
///
/// The temp name must be UNIQUE per writer: a deterministic temp path means
/// two concurrent writers open the same file with `truncate(true)` and
/// interleave their bytes, producing a file that contains a mix of two JSON
/// documents. The next load then reports the file as corrupt and silently
/// discards every setting the operator had configured.
pub async fn atomic_write_json<T: Serialize>(path: &Path, data: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("creating parent directory")?;
    }
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("json.tmp.{}.{}", std::process::id(), seq));
    let json = serde_json::to_string_pretty(data).context("serializing JSON")?;
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    #[cfg(unix)]
    {
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts.open(&tmp).await.context("opening temp file")?;
    tokio::io::AsyncWriteExt::write_all(&mut file, json.as_bytes())
        .await
        .context("writing temp file")?;
    // Flush to disk before the rename so a crash cannot leave the target
    // pointing at a file whose contents were never persisted. If the flush
    // fails we must NOT rename: propagate and leave the previous target intact.
    file.sync_all().await.context("syncing temp file to disk")?;
    drop(file);
    tokio::fs::rename(&tmp, path)
        .await
        .context("renaming temp file")?;
    Ok(())
}

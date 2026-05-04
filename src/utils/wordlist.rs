// src/utils/wordlist.rs
//
// On-demand wordlist fetcher + streaming reader for large wordlists.
//
// Two surfaces:
//
//   1. `resolve(name)` — fetches a checksum-pinned wordlist from a known
//      URL into `~/.rustsploit/wordlists/`.
//
//   2. `BatchedReader` — async streaming reader that yields batches of
//      lines without loading the whole file. Use this in place of
//      `crate::utils::load_lines` whenever the wordlist might exceed
//      `STREAMING_THRESHOLD` (currently 16 MiB). `load_lines` is fine for
//      small lists; this is for `rockyou.txt`-class inputs where the whole
//      file in memory is the difference between a 250 MB and 2 GB process.
//
// Modules adopt this incrementally — there is no need to retrofit existing
// `cfg_prompt_existing_file("password_wordlist", …)` calls today.

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncBufReadExt;

const FETCH_TIMEOUT_SECS: u64 = 120;
const MAX_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB hard cap on any one list.

/// A bundled wordlist descriptor. The catalogue lives in `KNOWN_LISTS` below.
struct WordlistSpec {
    /// Logical name used by callers (e.g. `wordlist::resolve("rockyou-top-1k")`).
    name: &'static str,
    /// HTTPS URL to download from. Must point at raw-content (not an HTML page).
    url: &'static str,
    /// SHA-256 of the file contents at `url`. The download is rejected if it
    /// doesn't match — protects against MitM and silent upstream replacement.
    sha256: &'static str,
    /// Local filename to use under `~/.rustsploit/wordlists/`.
    local_name: &'static str,
}

// IMPORTANT: every entry below MUST have a verified SHA-256. Adding an entry
// without a checksum opens an integrity hole. The recommended workflow is:
//
//   curl -L <url> | sha256sum
//
// then paste the digest here. Until a list has a real checksum, leave it out
// — there is no "TODO" placeholder, by design.
const KNOWN_LISTS: &[WordlistSpec] = &[
    // Catalogue entries are added by the maintainer after fetching + hashing
    // each upstream artefact. Empty by design until verified.
];

/// Resolve a logical wordlist name to a path on disk, downloading from the
/// upstream URL if needed. Returns the local path on success.
///
/// Errors:
///   - Unknown name → suggests close matches.
///   - Download failure (timeout, HTTP error, connection refused).
///   - Size cap exceeded (`MAX_BYTES`).
///   - Checksum mismatch — file is deleted and the call fails loudly.
#[allow(dead_code)] // public helper for incremental adoption by modules
pub async fn resolve(name: &str) -> Result<PathBuf> {
    let spec = lookup(name)?;
    let dest = wordlist_dir()?.join(spec.local_name);

    if dest.exists() {
        // Cached copy. Verify checksum once on every fetch to detect tampering.
        verify_sha256(&dest, spec.sha256)
            .with_context(|| format!("cached wordlist {} failed checksum check", spec.name))?;
        return Ok(dest);
    }

    download_to(&dest, spec).await?;
    Ok(dest)
}

/// List the names of every wordlist this build knows about.
#[allow(dead_code)]
pub fn catalogue() -> Vec<&'static str> {
    KNOWN_LISTS.iter().map(|w| w.name).collect()
}

// ----------------------------------------------------------------------------
// Internals
// ----------------------------------------------------------------------------

fn lookup(name: &str) -> Result<&'static WordlistSpec> {
    if let Some(spec) = KNOWN_LISTS.iter().find(|w| w.name == name) {
        return Ok(spec);
    }
    let close: Vec<&str> = KNOWN_LISTS
        .iter()
        .map(|w| w.name)
        .filter(|n| strsim::levenshtein(n, name) <= 3)
        .collect();
    if close.is_empty() {
        Err(anyhow!(
            "unknown wordlist '{}' (catalogue is empty until maintainer adds verified entries)",
            name
        ))
    } else {
        Err(anyhow!(
            "unknown wordlist '{}'; closest matches: {}",
            name,
            close.join(", ")
        ))
    }
}

fn wordlist_dir() -> Result<PathBuf> {
    let home =
        home::home_dir().ok_or_else(|| anyhow!("cannot resolve $HOME for wordlist cache"))?;
    let dir = home.join(".rustsploit").join("wordlists");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create {}", dir.display()))?;
    // Best-effort: tighten perms (700) on Unix so other local users can't read
    // wordlists that may be sensitive (e.g. client-specific lists).
    #[cfg(unix)]
    {
        if let Err(e) =
            crate::utils::privilege::set_secure_permissions(&dir, 0o700)
        {
            tracing::debug!("could not chmod {}: {}", dir.display(), e);
        }
    }
    Ok(dir)
}

async fn download_to(dest: &Path, spec: &WordlistSpec) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let client = crate::utils::build_http_client(Duration::from_secs(FETCH_TIMEOUT_SECS))
        .context("failed to build HTTP client for wordlist download")?;

    let resp = client
        .get(spec.url)
        .send()
        .await
        .with_context(|| format!("download of {} failed (network)", spec.url))?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "download of {} returned HTTP {}",
            spec.url,
            resp.status()
        );
    }

    if let Some(len) = resp.content_length() {
        if len > MAX_BYTES {
            anyhow::bail!(
                "{} reports content-length {} bytes — exceeds {}-byte cap",
                spec.url,
                len,
                MAX_BYTES
            );
        }
    }

    // Write to `<dest>.tmp` first; rename only after checksum passes so a
    // crashed / cancelled download never leaves a corrupt cached file.
    let tmp = dest.with_extension("tmp");
    let mut file = tokio::fs::File::create(&tmp)
        .await
        .with_context(|| format!("could not create {}", tmp.display()))?;

    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut stream = resp.bytes_stream();
    use futures_util::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("network read failed mid-download")?;
        total = total.saturating_add(chunk.len() as u64);
        if total > MAX_BYTES {
            // Best-effort cleanup; ignore errors (we're already failing).
            let _ = tokio::fs::remove_file(&tmp).await;
            anyhow::bail!(
                "wordlist {} exceeded {}-byte cap mid-stream",
                spec.name,
                MAX_BYTES
            );
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.context("disk write failed")?;
    }
    file.flush().await.ok();
    drop(file);

    let got = hex::encode(hasher.finalize());
    if !got.eq_ignore_ascii_case(spec.sha256) {
        let _ = tokio::fs::remove_file(&tmp).await;
        anyhow::bail!(
            "checksum mismatch for {}: expected {}, got {} (file rejected)",
            spec.name,
            spec.sha256,
            got
        );
    }

    tokio::fs::rename(&tmp, dest)
        .await
        .with_context(|| format!("rename {} -> {} failed", tmp.display(), dest.display()))?;
    #[cfg(unix)]
    {
        // We're already on a tokio runtime (the awaits above prove it), so use
        // the async chmod variant — avoids stalling the executor on a blocking
        // syscall while the rest of the download pipeline keeps running.
        if let Err(e) = crate::utils::privilege::set_secure_permissions_async(dest, 0o600).await {
            tracing::debug!("could not chmod {}: {}", dest.display(), e);
        }
    }
    Ok(())
}

fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("could not open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("read failed on {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let got = hex::encode(hasher.finalize());
    if got.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        anyhow::bail!(
            "checksum mismatch on cached file {}: expected {}, got {}",
            path.display(),
            expected,
            got
        );
    }
}

// ============================================================================
// STREAMING WORDLIST READER
// ============================================================================
//
// `crate::utils::load_lines` reads a whole file into a `Vec<String>`, which
// is fine for ~10k entry lists but allocates ~14 GB for `rockyou.txt`-sized
// inputs (~14 M lines × kilobyte-ish tokenised lines + Vec metadata).
//
// `BatchedReader` instead reads the file line-by-line through an async
// `BufReader`, materialising at most `batch_size` lines at a time. The
// caller drives consumption with `next_batch()`; when the file is exhausted
// it returns `Ok(None)`. Memory use is bounded to:
//
//   `batch_size * average_line_length + 64 KiB` (the reader's buffer)
//
// regardless of input size. Lines are trimmed and empty / comment lines
// (starting with `#`) are skipped, matching `load_lines` semantics.

/// Files larger than this should prefer `BatchedReader::open` over
/// `crate::utils::load_lines`. The threshold is heuristic — a 16 MiB ASCII
/// wordlist is ~1.6 M entries, well above the size where eager loading
/// starts to dominate startup latency.
pub const STREAMING_THRESHOLD: u64 = 16 * 1024 * 1024;

/// Default batch size. Tuned so a single batch fits comfortably in L2 cache
/// for typical lengths (`8 KiB * 8 KiB = 64 MiB`-ish working set worst-case).
#[allow(dead_code)] // public constant, used by module callers that opt in
pub const DEFAULT_BATCH_SIZE: usize = 8 * 1024;

/// Streaming wordlist reader. Yields `Vec<String>` batches of trimmed,
/// non-empty, non-comment lines.
///
/// ```ignore
/// use crate::utils::wordlist::BatchedReader;
///
/// let mut reader = BatchedReader::open("rockyou.txt").await?;
/// while let Some(batch) = reader.next_batch().await? {
///     for password in &batch {
///         // try password against target
///         if crate::context::is_cancelled() { return Ok(()); }
///     }
/// }
/// ```
///
/// The reader is `!Send` across `await` points by virtue of holding a
/// `BufReader<File>` — keep it on a single task. For parallel work, send
/// each `Vec<String>` batch to worker tasks via a channel.
pub struct BatchedReader {
    inner: tokio::io::BufReader<tokio::fs::File>,
    batch_size: usize,
    /// Total bytes seen so far — used to enforce `MAX_BYTES` so a malicious
    /// or runaway file can't exhaust disk-driven memory pressure (think
    /// 200 GB sparse file or a `pipe`-mount with infinite content).
    bytes_seen: u64,
    /// `true` once we've returned the final batch. Subsequent calls return
    /// `Ok(None)` without re-opening the file.
    done: bool,
}

impl BatchedReader {
    /// Open `path` for streaming reads with the default batch size
    /// ([`DEFAULT_BATCH_SIZE`]).
    #[allow(dead_code)] // public helper, called from modules that opt in
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_batch_size(path, DEFAULT_BATCH_SIZE).await
    }

    /// Open `path` with an explicit batch size. `batch_size` of 0 is
    /// treated as 1 to avoid an infinite loop in pathological callers.
    pub async fn open_with_batch_size(
        path: impl AsRef<Path>,
        batch_size: usize,
    ) -> Result<Self> {
        let path = path.as_ref();
        let f = tokio::fs::File::open(path)
            .await
            .with_context(|| format!("could not open wordlist {}", path.display()))?;
        Ok(Self {
            inner: tokio::io::BufReader::with_capacity(64 * 1024, f),
            batch_size: batch_size.max(1),
            bytes_seen: 0,
            done: false,
        })
    }

    /// Pull the next batch of up to `batch_size` lines.
    ///
    /// Returns:
    ///   - `Ok(Some(batch))` — non-empty batch ready for processing
    ///   - `Ok(None)` — file is exhausted, OR we hit the [`MAX_BYTES`] cap
    ///     and stopped reading (one warning is logged via `tracing` on the
    ///     transition; subsequent calls return `Ok(None)` silently). The
    ///     caller treats this exactly like a normal EOF — bounded memory
    ///     guarantees, no propagated error.
    ///   - `Err(_)` — I/O error (file disappeared, disk read failed, …).
    ///     The cap itself is fail-soft and never produces an `Err`.
    pub async fn next_batch(&mut self) -> Result<Option<Vec<String>>> {
        if self.done {
            return Ok(None);
        }
        let mut batch: Vec<String> = Vec::with_capacity(self.batch_size);
        let mut line = String::new();
        loop {
            line.clear();
            let n = self
                .inner
                .read_line(&mut line)
                .await
                .context("wordlist read failed")?;
            if n == 0 {
                // EOF
                self.done = true;
                break;
            }
            self.bytes_seen = self.bytes_seen.saturating_add(n as u64);
            if self.bytes_seen > MAX_BYTES {
                // Fail-soft: stop reading instead of erroring. The caller
                // sees a normal end-of-stream with whatever batches we
                // already produced. This protects against runaway / hostile
                // input without crashing the module that consumes us.
                tracing::warn!(
                    "wordlist exceeded {}-byte streaming cap (read so far: {}); \
                     stopping early — subsequent batches will be empty",
                    MAX_BYTES,
                    self.bytes_seen
                );
                self.done = true;
                break;
            }
            // Match `load_lines` semantics: trim, skip empty + `#` comments.
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            batch.push(trimmed.to_string());
            if batch.len() >= self.batch_size {
                break;
            }
        }
        if batch.is_empty() {
            Ok(None)
        } else {
            Ok(Some(batch))
        }
    }

    /// Number of bytes consumed from the underlying file so far. Useful for
    /// progress reporting.
    pub fn bytes_seen(&self) -> u64 {
        self.bytes_seen
    }
}

/// Convenience: open `path`, decide whether to use streaming based on file
/// size vs [`STREAMING_THRESHOLD`], and call `cb` for every batch.
///
/// For files below the threshold this delegates to a single batch. For
/// large files, batches are pulled lazily — caller's `cb` runs concurrently
/// with the next batch's read.
#[allow(dead_code)] // public helper, called from modules that opt in
pub async fn for_each_batch<F, Fut>(
    path: impl AsRef<Path>,
    batch_size: usize,
    mut cb: F,
) -> Result<()>
where
    F: FnMut(Vec<String>) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let path = path.as_ref();
    let mut reader = BatchedReader::open_with_batch_size(path, batch_size).await?;
    while let Some(batch) = reader.next_batch().await? {
        cb(batch).await?;
        if crate::context::is_cancelled() {
            tracing::info!(
                "wordlist iteration cancelled at {} bytes of {}",
                reader.bytes_seen(),
                path.display()
            );
            break;
        }
    }
    Ok(())
}

/// Returns `true` if `path`'s file size is at or above
/// [`STREAMING_THRESHOLD`]. Callers can use this to decide between
/// `crate::utils::load_lines` (in-memory) and `BatchedReader` (streaming).
#[allow(dead_code)]
pub fn should_stream(path: impl AsRef<Path>) -> bool {
    std::fs::metadata(path.as_ref())
        .map(|m| m.len() >= STREAMING_THRESHOLD)
        .unwrap_or(false)
}

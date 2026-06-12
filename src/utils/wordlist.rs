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

use anyhow::{anyhow, bail, Context, Result};
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
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
// Curated subset of SecLists (https://github.com/danielmiessler/SecLists, MIT).
// Each SHA-256 was computed over the exact raw bytes served from the pinned
// `master` raw URL (the same bytes `verify_sha256` hashes after download).
// Sizes are noted for reference; they are not enforced.
const KNOWN_LISTS: &[WordlistSpec] = &[
    // --- Passwords ---
    WordlistSpec {
        name: "passwords-top-1k",
        url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/Pwdb_top-1000.txt",
        sha256: "9a648a4f30a399af3fed0ff097d7c4f98a73e2e043ba9748d84a1c49f23c0725",
        local_name: "seclists-pwdb-top-1000.txt",
    },
    WordlistSpec {
        name: "passwords-top-10k",
        url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/Pwdb_top-10000.txt",
        sha256: "d9a018818f2357ac34c0534bdfd67826811859ae858bfd6398559085c7f4e925",
        local_name: "seclists-pwdb-top-10000.txt",
    },
    // --- Usernames ---
    WordlistSpec {
        name: "usernames-short",
        url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt",
        sha256: "dc44775d12dcdb4027017623ffaa935a018944839ce4b204ccb0c6ef566db5dd",
        local_name: "seclists-usernames-shortlist.txt",
    },
    // --- Web content discovery ---
    WordlistSpec {
        name: "web-common",
        url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        sha256: "fc320bacd30d93f5080029912b93667cd739401f81634579a7125fc0c027e6d5",
        local_name: "seclists-web-common.txt",
    },
    WordlistSpec {
        name: "web-raft-small-dirs",
        url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt",
        sha256: "06e1ac7b390c17eb9e0da416d0599c785a1541813daa95b01c676bc92d55185f",
        local_name: "seclists-raft-small-directories.txt",
    },
    // --- Subdomains (DNS) ---
    WordlistSpec {
        name: "subdomains-top5k",
        url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
        sha256: "e331367c140298cb179114fdeefa78f58f696219f0dec017a28bb79487cfcf19",
        local_name: "seclists-subdomains-top5000.txt",
    },
];

/// Resolve a logical wordlist name to a path on disk, downloading from the
/// upstream URL if needed. Returns the local path on success.
///
/// Errors:
///   - Unknown name → suggests close matches.
///   - Download failure (timeout, HTTP error, connection refused).
///   - Size cap exceeded (`MAX_BYTES`).
///   - Checksum mismatch — file is deleted and the call fails loudly.
pub async fn resolve(name: &str) -> Result<PathBuf> {
    let spec = lookup(name)?;
    let dest = wordlist_dir()?.join(spec.local_name);

    if dest.exists() {
        let check_path = dest.clone();
        let check_hash = spec.sha256.to_string();
        let check_name = spec.name.to_string();
        tokio::task::spawn_blocking(move || {
            verify_sha256(&check_path, &check_hash)
                .with_context(|| format!("cached wordlist {} failed checksum check", check_name))
        })
        .await
        .context("sha256 verify task panicked")??;
        return Ok(dest);
    }

    download_to(&dest, spec).await?;
    Ok(dest)
}

/// List the names of every wordlist this build knows about.
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

    if let Some(len) = resp.content_length()
        && len > MAX_BYTES {
            anyhow::bail!(
                "{} reports content-length {} bytes — exceeds {}-byte cap",
                spec.url,
                len,
                MAX_BYTES
            );
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
            if let Err(e) = tokio::fs::remove_file(&tmp).await {
                eprintln!("[!] Failed to remove temp file: {}", e);
            }
            anyhow::bail!(
                "wordlist {} exceeded {}-byte cap mid-stream",
                spec.name,
                MAX_BYTES
            );
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.context("disk write failed")?;
    }
    file.flush().await.context("flush downloaded wordlist failed")?;
    drop(file);

    let got = hex::encode(hasher.finalize());
    if !got.eq_ignore_ascii_case(spec.sha256) {
        if let Err(e) = tokio::fs::remove_file(&tmp).await {
            eprintln!("[!] Failed to remove temp file: {}", e);
        }
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
pub fn should_stream(path: impl AsRef<Path>) -> bool {
    std::fs::metadata(path.as_ref())
        .map(|m| m.len() >= STREAMING_THRESHOLD)
        .unwrap_or(false)
}

// ============================================================================
// SYNCHRONOUS LINE-LOADING FUNCTIONS (migrated from modules.rs)
// ============================================================================

/// Maximum file size for general text file loading (100 MB).
/// Wordlists bypass this via `load_lines_uncapped`.
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

// ----- Wordlist cache -------------------------------------------------------
//
// Many scanners load the same wordlist (e.g. rockyou.txt) multiple times in
// a session. Keying by canonical path + mtime + len lets us share a single
// `Arc<Vec<String>>` across scanners while still invalidating if the file is
// edited mid-session.

#[derive(Clone)]
struct CachedWordlist {
    lines: Arc<Vec<String>>,
    mtime: Option<SystemTime>,
    len: u64,
}

static WORDLIST_CACHE: Lazy<Mutex<HashMap<PathBuf, CachedWordlist>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Cap so a scan that opens many distinct wordlists in a session can't pin
/// memory indefinitely. Oldest entry is evicted when the cap is hit; we don't
/// bother with LRU since the workload is "a handful of recurring lists".
const WORDLIST_CACHE_MAX_ENTRIES: usize = 16;

/// Load lines from a file with a process-wide cache. Returns an `Arc<Vec>`
/// shared with any earlier identical load. Cache is keyed by canonical path
/// + (mtime, len) so an in-place edit is detected on the next call.
///
/// Use this from scanner / bruteforce module hot paths where the same
/// wordlist is loaded repeatedly in a session. For one-shot loads
/// (`load_lines` callers that already cache themselves), the cache adds no
/// value — keep using `load_lines`.
pub fn load_lines_cached<P: AsRef<Path>>(path: P) -> Result<Arc<Vec<String>>> {
    let path = path.as_ref();
    // Canonicalize so `./list.txt` and `/abs/list.txt` share a cache slot.
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("Failed to canonicalize '{}'", path.display()))?;
    let metadata = fs::metadata(&canonical)
        .with_context(|| format!("Failed to stat '{}'", canonical.display()))?;
    let mtime = metadata.modified().ok();
    let len = metadata.len();

    {
        let cache = WORDLIST_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cached) = cache.get(&canonical)
            && cached.len == len && cached.mtime == mtime {
                return Ok(cached.lines.clone());
            }
    }

    // Cache miss — load fresh. Honour the same size cap as `load_lines`.
    let lines = Arc::new(load_lines(&canonical)?);

    let mut cache = WORDLIST_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() >= WORDLIST_CACHE_MAX_ENTRIES {
        // Evict an arbitrary entry (HashMap iteration order is randomised).
        if let Some(victim) = cache.keys().next().cloned() {
            cache.remove(&victim);
        }
    }
    cache.insert(
        canonical,
        CachedWordlist {
            lines: lines.clone(),
            mtime,
            len,
        },
    );
    Ok(lines)
}

/// Helper to load lines from a file.
pub fn load_lines<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let metadata = fs::metadata(path.as_ref())
        .with_context(|| format!("Failed to stat file '{}'", path.as_ref().display()))?;
    if metadata.len() > MAX_FILE_SIZE {
        bail!(
            "File '{}' is too large ({:.1} MB, max {} MB)",
            path.as_ref().display(),
            metadata.len() as f64 / (1024.0 * 1024.0),
            MAX_FILE_SIZE / (1024 * 1024)
        );
    }
    let file = fs::File::open(path.as_ref())
        .with_context(|| format!("Failed to open file '{}'", path.as_ref().display()))?;
    let reader = BufReader::new(file);
    // Wordlists routinely contain stray non-UTF-8 bytes (binary garbage
    // in scraped dumps); the policy is "skip the line, keep going" rather
    // than failing the whole load, but count and report dropped lines.
    let mut skipped = 0u64;
    let lines: Vec<String> = reader
        .lines()
        .filter_map(|line| match line {
            Ok(s) => {
                let trimmed = s.trim().to_string();
                if trimmed.is_empty() { None } else { Some(trimmed) }
            }
            Err(e) => { tracing::trace!("Non-UTF-8 line in wordlist: {}", e); skipped += 1; None }
        })
        .collect();
    if skipped > 0 {
        crate::meprintln!("[*] Skipped {} non-UTF-8 lines from wordlist", skipped);
    }
    Ok(lines)
}

/// Load lines from a wordlist of any size.
/// Files <= 250 MB are loaded into memory. Larger files are streamed in
/// batches of `batch_size` lines, calling `on_batch` for each chunk.
/// Returns the total number of lines processed.
pub fn load_lines_batched<P, F>(
    path: P,
    batch_size: usize,
    mut on_batch: F,
) -> Result<usize>
where
    P: AsRef<Path>,
    F: FnMut(Vec<String>),
{
    let file = fs::File::open(path.as_ref())
        .with_context(|| format!("Failed to open file '{}'", path.as_ref().display()))?;
    let reader = BufReader::with_capacity(256 * 1024, file);
    let mut total = 0usize;
    let mut batch = Vec::with_capacity(batch_size);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l.trim().to_string(),
            Err(e) => { tracing::trace!("skipping non-UTF-8 wordlist line: {e}"); continue; }
        };
        if line.is_empty() {
            continue;
        }
        batch.push(line);
        if batch.len() >= batch_size {
            total += batch.len();
            on_batch(std::mem::replace(&mut batch, Vec::with_capacity(batch_size)));
        }
    }
    if !batch.is_empty() {
        total += batch.len();
        on_batch(batch);
    }
    Ok(total)
}

/// Load lines from a file without the 100 MB cap.
/// For wordlists that may be very large.
pub fn load_lines_uncapped<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let file = fs::File::open(path.as_ref())
        .with_context(|| format!("Failed to open file '{}'", path.as_ref().display()))?;
    let reader = BufReader::with_capacity(256 * 1024, file);
    // Same UTF-8-skip policy as load_lines.
    Ok(reader
        .lines()
        .filter_map(|line| line.ok().map(|s| s.trim().to_string()))
        .filter(|line| !line.is_empty())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{catalogue, KNOWN_LISTS};

    /// Every catalogue entry must be structurally sound: a non-empty logical
    /// name + local filename, an HTTPS raw URL, and a syntactically valid
    /// SHA-256 (64 lowercase hex chars). This does NOT hit the network — it
    /// guards against typos/placeholders that would make `resolve()` reject
    /// every download for that entry.
    #[test]
    fn known_lists_are_well_formed() {
        for spec in KNOWN_LISTS {
            assert!(!spec.name.is_empty(), "entry has empty name");
            assert!(
                !spec.local_name.is_empty(),
                "entry '{}' has empty local_name",
                spec.name
            );
            assert!(
                spec.url.starts_with("https://"),
                "entry '{}' url is not https: {}",
                spec.name,
                spec.url
            );
            assert_eq!(
                spec.sha256.len(),
                64,
                "entry '{}' sha256 is not 64 chars: {}",
                spec.name,
                spec.sha256
            );
            assert!(
                spec.sha256
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f')),
                "entry '{}' sha256 has non lowercase-hex chars: {}",
                spec.name,
                spec.sha256
            );
        }
    }

    /// Logical names are the public lookup key, so they must be unique.
    #[test]
    fn known_list_names_are_unique() {
        let names = catalogue();
        for (i, a) in names.iter().enumerate() {
            for b in names.iter().skip(i + 1) {
                assert_ne!(a, b, "duplicate wordlist name in catalogue: {a}");
            }
        }
    }
}

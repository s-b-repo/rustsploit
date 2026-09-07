// src/utils/stats.rs
//
// Universal runtime-stats lib for long-running operations (DoS floods, mass-scan
// fan-out, bruteforce, scanners). Three parts:
//   1. `Counters`  — shareable atomic items/bytes/errors (Arc-cheap to clone).
//   2. `Batch`     — per-worker local accumulator (accumulate locally, bulk
//                    fetch_add) so hot loops don't hammer the atomics.
//   3. helpers     — the rate / percent / ETA / bandwidth / duration math that
//                    every progress display re-derives, in ONE place.
//   4. `spawn_reporter` + `print_summary` — the periodic "\r" line and the final
//                    summary block used by the packet-flood modules.
//
// Modules with richer counters (scheduler `hits`, bruteforce success/fail/error
// split + error histogram, scanner status breakdowns) keep their own structs and
// just call the math helpers — that is the universal dedup point.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use colored::*;
use tokio::task::JoinHandle;

/// Default per-worker flush threshold (matches the DoS modules' old
/// `STATS_BATCH_SIZE`): accumulate this many items locally before folding into
/// the shared `Counters`.
pub const DEFAULT_BATCH_THRESHOLD: u64 = 5000;

// ============================================================================
// COUNTERS + SNAPSHOT
// ============================================================================

/// Shareable atomic counters. `Clone` is a cheap `Arc` bump — hand a clone to
/// each worker and to the reporter.
#[derive(Clone, Default)]
pub struct Counters {
    items: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
}

/// Immutable point-in-time read of all three counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub items: u64,
    pub bytes: u64,
    pub errors: u64,
}

impl Counters {
    /// Wrap three pre-existing `Arc<AtomicU64>` (e.g. a module's existing
    /// packets/bytes/errors counters threaded through `WorkerCtx`) so the
    /// reporter can read them without changing the worker plumbing.
    pub fn from_parts(
        items: Arc<AtomicU64>,
        bytes: Arc<AtomicU64>,
        errors: Arc<AtomicU64>,
    ) -> Self {
        Self {
            items,
            bytes,
            errors,
        }
    }

    #[inline]
    pub fn add_items(&self, n: u64) {
        self.items.fetch_add(n, Ordering::Relaxed);
    }
    #[inline]
    pub fn add_bytes(&self, n: u64) {
        self.bytes.fetch_add(n, Ordering::Relaxed);
    }
    #[inline]
    pub fn add_errors(&self, n: u64) {
        self.errors.fetch_add(n, Ordering::Relaxed);
    }

    /// Fold a whole [`Batch`] into the shared counters in one shot.
    #[inline]
    pub fn add_batch(&self, b: &Batch) {
        if b.items > 0 {
            self.add_items(b.items);
        }
        if b.bytes > 0 {
            self.add_bytes(b.bytes);
        }
        if b.errors > 0 {
            self.add_errors(b.errors);
        }
    }

    #[inline]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            items: self.items.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

/// Per-worker local accumulator. A worker does `batch.item(n)` / `batch.error()`
/// in its hot loop, `batch.flush_if_full(&counters, threshold)` each iteration,
/// and `batch.flush(&counters)` once on exit.
#[derive(Clone, Copy, Debug, Default)]
pub struct Batch {
    pub items: u64,
    pub bytes: u64,
    pub errors: u64,
}

impl Batch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one item carrying `bytes` payload.
    #[inline]
    pub fn item(&mut self, bytes: u64) {
        self.items += 1;
        self.bytes += bytes;
    }
    #[inline]
    pub fn error(&mut self) {
        self.errors += 1;
    }

    /// Fold into the shared counters and reset.
    #[inline]
    pub fn flush(&mut self, c: &Counters) {
        c.add_batch(self);
        *self = Self::default();
    }

    /// Flush only once `items` reaches `threshold`. Returns true if it flushed.
    #[inline]
    pub fn flush_if_full(&mut self, c: &Counters, threshold: u64) -> bool {
        if self.items >= threshold {
            self.flush(c);
            true
        } else {
            false
        }
    }
}

// ============================================================================
// UNIVERSAL MATH HELPERS (the dedup target for scheduler/bruteforce/scanners)
// ============================================================================

/// Lossless `u64` -> `f64` without an `as` cast (CLAUDE.md bans `as f64`).
/// Values above 2^53 lose precision, but no counter approaches that in a run.
#[inline]
pub fn u64_to_f64(v: u64) -> f64 {
    let hi = u32::try_from(v >> 32).unwrap_or(u32::MAX);
    let lo = u32::try_from(v & 0xFFFF_FFFF).unwrap_or(0);
    f64::from(hi) * 4_294_967_296.0 + f64::from(lo)
}

/// items per second over `elapsed`, guarding divide-by-zero.
#[inline]
pub fn rate_per_sec(items: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs > 0.0 {
        u64_to_f64(items) / secs
    } else {
        0.0
    }
}

/// `done / total * 100`, clamped to 0..=100; 0 when `total == 0`.
#[inline]
pub fn percent(done: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (u64_to_f64(done) / u64_to_f64(total) * 100.0).min(100.0)
    }
}

/// Estimated time remaining given progress so far. Returns `Duration::ZERO`
/// when it cannot be estimated (no progress yet, already complete, etc.).
#[inline]
pub fn eta(done: u64, total: u64, elapsed: Duration) -> Duration {
    let secs = elapsed.as_secs_f64();
    if done == 0 || total <= done || secs <= 0.0 {
        return Duration::ZERO;
    }
    let rate = u64_to_f64(done) / secs;
    if rate <= 0.0 {
        return Duration::ZERO;
    }
    let remaining = u64_to_f64(total - done) / rate;
    if remaining.is_finite() && remaining >= 0.0 {
        // Clamp well under Duration's overflow point so from_secs_f64 can't panic.
        Duration::from_secs_f64(remaining.min(8.64e9))
    } else {
        Duration::ZERO
    }
}

/// Megabits per second for a byte total over `elapsed`.
#[inline]
pub fn mbps(bytes: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs > 0.0 {
        (u64_to_f64(bytes) * 8.0) / (secs * 1_000_000.0)
    } else {
        0.0
    }
}

/// Bytes as mebibytes (MiB).
#[inline]
pub fn megabytes(bytes: u64) -> f64 {
    u64_to_f64(bytes) / (1024.0 * 1024.0)
}

/// Clock-style duration string for ETAs / elapsed: `HH:MM:SS` (or `MM:SS` under
/// an hour). Matches the format the bruteforce/scan progress lines already used.
pub fn format_duration(secs: f64) -> String {
    // Guarded f64 -> u64: clamp to finite, non-negative, and well under 2^64.
    let total = if secs.is_finite() && secs > 0.0 {
        secs.min(8.64e9) as u64
    } else {
        0
    };
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    if h > 0 {
        format!("{:02}:{:02}:{:02}", h, m, s)
    } else {
        format!("{:02}:{:02}", m, s)
    }
}

// ============================================================================
// REPORTER (periodic line + final summary) — for the packet-flood modules
// ============================================================================

/// How the periodic line + final summary render.
#[derive(Clone, Debug)]
pub struct ReportConfig {
    /// Live-line prefix, e.g. "[*] Packets".
    pub item_label: String,
    /// Summary noun, e.g. "Total Packets".
    pub item_label_long: String,
    /// Unit appended to the rate, e.g. "pkt/s".
    pub rate_unit: String,
    /// Show the bytes column (MB) on the live line and in the summary.
    pub show_bytes: bool,
    /// Show the Mbps bandwidth figure.
    pub show_bandwidth: bool,
    /// Periodic refresh interval.
    pub interval: Duration,
}

impl ReportConfig {
    /// Preset matching every packet/byte flood: items + bytes + errors, 2s, pkt/s.
    pub fn packet_flood(item_label_long: impl Into<String>) -> Self {
        Self {
            item_label: "[*] Packets".to_string(),
            item_label_long: item_label_long.into(),
            rate_unit: "pkt/s".to_string(),
            show_bytes: true,
            show_bandwidth: true,
            interval: Duration::from_secs(2),
        }
    }
}

fn render_live_line(cfg: &ReportConfig, s: &Snapshot, elapsed: Duration) -> String {
    let rate = rate_per_sec(s.items, elapsed);
    if cfg.show_bytes {
        format!(
            "{}: {:>12} | {:>8.2} MB | Rate: {:>10.0} {} | {:>8.2} Mbps | Errs: {}   ",
            cfg.item_label,
            s.items,
            megabytes(s.bytes),
            rate,
            cfg.rate_unit,
            mbps(s.bytes, elapsed),
            s.errors,
        )
    } else {
        format!(
            "{}: {:>12} | Rate: {:>10.0} {} | Errs: {}   ",
            cfg.item_label, s.items, rate, cfg.rate_unit, s.errors,
        )
    }
}

/// Spawn the periodic printer. Returns a `JoinHandle` the caller MUST `.abort()`
/// after the run ends. The task stops itself when `stop` flips true.
pub fn spawn_reporter(
    cfg: ReportConfig,
    counters: Counters,
    start: Instant,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while !stop.load(Ordering::Relaxed) {
            tokio::time::sleep(cfg.interval).await;
            let s = counters.snapshot();
            crate::mprint!("\r{}", render_live_line(&cfg, &s, start.elapsed()).dimmed());
            if let Err(e) = std::io::Write::flush(&mut std::io::stdout()) {
                crate::meprintln!("[!] Flush failed: {}", e);
            }
        }
    })
}

/// Print the `=== Attack Complete ===` summary block.
pub fn print_summary(cfg: &ReportConfig, s: &Snapshot, elapsed: Duration) {
    crate::mprintln!("\n\n{}", "=== Attack Complete ===".green().bold());
    crate::mprintln!("  Duration:      {:.2}s", elapsed.as_secs_f64());
    crate::mprintln!("  {}: {}", cfg.item_label_long, s.items);
    if cfg.show_bytes {
        crate::mprintln!("  Total Data:    {:.2} MB", megabytes(s.bytes));
    }
    crate::mprintln!("  Total Errors:  {}", s.errors);
    if elapsed.as_secs_f64() > 0.0 {
        crate::mprintln!(
            "  Avg Rate:      {:.0} {}",
            rate_per_sec(s.items, elapsed),
            cfg.rate_unit
        );
        if cfg.show_bandwidth {
            crate::mprintln!("  Avg Bandwidth: {:.2} Mbps", mbps(s.bytes, elapsed));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u64_to_f64_small_values_exact() {
        assert_eq!(u64_to_f64(0), 0.0); // audit-allow: test
        assert_eq!(u64_to_f64(5_000_000_000), 5_000_000_000.0); // audit-allow: test
    }

    #[test]
    fn rate_and_percent() {
        assert_eq!(rate_per_sec(1000, Duration::from_secs(2)), 500.0); // audit-allow: test
        assert_eq!(rate_per_sec(1000, Duration::ZERO), 0.0); // audit-allow: test
        assert_eq!(percent(50, 200), 25.0); // audit-allow: test
        assert_eq!(percent(10, 0), 0.0); // audit-allow: test
        assert_eq!(percent(300, 200), 100.0); // audit-allow: test (clamped)
    }

    #[test]
    fn mbps_and_eta() {
        assert_eq!(mbps(1_000_000, Duration::from_secs(1)), 8.0); // audit-allow: test
        // 50/100 done in 10s → ~10s remaining.
        assert_eq!(eta(50, 100, Duration::from_secs(10)).as_secs(), 10); // audit-allow: test
        assert_eq!(eta(0, 100, Duration::from_secs(10)), Duration::ZERO); // audit-allow: test
    }

    #[test]
    fn format_duration_buckets() {
        assert_eq!(format_duration(45.0), "00:45"); // audit-allow: test
        assert_eq!(format_duration(125.0), "02:05"); // audit-allow: test
        assert_eq!(format_duration(3723.0), "01:02:03"); // audit-allow: test
        assert_eq!(format_duration(-1.0), "00:00"); // audit-allow: test
    }

    #[test]
    fn batch_flush_threshold() {
        let c = Counters::default();
        let mut b = Batch::new();
        for _ in 0..DEFAULT_BATCH_THRESHOLD {
            b.item(10);
        }
        assert!(b.flush_if_full(&c, DEFAULT_BATCH_THRESHOLD)); // audit-allow: test
        let s = c.snapshot();
        assert_eq!(s.items, DEFAULT_BATCH_THRESHOLD); // audit-allow: test
        assert_eq!(s.bytes, DEFAULT_BATCH_THRESHOLD * 10); // audit-allow: test
        assert_eq!(b.items, 0); // audit-allow: test (reset after flush)
    }
}

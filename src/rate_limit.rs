// src/rate_limit.rs
//
// Hierarchical rate limiter shared across all scheduler invocations.
//
// Tiers (each must permit a request before it dispatches):
//   1. Global  — process-wide RPS cap (`GLOBAL_RPS` global option, default 0=unlimited)
//   2. Module  — per-module-type RPS cap (`module_rps:<name>` option, default 0=unlimited)
//   3. Target  — per-target-host cap (`target_rps` option, default 0=unlimited)
//
// Limiter uses a token-bucket implementation with per-bucket
// `tokio::sync::Semaphore` permits replenished by a background ticker. When
// RPS=0 the semaphore is bypassed entirely (no overhead).
//
// Wired into `ModuleCtx::limiter` so module code can call
// `ctx.acquire(target_str).await` before each network round trip.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use once_cell::sync::Lazy;
use tokio::sync::{Mutex, Semaphore};

/// One token-bucket. `rps == 0` means "no limit, fast path".
pub struct Bucket {
    rps: usize,
    sem: Arc<Semaphore>,
}

impl Bucket {
    pub fn new(rps: usize) -> Self {
        let cap = rps.max(1);
        let sem = Arc::new(Semaphore::new(cap));
        if rps > 0 {
            // Replenish a permit every (1/rps) seconds. Keep a long-lived
            // ticker on the tokio runtime; aborted cleanly when the limiter
            // drops (Arc<Semaphore> outlives the ticker only if there are
            // active borrowers).
            let sem_w = Arc::downgrade(&sem);
            let interval = Duration::from_micros((1_000_000 / rps as u64).max(1));
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(interval);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tick.tick().await;
                    let Some(sem) = sem_w.upgrade() else { break };
                    if sem.available_permits() < cap {
                        sem.add_permits(1);
                    }
                }
            });
        }
        Self { rps, sem }
    }

    /// Acquire one permit, awaiting if the bucket is empty.
    pub async fn acquire(&self) {
        if self.rps == 0 {
            return;
        }
        // forget() the permit so it's only refilled by the ticker.
        if let Ok(p) = self.sem.clone().acquire_owned().await {
            p.forget();
        }
    }
}

/// Process-wide rate limiter with global + per-module + per-target tiers.
pub struct GlobalLimiter {
    global: Bucket,
    per_module: Mutex<HashMap<String, Arc<Bucket>>>,
    per_target: Mutex<HashMap<String, Arc<Bucket>>>,
    /// Default per-module RPS when no override is set.
    module_default: AtomicUsize,
    /// Default per-target RPS when no override is set.
    target_default: AtomicUsize,
}

impl GlobalLimiter {
    fn new(global_rps: usize, module_default: usize, target_default: usize) -> Self {
        Self {
            global: Bucket::new(global_rps),
            per_module: Mutex::new(HashMap::new()),
            per_target: Mutex::new(HashMap::new()),
            module_default: AtomicUsize::new(module_default),
            target_default: AtomicUsize::new(target_default),
        }
    }

    /// Acquire all three tiers. Call once per network round trip.
    /// `module` is the module path (e.g. `"scanners/port_scanner"`),
    /// `target` is the host (without port).
    pub async fn acquire(&self, module: &str, target: &str) {
        self.global.acquire().await;
        let mb = self.module_bucket(module).await;
        mb.acquire().await;
        let tb = self.target_bucket(target).await;
        tb.acquire().await;
    }

    async fn module_bucket(&self, module: &str) -> Arc<Bucket> {
        let mut m = self.per_module.lock().await;
        if let Some(b) = m.get(module) {
            return b.clone();
        }
        let rps = module_rps_from_options(module)
            .unwrap_or_else(|| self.module_default.load(Ordering::Relaxed));
        let b = Arc::new(Bucket::new(rps));
        m.insert(module.to_string(), b.clone());
        b
    }

    const MAX_TARGET_BUCKETS: usize = 16_384;

    async fn target_bucket(&self, target: &str) -> Arc<Bucket> {
        let mut m = self.per_target.lock().await;
        if let Some(b) = m.get(target) {
            return b.clone();
        }
        // Cap the number of per-target buckets to prevent unbounded growth
        if m.len() >= Self::MAX_TARGET_BUCKETS {
            if let Some(old_key) = m.keys().next().cloned() {
                tracing::debug!("Rate limiter: evicting target bucket '{}' (cap {} reached)", old_key, Self::MAX_TARGET_BUCKETS);
                m.remove(&old_key);
            }
        }
        let rps = self.target_default.load(Ordering::Relaxed);
        let b = Arc::new(Bucket::new(rps));
        m.insert(target.to_string(), b.clone());
        b
    }
}

/// Look up `module_rps:<module>` in the active tenant's `global_options`.
/// Returns `None` to fall back to the default.
fn module_rps_from_options(module: &str) -> Option<usize> {
    let key = format!("module_rps:{}", module);
    let scope = crate::tenant::resolve();
    scope.global_options().try_get(&key).and_then(|v| v.parse().ok())
}

/// Process-wide singleton initialised lazily from `global_options`.
pub static LIMITER: Lazy<Arc<GlobalLimiter>> = Lazy::new(|| {
    let scope = crate::tenant::resolve();
    let opts = scope.global_options();
    let global = opts.try_get("global_rps").and_then(|v| v.parse().ok()).unwrap_or(0);
    let module = opts.try_get("module_rps").and_then(|v| v.parse().ok()).unwrap_or(0);
    let target = opts.try_get("target_rps").and_then(|v| v.parse().ok()).unwrap_or(0);
    Arc::new(GlobalLimiter::new(global, module, target))
});

/// Convenience accessor for `ModuleCtx::limiter`.
pub fn shared() -> Arc<GlobalLimiter> {
    LIMITER.clone()
}

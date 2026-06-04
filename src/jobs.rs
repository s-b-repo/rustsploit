use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::LazyLock as Lazy;
use std::sync::RwLock;

use rand::RngExt;

use colored::*;
use serde::Serialize;
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Serialize)]
pub enum JobEvent {
    Started { id: u32, module: String, target: String },
    Completed { id: u32 },
    Failed { id: u32, error: String },
    Cancelled { id: u32 },
}

/// Status of a background job.
#[derive(Debug, Clone, Serialize)]
pub enum JobStatus {
    Running,
    Completed,
    Failed(String),
    Cancelled,
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobStatus::Running => write!(f, "Running"),
            JobStatus::Completed => write!(f, "Completed"),
            JobStatus::Failed(msg) => write!(f, "Failed: {}", msg),
            JobStatus::Cancelled => write!(f, "Cancelled"),
        }
    }
}

/// Thread-safe output + progress tracker shared between the job task and API readers.
pub struct JobProgress {
    output: RwLock<std::collections::VecDeque<String>>,
    total_lines_pushed: AtomicU64,
    pub success_count: AtomicU64,
    pub fail_count: AtomicU64,
    pub total_targets: AtomicU64,
    pub last_activity: RwLock<chrono::DateTime<chrono::Local>>,
}

const MAX_OUTPUT_LINES: usize = 5000;
const MAX_LINE_BYTES: usize = 10_240;

impl JobProgress {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            output: RwLock::new(std::collections::VecDeque::with_capacity(MAX_OUTPUT_LINES)),
            total_lines_pushed: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            fail_count: AtomicU64::new(0),
            total_targets: AtomicU64::new(0),
            last_activity: RwLock::new(chrono::Local::now()),
        })
    }

    pub fn push_line(&self, line: String) {
        let capped = if line.len() > MAX_LINE_BYTES {
            let mut t = line;
            t.truncate(MAX_LINE_BYTES);
            t.push_str(" [truncated]");
            t
        } else {
            line
        };
        {
            let mut buf = self.output.write().unwrap_or_else(|e| e.into_inner());
            if buf.len() >= MAX_OUTPUT_LINES {
                buf.pop_front();
            }
            buf.push_back(capped);
        }
        self.total_lines_pushed.fetch_add(1, Ordering::Relaxed);
        *self.last_activity.write().unwrap_or_else(|e| e.into_inner()) = chrono::Local::now();
    }

    pub fn get_output(&self, from: usize) -> Vec<String> {
        self.output.read().unwrap_or_else(|e| e.into_inner())
            .iter().skip(from).cloned().collect()
    }

    pub fn output_len(&self) -> usize {
        self.output.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn completed(&self) -> u64 {
        self.success_count.load(Ordering::Relaxed) + self.fail_count.load(Ordering::Relaxed)
    }
}

/// A background job entry.
pub struct Job {
    pub id: u32,
    pub module: String,
    pub target: String,
    pub started_at: chrono::DateTime<chrono::Local>,
    pub status: JobStatus,
    pub progress: Arc<JobProgress>,
    finished_at: Option<std::time::Instant>,
    /// Lifecycle signal observed by the outer `tokio::select!` arm in `spawn`.
    /// Triggered together with `cancel_token` from `kill`.
    cancel_tx: watch::Sender<bool>,
    /// Cooperative-cancellation signal passed into the module's `RunContext`.
    /// Module loops can poll `crate::context::is_cancelled()` to terminate
    /// gracefully when `kill` is invoked.
    cancel_token: CancellationToken,
    handle: Option<tokio::task::JoinHandle<()>>,
}

const MAX_JOBS: usize = 1000;
const FINISHED_JOB_RETENTION_SECS: u64 = 300;
const DEFAULT_MAX_RUNNING: usize = 5;

/// Manages background jobs.
pub struct JobManager {
    jobs: RwLock<HashMap<u32, Job>>,
    max_running: AtomicU32,
    event_tx: broadcast::Sender<JobEvent>,
}

impl JobManager {
    pub(crate) fn new() -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self {
            jobs: RwLock::new(HashMap::new()),
            max_running: AtomicU32::new(DEFAULT_MAX_RUNNING as u32),
            event_tx,
        }
    }

    /// P1-2: generate an unpredictable u32 job ID across the full 32-bit space
    /// (skipping 0). Sequential IDs let one tenant guess another tenant's
    /// `jobId` and subscribe to / kill it. With MAX_JOBS = 1000 the birthday
    /// collision probability is ~1.2e-4 per spawn — the retry loop in `spawn`
    /// covers the rare hit.
    fn fresh_id() -> u32 {
        let mut rng = rand::rng();
        let mut id: u32 = rng.random();
        if id == 0 { id = 1; }
        id
    }

    pub fn subscribe(&self) -> broadcast::Receiver<JobEvent> {
        self.event_tx.subscribe()
    }

    pub fn running_count(&self) -> usize {
        self.jobs.read().map(|jobs| {
            jobs.values().filter(|j| {
                j.handle.as_ref().map(|h| !h.is_finished()).unwrap_or(false)
            }).count()
        }).unwrap_or(0)
    }

    pub fn get_max_running(&self) -> u32 {
        self.max_running.load(Ordering::Relaxed)
    }

    pub fn set_max_running(&self, limit: u32) {
        let clamped = limit.clamp(1, 100);
        self.max_running.store(clamped, Ordering::Relaxed);
    }

    /// Record a terminal status written back by the spawned task itself, so a
    /// crashed/errored job is never later misreported as "Completed" by the
    /// `is_finished()` fallback in `list()`/`get_detail()`. Only transitions a
    /// job that is still `Running` (a `kill()` that already set `Cancelled`
    /// must win), and stamps `finished_at` for retention.
    fn record_terminal(&self, id: u32, status: JobStatus) {
        let mut jobs = self.jobs.write().unwrap_or_else(|e| e.into_inner());
        if let Some(job) = jobs.get_mut(&id) {
            if matches!(job.status, JobStatus::Running) {
                job.status = status;
            }
            if job.finished_at.is_none() {
                job.finished_at = Some(std::time::Instant::now());
            }
        }
    }

    /// Mark a background job as successfully completed. Called by the spawned
    /// task on a clean `Ok` result so the durable record reflects success.
    pub fn mark_completed(&self, id: u32) {
        self.record_terminal(id, JobStatus::Completed);
    }

    /// Mark a background job as failed and persist the failure reason into the
    /// durable `Job` record (not just the bounded progress buffer / transient
    /// broadcast event). Called by the spawned task on an `Err`/panic result.
    pub fn mark_failed(&self, id: u32, msg: String) {
        self.record_terminal(id, JobStatus::Failed(msg));
    }

    pub fn spawn(
        &self,
        module: String,
        target: String,
        verbose: bool,
        config: Option<crate::config::ModuleConfig>,
    ) -> Result<(u32, Arc<JobProgress>), String> {
        let mut jobs = self.jobs.write().map_err(|e| format!("Job lock poisoned: {e}"))?;

        let running = jobs.values().filter(|j| {
            j.handle.as_ref().map(|h| !h.is_finished()).unwrap_or(false)
        }).count();
        let max = self.max_running.load(Ordering::Relaxed) as usize;
        if running >= max {
            return Err(format!(
                "Job limit reached: {}/{} concurrent jobs running. Kill a running job or increase the limit.",
                running, max
            ));
        }

        let mut id = Self::fresh_id();
        while jobs.contains_key(&id) {
            id = Self::fresh_id();
        }

        if jobs.len() >= MAX_JOBS {
            let now = std::time::Instant::now();
            jobs.retain(|_, j| {
                match j.finished_at {
                    None => true,
                    Some(at) => now.duration_since(at).as_secs() < FINISHED_JOB_RETENTION_SECS,
                }
            });
            if jobs.len() >= MAX_JOBS {
                let mut finished: Vec<(u32, std::time::Instant)> = jobs.iter()
                    .filter_map(|(jid, j)| j.finished_at.map(|t| (*jid, t)))
                    .collect();
                finished.sort_by_key(|(_, t)| *t);
                for (oldest_id, _) in finished.into_iter().take(jobs.len() - MAX_JOBS + 1) {
                    jobs.remove(&oldest_id);
                }
            }
        }

        let (cancel_tx, cancel_rx) = watch::channel(false);
        let cancel_token = CancellationToken::new();
        let cancel_token_for_task = cancel_token.clone();
        let progress = JobProgress::new();
        let prog_clone = progress.clone();
        let mod_clone = module.clone();
        let tgt_clone = target.clone();
        let evt_module = module.clone();
        let evt_target = target.clone();
        let event_tx = self.event_tx.clone();

        // `tokio::spawn` does NOT inherit the `CURRENT_TENANT` task-local, so a
        // background job would otherwise run against the process-global stores
        // and leak findings across tenants / into shell mode. Capture the
        // requesting tenant here (where the scope is still active) and
        // re-establish it inside the spawned task. Fall back to the
        // RunContext-scoped tenant (the same precedence `tenant::resolve` uses),
        // so a job spawned from module execution — where the tenant is set via
        // RunContext rather than the CURRENT_TENANT task-local — still binds to
        // the correct tenant instead of leaking into the process-global stores.
        let tenant_for_task = crate::tenant::CURRENT_TENANT
            .try_with(|t| t.clone())
            .ok()
            .or_else(crate::context::current_tenant_id);

        let handle = tokio::spawn(async move {
            let mut rx = cancel_rx;
            prog_clone.push_line(format!("[*] Starting {} against {}", mod_clone, tgt_clone));
            // P2-A10 / P3-15: catch panics from inside the module so the job
            // surfaces as Failed instead of staying "Running" forever after
            // `tokio::spawn` swallows the panic. Requires `AssertUnwindSafe`
            // because the inner future closes over arbitrary module state.
            use futures::FutureExt;
            use std::panic::AssertUnwindSafe;
            let run_fut = {
                let m = mod_clone.clone();
                let t = tgt_clone.clone();
                let token = cancel_token_for_task;
                AssertUnwindSafe(async move {
                    if let Some(cfg) = config {
                        let (result, _ctx) = crate::context::run_with_context_target_and_cancel(
                            cfg,
                            t.clone(),
                            token,
                            || async move { crate::commands::run_module(&m, &t, verbose).await },
                        ).await;
                        result
                    } else {
                        crate::commands::run_module(&m, &t, verbose).await
                    }
                })
                .catch_unwind()
            };
            // Keep a copy of the tenant id for the terminal-status updates below:
            // they run OUTSIDE the CURRENT_TENANT scope (only `run_fut` is
            // scoped), and a tenant job is registered in that tenant's own
            // JobManager, not the global one — so the terminal transition must be
            // applied to the same per-tenant manager (resolved via this id),
            // otherwise the job is stuck reporting Running and never records
            // Completed/Failed/Cancelled.
            let tenant_for_status = tenant_for_task.clone();
            // Re-establish the tenant context dropped by `tokio::spawn` so the
            // module's loot/hosts/findings and cfg_prompt lookups resolve to the
            // requesting tenant's stores (or stay global when spawned from CLI).
            let run_fut = async move {
                match tenant_for_task {
                    Some(tid) => crate::tenant::CURRENT_TENANT.scope(tid, run_fut).await,
                    None => run_fut.await,
                }
            };
            // Capture the module's console output. A background job has no
            // foreground OUTPUT_BUFFER, so without this the module's mprintln!
            // output would hit the server's real stdout and be lost — API
            // clients polling get_output() would only ever see the framing
            // lines. Scope a buffer around the run and stream it into the job's
            // progress log via a periodic drainer (+ a final flush).
            let job_buf = crate::output::OutputBuffer::new();
            let run_fut = {
                let buf = job_buf.clone();
                async move { crate::output::OUTPUT_BUFFER.scope(buf, run_fut).await }
            };
            // Scan counters: the scheduler fills these with real per-target
            // total/succeeded/failed so get_detail reports live progress instead
            // of the previously always-zero counters.
            let scan_counters = std::sync::Arc::new(crate::context::ScanCounters::default());
            let run_fut = {
                let c = scan_counters.clone();
                async move { crate::context::SCAN_COUNTERS.scope(c, run_fut).await }
            };
            let (stop_tx, mut stop_rx) = watch::channel(false);
            let drainer = {
                let buf = job_buf.clone();
                let prog = prog_clone.clone();
                let counters = scan_counters.clone();
                tokio::spawn(async move {
                    use std::sync::atomic::Ordering::Relaxed;
                    loop {
                        let stop = tokio::select! {
                            _ = tokio::time::sleep(std::time::Duration::from_millis(400)) => false,
                            _ = stop_rx.changed() => true,
                        };
                        let chunk = buf.drain_stdout();
                        for line in chunk.lines() {
                            prog.push_line(line.to_string());
                        }
                        // Mirror the scheduler's live scan counters into the job.
                        prog.total_targets.store(counters.total.load(Relaxed), Relaxed);
                        prog.success_count.store(counters.succeeded.load(Relaxed), Relaxed);
                        prog.fail_count.store(counters.failed.load(Relaxed), Relaxed);
                        if stop { break; }
                    }
                })
            };
            tokio::select! {
                result = run_fut => {
                    let result = match result {
                        Ok(inner) => inner,
                        Err(panic) => {
                            let msg = if let Some(s) = panic.downcast_ref::<&str>() {
                                format!("module panicked: {}", s)
                            } else if let Some(s) = panic.downcast_ref::<String>() {
                                format!("module panicked: {}", s)
                            } else {
                                "module panicked (unknown payload)".to_string()
                            };
                            Err(anyhow::anyhow!(msg))
                        }
                    };
                    match result {
                        Ok(_) => {
                            // Persist the terminal status into the durable Job
                            // record so a finished job is reported as Completed
                            // explicitly rather than via the is_finished()
                            // fallback (which can't distinguish success/failure).
                            match &tenant_for_status {
                                Some(tid) => match crate::tenant::resolve_for(tid) {
                                    Ok(s) => s.job_manager().mark_completed(id),
                                    Err(e) => tracing::warn!("job {}: could not resolve tenant '{}' to record completion: {}", id, tid, e),
                                },
                                None => JOB_MANAGER.mark_completed(id),
                            }
                            prog_clone.push_line(format!("[+] Completed: {} against {}", mod_clone, tgt_clone));
                            crate::mprintln!("\n{}", format!("[*] Job completed: {} against {}", mod_clone, tgt_clone).green());
                            if let Err(e) = event_tx.send(JobEvent::Completed { id }) {
                                tracing::debug!("No WS subscribers for job event: {}", e);
                            }
                        }
                        Err(e) => {
                            let msg = e.to_string();
                            // Persist the failure reason into the durable Job
                            // record so operators polling list()/get_detail()
                            // see Failed(msg), not a misleading "Completed".
                            match &tenant_for_status {
                                Some(tid) => match crate::tenant::resolve_for(tid) {
                                    Ok(s) => s.job_manager().mark_failed(id, msg.clone()),
                                    Err(e) => tracing::warn!("job {}: could not resolve tenant '{}' to record failure: {}", id, tid, e),
                                },
                                None => JOB_MANAGER.mark_failed(id, msg.clone()),
                            }
                            prog_clone.push_line(format!("[-] Failed: {} - {}", mod_clone, msg));
                            crate::meprintln!("\n{}", format!("[!] Job failed: {} - {}", mod_clone, msg).red());
                            if let Err(e) = event_tx.send(JobEvent::Failed { id, error: msg }) {
                                tracing::debug!("No WS subscribers for job event: {}", e);
                            }
                        }
                    }
                }
                _ = async { while rx.changed().await.is_ok() { if *rx.borrow() { break; } } } => {
                    // kill() already set status = Cancelled under the write lock;
                    // record_terminal() won't overwrite it. This is a no-op for
                    // status but ensures finished_at is stamped if kill() raced.
                    match &tenant_for_status {
                        Some(tid) => match crate::tenant::resolve_for(tid) {
                            Ok(s) => s.job_manager().record_terminal(id, JobStatus::Cancelled),
                            Err(e) => tracing::warn!("job {}: could not resolve tenant '{}' to record cancellation: {}", id, tid, e),
                        },
                        None => JOB_MANAGER.record_terminal(id, JobStatus::Cancelled),
                    }
                    prog_clone.push_line(format!("[!] Cancelled: {}", mod_clone));
                    crate::mprintln!("\n{}", format!("[*] Job cancelled: {}", mod_clone).yellow());
                    if let Err(e) = event_tx.send(JobEvent::Cancelled { id }) {
                        tracing::debug!("No WS subscribers for job event: {}", e);
                    }
                }
            }
            // Stop the output drainer and flush any remaining captured output so
            // the final lines of the run are visible in get_output().
            if let Err(e) = stop_tx.send(true) {
                tracing::debug!("job output drainer stop signal failed: {e}");
            }
            if let Err(e) = drainer.await {
                tracing::debug!("job output drainer join failed: {e}");
            }
        });

        jobs.insert(id, Job {
            id,
            module,
            target,
            started_at: chrono::Local::now(),
            status: JobStatus::Running,
            progress: progress.clone(),
            finished_at: None,
            cancel_tx,
            cancel_token,
            handle: Some(handle),
        });
        drop(jobs);

        if let Err(e) = self.event_tx.send(JobEvent::Started {
            id,
            module: evt_module,
            target: evt_target,
        }) {
            tracing::debug!("No WS subscribers for job started event: {}", e);
        }

        Ok((id, progress))
    }

    pub fn kill(&self, id: u32) -> bool {
        let handle_and_tx = {
            let mut jobs = match self.jobs.write() {
                Ok(j) => j,
                Err(e) => {
                    tracing::warn!(job_id = id, "JobManager write lock poisoned during kill: {}", e);
                    return false;
                }
            };
            let job = match jobs.get_mut(&id) {
                Some(j) => j,
                None => return false,
            };
            if let Err(e) = job.cancel_tx.send(true) {
                crate::meprintln!("[!] Job cancel signal error: {}", e);
            }
            // Trigger cooperative cancellation visible to module code via
            // `crate::context::is_cancelled()`. Idempotent — safe to call
            // even if the watch::Sender already fired.
            job.cancel_token.cancel();
            job.status = JobStatus::Cancelled;
            if job.finished_at.is_none() {
                job.finished_at = Some(std::time::Instant::now());
            }
            job.handle.take()
        };
        if let Some(handle) = handle_and_tx {
            let abort_handle = handle.abort_handle();
            // Fire-and-forget cleanup: give the job 2s to honour the
            // cooperative cancel before we hard-abort. We log via tracing
            // so a panic in the cleanup task isn't silently swallowed.
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                if !handle.is_finished() {
                    tracing::debug!("Job did not exit within 2s — hard-aborting");
                    abort_handle.abort();
                }
            });
        }
        true
    }

    pub fn list(&self) -> Vec<(u32, String, String, String, String)> {
        let mut result = Vec::new();
        let mut jobs = self.jobs.write().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        for job in jobs.values_mut() {
            // Fallback only: a finished handle whose task never recorded a
            // terminal status (e.g. hard-aborted before mark_*). Never
            // overwrites a recorded Completed/Failed/Cancelled — the task
            // (mark_completed/mark_failed) and kill() (Cancelled) own those.
            if let Some(ref handle) = job.handle
                && handle.is_finished() && matches!(job.status, JobStatus::Running) {
                    job.status = JobStatus::Completed;
                }
            let terminal = matches!(
                job.status,
                JobStatus::Completed | JobStatus::Failed(_) | JobStatus::Cancelled
            ) || job.handle.as_ref().map(|h| h.is_finished()).unwrap_or(false);
            if terminal && job.finished_at.is_none() {
                job.finished_at = Some(now);
            }
        }
        jobs.retain(|_, job| match job.finished_at {
            None => true,
            Some(at) => now.duration_since(at).as_secs() < FINISHED_JOB_RETENTION_SECS,
        });
        let mut ids: Vec<_> = jobs.keys().collect();
        ids.sort();
        for &id in &ids {
            if let Some(job) = jobs.get(id) {
                result.push((
                    *id,
                    job.module.clone(),
                    job.target.clone(),
                    job.started_at.format("%H:%M:%S").to_string(),
                    format!("{}", job.status),
                ));
            }
        }
        result
    }

    pub fn get_detail(&self, id: u32) -> Option<(String, String, String, String, Arc<JobProgress>)> {
        let mut jobs = self.jobs.write().unwrap_or_else(|e| e.into_inner());
        let job = jobs.get_mut(&id)?;
        // Fallback only: a finished handle whose task never recorded a terminal
        // status. Never overwrites a recorded Completed/Failed/Cancelled.
        if let Some(ref handle) = job.handle
            && handle.is_finished() && matches!(job.status, JobStatus::Running) {
                job.status = JobStatus::Completed;
            }
        let terminal = matches!(
            job.status,
            JobStatus::Completed | JobStatus::Failed(_) | JobStatus::Cancelled
        ) || job.handle.as_ref().map(|h| h.is_finished()).unwrap_or(false);
        if terminal && job.finished_at.is_none() {
            job.finished_at = Some(std::time::Instant::now());
        }
        Some((
            job.module.clone(),
            job.target.clone(),
            job.started_at.format("%H:%M:%S").to_string(),
            format!("{}", job.status),
            job.progress.clone(),
        ))
    }

    pub fn get_progress(&self, id: u32) -> Option<Arc<JobProgress>> {
        self.jobs.read().unwrap_or_else(|e| e.into_inner())
            .get(&id).map(|j| j.progress.clone())
    }

    pub fn cleanup(&self) {
        let mut jobs = self.jobs.write().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        for job in jobs.values_mut() {
            let finished = job.handle.as_ref().map(|h| h.is_finished()).unwrap_or(true);
            if finished && job.finished_at.is_none() {
                job.finished_at = Some(now);
            }
        }
        jobs.retain(|_, job| match job.finished_at {
            None => true,
            Some(at) => now.duration_since(at).as_secs() < FINISHED_JOB_RETENTION_SECS,
        });
    }

    pub fn display(&self) {
        let jobs = self.list();
        if jobs.is_empty() {
            crate::mprintln!("{}", "No active jobs.".dimmed());
            return;
        }
        crate::mprintln!();
        crate::mprintln!("{}", format!("Background Jobs ({}):", jobs.len()).bold().underline());
        crate::mprintln!();
        crate::mprintln!("  {:<6} {:<35} {:<20} {:<12} {}",
            "ID".bold(), "Module".bold(), "Target".bold(), "Started".bold(), "Status".bold());
        crate::mprintln!("  {}", "-".repeat(80).dimmed());
        for (id, module, target, started, status) in &jobs {
            let status_colored = if status == "Running" {
                status.green().to_string()
            } else if status == "Completed" {
                status.cyan().to_string()
            } else if status.starts_with("Failed") {
                status.red().to_string()
            } else {
                status.yellow().to_string()
            };
            crate::mprintln!("  {:<6} {:<35} {:<20} {:<12} {}",
                id, module, target, started, status_colored);
        }
        crate::mprintln!();
    }
}

pub static JOB_MANAGER: Lazy<JobManager> = Lazy::new(JobManager::new);

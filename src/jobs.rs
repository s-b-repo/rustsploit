use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::LazyLock as Lazy;
use std::sync::RwLock;

use colored::*;
use serde::Serialize;
use tokio::sync::{broadcast, watch};

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
        if let Ok(mut buf) = self.output.write() {
            if buf.len() >= MAX_OUTPUT_LINES {
                buf.pop_front();
            }
            buf.push_back(line);
        }
        self.total_lines_pushed.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut ts) = self.last_activity.write() {
            *ts = chrono::Local::now();
        }
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
    cancel_tx: watch::Sender<bool>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

const MAX_JOBS: usize = 1000;
const FINISHED_JOB_RETENTION_SECS: u64 = 300;
const DEFAULT_MAX_RUNNING: usize = 5;

/// Manages background jobs.
pub struct JobManager {
    jobs: RwLock<HashMap<u32, Job>>,
    next_id: AtomicU32,
    max_running: AtomicU32,
    event_tx: broadcast::Sender<JobEvent>,
}

impl JobManager {
    fn new() -> Self {
        use rand::RngExt;
        let start = rand::rng().random_range(1..(1u32 << 24));
        let (event_tx, _) = broadcast::channel(256);
        Self {
            jobs: RwLock::new(HashMap::new()),
            next_id: AtomicU32::new(start),
            max_running: AtomicU32::new(DEFAULT_MAX_RUNNING as u32),
            event_tx,
        }
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

    pub fn spawn(
        &self,
        module: String,
        target: String,
        verbose: bool,
        config: Option<crate::config::ModuleConfig>,
    ) -> Result<(u32, Arc<JobProgress>), String> {
        let mut jobs = self.jobs.write().map_err(|_| "Job lock poisoned".to_string())?;

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

        let mut id = self.next_id.fetch_add(1, Ordering::Relaxed);
        while jobs.contains_key(&id) {
            id = self.next_id.fetch_add(1, Ordering::Relaxed);
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
        let progress = JobProgress::new();
        let prog_clone = progress.clone();
        let mod_clone = module.clone();
        let tgt_clone = target.clone();
        let evt_module = module.clone();
        let evt_target = target.clone();
        let event_tx = self.event_tx.clone();

        let handle = tokio::spawn(async move {
            let mut rx = cancel_rx;
            prog_clone.push_line(format!("[*] Starting {} against {}", mod_clone, tgt_clone));
            let run_fut = {
                let m = mod_clone.clone();
                let t = tgt_clone.clone();
                async move {
                    if let Some(cfg) = config {
                        let (result, _ctx) = crate::context::run_with_context_target(
                            cfg,
                            t.clone(),
                            || async move { crate::commands::run_module(&m, &t, verbose).await },
                        ).await;
                        result
                    } else {
                        crate::commands::run_module(&m, &t, verbose).await
                    }
                }
            };
            tokio::select! {
                result = run_fut => {
                    match result {
                        Ok(_) => {
                            prog_clone.push_line(format!("[+] Completed: {} against {}", mod_clone, tgt_clone));
                            crate::mprintln!("\n{}", format!("[*] Job completed: {} against {}", mod_clone, tgt_clone).green());
                            if let Err(e) = event_tx.send(JobEvent::Completed { id }) {
                                tracing::debug!("No WS subscribers for job event: {}", e);
                            }
                        }
                        Err(e) => {
                            let msg = e.to_string();
                            prog_clone.push_line(format!("[-] Failed: {} - {}", mod_clone, msg));
                            crate::meprintln!("\n{}", format!("[!] Job failed: {} - {}", mod_clone, msg).red());
                            if let Err(e) = event_tx.send(JobEvent::Failed { id, error: msg }) {
                                tracing::debug!("No WS subscribers for job event: {}", e);
                            }
                        }
                    }
                }
                _ = async { while rx.changed().await.is_ok() { if *rx.borrow() { break; } } } => {
                    prog_clone.push_line(format!("[!] Cancelled: {}", mod_clone));
                    crate::mprintln!("\n{}", format!("[*] Job cancelled: {}", mod_clone).yellow());
                    if let Err(e) = event_tx.send(JobEvent::Cancelled { id }) {
                        tracing::debug!("No WS subscribers for job event: {}", e);
                    }
                }
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
                Err(_) => return false,
            };
            let job = match jobs.get_mut(&id) {
                Some(j) => j,
                None => return false,
            };
            if let Err(e) = job.cancel_tx.send(true) {
                crate::meprintln!("[!] Job cancel signal error: {}", e);
            }
            job.status = JobStatus::Cancelled;
            if job.finished_at.is_none() {
                job.finished_at = Some(std::time::Instant::now());
            }
            job.handle.take()
        };
        if let Some(handle) = handle_and_tx {
            let abort_handle = handle.abort_handle();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                if !handle.is_finished() {
                    abort_handle.abort();
                }
            });
        }
        true
    }

    pub fn list(&self) -> Vec<(u32, String, String, String, String)> {
        let mut result = Vec::new();
        if let Ok(mut jobs) = self.jobs.write() {
            let now = std::time::Instant::now();
            for job in jobs.values_mut() {
                if let Some(ref handle) = job.handle {
                    if handle.is_finished() && matches!(job.status, JobStatus::Running) {
                        job.status = JobStatus::Completed;
                    }
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
        }
        result
    }

    pub fn get_detail(&self, id: u32) -> Option<(String, String, String, String, Arc<JobProgress>)> {
        if let Ok(mut jobs) = self.jobs.write() {
            if let Some(job) = jobs.get_mut(&id) {
                if let Some(ref handle) = job.handle {
                    if handle.is_finished() && matches!(job.status, JobStatus::Running) {
                        job.status = JobStatus::Completed;
                    }
                }
                let terminal = matches!(
                    job.status,
                    JobStatus::Completed | JobStatus::Failed(_) | JobStatus::Cancelled
                ) || job.handle.as_ref().map(|h| h.is_finished()).unwrap_or(false);
                if terminal && job.finished_at.is_none() {
                    job.finished_at = Some(std::time::Instant::now());
                }
                return Some((
                    job.module.clone(),
                    job.target.clone(),
                    job.started_at.format("%H:%M:%S").to_string(),
                    format!("{}", job.status),
                    job.progress.clone(),
                ));
            }
        }
        None
    }

    pub fn get_progress(&self, id: u32) -> Option<Arc<JobProgress>> {
        self.jobs.read().ok().and_then(|jobs| {
            jobs.get(&id).map(|j| j.progress.clone())
        })
    }

    pub fn cleanup(&self) {
        if let Ok(mut jobs) = self.jobs.write() {
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

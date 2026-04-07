use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::RwLock;
use once_cell::sync::Lazy;
use serde::Serialize;
use colored::*;
use tokio::sync::watch;

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

/// A background job entry.
pub struct Job {
    pub id: u32,
    pub module: String,
    pub target: String,
    pub started_at: chrono::DateTime<chrono::Local>,
    pub status: JobStatus,
    cancel_tx: watch::Sender<bool>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

/// Manages background jobs.
pub struct JobManager {
    jobs: RwLock<HashMap<u32, Job>>,
    next_id: AtomicU32,
}

impl JobManager {
    fn new() -> Self {
        Self {
            jobs: RwLock::new(HashMap::new()),
            next_id: AtomicU32::new(1),
        }
    }

    /// Spawn a module as a background job. Returns the job ID.
    pub fn spawn(
        &self,
        module: String,
        target: String,
        verbose: bool,
    ) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (cancel_tx, cancel_rx) = watch::channel(false);

        let mod_clone = module.clone();
        let tgt_clone = target.clone();

        let handle = tokio::spawn(async move {
            let mut rx = cancel_rx;
            tokio::select! {
                result = crate::commands::run_module(&mod_clone, &tgt_clone, verbose) => {
                    match result {
                        Ok(_) => {
                            println!("\n{}", format!("[*] Job completed: {} against {}", mod_clone, tgt_clone).green());
                        }
                        Err(e) => {
                            eprintln!("\n{}", format!("[!] Job failed: {} - {}", mod_clone, e).red());
                        }
                    }
                }
                _ = async { while rx.changed().await.is_ok() { if *rx.borrow() { break; } } } => {
                    println!("\n{}", format!("[*] Job cancelled: {}", mod_clone).yellow());
                }
            }
        });

        let job = Job {
            id,
            module,
            target,
            started_at: chrono::Local::now(),
            status: JobStatus::Running,
            cancel_tx,
            handle: Some(handle),
        };

        if let Ok(mut jobs) = self.jobs.write() {
            jobs.insert(id, job);
        }

        id
    }

    /// Kill a background job.
    pub fn kill(&self, id: u32) -> bool {
        if let Ok(mut jobs) = self.jobs.write() {
            if let Some(job) = jobs.get_mut(&id) {
                let _ = job.cancel_tx.send(true);
                if let Some(handle) = job.handle.take() {
                    handle.abort();
                }
                job.status = JobStatus::Cancelled;
                return true;
            }
        }
        false
    }

    /// List all jobs. Auto-cleans finished jobs older than 5 minutes.
    pub fn list(&self) -> Vec<(u32, String, String, String, String)> {
        // Auto-cleanup finished jobs
        self.cleanup();
        let mut result = Vec::new();
        if let Ok(jobs) = self.jobs.read() {
            let mut ids: Vec<_> = jobs.keys().collect();
            ids.sort();
            for &id in &ids {
                if let Some(job) = jobs.get(id) {
                    // Check if handle is finished
                    let status = if let Some(ref handle) = job.handle {
                        if handle.is_finished() {
                            "Completed".to_string()
                        } else {
                            format!("{}", job.status)
                        }
                    } else {
                        format!("{}", job.status)
                    };
                    result.push((
                        *id,
                        job.module.clone(),
                        job.target.clone(),
                        job.started_at.format("%H:%M:%S").to_string(),
                        status,
                    ));
                }
            }
        }
        result
    }

    /// Clean up finished jobs.
    pub fn cleanup(&self) {
        if let Ok(mut jobs) = self.jobs.write() {
            jobs.retain(|_, job| {
                if let Some(ref handle) = job.handle {
                    !handle.is_finished()
                } else {
                    false
                }
            });
        }
    }

    /// Display jobs table.
    pub fn display(&self) {
        let jobs = self.list();
        if jobs.is_empty() {
            println!("{}", "No active jobs.".dimmed());
            return;
        }
        println!();
        println!("{}", format!("Background Jobs ({}):", jobs.len()).bold().underline());
        println!();
        println!("  {:<6} {:<35} {:<20} {:<12} {}",
            "ID".bold(), "Module".bold(), "Target".bold(), "Started".bold(), "Status".bold());
        println!("  {}", "-".repeat(80).dimmed());
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
            println!("  {:<6} {:<35} {:<20} {:<12} {}",
                id, module, target, started, status_colored);
        }
        println!();
    }
}

pub static JOB_MANAGER: Lazy<JobManager> = Lazy::new(JobManager::new);

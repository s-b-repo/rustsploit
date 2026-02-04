// src/job_archive.rs
//
// Immutable job output archival system
// - In-memory circular buffer for recent jobs
// - Automatic archival to compressed tar.gz files
// - SHA256 checksums for integrity

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Maximum output size per job (1MB) - reduced from 10MB for DoS protection
pub const MAX_OUTPUT_SIZE: usize = 1 * 1024 * 1024;

/// Maximum jobs in memory before archiving - reduced from 100 for DoS protection
const MAX_MEMORY_JOBS: usize = 20;

/// Maximum total archive size (1GB) before cleanup
const MAX_ARCHIVE_SIZE_BYTES: u64 = 1024 * 1024 * 1024;

/// A single job result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    /// Unique job identifier
    pub id: String,
    /// Module that was executed
    pub module: String,
    /// Target that was scanned/exploited
    pub target: String,
    /// Captured output (stdout + stderr)
    pub output: String,
    /// Whether output was truncated
    pub truncated: bool,
    /// Job status
    pub status: JobStatus,
    /// When the job started
    pub started_at: DateTime<Utc>,
    /// When the job completed
    pub completed_at: Option<DateTime<Utc>>,
    /// Duration in milliseconds
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    Running,
    Completed,
    Failed,
    Timeout,
}

/// Thread-safe job storage with automatic archival
#[derive(Clone)]
pub struct JobArchive {
    /// In-memory job storage
    jobs: Arc<RwLock<VecDeque<JobResult>>>,
    /// Archive directory
    archive_dir: PathBuf,
}

impl JobArchive {
    /// Create a new job archive
    pub fn new() -> Result<Self> {
        let home = home::home_dir()
            .ok_or_else(|| anyhow!("Cannot determine home directory"))?;
        let archive_dir = home.join(".rustsploit").join("archives");
        
        // Create archive directory if it doesn't exist
        if !archive_dir.exists() {
            fs::create_dir_all(&archive_dir)
                .context("Failed to create archive directory")?;
        }
        
        Ok(Self {
            jobs: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_MEMORY_JOBS + 10))),
            archive_dir,
        })
    }
    
    /// Add a new job result
    pub async fn add_job(&self, job: JobResult) -> Result<()> {
        let mut jobs = self.jobs.write().await;
        
        // Check if we need to archive before adding
        if jobs.len() >= MAX_MEMORY_JOBS {
            // Archive oldest jobs
            let to_archive: Vec<JobResult> = jobs.drain(..MAX_MEMORY_JOBS / 2).collect();
            drop(jobs); // Release lock before archiving
            
            self.archive_jobs(to_archive).await?;
            
            // Re-acquire lock
            let mut jobs = self.jobs.write().await;
            jobs.push_back(job);
        } else {
            jobs.push_back(job);
        }
        
        Ok(())
    }
    
    /// Get a job by ID
    pub async fn get_job(&self, id: &str) -> Option<JobResult> {
        let jobs = self.jobs.read().await;
        jobs.iter().find(|j| j.id == id).cloned()
    }
    
    /// Update a job's status and output
    pub async fn update_job(&self, id: &str, output: String, status: JobStatus) -> Result<()> {
        let mut jobs = self.jobs.write().await;
        
        if let Some(job) = jobs.iter_mut().find(|j| j.id == id) {
            // Truncate output if too large
            let (final_output, truncated) = if output.len() > MAX_OUTPUT_SIZE {
                let truncated_output = format!(
                    "{}\n\n[OUTPUT TRUNCATED - exceeded {}MB limit]",
                    &output[..MAX_OUTPUT_SIZE - 100],
                    MAX_OUTPUT_SIZE / 1024 / 1024
                );
                (truncated_output, true)
            } else {
                (output, false)
            };
            
            job.output = final_output;
            job.truncated = truncated;
            job.status = status;
            job.completed_at = Some(Utc::now());
            
            // Calculate duration
            let now = Utc::now().timestamp_millis();
            job.duration_ms = Some((now - job.started_at.timestamp_millis()) as u64);
        }
        
        Ok(())
    }
    
    /// Create a new job entry with empty output
    pub fn create_job(id: String, module: String, target: String) -> JobResult {
        JobResult {
            id,
            module,
            target,
            output: String::new(),
            truncated: false,
            status: JobStatus::Running,
            started_at: Utc::now(),
            completed_at: None,
            duration_ms: None,
        }
    }
    
    /// Archive jobs to a compressed, immutable tar.gz file
    async fn archive_jobs(&self, jobs: Vec<JobResult>) -> Result<()> {
        if jobs.is_empty() {
            return Ok(());
        }
        
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let archive_name = format!("jobs_{}.tar.gz", timestamp);
        let archive_path = self.archive_dir.join(&archive_name);
        let checksum_path = self.archive_dir.join(format!("jobs_{}.sha256", timestamp));
        
        // Create tar.gz archive
        let tar_gz = File::create(&archive_path)
            .context("Failed to create archive file")?;
        let enc = GzEncoder::new(tar_gz, Compression::default());
        let mut tar = tar::Builder::new(enc);
        
        // Add each job as a JSON file in the archive
        for job in &jobs {
            let job_json = serde_json::to_string_pretty(job)
                .context("Failed to serialize job")?;
            
            let mut header = tar::Header::new_gnu();
            header.set_size(job_json.len() as u64);
            header.set_mode(0o444); // Read-only
            header.set_cksum();
            
            tar.append_data(
                &mut header,
                format!("{}.json", job.id),
                job_json.as_bytes(),
            ).context("Failed to add job to archive")?;
        }
        
        // Finish the archive
        let enc = tar.into_inner()
            .context("Failed to finalize tar archive")?;
        enc.finish()
            .context("Failed to finalize gzip compression")?;
        
        // Calculate SHA256 checksum
        let mut file = File::open(&archive_path)
            .context("Failed to open archive for checksum")?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 { break; }
            hasher.update(&buffer[..n]);
        }
        let checksum = format!("{:x}  {}\n", hasher.finalize(), archive_name);
        
        // Write checksum file
        let mut checksum_file = File::create(&checksum_path)
            .context("Failed to create checksum file")?;
        checksum_file.write_all(checksum.as_bytes())
            .context("Failed to write checksum")?;
        
        // Make archive and checksum read-only
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&archive_path, fs::Permissions::from_mode(0o444))
                .context("Failed to set archive permissions")?;
            fs::set_permissions(&checksum_path, fs::Permissions::from_mode(0o444))
                .context("Failed to set checksum permissions")?;
        }
        
        eprintln!("[INFO] Archived {} jobs to {}", jobs.len(), archive_path.display());
        
        // Cleanup old archives if disk limit exceeded
        Self::cleanup_old_archives(&self.archive_dir)?;
        
        Ok(())
    }
    
    /// Delete oldest archives if total size exceeds MAX_ARCHIVE_SIZE_BYTES (1GB)
    fn cleanup_old_archives(archive_dir: &PathBuf) -> Result<()> {
        let mut archives: Vec<_> = fs::read_dir(archive_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "gz"))
            .collect();
        
        // Sort by modification time (oldest first)
        archives.sort_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()));
        
        let total_size: u64 = archives.iter()
            .filter_map(|e| e.metadata().ok().map(|m| m.len()))
            .sum();
        
        if total_size > MAX_ARCHIVE_SIZE_BYTES {
            let mut freed = 0u64;
            for entry in &archives {
                if total_size - freed <= MAX_ARCHIVE_SIZE_BYTES {
                    break;
                }
                if let Ok(metadata) = entry.metadata() {
                    let size = metadata.len();
                    let path = entry.path();
                    if fs::remove_file(&path).is_ok() {
                        // Also remove matching .sha256 file
                        let mut sha_path = path.clone();
                        sha_path.set_extension("sha256");
                        let _ = fs::remove_file(sha_path);
                        freed += size;
                        eprintln!("[CLEANUP] Removed old archive: {} (freed {} bytes)", path.display(), size);
                    }
                }
            }
            eprintln!("[CLEANUP] Total freed: {} bytes", freed);
        }
        Ok(())
    }
    
    /// List all jobs in memory
    pub async fn list_jobs(&self) -> Vec<JobResult> {
        let jobs = self.jobs.read().await;
        jobs.iter().cloned().collect()
    }
    
    /// Get archive directory path
    pub fn archive_dir(&self) -> &PathBuf {
        &self.archive_dir
    }
}

impl Default for JobArchive {
    fn default() -> Self {
        match Self::new() {
            Ok(archive) => archive,
            Err(e) => {
                eprintln!("[!] Warning: Failed to create job archive: {}. Using fallback.", e);
                // Fallback to current directory
                Self {
                    archive_dir: std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
                    jobs: std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
                }
            }
        }
    }
}

/// Output buffer with overflow protection
pub struct OutputBuffer {
    buffer: String,
    max_size: usize,
    truncated: bool,
}

impl OutputBuffer {
    pub fn new() -> Self {
        Self {
            buffer: String::with_capacity(1024 * 64), // 64KB initial
            max_size: MAX_OUTPUT_SIZE,
            truncated: false,
        }
    }
    
    /// Append data to buffer, respecting max size
    pub fn append(&mut self, data: &str) {
        if self.truncated {
            return; // Already at max, ignore further input
        }
        
        let remaining = self.max_size.saturating_sub(self.buffer.len());
        if remaining == 0 {
            self.truncated = true;
            self.buffer.push_str("\n\n[OUTPUT TRUNCATED]");
            return;
        }
        
        if data.len() <= remaining {
            self.buffer.push_str(data);
        } else {
            self.buffer.push_str(&data[..remaining]);
            self.truncated = true;
            self.buffer.push_str("\n\n[OUTPUT TRUNCATED]");
        }
    }
    
    /// Get the final output
    pub fn finish(self) -> (String, bool) {
        (self.buffer, self.truncated)
    }
}

impl Default for OutputBuffer {
    fn default() -> Self {
        Self::new()
    }
}

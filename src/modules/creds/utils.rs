use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use colored::*;
use tokio::sync::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use rand::Rng;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;



/// Standard statistics tracking for bruteforce modules
pub struct BruteforceStats {
    total_attempts: AtomicU64,
    successful_attempts: AtomicU64,
    failed_attempts: AtomicU64,
    error_attempts: AtomicU64,
    retried_attempts: AtomicU64,
    start_time: Instant,
    unique_errors: Mutex<HashMap<String, usize>>,
}

impl BruteforceStats {
    pub fn new() -> Self {
        Self {
            total_attempts: AtomicU64::new(0),
            successful_attempts: AtomicU64::new(0),
            failed_attempts: AtomicU64::new(0),
            error_attempts: AtomicU64::new(0),
            retried_attempts: AtomicU64::new(0),
            start_time: Instant::now(),
            unique_errors: Mutex::new(HashMap::new()),
        }
    }

    pub fn record_attempt(&self, success: bool, error: bool) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        if error {
            self.error_attempts.fetch_add(1, Ordering::Relaxed);
        } else if success {
            self.successful_attempts.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_attempts.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_success(&self) {
        self.record_attempt(true, false);
    }

    pub fn record_failure(&self) {
        self.record_attempt(false, false);
    }

    pub fn record_retry(&self) {
        self.retried_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn record_error_detail(&self, msg: String) {
        let mut guard = self.unique_errors.lock().await;
        *guard.entry(msg).or_insert(0) += 1;
    }

    pub async fn record_error(&self, msg: String) {
        // Increment error counter
        self.record_attempt(false, true);
        // Record detail
        self.record_error_detail(msg).await;
    }

    pub fn print_progress(&self) {
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_attempts.load(Ordering::Relaxed);
        let failed = self.failed_attempts.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let retries = self.retried_attempts.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 };

        print!(
            "\r{} {} attempts | {} OK | {} fail | {} err | {} retry | {:.1}/s    ",
            "[Progress]".cyan(),
            total.to_string().bold(),
            success.to_string().green(),
            failed,
            errors.to_string().red(),
            retries,
            rate
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }

    pub async fn print_final(&self) {
        println!();
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_attempts.load(Ordering::Relaxed);
        let failed = self.failed_attempts.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let retries = self.retried_attempts.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();

        println!("{}", "=== Statistics ===".bold());
        println!("  Total attempts:    {}", total);
        println!("  Successful:        {}", success.to_string().green().bold());
        println!("  Failed:            {}", failed);
        println!("  Errors:            {}", errors.to_string().red());
        println!("  Retries:           {}", retries);
        println!("  Elapsed time:      {:.2}s", elapsed);
        if elapsed > 0.0 {
            println!("  Average rate:      {:.1} attempts/s", total as f64 / elapsed);
        }

        let errors_guard = self.unique_errors.lock().await;
        if !errors_guard.is_empty() {
             println!("\n{}", "Top Errors:".bold());
             let mut sorted_errors: Vec<_> = errors_guard.iter().collect();
             sorted_errors.sort_by(|a, b| b.1.cmp(a.1));
             for (msg, count) in sorted_errors.into_iter().take(5) {
                 println!("  - {}: {}", msg.yellow(), count);
             }
        }
    }
}

pub fn generate_random_public_ip(exclusions: &[ipnetwork::IpNetwork]) -> IpAddr {
    let mut rng = rand::rng();
    loop {
        let octets: [u8; 4] = rng.random();
        let ip = Ipv4Addr::from(octets);
        let ip_addr = IpAddr::V4(ip);
        
        // Basic check first to avoid expensive loop
        if octets[0] == 10 || octets[0] == 127 || octets[0] == 0 {
             continue;
        }

        let mut excluded = false;
        for net in exclusions {
            if net.contains(ip_addr) {
                excluded = true;
                break;
            }
        }
        
        if !excluded {
            return ip_addr;
        }
    }
}

pub async fn is_ip_checked(ip: &impl ToString, state_file: &str) -> bool {
    // Ensure state file exists before checking
    if !std::path::Path::new(state_file).exists() {
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .write(true)
            .open(state_file)
            .await
        {
            let _ = file.flush().await;
        }
        return false;
    }

    let ip_s = ip.to_string();
    let status = Command::new("grep")
        .arg("-F")
        .arg("-q")
        .arg(format!("checked: {}", ip_s))
        .arg(state_file)
        .status()
        .await;
    
    match status {
        Ok(s) => s.success(), 
        Err(_) => false, 
    }
}

pub async fn mark_ip_checked(ip: &impl ToString, state_file: &str) {
    let data = format!("checked: {}\n", ip.to_string());
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(state_file)
        .await 
    {
        let _ = file.write_all(data.as_bytes()).await;
    }
}

pub fn parse_exclusions(min_ranges: &[&str]) -> Vec<ipnetwork::IpNetwork> {
    let mut exclusion_subnets = Vec::new();
    for cidr in min_ranges {
        if let Ok(net) = cidr.parse::<ipnetwork::IpNetwork>() {
            exclusion_subnets.push(net);
        }
    }
    exclusion_subnets
}

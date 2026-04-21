use anyhow::{Context, Result};
use colored::*;
use futures::stream::{FuturesUnordered, StreamExt};
use rand::RngExt;
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex, Semaphore};

use crate::utils::cfg_prompt_int_range;
use crate::utils::cfg_prompt_output_file;

/// Standard IP exclusion ranges for mass scanning (private, reserved, CDN, DNS).
pub const EXCLUDED_RANGES: &[&str] = &[
    "10.0.0.0/8",
    "127.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "0.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "255.255.255.255/32",
    // Cloudflare
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "1.1.1.1/32",
    "1.0.0.1/32",
    // Google
    "8.8.8.8/32",
    "8.8.4.4/32",
];

/// Standard statistics tracking for bruteforce modules.
/// Provides real-time progress with ETA, percentage, speed, and lockout detection.
pub struct BruteforceStats {
    total_attempts: AtomicU64,
    successful_attempts: AtomicU64,
    failed_attempts: AtomicU64,
    error_attempts: AtomicU64,
    retried_attempts: AtomicU64,
    total_expected: AtomicU64,
    consecutive_errors: AtomicU64,
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
            total_expected: AtomicU64::new(0),
            consecutive_errors: AtomicU64::new(0),
            start_time: Instant::now(),
            unique_errors: Mutex::new(HashMap::new()),
        }
    }

    /// Set the total expected number of attempts (enables percentage + ETA display).
    pub fn set_total(&self, n: u64) {
        self.total_expected.store(n, Ordering::Relaxed);
    }

    pub fn record_attempt(&self, success: bool, error: bool) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        if error {
            self.error_attempts.fetch_add(1, Ordering::Relaxed);
            self.consecutive_errors.fetch_add(1, Ordering::Relaxed);
        } else if success {
            self.successful_attempts.fetch_add(1, Ordering::Relaxed);
            self.consecutive_errors.store(0, Ordering::Relaxed);
        } else {
            self.failed_attempts.fetch_add(1, Ordering::Relaxed);
            self.consecutive_errors.store(0, Ordering::Relaxed);
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

    /// Returns true if consecutive errors exceed the threshold (possible lockout).
    pub fn is_lockout_likely(&self, threshold: u64) -> bool {
        self.consecutive_errors.load(Ordering::Relaxed) >= threshold
    }

    pub async fn record_error_detail(&self, msg: String) {
        let mut guard = self.unique_errors.lock().await;
        *guard.entry(msg).or_insert(0) += 1;
    }

    pub async fn record_error(&self, msg: String) {
        self.record_attempt(false, true);
        self.record_error_detail(msg).await;
    }

    pub fn print_progress(&self) {
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_attempts.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let retries = self.retried_attempts.load(Ordering::Relaxed);
        let expected = self.total_expected.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 {
            total as f64 / elapsed
        } else {
            0.0
        };

        if expected > 0 {
            let pct = (total as f64 / expected as f64 * 100.0).min(100.0);
            let remaining = expected.saturating_sub(total);
            let eta_secs = if rate > 0.0 {
                remaining as f64 / rate
            } else {
                0.0
            };
            let eta_str = format_duration(eta_secs);

            crate::mprint!(
                "\r{} {}/{} ({:.1}%) | {} OK | {} err | {} retry | {:.1}/s | ETA: {}    ",
                "[Progress]".cyan(),
                total.to_string().bold(),
                expected,
                pct,
                success.to_string().green(),
                errors.to_string().red(),
                retries,
                rate,
                eta_str.yellow()
            );
        } else {
            crate::mprint!(
                "\r{} {} attempts | {} OK | {} err | {} retry | {:.1}/s    ",
                "[Progress]".cyan(),
                total.to_string().bold(),
                success.to_string().green(),
                errors.to_string().red(),
                retries,
                rate
            );
        }
        if let Err(e) = std::io::Write::flush(&mut std::io::stdout()) { crate::meprintln!("[!] Flush error: {}", e); }
    }

    pub async fn print_final(&self) {
        crate::mprintln!();
        let total = self.total_attempts.load(Ordering::Relaxed);
        let success = self.successful_attempts.load(Ordering::Relaxed);
        let failed = self.failed_attempts.load(Ordering::Relaxed);
        let errors = self.error_attempts.load(Ordering::Relaxed);
        let retries = self.retried_attempts.load(Ordering::Relaxed);
        let expected = self.total_expected.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let elapsed_str = format_duration(elapsed);

        crate::mprintln!("{}", "=== Final Statistics ===".bold());
        if expected > 0 {
            crate::mprintln!(
                "  Total attempts:    {}/{} ({:.1}%)",
                total,
                expected,
                (total as f64 / expected as f64 * 100.0).min(100.0)
            );
        } else {
            crate::mprintln!("  Total attempts:    {}", total);
        }
        crate::mprintln!(
            "  Successful:        {}",
            success.to_string().green().bold()
        );
        crate::mprintln!("  Failed:            {}", failed);
        crate::mprintln!("  Errors:            {}", errors.to_string().red());
        crate::mprintln!("  Retries:           {}", retries);
        crate::mprintln!("  Elapsed time:      {}", elapsed_str);
        if elapsed > 0.0 {
            crate::mprintln!(
                "  Average rate:      {:.1} attempts/s",
                total as f64 / elapsed
            );
        }

        let errors_guard = self.unique_errors.lock().await;
        if !errors_guard.is_empty() {
            crate::mprintln!("\n{}", "Top Errors:".bold());
            let mut sorted_errors: Vec<_> = errors_guard.iter().collect();
            sorted_errors.sort_by(|a, b| b.1.cmp(a.1));
            for (msg, count) in sorted_errors.into_iter().take(5) {
                crate::mprintln!("  - {}: {}", msg.yellow(), count);
            }
        }
    }
}

/// Format seconds into HH:MM:SS display string.
pub fn format_duration(secs: f64) -> String {
    let total = secs as u64;
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    if h > 0 {
        format!("{:02}:{:02}:{:02}", h, m, s)
    } else {
        format!("{:02}:{:02}", m, s)
    }
}

/// Compute exponential backoff delay with random jitter.
/// `base_ms` — base delay in milliseconds (e.g. 500)
/// `attempt` — retry attempt number (0-indexed, delay doubles each time)
/// `max_multiplier` — cap on the 2^attempt multiplier (e.g. 8 = max 8x base)
pub fn backoff_delay(base_ms: u64, attempt: u32, max_multiplier: u64) -> Duration {
    let multiplier = (1u64 << attempt.min(16)).min(max_multiplier);
    let backoff = base_ms.saturating_mul(multiplier);
    let jitter = if backoff > 0 {
        rand::rng().random_range(0..=backoff / 2)
    } else {
        0
    };
    Duration::from_millis(backoff + jitter)
}

pub fn generate_random_public_ip(exclusions: &[ipnetwork::IpNetwork]) -> IpAddr {
    let mut rng = rand::rng();
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        if attempts > 100_000 {
            // Fallback: generate from common public ranges and re-check exclusions
            let fallback = IpAddr::V4(std::net::Ipv4Addr::new(
                rng.random_range(1..224),
                rng.random_range(0..256) as u8,
                rng.random_range(0..256) as u8,
                rng.random_range(1..255) as u8,
            ));
            if !exclusions.iter().any(|net| net.contains(fallback)) {
                return fallback;
            }
            continue; // Fallback was excluded too — keep trying
        }

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

/// In-memory dedup set for mass scan IP tracking.
/// Avoids the TOCTOU race of file-based is_ip_checked + mark_ip_checked.
static CHECKED_IPS: std::sync::LazyLock<tokio::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(std::collections::HashSet::new()));

/// Atomically check AND mark an IP in a single lock acquisition.
/// Returns `true` if the IP was already checked (caller should skip it).
/// On first call, loads persisted state from file (cold start recovery).
/// Persists the new entry to file for restart durability.
pub async fn check_and_mark_ip(ip: &impl ToString, state_file: &str) -> bool {
    if state_file.contains("..") {
        crate::meprintln!("[!] Invalid state file path: {}", state_file);
        return false;
    }
    let ip_str = ip.to_string();
    {
        let mut set = CHECKED_IPS.lock().await;

        // Cold start: load persisted state from file on first access
        if set.is_empty() {
            if let Ok(contents) = tokio::fs::read_to_string(state_file).await {
                for line in contents.lines() {
                    if let Some(checked_ip) = line.strip_prefix("checked: ") {
                        set.insert(checked_ip.to_string());
                    }
                }
            }
        }

        if !set.insert(ip_str.clone()) {
            // Already present — skip this IP
            return true;
        }
    }
    // Persist outside the lock to minimize hold time
    let data = format!("checked: {}\n", ip_str);
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(state_file)
        .await
    {
        if let Err(e) = file.write_all(data.as_bytes()).await { crate::meprintln!("[!] Write error: {}", e); }
    }
    false
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

/// Check if a target string is a CIDR subnet (e.g. "192.168.8.0/21").
/// Any valid CIDR notation (including 0.0.0.0/0) is treated as a subnet target.
pub fn is_subnet_target(target: &str) -> bool {
    if !target.contains('/') {
        return false;
    }
    target.parse::<ipnetwork::IpNetwork>().is_ok()
}

/// Parse a CIDR string into an IpNetwork for lazy iteration.
/// Does NOT allocate a Vec — callers iterate with `network.iter()`.
/// This handles ANY subnet size (/0 through /32) without OOM risk.
pub fn parse_subnet(target: &str) -> Result<ipnetwork::IpNetwork, anyhow::Error> {
    let network: ipnetwork::IpNetwork = target
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid CIDR '{}': {}", target, e))?;
    Ok(network)
}

/// Get the number of host IPs in a network (for display purposes).
pub fn subnet_host_count(net: &ipnetwork::IpNetwork) -> u128 {
    match net.size() {
        ipnetwork::NetworkSize::V4(n) => n as u128,
        ipnetwork::NetworkSize::V6(n) => n,
    }
}

// ============================================================
// UNIFIED MASS SCAN ENGINE
// ============================================================

/// Check if a target triggers mass scan mode.
/// Recognizes: "random", "0.0.0.0", "0.0.0.0/0", CIDR subnets, and file paths.
pub fn is_mass_scan_target(target: &str) -> bool {
    target == "random"
        || target == "0.0.0.0"
        || target == "0.0.0.0/0"
        || is_subnet_target(target)
        || std::path::Path::new(target).is_file()
}

/// Configuration for the shared mass scan engine.
pub struct MassScanConfig {
    pub protocol_name: &'static str,
    pub default_port: u16,
    pub state_file: &'static str,
    pub default_output: &'static str,
    pub default_concurrency: usize,
}

/// Run a mass scan using the shared engine. Modules provide a `probe` closure
/// that receives `(ip, port)` and returns `Option<String>` — `Some(log_line)` on
/// a successful hit (appended to the output file), `None` on failure/skip.
///
/// Handles: IP generation, state tracking, concurrency, progress, output writing.
pub async fn run_mass_scan<F, Fut>(target: &str, cfg: MassScanConfig, probe: F) -> Result<()>
where
    F: Fn(IpAddr, u16) -> Fut + Send + Sync + 'static + Clone,
    Fut: Future<Output = Option<String>> + Send,
{
    crate::mprintln!(
        "\n{}",
        format!("=== {} Mass Scan ===", cfg.protocol_name)
            .bold()
            .cyan()
    );

    let port =
        cfg_prompt_int_range("port", "Port", cfg.default_port as i64, 1, 65535).await? as u16;
    let concurrency = cfg_prompt_int_range(
        "concurrency",
        "Concurrent hosts",
        cfg.default_concurrency as i64,
        1,
        10000,
    )
    .await? as usize;
    let output_file = cfg_prompt_output_file(
        "output_file",
        "Output file (append mode)",
        cfg.default_output,
    )
    .await?;

    let exclusions = Arc::new(parse_exclusions(EXCLUDED_RANGES));
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let checked = Arc::new(AtomicUsize::new(0));
    let found = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    // Bounded channel → async file writer (append mode)
    let (tx, mut rx) = mpsc::channel::<String>(1024);
    let out = output_file.clone();
    tokio::spawn(async move {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&out)
            .await;
        match file {
            Ok(mut f) => {
                while let Some(line) = rx.recv().await {
                    if let Err(e) = f.write_all(line.as_bytes()).await { crate::meprintln!("[!] Write error: {}", e); }
                }
            }
            Err(e) => {
                crate::meprintln!("[!] Cannot open output file '{}': {}", out, e);
                // Drain the channel so senders don't block
                while rx.recv().await.is_some() {}
            }
        }
    });

    // Progress reporter
    let p_checked = checked.clone();
    let p_found = found.clone();
    let p_stop = stop.clone();
    let p_name = cfg.protocol_name;
    let progress_start = Instant::now();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if p_stop.load(Ordering::Relaxed) {
                break;
            }
            let c = p_checked.load(Ordering::Relaxed);
            let f = p_found.load(Ordering::Relaxed);
            let elapsed = progress_start.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                c as f64 / elapsed
            } else {
                0.0
            };
            crate::mprintln!(
                "[*] {} | Scanned: {} | Hits: {} | {:.1} hosts/s",
                p_name,
                c,
                f.to_string().green().bold(),
                rate
            );
        }
    });

    let is_random = target == "random" || target == "0.0.0.0" || target == "0.0.0.0/0";
    let is_cidr = !is_random && is_subnet_target(target);
    let state_file = cfg.state_file;

    if is_random {
        crate::mprintln!(
            "{}",
            "[*] Mode: Random Internet Scan (Ctrl+C to stop)".yellow()
        );
        let max_checks: usize = crate::global_options::GLOBAL_OPTIONS
            .try_get("max_random_hosts")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10_000_000);

        loop {
            if checked.load(Ordering::Relaxed) >= max_checks {
                crate::mprintln!("[*] Reached max scan limit ({}), stopping.", max_checks);
                break;
            }

            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .context("Semaphore closed")?;
            let exc = exclusions.clone();
            let sc = checked.clone();
            let sf = found.clone();
            let tx = tx.clone();
            let probe = probe.clone();

            tokio::spawn(async move {
                let ip = generate_random_public_ip(&exc);
                if !check_and_mark_ip(&ip, state_file).await {
                    if let Some(line) = probe(ip, port).await {
                        sf.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = tx.send(line).await {
                            crate::meprintln!("[!] Channel send error: {}", e);
                        }
                    }
                }
                sc.fetch_add(1, Ordering::Relaxed);
                drop(permit);
            });
        }
    } else if is_cidr {
        // CIDR subnet mode — iterate over every IP in the range
        let network = parse_subnet(target)?;
        let host_count = subnet_host_count(&network);
        crate::mprintln!(
            "{}",
            format!("[*] Mode: Subnet scan — {} ({} hosts)", network, host_count).cyan()
        );

        for ip_addr in network.iter() {
            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .context("Semaphore closed")?;
            let sc = checked.clone();
            let sf = found.clone();
            let tx = tx.clone();
            let probe = probe.clone();

            tokio::spawn(async move {
                if !check_and_mark_ip(&ip_addr, state_file).await {
                    if let Some(line) = probe(ip_addr, port).await {
                        sf.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = tx.send(line).await {
                            crate::meprintln!("[!] Channel send error: {}", e);
                        }
                    }
                }
                sc.fetch_add(1, Ordering::Relaxed);
                drop(permit);
            });
        }

        // Wait for all tasks to finish
        for _ in 0..concurrency {
            if let Err(e) = semaphore.acquire().await { crate::meprintln!("[!] Semaphore error: {}", e); }
        }
    } else {
        // File mode
        let content = match crate::utils::safe_read_to_string_async(target, None).await {
            Ok(c) => c,
            Err(e) => {
                crate::meprintln!("[!] Failed to read target file '{}': {}", target, e);
                return Ok(());
            }
        };
        let targets: Vec<String> = content
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        crate::mprintln!(
            "{}",
            format!("[*] Mode: File scan — {} targets loaded", targets.len()).cyan()
        );

        for ip_str in &targets {
            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .context("Semaphore closed")?;
            let sc = checked.clone();
            let sf = found.clone();
            let tx = tx.clone();
            let probe = probe.clone();
            let ip_str = ip_str.clone();

            tokio::spawn(async move {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    if !check_and_mark_ip(&ip, state_file).await {
                        if let Some(line) = probe(ip, port).await {
                            sf.fetch_add(1, Ordering::Relaxed);
                            if let Err(e) = tx.send(line).await {
                                crate::meprintln!("[!] Channel send error: {}", e);
                            }
                        }
                    }
                }
                sc.fetch_add(1, Ordering::Relaxed);
                drop(permit);
            });
        }

        // Wait for all tasks to finish
        for _ in 0..concurrency {
            if let Err(e) = semaphore.acquire().await { crate::meprintln!("[!] Semaphore error: {}", e); }
        }
    }

    stop.store(true, Ordering::Relaxed);
    drop(tx);
    crate::mprintln!(
        "\n[*] {} mass scan complete. Results saved to: {}",
        cfg.protocol_name,
        output_file
    );
    crate::mprintln!(
        "[*] Total scanned: {} | Hits: {}",
        checked.load(Ordering::Relaxed),
        found.load(Ordering::Relaxed).to_string().green().bold()
    );
    Ok(())
}

// ============================================================
// GENERIC BRUTEFORCE ENGINE
// ============================================================

/// Result of a single login attempt.
#[derive(Debug)]
pub enum LoginResult {
    /// Authentication succeeded.
    Success,
    /// Authentication was explicitly rejected. Do not retry.
    AuthFailed,
    /// Connection/protocol error occurred.
    Error { message: String, retryable: bool },
}

/// Credential combination strategy.
#[derive(Clone, Copy, Debug)]
pub enum ComboMode {
    /// Pair user\[i\] with pass\[i\], cycling the shorter list.
    Linear,
    /// Full cross product: every user × every password.
    Combo,
    /// Password spray: for each password, try all users (avoids account lockout).
    Spray,
}

/// Common configuration for the bruteforce engine.
#[derive(Clone)]
pub struct BruteforceConfig {
    pub target: String,
    pub port: u16,
    pub concurrency: usize,
    pub stop_on_success: bool,
    pub verbose: bool,
    pub delay_ms: u64,
    /// Random jitter added to delay_ms (0..jitter_ms) for IDS evasion.
    pub jitter_ms: u64,
    pub max_retries: usize,
    pub service_name: &'static str,
    pub source_module: &'static str,
}

/// Results from a bruteforce run.
pub struct BruteforceResult {
    /// Successful credentials: (display_addr, username, password).
    pub found: Vec<(String, String, String)>,
    /// Errored attempts: (display_addr, username, password, error_message).
    pub errors: Vec<(String, String, String, String)>,
}

impl BruteforceResult {
    /// Print found credentials to console.
    pub fn print_found(&self) {
        if self.found.is_empty() {
            crate::mprintln!("{}", "[-] No credentials found.".yellow());
        } else {
            crate::mprintln!(
                "{}",
                format!("[+] Found {} valid credential(s):", self.found.len())
                    .green()
                    .bold()
            );
            for (host, user, pass) in &self.found {
                crate::mprintln!("  {} {}  {}:{}", "✓".green(), host, user, pass);
            }
        }
    }

    /// Save found credentials to file with restricted permissions (0o600).
    pub fn save_to_file(&self, path: &str) -> Result<()> {
        if self.found.is_empty() {
            return Ok(());
        }
        let file_path = crate::utils::get_filename_in_current_dir(path);
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        match opts.open(&file_path) {
            Ok(mut file) => {
                use std::io::Write;
                for (host, user, pass) in &self.found {
                    if let Err(e) = writeln!(file, "{}:{}:{}", host, user, pass) { crate::meprintln!("[!] Write error: {}", e); }
                }
                crate::mprintln!("[+] Results saved to '{}'", file_path.display());
            }
            Err(e) => {
                crate::meprintln!("[!] Could not write to '{}': {}", file_path.display(), e);
            }
        }
        Ok(())
    }
}

/// Generate credential pairs with full combo mode control.
/// - Linear: pairs user\[i\] with pass\[i\], cycling the shorter list.
/// - Combo: full cross product (user × pass).
/// - Spray: for each password, try all users (lockout-safe ordering).
pub fn generate_combos_mode(
    usernames: &[String],
    passwords: &[String],
    mode: ComboMode,
) -> Vec<(String, String)> {
    if usernames.is_empty() || passwords.is_empty() {
        return Vec::new();
    }
    match mode {
        ComboMode::Combo => {
            let mut combos = Vec::with_capacity(usernames.len() * passwords.len());
            for u in usernames {
                for p in passwords {
                    combos.push((u.clone(), p.clone()));
                }
            }
            combos
        }
        ComboMode::Spray => {
            let mut combos = Vec::with_capacity(usernames.len() * passwords.len());
            for p in passwords {
                for u in usernames {
                    combos.push((u.clone(), p.clone()));
                }
            }
            combos
        }
        ComboMode::Linear => {
            let max_len = std::cmp::max(usernames.len(), passwords.len());
            let mut combos = Vec::with_capacity(max_len);
            for i in 0..max_len {
                let u = &usernames[i % usernames.len()];
                let p = &passwords[i % passwords.len()];
                combos.push((u.clone(), p.clone()));
            }
            combos
        }
    }
}

/// Load user:pass credential pairs from a file (one pair per line, colon-separated).
pub fn load_credential_file(path: &str) -> Result<Vec<(String, String)>> {
    let lines = crate::utils::load_lines(path)?;
    let mut combos = Vec::new();
    for line in lines {
        if let Some((user, pass)) = line.split_once(':') {
            combos.push((user.to_string(), pass.to_string()));
        }
    }
    Ok(combos)
}

/// Parse combo mode from user input string.
pub fn parse_combo_mode(input: &str) -> ComboMode {
    match input.trim().to_lowercase().as_str() {
        "combo" | "cross" => ComboMode::Combo,
        "spray" | "password_spray" => ComboMode::Spray,
        _ => ComboMode::Linear,
    }
}

/// Run the generic bruteforce engine against a single target.
///
/// The `try_login` closure receives `(target, port, username, password)` and
/// returns a `LoginResult`. It captures any protocol-specific state (timeouts,
/// TLS flags, etc.) by move.
///
/// Handles: concurrency limiting, progress reporting, retry with backoff,
/// lockout detection, credential storage, and result collection.
pub async fn run_bruteforce<F, Fut>(
    config: &BruteforceConfig,
    combos: Vec<(String, String)>,
    try_login: F,
) -> Result<BruteforceResult>
where
    F: Fn(String, u16, String, String) -> Fut + Send + Sync + 'static + Clone,
    Fut: Future<Output = LoginResult> + Send,
{
    let total = combos.len();
    if total == 0 {
        anyhow::bail!("No credential combinations to test");
    }

    let display_addr = format!("{}:{}", config.target, config.port);
    crate::mprintln!("\n[*] Starting brute-force on {}", display_addr);
    crate::mprintln!("{}", format!("[*] Total attempts: {}", total).cyan());
    crate::mprintln!();

    let stats = Arc::new(BruteforceStats::new());
    stats.set_total(total as u64);
    let found: Arc<Mutex<Vec<(String, String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let errors: Arc<Mutex<Vec<(String, String, String, String)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let semaphore = Arc::new(Semaphore::new(config.concurrency));

    // Progress reporter
    let stats_p = stats.clone();
    let stop_p = stop.clone();
    let progress_handle = tokio::spawn(async move {
        loop {
            if stop_p.load(Ordering::Relaxed) {
                break;
            }
            stats_p.print_progress();
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });

    let mut tasks = FuturesUnordered::new();

    for (user, pass) in combos {
        if config.stop_on_success && stop.load(Ordering::Relaxed) {
            break;
        }

        let target = config.target.clone();
        let port = config.port;
        let display = display_addr.clone();
        let service = config.service_name;
        let source = config.source_module;
        let found_c = found.clone();
        let errors_c = errors.clone();
        let stop_c = stop.clone();
        let stats_c = stats.clone();
        let sem_c = semaphore.clone();
        let try_login_c = try_login.clone();
        let verbose = config.verbose;
        let stop_on_success = config.stop_on_success;
        let max_retries = config.max_retries;
        let delay_ms = config.delay_ms;
        let jitter_ms = config.jitter_ms;

        tasks.push(tokio::spawn(async move {
            if stop_on_success && stop_c.load(Ordering::Relaxed) { return; }

            let _permit = match sem_c.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return,
            };

            if stop_on_success && stop_c.load(Ordering::Relaxed) { return; }

            let mut retries = 0usize;
            loop {
                let result = try_login_c(target.clone(), port, user.clone(), pass.clone()).await;

                match result {
                    LoginResult::Success => {
                        crate::mprintln!("\r{}", format!("[+] {} -> {}:{}", display, user, pass).green().bold());
                        {
                            let id = crate::cred_store::store_credential(
                                &target, port, service, &user, &pass,
                                crate::cred_store::CredType::Password,
                                source,
                            ).await;
                            if id.is_empty() { crate::meprintln!("[!] Failed to store credential"); }
                        }
                        found_c.lock().await.push((display.clone(), user.clone(), pass.clone()));
                        stats_c.record_success();
                        if stop_on_success {
                            stop_c.store(true, Ordering::Relaxed);
                        }
                        break;
                    }
                    LoginResult::AuthFailed => {
                        stats_c.record_failure();
                        if verbose {
                            crate::mprintln!("\r{}", format!("[-] {} -> {}:{}", display, user, pass).dimmed());
                        }
                        break;
                    }
                    LoginResult::Error { message, retryable } => {
                        if retryable && retries < max_retries {
                            retries += 1;
                            stats_c.record_retry();
                            if verbose {
                                crate::mprintln!("\r{}", format!(
                                    "[!] {} -> {}:{} retry {}/{} - {}",
                                    display, user, pass, retries, max_retries, message
                                ).yellow());
                            }
                            tokio::time::sleep(backoff_delay(500, retries as u32, 8)).await;
                            continue;
                        }
                        stats_c.record_error(message.clone()).await;
                        if stats_c.is_lockout_likely(10) {
                            crate::meprintln!("\n{}", "[!] WARNING: 10+ consecutive errors — possible rate limiting. Pausing 30s...".red().bold());
                            tokio::time::sleep(Duration::from_secs(30)).await;
                        }
                        errors_c.lock().await.push((display.clone(), user.clone(), pass.clone(), message.clone()));
                        if verbose {
                            crate::mprintln!("\r{}", format!("[?] {} -> {}:{} error: {}", display, user, pass, message).yellow());
                        }
                        break;
                    }
                }
            }

            if delay_ms > 0 || jitter_ms > 0 {
                let jitter = if jitter_ms > 0 {
                    rand::rng().random_range(0..=jitter_ms)
                } else { 0 };
                tokio::time::sleep(Duration::from_millis(delay_ms + jitter)).await;
            }
        }));

    }

    // Wait for remaining tasks
    while let Some(res) = tasks.next().await {
        if let Err(e) = res {
            if config.verbose {
                crate::mprintln!("\r{}", format!("[!] Task error: {}", e).red());
            }
        }
    }

    stop.store(true, Ordering::Relaxed);
    if let Err(e) = progress_handle.await { crate::meprintln!("[!] Progress task error: {}", e); }
    stats.print_final().await;

    let found_creds = found.lock().await.clone();
    let error_list = errors.lock().await.clone();

    Ok(BruteforceResult {
        found: found_creds,
        errors: error_list,
    })
}

// ============================================================
// GENERIC SUBNET BRUTEFORCE ENGINE
// ============================================================

/// Configuration for subnet-mode bruteforce scanning.
#[derive(Clone)]
pub struct SubnetScanConfig {
    pub concurrency: usize,
    pub verbose: bool,
    pub output_file: String,
    pub service_name: &'static str,
    /// Random jitter added to delay between attempts (0..jitter_ms).
    pub jitter_ms: u64,
    pub source_module: &'static str,
    /// Skip the TCP port pre-check before attempting credentials.
    /// Set to `true` for UDP-based protocols (SNMP, L2TP) where a TCP
    /// connect would always fail.
    pub skip_tcp_check: bool,
}

/// Run bruteforce against all IPs in a CIDR subnet.
///
/// For each IP: optionally checks TCP connectivity (skipped when
/// `config.skip_tcp_check` is true for UDP protocols), then iterates all
/// credential pairs using the `try_login` closure. Stops per-host on first
/// success or fatal error.
pub async fn run_subnet_bruteforce<F, Fut>(
    target: &str,
    port: u16,
    usernames: Vec<String>,
    passwords: Vec<String>,
    config: &SubnetScanConfig,
    try_login: F,
) -> Result<()>
where
    F: Fn(IpAddr, u16, String, String) -> Fut + Send + Sync + 'static + Clone,
    Fut: Future<Output = LoginResult> + Send,
{
    let network = parse_subnet(target)?;
    let count = subnet_host_count(&network);
    if count > 1_000_000 {
        crate::mprintln!(
            "{}",
            format!(
                "[!] Large subnet: {} ({} hosts) — this will take a while. Ctrl+C to stop.",
                target, count
            )
            .yellow()
            .bold()
        );
    }
    crate::mprintln!(
        "{}",
        format!("[*] Subnet {} — {} hosts to scan", target, count).cyan()
    );

    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let stats_checked = Arc::new(AtomicUsize::new(0));
    let stats_found = Arc::new(AtomicUsize::new(0));
    let creds_pkg = Arc::new((usernames, passwords));
    let total = count;
    let service: &'static str = config.service_name;
    let source: &'static str = config.source_module;

    // Progress reporter
    let s_checked = stats_checked.clone();
    let s_found = stats_found.clone();
    let progress_stop = Arc::new(AtomicBool::new(false));
    let stop_flag = progress_stop.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            crate::mprintln!(
                "[*] Status: {}/{} IPs scanned, {} valid credentials found",
                s_checked.load(Ordering::Relaxed),
                total,
                s_found.load(Ordering::Relaxed).to_string().green().bold()
            );
        }
    });

    // Bounded channel for serialized file writes
    let (tx, mut rx) = mpsc::channel::<String>(1024);
    let out = config.output_file.clone();
    let writer_handle = tokio::spawn(async move {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&out)
            .await;
        match file {
            Ok(mut f) => {
                while let Some(line) = rx.recv().await {
                    if let Err(e) = f.write_all(line.as_bytes()).await { crate::meprintln!("[!] Write error: {}", e); }
                }
            }
            Err(e) => {
                crate::meprintln!("[!] Cannot open output file '{}': {}", out, e);
                while rx.recv().await.is_some() {}
            }
        }
    });

    for ip in network.iter() {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .context("Semaphore")?;
        let cp = creds_pkg.clone();
        let sc = stats_checked.clone();
        let sf = stats_found.clone();
        let tx = tx.clone();
        let try_login = try_login.clone();
        let verbose = config.verbose;
        let skip_tcp = config.skip_tcp_check;
        let jitter_ms = config.jitter_ms;

        tokio::spawn(async move {
            // Quick TCP port check (skipped for UDP protocols)
            if !skip_tcp {
                let sa = SocketAddr::new(ip, port);
                if crate::utils::network::tcp_connect_addr(sa, Duration::from_millis(3000))
                .await
                .is_err()
                {
                    sc.fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                    return;
                }
            }

            let (users, passes) = &*cp;
            'outer: for user in users {
                for pass in passes {
                    let result = try_login(ip, port, user.clone(), pass.clone()).await;
                    match result {
                        LoginResult::Success => {
                            let msg = format!("{}:{}:{}:{}", ip, port, user, pass);
                            crate::mprintln!("\r{}", format!("[+] FOUND: {}", msg).green().bold());
                            {
                                let id = crate::cred_store::store_credential(
                                    &ip.to_string(),
                                    port,
                                    service,
                                    user,
                                    pass,
                                    crate::cred_store::CredType::Password,
                                    source,
                                )
                                .await;
                                if id.is_empty() { crate::meprintln!("[!] Failed to store credential"); }
                            }
                            if let Err(e) = tx.send(format!("{}\n", msg)).await {
                                crate::meprintln!("[!] Channel send error: {}", e);
                            }
                            sf.fetch_add(1, Ordering::Relaxed);
                            break 'outer;
                        }
                        LoginResult::AuthFailed => {
                            if verbose {
                                crate::mprintln!(
                                    "\r{}",
                                    format!("[-] {}:{} -> {}:{}", ip, port, user, pass).dimmed()
                                );
                            }
                        }
                        LoginResult::Error { message, .. } => {
                            let lower = message.to_lowercase();
                            if lower.contains("refused")
                                || lower.contains("timeout")
                                || lower.contains("reset")
                            {
                                break 'outer; // host unreachable, skip
                            }
                        }
                    }
                    // Apply jitter between attempts if configured
                    if jitter_ms > 0 {
                        let jitter = rand::rng().random_range(0..=jitter_ms);
                        tokio::time::sleep(Duration::from_millis(jitter)).await;
                    }
                }
            }
            sc.fetch_add(1, Ordering::Relaxed);
            drop(permit);
        });
    }

    // Wait for all tasks
    for _ in 0..config.concurrency {
        let _permit = semaphore.acquire().await.context("Semaphore")?;
    }

    // Shut down writer task
    drop(tx);
    if let Err(e) = writer_handle.await { crate::meprintln!("[!] Task error: {}", e); }

    progress_stop.store(true, Ordering::Relaxed);
    crate::mprintln!(
        "\n{}",
        format!(
            "[*] Subnet scan complete. {} hosts scanned, {} credentials found.",
            stats_checked.load(Ordering::Relaxed),
            stats_found.load(Ordering::Relaxed)
        )
        .cyan()
        .bold()
    );
    Ok(())
}

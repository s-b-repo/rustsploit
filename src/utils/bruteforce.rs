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
        let total = self.total_attempts.load(Ordering::Acquire);
        let success = self.successful_attempts.load(Ordering::Acquire);
        let errors = self.error_attempts.load(Ordering::Acquire);
        let retries = self.retried_attempts.load(Ordering::Acquire);
        let expected = self.total_expected.load(Ordering::Acquire);
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
        if let Err(e) = std::io::Write::flush(&mut std::io::stdout()) {
            eprintln!("[!] Flush failed: {}", e);
        }
    }

    pub async fn print_final(&self) {
        crate::mprintln!();
        let total = self.total_attempts.load(Ordering::Acquire);
        let success = self.successful_attempts.load(Ordering::Acquire);
        let failed = self.failed_attempts.load(Ordering::Acquire);
        let errors = self.error_attempts.load(Ordering::Acquire);
        let retries = self.retried_attempts.load(Ordering::Acquire);
        let expected = self.total_expected.load(Ordering::Acquire);
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
    Duration::from_millis(backoff.saturating_add(jitter))
}

pub fn generate_random_public_ip(exclusions: &[ipnetwork::IpNetwork]) -> IpAddr {
    let mut rng = rand::rng();
    const MAX_ATTEMPTS: u32 = 500_000;
    for _ in 0..MAX_ATTEMPTS {
        let first = rng.random_range(1u8..224);
        if first == 10 || first == 127 {
            continue;
        }
        let ip = IpAddr::V4(Ipv4Addr::new(
            first,
            rng.random_range(0..=255),
            rng.random_range(0..=255),
            rng.random_range(1..=254),
        ));

        if !exclusions.iter().any(|net| net.contains(ip)) {
            return ip;
        }
    }
    // Exhausted attempts — exclusion set covers most of the IPv4 space.
    // Return a best-effort candidate from a rarely-excluded range.
    tracing::warn!(
        "generate_random_public_ip: exhausted {} attempts; exclusion set may be too broad",
        MAX_ATTEMPTS
    );
    IpAddr::V4(Ipv4Addr::new(
        rng.random_range(44u8..46),
        rng.random_range(0..=255),
        rng.random_range(0..=255),
        rng.random_range(1..=254),
    ))
}

pub async fn is_ip_checked(ip: &impl ToString, state_file: &str) -> bool {
    let path = std::path::Path::new(state_file);
    if path.is_absolute() || state_file.contains("..") || state_file.contains('\0')
        || state_file.contains('/') || state_file.contains('\\')
    {
        return false;
    }
    let needle = format!("checked: {}", ip.to_string());
    // Cap state-file size to keep a corrupted/runaway file from OOMing us.
    const MAX_STATE_FILE: u64 = 256 * 1024 * 1024;
    match tokio::fs::metadata(state_file).await {
        Ok(meta) if meta.len() > MAX_STATE_FILE => return false,
        Ok(_) => {}
        Err(e) => { tracing::trace!("state file {state_file} not accessible: {e}"); return false; }
    }
    match tokio::fs::read_to_string(state_file).await {
        Ok(contents) => contents.lines().any(|line| line.contains(&needle)),
        Err(e) => { tracing::debug!("failed to read state file {state_file}: {e}"); false }
    }
}

pub async fn mark_ip_checked(ip: &impl ToString, state_file: &str) {
    let path = std::path::Path::new(state_file);
    if path.is_absolute() || state_file.contains("..") || state_file.contains('\0') {
        crate::meprintln!("[!] Invalid state file path: {}", state_file);
        return;
    }
    // Validate the filename contains no path separators (must be local file only)
    if state_file.contains('/') || state_file.contains('\\') {
        crate::meprintln!("[!] Invalid state file path (no directories allowed): {}", state_file);
        return;
    }
    let data = format!("checked: {}\n", ip.to_string());
    match OpenOptions::new()
        .create(true)
        .append(true)
        .open(state_file)
        .await
    {
        Ok(mut file) => {
            if let Err(e) = file.write_all(data.as_bytes()).await {
                eprintln!("[!] Write failed: {}", e);
            }
        }
        Err(e) => {
            eprintln!("[!] Could not open state file '{}': {}", state_file, e);
        }
    }
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

// MassScanConfig and run_mass_scan removed in v0.5.1 — universal mass-scan
// fan-out is now handled by `crate::scheduler::run` for every module.
// See docs/Legacy.md for migration history.


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

/// Hard cap on materialized combos. Beyond this, callers should route through
/// `run_bruteforce_streaming` so we don't OOM on a 10⁷×10⁵ wordlist combo.
const MAX_COMBOS: usize = 10_000_000;

/// Generate credential pairs with full combo mode control.
/// - Linear: pairs user\[i\] with pass\[i\], cycling the shorter list.
/// - Combo: full cross product (user × pass).
/// - Spray: for each password, try all users (lockout-safe ordering).
///
/// Output is hard-capped at `MAX_COMBOS` entries; if the requested combo count
/// exceeds the cap, a warning is printed and the remainder is dropped.
pub fn generate_combos_mode(
    usernames: &[String],
    passwords: &[String],
    mode: ComboMode,
) -> Vec<(String, String)> {
    if usernames.is_empty() || passwords.is_empty() {
        return Vec::new();
    }
    let requested = match mode {
        ComboMode::Combo | ComboMode::Spray => {
            usernames.len().saturating_mul(passwords.len())
        }
        ComboMode::Linear => std::cmp::max(usernames.len(), passwords.len()),
    };
    let cap = requested.min(MAX_COMBOS);
    if requested > MAX_COMBOS {
        crate::meprintln!(
            "{}",
            format!(
                "[!] Combo cap reached: requested {} pairs, truncated to {}. Use streaming mode for large wordlists.",
                requested, MAX_COMBOS
            ).yellow()
        );
    }
    let mut combos = Vec::with_capacity(cap);
    match mode {
        ComboMode::Combo => {
            'outer: for u in usernames {
                for p in passwords {
                    if combos.len() >= cap { break 'outer; }
                    combos.push((u.clone(), p.clone()));
                }
            }
        }
        ComboMode::Spray => {
            'outer: for p in passwords {
                for u in usernames {
                    if combos.len() >= cap { break 'outer; }
                    combos.push((u.clone(), p.clone()));
                }
            }
        }
        ComboMode::Linear => {
            for i in 0..cap {
                let u = &usernames[i % usernames.len()];
                let p = &passwords[i % passwords.len()];
                combos.push((u.clone(), p.clone()));
            }
        }
    }
    combos
}

/// Load user:pass credential pairs from a file (one pair per line, colon-separated).
/// Uses streaming for large files to avoid OOM with huge credential lists.
pub fn load_credential_file(path: &str) -> Result<Vec<(String, String)>> {
    let mut combos = Vec::new();
    if crate::utils::wordlist::should_stream(path) {
        crate::utils::load_lines_batched(path, crate::utils::wordlist::DEFAULT_BATCH_SIZE, |batch| {
            for line in batch {
                if let Some((user, pass)) = line.split_once(':') {
                    combos.push((user.to_string(), pass.to_string()));
                }
            }
        })?;
    } else {
        let lines = crate::utils::load_lines(path)?;
        for line in lines {
            if let Some((user, pass)) = line.split_once(':') {
                combos.push((user.to_string(), pass.to_string()));
            }
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
                    if let Err(e) = writeln!(file, "{}:{}:{}", host, user, pass) {
                        eprintln!("[!] Write failed: {}", e);
                    }
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

/// Shared list of successful credentials: (host, username, password).
type BruteforceFoundList = Arc<Mutex<Vec<(String, String, String)>>>;
/// Shared list of errors: (host, username, password, error_message).
type BruteforceErrorList = Arc<Mutex<Vec<(String, String, String, String)>>>;

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
    // Deduplicate combos preserving order
    let combos = {
        let mut seen = std::collections::HashSet::new();
        let mut deduped = combos;
        deduped.retain(|combo| seen.insert(combo.clone()));
        deduped
    };

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
    let found: BruteforceFoundList = Arc::new(Mutex::new(Vec::new()));
    let errors: BruteforceErrorList = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let paused = Arc::new(AtomicBool::new(false));
    let semaphore = Arc::new(Semaphore::new(config.concurrency.max(1)));

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

        // Acquire the permit BEFORE tokio::spawn so the spawn rate is gated by
        // concurrency, not just runtime parallelism. Otherwise a 100M-combo
        // wordlist would materialize 100M task structs immediately.
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(e) => { tracing::debug!("bruteforce semaphore closed, stopping: {e}"); break; }
        };

        let target = config.target.clone();
        let port = config.port;
        let display = display_addr.clone();
        let service = config.service_name;
        let source = config.source_module;
        let found_c = found.clone();
        let errors_c = errors.clone();
        let stop_c = stop.clone();
        let paused_c = paused.clone();
        let stats_c = stats.clone();
        let try_login_c = try_login.clone();
        let verbose = config.verbose;
        let stop_on_success = config.stop_on_success;
        let max_retries = config.max_retries;
        let delay_ms = config.delay_ms;
        let jitter_ms = config.jitter_ms;

        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            if stop_on_success && stop_c.load(Ordering::Relaxed) { return; }

            // Respect global rate-limit pause
            while paused_c.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            let mut retries = 0usize;
            loop {
                let result = try_login_c(target.clone(), port, user.clone(), pass.clone()).await;

                match result {
                    LoginResult::Success => {
                        crate::mprintln!("\r{}", format!("[+] {} -> {}:{}", display, user, pass).green().bold());
                        if crate::cred_store::store_credential(crate::cred_store::NewCred {
                            host: &target, port, service, username: &user, secret: &pass,
                            cred_type: crate::cred_store::CredType::Password,
                            source_module: source,
                        }).await.is_none() {
                            eprintln!("[!] Failed to store credential for {}:{}@{}", user, pass, target);
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
                            tokio::time::sleep(backoff_delay(500, (retries - 1) as u32, 8)).await;
                            continue;
                        }
                        stats_c.record_error(message.clone()).await;
                        if stats_c.is_lockout_likely(10) && !paused_c.swap(true, Ordering::AcqRel) {
                            crate::meprintln!("\n{}", "[!] WARNING: 10+ consecutive errors — possible rate limiting. Pausing 30s...".red().bold());
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            stats_c.consecutive_errors.store(0, Ordering::Relaxed);
                            paused_c.store(false, Ordering::Release);
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
            crate::meprintln!("[!] Task join error: {}", e);
        }
    }

    stop.store(true, Ordering::Relaxed);
    if let Err(e) = progress_handle.await {
        eprintln!("[!] Task join failed: {}", e);
    }
    stats.print_final().await;

    let found_creds = found.lock().await.clone();
    let error_list = errors.lock().await.clone();

    Ok(BruteforceResult {
        found: found_creds,
        errors: error_list,
    })
}

/// Run bruteforce with streaming wordlist support.
/// If either wordlist file exceeds 250 MB, combos are generated and processed in
/// batches rather than materializing the full cross product in memory.
/// For normal-sized wordlists, falls back to the standard `run_bruteforce`.
pub async fn run_bruteforce_streaming<F, Fut>(
    config: &BruteforceConfig,
    usernames: Vec<String>,
    password_file: Option<&str>,
    passwords: Vec<String>,
    mode: ComboMode,
    extra_combos: Vec<(String, String)>,
    try_login: F,
) -> Result<BruteforceResult>
where
    F: Fn(String, u16, String, String) -> Fut + Send + Sync + 'static + Clone,
    Fut: Future<Output = LoginResult> + Send,
{
    let needs_streaming = password_file
        .map(|p| crate::utils::file_size(p) > crate::utils::STREAMING_THRESHOLD)
        .unwrap_or(false);

    if !needs_streaming {
        let mut combos = generate_combos_mode(&usernames, &passwords, mode);
        combos.extend(extra_combos);
        return run_bruteforce(config, combos, try_login).await;
    }

    let pass_path = match password_file {
        Some(p) => p,
        None => return run_bruteforce(config, generate_combos_mode(&usernames, &passwords, mode), try_login).await,
    };
    crate::mprintln!(
        "{}",
        format!(
            "[*] Large wordlist detected ({:.0} MB), using streaming mode",
            crate::utils::file_size(pass_path) as f64 / (1024.0 * 1024.0)
        ).cyan()
    );

    let mut aggregate = BruteforceResult {
        found: Vec::new(),
        errors: Vec::new(),
    };

    const BATCH_SIZE: usize = 500_000;
    let config_ref = config;
    let mode_val = mode;
    let try_login_ref = &try_login;

    // Stream batches through a channel instead of collecting all into memory
    let (batch_tx, mut batch_rx) = tokio::sync::mpsc::channel::<Vec<String>>(2);

    let pass_path_owned = pass_path.to_string();
    let reader_handle = tokio::task::spawn_blocking(move || {
        crate::utils::load_lines_batched(&pass_path_owned, BATCH_SIZE, |batch| {
            if let Err(e) = batch_tx.blocking_send(batch) {
                tracing::debug!("Batch send failed (receiver dropped?): {}", e);
            }
        })
    });

    let mut batch_idx = 0usize;
    while let Some(pass_batch) = batch_rx.recv().await {
        batch_idx += 1;
        crate::mprintln!("{}", format!("[*] Processing batch {} ({} passwords)", batch_idx, pass_batch.len()).cyan());
        let combos = generate_combos_mode(&usernames, &pass_batch, mode_val);
        let result = run_bruteforce(config_ref, combos, try_login_ref.clone()).await?;
        aggregate.found.extend(result.found);
        aggregate.errors.extend(result.errors);
        if config_ref.stop_on_success && !aggregate.found.is_empty() {
            return Ok(aggregate);
        }
    }

    reader_handle.await.context("batch reader task panicked")??;

    if !extra_combos.is_empty() {
        crate::mprintln!("{}", format!("[*] Processing {} extra combos from credential file", extra_combos.len()).cyan());
        let result = run_bruteforce(config_ref, extra_combos, try_login_ref.clone()).await?;
        aggregate.found.extend(result.found);
        aggregate.errors.extend(result.errors);
    }

    Ok(aggregate)
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
    /// Optional CWD-relative checkpoint file (no path separators allowed).
    /// When set, IPs already marked in the file are skipped, and successfully
    /// processed IPs are appended on completion. Enables resume across runs.
    pub state_file: Option<String>,
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

    let semaphore = Arc::new(Semaphore::new(config.concurrency.max(1)));
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
    let progress_handle = tokio::spawn(async move {
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
                    if let Err(e) = f.write_all(line.as_bytes()).await {
                        eprintln!("[!] Write failed: {}", e);
                    }
                }
            }
            Err(e) => {
                crate::meprintln!("[!] Cannot open output file '{}': {}", out, e);
                while rx.recv().await.is_some() {}
            }
        }
    });

    let state_file = config.state_file.clone();
    for ip in network.iter() {
        // Resume support: skip IPs already recorded in the checkpoint file.
        if let Some(ref sf_name) = state_file
            && is_ip_checked(&ip, sf_name).await {
                stats_checked.fetch_add(1, Ordering::Relaxed);
                continue;
            }
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
        let state_file_task = state_file.clone();

        tokio::spawn(async move {
            // Quick TCP port check (skipped for UDP protocols).
            // Uses the helper so source-port (`setg src_port`) is honoured.
            if !skip_tcp {
                let sa = SocketAddr::new(ip, port);
                if let Err(e) = crate::utils::network::tcp_connect_addr(sa, Duration::from_millis(3000))
                    .await
                {
                    tracing::trace!("Pre-check TCP connect to {} failed: {}", sa, e);
                    sc.fetch_add(1, Ordering::Relaxed);
                    if let Some(ref sf_name) = state_file_task {
                        mark_ip_checked(&ip, sf_name).await;
                    }
                    drop(permit);
                    return;
                }
            }

            let (users, passes) = &*cp;
            'outer: for user in users {
                for pass in passes {
                    if jitter_ms > 0 {
                        let jitter = rand::rng().random_range(0..=jitter_ms);
                        tokio::time::sleep(Duration::from_millis(jitter)).await;
                    }
                    let result = try_login(ip, port, user.clone(), pass.clone()).await;
                    match result {
                        LoginResult::Success => {
                            let msg = format!("{}:{}:{}:{}", ip, port, user, pass);
                            crate::mprintln!("\r{}", format!("[+] FOUND: {}", msg).green().bold());
                            if crate::cred_store::store_credential(crate::cred_store::NewCred {
                                host: &ip.to_string(),
                                port,
                                service,
                                username: user,
                                secret: pass,
                                cred_type: crate::cred_store::CredType::Password,
                                source_module: source,
                            })
                            .await
                            .is_none() {
                                eprintln!("[!] Failed to store credential for {}:{}", user, ip);
                            }
                            if let Err(e) = tx.send(format!("{}\n", msg)).await {
                                eprintln!("[!] Channel send failed: {}", e);
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
                            if verbose {
                                crate::mprintln!(
                                    "\r{}",
                                    format!("[?] {}:{} -> {}:{} error: {}", ip, port, user, pass, message).yellow()
                                );
                            }
                        }
                    }
                }
            }
            sc.fetch_add(1, Ordering::Relaxed);
            if let Some(ref sf_name) = state_file_task {
                mark_ip_checked(&ip, sf_name).await;
            }
            drop(permit);
        });
    }

    // Drain barrier: wait until all in-flight tasks release their permits.
    // Use the same `.max(1)` as the Semaphore creation to stay consistent,
    // and cap to u32::MAX to avoid truncation on exotic configs.
    let drain_permits = (config.concurrency.max(1)).min(u32::MAX as usize) as u32;
    let drain = semaphore.acquire_many(drain_permits).await.context("Semaphore closed")?;
    drop(drain);

    // Shut down writer task
    drop(tx);
    if let Err(e) = writer_handle.await {
        eprintln!("[!] Task join failed: {}", e);
    }

    progress_stop.store(true, Ordering::Relaxed);
    progress_handle.abort();
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

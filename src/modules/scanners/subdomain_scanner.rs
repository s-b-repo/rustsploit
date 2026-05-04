//! DNS Subdomain Enumeration Scanner
//!
//! Brute-forces subdomains using a built-in or custom wordlist and
//! resolves each via DNS A/AAAA lookup.
//!
//! For authorized penetration testing only.

use anyhow::{Result, Context, anyhow};
use colored::*;
use std::time::Duration;
use tokio::time::timeout;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Semaphore;
use crate::utils::{cfg_prompt_default, cfg_prompt_yes_no, cfg_prompt_output_file, cfg_prompt_int_range};
use crate::module_info::{ModuleInfo, ModuleRank};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "DNS Subdomain Enumerator".into(),
        description: "Brute-forces subdomains of a target domain using DNS resolution. \
            Supports built-in wordlist or custom wordlist file. Uses concurrent \
            asynchronous DNS lookups for fast enumeration."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec![
            "https://book.hacktricks.wiki/en/generic-hacking/pentesting-network/pentesting-dns.html".into(),
            "https://owasp.org/www-community/attacks/Subdomain_Enumeration".into(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
    }
}

const DEFAULT_SUBDOMAINS: &[&str] = &[
    "www", "mail", "ftp", "admin", "dev", "staging", "test", "api", "app",
    "blog", "cdn", "cloud", "db", "demo", "docs", "git", "jenkins", "jira",
    "lab", "login", "m", "ns1", "ns2", "portal", "proxy", "remote", "shop",
    "smtp", "ssh", "vpn", "webmail", "wiki", "beta", "ci", "crm", "dashboard",
    "exchange", "forum", "gateway", "grafana", "help", "hr", "internal",
    "intranet", "ldap", "monitoring", "mx", "mysql", "nagios", "office",
    "ops", "pma", "pop", "pop3", "preview", "prod", "rdp", "sentry",
    "sftp", "sip", "stage", "status", "support", "syslog", "vault",
    "web", "zabbix",
];

fn display_banner() {
    if crate::utils::is_batch_mode() { return; }
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   DNS Subdomain Enumerator                                   ║".cyan());
    crate::mprintln!("{}", "║   Brute-force subdomain discovery via DNS resolution         ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

#[derive(Debug, Clone)]
struct SubdomainResult {
    subdomain: String,
    ips: Vec<String>,
}

impl std::fmt::Display for SubdomainResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.subdomain, self.ips.join(", "))
    }
}

/// Resolve a hostname and return all IP addresses
async fn resolve_subdomain(fqdn: &str, timeout_dur: Duration) -> Option<Vec<String>> {
    let lookup_addr = format!("{}:80", fqdn);
    match timeout(timeout_dur, tokio::net::lookup_host(&lookup_addr)).await {
        Ok(Ok(addrs)) => {
            let ips: Vec<String> = addrs
                .map(|a| a.ip().to_string())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            if ips.is_empty() {
                None
            } else {
                Some(ips)
            }
        }
        _ => None,
    }
}

pub async fn run(target: &str) -> Result<()> {
    if crate::utils::is_mass_scan_target(target) {
        anyhow::bail!("subdomain_scanner does not support mass-scan targets — it brute-forces DNS subdomains, target must be a registrable domain like example.com");
    }
    display_banner();

    // Clean domain: strip protocol, paths, ports
    let domain = target
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or(target)
        .split(':')
        .next()
        .unwrap_or(target)
        .trim()
        .to_lowercase();

    if domain.is_empty() || !domain.contains('.') {
        return Err(anyhow!("Invalid domain: '{}'. Provide a domain like 'example.com'", target));
    }

    crate::mprintln!("{}", format!("[*] Target domain: {}", domain).cyan());

    let wordlist_choice = cfg_prompt_default("wordlist", "Wordlist (built-in / path to file)", "built-in").await?;
    let concurrency = cfg_prompt_int_range("concurrency", "Concurrent lookups", 20, 1, 200).await? as usize;
    let timeout_secs = cfg_prompt_int_range("timeout", "DNS timeout per lookup (seconds)", 3, 1, 15).await? as u64;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", false).await?;

    let timeout_dur = Duration::from_secs(timeout_secs);

    // Decide between in-memory load and streaming-batched load.
    // Wordlists <= STREAM_THRESHOLD load fully (cheap, simple); larger wordlists
    // stream in BATCH_SIZE-line batches so memory usage stays bounded.
    const STREAM_THRESHOLD: u64 = 10 * 1024 * 1024;
    const BATCH_SIZE: usize = 100_000;

    enum WordlistSource {
        InMemory(Vec<String>),
        Streaming { path: String, size: u64 },
    }

    let source = if wordlist_choice == "built-in" || wordlist_choice.is_empty() {
        WordlistSource::InMemory(DEFAULT_SUBDOMAINS.iter().map(|s| s.to_string()).collect())
    } else {
        let meta = tokio::fs::metadata(&wordlist_choice).await
            .with_context(|| format!("Cannot stat wordlist: {}", wordlist_choice))?;
        if meta.len() > STREAM_THRESHOLD {
            crate::mprintln!(
                "{}",
                format!(
                    "[*] Large wordlist detected ({:.1} MB) — streaming in batches of {}",
                    meta.len() as f64 / (1024.0 * 1024.0),
                    BATCH_SIZE
                ).cyan()
            );
            WordlistSource::Streaming { path: wordlist_choice.clone(), size: meta.len() }
        } else {
            let content = tokio::fs::read_to_string(&wordlist_choice).await
                .with_context(|| format!("Failed to read wordlist: {}", wordlist_choice))?;
            let v: Vec<String> = content.lines()
                .map(|l| l.trim().to_lowercase())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            WordlistSource::InMemory(v)
        }
    };

    match &source {
        WordlistSource::InMemory(v) => {
            crate::mprintln!("{}", format!("[*] Loaded {} subdomains to test", v.len()).cyan());
        }
        WordlistSource::Streaming { size, .. } => {
            crate::mprintln!("{}", format!("[*] Streaming wordlist ({:.1} MB, total unknown until processed)", *size as f64 / (1024.0 * 1024.0)).cyan());
        }
    }
    crate::mprintln!("{}", format!("[*] Concurrency: {}, Timeout: {}s", concurrency, timeout_secs).dimmed());

    // Wildcard detection: test multiple random non-existent subdomains to reduce false negatives
    let mut wildcard_hits: Vec<Vec<String>> = Vec::new();
    for i in 0..3u32 {
        let probe = format!("xz9q7k{}r{}.{}", rand::random::<u32>(), i, domain);
        if let Some(ips) = resolve_subdomain(&probe, timeout_dur).await {
            wildcard_hits.push(ips);
        }
    }
    let wildcard_filter: Option<Vec<String>> = if wildcard_hits.len() >= 2 {
        let ips = &wildcard_hits[0];
        crate::mprintln!("{}", format!(
            "[!] WILDCARD DNS DETECTED — *.{} resolves to {} ({}/3 probes matched). Filtering results.",
            domain, ips.join(", "), wildcard_hits.len()
        ).yellow().bold());
        Some(ips.clone())
    } else if wildcard_hits.len() == 1 {
        crate::mprintln!("{}", format!(
            "[?] Possible wildcard DNS — 1/3 probes resolved for *.{}. Not filtering (may be flaky).",
            domain
        ).yellow());
        None
    } else {
        crate::mprintln!("{}", "[+] No wildcard DNS detected".green());
        None
    };

    crate::mprintln!();
    crate::mprintln!("{}", "[*] Starting enumeration...".bold());

    let results = Arc::new(tokio::sync::Mutex::new(Vec::<SubdomainResult>::new()));
    let tested = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicU64::new(0));
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let wf_outer = wildcard_filter.clone();

    // Process a single batch of subdomains: spawn per-name resolution tasks
    // and await them all before returning. Memory peaks at one batch.
    async fn scan_batch(
        batch: Vec<String>,
        domain: &str,
        timeout_dur: Duration,
        wildcard_filter: Option<Vec<String>>,
        results: Arc<tokio::sync::Mutex<Vec<SubdomainResult>>>,
        tested: Arc<AtomicU64>,
        found: Arc<AtomicU64>,
        semaphore: Arc<Semaphore>,
    ) {
        let mut handles = Vec::with_capacity(batch.len());
        for sub in batch {
            // Acquire the permit BEFORE tokio::spawn so that a 100k-line batch
            // doesn't materialize 100k task structs at once.
            let permit = match Arc::clone(&semaphore).acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let domain = domain.to_string();
            let results = Arc::clone(&results);
            let tested = Arc::clone(&tested);
            let found = Arc::clone(&found);
            let wf = wildcard_filter.clone();

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                if crate::context::is_cancelled() { return; }
                let fqdn = format!("{}.{}", sub, domain);

                if let Some(ips) = resolve_subdomain(&fqdn, timeout_dur).await {
                    if let Some(ref wildcard_ips) = wf {
                        if ips == *wildcard_ips {
                            tested.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    }
                    crate::mprintln!("{}", format!("[+] {} -> {}", fqdn, ips.join(", ")).green());
                    found.fetch_add(1, Ordering::Relaxed);
                    crate::events::emit(crate::events::ModuleEvent::HostUp {
                        host: fqdn.clone(),
                    });
                    results.lock().await.push(SubdomainResult { subdomain: fqdn, ips });
                }

                let done = tested.fetch_add(1, Ordering::Relaxed) + 1;
                if done % 50 == 0 {
                    crate::mprint!("\r{} {} tested, {} found    ",
                        "[Progress]".cyan(),
                        done,
                        found.load(Ordering::Relaxed).to_string().green()
                    );
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
            }));
        }
        for h in handles { let _ = h.await; }
    }

    match source {
        WordlistSource::InMemory(batch) => {
            scan_batch(
                batch, &domain, timeout_dur, wf_outer.clone(),
                Arc::clone(&results), Arc::clone(&tested), Arc::clone(&found), Arc::clone(&semaphore),
            ).await;
        }
        WordlistSource::Streaming { path, size: _ } => {
            // Read batches on a blocking thread, send to async side via channel.
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<String>>(2);
            let read_path = path.clone();
            let reader_handle = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
                crate::utils::load_lines_batched(&read_path, BATCH_SIZE, |raw_batch| {
                    // normalize per-line (lowercase, drop comments) on the reader thread
                    let cleaned: Vec<String> = raw_batch.into_iter()
                        .map(|l| l.trim().to_lowercase())
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .collect();
                    if !cleaned.is_empty() {
                        let _ = tx.blocking_send(cleaned);
                    }
                })
            });

            let mut batch_idx = 0usize;
            while let Some(batch) = rx.recv().await {
                batch_idx += 1;
                crate::mprintln!("{}", format!("[*] Batch {}: {} entries", batch_idx, batch.len()).cyan());
                scan_batch(
                    batch, &domain, timeout_dur, wf_outer.clone(),
                    Arc::clone(&results), Arc::clone(&tested), Arc::clone(&found), Arc::clone(&semaphore),
                ).await;
            }

            match reader_handle.await {
                Ok(Ok(total_lines)) => {
                    crate::mprintln!("{}", format!("[*] Streamed {} total lines from wordlist", total_lines).dimmed());
                }
                Ok(Err(e)) => crate::meprintln!("[!] Wordlist read error: {}", e),
                Err(e) => crate::meprintln!("[!] Wordlist reader task panicked: {}", e),
            }
        }
    }

    crate::mprintln!(); // Clear progress line

    let results = results.lock().await;
    let found_count = results.len();
    let total = tested.load(Ordering::Relaxed);

    // Summary
    crate::mprintln!();
    crate::mprintln!("{}", "=== Enumeration Summary ===".bold());
    crate::mprintln!("  Domain:           {}", domain);
    crate::mprintln!("  Subdomains tested: {}", total);
    crate::mprintln!("  Found:            {}", if found_count > 0 {
        found_count.to_string().green().bold().to_string()
    } else {
        "0".dimmed().to_string()
    });

    if !results.is_empty() {
        crate::mprintln!();
        crate::mprintln!("{}", "Found subdomains:".bold());
        for r in results.iter() {
            crate::mprintln!("  {} -> {}", r.subdomain.green(), r.ips.join(", "));
        }
    }

    if save_results && !results.is_empty() {
        let default_file = format!("subdomains_{}.txt", domain.replace('.', "_"));
        let output_path = cfg_prompt_output_file("output_file", "Output file", &default_file).await?;
        let content = results.iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&output_path, format!("Subdomain Enumeration - {}\n\n{}", domain, content))
            .with_context(|| format!("Failed to write results to {}", output_path))?;
        crate::mprintln!("{}", format!("[+] Results saved to '{}'", output_path).green());
    }

    Ok(())
}

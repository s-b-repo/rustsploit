//! DNS Subdomain Wordlist Brute-forcer
//!
//! Dictionary-based subdomain enumeration fed from the checksum-pinned
//! SecLists catalog (`subdomains-top5k` by default) via
//! [`crate::utils::wordlist::resolve`], so the operator gets broad coverage
//! with zero setup. Any catalog name or a path to a local wordlist also works.
//!
//! Unlike `subdomain_scanner` (small built-in list or an explicit file), this
//! module defaults to auto-resolving the curated 5,000-entry SecLists DNS
//! wordlist and streams it, so a multi-million-line custom list stays within
//! bounded memory.
//!
//! For authorized penetration testing only.

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{cfg_prompt_default, cfg_prompt_int_range, cfg_prompt_yes_no};
use anyhow::{Context, Result, anyhow};
use colored::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::timeout;

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "DNS Subdomain Wordlist Brute-forcer".into(),
        description: "Dictionary-based subdomain enumeration fed from the checksum-pinned \
            SecLists catalog (default 'subdomains-top5k', ~5,000 entries) or any catalog \
            name / local wordlist path. Streams the wordlist and resolves each candidate \
            via concurrent async DNS lookups, with wildcard-DNS detection to suppress \
            false positives."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec![
            "https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS".into(),
            "https://owasp.org/www-community/attacks/Subdomain_Enumeration".into(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Excellent,
        default_port: None,
    }
}

const DEFAULT_WORDLIST: &str = "subdomains-top5k";
const BATCH_SIZE: usize = 100_000;

fn display_banner() {
    if crate::utils::is_batch_mode() {
        return;
    }
    crate::mprintln!(
        "{}",
        "╔══════════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   DNS Subdomain Wordlist Brute-forcer                        ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   SecLists-catalog-fed subdomain discovery via DNS           ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚══════════════════════════════════════════════════════════════╝".cyan()
    );
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

/// Resolve a hostname to the set of IP addresses it points at.
async fn resolve_subdomain(fqdn: &str, timeout_dur: Duration) -> Option<Vec<String>> {
    let lookup_addr = format!("{}:80", fqdn);
    match timeout(timeout_dur, tokio::net::lookup_host(&lookup_addr)).await {
        Ok(Ok(addrs)) => {
            let ips: Vec<String> = addrs
                .map(|a| a.ip().to_string())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            if ips.is_empty() { None } else { Some(ips) }
        }
        _ => None,
    }
}

struct ScanState {
    results: Arc<tokio::sync::Mutex<Vec<SubdomainResult>>>,
    tested: Arc<AtomicU64>,
    found: Arc<AtomicU64>,
    semaphore: Arc<Semaphore>,
}

/// Resolve one batch of candidate labels against `domain`, honouring the
/// concurrency limit, cancellation, and the wildcard filter.
async fn scan_batch(
    batch: Vec<String>,
    domain: &str,
    timeout_dur: Duration,
    wildcard_filter: Option<Vec<String>>,
    state: &ScanState,
) {
    let ScanState {
        results,
        tested,
        found,
        semaphore,
    } = state;
    let mut handles = Vec::with_capacity(batch.len());
    for sub in batch {
        // Acquire the permit BEFORE spawning so a huge batch does not
        // materialize one task struct per line up front.
        let permit = match Arc::clone(semaphore).acquire_owned().await {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("semaphore closed: {e}");
                break;
            }
        };
        let domain = domain.to_string();
        let results = Arc::clone(results);
        let tested = Arc::clone(tested);
        let found = Arc::clone(found);
        let wf = wildcard_filter.clone();

        handles.push(tokio::spawn(async move {
            if crate::context::is_cancelled() {
                // `permit` (moved in) drops here, freeing the slot.
                return;
            }
            let fqdn = format!("{}.{}", sub, domain);

            if let Some(ips) = resolve_subdomain(&fqdn, timeout_dur).await {
                if let Some(ref wildcard_ips) = wf
                    && ips == *wildcard_ips
                {
                    tested.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                crate::mprintln!("{}", format!("[+] {} -> {}", fqdn, ips.join(", ")).green());
                found.fetch_add(1, Ordering::Relaxed);
                crate::events::emit(crate::events::ModuleEvent::HostUp { host: fqdn.clone() });
                results.lock().await.push(SubdomainResult {
                    subdomain: fqdn,
                    ips,
                });
            }

            let done = tested.fetch_add(1, Ordering::Relaxed) + 1;
            if done.is_multiple_of(100) {
                crate::mprint!(
                    "\r{} {} tested, {} found    ",
                    "[Progress]".cyan(),
                    done,
                    found.load(Ordering::Relaxed).to_string().green()
                );
                if let Err(e) = std::io::Write::flush(&mut std::io::stdout()) {
                    crate::meprintln!("[!] Flush failed: {}", e);
                }
            }

            // Hold the acquired permit for the whole lookup, then release the
            // concurrency slot (earlier returns release it at scope exit).
            drop(permit);
        }));
    }
    for h in handles {
        if let Err(e) = h.await {
            crate::meprintln!("[!] Task join failed: {}", e);
        }
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("module requires a single-host target")?;
    display_banner();

    // Clean domain: strip protocol, path and port.
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
        return Err(anyhow!(
            "Invalid domain: '{}'. Provide a domain like 'example.com'",
            target
        ));
    }

    crate::mprintln!("{}", format!("[*] Target domain: {}", domain).cyan());

    let wordlist_choice = cfg_prompt_default(
        "wordlist",
        "Wordlist (SecLists catalog name or path to a file)",
        DEFAULT_WORDLIST,
    )
    .await?;
    let concurrency: usize = cfg_prompt_int_range("concurrency", "Concurrent lookups", 50, 1, 500)
        .await?
        .try_into()
        .context("concurrency value out of range")?;
    let timeout_secs: u64 =
        cfg_prompt_int_range("timeout", "DNS timeout per lookup (seconds)", 5, 1, 300)
            .await?
            .try_into()
            .context("timeout value out of range")?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", false).await?;

    let timeout_dur = Duration::from_secs(timeout_secs);

    // A known catalog name is downloaded + checksum-verified; anything else is
    // treated as a path to a local wordlist file.
    let is_catalog = crate::utils::wordlist::catalogue()
        .iter()
        .any(|n| *n == wordlist_choice.as_str());
    let wordlist_path = if is_catalog {
        crate::mprintln!(
            "{}",
            format!(
                "[*] Resolving catalog wordlist '{}' (download + checksum if needed)...",
                wordlist_choice
            )
            .cyan()
        );
        crate::utils::wordlist::resolve(&wordlist_choice)
            .await
            .with_context(|| format!("resolving catalog wordlist '{}'", wordlist_choice))?
    } else {
        let p = std::path::PathBuf::from(&wordlist_choice);
        if !tokio::fs::try_exists(&p).await.unwrap_or(false) {
            return Err(anyhow!(
                "Wordlist '{}' is neither a known catalog name ({}) nor an existing file path",
                wordlist_choice,
                crate::utils::wordlist::catalogue().join(", ")
            ));
        }
        p
    };

    let wordlist_display = wordlist_path.display().to_string();
    crate::mprintln!("{}", format!("[*] Wordlist: {}", wordlist_display).dimmed());
    crate::mprintln!(
        "{}",
        format!(
            "[*] Concurrency: {}, Timeout: {}s",
            concurrency, timeout_secs
        )
        .dimmed()
    );

    // Wildcard detection: random labels that should never exist. If they
    // resolve, the zone has wildcard DNS and raw hits are meaningless.
    let mut wildcard_hits: Vec<Vec<String>> = Vec::new();
    for i in 0..3u32 {
        let probe = format!("zq7x4k{}v{}.{}", rand::random::<u32>(), i, domain);
        if let Some(ips) = resolve_subdomain(&probe, timeout_dur).await {
            wildcard_hits.push(ips);
        }
    }
    let wildcard_filter: Option<Vec<String>> = if wildcard_hits.len() >= 2 {
        let ips = wildcard_hits[0].clone();
        crate::mprintln!(
            "{}",
            format!(
                "[!] WILDCARD DNS DETECTED — *.{} resolves to {} ({}/3 probes). Filtering matches.",
                domain,
                ips.join(", "),
                wildcard_hits.len()
            )
            .yellow()
            .bold()
        );
        Some(ips)
    } else {
        if wildcard_hits.len() == 1 {
            crate::mprintln!(
                "{}",
                format!(
                    "[?] Possible wildcard DNS — 1/3 probes resolved for *.{} (not filtering).",
                    domain
                )
                .yellow()
            );
        } else {
            crate::mprintln!("{}", "[+] No wildcard DNS detected".green());
        }
        None
    };

    crate::mprintln!();
    crate::mprintln!("{}", "[*] Starting enumeration...".bold());

    let state = ScanState {
        results: Arc::new(tokio::sync::Mutex::new(Vec::<SubdomainResult>::new())),
        tested: Arc::new(AtomicU64::new(0)),
        found: Arc::new(AtomicU64::new(0)),
        semaphore: Arc::new(Semaphore::new(concurrency.clamp(1, Semaphore::MAX_PERMITS))),
    };

    // Stream the wordlist in batches on a blocking thread so memory stays
    // bounded regardless of file size; scan each batch on the async side.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<String>>(2);
    let read_path = wordlist_display.clone();
    let reader_handle = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
        crate::utils::load_lines_batched(&read_path, BATCH_SIZE, |raw_batch| {
            let cleaned: Vec<String> = raw_batch
                .into_iter()
                .map(|l| l.trim().to_lowercase())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            if !cleaned.is_empty()
                && let Err(e) = tx.blocking_send(cleaned)
            {
                crate::meprintln!("[!] Channel send failed: {}", e);
            }
        })
    });

    let mut batch_idx = 0usize;
    while let Some(batch) = rx.recv().await {
        batch_idx += 1;
        if batch_idx > 1 {
            crate::mprintln!(
                "{}",
                format!("[*] Batch {}: {} entries", batch_idx, batch.len()).dimmed()
            );
        }
        scan_batch(batch, &domain, timeout_dur, wildcard_filter.clone(), &state).await;
    }

    match reader_handle.await {
        Ok(Ok(total_lines)) => crate::mprintln!(
            "{}",
            format!("[*] Processed {} wordlist entries", total_lines).dimmed()
        ),
        Ok(Err(e)) => crate::meprintln!("[!] Wordlist read error: {}", e),
        Err(e) => crate::meprintln!("[!] Wordlist reader task panicked: {}", e),
    }

    crate::mprintln!(); // clear progress line

    let results = state.results.lock().await;
    let found_count = results.len();
    let total = state.tested.load(Ordering::Relaxed);

    crate::mprintln!();
    crate::mprintln!("{}", "=== Enumeration Summary ===".bold());
    crate::mprintln!("  Domain:            {}", domain);
    crate::mprintln!("  Candidates tested: {}", total);
    crate::mprintln!(
        "  Found:             {}",
        if found_count > 0 {
            found_count.to_string().green().bold().to_string()
        } else {
            "0".dimmed().to_string()
        }
    );

    let mut outcome = ModuleOutcome::ok();

    if !results.is_empty() {
        crate::mprintln!();
        crate::mprintln!("{}", "Found subdomains:".bold());
        for r in results.iter() {
            crate::mprintln!("  {} -> {}", r.subdomain.green(), r.ips.join(", "));
            outcome = outcome.with(Finding {
                target: r.subdomain.clone(),
                kind: FindingKind::Note,
                message: format!(
                    "Subdomain discovered: {} -> {}",
                    r.subdomain,
                    r.ips.join(", ")
                ),
                data: Some(serde_json::json!({
                    "subdomain": r.subdomain,
                    "ips": r.ips,
                    "domain": domain,
                    "wordlist": wordlist_display,
                })),
            });
        }
    }

    if save_results && !results.is_empty() {
        let default_file = format!("subdomains_{}.txt", domain.replace('.', "_"));
        let output_path =
            crate::utils::cfg_prompt_output_file("output_file", "Output file", &default_file)
                .await?;
        let content = results
            .iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        tokio::fs::write(
            &output_path,
            format!("Subdomain Enumeration - {}\n\n{}", domain, content),
        )
        .await
        .with_context(|| format!("Failed to write results to {}", output_path))?;
        if let Err(e) = crate::utils::set_secure_permissions(&output_path, 0o600) {
            crate::meprintln!("[!] Failed to set file permissions: {}", e);
        }
        crate::mprintln!(
            "{}",
            format!("[+] Results saved to '{}'", output_path).green()
        );
    }

    Ok(outcome)
}

crate::register_native_module!(
    crate::module::Category::Scanners,
    "subdomain_wordlist",
    native
);

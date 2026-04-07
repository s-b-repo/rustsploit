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

    // Load wordlist
    let subdomains: Vec<String> = if wordlist_choice == "built-in" || wordlist_choice.is_empty() {
        DEFAULT_SUBDOMAINS.iter().map(|s| s.to_string()).collect()
    } else {
        // Cap wordlist at 10MB to prevent OOM
        let meta = std::fs::metadata(&wordlist_choice)
            .with_context(|| format!("Cannot stat wordlist: {}", wordlist_choice))?;
        if meta.len() > 10 * 1024 * 1024 {
            return Err(anyhow!("Wordlist too large ({:.1}MB, max 10MB)", meta.len() as f64 / (1024.0 * 1024.0)));
        }
        let content = std::fs::read_to_string(&wordlist_choice)
            .with_context(|| format!("Failed to read wordlist: {}", wordlist_choice))?;
        content.lines()
            .map(|l| l.trim().to_lowercase())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    };

    crate::mprintln!("{}", format!("[*] Loaded {} subdomains to test", subdomains.len()).cyan());
    crate::mprintln!("{}", format!("[*] Concurrency: {}, Timeout: {}s", concurrency, timeout_secs).dimmed());

    // Wildcard detection: test a random non-existent subdomain
    let wildcard_test = format!("xz9q7k2m4p{}.{}", rand::random::<u32>(), domain);
    let wildcard_ips = resolve_subdomain(&wildcard_test, timeout_dur).await;
    let wildcard_filter: Option<Vec<String>> = if let Some(ref ips) = wildcard_ips {
        crate::mprintln!("{}", format!(
            "[!] WILDCARD DNS DETECTED — *.{} resolves to {}. Filtering results.",
            domain, ips.join(", ")
        ).yellow().bold());
        Some(ips.clone())
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
    let total = subdomains.len() as u64;

    let mut handles = Vec::new();

    let wf = wildcard_filter.clone();
    for sub in subdomains {
        let domain = domain.clone();
        let results = Arc::clone(&results);
        let tested = Arc::clone(&tested);
        let found = Arc::clone(&found);
        let semaphore = Arc::clone(&semaphore);
        let wf = wf.clone();

        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await;
            let fqdn = format!("{}.{}", sub, domain);

            if let Some(ips) = resolve_subdomain(&fqdn, timeout_dur).await {
                // Filter out wildcard results
                if let Some(ref wildcard_ips) = wf {
                    if ips == *wildcard_ips {
                        // Same IPs as wildcard — skip
                        tested.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                }
                crate::mprintln!("{}", format!("[+] {} -> {}", fqdn, ips.join(", ")).green());
                found.fetch_add(1, Ordering::Relaxed);
                results.lock().await.push(SubdomainResult {
                    subdomain: fqdn,
                    ips,
                });
            }

            let done = tested.fetch_add(1, Ordering::Relaxed) + 1;
            if done % 50 == 0 || done == total {
                crate::mprint!("\r{} {}/{} tested, {} found    ",
                    "[Progress]".cyan(),
                    done, total,
                    found.load(Ordering::Relaxed).to_string().green()
                );
                if let Err(e) = std::io::Write::flush(&mut std::io::stdout()) { eprintln!("[!] Flush error: {}", e); }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        if let Err(e) = handle.await { crate::meprintln!("[!] Task error: {}", e); }
    }

    crate::mprintln!(); // Clear progress line

    let results = results.lock().await;
    let found_count = results.len();

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
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&output_path)
                .with_context(|| format!("Failed to write results to {}", output_path))?;
            writeln!(f, "\n--- Scan at {} ---", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
                .with_context(|| format!("Failed to write results to {}", output_path))?;
            f.write_all(format!("Subdomain Enumeration - {}\n\n{}", domain, content).as_bytes())
                .with_context(|| format!("Failed to write results to {}", output_path))?;
        }
        crate::mprintln!("{}", format!("[+] Results saved to '{}'", output_path).green());
    }

    Ok(())
}

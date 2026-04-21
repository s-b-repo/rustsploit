use anyhow::Result;
use colored::*;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::time::Instant;
use tokio::sync::Semaphore;
use crate::utils::{
    cfg_prompt_default, cfg_prompt_int_range, cfg_prompt_yes_no, cfg_prompt_output_file,
};
use crate::utils::target::extract_ip_from_target;
use crate::utils::{
    is_mass_scan_target, is_subnet_target, parse_subnet, subnet_host_count,
    run_mass_scan, MassScanConfig,
};

/// Ports to scan for honeypot detection (50 common service ports).
const HONEYPOT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 161, 389, 443, 445, 465, 502, 554, 587, 636,
    993, 995, 1433, 1521, 1723, 1883, 2049, 3306, 3389, 5060,
    5432, 5900, 6379, 6667, 8080, 8443, 8888, 9090, 9200, 9300,
    11211, 27017, 5672, 15672, 2181, 4848, 7001, 8000, 8081, 10000,
];

/// Scan a single IP for honeypot indicators.
/// Returns (open_count, open_ports_list).
async fn scan_ip_ports(ip: &str, timeout_ms: u64) -> (usize, Vec<u16>) {
    let parsed_ip: std::net::IpAddr = match ip.parse() {
        Ok(addr) => addr,
        Err(_) => return (0, Vec::new()),
    };

    let timeout = std::time::Duration::from_millis(timeout_ms);
    let semaphore = Arc::new(Semaphore::new(50));
    let open_count = Arc::new(AtomicUsize::new(0));
    let open_ports = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut tasks = Vec::with_capacity(HONEYPOT_PORTS.len());

    for &port in HONEYPOT_PORTS {
        let sem = semaphore.clone();
        let count = open_count.clone();
        let ports = open_ports.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(permit) => permit,
                Err(_) => return,
            };
            if crate::utils::network::tcp_port_open(parsed_ip, port, timeout).await {
                count.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut list) = ports.lock() {
                    list.push(port);
                }
            }
        }));
    }

    for task in tasks {
        let _ = task.await;
    }

    let count = open_count.load(Ordering::Relaxed);
    let mut ports = open_ports.lock().unwrap_or_else(|e| e.into_inner()).clone();
    ports.sort();
    (count, ports)
}

/// Classify honeypot status from open port count.
fn classify(open_count: usize) -> (&'static str, &'static str) {
    match open_count {
        0..=5 => ("Clean", "green"),
        6..=10 => ("Suspicious", "yellow"),
        11..=20 => ("Likely Honeypot", "red"),
        _ => ("Definite Honeypot", "red_bold"),
    }
}

/// Print a colored status string.
fn colored_status(status: &str, color: &str) -> String {
    match color {
        "green" => status.green().to_string(),
        "yellow" => status.yellow().to_string(),
        "red" => status.red().to_string(),
        "red_bold" => status.red().bold().to_string(),
        _ => status.to_string(),
    }
}

/// Scan a list of IPs for honeypot indicators with concurrency control.
async fn scan_targets(
    ips: Vec<String>,
    timeout_ms: u64,
    concurrency: usize,
    verbose: bool,
) -> Vec<(String, usize, String, String, Vec<u16>)> {
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let results = Arc::new(std::sync::Mutex::new(Vec::new()));
    let total = ips.len();
    let progress = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::with_capacity(total);

    for ip_str in ips {
        let permit = semaphore.clone().acquire_owned().await;
        let permit = match permit {
            Ok(p) => p,
            Err(_) => continue,
        };
        let res = results.clone();
        let prog = progress.clone();

        tasks.push(tokio::spawn(async move {
            let (open_count, open_ports) = scan_ip_ports(&ip_str, timeout_ms).await;
            let (status, color) = classify(open_count);

            if let Ok(mut list) = res.lock() {
                list.push((
                    ip_str.clone(),
                    open_count,
                    status.to_string(),
                    color.to_string(),
                    open_ports,
                ));
            }

            let idx = prog.fetch_add(1, Ordering::Relaxed) + 1;
            if verbose || idx % 20 == 0 || idx == 1 || idx == total {
                crate::mprintln!("[*] Honeypot scan progress: {}/{} hosts", idx, total);
            }

            drop(permit);
        }));
    }

    for task in tasks {
        let _ = task.await;
    }

    let mut out = results.lock().unwrap_or_else(|e| e.into_inner()).clone();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Print results table.
fn print_results(results: &[(String, usize, String, String, Vec<u16>)], verbose: bool) {
    crate::mprintln!();
    crate::mprintln!("{}", "=== Honeypot Detection Results ===".cyan().bold());
    crate::mprintln!();
    crate::mprintln!("  {:<40} {:<8} {:<22} {}",
        "IP".bold(), "Open".bold(), "Status".bold(), "Ports".bold());
    crate::mprintln!("  {}", "-".repeat(100));

    for (ip, open_count, status, color, ports) in results {
        let status_str = colored_status(status, color);
        let ports_str = if verbose || *open_count <= 25 {
            ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")
        } else {
            let shown: Vec<String> = ports.iter().take(15).map(|p| p.to_string()).collect();
            format!("{}... (+{})", shown.join(","), open_count.saturating_sub(15))
        };
        crate::mprintln!("  {:<40} {:<8} {:<22} {}",
            ip, open_count, status_str, ports_str.dimmed());
    }
    crate::mprintln!();
}

/// Save results to a file.
fn save_results(
    results: &[(String, usize, String, String, Vec<u16>)],
    output_file: &str,
) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(output_file)?;
    if let Err(e) = crate::utils::set_secure_permissions(output_file, 0o600) {
        crate::meprintln!("[!] Failed to chmod 0o600 on {}: {} — file may be world-readable", output_file, e);
    }
    writeln!(file, "Honeypot Detection Results")?;
    writeln!(file, "=========================")?;
    writeln!(file, "Scan time: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(file)?;
    writeln!(file, "{:<40} {:<8} {:<22} {}",
        "IP", "Open", "Status", "Ports")?;
    writeln!(file, "{}", "-".repeat(100))?;

    for (ip, open_count, status, _color, ports) in results {
        let ports_str = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        writeln!(file, "{:<40} {:<8} {:<22} {}",
            ip, open_count, status, ports_str)?;
    }

    let honeypots: Vec<_> = results.iter().filter(|r| r.1 >= 11).collect();
    let suspicious: Vec<_> = results.iter().filter(|r| r.1 >= 6 && r.1 < 11).collect();
    let clean: Vec<_> = results.iter().filter(|r| r.1 < 6).collect();
    writeln!(file)?;
    writeln!(file, "Summary: {} total | {} honeypot | {} suspicious | {} clean",
        results.len(), honeypots.len(), suspicious.len(), clean.len())?;

    Ok(())
}

/// Store honeypot hosts in the workspace with notes.
async fn store_to_workspace(results: &[(String, usize, String, String, Vec<u16>)]) {
    for (ip, open_count, status, _color, _ports) in results {
        if *open_count >= 6 {
            crate::workspace::track_host(ip, None, None).await;
            let note = format!("Honeypot scan: {} ({}/{} ports open)", status, open_count, HONEYPOT_PORTS.len());
            crate::workspace::WORKSPACE.add_note(ip, &note).await;
        }
    }
}

pub async fn run(target: &str) -> Result<()> {
    // Mass scan mode: random / 0.0.0.0 / file-based targets
    if is_mass_scan_target(target) {
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "HoneypotScan",
            default_port: 80,
            state_file: "honeypot_scanner_mass_state.log",
            default_output: "honeypot_scanner_mass_results.txt",
            default_concurrency: 500,
        }, move |ip, _port| {
            async move {
                let ip_str = ip.to_string();
                let (open_count, ports) = scan_ip_ports(&ip_str, 200).await;
                if open_count >= 6 {
                    let (status, _) = classify(open_count);
                    let ports_str = ports.iter().take(15).map(|p| p.to_string()).collect::<Vec<_>>().join(",");
                    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                    Some(format!("[{}] {} {} ({} open) ports:[{}]\n",
                        ts, ip_str, status, open_count, ports_str))
                } else {
                    None
                }
            }
        }).await;
    }

    // Only print the header if we're NOT running inside a batch/mass scan context
    if !crate::utils::is_batch_mode() {
        crate::mprintln!();
        crate::mprintln!("{}", "=== Honeypot Detection Scanner ===".cyan().bold());
        crate::mprintln!();
    }

    // Prompts
    let target_input = cfg_prompt_default("target", "Target (IP/CIDR/file)", target).await?;
    let timeout_ms = cfg_prompt_int_range("port_timeout_ms", "Port timeout (ms)", 200, 50, 5000).await? as u64;
    let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent hosts", 50, 1, 1000).await? as usize;
    let save_results_opt = cfg_prompt_yes_no("save_results", "Save results to file?", false).await?;
    let output_file = if save_results_opt {
        cfg_prompt_output_file("output_file", "Output file", "honeypot_results.txt").await?
    } else {
        String::new()
    };
    let verbose = cfg_prompt_yes_no("verbose", "Verbose output?", false).await?;

    // Confirmation
    let confirm = cfg_prompt_yes_no("confirm", "Start honeypot scan?", true).await?;
    if !confirm {
        crate::mprintln!("{}", "[*] Scan cancelled.".yellow());
        return Ok(());
    }

    let start = Instant::now();

    // Build target list
    let ips: Vec<String> = if std::path::Path::new(&target_input).is_file() {
        // File-based target list
        let content = crate::utils::safe_read_to_string_async(&target_input, None).await?;
        content.lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .collect()
    } else if is_subnet_target(&target_input) {
        // CIDR subnet
        let network = parse_subnet(&target_input)?;
        let host_count = subnet_host_count(&network);
        crate::mprintln!("{}", format!(
            "[*] Subnet {} — {} hosts to scan", target_input, host_count
        ).cyan());
        network.iter().map(|ip| ip.to_string()).collect()
    } else {
        // Single IP
        let ip = extract_ip_from_target(&target_input)
            .unwrap_or_else(|| target_input.clone());
        vec![ip]
    };

    let total = ips.len();
    crate::mprintln!("{}", format!("[*] Scanning {} host(s) for honeypot indicators...", total).cyan());
    crate::mprintln!("{}", format!(
        "[*] Checking {} ports per host | timeout {}ms | concurrency {}",
        HONEYPOT_PORTS.len(), timeout_ms, concurrency
    ).cyan());

    // Run scan
    let results = scan_targets(ips, timeout_ms, concurrency, verbose).await;

    let elapsed = start.elapsed();

    // Print results
    print_results(&results, verbose);

    // Summary
    let honeypots: Vec<_> = results.iter().filter(|r| r.1 >= 11).collect();
    let suspicious: Vec<_> = results.iter().filter(|r| r.1 >= 6 && r.1 < 11).collect();
    let clean: Vec<_> = results.iter().filter(|r| r.1 < 6).collect();

    crate::mprintln!("{}", "=== Summary ===".cyan().bold());
    crate::mprintln!("  Total hosts:    {}", total);
    crate::mprintln!("  {}", format!("Clean:          {}", clean.len()).green());
    crate::mprintln!("  {}", format!("Suspicious:     {}", suspicious.len()).yellow());
    crate::mprintln!("  {}", format!("Honeypots:      {}", honeypots.len()).red());
    crate::mprintln!("  Scan duration:  {:.2}s", elapsed.as_secs_f64());
    crate::mprintln!();

    // Save to file
    if save_results_opt && !output_file.is_empty() {
        match save_results(&results, &output_file) {
            Ok(_) => crate::mprintln!("{}", format!("[+] Results saved to {}", output_file).green()),
            Err(e) => crate::meprintln!("{}", format!("[!] Failed to save results: {}", e).red()),
        }
    }

    // Store honeypot hosts to workspace
    store_to_workspace(&results).await;
    if !honeypots.is_empty() || !suspicious.is_empty() {
        crate::mprintln!("{}", "[+] Honeypot/suspicious hosts added to workspace with notes.".green());
    }

    Ok(())
}

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "Honeypot Detection Scanner".to_string(),
        description: "Scans targets for honeypot indicators by probing 50 common TCP ports in \
            parallel. Classifies hosts as Clean (0-5 open), Suspicious (6-10), Likely Honeypot \
            (11-20), or Definite Honeypot (21+). Supports single IP, CIDR subnets, file-based \
            target lists, and random/mass scanning. Results are stored to the workspace with \
            honeypot notes."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://en.wikipedia.org/wiki/Honeypot_(computing)".to_string(),
        ],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

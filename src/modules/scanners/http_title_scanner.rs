use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use colored::*;
use regex::Regex;
use reqwest::{Client, StatusCode, Url};
use std::collections::HashSet;
use std::fs;

use std::time::{Duration, Instant};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_yes_no, cfg_prompt_int_range, cfg_prompt_output_file,
    safe_read_to_string,
};
use crate::modules::creds::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};

pub async fn run(initial_target: &str) -> Result<()> {
    if crate::utils::get_global_source_port().await.is_some() {
        crate::mprintln!("{}", "[*] Note: source_port does not apply to HTTP connections.".dimmed());
    }
    if is_mass_scan_target(initial_target) {
        return run_mass_scan(initial_target, MassScanConfig {
            protocol_name: "HTTP-Title",
            default_port: 80,
            state_file: "http_title_scanner_mass_state.log",
            default_output: "http_title_scanner_mass_results.txt",
            default_concurrency: 500,
        }, move |ip, port| {
            async move {
                if crate::utils::tcp_port_open(ip, port, std::time::Duration::from_secs(3)).await {
                    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                    Some(format!("[{}] {}:{} HTTP-Title open\n", ts, ip, port))
                } else {
                    None
                }
            }
        }).await;
    }

    banner();

    let mut targets = collect_initial_targets(initial_target);

    let additional = cfg_prompt_default("additional_targets", "Enter additional comma-separated targets (optional)", "").await?;
    if !additional.is_empty() {
        targets.extend(split_targets(&additional));
    }

    let file_path = cfg_prompt_default("target_file", "Path to file with targets (optional)", "").await?;
    if !file_path.is_empty() {
        let file_targets = load_targets_from_file(&file_path)?;
        targets.extend(file_targets);
    }

    let check_http = cfg_prompt_yes_no("check_http", "Check HTTP (http://)?", true).await?;
    let check_https = cfg_prompt_yes_no("check_https", "Check HTTPS (https://)?", true).await?;

    if !check_http && !check_https {
        crate::mprintln!("[!] Neither HTTP nor HTTPS selected; nothing to scan.");
        return Ok(());
    }

    let use_ports = cfg_prompt_yes_no("use_ports", "Test via specific ports (port tunneling)?", false).await?;
    let ports = if use_ports {
        let ports_str = cfg_prompt_default("ports", "Enter port(s) comma-separated (e.g. 80,8080)", "").await?;
        parse_ports_from_string(&ports_str)
    } else {
        Vec::new()
    };

    let timeout_secs = cfg_prompt_int_range("timeout", "Request timeout in seconds", 10, 1, 120).await? as u64;
    let save_output = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let verbose = cfg_prompt_yes_no("verbose", "Enable verbose output?", false).await?;

    let mut normalized = normalize_targets(targets, check_http, check_https);
    if !ports.is_empty() {
        let expanded = expand_targets_with_ports(&normalized, &ports);
        if expanded.is_empty() {
            crate::mprintln!("[!] No valid port combinations derived; continuing without port tunneling.");
        } else {
            normalized = expanded;
        }
    }
    if normalized.is_empty() {
        return Err(anyhow!("No valid targets provided"));
    }
    normalized.sort();

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .user_agent("RustSploit-HTTP-Title-Scanner/1.0")
        .timeout(Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .context("Failed to build HTTP client")?;

    let title_re = Regex::new(r"(?is)<title\b[^>]*>(.*?)</title>")?;
    let mut all_results = Vec::new();
    let mut success_count = 0usize;
    let mut error_count = 0usize;
    let start_time = Instant::now();
    let total_targets = normalized.len();

    crate::mprintln!("{}", format!("[*] Scanning {} target(s)...", total_targets).cyan().bold());
    crate::mprintln!();

    for (idx, url) in normalized.iter().enumerate() {
        // Progress indicator
        if (idx + 1) % 10 == 0 || idx + 1 == total_targets {
            crate::mprint!("\r{}", format!("[*] Progress: {}/{} ({:.0}%)", 
                idx + 1, total_targets, ((idx + 1) as f64 / total_targets as f64) * 100.0).dimmed());
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }

        match fetch_title(&client, url, &title_re).await {
            Ok(result) => {
                if let Some(title) = &result.title {
                    crate::mprintln!("\r{}", format!("[+] {} -> {}", url, title).green());
                    success_count += 1;
                } else if let Some(status) = result.status {
                    if status.is_success() {
                        crate::mprintln!("\r{}", format!("[+] {} -> <no title> (status: {})", url, status).green());
                        success_count += 1;
                    } else {
                        crate::mprintln!("\r{}", format!("[~] {} -> <no title> (status: {})", url, status).yellow());
                    }
                } else {
                    crate::mprintln!("\r{}", format!("[~] {} -> <no title>", url).yellow());
                }
                if verbose {
                    if let Some(status) = result.status {
                        crate::mprintln!("    Status: {}", status);
                    }
                    crate::mprintln!("    Duration: {} ms", result.duration_ms);
                }
                all_results.push(result);
            }
            Err(err) => {
                crate::mprintln!("\r{}", format!("[-] {} -> error: {}", url, err).red());
                error_count += 1;
                all_results.push(TitleResult {
                    url: url.clone(),
                    status: None,
                    title: None,
                    error: Some(err.to_string()),
                    duration_ms: 0,
                });
            }
        }
    }

    let elapsed = start_time.elapsed();
    
    // Print statistics
    crate::mprintln!();
    crate::mprintln!("{}", "=== Scan Statistics ===".bold());
    crate::mprintln!("  Total scanned:  {}", total_targets);
    crate::mprintln!("  Successful:     {}", success_count.to_string().green());
    crate::mprintln!("  Errors:         {}", error_count.to_string().red());
    crate::mprintln!("  Duration:       {:.2}s", elapsed.as_secs_f64());
    if elapsed.as_secs() > 0 {
        crate::mprintln!("  Rate:           {:.1} requests/s", total_targets as f64 / elapsed.as_secs_f64());
    }

    if save_output {
        let default_name = format!(
            "http_title_scan_{}.txt",
            Utc::now().format("%Y%m%d_%H%M%S")
        );
        let output_path = cfg_prompt_output_file("output_file", "Enter output file path", &default_name).await?;
        write_report(&output_path, &all_results)?;
        crate::mprintln!("[*] Results saved to {}", output_path);
    }

    crate::mprintln!("\n[*] Scan complete.");
    Ok(())
}

struct TitleResult {
    url: String,
    status: Option<StatusCode>,
    title: Option<String>,
    error: Option<String>,
    duration_ms: u128,
}

impl TitleResult {
    fn display_title(&self) -> String {
        match (&self.title, &self.error) {
            (Some(title), _) => title.clone(),
            (None, Some(err)) => format!("error: {}", err),
            (None, None) => "<no title>".to_string(),
        }
    }
}

async fn fetch_title(client: &Client, url: &str, title_re: &Regex) -> Result<TitleResult> {
    let start = std::time::Instant::now();
    let response = client.get(url).send().await.context("Request failed")?;
    let status = response.status();
    // Read at most 256KB to prevent OOM from malicious responses
    let bytes = match response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return Err(anyhow!("Failed to read response body: {}", e));
        }
    };
    let truncated = if bytes.len() > 256 * 1024 { &bytes[..256 * 1024] } else { &bytes };
    let text = String::from_utf8_lossy(truncated).to_string();
    let title = title_re
        .captures(&text)
        .and_then(|cap| cap.get(1))
        .map(|m| sanitize_title(m.as_str()));
    let duration = start.elapsed().as_millis();

    Ok(TitleResult {
        url: url.to_string(),
        status: Some(status),
        title,
        error: None,
        duration_ms: duration,
    })
}

fn sanitize_title(raw: &str) -> String {
    raw
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(200)
        .collect()
}

fn collect_initial_targets(initial_target: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let trimmed = initial_target.trim();
    if !trimmed.is_empty() && trimmed != "http_title_scanner" {
        targets.extend(split_targets(trimmed));
    }
    targets
}

fn split_targets(input: &str) -> Vec<String> {
    input
        .split(|c| c == ',' || c == '\n' || c == ';')
        .map(|item| item.trim().trim_end_matches('/').to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn load_targets_from_file(path: &str) -> Result<Vec<String>> {
    let data = safe_read_to_string(path, None)
        .with_context(|| format!("Failed to read target file: {}", path))?;
    Ok(split_targets(&data))
}

fn normalize_targets(targets: Vec<String>, check_http: bool, check_https: bool) -> Vec<String> {
    let mut unique = HashSet::new();
    let mut normalized = Vec::new();

    for raw in targets {
        let target = raw.trim();
        if target.is_empty() {
            continue;
        }

        if target.starts_with("http://") || target.starts_with("https://") {
            if unique.insert(target.to_string()) {
                normalized.push(target.to_string());
            }
            continue;
        }

        if check_https {
            let https = format!("https://{}", target);
            if unique.insert(https.clone()) {
                normalized.push(https);
            }
        }

        if check_http {
            let http = format!("http://{}", target);
            if unique.insert(http.clone()) {
                normalized.push(http);
            }
        }
    }

    normalized
}

fn parse_ports_from_string(s: &str) -> Vec<u16> {
    s.split(',')
        .filter_map(|p| p.trim().parse::<u16>().ok())
        .filter(|p| *p > 0)
        .collect()
}

fn expand_targets_with_ports(targets: &[String], ports: &[u16]) -> Vec<String> {
    let mut expanded = Vec::new();
    let mut seen = HashSet::new();

    for target in targets {
        if let Ok(url) = Url::parse(target) {
            for port in ports {
                let mut candidate = url.clone();
                if candidate.set_port(Some(*port)).is_ok() {
                    let final_url = candidate.to_string();
                    if seen.insert(final_url.clone()) {
                        expanded.push(final_url);
                    }
                }
            }
        } else {
            for port in ports {
                let final_url = format!("{}:{}", target, port);
                if seen.insert(final_url.clone()) {
                    expanded.push(final_url);
                }
            }
        }
    }

    expanded
}

fn write_report(path: &str, results: &[TitleResult]) -> Result<()> {
    let mut lines = Vec::new();
    lines.push("HTTP Title Scanner Report".to_string());
    lines.push(format!("Generated at: {}", Utc::now()));
    lines.push(String::new());

    for result in results {
        let status_text = result
            .status
            .map(|s| s.as_u16().to_string())
            .unwrap_or_else(|| "n/a".to_string());
        lines.push(format!(
            "{} | status: {:<5} | title: {}",
            result.url,
            status_text,
            result.display_title()
        ));
        if result.duration_ms > 0 {
            lines.push(format!("    duration: {} ms", result.duration_ms));
        }
    }

    fs::write(path, lines.join("\n")).with_context(|| format!("Failed to write report to {}", path))
}

fn banner() {
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   HTTP Title Scanner                                         ║".cyan());
    crate::mprintln!("{}", "║   Enumerate page titles over HTTP/HTTPS endpoints            ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "HTTP Title Scanner".to_string(),
        description: "Enumerates HTML page titles across HTTP and HTTPS endpoints for target fingerprinting.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

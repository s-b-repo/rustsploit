use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use colored::*;
use regex::Regex;
use reqwest::{Client, StatusCode, Url};
use std::collections::HashSet;
use std::fs;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use std::time::{Duration, Instant};

pub async fn run(initial_target: &str) -> Result<()> {
    banner();

    let mut targets = collect_initial_targets(initial_target);

    let additional = prompt("Enter additional comma-separated targets (optional): ").await?;
    if !additional.is_empty() {
        targets.extend(split_targets(&additional));
    }

    let file_path = prompt("Path to file with targets (optional): ").await?;
    if !file_path.is_empty() {
        let file_targets = load_targets_from_file(&file_path)?;
        targets.extend(file_targets);
    }

    let check_http = prompt_bool("Check HTTP (http://)? (yes/no, default yes): ", true).await?;
    let check_https = prompt_bool("Check HTTPS (https://)? (yes/no, default yes): ", true).await?;

    if !check_http && !check_https {
        println!("[!] Neither HTTP nor HTTPS selected; nothing to scan.");
        return Ok(());
    }

    let use_ports = prompt_bool(
        "Test via specific ports (port tunneling)? (yes/no, default no): ",
        false,
    ).await?;
    let ports = if use_ports {
        prompt_ports().await?
    } else {
        Vec::new()
    };

    let timeout_secs = prompt_timeout().await?;
    let save_output = prompt_bool("Save results to file? (yes/no, default yes): ", true).await?;
    let verbose = prompt_bool("Enable verbose output? (yes/no, default no): ", false).await?;

    let mut normalized = normalize_targets(targets, check_http, check_https);
    if !ports.is_empty() {
        let expanded = expand_targets_with_ports(&normalized, &ports);
        if expanded.is_empty() {
            println!("[!] No valid port combinations derived; continuing without port tunneling.");
        } else {
            normalized = expanded;
        }
    }
    if normalized.is_empty() {
        return Err(anyhow!("No valid targets provided"));
    }
    normalized.sort();

    let client = Client::builder()
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

    println!("{}", format!("[*] Scanning {} target(s)...", total_targets).cyan().bold());
    println!();

    for (idx, url) in normalized.iter().enumerate() {
        // Progress indicator
        if (idx + 1) % 10 == 0 || idx + 1 == total_targets {
            print!("\r{}", format!("[*] Progress: {}/{} ({:.0}%)", 
                idx + 1, total_targets, ((idx + 1) as f64 / total_targets as f64) * 100.0).dimmed());
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }

        match fetch_title(&client, url, &title_re).await {
            Ok(result) => {
                if let Some(title) = &result.title {
                    println!("\r{}", format!("[+] {} -> {}", url, title).green());
                    success_count += 1;
                } else if let Some(status) = result.status {
                    if status.is_success() {
                        println!("\r{}", format!("[+] {} -> <no title> (status: {})", url, status).green());
                        success_count += 1;
                    } else {
                        println!("\r{}", format!("[~] {} -> <no title> (status: {})", url, status).yellow());
                    }
                } else {
                    println!("\r{}", format!("[~] {} -> <no title>", url).yellow());
                }
                if verbose {
                    if let Some(status) = result.status {
                        println!("    Status: {}", status);
                    }
                    println!("    Duration: {} ms", result.duration_ms);
                }
                all_results.push(result);
            }
            Err(err) => {
                println!("\r{}", format!("[-] {} -> error: {}", url, err).red());
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
    println!();
    println!("{}", "=== Scan Statistics ===".bold());
    println!("  Total scanned:  {}", total_targets);
    println!("  Successful:     {}", success_count.to_string().green());
    println!("  Errors:         {}", error_count.to_string().red());
    println!("  Duration:       {:.2}s", elapsed.as_secs_f64());
    if elapsed.as_secs() > 0 {
        println!("  Rate:           {:.1} requests/s", total_targets as f64 / elapsed.as_secs_f64());
    }

    if save_output {
        let default_name = format!(
            "http_title_scan_{}.txt",
            Utc::now().format("%Y%m%d_%H%M%S")
        );
        let output_path = prompt_with_default(
            "Enter output file path (press Enter for default): ",
            &default_name,
        ).await?;
        write_report(&output_path, &all_results)?;
        println!("[*] Results saved to {}", output_path);
    }

    println!("\n[*] Scan complete.");
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
    let text = response.text().await.unwrap_or_default();
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
    let data = fs::read_to_string(path)
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

async fn prompt(message: &str) -> Result<String> {
    print!("{}", message);
    tokio::io::stdout()
        .flush()
        .await
        .context("Failed to flush stdout")?;
    let mut input = String::new();
    tokio::io::BufReader::new(tokio::io::stdin())
        .read_line(&mut input)
        .await
        .context("Failed to read user input")?;
    Ok(input.trim().to_string())
}

async fn prompt_bool(message: &str, default: bool) -> Result<bool> {
    let default_text = if default { "yes" } else { "no" };
    let input = prompt(message).await?;
    if input.is_empty() {
        return Ok(default);
    }
    match input.to_lowercase().as_str() {
        "y" | "yes" | "true" => Ok(true),
        "n" | "no" | "false" => Ok(false),
        _ => {
            println!("[!] Invalid input, using default ({})", default_text);
            Ok(default)
        }
    }
}

async fn prompt_with_default(message: &str, default: &str) -> Result<String> {
    let input = prompt(message).await?;
    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input)
    }
}

async fn prompt_timeout() -> Result<u64> {
    let input = prompt("Request timeout in seconds (default 10): ").await?;
    if input.is_empty() {
        return Ok(10);
    }
    match input.parse::<u64>() {
        Ok(val) if val > 0 => Ok(val),
        _ => {
            println!("[!] Invalid timeout, using default (10s)");
            Ok(10)
        }
    }
}

async fn prompt_ports() -> Result<Vec<u16>> {
    let input = prompt(
        "Enter port(s) to tunnel through (comma-separated, e.g., 80,8080; leave blank to skip): ",
    ).await?;
    if input.is_empty() {
        println!("[!] No ports provided; skipping port tunneling.");
        return Ok(Vec::new());
    }

    let mut ports = Vec::new();
    let mut seen = HashSet::new();
    for part in input.split(|c| c == ',' || c == ';' || c == ' ') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        match trimmed.parse::<u16>() {
            Ok(port) => {
                if seen.insert(port) {
                    ports.push(port);
                }
            }
            Err(_) => println!("[!] Skipping invalid port '{}'.", trimmed),
        }
    }

    if ports.is_empty() {
        println!("[!] No valid ports parsed; skipping port tunneling.");
    }

    Ok(ports)
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
    println!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   HTTP Title Scanner                                         ║".cyan());
    println!("{}", "║   Enumerate page titles over HTTP/HTTPS endpoints            ║".cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    println!();
}

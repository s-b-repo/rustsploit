use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use colored::*;
use reqwest::{Client, Method, StatusCode, Url};
use std::collections::HashSet;
use std::fs;

use std::time::{Duration, Instant};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_yes_no, cfg_prompt_int_range, cfg_prompt_output_file,
};

const METHODS: &[&str] = &[
    "GET",
"POST",
"HEAD",
"OPTIONS",
"PUT",
"DELETE",
"PATCH",
"TRACE",
"CONNECT",
];

struct MethodResult {
    method: &'static str,
    status: Option<StatusCode>,
    ok: bool,
    error: Option<String>,
    duration_ms: u128,
}

struct TargetResult {
    target: String,
    results: Vec<MethodResult>,
}

pub async fn run(initial_target: &str) -> Result<()> {
    banner();

    let mut targets = collect_initial_targets(initial_target);

    let additional = cfg_prompt_default("additional_targets", "Enter additional comma-separated targets (optional)", "")?;
    if !additional.is_empty() {
        targets.extend(split_targets(&additional));
    }

    let file_path = cfg_prompt_default("target_file", "Path to file with targets (optional)", "")?;
    if !file_path.is_empty() {
        let file_targets = load_targets_from_file(&file_path)?;
        targets.extend(file_targets);
    }

    let default_scheme_input = cfg_prompt_default("scheme", "Preferred scheme (http/https)", "https")?;
    let default_scheme = match default_scheme_input.to_lowercase().as_str() {
        "http" => "http",
        _ => "https",
    };

    let use_ports = cfg_prompt_yes_no("use_ports", "Test via specific ports (port tunneling)?", false)?;
    let ports = if use_ports {
        let ports_str = cfg_prompt_default("ports", "Enter port(s) comma-separated (e.g. 80,8080)", "")?;
        parse_ports_from_string(&ports_str)
    } else {
        Vec::new()
    };

    let timeout_secs = cfg_prompt_int_range("timeout", "Request timeout in seconds", 10, 1, 120)? as u64;

    let verbose = cfg_prompt_yes_no("verbose", "Enable verbose output?", false)?;
    let save_output = cfg_prompt_yes_no("save_results", "Save results to file?", true)?;

    let mut normalized = normalize_targets(targets, default_scheme);
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
    .user_agent("RustSploit-HTTP-Method-Scanner/1.0")
    .timeout(Duration::from_secs(timeout_secs))
    .redirect(reqwest::redirect::Policy::limited(5))
    .build()
    .context("Failed to build HTTP client")?;

    let mut all_results = Vec::new();
    let mut total_success = 0usize;
    let mut total_errors = 0usize;
    let start_time = Instant::now();

    println!("{}", format!("[*] Scanning {} target(s) with {} methods each...", 
        normalized.len(), METHODS.len()).cyan().bold());

    for target in &normalized {
        println!("\n{}", format!("=== Target: {} ===", target).bold());
        let mut method_results = Vec::new();

        for &method_name in METHODS {
            let method = Method::from_bytes(method_name.as_bytes()).unwrap_or(Method::GET);
            let body = match method_name {
                "POST" | "PUT" | "PATCH" => Some("RustSploit HTTP method scanner test".to_string()),
                _ => None,
            };

            let start = std::time::Instant::now();
            let response = if let Some(ref payload) = body {
                client
                .request(method.clone(), target)
                .body(payload.clone())
                .send()
                .await
            } else {
                client.request(method.clone(), target).send().await
            };
            let elapsed = start.elapsed();

            match response {
                Ok(resp) => {
                    let status = resp.status();
                    let ok = status.is_success();
                    if ok {
                        total_success += 1;
                        if verbose {
                            println!("{}", format!("  [{}] {} -> {} ({:.2?})", method_name, target, status, elapsed).green());
                        } else {
                            println!("{}", format!("  [{}] {}", method_name, status).green());
                        }
                    } else {
                        if verbose {
                            println!("{}", format!("  [{}] {} -> {} ({:.2?})", method_name, target, status, elapsed).yellow());
                        } else {
                            println!("{}", format!("  [{}] {}", method_name, status).yellow());
                        }
                    }
                    method_results.push(MethodResult {
                        method: method_name,
                        status: Some(status),
                        ok,
                        error: None,
                        duration_ms: elapsed.as_millis(),
                    });
                }
                Err(err) => {
                    total_errors += 1;
                    if verbose {
                        println!("{}", format!("  [{}] {} -> error: {} ({:.2?})", method_name, target, err, elapsed).red());
                    } else {
                        println!("{}", format!("  [{}] error: {}", method_name, err).red());
                    }
                    method_results.push(MethodResult {
                        method: method_name,
                        status: None,
                        ok: false,
                        error: Some(err.to_string()),
                        duration_ms: elapsed.as_millis(),
                    });
                }
            }
        }

        all_results.push(TargetResult {
            target: target.clone(),
            results: method_results,
        });
    }

    let total_elapsed = start_time.elapsed();
    let total_requests = normalized.len() * METHODS.len();

    // Print statistics
    println!();
    println!("{}", "=== Scan Statistics ===".bold());
    println!("  Targets:        {}", normalized.len());
    println!("  Methods tested: {}", METHODS.len());
    println!("  Total requests: {}", total_requests);
    println!("  Successful:     {}", total_success.to_string().green());
    println!("  Errors:         {}", total_errors.to_string().red());
    println!("  Duration:       {:.2}s", total_elapsed.as_secs_f64());
    if total_elapsed.as_secs() > 0 {
        println!("  Rate:           {:.1} requests/s", total_requests as f64 / total_elapsed.as_secs_f64());
    }

    if save_output {
        let default_name = format!(
            "http_method_scan_{}.txt",
            Utc::now().format("%Y%m%d_%H%M%S")
        );
        let output_path = cfg_prompt_output_file("output_file", "Enter output file path", &default_name)?;
        write_report(&output_path, &all_results)?;
        println!("[*] Results saved to {}", output_path);
    }

    println!("\n[*] Scan complete.");
    Ok(())
}

fn banner() {
    println!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   HTTP Method Capability Scanner                             ║".cyan());
    println!("{}", "║   Checks support for common HTTP verbs (GET, POST, etc.)     ║".cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    println!();
}

fn collect_initial_targets(initial_target: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let trimmed = initial_target.trim();
    if !trimmed.is_empty() && trimmed != "http_method_scanner" {
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

fn normalize_targets(targets: Vec<String>, default_scheme: &str) -> Vec<String> {
    let mut unique = HashSet::new();
    let mut normalized = Vec::new();

    for raw in targets {
        let target = raw.trim();
        if target.is_empty() {
            continue;
        }
        let formatted = if target.starts_with("http://")
        || target.starts_with("https://")
        || target.contains("://")
        {
            target.to_string()
        } else {
            format!("{}://{}", default_scheme, target)
        };
        if unique.insert(formatted.clone()) {
            normalized.push(formatted);
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
        if let Ok(mut url) = Url::parse(target) {
            for port in ports {
                if url.set_port(Some(*port)).is_ok() {
                    let final_url = url.to_string();
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

fn write_report(path: &str, results: &[TargetResult]) -> Result<()> {
    let mut lines = Vec::new();
    lines.push("HTTP Method Scanner Report".to_string());
    lines.push(format!("Generated at: {}", Utc::now()));
    lines.push(String::new());

    for target in results {
        lines.push(format!("Target: {}", target.target));
        for method in &target.results {
            if let Some(status) = method.status {
                lines.push(format!(
                    "  - {:<7} status: {:<5} success: {:<5} time: {} ms",
                    method.method,
                    status.as_u16(),
                                   method.ok,
                                   method.duration_ms
                ));
            } else if let Some(ref error) = method.error {
                lines.push(format!(
                    "  - {:<7} error: {} time: {} ms",
                    method.method, error, method.duration_ms
                ));
            }
        }
        lines.push(String::new());
    }

    fs::write(path, lines.join("\n"))
    .with_context(|| format!("Failed to write report to {}", path))
}

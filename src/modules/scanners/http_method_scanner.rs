use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use reqwest::{Client, Method, StatusCode, Url};
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::time::Duration;

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

    let additional = prompt("Enter additional comma-separated targets (optional): ")?;
    if !additional.is_empty() {
        targets.extend(split_targets(&additional));
    }

    let file_path = prompt("Path to file with targets (optional): ")?;
    if !file_path.is_empty() {
        let file_targets = load_targets_from_file(&file_path)?;
        targets.extend(file_targets);
    }

    let default_scheme_input = prompt("Preferred scheme (http/https, default https): ")?;
    let default_scheme = match default_scheme_input.to_lowercase().as_str() {
        "http" => "http",
        _ => "https",
    };

    let use_ports = prompt_bool(
        "Test via specific ports (port tunneling)? (yes/no, default no): ",
                                false,
    )?;
    let ports = if use_ports {
        prompt_ports()?
    } else {
        Vec::new()
    };

    let timeout_input = prompt("Request timeout in seconds (default 10): ")?;
    let timeout_secs: u64 = timeout_input
    .parse()
    .ok()
    .filter(|val| *val > 0)
    .unwrap_or(10);

    let verbose = prompt_bool("Enable verbose output? (yes/no, default no): ", false)?;
    let save_output = prompt_bool("Save results to file? (yes/no, default yes): ", true)?;

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

    for target in &normalized {
        println!("\n=== Target: {} ===", target);
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
                    if verbose {
                        println!(
                            "  [{}] {} -> {} ({:.2?})",
                                 method_name,
                                 target,
                                 status,
                                 elapsed
                        );
                    } else {
                        println!("  [{}] {}", method_name, status);
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
                    if verbose {
                        println!(
                            "  [{}] {} -> error: {} ({:.2?})",
                                 method_name,
                                 target,
                                 err,
                                 elapsed
                        );
                    } else {
                        println!("  [{}] error: {}", method_name, err);
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

    if save_output {
        let default_name = format!(
            "http_method_scan_{}.txt",
            Utc::now().format("%Y%m%d_%H%M%S")
        );
        let output_path = prompt_with_default(
            "Enter output file path (press Enter for default): ",
                                              &default_name,
        )?;
        write_report(&output_path, &all_results)?;
        println!("[*] Results saved to {}", output_path);
    }

    println!("\n[*] Scan complete.");
    Ok(())
}

fn banner() {
    println!(
        "{}",
        r#"
        ╔══════════════════════════════════════════════════════╗
        ║         HTTP METHOD CAPABILITY SCANNER               ║
        ║          Checks support for common verbs             ║
        ╚══════════════════════════════════════════════════════╝
        "#
    );
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

fn prompt(message: &str) -> Result<String> {
    print!("{}", message);
    io::stdout().flush().context("Failed to flush stdout")?;
    let mut input = String::new();
    io::stdin()
    .read_line(&mut input)
    .context("Failed to read user input")?;
    Ok(input.trim().to_string())
}

fn prompt_bool(message: &str, default: bool) -> Result<bool> {
    let default_text = if default { "yes" } else { "no" };
    let input = prompt(message)?;
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

fn prompt_with_default(message: &str, default: &str) -> Result<String> {
    let input = prompt(message)?;
    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input)
    }
}

fn prompt_ports() -> Result<Vec<u16>> {
    let input = prompt(
        "Enter port(s) to tunnel through (comma-separated, e.g., 80,8080; leave blank to skip): ",
    )?;
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

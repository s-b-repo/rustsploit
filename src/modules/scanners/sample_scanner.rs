use anyhow::{anyhow, Context, Result};
use colored::*;
use reqwest::Client;
use std::fs::File;
use std::io::Write;

use std::time::{Duration, Instant};

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   HTTP Connectivity Scanner                               ║".cyan());
    println!("{}", "║   Checks HTTP/HTTPS reachability and response codes       ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

pub async fn run(target: &str) -> Result<()> {
    display_banner();
    
    println!("{}", format!("[*] Target: {}", target).cyan());
    
    let timeout_secs = prompt_timeout()?;
    let check_http = prompt_bool("Check HTTP (port 80)?", true)?;
    let check_https = prompt_bool("Check HTTPS (port 443)?", true)?;
    let verbose = prompt_bool("Verbose output?", false)?;
    let save_results = prompt_bool("Save results to file?", false)?;
    
    if !check_http && !check_https {
        return Err(anyhow!("At least one protocol must be selected"));
    }
    
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(true)
        .build()
        .context("Failed to build HTTP client")?;
    
    let mut results = Vec::new();
    let start = Instant::now();
    
    println!();
    println!("{}", "[*] Starting scan...".cyan().bold());
    
    // Check HTTP
    if check_http {
        let url = if target.contains("://") {
            target.to_string()
        } else {
            format!("http://{}", target)
        };
        
        if verbose {
            println!("{}", format!("[*] Checking {}...", url).dimmed());
        }
        
        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let status_str = status.to_string();
                let content_type = resp.headers()
                    .get("content-type")
                    .map(|v| v.to_str().unwrap_or("unknown"))
                    .unwrap_or("unknown");
                let server = resp.headers()
                    .get("server")
                    .map(|v| v.to_str().unwrap_or("unknown"))
                    .unwrap_or("unknown");
                
                if status.is_success() {
                    println!("{}", format!("[+] HTTP {} -> {} (Server: {}, Content-Type: {})", 
                        url, status_str, server, content_type).green());
                } else if status.is_redirection() {
                    let location = resp.headers()
                        .get("location")
                        .map(|v| v.to_str().unwrap_or("unknown"))
                        .unwrap_or("unknown");
                    println!("{}", format!("[~] HTTP {} -> {} (Redirect: {})", url, status_str, location).yellow());
                } else {
                    println!("{}", format!("[-] HTTP {} -> {}", url, status_str).red());
                }
                
                results.push(format!("HTTP {} -> {} (Server: {})", url, status_str, server));
            }
            Err(e) => {
                println!("{}", format!("[-] HTTP {} -> Error: {}", url, e).red());
                results.push(format!("HTTP {} -> Error: {}", url, e));
            }
        }
    }
    
    // Check HTTPS
    if check_https {
        let url = if target.contains("://") {
            target.replace("http://", "https://")
        } else {
            format!("https://{}", target)
        };
        
        if verbose {
            println!("{}", format!("[*] Checking {}...", url).dimmed());
        }
        
        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let status_str = status.to_string();
                let server = resp.headers()
                    .get("server")
                    .map(|v| v.to_str().unwrap_or("unknown"))
                    .unwrap_or("unknown");
                let content_type = resp.headers()
                    .get("content-type")
                    .map(|v| v.to_str().unwrap_or("unknown"))
                    .unwrap_or("unknown");
                
                if status.is_success() {
                    println!("{}", format!("[+] HTTPS {} -> {} (Server: {}, Content-Type: {})", 
                        url, status_str, server, content_type).green());
                } else if status.is_redirection() {
                    let location = resp.headers()
                        .get("location")
                        .map(|v| v.to_str().unwrap_or("unknown"))
                        .unwrap_or("unknown");
                    println!("{}", format!("[~] HTTPS {} -> {} (Redirect: {})", url, status_str, location).yellow());
                } else {
                    println!("{}", format!("[-] HTTPS {} -> {}", url, status_str).red());
                }
                
                results.push(format!("HTTPS {} -> {} (Server: {})", url, status_str, server));
            }
            Err(e) => {
                println!("{}", format!("[-] HTTPS {} -> Error: {}", url, e).red());
                results.push(format!("HTTPS {} -> Error: {}", url, e));
            }
        }
    }
    
    let elapsed = start.elapsed();
    
    // Print summary
    println!();
    println!("{}", "=== Scan Summary ===".bold());
    println!("  Target:         {}", target);
    println!("  Duration:       {:.2}s", elapsed.as_secs_f64());
    println!("  Checks:         {}", results.len());
    
    // Save results
    if save_results && !results.is_empty() {
        let filename = prompt_with_default("Output filename", "http_scan_results.txt")?;
        let mut file = File::create(&filename).context("Failed to create output file")?;
        writeln!(file, "HTTP Connectivity Scan Results")?;
        writeln!(file, "Target: {}", target)?;
        writeln!(file, "Duration: {:.2}s", elapsed.as_secs_f64())?;
        writeln!(file)?;
        for result in &results {
            writeln!(file, "{}", result)?;
        }
        println!("{}", format!("[+] Results saved to '{}'", filename).green());
    }
    
    Ok(())
}

fn prompt_bool(message: &str, default: bool) -> Result<bool> {
    let hint = if default { "Y/n" } else { "y/N" };
    print!("{}", format!("{} [{}]: ", message, hint).cyan().bold());
    std::io::stdout()
        .flush()
        .context("Failed to flush stdout")?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("Failed to read input")?;
    let trimmed = input.trim().to_lowercase();
    match trimmed.as_str() {
        "" => Ok(default),
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => Ok(default),
    }
}

fn prompt_with_default(message: &str, default: &str) -> Result<String> {
    print!("{}", format!("{} [{}]: ", message, default).cyan().bold());
    std::io::stdout()
        .flush()
        .context("Failed to flush stdout")?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("Failed to read input")?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn prompt_timeout() -> Result<u64> {
    print!("{}", "Timeout in seconds [10]: ".cyan().bold());
    std::io::stdout()
        .flush()
        .context("Failed to flush stdout")?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("Failed to read input")?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(10)
    } else {
        trimmed.parse().map_err(|_| anyhow!("Invalid timeout"))
    }
}

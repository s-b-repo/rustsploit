use anyhow::{anyhow, Context, Result};
use colored::*;
use reqwest::Client;
use std::fs::File;
use std::io::Write;

use std::time::{Duration, Instant};
use crate::utils::{
    cfg_prompt_int_range, cfg_prompt_yes_no, cfg_prompt_output_file,
};

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
    
    let timeout_secs = cfg_prompt_int_range("timeout", "Timeout in seconds", 10, 1, 120)? as u64;
    let check_http = cfg_prompt_yes_no("check_http", "Check HTTP (port 80)?", true)?;
    let check_https = cfg_prompt_yes_no("check_https", "Check HTTPS (port 443)?", true)?;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose output?", false)?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", false)?;
    
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
        let filename = cfg_prompt_output_file("output_file", "Output filename", "http_scan_results.txt")?;
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

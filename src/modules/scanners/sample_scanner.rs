use anyhow::{anyhow, Context, Result};
use colored::*;
use std::fs::File;
use std::io::Write;

use std::time::{Duration, Instant};
use crate::utils::{
    cfg_prompt_int_range, cfg_prompt_yes_no, cfg_prompt_output_file,
};
use crate::modules::creds::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};

fn display_banner() {
    crate::mprintln!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   HTTP Connectivity Scanner                               ║".cyan());
    crate::mprintln!("{}", "║   Checks HTTP/HTTPS reachability and response codes       ║".cyan());
    crate::mprintln!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

pub async fn run(target: &str) -> Result<()> {
    if is_mass_scan_target(target) {
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "Sample",
            default_port: 80,
            state_file: "sample_scanner_mass_state.log",
            default_output: "sample_scanner_mass_results.txt",
            default_concurrency: 500,
        }, move |ip, port| {
            async move {
                if crate::utils::tcp_port_open(ip, port, std::time::Duration::from_secs(3)).await {
                    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                    Some(format!("[{}] {}:{} Sample open\n", ts, ip, port))
                } else {
                    None
                }
            }
        }).await;
    }

    display_banner();

    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());
    
    let timeout_secs = cfg_prompt_int_range("timeout", "Timeout in seconds", 10, 1, 120).await? as u64;
    let check_http = cfg_prompt_yes_no("check_http", "Check HTTP (port 80)?", true).await?;
    let check_https = cfg_prompt_yes_no("check_https", "Check HTTPS (port 443)?", true).await?;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose output?", false).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", false).await?;
    
    if !check_http && !check_https {
        return Err(anyhow!("At least one protocol must be selected"));
    }
    
    let client = crate::utils::build_http_client(Duration::from_secs(timeout_secs))?;
    
    let mut results = Vec::new();
    let start = Instant::now();
    
    crate::mprintln!();
    crate::mprintln!("{}", "[*] Starting scan...".cyan().bold());
    
    // Check HTTP
    if check_http {
        let url = if target.contains("://") {
            target.to_string()
        } else {
            format!("http://{}", target)
        };
        
        if verbose {
            crate::mprintln!("{}", format!("[*] Checking {}...", url).dimmed());
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
                    crate::mprintln!("{}", format!("[+] HTTP {} -> {} (Server: {}, Content-Type: {})", 
                        url, status_str, server, content_type).green());
                } else if status.is_redirection() {
                    let location = resp.headers()
                        .get("location")
                        .map(|v| v.to_str().unwrap_or("unknown"))
                        .unwrap_or("unknown");
                    crate::mprintln!("{}", format!("[~] HTTP {} -> {} (Redirect: {})", url, status_str, location).yellow());
                } else {
                    crate::mprintln!("{}", format!("[-] HTTP {} -> {}", url, status_str).red());
                }
                
                results.push(format!("HTTP {} -> {} (Server: {})", url, status_str, server));
            }
            Err(e) => {
                crate::mprintln!("{}", format!("[-] HTTP {} -> Error: {}", url, e).red());
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
            crate::mprintln!("{}", format!("[*] Checking {}...", url).dimmed());
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
                    crate::mprintln!("{}", format!("[+] HTTPS {} -> {} (Server: {}, Content-Type: {})", 
                        url, status_str, server, content_type).green());
                } else if status.is_redirection() {
                    let location = resp.headers()
                        .get("location")
                        .map(|v| v.to_str().unwrap_or("unknown"))
                        .unwrap_or("unknown");
                    crate::mprintln!("{}", format!("[~] HTTPS {} -> {} (Redirect: {})", url, status_str, location).yellow());
                } else {
                    crate::mprintln!("{}", format!("[-] HTTPS {} -> {}", url, status_str).red());
                }
                
                results.push(format!("HTTPS {} -> {} (Server: {})", url, status_str, server));
            }
            Err(e) => {
                crate::mprintln!("{}", format!("[-] HTTPS {} -> Error: {}", url, e).red());
                results.push(format!("HTTPS {} -> Error: {}", url, e));
            }
        }
    }
    
    let elapsed = start.elapsed();
    
    // Print summary
    crate::mprintln!();
    crate::mprintln!("{}", "=== Scan Summary ===".bold());
    crate::mprintln!("  Target:         {}", target);
    crate::mprintln!("  Duration:       {:.2}s", elapsed.as_secs_f64());
    crate::mprintln!("  Checks:         {}", results.len());
    
    // Save results
    if save_results && !results.is_empty() {
        let filename = cfg_prompt_output_file("output_file", "Output filename", "http_scan_results.txt").await?;
        let mut file = File::create(&filename).context("Failed to create output file")?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&filename, std::fs::Permissions::from_mode(0o600));
        writeln!(file, "HTTP Connectivity Scan Results")?;
        writeln!(file, "Target: {}", target)?;
        writeln!(file, "Duration: {:.2}s", elapsed.as_secs_f64())?;
        writeln!(file)?;
        for result in &results {
            writeln!(file, "{}", result)?;
        }
        crate::mprintln!("{}", format!("[+] Results saved to '{}'", filename).green());
    }

    Ok(())
}

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "HTTP Connectivity Scanner".to_string(),
        description: "Checks HTTP and HTTPS reachability and response codes for target hosts.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

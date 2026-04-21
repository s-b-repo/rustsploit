use anyhow::{Result, Context};
use colored::*;
use std::time::Duration;
use crate::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};

const DEFAULT_TIMEOUT_SECS: u64 = 10;

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "Sample Default Credential Checker".to_string(),
        description: "Sample module that tests HTTP Basic Auth with default admin:admin credentials. Serves as a template for building custom credential checking modules.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

fn display_banner() {
    if crate::utils::is_batch_mode() { return; }
    crate::mprintln!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   Sample Default Credential Checker                       ║".cyan());
    crate::mprintln!("{}", "║   HTTP Basic Auth Test Module                             ║".cyan());
    crate::mprintln!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

/// A sample credential check - tries a basic auth login
pub async fn run(target: &str) -> Result<()> {
    // Mass scan mode: random IPs, CIDR subnets, or target file
    if is_mass_scan_target(target) {
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "HTTP Basic Auth",
            default_port: 80,
            state_file: "sample_cred_mass_state.log",
            default_output: "sample_cred_mass_results.txt",
            default_concurrency: 200,
        }, |ip: std::net::IpAddr, port: u16| async move {
            if !crate::utils::tcp_port_open(ip, port, Duration::from_secs(3)).await {
                return None;
            }
            let client = crate::utils::build_http_client(Duration::from_secs(5)).ok()?;
            let url = format!("http://{}:{}/login", ip, port);
            let resp = client.post(&url)
                .basic_auth("admin", Some("admin"))
                .send()
                .await
                .ok()?;
            if resp.status().is_success() {
                let msg = format!("{}:{}:admin:admin", ip, port);
                crate::mprintln!("\r{}", format!("[+] FOUND: {}", msg).green().bold());
                return Some(format!("{}\n", msg));
            }
            None
        }).await;
    }

    display_banner();

    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());
    crate::mprintln!("{}", "[*] Checking default credentials (admin:admin)...".cyan());
    crate::mprintln!();

    let url = format!("http://{}/login", target);
    let client = crate::utils::build_http_client(Duration::from_secs(DEFAULT_TIMEOUT_SECS))?;

    let resp = client
        .post(&url)
        .basic_auth("admin", Some("admin"))
        .send()
        .await
        .context("Failed to send login request")?;

    if resp.status().is_success() {
        crate::mprintln!("{}", "[+] Default credentials admin:admin are valid!".green().bold());
        // Persist discovered credential to the framework's credential store
        let _ = crate::cred_store::store_credential(
            target, 80, "http", "admin", "admin",
            crate::cred_store::CredType::Password,
            "creds/generic/sample_cred_check",
        ).await;
    } else {
        crate::mprintln!("{}", "[-] Default credentials admin:admin failed.".yellow());
    }

    Ok(())
}

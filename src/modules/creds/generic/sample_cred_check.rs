use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};

const DEFAULT_TIMEOUT_SECS: u64 = 10;

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "Sample Default Credential Checker".to_string(),
        description: "Sample module that tests HTTP Basic Auth with default admin:admin credentials. Serves as a template for building custom credential checking modules — uses the native ModuleCtx/ModuleOutcome shape so credential findings flow into LootStore.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
        default_port: None,
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

/// Sample credential check — tries an HTTP Basic Auth login with `admin:admin`.
pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("sample_cred_check requires a single-host target")?;

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

    let mut outcome = ModuleOutcome::ok();
    if resp.status().is_success() {
        crate::mprintln!("{}", "[+] Default credentials admin:admin are valid!".green().bold());
        // Persist discovered credential to the framework's credential store.
        // The scheduler also routes the Finding below into LootStore.
        if crate::cred_store::store_credential(crate::cred_store::NewCred {
            host: target, port: 80, service: "http", username: "admin", secret: "admin",
            cred_type: crate::cred_store::CredType::Password,
            source_module: "creds/generic/sample_cred_check",
        }).await.is_none() { eprintln!("[!] Failed to store credential"); }
        outcome.findings.push(Finding {
            target: target.to_string(),
            kind: FindingKind::Credential,
            message: format!("HTTP basic auth admin:admin succeeded at {}", url),
            data: Some(serde_json::json!({
                "service": "http",
                "port": 80,
                "username": "admin",
                "password": "admin",
                "url": url,
            })),
        });
    } else {
        crate::mprintln!("{}", "[-] Default credentials admin:admin failed.".yellow());
    }

    Ok(outcome)
}

crate::register_native_module!(crate::module::Category::Creds, "generic/sample_cred_check", native);

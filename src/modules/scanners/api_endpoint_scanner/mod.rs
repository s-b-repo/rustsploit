//! API endpoint scanner — entry point.
//!
//! The scanner is split into focused submodules so each phase (config, endpoint
//! discovery, request transport, per-endpoint scan orchestration, ID-enumeration)
//! has its own file. This file owns only the interactive `run` driver, the
//! `ModuleInfo`, and the inventory registration.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use colored::*;
use futures::{stream, StreamExt};
use reqwest::Method;

use crate::module::{Finding, ModuleCtx, ModuleOutcome};
use crate::native::payload_engine::MutatorConfig;
use crate::utils::{
    cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_int_range,
    cfg_prompt_wordlist, cfg_prompt_yes_no,
};

mod config;
mod enumerate;
mod idenum;
mod request;
mod scan;

use config::{
    ScanConfig, ScanModule, CMDI_PAYLOADS, NOSQLI_PAYLOADS, SQLI_PAYLOADS, TRAVERSAL_PAYLOADS,
};
use enumerate::{configure_injection_payloads, enumerate_endpoints, parse_endpoint_file};
use scan::scan_endpoint;

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("module requires a single-host target")?;

    crate::mprintln!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   API Endpoint Pentest Module                             ║".cyan());
    crate::mprintln!("{}", "║   Tests API endpoints for common issues                   ║".cyan());
    crate::mprintln!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();

    // 1. Input parsing & configuration.
    let default_output_dir =
        format!("api_scan_results_{}", target.replace(['/', ':', '.', '[', ']', '\\'], "_"));
    let output_dir_name =
        cfg_prompt_default("output_dir", "Output directory name", &default_output_dir).await?;
    let use_spoofing = cfg_prompt_yes_no(
        "use_spoofing",
        "Enable IP Spoofing/Bypass headers logic? (Applies to all selected modules)",
        false,
    )
    .await?;
    let use_generic_payload = cfg_prompt_yes_no(
        "use_generic_payload",
        "Send generic JSON payload with POST/PUT/PATCH? (Better for API compatibility)",
        true,
    )
    .await?;

    // Method selection.
    let mut methods = vec![Method::GET, Method::POST];
    if cfg_prompt_yes_no(
        "enable_delete",
        "Enable DELETE method? (WARNING: Destructive)",
        false,
    )
    .await?
    {
        methods.push(Method::DELETE);
    }
    if cfg_prompt_yes_no(
        "enable_extended_methods",
        "Enable Extended HTTP methods (PUT, PATCH, HEAD, OPTIONS, CONNECT, TRACE, DEBUG)?",
        false,
    )
    .await?
    {
        methods.extend(vec![
            Method::PUT,
            Method::PATCH,
            Method::HEAD,
            Method::OPTIONS,
            Method::CONNECT,
            Method::TRACE,
        ]);
        match Method::from_bytes(b"DEBUG") {
            Ok(m) => methods.push(m),
            Err(e) => crate::mprintln!(
                "{}",
                format!("[!] Failed to register DEBUG method: {}", e).yellow()
            ),
        }
    }

    crate::mprintln!("1. Baseline (Standard Requests)");
    crate::mprintln!("2. SQL Injection");
    crate::mprintln!("3. NoSQL Injection");
    crate::mprintln!("4. Command Injection");
    crate::mprintln!("5. Path Traversal");
    crate::mprintln!("6. ID/Payload Enumeration");

    let module_selection = cfg_prompt_default("modules", "Selection", "1").await?;
    let mut modules = Vec::new();

    for s in module_selection.split(',') {
        match s.trim() {
            "1" => modules.push(ScanModule::Baseline),
            "2" => modules.push(ScanModule::SQLi),
            "3" => modules.push(ScanModule::NoSQLi),
            "4" => modules.push(ScanModule::CMDi),
            "5" => modules.push(ScanModule::PathTraversal),
            "6" => modules.push(ScanModule::IdEnumeration),
            _ => crate::mprintln!("{}", format!("Invalid module selection: {}", s).yellow()),
        }
    }
    if use_spoofing {
        modules.push(ScanModule::Spoofing);
    }
    modules.dedup();

    if modules.is_empty() {
        return Err(anyhow!("No modules selected!"));
    }

    let concurrency = cfg_prompt_int_range("concurrency", "Concurrency limit", 10, 1, 100).await?
        as usize;
    let timeout_secs =
        cfg_prompt_int_range("timeout", "Timeout (seconds)", 10, 1, 60).await? as u64;

    // Per-category injection payloads.
    let sqli_payloads = if modules.contains(&ScanModule::SQLi) {
        configure_injection_payloads("SQL", SQLI_PAYLOADS).await?
    } else {
        None
    };

    let nosqli_payloads = if modules.contains(&ScanModule::NoSQLi) {
        configure_injection_payloads("NoSQL", NOSQLI_PAYLOADS).await?
    } else {
        None
    };

    let cmdi_payloads = if modules.contains(&ScanModule::CMDi) {
        configure_injection_payloads("Command", CMDI_PAYLOADS).await?
    } else {
        None
    };

    let traversal_payloads = if modules.contains(&ScanModule::PathTraversal) {
        configure_injection_payloads("Path Traversal", TRAVERSAL_PAYLOADS).await?
    } else {
        None
    };

    // ID enumeration configuration.
    let (id_start, id_end, id_file_path) = if modules.contains(&ScanModule::IdEnumeration) {
        crate::mprintln!("\n{}", "Configure ID/Payload Enumeration:".cyan().bold());
        crate::mprintln!("1. Numeric Range (e.g. 1-100)");
        crate::mprintln!("2. File List (e.g. valid_ids.txt)");
        let enum_choice = cfg_prompt_default("enum_mode", "Selection", "1").await?;

        if enum_choice == "2" {
            (
                None,
                None,
                Some(cfg_prompt_existing_file("id_file", "Path to ID/Payload file").await?),
            )
        } else {
            let start =
                cfg_prompt_int_range("id_start", "Start ID", 1, 0, 1_000_000).await? as usize;
            let end = cfg_prompt_int_range("id_end", "End ID", 100, start as i64, 1_000_000).await?
                as usize;
            if start > end {
                return Err(anyhow!("Start ID must be less than or equal to End ID"));
            }
            (Some(start), Some(end), None)
        }
    } else {
        (None, None, None)
    };

    // Payload mutation engine configuration.
    let has_injection = modules.iter().any(|m| {
        matches!(
            m,
            ScanModule::SQLi
                | ScanModule::NoSQLi
                | ScanModule::CMDi
                | ScanModule::PathTraversal
        )
    });
    let mutation_enabled = if has_injection {
        crate::mprintln!("\n{}", "Dynamic Payload Mutation Engine:".cyan().bold());
        cfg_prompt_yes_no(
            "enable_mutations",
            "Enable dynamic payload mutations? (WAF bypass, exhaustive encoding)",
            true,
        )
        .await?
    } else {
        false
    };

    let mutator_config = if mutation_enabled {
        let depth = cfg_prompt_int_range(
            "mutation_depth",
            "Mutation depth (generations of mutations)",
            3,
            1,
            10,
        )
        .await? as usize;
        let max_variants =
            cfg_prompt_int_range("max_variants", "Max variants per seed payload", 15, 1, 50).await?
                as usize;
        let max_total = cfg_prompt_int_range(
            "max_total_payloads",
            "Max total payloads per category",
            500,
            10,
            5_000,
        )
        .await? as usize;
        let traversal_depth = if modules.contains(&ScanModule::PathTraversal) {
            cfg_prompt_int_range(
                "traversal_max_depth",
                "Max traversal directory depth",
                15,
                1,
                30,
            )
            .await? as usize
        } else {
            15
        };
        let exhaustive = cfg_prompt_yes_no(
            "exhaustive_encoding",
            "Exhaustive encoding chains? (tries every combination)",
            true,
        )
        .await?;
        crate::mprintln!(
            "[+] Mutation engine: depth={}, max_variants={}, max_total={}, exhaustive={}",
            depth,
            max_variants,
            max_total,
            exhaustive
        );
        MutatorConfig {
            depth,
            max_variants_per_seed: max_variants,
            max_total,
            traversal_max_depth: traversal_depth,
            exhaustive_encoding: exhaustive,
        }
    } else {
        MutatorConfig::default()
    };

    // Validate and format target base URL.
    let target_base = if target.contains("://") {
        target.trim_end_matches('/').to_string()
    } else {
        format!("https://{}", target.trim_end_matches('/'))
    };

    crate::mprintln!("[*] Using target: {}", target_base.cyan());

    // 2. Endpoint source selection.
    crate::mprintln!("\n{}", "Select Endpoint Source:".cyan().bold());
    crate::mprintln!("1. Load from file (Known endpoints)");
    crate::mprintln!("2. Brute-force/Enumerate (Discover using wordlist)");
    let source_choice = cfg_prompt_default("endpoint_source", "Selection", "1").await?;

    let mut endpoints = if source_choice == "2" {
        let base_path = cfg_prompt_default("base_path", "Base Path (e.g. /api/)", "/").await?;
        let wordlist_path = cfg_prompt_wordlist("wordlist", "Wordlist path").await?;

        let enum_client = crate::utils::build_http_client(std::time::Duration::from_secs(5))?;
        enumerate_endpoints(&enum_client, &target_base, &base_path, &wordlist_path, concurrency)
            .await?
    } else {
        let endpoint_file =
            cfg_prompt_existing_file("endpoint_file", "Path to endpoint list file").await?;
        parse_endpoint_file(&endpoint_file)?
    };

    // Deduplicate endpoints by (key, path).
    endpoints.sort_by(|a, b| a.key.cmp(&b.key).then(a.path.cmp(&b.path)));
    endpoints.dedup_by(|a, b| a.key == b.key && a.path == b.path);

    if endpoints.is_empty() {
        return Err(anyhow!("No valid endpoints found/discovered. Exiting."));
    }
    crate::mprintln!("[*] Processing {} endpoints", endpoints.len().to_string().cyan());

    // 3. Setup HTTP client + output directory.
    let client = crate::utils::build_http_client(std::time::Duration::from_secs(timeout_secs))?;
    tokio::fs::create_dir_all(&output_dir_name).await
        .context("Failed to create output directory")?;
    let abs_output_dir = tokio::fs::canonicalize(&output_dir_name).await?;
    crate::mprintln!(
        "[*] Saving results to: {}",
        abs_output_dir.display().to_string().cyan()
    );

    let config = Arc::new(ScanConfig {
        target_base,
        methods,
        modules,
        use_generic_payload,
        output_dir: output_dir_name,
        sqli_payloads,
        nosqli_payloads,
        cmdi_payloads,
        traversal_payloads,
        id_start,
        id_end,
        id_file_path,
        mutation_enabled,
        mutator_config,
    });
    let client = Arc::new(client);

    // 4. Concurrent scan.
    crate::mprintln!("{}", "\n[*] Starting scan...".cyan().bold());
    let start_time = Instant::now();
    let counter = Arc::new(AtomicUsize::new(0));
    let total = endpoints.len();

    // Shared findings collector — every detection along the scan path pushes
    // into this so results reach loot/export instead of only landing on disk.
    let findings: Arc<tokio::sync::Mutex<Vec<Finding>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let stream = stream::iter(endpoints)
        .map(|endpoint| {
            let config = Arc::clone(&config);
            let client = client.clone();
            let counter = Arc::clone(&counter);
            let findings = Arc::clone(&findings);
            async move {
                let current = counter.fetch_add(1, Ordering::SeqCst) + 1;
                if current.is_multiple_of(10) || current == total {
                    crate::mprint!("\r[*] Progress: {}/{}", current, total);
                    if let Err(e) = std::io::Write::flush(&mut std::io::stdout()) {
                        crate::meprintln!("\n[!] Failed to flush stdout: {}", e);
                    }
                }

                scan_endpoint(&client, &config, endpoint, &findings).await
            }
        })
        .buffer_unordered(concurrency);

    let results: Vec<()> = stream.collect().await;

    crate::mprintln!("\n{}", "\n[+] Scan completed!".green().bold());
    crate::mprintln!("[+] Processed {} endpoints.", results.len());
    crate::mprintln!("Time elapsed: {:.2?}", start_time.elapsed());

    // Move the collected detections into the outcome so they are exported.
    let collected = std::mem::take(&mut *findings.lock().await);
    if !collected.is_empty() {
        crate::mprintln!(
            "{}",
            format!("[+] {} finding(s) recorded.", collected.len()).green().bold()
        );
    }
    let mut outcome = ModuleOutcome::ok();
    outcome.findings = collected;
    Ok(outcome)
}

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "API Endpoint Scanner".to_string(),
        description: "Comprehensive REST API endpoint discovery and vulnerability scanner with \
                      fuzzing, authentication bypass, and injection detection."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
        default_port: None,
    }
}

crate::register_native_module!(crate::module::Category::Scanners, "api_endpoint_scanner", native);

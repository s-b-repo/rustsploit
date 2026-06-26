//! Endpoint discovery for the API scanner.
//!
//! Two strategies live here:
//!   - `parse_endpoint_file` — operator-supplied list of `key path` lines.
//!   - `enumerate_endpoints` — wordlist-driven brute force against a base URL.
//!
//! `configure_injection_payloads` is the interactive helper that builds the
//! per-category payload set (defaults vs custom file) used by the injection
//! scan path.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use colored::*;
use futures::{stream, StreamExt};
use reqwest::Client;

use crate::utils::{cfg_prompt_existing_file, cfg_prompt_yes_no, load_lines_cached};

use super::config::Endpoint;

pub(super) async fn configure_injection_payloads(
    name: &str,
    default_payloads: &[&str],
) -> Result<Option<Vec<String>>> {
    crate::mprintln!(); // spacing
    if !cfg_prompt_yes_no(
        &format!("test_{}", name.to_lowercase()),
        &format!("Test for {} Injection?", name),
        false,
    )
    .await?
    {
        return Ok(None);
    }

    if cfg_prompt_yes_no(
        &format!("default_{}_payloads", name.to_lowercase()),
        &format!("Use default {} payloads?", name),
        true,
    )
    .await?
    {
        return Ok(Some(default_payloads.iter().map(|&s| s.to_string()).collect()));
    }

    let file_path = cfg_prompt_existing_file(
        &format!("{}_payload_file", name.to_lowercase()),
        &format!("Path to custom {} payload file", name),
    )
    .await?;
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let payloads: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

    if payloads.is_empty() {
        return Err(anyhow!("Payload file is empty"));
    }

    Ok(Some(payloads))
}

pub(super) fn parse_endpoint_file(path: &str) -> Result<Vec<Endpoint>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut endpoints = Vec::new();

    for (idx, line_res) in reader.lines().enumerate() {
        let line = line_res?;
        let items: Vec<&str> = line.split_whitespace().collect();

        if items.is_empty() {
            continue;
        }

        if items.len() >= 2 {
            endpoints.push(Endpoint {
                key: items[0].to_string(),
                path: items[1].to_string(),
            });
        } else {
            // Single-column file: synthesise a key from the path.
            let path_str = items[0];
            let key = path_str.replace('/', "_").trim_start_matches('_').to_string();
            endpoints.push(Endpoint {
                key: if key.is_empty() { "root".to_string() } else { key },
                path: path_str.to_string(),
            });
            // (No `else` branch is reachable here — `items.is_empty()` short-
            // circuits the only way `items.len() == 0` would occur; left
            // unreached intentionally rather than introducing an unreachable!()
            // that would be its own clippy lint.)
            if false {
                crate::mprintln!(
                    "{}",
                    format!("[!] Skipping line {} - unknown format: '{}'", idx + 1, line).yellow()
                );
            }
        }
    }
    Ok(endpoints)
}

pub(super) async fn enumerate_endpoints(
    client: &Client,
    target_base: &str,
    base_path: &str,
    wordlist_path: &str,
    concurrency: usize,
) -> Result<Vec<Endpoint>> {
    crate::mprintln!("{}", "\n[*] Starting Endpoint Enumeration...".cyan());

    let lines = load_lines_cached(wordlist_path)?;
    if lines.is_empty() {
        return Err(anyhow!("Wordlist is empty"));
    }
    let total = lines.len();
    crate::mprintln!(
        "[*] Enumerating {} potential endpoints with concurrency {}",
        total,
        concurrency
    );

    let base_url = format!(
        "{}{}",
        target_base.trim_end_matches('/'),
        if base_path.starts_with('/') {
            base_path.to_string()
        } else {
            format!("/{}", base_path)
        }
    );
    let base_url = if base_url.ends_with('/') {
        base_url
    } else {
        format!("{}/", base_url)
    };

    let counter = Arc::new(AtomicUsize::new(0));

    let clean_base_path = if base_path.starts_with('/') {
        base_path.to_string()
    } else {
        format!("/{}", base_path)
    };

    let stream = stream::iter(lines.iter().cloned().collect::<Vec<_>>())
        .map(|word| {
            let client = client.clone();
            let counter = Arc::clone(&counter);
            let base_url = base_url.clone();
            let clean_base_path = clean_base_path.clone();
            async move {
                let current = counter.fetch_add(1, Ordering::SeqCst) + 1;
                if current.is_multiple_of(50) || current == total {
                    crate::mprint!("\r[*] Brute-force Progress: {}/{}", current, total);
                    if let Err(e) = std::io::Write::flush(&mut std::io::stdout()) {
                        tracing::trace!("stdout flush failed: {e}");
                    }
                }

                let url = format!("{}{}", base_url, word);
                match client.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        if status != reqwest::StatusCode::NOT_FOUND {
                            let clean_path = format!("{}{}", clean_base_path, word);
                            let clean_path = clean_path.replace("//", "/");

                            Some(Endpoint {
                                key: word.to_string(),
                                path: clean_path,
                            })
                        } else {
                            None
                        }
                    }
                    Err(e) => { tracing::debug!("request failed: {e}"); None }
                }
            }
        })
        .buffer_unordered(concurrency);

    let results: Vec<Endpoint> = stream.filter_map(|x| async { x }).collect().await;

    crate::mprintln!(); // newline after progress

    if results.is_empty() {
        crate::mprintln!("{}", "[-] No endpoints occurred.".yellow());
    } else {
        crate::mprintln!(
            "{}",
            format!("[+] Discovered {} endpoints!", results.len()).green().bold()
        );
        for ep in &results {
            crate::mprintln!("    - {}", ep.path);
        }
    }

    Ok(results)
}

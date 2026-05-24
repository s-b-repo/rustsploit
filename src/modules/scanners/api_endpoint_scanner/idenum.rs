//! ID/Payload enumeration (IDOR-style sweep) for the API scanner.
//!
//! Locates the last numeric segment of the URL and substitutes each payload
//! in turn. Non-404 responses are logged with timestamp + URL; 2xx bodies
//! are written to `bodies/<payload>.txt` under the endpoint dir for offline
//! inspection.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use reqwest::{Client, Method};

use crate::utils::load_lines;

use super::config::ScanConfig;

pub(super) async fn perform_id_enumeration(
    client: &Client,
    url: &str,
    method: Method,
    dir: &Path,
    config: &ScanConfig,
) {
    let enum_dir = dir.join("enumeration");
    if let Err(e) = tokio::fs::create_dir_all(&enum_dir).await {
        crate::meprintln!("[!] Failed to create enumeration directory: {}", e);
        return;
    }

    let bodies_dir = enum_dir.join("bodies");
    if let Err(e) = tokio::fs::create_dir_all(&bodies_dir).await {
        crate::meprintln!("[!] Failed to create bodies directory: {}", e);
        return;
    }

    let results_file = enum_dir.join("results.txt");
    let mut results_file_handle = match OpenOptions::new().create(true).append(true).open(&results_file) {
        Ok(f) => f,
        Err(e) => {
            crate::meprintln!("[!] Failed to open results file: {}", e);
            return;
        }
    };

    // Strategy: replace the last numeric path segment; if none exists, append.
    let parts: Vec<&str> = url.split('/').collect();
    let mut numeric_index = None;

    for (i, part) in parts.iter().enumerate().rev() {
        if !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()) {
            numeric_index = Some(i);
            break;
        }
    }

    let payloads: Vec<String> = if let Some(path) = &config.id_file_path {
        match load_lines(path) {
            Ok(lines) => lines,
            Err(e) => { tracing::debug!("load lines failed: {e}"); return; }
        }
    } else if let (Some(start), Some(end)) = (config.id_start, config.id_end) {
        (start..=end).map(|i| i.to_string()).collect()
    } else {
        return;
    };

    for payload in payloads {
        let target_url = if let Some(idx) = numeric_index {
            let mut new_parts = parts.clone();
            new_parts[idx] = &payload;
            new_parts.join("/")
        } else {
            let base = if url.ends_with('/') {
                url.to_string()
            } else {
                format!("{}/", url)
            };
            format!("{}{}", base, payload)
        };

        let label = format!("ID-Enum-{}", payload);

        let req_builder = client
            .request(method.clone(), &target_url)
            .header("User-Agent", "Mozilla/5.0 (IDEnum)");

        if let Ok(resp) = req_builder.send().await {
            let status = resp.status();
            if status != reqwest::StatusCode::NOT_FOUND {
                if let Err(e) =
                    run_enum_logging_handle(&mut results_file_handle, &payload, &label, status, &target_url)
                {
                    crate::meprintln!("[!] Logging failed: {}", e);
                }
                crate::events::emit(crate::events::ModuleEvent::ServiceDetected {
                    host: target_url.clone(),
                    port: 0,
                    service: format!("api-endpoint:{}", label),
                    version: Some(format!("status={}", status.as_u16())),
                });

                if status.is_success() {
                    let body_file = bodies_dir.join(format!("{}.txt", payload));
                    let body = match resp.bytes().await {
                        Ok(b) => b,
                        Err(e) => { tracing::debug!("read body failed: {e}"); bytes::Bytes::new() }
                    };
                    if let Ok(mut f) = File::create(&body_file) {
                        if let Err(e) = crate::utils::set_secure_permissions(&body_file, 0o600) {
                            crate::meprintln!(
                                "[!] Failed to chmod 0o600 on {}: {} — file may be world-readable",
                                body_file.display(),
                                e
                            );
                        }
                        if let Err(e) = f.write_all(&body) {
                            crate::meprintln!("[!] Failed to write body: {}", e);
                        }
                    }
                }
            }
        }
    }
}

fn run_enum_logging_handle(
    file: &mut File,
    payload: &str,
    label: &str,
    status: reqwest::StatusCode,
    url: &str,
) -> std::io::Result<()> {
    writeln!(
        file,
        "[{}] [{}] ID: {} - Status: {} - URL: {}",
        chrono::Local::now().format("%H:%M:%S"),
        label,
        payload,
        status,
        url
    )?;
    Ok(())
}

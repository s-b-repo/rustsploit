//! Per-endpoint scan orchestration.
//!
//! `scan_endpoint` is the per-(host, method, module) entry point. It
//! creates a per-endpoint output dir and dispatches into:
//!   - `scan_method` for baseline standard requests
//!   - `scan_spoofing` for IP / origin spoof headers
//!   - `perform_injection` for SQLi/NoSQLi/CMDi/Traversal
//!   - `super::idenum::perform_id_enumeration` for IDOR-style id sweeps

use std::fs;
use std::path::Path;
use std::sync::Arc;

use colored::*;
use reqwest::{Client, Method};
use serde_json::json;

use crate::module::Finding;
use crate::native::payload_engine::{self as payload_mutator, PayloadCategory};

/// Shared collector threaded through the scan path so detections reach the
/// `ModuleOutcome` instead of only the on-disk result files.
pub(super) type FindingSink = Arc<tokio::sync::Mutex<Vec<Finding>>>;

use super::config::{Endpoint, ScanConfig, ScanModule, SPOOF_HEADERS};
use super::idenum::perform_id_enumeration;
use super::request::RequestSpec;
use super::request::perform_request;

/// Expand seed payloads with dynamic mutations if enabled.
fn expand_with_mutations(
    seeds: &[String],
    category: PayloadCategory,
    config: &ScanConfig,
) -> Vec<String> {
    if !config.mutation_enabled {
        return seeds.to_vec();
    }
    let mutated = payload_mutator::mutate_payloads(seeds, category, &config.mutator_config);
    crate::mprintln!(
        "  [~] {} seeds → {} payloads ({:?}, depth={})",
        seeds.len(),
        mutated.len(),
        category,
        config.mutator_config.depth
    );
    mutated
}

pub(super) async fn scan_endpoint(
    client: &Client,
    config: &ScanConfig,
    endpoint: Endpoint,
    findings: &FindingSink,
) {
    // Per-endpoint output dir keyed on `<sanitized_key>_<path_hash>` so two
    // endpoints that sanitize to the same name still get separate directories.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    endpoint.path.hash(&mut hasher);
    let path_hash = hasher.finish();

    let sanitized_key = format!(
        "{}_{:x}",
        endpoint
            .key
            .replace(|c: char| !c.is_alphanumeric() && c != '_', "_"),
        path_hash
    );
    let endpoint_dir = Path::new(&config.output_dir).join(&sanitized_key);

    if let Err(e) = fs::create_dir_all(&endpoint_dir) {
        crate::meprintln!(
            "\n{}",
            format!("[!] Failed to create dir for {}: {}", endpoint.key, e).red()
        );
        return;
    }

    let url = format!("{}{}", config.target_base, endpoint.path);

    for method in &config.methods {
        let method_str = method.as_str().to_string();

        for module in &config.modules {
            match module {
                ScanModule::Baseline => {
                    scan_method(
                        client, &url, method.clone(), &endpoint_dir, &method_str, config, findings,
                    )
                    .await;
                }
                ScanModule::Spoofing => {
                    scan_spoofing(
                        client,
                        &url,
                        method.clone(),
                        &endpoint_dir,
                        &method_str,
                        config,
                        findings,
                    )
                    .await;
                }
                ScanModule::SQLi => {
                    if let Some(payloads) = &config.sqli_payloads {
                        let effective = expand_with_mutations(payloads, PayloadCategory::SQLi, config);
                        for payload in &effective {
                            perform_injection(
                                client,
                                &url,
                                method.clone(),
                                "SQLi",
                                payload,
                                &endpoint_dir,
                                config,
                                findings,
                            )
                            .await;
                        }
                    }
                }
                ScanModule::NoSQLi => {
                    if let Some(payloads) = &config.nosqli_payloads {
                        let effective =
                            expand_with_mutations(payloads, PayloadCategory::NoSQLi, config);
                        for payload in &effective {
                            perform_injection(
                                client,
                                &url,
                                method.clone(),
                                "NoSQLi",
                                payload,
                                &endpoint_dir,
                                config,
                                findings,
                            )
                            .await;
                        }
                    }
                }
                ScanModule::CMDi => {
                    if let Some(payloads) = &config.cmdi_payloads {
                        let effective = expand_with_mutations(payloads, PayloadCategory::CMDi, config);
                        for payload in &effective {
                            perform_injection(
                                client,
                                &url,
                                method.clone(),
                                "CMDi",
                                payload,
                                &endpoint_dir,
                                config,
                                findings,
                            )
                            .await;
                        }
                    }
                }
                ScanModule::PathTraversal => {
                    if let Some(payloads) = &config.traversal_payloads {
                        let effective =
                            expand_with_mutations(payloads, PayloadCategory::Traversal, config);
                        for payload in &effective {
                            perform_injection(
                                client,
                                &url,
                                method.clone(),
                                "Traversal",
                                payload,
                                &endpoint_dir,
                                config,
                                findings,
                            )
                            .await;
                        }
                    }
                }
                ScanModule::IdEnumeration => {
                    perform_id_enumeration(
                        client, &url, method.clone(), &endpoint_dir, config, findings,
                    )
                    .await;
                }
            }
        }
    }
}

async fn scan_method(
    client: &Client,
    url: &str,
    method: Method,
    dir: &Path,
    method_name: &str,
    config: &ScanConfig,
    findings: &FindingSink,
) {
    let result_file = dir.join("results.txt");
    perform_request(&RequestSpec {
        client,
        url,
        method: method.clone(),
        result_file: &result_file,
        method_name,
        valid_label: "Standard",
        header: None,
        custom_json: None,
        config,
        injection_type: None,
        findings,
    })
    .await;
}

async fn scan_spoofing(
    client: &Client,
    url: &str,
    method: Method,
    dir: &Path,
    method_name: &str,
    config: &ScanConfig,
    findings: &FindingSink,
) {
    let result_file = dir.join("results.txt");
    for &header in SPOOF_HEADERS {
        let value = if header == "X-Forwarded-Host" {
            "localhost"
        } else {
            "127.0.0.1"
        };
        perform_request(&RequestSpec {
            client,
            url,
            method: method.clone(),
            result_file: &result_file,
            method_name,
            valid_label: &format!("Spoof-{}", header),
            header: Some((header, value)),
            custom_json: None,
            config,
            injection_type: None,
            findings,
        })
        .await;
    }
}

async fn perform_injection(
    client: &Client,
    url: &str,
    method: Method,
    type_name: &str,
    payload: &str,
    dir: &Path,
    config: &ScanConfig,
    findings: &FindingSink,
) {
    let result_file = dir.join("injection_results.txt");

    // 1. URL injection — applies to every method.
    let injected_url = if url.contains('?') {
        format!("{}&test={}", url, payload)
    } else {
        format!("{}?test={}", url, payload)
    };

    perform_request(&RequestSpec {
        client,
        url: &injected_url,
        method: method.clone(),
        result_file: &result_file,
        method_name: type_name,
        valid_label: &format!("{}-URL-{}", method.as_str(), payload),
        header: None,
        custom_json: None,
        config,
        injection_type: Some(type_name),
        findings,
    })
    .await;

    // 2. Body injection — only methods that typically carry a body.
    match method {
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE => {
            let json_payload = json!({
                "name": payload,
                "description": payload,
                "test": true,
                "id": payload,
                "query": payload,
            });

            perform_request(&RequestSpec {
                client,
                url,
                method,
                result_file: &result_file,
                method_name: type_name,
                valid_label: &format!("Body-{}", payload),
                header: None,
                custom_json: Some(json_payload),
                config,
                injection_type: Some(type_name),
                findings,
            })
            .await;
        }
        _ => {}
    }
}

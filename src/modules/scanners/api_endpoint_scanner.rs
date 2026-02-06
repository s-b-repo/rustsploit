use anyhow::{anyhow, Context, Result};
use colored::*;
use futures::{stream, StreamExt};
use rand::seq::IndexedRandom;
use reqwest::{Client, Method, Response};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::utils::{prompt_existing_file, prompt_int_range, prompt_default, prompt_yes_no, prompt_wordlist, load_lines};
use serde_json::json;

// =========================================================================
//                              CONSTANTS
// =========================================================================

const CHROME_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
];

const SPOOF_HEADERS: &[&str] = &[
    "X-Forwarded-For", "X-Forwarded-Host", "X-Client-IP", "X-Remote-IP", "X-Remote-Addr",
    "X-Host", "X-Originating-IP", "Client-IP", "True-Client-IP", "Cluster-Client-IP",
    "X-ProxyUser-Ip", "Via", "X-Real-IP", "Forwarded", "X-Custom-IP-Authorization",
    "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Forwarded-Port"
];

const SQLI_PAYLOADS: &[&str] = &[
    "'", "\"", "OR 1=1", "' OR '1'='1", "\" OR \"1\"=\"1",
    "1' ORDER BY 1--+", "1' UNION SELECT 1,2,3--+",
    "admin' --", "admin' #", "' OR 1=1--",
];

const NOSQLI_PAYLOADS: &[&str] = &[
    "{$ne: null}", "{$gt: \"\"}", "{$where: \"return true\"}",
    "|| return true;", "'; return true; var foo='",
];

const CMDI_PAYLOADS: &[&str] = &[
    "; id", "| id", "`id`", "$(id)",
    "; cat /etc/passwd", "| cat /etc/passwd",
    "& ping -c 1 127.0.0.1",
];
const TRAVERSAL_PAYLOADS: &[&str] = &[
    "../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "../../windows/win.ini",
];

// =========================================================================
//                            DATA STRUCTURES
// =========================================================================

#[derive(Clone, Copy, PartialEq, Debug)]
enum ScanModule {
    Baseline,
    Spoofing,
    SQLi,
    NoSQLi,
    CMDi,
    PathTraversal,
    IdEnumeration,
}

struct ScanConfig {
    target_base: String,
    methods: Vec<Method>,
    modules: Vec<ScanModule>,
    use_generic_payload: bool,
    output_dir: String,
    sqli_payloads: Option<Vec<String>>,
    nosqli_payloads: Option<Vec<String>>,
    cmdi_payloads: Option<Vec<String>>,
    traversal_payloads: Option<Vec<String>>,
    // ID Enumeration Config
    id_start: Option<usize>,
    id_end: Option<usize>,
    id_file_path: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct Endpoint {
    key: String,
    path: String,
}

#[derive(serde::Serialize)]
struct GenericPayload {
    name: String,
    description: String,
    test: bool,
}

// =========================================================================
//                            MAIN ENTRY POINT
// =========================================================================

pub async fn run(target: &str) -> Result<()> {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   API Endpoint Pentest Module                             ║".cyan());
    println!("{}", "║   Tests API endpoints for common issues                   ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();

    // 1. Input parsing & Configuration
    let output_dir_name = prompt_default("Output directory name", "api_scan_results")?;
    let use_spoofing = prompt_yes_no("Enable IP Spoofing/Bypass headers logic? (Applies to all selected modules)", false)?;
    let use_generic_payload = prompt_yes_no("Send generic JSON payload with POST/PUT/PATCH? (Better for API compatibility)", true)?;
    
    // Method Selection
    let mut methods = vec![Method::GET, Method::POST];
    if prompt_yes_no("Enable DELETE method? (WARNING: Destructive)", false)? {
        methods.push(Method::DELETE);
    }
    if prompt_yes_no("Enable Extended HTTP methods (PUT, PATCH, HEAD, OPTIONS, CONNECT, TRACE, DEBUG)?", false)? {
        methods.extend(vec![
            Method::PUT, Method::PATCH, Method::HEAD, Method::OPTIONS, Method::CONNECT, Method::TRACE, 
            Method::PUT, Method::PATCH, Method::HEAD, Method::OPTIONS, Method::CONNECT, Method::TRACE, 
            match Method::from_bytes(b"DEBUG") { Ok(m) => m, Err(_) => Method::GET }, // Method parsing is generally safe for ASCII
        ]);
    }

    println!("1. Baseline (Standard Requests)");
    println!("2. SQL Injection");
    println!("3. NoSQL Injection");
    println!("4. Command Injection");
    println!("5. Path Traversal");
    println!("6. ID/Payload Enumeration");
    
    let module_selection = prompt_default("Selection", "1")?;
    let mut modules = Vec::new();
    
    for s in module_selection.split(',') {
        match s.trim() {
            "1" => modules.push(ScanModule::Baseline),
            "2" => modules.push(ScanModule::SQLi),
            "3" => modules.push(ScanModule::NoSQLi),
            "4" => modules.push(ScanModule::CMDi),
            "5" => modules.push(ScanModule::PathTraversal),
            "6" => modules.push(ScanModule::IdEnumeration),
            _ => println!("{}", format!("Invalid module selection: {}", s).yellow()),
        }
    }
    if use_spoofing {
        modules.push(ScanModule::Spoofing);
    }
    modules.dedup(); // Remove duplicates if any
    
    if modules.is_empty() {
        return Err(anyhow!("No modules selected!"));
    }

    let concurrency = prompt_int_range("Concurrency limit", 10, 1, 100)? as usize;
    
    // Bug 10: Configurable timeout
    let timeout_secs = prompt_int_range("Timeout (seconds)", 10, 1, 60)? as u64;

    // Injection Attacks Configuration
    let sqli_payloads = if modules.contains(&ScanModule::SQLi) {
        configure_injection_payloads("SQL", SQLI_PAYLOADS)?
    } else { None };

    let nosqli_payloads = if modules.contains(&ScanModule::NoSQLi) {
        configure_injection_payloads("NoSQL", NOSQLI_PAYLOADS)?
    } else { None };

    let cmdi_payloads = if modules.contains(&ScanModule::CMDi) {
        configure_injection_payloads("Command", CMDI_PAYLOADS)?
    } else { None };

    let traversal_payloads = if modules.contains(&ScanModule::PathTraversal) {
        configure_injection_payloads("Path Traversal", TRAVERSAL_PAYLOADS)?
    } else { None };

    // ID Enumeration Configuration
    let (id_start, id_end, id_file_path) = if modules.contains(&ScanModule::IdEnumeration) {
        println!("\n{}", "Configure ID/Payload Enumeration:".cyan().bold());
        println!("1. Numeric Range (e.g. 1-100)");
        println!("2. File List (e.g. valid_ids.txt)");
        let enum_choice = prompt_default("Selection", "1")?;
        
        if enum_choice == "2" {
            (None, None, Some(prompt_existing_file("Path to ID/Payload file")?))
        } else {
             let start = prompt_int_range("Start ID", 1, 0, 1000000)? as usize;
             let end = prompt_int_range("End ID", 100, start as i64, 1000000)? as usize;
             if start > end {
                 return Err(anyhow!("Start ID must be less than or equal to End ID"));
             }
             (Some(start), Some(end), None)
        }
    } else {
        (None, None, None)
    };

    // Validate and format target base URL
    let target_base = if target.contains("://") {
        target.trim_end_matches('/').to_string()
    } else {
        format!("https://{}", target.trim_end_matches('/'))
    };

    println!("[*] Using target: {}", target_base.cyan());

    // 2. Endpoint Source Selection
    println!("\n{}", "Select Endpoint Source:".cyan().bold());
    println!("1. Load from file (Known endpoints)");
    println!("2. Brute-force/Enumerate (Discover using wordlist)");
    let source_choice = prompt_default("Selection", "1")?;

    let mut endpoints = if source_choice == "2" {
        // Enumerate
        let base_path = prompt_default("Base Path (e.g. /api/)", "/")?;
        let wordlist_path = prompt_wordlist("Wordlist path")?;
        
        // Setup simple client for enumeration
        let enum_client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(5))
            .build()?;
            
        enumerate_endpoints(&enum_client, &target_base, &base_path, &wordlist_path, concurrency).await?
    } else {
        // Load from file
        let endpoint_file = prompt_existing_file("Path to endpoint list file")?;
        parse_endpoint_file(&endpoint_file)?
    };
    
    // Deduplicate endpoints based on key and path to avoid redundant work and file collisions
    endpoints.sort_by(|a, b| a.key.cmp(&b.key).then(a.path.cmp(&b.path)));
    endpoints.dedup_by(|a, b| a.key == b.key && a.path == b.path);

    if endpoints.is_empty() {
        return Err(anyhow!("No valid endpoints found/discovered. Exiting."));
    }
    println!("[*] Processing {} endpoints", endpoints.len().to_string().cyan());

    // 3. Setup Client
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
        .context("Failed to build HTTP client")?;

    // 4. Create Output Directory
    fs::create_dir_all(&output_dir_name).context("Failed to create output directory")?;
    // Get absolute path for logging
    let abs_output_dir = fs::canonicalize(&output_dir_name)?;
    println!("[*] Saving results to: {}", abs_output_dir.display().to_string().cyan());

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
    });
    let client = Arc::new(client);

    // 5. Run Concurrent Scan
    println!("{}", "\n[*] Starting scan...".cyan().bold());
    let start_time = Instant::now();
    let counter = Arc::new(AtomicUsize::new(0));
    let total = endpoints.len();

    let stream = stream::iter(endpoints)
        .map(|endpoint| {
            let config = Arc::clone(&config);
            let client = client.clone();
            let counter = Arc::clone(&counter);
            async move {
                let current = counter.fetch_add(1, Ordering::SeqCst) + 1;
                // Print progress occasionally
                if current % 10 == 0 || current == total {
                    print!("\r[*] Progress: {}/{}", current, total);
                    if let Err(e) = std::io::stdout().flush() {
                        eprintln!("\n[!] Failed to flush stdout: {}", e);
                    }
                }
                
                scan_endpoint(&client, &config, endpoint).await
            }
        })
        .buffer_unordered(concurrency);

    // Collect all results
    let results: Vec<()> = stream.collect().await;

    println!("\n{}", "\n[+] Scan completed!".green().bold());
    println!("[+] Processed {} endpoints.", results.len());
    println!("Time elapsed: {:.2?}", start_time.elapsed());
    Ok(())
}

// =========================================================================
//                             SETUP HELPERS
// =========================================================================

fn configure_injection_payloads(name: &str, default_payloads: &[&str]) -> Result<Option<Vec<String>>> {
    println!(); // Add spacing
    if !prompt_yes_no(&format!("Test for {} Injection?", name), false)? {
        return Ok(None);
    }

    if prompt_yes_no(&format!("Use default {} payloads?", name), true)? {
        return Ok(Some(default_payloads.iter().map(|&s| s.to_string()).collect()));
    }

    let file_path = prompt_existing_file(&format!("Path to custom {} payload file", name))?;
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let payloads: Vec<String> = reader.lines()
        .collect::<Result<_, _>>()?;
    
    if payloads.is_empty() {
        return Err(anyhow!("Payload file is empty"));
    }

    Ok(Some(payloads))
}

fn parse_endpoint_file(path: &str) -> Result<Vec<Endpoint>> {
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
        } else if items.len() == 1 {
            // Fallback for files with just paths
            // Use path as key (sanitized)
            let path_str = items[0];
            let key = path_str.replace('/', "_").trim_start_matches('_').to_string();
            endpoints.push(Endpoint {
                key: if key.is_empty() { "root".to_string() } else { key },
                path: path_str.to_string(),
            });
        } else {
             // Should not happen due to is_empty check, but good to report if logic changes
             println!("{}", format!("[!] Skipping line {} - unknown format: '{}'", idx + 1, line).yellow());
        }
    }
    Ok(endpoints)
}

async fn enumerate_endpoints(client: &Client, target_base: &str, base_path: &str, wordlist_path: &str, concurrency: usize) -> Result<Vec<Endpoint>> {
    println!("{}", "\n[*] Starting Endpoint Enumeration...".cyan());
    
    let lines = load_lines(wordlist_path)?;
    if lines.is_empty() {
        return Err(anyhow!("Wordlist is empty"));
    }
    let total = lines.len();
    println!("[*] Enumerating {} potential endpoints with concurrency {}", total, concurrency);
    
    let base_url = format!("{}{}", 
        target_base.trim_end_matches('/'), 
        if base_path.starts_with('/') { base_path.to_string() } else { format!("/{}", base_path) }
    );
    // Ensure base_url ends with / for appending words
    let base_url = if base_url.ends_with('/') { base_url } else { format!("{}/", base_url) };

    let counter = Arc::new(AtomicUsize::new(0));

    // Bug 6: Calculate base path prefix once outside loop
    let clean_base_path = if base_path.starts_with('/') { base_path.to_string() } else { format!("/{}", base_path) };

    // Use a stream that returns Option<Endpoint> instead of locking a shared Vec
    let stream = stream::iter(lines)
        .map(|word| {
            let client = client.clone();
            let counter = Arc::clone(&counter);
            let base_url = base_url.clone();
            let clean_base_path = clean_base_path.clone();
            async move {
                let current = counter.fetch_add(1, Ordering::SeqCst) + 1;
                 if current % 50 == 0 || current == total {
                    print!("\r[*] Brute-force Progress: {}/{}", current, total);
                if let Err(_e) = std::io::stdout().flush() {
                    // Ignore flush errors in tough loops
                }
                }

                let url = format!("{}{}", base_url, word);
                match client.get(&url).send().await {
                    Ok(resp) => {
                         let status = resp.status();
                         // Consider valid if not 404
                        if status != reqwest::StatusCode::NOT_FOUND {
                             // Recalculate clean path efficiently
                             let clean_path = format!("{}{}", clean_base_path, word);
                             // Ensure no double slashes (Bug 5 fix: check logic)
                             let clean_path = clean_path.replace("//", "/");

                            Some(Endpoint {
                                key: word.to_string(),
                                path: clean_path,
                            })
                        } else {
                            None
                        }
                    },
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(concurrency);

    // Collect all results and filter out Nones
    let results: Vec<Endpoint> = stream
        .filter_map(|x| async { x })
        .collect()
        .await;

    println!(); // Newline after progress

    if results.is_empty() {
        println!("{}", "[-] No endpoints occurred.".yellow());
    } else {
        println!("{}", format!("[+] Discovered {} endpoints!", results.len()).green().bold());
        for ep in &results {
            println!("    - {}", ep.path);
        }
    }
    
    Ok(results)
}

// =========================================================================
//                            SCAN LOGIC
// =========================================================================

async fn scan_endpoint(client: &Client, config: &ScanConfig, endpoint: Endpoint) {
    // Create directory for this endpoint
    // Bug 9: Fix collision by appending a short hash of path
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    endpoint.path.hash(&mut hasher);
    let path_hash = hasher.finish();
    
    let sanitized_key = format!("{}_{:x}", 
        endpoint.key.replace(|c: char| !c.is_alphanumeric() && c != '_', "_"),
        path_hash
    );
    let endpoint_dir = Path::new(&config.output_dir).join(&sanitized_key);
    
    if let Err(e) = fs::create_dir_all(&endpoint_dir) {
        eprintln!("\n{}", format!("[!] Failed to create dir for {}: {}", endpoint.key, e).red());
        return;
    }

    let url = format!("{}{}", config.target_base, endpoint.path);

    // Iterate through all selected methods
    for method in &config.methods {
        let method_str = method.as_str().to_string();
        
        // Iterate through all selected modules
        for module in &config.modules {
            match module {
                ScanModule::Baseline => {
                     // Standard Request
                     scan_method(client, &url, method.clone(), &endpoint_dir, &method_str, config).await;
                },
                ScanModule::Spoofing => {
                     scan_spoofing(client, &url, method.clone(), &endpoint_dir, &method_str, config).await;
                },
                ScanModule::SQLi => {
                    if let Some(payloads) = &config.sqli_payloads {
                        for payload in payloads {
                             perform_injection(client, &url, method.clone(), "SQLi", payload, &endpoint_dir, config).await;
                        }
                    }
                },
                ScanModule::NoSQLi => {
                    if let Some(payloads) = &config.nosqli_payloads {
                        for payload in payloads {
                             perform_injection(client, &url, method.clone(), "NoSQLi", payload, &endpoint_dir, config).await;
                        }
                    }
                },
                ScanModule::CMDi => {
                    if let Some(payloads) = &config.cmdi_payloads {
                        for payload in payloads {
                             perform_injection(client, &url, method.clone(), "CMDi", payload, &endpoint_dir, config).await;
                        }
                    }
                },
                ScanModule::PathTraversal => {
                    if let Some(payloads) = &config.traversal_payloads {
                        for payload in payloads {
                             perform_injection(client, &url, method.clone(), "Traversal", payload, &endpoint_dir, config).await;
                        }
                    }
                },
                ScanModule::IdEnumeration => {
                    perform_id_enumeration(client, &url, method.clone(), &endpoint_dir, config).await;
                }
            }
        }
    }
}

async fn perform_id_enumeration(client: &Client, url: &str, method: Method, dir: &Path, config: &ScanConfig) {
    let enum_dir = dir.join("enumeration");
    if let Err(e) = fs::create_dir_all(&enum_dir) {
        eprintln!("[!] Failed to create enumeration directory: {}", e);
        return;
    }
    
    let bodies_dir = enum_dir.join("bodies");
    if let Err(e) = fs::create_dir_all(&bodies_dir) {
        eprintln!("[!] Failed to create bodies directory: {}", e);
        return;
    }

    let results_file = enum_dir.join("results.txt");
    // Open file once to prevent resource exhaustion in loop
    let mut results_file_handle = match OpenOptions::new().create(true).append(true).open(&results_file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[!] Failed to open results file: {}", e);
            return;
        }
    };

    // Determine injection point
    // Strategy: Look for the last numeric segment. If found, replace it.
    // If NOT found, append to the end.
    let parts: Vec<&str> = url.split('/').collect();
    let mut numeric_index = None;
    
    for (i, part) in parts.iter().enumerate().rev() {
        if part.chars().all(|c| c.is_digit(10)) && !part.is_empty() {
            numeric_index = Some(i);
            break;
        }
    }

    // Prepare iterator
     let payloads: Vec<String> = if let Some(path) = &config.id_file_path {
        if let Ok(lines) = load_lines(path) {
            lines
        } else {
            return;
        }
    } else if let (Some(start), Some(end)) = (config.id_start, config.id_end) {
        (start..=end).map(|i| i.to_string()).collect()
    } else {
        return;
    };

    for payload in payloads {
        let target_url = if let Some(idx) = numeric_index {
            // Replace existing number
            let mut new_parts = parts.clone();
            new_parts[idx] = &payload;
            new_parts.join("/")
        } else {
            // Append
            let base = if url.ends_with('/') { url.to_string() } else { format!("{}/", url) };
            format!("{}{}", base, payload)
        };
        
        // Label for connection reuse/logging
        let label = format!("ID-Enum-{}", payload);
        
        // Execute Request logic manually here to handle specific saving logic
        // Or reuse perform_request but we want to save bodies specifically
        
         let req_builder = client.request(method.clone(), &target_url)
            .header("User-Agent", "Mozilla/5.0 (IDEnum)");

         match req_builder.send().await {
             Ok(resp) => {
                 let status = resp.status();
                 if status != reqwest::StatusCode::NOT_FOUND {
                      // Log hit
                      // Log hit with shared handle
                      // Log hit with shared handle
                      if let Err(e) = run_enum_logging_handle(&mut results_file_handle, &payload, &label, status, &target_url) {
                          eprintln!("[!] Logging failed: {}", e);
                      }
                      
                      // If 200, save body
                       if status.is_success() {
                            let body_file = bodies_dir.join(format!("{}.txt", payload));
                            let body = match resp.bytes().await {
                                Ok(b) => b,
                                Err(_) => bytes::Bytes::new(),
                            };
                            if let Ok(mut f) = File::create(body_file) {
                                if let Err(e) = f.write_all(&body) {
                                    eprintln!("[!] Failed to write body: {}", e);
                                }
                            }
                       }
                 }
             },
             _ => {}
         }
    }
}

fn run_enum_logging_handle(file: &mut File, payload: &str, label: &str, status: reqwest::StatusCode, url: &str) -> std::io::Result<()> {
    writeln!(file, "[{}] [{}] ID: {} - Status: {} - URL: {}", chrono::Local::now().format("%H:%M:%S"), label, payload, status, url)?;
    Ok(())
}

async fn scan_method(client: &Client, url: &str, method: Method, dir: &Path, method_name: &str, config: &ScanConfig) {
    let result_file = dir.join("results.txt");
    // Standard Request Only (Spoofing separated)
    perform_request(client, url, method.clone(), &result_file, method_name, "Standard", None, None, config).await;
}

async fn scan_spoofing(client: &Client, url: &str, method: Method, dir: &Path, method_name: &str, config: &ScanConfig) {
    let result_file = dir.join("results.txt");
    for &header in SPOOF_HEADERS {
         let value = if header == "X-Forwarded-Host" { "localhost" } else { "127.0.0.1" };
         perform_request(client, url, method.clone(), &result_file, method_name, &format!("Spoof-{}", header), Some((header, value)), None, config).await;
    }
}

async fn perform_injection(client: &Client, url: &str, method: Method, type_name: &str, payload: &str, dir: &Path, config: &ScanConfig) {
     let result_file = dir.join("injection_results.txt");
     
     // 1. URL Injection (Applies to ALL methods)
     // Construct URL with payload
     // Bug 16: Fix parameter injection logic
     let injected_url = if url.contains('?') {
         format!("{}&test={}", url, payload)
     } else {
         format!("{}?test={}", url, payload)
     };
     
     perform_request(client, &injected_url, method.clone(), &result_file, type_name, &format!("{}-URL-{}", method.as_str(), payload), None, None, config).await;

     // 2. Body Injection (Only for methods that typically support body)
     // POST, PUT, PATCH, DELETE 
     match method {
         Method::POST | Method::PUT | Method::PATCH | Method::DELETE => {
             // Construct malicious JSON
             let json_payload = json!({
                "name": payload,
                "description": payload,
                "test": true,
                "id": payload,
                "query": payload
             });

             perform_request(client, url, method, &result_file, type_name, &format!("Body-{}", payload), None, Some(json_payload), config).await;
         },
         _ => {}
     }
}

// =========================================================================
//                            REQUEST EXECUTION
// =========================================================================

async fn perform_request(client: &Client, url: &str, method: Method, result_file: &Path, method_name: &str, valid_label: &str, header: Option<(&str, &str)>, custom_json: Option<serde_json::Value>, config: &ScanConfig) {
    let user_agent = match CHROME_USER_AGENTS.choose(&mut rand::rng()) {
        Some(ua) => *ua,
        None => "Mozilla/5.0",
    };

    let mut req_builder = client.request(method.clone(), url)
        .header("User-Agent", user_agent);

    if let Some((k, v)) = header {
        req_builder = req_builder.header(k, v);
    }
    
    // Add payload
    if let Some(json) = custom_json {
        req_builder = req_builder.json(&json);
    } else if config.use_generic_payload && (method == Method::POST || method == Method::PUT) {
         req_builder = req_builder.json(&GenericPayload {
            name: "test_api_scanner".to_string(),
            description: "Automated scan".to_string(),
            test: true,
         });
    }
    
    // Full method label for logging
    let full_label = format!("{} [{}]", method_name, valid_label);

    match req_builder.send().await {
        Ok(resp) => {
            if let Err(e) = log_response(resp, result_file, &full_label, url, user_agent).await {
                eprintln!("\n{}", format!("[!] Failed to log response for {}: {}", full_label, e).red());
            }
        },
        Err(e) => {
             // Log error to file
             if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(result_file) {
                 if let Err(write_err) = writeln!(file, "=== {} {} ===\nError: {}\n", full_label, url, e) {
                     eprintln!("[!] Failed to write error log: {}", write_err);
                 }
             }
        }
    }
}

async fn log_response(resp: Response, path: &Path, method: &str, url: &str, user_agent: &str) -> Result<()> {
    let status = resp.status();
    let headers = resp.headers().clone();
    
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    // Safety: Limit body read to 1MB to prevent OOM
    // Bug 11: Check Content-Length first
    if let Some(cl) = headers.get("content-length") {
        if let Ok(s) = cl.to_str() {
            if let Ok(len) = s.parse::<usize>() {
                if len > 5_000_000 {
                     writeln!(file, "Body skipped (Content-Length: {} > 5MB)", len)?;
                     return Ok(());
                }
            }
        }
    }

    // Streaming check or limited read
    let body_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
             // Don't fail the whole log just for body read error
             writeln!(file, "Failed to read body: {}", e)?;
             return Ok(());
        }
    };
    let body_len = body_bytes.len();
    let max_len = 1_000_000;
    let truncated = body_len > max_len;
    let body = if truncated {
        &body_bytes[..max_len]
    } else {
        &body_bytes[..]
    };
    

    writeln!(file, "=======================================================")?;
    writeln!(file, "Timestamp: {}", chrono::Local::now().to_rfc3339())?;
    writeln!(file, "Request: {} {}", method, url)?;
    writeln!(file, "User-Agent: {}", user_agent)?;
    writeln!(file, "-------------------------------------------------------")?;
    writeln!(file, "Status: {}", status)?;
    writeln!(file, "Headers:")?;

    for (k, v) in headers.iter() {
        writeln!(file, "  {}: {:?}", k, v)?;
    }
    writeln!(file, "Body Length: {} bytes", body.len())?;
    writeln!(file, "-------------------------------------------------------")?;
    
    // Try to convert body to string for log, if utf8
    if let Ok(body_str) = String::from_utf8(body.to_vec()) {
        writeln!(file, "Body Preview{}:\n{}", if truncated { " (TRUNCATED)" } else { "" }, body_str)?;
    } else {
        writeln!(file, "Body is binary or non-UTF8")?;
    }
    writeln!(file, "=======================================================\n")?;

    Ok(())
}

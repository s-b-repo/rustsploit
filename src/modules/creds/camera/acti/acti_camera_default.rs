use anyhow::{Context, Result};
use suppaftp::tokio::AsyncFtpStream;
use colored::*;
use ssh2::Session;
use telnet::{Telnet, Event};
use std::time::Duration;
use tokio::{join, task};
use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::utils::url_encode;

const DEFAULT_TIMEOUT_SECS: u64 = 10;

fn display_banner() {
    if crate::utils::is_batch_mode() { return; }
    crate::mprintln!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║   ACTi Camera Default Credentials Checker                 ║".cyan());
    crate::mprintln!("{}", "║   Multi-Protocol Scanner (FTP/SSH/Telnet/HTTP)            ║".cyan());
    crate::mprintln!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
}

/// Supported Acti services
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceType {
    Ftp,
    Ssh,
    Telnet,
    Http,
}

impl ServiceType {
    fn as_str(&self) -> &'static str {
        match self {
            ServiceType::Ftp => "FTP",
            ServiceType::Ssh => "SSH",
            ServiceType::Telnet => "Telnet",
            ServiceType::Http => "HTTP",
        }
    }
}

/// Common config
#[derive(Clone)]
pub struct Config {
    pub target: String,
    pub port: u16,
    pub credentials: Vec<(&'static str, &'static str)>,
    pub stop_on_success: bool,
    pub verbosity: bool,
}

/// Helper to normalize IPv4, IPv6 (with any amount of brackets)
fn normalize_target(target: &str, port: u16) -> String {
    let cleaned = target.trim_matches(|c| c == '[' || c == ']');
    if cleaned.contains(':') && !cleaned.contains('.') {
        format!("[{}]:{}", cleaned, port) // IPv6
    } else {
        format!("{}:{}", cleaned, port) // IPv4 or hostname
    }
}

/// FTP check (async)
pub async fn check_ftp(config: &Config) -> Result<Option<(ServiceType, String, String)>> {
    crate::mprintln!("{}", format!("[*] Checking FTP credentials on {}:{}", config.target, config.port).cyan());

    for (username, password) in &config.credentials {
        if config.verbosity {
            crate::mprintln!("{}", format!("[*] Trying FTP: {}:{}", username, password).dimmed());
        }

        let address = normalize_target(&config.target, config.port);
        let tcp_stream = match crate::utils::network::tcp_connect_str(&address, Duration::from_secs(DEFAULT_TIMEOUT_SECS)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::trace!(target = %config.target, port = config.port, user = %username, "TCP connect failed: {}", e);
                continue;
            }
        };
        match AsyncFtpStream::connect_with_stream(tcp_stream).await {
            Ok(mut ftp) => {
                if ftp.login(username, password).await.is_ok() {
                    crate::mprintln!("{}", format!("[+] FTP credentials valid: {}:{}", username, password).green().bold());
                    if let Err(e) = ftp.quit().await { eprintln!("[!] FTP quit failed: {}", e); }
                    let result = Some((ServiceType::Ftp, username.to_string(), password.to_string()));
                    // Respect stop_on_success: if true, stop after first valid credential
                    if config.stop_on_success {
                        return Ok(result);
                    }
                    // If false, continue checking but still return first found (for consistency)
                    return Ok(result);
                }
                if let Err(e) = ftp.quit().await { eprintln!("[!] FTP quit failed: {}", e); }
            }
            Err(e) => {
                tracing::trace!(target = %config.target, port = config.port, user = %username, "FTP login attempt failed: {}", e);
                continue;
            }
        }
    }

    crate::mprintln!("{}", format!("[-] No valid FTP credentials found on {}:{}", config.target, config.port).yellow());
    Ok(None)
}

/// SSH check (blocking, so we use spawn_blocking)
pub fn check_ssh_blocking(config: &Config) -> Result<Option<(ServiceType, String, String)>> {
    crate::mprintln!("{}", format!("[*] Checking SSH credentials on {}:{}", config.target, config.port).cyan());

    for (username, password) in &config.credentials {
        if config.verbosity {
            crate::mprintln!("{}", format!("[*] Trying SSH: {}:{}", username, password).dimmed());
        }

        let address = normalize_target(&config.target, config.port);
        let socket_addr: std::net::SocketAddr = match address.parse() {
            Ok(sa) => sa,
            Err(e) => {
                tracing::debug!(addr = %address, "SSH target parse failed: {}", e);
                continue;
            }
        };
        // libssh2 needs a blocking std stream — blocking_tcp_connect honors
        // `setg src_port` which the raw connect_timeout silently skipped.
        if let Ok(stream) = crate::utils::network::blocking_tcp_connect(&socket_addr, Duration::from_secs(DEFAULT_TIMEOUT_SECS)) {
            let mut session = Session::new().context("Failed to create SSH session")?;
            session.set_tcp_stream(stream);
            session.handshake().context("SSH handshake failed")?;

            if session.userauth_password(username, password).is_ok() && session.authenticated() {
                crate::mprintln!("{}", format!("[+] SSH credentials valid: {}:{}", username, password).green().bold());
                return Ok(Some((ServiceType::Ssh, username.to_string(), password.to_string())));
            }
        }
    }

    crate::mprintln!("{}", format!("[-] No valid SSH credentials found on {}:{}", config.target, config.port).yellow());
    Ok(None)
}

/// Telnet check (blocking)
pub fn check_telnet_blocking(config: &Config) -> Result<Option<(ServiceType, String, String)>> {
    crate::mprintln!("{}", format!("[*] Checking Telnet credentials on {}:{}", config.target, config.port).cyan());

    for (username, password) in &config.credentials {
        if config.verbosity {
            crate::mprintln!("{}", format!("[*] Trying Telnet: {}:{}", username, password).dimmed());
        }

        let address = normalize_target(&config.target, config.port);
        let parts: Vec<&str> = address.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }
        let host = parts[1];
        let port: u16 = parts[0].parse().unwrap_or(23);

        let socket_addr: std::net::SocketAddr = match format!("{}:{}", host, port).parse() {
            Ok(sa) => sa,
            Err(e) => {
                tracing::debug!(addr = %address, "Telnet target parse failed: {}", e);
                continue;
            }
        };
        if let Ok(tcp_stream) = crate::utils::network::blocking_tcp_connect(&socket_addr, Duration::from_secs(DEFAULT_TIMEOUT_SECS)) {
            let mut telnet = Telnet::from_stream(Box::new(tcp_stream), 500);
            if let Err(e) = telnet.write(format!("{}\r\n", username).as_bytes()) { eprintln!("[!] Write failed: {}", e); }
            if let Err(e) = telnet.write(format!("{}\r\n", password).as_bytes()) { eprintln!("[!] Write failed: {}", e); }

            // Give device time to respond
            std::thread::sleep(Duration::from_millis(500));

            if let Ok(Event::Data(buffer)) = telnet.read_timeout(Duration::from_millis(800)) {
                let response = String::from_utf8_lossy(&buffer);
                // Explicit failure indicators -> auth failed
                if response.contains("incorrect") || response.contains("failed") {
                    continue;
                }
                // Require a positive indicator of a successful login:
                // shell prompts ($, #, >, ~) or welcome/session messages.
                let has_shell_prompt = response.contains('$')
                    || response.contains('#')
                    || response.contains('>')
                    || response.contains('~');
                let has_welcome = response.contains("Welcome")
                    || response.contains("Last login");
                if has_shell_prompt || has_welcome {
                    crate::mprintln!("{}", format!("[+] Telnet credentials valid: {}:{}", username, password).green().bold());
                    return Ok(Some((ServiceType::Telnet, username.to_string(), password.to_string())));
                }
                // Otherwise the response is inconclusive (e.g. empty,
                // connection-closed, re-prompt of "login:") -> treat as failed.
            }
        }
    }

    crate::mprintln!("{}", format!("[-] No valid Telnet credentials found on {}:{}", config.target, config.port).yellow());
    Ok(None)
}

/// HTTP Web Login check (async)
pub async fn check_http_form(config: &Config) -> Result<Option<(ServiceType, String, String)>> {
    crate::mprintln!("{}", format!("[*] Checking HTTP Web Form credentials on {}:{}", config.target, config.port).cyan());

    let client = crate::utils::build_http_client(Duration::from_secs(DEFAULT_TIMEOUT_SECS))?;

    let url = format!("http://{}:{}/video.htm", config.target.trim_matches(|c| c == '[' || c == ']'), config.port);

    for (username, password) in &config.credentials {
        if config.verbosity {
            crate::mprintln!("{}", format!("[*] Trying HTTP: {}:{}", username, password).dimmed());
        }

        let data = [
            ("LOGIN_ACCOUNT", *username),
            ("LOGIN_PASSWORD", *password),
            ("LANGUAGE", "0"),
            ("btnSubmit", "Login"),
        ];

        // Manual form construction
        let mut body = String::new();
        for (key, val) in &data {
            if !body.is_empty() { body.push('&'); }
            body.push_str(&format!("{}={}", key, url_encode(val)));
        }

        // Treat a transient request failure as a retryable/transport error: skip
        // this credential and continue, mirroring the FTP/SSH/Telnet loops above
        // instead of `?`-aborting the whole HTTP service check.
        let res = match client
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::trace!(target = %config.target, port = config.port, user = %username, "HTTP form request failed: {}", e);
                continue;
            }
        };

        let status = res.status();

        // A failed body read is a transport error, NOT evidence of valid creds.
        // Previously this was mapped to an empty String, which trivially does not
        // contain the login-form marker and was misreported as a successful login.
        let body = match crate::utils::network::read_http_body_text_capped(res, crate::utils::safe_io::DEFAULT_BODY_CAP).await {
            Ok(t) => t,
            Err(e) => {
                tracing::trace!(target = %config.target, port = config.port, user = %username, "HTTP form response body read failed: {}", e);
                continue;
            }
        };

        // Require a POSITIVE success signal rather than inferring success from the
        // mere absence of the ">Password<" login-form token:
        //  - HTTP status must indicate success/redirect (200 / 3xx login-redirect)
        //  - the login form must NO LONGER be presented (no LOGIN_PASSWORD field
        //    and no ">Password<" prompt — both are present on the re-served form)
        let still_login_form =
            body.contains(">Password<") || body.contains("LOGIN_PASSWORD");
        if (status.is_success() || status.is_redirection()) && !still_login_form && !body.is_empty() {
            crate::mprintln!("{}", format!("[+] HTTP credentials valid: {}:{}", username, password).green().bold());
            return Ok(Some((ServiceType::Http, username.to_string(), password.to_string())));
        }
    }

    crate::mprintln!("{}", format!("[-] No valid HTTP credentials found on {}:{}", config.target, config.port).yellow());
    Ok(None)
}

/// Entrypoint for module - parallel checks
pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("acti_camera_default requires a single-host target")?;

    display_banner();
    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());
    crate::mprintln!();

    let mut outcome = ModuleOutcome::ok();
    ctx.rate_limit(target).await;

    let creds = vec![
        ("admin", "12345"),
        ("admin", "123456"),
        ("Admin", "12345"),
        ("Admin", "123456"),
    ];

    let base_config = Config {
        target: target.to_string(),
        port: 0,
        credentials: creds,
        stop_on_success: true,
        verbosity: true,
    };

    let ftp_conf    = Config { port: 21, ..base_config.clone() };
    let ssh_conf    = Config { port: 22, ..base_config.clone() };
    let telnet_conf = Config { port: 23, ..base_config.clone() };
    let http_conf   = Config { port: 80, ..base_config.clone() };

    let (ftp_res, ssh_res, telnet_res, http_res) = join!(
        check_ftp(&ftp_conf),
        async {
            task::spawn_blocking(move || check_ssh_blocking(&ssh_conf)).await?
        },
        async {
            task::spawn_blocking(move || check_telnet_blocking(&telnet_conf)).await?
        },
        check_http_form(&http_conf),
    );

    // Collect all successful results
    let mut found_credentials = Vec::new();
    
    if let Ok(Some((service, user, pass))) = ftp_res {
        found_credentials.push((service, user, pass));
    }
    if let Ok(Some((service, user, pass))) = ssh_res {
        found_credentials.push((service, user, pass));
    }
    if let Ok(Some((service, user, pass))) = telnet_res {
        found_credentials.push((service, user, pass));
    }
    if let Ok(Some((service, user, pass))) = http_res {
        found_credentials.push((service, user, pass));
    }

    // Print summary and store credentials
    if !found_credentials.is_empty() {
        crate::mprintln!();
        crate::mprintln!("{}", "=== Summary ===".bold());
        for (service, user, pass) in &found_credentials {
            crate::mprintln!("{}", format!("  {}: {}:{}", service.as_str(), user, pass).green());
            let (svc_port, svc_name) = match service.as_str() {
                "FTP" => (21u16, "ftp"),
                "SSH" => (22, "ssh"),
                "Telnet" => (23, "telnet"),
                "HTTP" => (80, "http"),
                _ => (0, "unknown"),
            };
            if crate::cred_store::store_credential(crate::cred_store::NewCred {
                host: target, port: svc_port, service: svc_name, username: user, secret: pass,
                cred_type: crate::cred_store::CredType::Password,
                source_module: "creds/camera/acti/acti_camera_default",
            }).await.is_none() { eprintln!("[!] Failed to store credential"); }
            outcome.findings.push(Finding {
                target: target.to_string(),
                kind: FindingKind::Credential,
                message: format!("ACTi default credentials valid {}:{} on {} ({}:{})", user, pass, svc_name, target, svc_port),
                data: Some(serde_json::json!({
                    "service": svc_name,
                    "port": svc_port,
                    "username": user,
                    "password": pass,
                })),
            });
        }
    } else {
        crate::mprintln!();
        crate::mprintln!("{}", "[-] No valid credentials found on any service.".yellow());
    }

    Ok(outcome)
}

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "ACTi Camera Default Credentials".to_string(),
        description: "Tests default credentials across FTP, SSH, Telnet, and HTTP on ACTi IP cameras.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
        default_port: None,
    }
}

crate::register_native_module!(crate::module::Category::Creds, "camera/acti/acti_camera_default", native);

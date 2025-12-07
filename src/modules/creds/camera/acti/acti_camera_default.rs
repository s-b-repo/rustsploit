use anyhow::{Context, Result};
use async_ftp::FtpStream;
use colored::*;
use reqwest::Client;
use ssh2::Session;
use telnet::{Telnet, Event};
use std::{net::TcpStream, time::Duration};
use tokio::{join, task};

const DEFAULT_TIMEOUT_SECS: u64 = 10;

fn display_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║   ACTi Camera Default Credentials Checker                 ║".cyan());
    println!("{}", "║   Multi-Protocol Scanner (FTP/SSH/Telnet/HTTP)            ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
    println!();
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
    println!("{}", format!("[*] Checking FTP credentials on {}:{}", config.target, config.port).cyan());

    for (username, password) in &config.credentials {
        if config.verbosity {
            println!("{}", format!("[*] Trying FTP: {}:{}", username, password).dimmed());
        }

        let address = normalize_target(&config.target, config.port);
        match FtpStream::connect(address).await {
            Ok(mut ftp) => {
                if ftp.login(username, password).await.is_ok() {
                    println!("{}", format!("[+] FTP credentials valid: {}:{}", username, password).green().bold());
                    let _ = ftp.quit().await;
                    let result = Some((ServiceType::Ftp, username.to_string(), password.to_string()));
                    // Respect stop_on_success: if true, stop after first valid credential
                    if config.stop_on_success {
                        return Ok(result);
                    }
                    // If false, continue checking but still return first found (for consistency)
                    return Ok(result);
                }
                let _ = ftp.quit().await;
            }
            Err(_) => continue,
        }
    }

    println!("{}", format!("[-] No valid FTP credentials found on {}:{}", config.target, config.port).yellow());
    Ok(None)
}

/// SSH check (blocking, so we use spawn_blocking)
pub fn check_ssh_blocking(config: &Config) -> Result<Option<(ServiceType, String, String)>> {
    println!("{}", format!("[*] Checking SSH credentials on {}:{}", config.target, config.port).cyan());

    for (username, password) in &config.credentials {
        if config.verbosity {
            println!("{}", format!("[*] Trying SSH: {}:{}", username, password).dimmed());
        }

        let address = normalize_target(&config.target, config.port);
        if let Ok(stream) = TcpStream::connect(address) {
            let mut session = Session::new().context("Failed to create SSH session")?;
            session.set_tcp_stream(stream);
            session.handshake().context("SSH handshake failed")?;

            if session.userauth_password(username, password).is_ok() && session.authenticated() {
                println!("{}", format!("[+] SSH credentials valid: {}:{}", username, password).green().bold());
                return Ok(Some((ServiceType::Ssh, username.to_string(), password.to_string())));
            }
        }
    }

    println!("{}", format!("[-] No valid SSH credentials found on {}:{}", config.target, config.port).yellow());
    Ok(None)
}

/// Telnet check (blocking)
pub fn check_telnet_blocking(config: &Config) -> Result<Option<(ServiceType, String, String)>> {
    println!("{}", format!("[*] Checking Telnet credentials on {}:{}", config.target, config.port).cyan());

    for (username, password) in &config.credentials {
        if config.verbosity {
            println!("{}", format!("[*] Trying Telnet: {}:{}", username, password).dimmed());
        }

        let address = normalize_target(&config.target, config.port);
        let parts: Vec<&str> = address.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }
        let host = parts[1];
        let port: u16 = parts[0].parse().unwrap_or(23);

        if let Ok(mut telnet) = Telnet::connect((host, port), 500) {
            let _ = telnet.write(format!("{}\r\n", username).as_bytes());
            let _ = telnet.write(format!("{}\r\n", password).as_bytes());

            // Give device time to respond
            std::thread::sleep(Duration::from_millis(500));

            if let Ok(Event::Data(buffer)) = telnet.read_timeout(Duration::from_millis(800)) {
                let response = String::from_utf8_lossy(&buffer);
                if !response.contains("incorrect") && !response.contains("failed") {
                    println!("{}", format!("[+] Telnet credentials valid: {}:{}", username, password).green().bold());
                    return Ok(Some((ServiceType::Telnet, username.to_string(), password.to_string())));
                }
            }
        }
    }

    println!("{}", format!("[-] No valid Telnet credentials found on {}:{}", config.target, config.port).yellow());
    Ok(None)
}

/// HTTP Web Login check (async)
pub async fn check_http_form(config: &Config) -> Result<Option<(ServiceType, String, String)>> {
    println!("{}", format!("[*] Checking HTTP Web Form credentials on {}:{}", config.target, config.port).cyan());

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .build()?;

    let url = format!("http://{}:{}/video.htm", config.target.trim_matches(|c| c == '[' || c == ']'), config.port);

    for (username, password) in &config.credentials {
        if config.verbosity {
            println!("{}", format!("[*] Trying HTTP: {}:{}", username, password).dimmed());
        }

        let data = [
            ("LOGIN_ACCOUNT", *username),
            ("LOGIN_PASSWORD", *password),
            ("LANGUAGE", "0"),
            ("btnSubmit", "Login"),
        ];

        let res = client
            .post(&url)
            .form(&data)
            .send()
            .await
            .context("[!] Failed to send HTTP form request")?;

        let body = res.text().await.unwrap_or_default();

        if !body.contains(">Password<") {
            println!("{}", format!("[+] HTTP credentials valid: {}:{}", username, password).green().bold());
            return Ok(Some((ServiceType::Http, username.to_string(), password.to_string())));
        }
    }

    println!("{}", format!("[-] No valid HTTP credentials found on {}:{}", config.target, config.port).yellow());
    Ok(None)
}

/// Entrypoint for module - parallel checks
pub async fn run(target: &str) -> Result<()> {
    display_banner();
    println!("{}", format!("[*] Target: {}", target).cyan());
    println!();

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

    // Print summary
    if !found_credentials.is_empty() {
        println!();
        println!("{}", "=== Summary ===".bold());
        for (service, user, pass) in &found_credentials {
            println!("{}", format!("  {}: {}:{}", service.as_str(), user, pass).green());
        }
    } else {
        println!();
        println!("{}", "[-] No valid credentials found on any service.".yellow());
    }

    Ok(())
}

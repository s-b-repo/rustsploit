use anyhow::{Context, Result};
use async_ftp::FtpStream;
use reqwest::Client;
use ssh2::Session;
use telnet::{Telnet, Event};
use std::{net::TcpStream, time::Duration};
use tokio::{join, task};

#[allow(dead_code)]
/// Supported Acti services
pub enum ServiceType {
    Ftp,
    Ssh,
    Telnet,
    Http,
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
pub async fn check_ftp(config: &Config) -> Result<()> {
    println!("[*] Checking FTP credentials on {}:{}", config.target, config.port);

    for (username, password) in &config.credentials {
        if config.verbosity {
            println!("[*] Trying FTP: {}:{}", username, password);
        }

        let address = normalize_target(&config.target, config.port);
        match FtpStream::connect(address).await {
            Ok(mut ftp) => {
                if ftp.login(username, password).await.is_ok() {
                    println!("[+] FTP credentials valid: {}:{}", username, password);
                    if config.stop_on_success {
                        return Ok(());
                    }
                }
                let _ = ftp.quit().await;
            }
            Err(_) => continue,
        }
    }

    println!("[-] No valid FTP credentials found on {}:{}", config.target, config.port);
    Ok(())
}

/// SSH check (blocking, so we use spawn_blocking)
pub fn check_ssh_blocking(config: &Config) -> Result<()> {
    println!("[*] Checking SSH credentials on {}:{}", config.target, config.port);

    for (username, password) in &config.credentials {
        if config.verbosity {
            println!("[*] Trying SSH: {}:{}", username, password);
        }

        let address = normalize_target(&config.target, config.port);
        if let Ok(stream) = TcpStream::connect(address) {
            let mut session = Session::new().context("Failed to create SSH session")?;
            session.set_tcp_stream(stream);
            session.handshake().context("SSH handshake failed")?;

            if session.userauth_password(username, password).is_ok() && session.authenticated() {
                println!("[+] SSH credentials valid: {}:{}", username, password);
                if config.stop_on_success {
                    return Ok(());
                }
            }
        }
    }

    println!("[-] No valid SSH credentials found on {}:{}", config.target, config.port);
    Ok(())
}

/// Telnet check (blocking)
pub fn check_telnet_blocking(config: &Config) -> Result<()> {
    println!("[*] Checking Telnet credentials on {}:{}", config.target, config.port);

    for (username, password) in &config.credentials {
        if config.verbosity {
            println!("[*] Trying Telnet: {}:{}", username, password);
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
                    println!("[+] Telnet credentials valid: {}:{}", username, password);
                    if config.stop_on_success {
                        return Ok(());
                    }
                }
            }
        }
    }

    println!("[-] No valid Telnet credentials found on {}:{}", config.target, config.port);
    Ok(())
}

/// HTTP Web Login check (async)
pub async fn check_http_form(config: &Config) -> Result<()> {
    println!("[*] Checking HTTP Web Form credentials on {}:{}", config.target, config.port);

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()?;

    let url = format!("http://{}:{}/video.htm", config.target.trim_matches(|c| c == '[' || c == ']'), config.port);

    for (username, password) in &config.credentials {
        if config.verbosity {
            println!("[*] Trying HTTP: {}:{}", username, password);
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
            println!("[+] HTTP credentials valid: {}:{}", username, password);
            if config.stop_on_success {
                return Ok(());
            }
        }
    }

    println!("[-] No valid HTTP credentials found on {}:{}", config.target, config.port);
    Ok(())
}

/// Entrypoint for module - parallel checks
pub async fn run(target: &str) -> Result<()> {
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

    ftp_res?;
    ssh_res?;
    telnet_res?;
    http_res?;

    Ok(())
}

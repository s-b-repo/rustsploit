use anyhow::{Result, Context, anyhow};
use colored::*;
use reqwest::{Client, Method, header};
use serde::{Deserialize, Serialize};

use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Semaphore;
use crate::utils::{
    prompt_required, prompt_default, prompt_yes_no, prompt_wordlist, 
    normalize_target, load_lines, prompt_existing_file
};
use rand::seq::IndexedRandom;

// --- Constants & Data ---

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "RustSploit/0.3",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
];

const COMMON_STATUS_CODES: &[u16] = &[200, 201, 204, 301, 302, 307, 401, 403, 405, 421, 500];

// --- Configuration Structs ---

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DirBruteConfig {
    pub target_host: String,
    pub protocol: String, // http or https
    pub port: u16,
    pub base_path: String, // e.g. "/" or "/api/"
    pub wordlist_path: String,
    
    // Scan Settings
    pub scan_mode: u8, // 1=GET, 2=NUKE (Safe), 3=DESTROY (Delete)
    pub concurrency: usize,
    pub delay_ms: u64,
    
    // Evasion
    pub random_agent: bool,
    pub custom_cookies: Option<String>, // e.g. "cf_clearance=...; _cfduid=..."
    
    // Reporting
    pub verbose: bool,
}

impl Default for DirBruteConfig {
    fn default() -> Self {
        Self {
            target_host: String::new(),
            protocol: "http".to_string(),
            port: 80,
            base_path: "/".to_string(),
            wordlist_path: String::new(),
            scan_mode: 1,
            concurrency: 10,
            delay_ms: 200,
            random_agent: false,
            custom_cookies: None,
            verbose: false,
        }
    }
}

// --- Main Entry Point ---

pub async fn run(target: &str) -> Result<()> {
    print_banner();

    // 1. Wizard Menu
    println!("{}", "Select Operation Mode:".cyan().bold());
    println!("1. Quick Attack (Default Settings)");
    println!("2. Create Template (Wizard -> Save)");
    println!("3. Load Template (Load -> Run)");
    println!("4. Custom Attack (Wizard -> Run)");
    
    let choice = prompt_default("Selection", "1").await?;
    
    let config = match choice.as_str() {
        "1" => setup_quick_attack(target).await?,
        "2" => {
            let cfg = setup_wizard(target).await?;
            save_template(&cfg).await?;
            println!("\n{}", "Template saved. Exiting module.".green());
            return Ok(());
        },
        "3" => load_template().await?,
        "4" => setup_wizard(target).await?,
        _ => {
            println!("{}", "Invalid selection. Defaulting to Quick Attack.".yellow());
            setup_quick_attack(target).await?
        }
    };

    // 2. Execution
    execute_scan(config).await
}

fn print_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║              Advanced Directory Brute Force               ║".cyan());
    println!("{}", "║      Features: Nuke Mode, WAF Evasion, Config Manager     ║".red());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
}

// --- Setup Helpers ---

async fn setup_quick_attack(initial_target: &str) -> Result<DirBruteConfig> {
    println!("\n{}", "--- Quick Attack Setup ---".blue().bold());
    
    // 1. Target
    let (proto, host, port, path) = parse_target_interactive(initial_target).await?;
    
    // 2. Wordlist
    let wordlist = prompt_wordlist("Wordlist path").await?;
    
    Ok(DirBruteConfig {
        target_host: host,
        protocol: proto,
        port,
        base_path: path,
        wordlist_path: wordlist,
        verbose: false,
        ..DirBruteConfig::default()
    })
}

async fn setup_wizard(initial_target: &str) -> Result<DirBruteConfig> {
    println!("\n{}", "--- Advanced Configuration Wizard ---".blue().bold());
    
    // 1. Target
    let (proto, host, port, path) = parse_target_interactive(initial_target).await?;
    
    // 2. Scan Mode
    println!("\n{}", "Select Scan Mode:".cyan());
    println!("1. Standard (GET only) - [Recommended]");
    println!("2. Nuke Mode (GET, POST, PUT, HEAD, OPTIONS...) - Noisy!");
    println!("3. TOTAL DESTRUCTION (Level 2 + DELETE) - DANGEROUS");
    
    let mode_str = prompt_default("Mode", "1").await?;
    let scan_mode = match mode_str.as_str() {
        "3" => {
            println!("\n{}", "!!! CRITICAL WARNING !!!".on_red().white().bold());
            println!("{}", "You have selected TOTAL DESTRUCTION mode.".red().bold());
            println!("This will attempt HTTP DELETE method on discovered resources.");
            println!("This can PERMANENTLY DESTROY data on the target server.");
            let confirm = prompt_required("Type 'DESTROY' to confirm").await?;
            if confirm != "DESTROY" {
                println!("{}", "Confirmation failed. Reverting to Standard Mode.".yellow());
                1
            } else {
                3
            }
        },
        "2" => {
            println!("\n{}", "[!] Warning: Nuke Mode sends multiple requests per path.".yellow());
            if prompt_yes_no("Continue?", true).await? { 2 } else { 1 }
        },
        _ => 1
    };
    
    // 3. Wordlist
    let wordlist = prompt_wordlist("Wordlist path").await?;
    
    // 4. Performance
    let concurrency: usize = prompt_default("Concurrency (Threads)", "10").await?.parse().unwrap_or(10);
    let delay_ms: u64 = prompt_default("Delay per request (ms)", "200").await?.parse().unwrap_or(200);
    
    // 5. Evasion
    let random_agent = prompt_yes_no("Use Random User-Agents?", false).await?;
    
    let custom_cookies = if prompt_yes_no("Configure Custom Cookies (WAF/Cloudflare)?", false).await? {
        println!("{}", "Enter cookie string (e.g. 'cf_clearance=XXX; _cfduid=YYY')".dimmed());
        Some(prompt_required("Cookies").await?)
    } else {
        None
    };

    // 6. Reporting
    let verbose = prompt_yes_no("Verbose Output (show 403s)?", false).await?;
    
    Ok(DirBruteConfig {
        target_host: host,
        protocol: proto,
        port,
        base_path: path,
        wordlist_path: wordlist,
        scan_mode,
        concurrency,
        delay_ms,
        random_agent,
        custom_cookies,
        verbose,
    })
}

// Interactive target parser logic
async fn parse_target_interactive(raw: &str) -> Result<(String, String, u16, String)> {
    // Basic normalization from utils
    let resolved_ip = if raw.is_empty() {
        prompt_required("Target Host/IP").await?
    } else {
        let normalized = normalize_target(raw)?;
        // strip port if present in normalized, we ask for it separately to allow http/https logic
        if let Some((host, _)) = normalized.split_once(':') {
             host.to_string()
        } else {
             normalized
        }
    };

    let use_https = prompt_yes_no("Use HTTPS?", true).await?;
    let proto = if use_https { "https".to_string() } else { "http".to_string() };
    
    let def_port = if use_https { "443" } else { "80" };
    let port: u16 = prompt_default(&format!("Port (default {})", def_port), def_port).await?
        .parse()
        .context("Invalid port")?;
        
    let path_input = prompt_default("Base Path (must end with /)", "/").await?;
    
    // Slash check logic
    let path = if !path_input.ends_with('/') {
        if prompt_yes_no("Path does not end with '/'. Append it?", true).await? {
            format!("{}/", path_input)
        } else {
            if !prompt_yes_no("Continue without trailing slash? (May break scanning)", false).await? {
                return Err(anyhow!("Aborted by user due to path format."));
            }
            path_input
        }
    } else {
        path_input
    };
    
    Ok((proto, resolved_ip, port, path))
}

// --- Persistence ---

async fn save_template(config: &DirBruteConfig) -> Result<()> {
    let name = prompt_default("Template Name (e.g. 'myscan.json')", "scan_template.json").await?;
    let json = serde_json::to_string_pretty(config)?;
    fs::write(&name, json).context("Failed to write template file")?;
    println!("Saved config to {}", name);
    Ok(())
}

async fn load_template() -> Result<DirBruteConfig> {
    let path = prompt_existing_file("Template File Path").await?;
    let content = fs::read_to_string(&path)?;
    let config: DirBruteConfig = serde_json::from_str(&content).context("Invalid template format")?;
    
    println!("{}", "Loaded Configuration:".green());
    println!("Target: {}://{}:{}{}", config.protocol, config.target_host, config.port, config.base_path);
    println!("Mode: Level {}", config.scan_mode);
    println!("Wordlist: {}", config.wordlist_path);
    
    if !prompt_yes_no("Run this configuration?", true).await? {
        return Err(anyhow!("User cancelled after loading template."));
    }
    
    Ok(config)
}

// --- Execution Engine ---

struct ScanResult {
    path: String,
    method: String,
    status: u16,
    len: u64,
}

async fn execute_scan(config: DirBruteConfig) -> Result<()> {
    let lines = load_lines(&config.wordlist_path)?;
    let total = lines.len();
    println!("\n{}", format!("Loaded {} words. Starting scan...", total).blue().bold());
    
    let base_url = format!("{}://{}:{}{}", config.protocol, config.target_host, config.port, config.base_path);
    
    // Build Client
    let mut headers = header::HeaderMap::new();
    if let Some(cookies) = &config.custom_cookies {
        headers.insert(header::COOKIE, cookies.parse().context("Invalid cookie string")?);
    }
    
    let client = Client::builder()
        .default_headers(headers)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()?;

    let sem = Arc::new(Semaphore::new(config.concurrency));
    let results_mutex = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let forbidden_count = Arc::new(AtomicUsize::new(0));
    
    let methods = get_methods_for_mode(config.scan_mode);
    let delay = Duration::from_millis(config.delay_ms);

    println!("{}", format!("Target Base: {}", base_url).cyan());
    println!("{}", "Press Ctrl+C to stop (handler not implemented, so just wait)".dimmed());
    println!("{}", "---------------------------------------------------");

    let mut tasks = Vec::new();

    for word in lines {
        let sem = Arc::clone(&sem);
        let client = client.clone();
        let base = base_url.clone();
        let r_mutex = Arc::clone(&results_mutex);
        let f_count = Arc::clone(&forbidden_count);
        let methods = methods.clone();

        let config_verbose = config.verbose;
        let random_agent = config.random_agent;
        
        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            
            // Apply delay
            if delay.as_millis() > 0 {
                tokio::time::sleep(delay).await;
            }
            
            let url = format!("{}{}", base, word);

            for method in methods {
                let mut req_builder = client.request(method.clone(), &url);
                
                if random_agent {
                     let agent = USER_AGENTS.choose(&mut rand::rng()).unwrap_or(&"RustSploit");
                     req_builder = req_builder.header(header::USER_AGENT, *agent);
                } else {
                     req_builder = req_builder.header(header::USER_AGENT, "RustSploit/0.3");
                }
                
                match req_builder.send().await {
                    Ok(resp) => {
                         let status = resp.status().as_u16();
                         let len = resp.content_length().unwrap_or(0);
                         
                         // Special handling for 403 Forbidden
                         if status == 403 {
                             f_count.fetch_add(1, Ordering::Relaxed);
                             if !config_verbose {
                                 continue; // Skip printing if not verbose
                             }
                         }

                         // Determine if "Interesting"
                         if COMMON_STATUS_CODES.contains(&status) {
                             let method_str = method.as_str();
                             
                             // Enhanced Color Logic
                             let status_display = if status >= 200 && status < 300 {
                                 format!("{} {}", "[FOUND]".green().bold(), status.to_string().green())
                             } else if status >= 300 && status < 400 {
                                 format!("{} {}", "[REDIR]".blue().bold(), status.to_string().blue())
                             } else if status >= 500 {
                                 format!("{} {}", "[ERROR]".red().bold(), status.to_string().red())
                             } else if status == 403 || status == 401 {
                                 format!("{} {}", "[AUTH]".yellow().bold(), status.to_string().yellow())
                             } else {
                                 format!("[{}]", status).white().to_string()
                             };
                             
                             println!("{} Size: {} | Method: {} | {}", 
                                 status_display, 
                                 len.to_string().dimmed(), 
                                 method_str.bold(), 
                                 url
                             );
                             
                             let res = ScanResult {
                                 path: url.clone(),
                                 method: method.to_string(),
                                 status,
                                 len,
                             };
                             r_mutex.lock().await.push(res);
                         }
                    }
                    Err(_) => {}
                }
            }
        });
        tasks.push(task);
    }
    
    // Await all
    for t in tasks {
        let _ = t.await;
    }

    println!("\n{}", "Scan Complete.".green().bold());
    
    // 403 Summary
    let f_total = forbidden_count.load(Ordering::Relaxed);
    if f_total > 0 && !config.verbose {
        println!("{}", format!("[*] Aggregated {} '403 Forbidden' responses. (Use verbose mode to see them)", f_total).yellow());
    }

    // Report & Save
    let final_results = results_mutex.lock().await;
    if !final_results.is_empty() && prompt_yes_no("Save results to file?", true).await? {
        let sort_choice = prompt_default("Sort by (1) Status or (2) Size", "1").await?;
        
        let mut sorted: Vec<&ScanResult> = final_results.iter().collect();
        if sort_choice == "2" {
            sorted.sort_by(|a, b| b.len.cmp(&a.len)); // Size desc
        } else {
            sorted.sort_by(|a, b| a.status.cmp(&b.status)); // Status asc
        }
        
        let filename = format!("scan_results_{}.txt", chrono::Local::now().format("%Y%m%d_%H%M%S"));
        let mut file_content = String::new();
        for r in sorted {
             use std::fmt::Write;
             writeln!(file_content, "[{}] {} | Size: {} | Method: {} | {}", 
                 r.status, get_status_text(r.status), r.len, r.method, r.path).unwrap();
        }
        
        fs::write(&filename, file_content)?;
        println!("Results saved to {}", filename.green());
    }

    Ok(())
}

fn get_methods_for_mode(mode: u8) -> Vec<Method> {
    match mode {
        3 => vec![
            Method::GET, Method::POST, Method::PUT, Method::DELETE, 
            Method::HEAD, Method::OPTIONS, Method::PATCH, Method::TRACE,
            Method::CONNECT
        ],
        2 => vec![
            Method::GET, Method::POST, Method::PUT, 
            Method::HEAD, Method::OPTIONS, Method::PATCH, Method::TRACE,
            Method::CONNECT
        ],
        _ => vec![Method::GET], // Level 1
    }
}

fn get_status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        421 => "Misdirected Request",
        500 => "Internal Server Error",
        _ => "",
    }
}

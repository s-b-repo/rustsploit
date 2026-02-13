use anyhow::{Result, Context};
use colored::*;
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::fmt::Write as FmtWrite; // Rename to avoid conflict with io::Write
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};
use crate::utils::{
    prompt_required, prompt_default, prompt_yes_no, normalize_target, prompt_existing_file
};
use base64::{Engine as _, engine::general_purpose};
use rand::seq::IndexedRandom;

// --- Enums & Config ---

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum EncodingType {
    None,
    Url,
    DoubleUrl,
    Hex,
    Unicode,
    HtmlEntity,
    Decimal,
    Octal,
    Base64,
    Mixed, 
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SequentialFuzzerConfig {
    pub target_url: String,
    pub charset_mode: u8, // 1=SQL, 2=Traversal, 3=Cmd, 4=All, 5=Custom
    pub custom_charset: Option<String>,
    pub min_length: usize,
    pub max_length: usize,
    pub encoding: EncodingType,
    pub concurrency: usize,
    pub cookies: Option<String>,
    pub verbose: bool,
}

impl Default for SequentialFuzzerConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            charset_mode: 4,
            custom_charset: None,
            min_length: 1,
            max_length: 3,
            encoding: EncodingType::None,
            concurrency: 50,
            cookies: None,
            verbose: false,
        }
    }
}

struct FuzzResult {
    path: String,
    status: u16,
    size: u64,
}

// --- Charsets ---

const CHARSET_SQL: &str = "'\";-/*=";
const CHARSET_TRAVERSAL: &str = "./\\";
const CHARSET_CMD: &str = "|;&$()<> '\"";
const CHARSET_ALL: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-_=+[]{};:'\",.<>/?|`~";

fn get_charset(config: &SequentialFuzzerConfig) -> Vec<char> {
    match config.charset_mode {
        1 => CHARSET_SQL.chars().collect(),
        2 => CHARSET_TRAVERSAL.chars().collect(),
        3 => CHARSET_CMD.chars().collect(),
        5 => config.custom_charset.as_deref().unwrap_or("").chars().collect(),
        _ => CHARSET_ALL.chars().collect(),
    }
}

// --- Encoding Logic ---

fn encode_payload(input: &str, encoding: EncodingType) -> String {
    match encoding {
        EncodingType::None => input.to_string(),
        EncodingType::Url => urlencoding::encode(input).to_string(),
        EncodingType::DoubleUrl => urlencoding::encode(&urlencoding::encode(input).to_string()).to_string(),
        EncodingType::Hex => {
            input.chars().map(|c| format!("\\x{:02X}", c as u8)).collect()
        },
        EncodingType::Unicode => {
            input.chars().map(|c| format!("\\u00{:02X}", c as u8)).collect()
        },
        EncodingType::HtmlEntity => {
             input.chars().map(|c| {
                 match c {
                     '"' => "&quot;".to_string(),
                     '\'' => "&apos;".to_string(),
                     '<' => "&lt;".to_string(),
                     '>' => "&gt;".to_string(),
                     '&' => "&amp;".to_string(),
                     _ => c.to_string()
                 }
             }).collect()
        },
        EncodingType::Decimal => {
             input.chars().map(|c| format!("&#{};", c as u8)).collect()
        },
        EncodingType::Octal => {
             input.chars().map(|c| format!("\\{:03o}", c as u8)).collect()
        },
        EncodingType::Base64 => {
             general_purpose::STANDARD.encode(input)
        },
        EncodingType::Mixed => {
             // Randomly apply an encoding per character (simplified: raw or url or hex)
             let mut rng = rand::rng();
             input.chars().map(|c| {
                 match [0, 1, 2].choose(&mut rng).unwrap_or(&0) {
                     0 => c.to_string(),
                     1 => format!("%{:02X}", c as u8),
                     _ => format!("\\x{:02X}", c as u8),
                 }
             }).collect()
        }
    }
}

// --- Main Entry ---

pub async fn run(target: &str) -> Result<()> {
    print_banner();

    // Menu
    println!("{}", "Select Operation Mode:".cyan().bold());
    println!("1. Quick Attack (All ASCII, No Encoding)");
    println!("2. Create Template (Wizard -> Save)");
    println!("3. Load Template (Load -> Run)");
    println!("4. Custom Attack (Wizard -> Run)");
    
    let choice = prompt_default("Selection", "1")?;
    
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

    execute_fuzz(config).await
}

fn print_banner() {
    println!("{}", "╔═══════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║              Sequential Fuzzer (Brute Force)              ║".cyan());
    println!("{}", "║  Features: Actor Storage, 10 Encodings, Instant Saving    ║".red());
    println!("{}", "╚═══════════════════════════════════════════════════════════╝".cyan());
}

// --- Setup ---

async fn setup_quick_attack(initial_target: &str) -> Result<SequentialFuzzerConfig> {
    println!("\n{}", "--- Quick Attack Setup ---".blue().bold());
    let url = parse_target_interactive(initial_target).await?;
    
    // Forced Input for Reliability
    let min_len_str = prompt_required("Min Sequence Length (e.g. 1)")?;
    let min_len: usize = min_len_str.parse().unwrap_or(1);
    
    let max_len_str = prompt_required("Max Sequence Length (e.g. 3)")?;
    let max_len: usize = max_len_str.parse().unwrap_or(3);
    
    let verbose = prompt_yes_no("Verbose Mode? (Print all 403s)", false)?;

    Ok(SequentialFuzzerConfig {
        target_url: url,
        charset_mode: 4, // All
        min_length: min_len,
        max_length: max_len,
        encoding: EncodingType::None,
        concurrency: 50,
        verbose,
        ..SequentialFuzzerConfig::default()
    })
}

async fn setup_wizard(initial_target: &str) -> Result<SequentialFuzzerConfig> {
    println!("\n{}", "--- Configuration Wizard ---".blue().bold());
    
    // 1. Target
    let url = parse_target_interactive(initial_target).await?;
    
    // 2. Charset
    println!("\n{}", "Select Charset:".cyan());
    println!("1. SQL Injection ({})", CHARSET_SQL);
    println!("2. Path Traversal ({})", CHARSET_TRAVERSAL);
    println!("3. Command Injection ({})", CHARSET_CMD);
    println!("4. All Printable ASCII (Standard Brute)");
    println!("5. Custom");
    
    let c_mode_str = prompt_required("Charset Selection (1-5)")?;
    let c_mode: u8 = c_mode_str.parse().unwrap_or(4);

    let custom = if c_mode == 5 {
        Some(prompt_required("Custom Charset String")?)
    } else {
        None
    };
    
    // 3. Lengths
    // Using prompt_required to prevent skipping issues with buffered inputs
    let min_len_str = prompt_required("Min Sequence Length (e.g. 1)")?;
    let min_len: usize = min_len_str.parse().unwrap_or(1);
    
    let max_len_str = prompt_required("Max Sequence Length (e.g. 3)")?;
    let max_len: usize = max_len_str.parse().unwrap_or(3);
    
    if max_len > 4 && c_mode == 4 {
        println!("{}", "[!] Warning: Brute forcing printable ASCII > 4 chars will take a VERY long time.".yellow());
    }

    // 4. Encoding
    println!("\n{}", "Select Encoding (WAF Bypass):".cyan());
    println!("0. None (Raw)");
    println!("1. URL Encode (%XX)");
    println!("2. Double URL Encode (%25XX)");
    println!("3. Hex Encode (\\xXX)");
    println!("4. Unicode (\\u00XX)");
    println!("5. HTML Entity (&quot;)");
    println!("6. Decimal (&#DDD;)");
    println!("7. Octal (\\OOO)");
    println!("8. Base64");
    println!("9. Mixed/Random");
    
    let enc_choice_str = prompt_required("Encoding Selection (0-9)")?;
    let enc_choice: u8 = enc_choice_str.parse().unwrap_or(0);

    let encoding = match enc_choice {
        1 => EncodingType::Url,
        2 => EncodingType::DoubleUrl,
        3 => EncodingType::Hex,
        4 => EncodingType::Unicode,
        5 => EncodingType::HtmlEntity,
        6 => EncodingType::Decimal,
        7 => EncodingType::Octal,
        8 => EncodingType::Base64,
        9 => EncodingType::Mixed,
        _ => EncodingType::None,
    };
    
    // 5. Config
    let concurrency_str = prompt_required("Concurrency (Threads)")?;
    let concurrency: usize = concurrency_str.parse().unwrap_or(50);
    
    let cookies = if prompt_yes_no("Add Cookies?", false)? {
        Some(prompt_required("Cookie Header Value")?)
    } else {
        None
    };
    
    let verbose = prompt_yes_no("Verbose Mode? (Print all 403s)", false)?;

    Ok(SequentialFuzzerConfig {
        target_url: url,
        charset_mode: c_mode,
        custom_charset: custom,
        min_length: min_len,
        max_length: max_len,
        encoding,
        concurrency,
        cookies,
        verbose,
    })
}

async fn parse_target_interactive(raw: &str) -> Result<String> {
    let base = if raw.is_empty() {
        normalize_target(&prompt_required("Target URL")?)?
    } else {
        normalize_target(raw)?
    };
    
    // Ensure protocol
    let url = if !base.starts_with("http") {
        format!("http://{}", base)
    } else {
        base
    };

    // Ensure trailing slash
    if !url.ends_with('/') {
        println!("{}", format!("[*] Current Target: {}", url).cyan());
        if prompt_yes_no("Target does not end with '/'. Append it?", true)? {
            Ok(format!("{}/", url))
        } else {
            Ok(url)
        }
    } else {
        Ok(url)
    }
}

// --- Persistence ---

async fn save_template(config: &SequentialFuzzerConfig) -> Result<()> {
    let name = prompt_default("Template Name", "fuzz_template.json")?;
    let json = serde_json::to_string_pretty(config)?;
    fs::write(&name, json).context("Failed to write template")?;
    println!("Saved to {}", name);
    Ok(())
}

async fn load_template() -> Result<SequentialFuzzerConfig> {
    let path = prompt_existing_file("Template File")?;
    let content = fs::read_to_string(&path)?;
    let config: SequentialFuzzerConfig = serde_json::from_str(&content).context("Invalid JSON")?;
    println!("{}", "Loaded Config.".green());
    Ok(config)
}

// --- Execution Engine ---

enum WriterMessage {
    Result(FuzzResult),
    Stop,
}

async fn execute_fuzz(config: SequentialFuzzerConfig) -> Result<()> {
    // 1. Prepare Output Dir
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let out_dir = format!("scans/fuzz_{}", timestamp);
    fs::create_dir_all(&out_dir).context("Failed to create output dir")?;
    println!("Output Directory: {}", out_dir.cyan());

    // 2. Spawn Writer Actor
    let (tx, mut rx) = mpsc::channel::<WriterMessage>(1000);
    let writer_dir = out_dir.clone();
    let verbose = config.verbose;
    
    // We cannot move the JoinHandle out easily if we await it later, but we can spawn it.
    // We need to await it at the end.
    let writer_handle = tokio::spawn(async move {
        let mut buffer: HashMap<u16, Vec<FuzzResult>> = HashMap::new();
        // We don't keep file handles open to avoid limits, we append-open each time.
        
        while let Some(msg) = rx.recv().await {
            match msg {
                WriterMessage::Result(res) => {
                    // 1. Instant Save
                    let file_path = format!("{}/raw_{}.txt", writer_dir, res.status);
                    let line = format!("[Size: {}] {}\n", res.size, res.path);
                    
                    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&file_path) {
                        let _ = file.write_all(line.as_bytes());
                    }

                    // 2. Print Control (Real-time Output)
                    let status = res.status;
                    let should_print = if status == 403 && !verbose {
                        false
                    } else {
                        true
                    };

                    if should_print {
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
                         
                         println!("{} Size: {} | {}", 
                             status_display, 
                             res.size.to_string().dimmed(), 
                             res.path
                         );
                    }

                    // 3. Buffer
                    buffer.entry(res.status).or_default().push(res);
                },
                WriterMessage::Stop => break,
            }
        }
        buffer
    });

    // 3. Engine Setup
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()?;
        
    let charset = get_charset(&config);
    let sem = Arc::new(Semaphore::new(config.concurrency));
    
    println!("{}", "Starting Fuzzer... Press Ctrl+C to abort (not handled cleanly)".yellow());
    
    // 4. Generator Loop
    // Memory Fix: Do not store JoinHandles in a Vec.
    // Instead, we rely on the semaphore to track active tasks.
    
    // We iterate lengths
    for len in config.min_length..=config.max_length {
        spawn_combinations_iterative(
            &client, 
            &config, 
            &charset, 
            len, 
            &sem, 
            &tx
        ).await;
    }
    
    // 5. Wait for all tasks to finish
    // We do this by attempting to acquire ALL permits.
    // This will block until all active tasks release their permits.
    println!("Generation done. Waiting for active tasks to complete...");
    let _ = sem.acquire_many(config.concurrency as u32).await;
    
    // Stop Writer
    let _ = tx.send(WriterMessage::Stop).await;
    let final_buffer = writer_handle.await?;
    
    println!("\n{}", "Scan Complete. Sorting results...".blue());
    
    // 6. Sort and Final Save
    let mut total_403 = 0;
    
    for (status, mut results) in final_buffer {
        if status == 403 {
            total_403 += results.len();
        }
    
        results.sort_by(|a, b| b.size.cmp(&a.size)); // Descending size
        
        let file_path = format!("{}/sorted_{}.txt", out_dir, status);
        let mut content = String::new();
        for r in results {
            // Avoid unwrap on string write (very unlikely to fail on memory, but strictness requested)
            let _ = writeln!(content, "[Size: {}] {}", r.size, r.path);
        }
        fs::write(&file_path, content)?;
        println!("Saved sorted results for status {} to {}", status, file_path.green());
    }
    
    if total_403 > 0 && !config.verbose {
         println!("{}", format!("\n[*] Aggregated {} '403 Forbidden' responses. (Use verbose mode to see them)", total_403).yellow());
    }

    Ok(())
}

// Iterative generator that spawns tasks (Base-N Counting)
async fn spawn_combinations_iterative(
    client: &Client,
    config: &SequentialFuzzerConfig,
    charset: &[char],
    length: usize,
    sem: &Arc<Semaphore>,
    tx: &mpsc::Sender<WriterMessage>
) {
    if charset.is_empty() || length == 0 { return; }
    
    // Performance: Parse headers ONCE, not per iteration
    let mut base_headers = header::HeaderMap::new();
    if let Some(c) = &config.cookies {
         if let Ok(val) = c.parse() {
             base_headers.insert(header::COOKIE, val);
         }
    }
    
    // Indices for each position in the string (0 to charset.len()-1)
    let mut indices = vec![0; length];
    let charset_len = charset.len();
    
    loop {
        // 1. Build String from Indices
        let current_payload: String = indices.iter().map(|&i| charset[i]).collect();
        
        // 2. Execute Task Logic
        // Safety: Handle semaphore error (closed) gracefully
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                // Semaphore closed or poisoned, stop generation
                return;
            }
        };

        let client = client.clone();
        let tx = tx.clone();
        let base = config.target_url.clone();
        let encoding = config.encoding;
        let headers = base_headers.clone(); // Clone ARC-like/cheap map? No, HeaderMap clone is relatively cheap but doing it here is necessary for async move.
        
        // Apply encoding
        let encoded_payload = encode_payload(&current_payload, encoding);
        let url = format!("{}{}", base, encoded_payload);
        
        tokio::spawn(async move {
            let _permit = permit; // drop when task done (releases semaphore)
            
            let req = client.get(&url).headers(headers);
            // Safety: Handle send errors (don't unwrap)
            if let Ok(resp) = req.send().await {
                let status = resp.status().as_u16();
                let size = resp.content_length().unwrap_or(0);
                
                let res = FuzzResult {
                    path: url,
                    status,
                    size,
                };
                // If receiver dropped, we just stop sending.
                let _ = tx.send(WriterMessage::Result(res)).await;
            }
        });
        
        // 3. Increment Indices (Standard Base-N Carry)
        let mut carry = true;
        for i in (0..length).rev() {
            indices[i] += 1;
            if indices[i] < charset_len {
                carry = false;
                break; // No carry needed, valid state found
            }
            indices[i] = 0; // Reset this position and carry to left
        }

        if carry {
            return;
        }
    }
}

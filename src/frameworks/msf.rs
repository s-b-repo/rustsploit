// src/frameworks/msf.rs
//
// Metasploit adapter — reads the declarative half of a Metasploit module
// (`MetasploitModule`, the `Info` block and `register_options`) and turns it
// into the common [`Template`] model.
//
// A Metasploit module's *body* is Ruby that talks to the framework's own
// socket/transport layer, so it cannot be executed natively here. What can be
// carried over is everything declarative: name, description, authors,
// references, disclosure date, rank, default port and the option set. The
// shared generator ([`super::generate`]) turns that into a RustSploit module
// with the same prompts and port defaults, so the operator only has to fill
// in the probe.

use std::path::Path;

use anyhow::Result;

use super::{FrameworkAdapter, Protocol, Severity, Template, TemplateOption};

/// The Metasploit adapter.
pub static MSF: MsfAdapter = MsfAdapter;

/// Adapter for Metasploit Framework `.rb` modules.
pub struct MsfAdapter;

impl FrameworkAdapter for MsfAdapter {
    fn id(&self) -> &'static str {
        "msf"
    }

    fn display_name(&self) -> &'static str {
        "Metasploit Framework"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["rb"]
    }

    fn sniff(&self, source: &str, _path: &Path) -> bool {
        let has_class = source.contains("MetasploitModule") || source.contains("Msf::Exploit");
        let has_info = source.contains("'Name'") || source.contains("'Description'");
        has_class && has_info
    }

    fn parse(&self, source: &str, path: &Path) -> Result<Template> {
        let meta = extract_msf_meta(source, path);
        let severity = match meta.rank.as_str() {
            "Excellent" => Severity::Critical,
            "Great" => Severity::High,
            "Good" => Severity::Medium,
            _ => Severity::Info,
        };
        Ok(Template {
            framework: "msf".to_string(),
            name: meta.name,
            description: meta.description,
            authors: meta.authors,
            references: meta.references,
            tags: Vec::new(),
            severity,
            disclosure_date: meta.disclosure_date,
            default_port: meta.default_port,
            category: "exploits".to_string(),
            options: meta.options,
            protocol: Protocol::None,
            http_based: false,
        })
    }
}

/// Extracted metadata from a Metasploit module's `initialize` / `Info` block.
#[derive(Debug, Default)]
pub struct MsfMeta {
    /// `Name`
    pub name: String,
    /// `Description`
    pub description: String,
    /// `Author`
    pub authors: Vec<String>,
    /// `References`
    pub references: Vec<String>,
    /// `DisclosureDate`
    pub disclosure_date: Option<String>,
    /// `Rank`
    pub rank: String,
    /// `DefaultOptions` / `Opt::RPORT`
    pub default_port: Option<u16>,
    /// `register_options(...)`
    pub options: Vec<TemplateOption>,
}

/// Extract the declarative metadata of a Metasploit module.
///
/// A line scanner rather than a Ruby parser: it covers the standard module
/// layout, and anything exotic produces an incomplete template (never a
/// wrong one) — the generator still emits a compilable module.
pub fn extract_msf_meta(source: &str, module_path: &Path) -> MsfMeta {
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
        meta.name = module_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
    }

    meta
}

fn extract_single_quoted(line: &str, key: &str) -> Option<String> {
    let prefix = format!("'{key}'");
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
    let prefix = format!("'{key}'");
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
                "CVE" => refs.push(format!("CVE-{value}")),
                "BID" => refs.push(format!("BID-{value}")),
                "OSVDB" => refs.push(format!("OSVDB-{value}")),
                "URL" => refs.push(value.to_string()),
                _ => refs.push(format!("{ref_type}: {value}")),
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
        if let Some(rport) = part.split("RPORT").nth(1)
            && let Some(val) = rport.split("=>").nth(1)
            && let Ok(port) = val.trim().trim_matches('\'').trim_matches('"').parse()
        {
            return Some(port);
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
        let Some(rest) = collector.split(&format!("Opt::{opt}")).nth(1) else {
            continue;
        };
        let trimmed = rest.trim();
        // Extract the default value in parentheses
        let Some(paren_start) = trimmed.find('(') else {
            continue;
        };
        let after_paren = &trimmed[paren_start + 1..];
        let Some(paren_end) = after_paren.find(')') else {
            continue;
        };
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
                meta.options.push(TemplateOption {
                    name: rustsploit_name(opt).to_string(),
                    default: val.to_string(),
                    description: msf_option_description(opt),
                    required: matches!(opt, "RHOST" | "RHOSTS"),
                });
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
        other => format!("{other} (from MSF)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULE: &str = r#"
require 'msf/core/exploit'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  def initialize
    super
    update_info(
      'Name' => 'Example Webshell Upload',
      'Description' => %q|
        Uploads a web shell to the target.
      |,
      'Author' => ['alice', 'bob'],
      'References' => [
        ['CVE', '2024-12345'],
        ['URL', 'https://example.com/advisory']
      ],
      'DisclosureDate' => '2024-05-01',
      'DefaultOptions' => { 'RPORT' => 8080 }
    )

    register_options(
      Opt::RPORT(8080),
      Opt::RHOSTS,
      Opt::THREADS(5),
      Opt::URIPATH('/upload')
    )
  end
end
"#;

    #[test]
    fn metadata_is_extracted() {
        let tmpl = MSF
            .parse(MODULE, Path::new("exploit.rb"))
            .expect("msf module should parse");
        assert_eq!(tmpl.name, "Example Webshell Upload");
        assert_eq!(tmpl.authors, vec!["alice", "bob"]);
        assert_eq!(tmpl.default_port, Some(8080));
        assert_eq!(tmpl.disclosure_date.as_deref(), Some("2024-05-01"));
        assert_eq!(tmpl.severity, Severity::Critical);
        assert!(tmpl.references.iter().any(|r| r == "CVE-2024-12345"));
        assert!(
            tmpl.references
                .iter()
                .any(|r| r == "https://example.com/advisory")
        );
    }

    #[test]
    fn options_are_carried_over() {
        let tmpl = MSF
            .parse(MODULE, Path::new("exploit.rb"))
            .expect("msf module should parse");
        let names: Vec<&str> = tmpl.options.iter().map(|o| o.name.as_str()).collect();
        assert!(names.contains(&"target"));
        assert!(names.contains(&"concurrency"));
        assert!(names.contains(&"custom"));
    }

    #[test]
    fn a_module_is_recognised() {
        assert!(MSF.sniff(MODULE, Path::new("exploit.rb")));
        assert!(!MSF.sniff("print('hello')", Path::new("x.rb")));
    }
}

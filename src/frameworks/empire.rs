// src/frameworks/empire.rs
//
// PowerShell Empire adapter.
//
// Empire "modules" are Python launcher classes (`class Invoke-XXX:`) whose
// body is PowerShell executed through an agent — not reproducible natively.
// What is carried over is the declarative metadata: the class name, the
// author, the description and the references, which the shared generator
// turns into a RustSploit module scaffold.

use std::path::Path;

use anyhow::Result;

use super::{FrameworkAdapter, Protocol, Severity, Template, TemplateOption};

/// The Empire adapter.
pub static EMPIRE: EmpireAdapter = EmpireAdapter;

/// Adapter for PowerShell Empire launcher modules.
pub struct EmpireAdapter;

impl FrameworkAdapter for EmpireAdapter {
    fn id(&self) -> &'static str {
        "empire"
    }

    fn display_name(&self) -> &'static str {
        "PowerShell Empire"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["py"]
    }

    fn sniff(&self, source: &str, _: &Path) -> bool {
        let has_class = source.contains("class Invoke-") || source.contains("class Get-");
        let has_author = source.contains("Author") || source.contains("author");
        has_class && has_author
    }

    fn parse(&self, source: &str, path: &Path) -> Result<Template> {
        let mut name = String::new();
        let mut description = String::new();
        let mut authors: Vec<String> = Vec::new();
        let mut references: Vec<String> = Vec::new();

        for line in source.lines() {
            let t = line.trim();
            if t.starts_with("class ") && name.is_empty() {
                // class Invoke-Shellcode:
                let class_name = t
                    .trim_start_matches("class ")
                    .split([':', ' ', '('])
                    .next()
                    .unwrap_or("")
                    .trim();
                if !class_name.is_empty() {
                    name = class_name.to_string();
                }
                continue;
            }
            if let Some(v) = quoted_value(t, "Author") {
                authors.push(v);
            }
            if let Some(v) = quoted_value(t, "Description") {
                description = v;
            }
            if let Some(v) = quoted_value(t, "Info") {
                if description.is_empty() {
                    description = v;
                }
            }
            if let Some(v) = quoted_value(t, "Reference") {
                references.push(v);
            }
        }

        if name.is_empty() {
            name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("empire_module")
                .to_string();
        }
        if description.is_empty() {
            description = format!("Empire launcher '{name}' — body requires manual port.");
        }

        Ok(Template {
            framework: "empire".to_string(),
            name,
            description,
            authors,
            references,
            tags: Vec::new(),
            severity: Severity::Info,
            disclosure_date: None,
            default_port: None,
            category: "exploits".to_string(),
            options: vec![TemplateOption::new(
                "listener",
                "http",
                "Empire listener to bind the launcher to",
            )],
            protocol: Protocol::None,
            http_based: false,
        })
    }
}

/// Pull `Key = 'value'` / `Key: 'value'` out of a line. The key may itself be
/// quoted (`'Key'`) and the value may sit inside a `[ ... ]` list, as in a
/// Python `self.info` dict — so locate the `:`/`=` separator first, then take
/// the first quoted string after it.
fn quoted_value(line: &str, key: &str) -> Option<String> {
    let idx = line.find(key)?;
    let rest = line.get(idx + key.len()..)?;
    let sep = rest.find([':', '='])?;
    let after_sep = rest.get(sep + 1..)?;
    let open = after_sep.find(['"', '\''])?;
    let value = after_sep.get(open + 1..)?;
    let end = value.find(['"', '\''])?;
    let v = value.get(..end)?.trim();
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAUNCHER: &str = r#"
class Invoke-Shellcode:
    def __init__(self):
        self.info = {
            'Name': 'Invoke-Shellcode',
            'Author': ['[@darklogin]'],
            'Description': 'Launches shellcode from a remote URL.',
            'Reference': ['https://example.com'],
        }
"#;

    #[test]
    fn launcher_metadata_is_extracted() {
        let tmpl = EMPIRE
            .parse(LAUNCHER, Path::new("invoke_shellcode.py"))
            .expect("empire module should parse"); // audit-allow: test
        assert_eq!(tmpl.name, "Invoke-Shellcode"); // audit-allow: test
        assert_eq!(tmpl.description, "Launches shellcode from a remote URL."); // audit-allow: test
        assert_eq!(tmpl.authors, vec!["[@darklogin]".to_string()]); // audit-allow: test
        assert_eq!(tmpl.references, vec!["https://example.com".to_string()]); // audit-allow: test
    }

    #[test]
    fn launcher_is_recognised() {
        assert!(EMPIRE.sniff(LAUNCHER, Path::new("x.py"))); // audit-allow: test
        assert!(!EMPIRE.sniff("import os", Path::new("x.py"))); // audit-allow: test
    }
}

// src/frameworks/cobaltstrike.rs
//
// Cobalt Strike adapter.
//
// A `.cna` aggressor script is a Squirrel-language DSL whose behaviour lives
// in callbacks (`on ready`, `on message_received`, `on beacon_http_response`)
// — not reproducible natively. The adapter reads the script's descriptive
// metadata so the script can still be catalogued and turned into a module
// scaffold.

use std::path::Path;

use anyhow::Result;

use super::{FrameworkAdapter, Protocol, Severity, Template, TemplateOption};

/// The Cobalt Strike adapter.
pub static COBALTSTRIKE: CobaltStrikeAdapter = CobaltStrikeAdapter;

/// Adapter for Cobalt Strike `.cna` aggressor scripts.
pub struct CobaltStrikeAdapter;

impl FrameworkAdapter for CobaltStrikeAdapter {
    fn id(&self) -> &'static str {
        "cobaltstrike"
    }

    fn display_name(&self) -> &'static str {
        "Cobalt Strike"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["cna"]
    }

    fn sniff(&self, source: &str, _path: &Path) -> bool {
        let has_beacon = source.contains("on ready") || source.contains("on message_received");
        let has_squirrel = source.contains("set") || source.contains("data ");
        has_beacon && has_squirrel
    }

    fn parse(&self, source: &str, path: &Path) -> Result<Template> {
        let mut name = String::new();
        let mut description = String::new();
        let mut authors: Vec<String> = Vec::new();

        for line in source.lines() {
            let t = line.trim();
            if name.is_empty()
                && let Some(v) = quoted_value(t, "name")
            {
                name = v;
            }
            if description.is_empty()
                && let Some(v) = quoted_value(t, "description")
            {
                description = v;
            }
            if authors.is_empty()
                && let Some(v) = quoted_value(t, "author")
            {
                authors.push(v);
            }
        }

        if name.is_empty() {
            name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("aggressor_script")
                .to_string();
        }
        if description.is_empty() {
            description = format!(
                "Cobalt Strike aggressor script '{name}' — the callback body requires a manual port."
            );
        }

        Ok(Template {
            framework: "cobaltstrike".to_string(),
            name,
            description,
            authors,
            references: Vec::new(),
            tags: Vec::new(),
            severity: Severity::Info,
            disclosure_date: None,
            default_port: None,
            category: "post".to_string(),
            options: vec![TemplateOption::new(
                "beacon",
                "",
                "Beacon session the script attaches to",
            )],
            protocol: Protocol::None,
            http_based: false,
        })
    }
}

/// Pull `name = "value"` / `name: "value"` out of a Squirrel assignment.
fn quoted_value(line: &str, key: &str) -> Option<String> {
    let idx = line.find(key)?;
    let rest = &line[idx + key.len()..];
    let rest = rest.trim_start();
    let rest = rest.trim_start_matches(['=', ':']).trim_start();
    let value = rest.trim_start_matches(['"', '\'']);
    let end = value.find(['"', '\''])?;
    let v = value[..end].trim();
    if v.is_empty() { None } else { Some(v.to_string()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCRIPT: &str = r#"
        name = "Demo Aggressor"
        description = "Does a demo thing on beacon"
        author = "operator"
        on ready {
            println("ready");
        }
"#;

    #[test]
    fn script_metadata_is_extracted() {
        let tmpl = COBALTSTRIKE
            .parse(SCRIPT, Path::new("demo.cna"))
            .expect("aggressor script should parse");
        assert_eq!(tmpl.name, "Demo Aggressor");
        assert_eq!(tmpl.description, "Does a demo thing on beacon");
        assert_eq!(tmpl.authors, vec!["operator".to_string()]);
    }

    #[test]
    fn script_is_recognised() {
        assert!(COBALTSTRIKE.sniff(SCRIPT, Path::new("x.cna")));
        assert!(!COBALTSTRIKE.sniff("print(1)", Path::new("x.cna")));
    }
}

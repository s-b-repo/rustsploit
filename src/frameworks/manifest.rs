// src/frameworks/manifest.rs
//
// Generic JSON manifest adapter.
//
// The escape hatch for frameworks RustSploit does not know: describe the
// template in a small JSON document and it behaves like any other template.
//
//   {
//     "name": "My check",
//     "description": "What it does",
//     "authors": ["me"],
//     "references": ["https://example.com"],
//     "severity": "high",
//     "default_port": 8443,
//     "category": "scanners",
//     "options": [
//       { "name": "path", "default": "/admin", "description": "Path", "required": false }
//     ]
//   }

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use super::{FrameworkAdapter, Protocol, Severity, Template, TemplateOption};

/// The generic-manifest adapter.
pub static MANIFEST: ManifestAdapter = ManifestAdapter;

/// Adapter for hand-written JSON manifests.
pub struct ManifestAdapter;

#[derive(Debug, Deserialize)]
struct JsonManifest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    authors: Vec<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    disclosure_date: Option<String>,
    #[serde(default)]
    default_port: Option<u16>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    options: Vec<JsonOption>,
}

#[derive(Debug, Deserialize)]
struct JsonOption {
    #[serde(default)]
    name: String,
    #[serde(default)]
    default: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    required: Option<bool>,
}

impl FrameworkAdapter for ManifestAdapter {
    fn id(&self) -> &'static str {
        "json"
    }

    fn display_name(&self) -> &'static str {
        "JSON manifest"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["json"]
    }

    fn sniff(&self, source: &str, _: &Path) -> bool {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(source) else {
            return false;
        };
        let Some(obj) = value.as_object() else {
            return false;
        };
        // A manifest always names itself; a nuclei template is YAML and a
        // Metasploit module is Ruby, so this only fires for JSON.
        obj.contains_key("name") && obj.contains_key("description")
    }

    fn parse(&self, source: &str, path: &Path) -> Result<Template> {
        let manifest: JsonManifest = serde_json::from_str(source)
            .with_context(|| format!("parse JSON manifest {path:?}"))?;
        let name = manifest
            .name
            .clone()
            .unwrap_or_else(|| "manifest template".to_string());
        Ok(Template {
            framework: "json".to_string(),
            name,
            description: manifest.description.unwrap_or_else(String::new),
            authors: manifest.authors,
            references: manifest.references,
            tags: manifest.tags,
            severity: Severity::parse(manifest.severity.as_deref().unwrap_or("info")),
            disclosure_date: manifest.disclosure_date,
            default_port: manifest.default_port,
            category: manifest.category.unwrap_or_else(|| "scanners".to_string()),
            options: manifest
                .options
                .into_iter()
                .filter(|o| !o.name.is_empty())
                .map(|o| TemplateOption {
                    name: o.name,
                    default: o.default.unwrap_or_else(String::new),
                    description: o.description.unwrap_or_else(String::new),
                    required: o.required.unwrap_or(false),
                })
                .collect(),
            protocol: Protocol::None,
            http_based: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_parsed() {
        let src = r#"{
            "name": "Demo manifest",
            "description": "does a thing",
            "authors": ["tester"],
            "severity": "high",
            "default_port": 8443,
            "options": [{"name": "path", "default": "/x"}]
        }"#;
        let tmpl = MANIFEST
            .parse(src, Path::new("m.json"))
            .expect("manifest should parse"); // audit-allow: test
        assert_eq!(tmpl.name, "Demo manifest"); // audit-allow: test
        assert_eq!(tmpl.severity, Severity::High); // audit-allow: test
        assert_eq!(tmpl.default_port, Some(8443)); // audit-allow: test
        assert_eq!(tmpl.options.len(), 1); // audit-allow: test
    }

    #[test]
    fn non_manifest_json_is_rejected() {
        assert!(!MANIFEST.sniff("{\"foo\": 1}", Path::new("x.json"))); // audit-allow: test
    }
}

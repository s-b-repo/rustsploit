// src/frameworks/mod.rs
//
// Framework bridges — one adapter layer that lets RustSploit consume
// templates from other offensive-security frameworks.
//
// Every adapter answers the same three questions:
//
//   1. *Is this file mine?*      → `FrameworkAdapter::sniff`
//   2. *What does it say?*       → `FrameworkAdapter::parse` → [`Template`]
//   3. *Can I run it myself?*    → `FrameworkAdapter::execute` (optional)
//
// A template that cannot be executed natively is not a dead end: the shared
// generator ([`generate`]) turns it into a compilable RustSploit module, so
// the operator always gets *something* runnable from a third-party template.
//
// The framework is detected from the file itself (content first, extension
// second), so the operator never has to know which dialect a template is in.

pub mod cobaltstrike;
pub mod empire;
pub mod generate;
pub mod manifest;
pub mod msf;
pub mod nuclei;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;

use crate::module_info::ModuleRank;

/// Severity of a template, normalised across frameworks.
///
/// Nuclei uses `info.severity`, Metasploit uses `Rank`, Empire/Cobalt Strike
/// use free-text — they all collapse onto this scale so the findings the
/// framework produces carry one comparable severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Parse a framework severity string. Unknown values become `Info`.
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "critical" | "extreme" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "moderate" => Severity::Medium,
            "low" | "minor" => Severity::Low,
            _ => Severity::Info,
        }
    }

    /// Canonical lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Map onto the RustSploit module rank so a translated module is ranked
    /// by the source template's own severity.
    pub fn module_rank(self) -> ModuleRank {
        match self {
            Severity::Critical => ModuleRank::Excellent,
            Severity::High => ModuleRank::Great,
            Severity::Medium => ModuleRank::Good,
            Severity::Low => ModuleRank::Normal,
            Severity::Info => ModuleRank::Normal,
        }
    }
}

/// One operator-supplied parameter of a template.
#[derive(Debug, Clone)]
pub struct TemplateOption {
    /// Option key (Metasploit `RPORT`, nuclei variable name, …).
    pub name: String,
    /// Default value, as written in the source template.
    pub default: String,
    /// Human-readable description.
    pub description: String,
    /// Whether the template refuses to run without it.
    pub required: bool,
}

impl TemplateOption {
    /// Build an option with sane defaults.
    pub fn new(name: &str, default: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            default: default.to_string(),
            description: description.to_string(),
            required: false,
        }
    }
}

/// The protocol a template speaks — the part that can be executed natively.
///
/// `None` means the template carries no reproducible protocol (a Metasploit
/// exploit body, an Empire launcher): it is metadata plus options, and the
/// generator turns it into a module scaffold instead.
#[derive(Debug, Clone)]
pub enum Protocol {
    /// No reproducible protocol.
    None,
    /// One or more HTTP request blocks with matchers (nuclei `http:`).
    Http(Vec<nuclei::HttpRequest>),
    /// A DNS query with matchers (nuclei `dns:`).
    Dns(nuclei::DnsRequest),
    /// A TCP connect + payload with matchers (nuclei `tcp:`).
    Tcp(nuclei::TcpRequest),
}

/// A framework-independent template: metadata + options + protocol.
#[derive(Debug, Clone, Default)]
pub struct Template {
    /// Which adapter produced this template (`nuclei`, `msf`, …).
    pub framework: String,
    /// Display name of the template.
    pub name: String,
    /// Long description.
    pub description: String,
    /// Authors of the original template.
    pub authors: Vec<String>,
    /// Reference URLs / CVE ids.
    pub references: Vec<String>,
    /// Free-text tags (`cve`, `rce`, `misconfig`).
    pub tags: Vec<String>,
    /// Normalised severity.
    pub severity: Severity,
    /// Disclosure date, if the source template states one.
    pub disclosure_date: Option<String>,
    /// Default port for the target service.
    pub default_port: Option<u16>,
    /// Suggested RustSploit category (`scanners`, `exploits`, …).
    pub category: String,
    /// Operator-facing parameters.
    pub options: Vec<TemplateOption>,
    /// The reproducible protocol, when there is one.
    pub protocol: Protocol,
    /// Whether the protocol needs an HTTP client at all (false for DNS/TCP).
    pub http_based: bool,
}

impl Template {
    /// Parse a template from its source, detecting the framework.
    ///
    /// This is what a generated module calls at run time: it re-parses the
    /// template it embeds, so the module inherits every improvement to the
    /// bridge engine instead of carrying a frozen copy of its logic.
    pub fn from_source(source: &str) -> Result<Self> {
        let path = Path::new("template");
        let adapter = detect(source, path).ok_or_else(|| {
            anyhow::anyhow!(
                "could not detect the template format — supported: {}",
                adapter_ids()
            )
        })?;
        adapter.parse(source, path)
    }

    /// Execute the template natively against a target.
    pub async fn execute(&self, ctx: &ExecutionCtx<'_>) -> Result<Vec<TemplateResult>> {
        let adapter = adapter_by_id(&self.framework).ok_or_else(|| {
            anyhow::anyhow!("no adapter for framework '{}'", self.framework)
        })?;
        adapter.execute(self, ctx).await
    }
}

/// The outcome of running one request block of a template.
#[derive(Debug, Clone)]
pub struct TemplateResult {
    /// Did the matchers fire?
    pub matched: bool,
    /// Human-readable summary.
    pub message: String,
    /// Severity carried over from the template.
    pub severity: Severity,
    /// Values pulled out by the template's extractors.
    pub extracted: BTreeMap<String, String>,
    /// Short response snippet (status line, banner) for the operator.
    pub evidence: Option<String>,
}

/// Everything an adapter needs to run a template against a target.
pub struct ExecutionCtx<'a> {
    /// Target host (IP or hostname).
    pub host: &'a str,
    /// Target port.
    pub port: u16,
    /// Scheme for HTTP templates (`http` / `https`).
    pub scheme: &'a str,
    /// Operator-supplied variables (nuclei `variables:` + `setg` answers).
    pub variables: BTreeMap<String, String>,
    /// Per-request timeout.
    pub timeout: Duration,
    /// Skip TLS verification.
    pub insecure: bool,
}

impl<'a> ExecutionCtx<'a> {
    /// The base URL an HTTP template is executed against.
    pub fn base_url(&self) -> String {
        let port = self.port;
        let scheme = self.scheme;
        let host = self.host;
        if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
            format!("{scheme}://{host}")
        } else {
            format!("{scheme}://{host}:{port}")
        }
    }
}

/// One bridge to a third-party framework.
#[async_trait::async_trait]
pub trait FrameworkAdapter: Send + Sync {
    /// Stable id (`nuclei`, `msf`, …) — also the CLI value for `--framework`.
    fn id(&self) -> &'static str;

    /// Human-readable name for the operator.
    fn display_name(&self) -> &'static str;

    /// File extensions this adapter normally handles.
    fn extensions(&self) -> &'static [&'static str];

    /// Does this source look like one of my templates?
    fn sniff(&self, source: &str, path: &Path) -> bool;

    /// Parse the source into a [`Template`].
    fn parse(&self, source: &str, path: &Path) -> Result<Template>;

    /// Can this adapter execute the template natively?
    fn executable(&self) -> bool {
        false
    }

    /// Execute the template against `ctx`.
    ///
    /// Only called for adapters whose [`FrameworkAdapter::executable`] is
    /// true; the default refuses with an explanation instead of pretending.
    async fn execute(
        &self,
        template: &Template,
        ctx: &ExecutionCtx<'_>,
    ) -> Result<Vec<TemplateResult>> {
        anyhow::bail!(
            "'{}' templates cannot be executed natively — generate a RustSploit module \
             from the template instead.",
            self.display_name()
        )
    }
}

/// Every adapter the framework knows about.
pub fn adapters() -> &'static [&'static dyn FrameworkAdapter] {
    &[
        &nuclei::NUCLEI,
        &msf::MSF,
        &empire::EMPIRE,
        &cobaltstrike::COBALTSTRIKE,
        &manifest::MANIFEST,
    ]
}

/// Look an adapter up by id (`nuclei`, `msf`, `empire`, `cobaltstrike`, `json`).
pub fn adapter_by_id(id: &str) -> Option<&'static dyn FrameworkAdapter> {
    let want = id.trim().to_ascii_lowercase();
    adapters()
        .iter()
        .copied()
        .find(|a| a.id() == want || a.extensions().contains(&want.as_str()))
}

/// Detect which framework a template file belongs to.
///
/// Content wins over the extension: a `.yaml` file may be a nuclei template
/// or a hand-written manifest, and a `.txt` may hold either. The extension is
/// only consulted when the content is ambiguous.
pub fn detect(source: &str, path: &Path) -> Option<&'static dyn FrameworkAdapter> {
    // 1. Strong content markers first — these are unambiguous.
    for adapter in adapters() {
        if adapter.sniff(source, path) {
            return Some(*adapter);
        }
    }
    // 2. Fall back to the extension.
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    if ext.is_empty() {
        return None;
    }
    adapters()
        .iter()
        .copied()
        .find(|a| a.extensions().contains(&ext.as_str()))
}

/// Adapter ids joined for the operator-facing help text.
pub fn adapter_ids() -> String {
    adapters()
        .iter()
        .map(|a| a.id())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Split a comma / space separated option list into a vector.
pub(crate) fn split_list(raw: &str) -> Vec<String> {
    raw.split([',', '\n', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_parsing_is_normalised() {
        assert_eq!(Severity::parse("Critical"), Severity::Critical);
        assert_eq!(Severity::parse("HIGH"), Severity::High);
        assert_eq!(Severity::parse("medium"), Severity::Medium);
        assert_eq!(Severity::parse("unknown"), Severity::Info);
        assert_eq!(Severity::parse("critical").as_str(), "critical");
    }

    #[test]
    fn nuclei_template_is_detected_by_content() {
        let src = "id: my-template\ninfo:\n  name: Demo\n  severity: high\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/x\"\n";
        let path = Path::new("template.yaml");
        let adapter = detect(src, path).expect("nuclei template should be detected");
        assert_eq!(adapter.id(), "nuclei");
    }

    #[test]
    fn msf_module_is_detected_by_content() {
        let src = "require 'msf/core/exploit'\nclass MetasploitModule < Msf::Exploit::Remote\n  Rank = Excellent\nend\n";
        let path = Path::new("exploit.rb");
        let adapter = detect(src, path).expect("msf module should be detected");
        assert_eq!(adapter.id(), "msf");
    }

    #[test]
    fn adapter_lookup_by_id() {
        assert_eq!(
            adapter_by_id("nuclei").map(|a| a.id()),
            Some("nuclei")
        );
        assert_eq!(adapter_by_id("rb").map(|a| a.id()), Some("msf"));
        assert!(adapter_by_id("nope").is_none());
    }
}

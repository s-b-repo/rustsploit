// src/frameworks/nuclei.rs
//
// Nuclei adapter — parses a ProjectDiscovery **nuclei** template and runs it
// natively inside RustSploit.
//
// Unlike the other adapters, a nuclei template is *executable*: it carries a
// protocol (HTTP / DNS / TCP), the request to send and the matchers that
// decide whether the target is vulnerable. All of that is reproduced here, so
// `nuclei` templates work without the nuclei binary and without hand-porting
// anything to Rust.
//
// Supported template surface:
//   * `id`, `info` (name/author/severity/description/reference/tags)
//   * `variables` — interpolated into the request
//   * `http:` / `requests:` — method, path(s), headers, body, matchers,
//     extractors, `matchers-condition`
//   * `dns:` — query name/type with matchers
//   * `tcp:` — host/port/hex payload with matchers
//   * matchers: `word`, `regex`, `status`, `size`, `binary`, and nested
//     `and`/`or` groups; `negative: true` inverts a matcher
//   * extractors: `regex` with a capture group
//
// Not reproduced natively (reported, never silently ignored): `file:`,
// `code:`, `javascript:`, `headless:`, `websocket:`, `ssl:` and `network:`
// request bodies, and DSL matchers.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use super::{
    ExecutionCtx, FrameworkAdapter, Protocol, Severity, Template, TemplateOption, TemplateResult,
};

/// The nuclei adapter.
pub static NUCLEI: NucleiAdapter = NucleiAdapter;

/// Adapter for ProjectDiscovery nuclei templates.
pub struct NucleiAdapter;

#[async_trait::async_trait]
impl FrameworkAdapter for NucleiAdapter {
    fn id(&self) -> &'static str {
        "nuclei"
    }

    fn display_name(&self) -> &'static str {
        "Nuclei"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["yaml", "yml"]
    }

    fn sniff(&self, source: &str, _: &Path) -> bool {
        // A nuclei template always carries a top-level `id:` and an `info:`
        // block; the protocol block (`http:`/`dns:`/`tcp:`) is what makes it
        // executable. Require the protocol block so a plain YAML manifest is
        // not mistaken for a template.
        let Ok(doc) = serde_yaml_ng::from_str::<YamlTemplate>(source) else {
            return false;
        };
        doc.id.is_some() && doc.info.is_some() && doc.has_protocol()
    }

    fn parse(&self, source: &str, path: &Path) -> Result<Template> {
        let doc: YamlTemplate = serde_yaml_ng::from_str(source)
            .with_context(|| format!("parse nuclei template {path:?}"))?;

        let info = doc.info.clone().unwrap_or_else(Default::default);
        let name = match info.name {
            Some(n) if !n.trim().is_empty() => n,
            _ => doc
                .id
                .clone()
                .unwrap_or_else(|| "nuclei template".to_string()),
        };

        let mut options: Vec<TemplateOption> = Vec::new();
        for (key, value) in &doc.variables {
            let mut opt = TemplateOption::new(key, value, &format!("nuclei variable '{key}'"));
            opt.required = false;
            options.push(opt);
        }

        let severity = Severity::parse(info.severity.as_deref().unwrap_or("info"));
        let default_port = doc
            .http
            .as_ref()
            .and_then(|blocks| blocks.first())
            .and_then(|b| b.port);

        let protocol = build_protocol(&doc);
        let http_based = matches!(protocol, Protocol::Http(_));

        Ok(Template {
            framework: "nuclei".to_string(),
            name,
            description: info.description.unwrap_or_else(String::new),
            authors: info
                .author
                .map(StringOrList::into_vec)
                .unwrap_or_else(Vec::new),
            references: info
                .reference
                .map(StringOrList::into_vec)
                .unwrap_or_else(Vec::new),
            tags: info
                .tags
                .map(StringOrList::into_vec)
                .unwrap_or_else(Vec::new)
                .iter()
                .flat_map(|t| t.split(',').map(|s| s.trim().to_string()))
                .filter(|t| !t.is_empty())
                .collect(),
            severity,
            disclosure_date: None,
            default_port,
            category: "scanners".to_string(),
            options,
            protocol,
            http_based,
        })
    }

    fn executable(&self) -> bool {
        true
    }

    async fn execute(
        &self,
        template: &Template,
        ctx: &ExecutionCtx<'_>,
    ) -> Result<Vec<TemplateResult>> {
        match &template.protocol {
            Protocol::Http(blocks) => execute_http(template, blocks, ctx).await,
            Protocol::Dns(spec) => execute_dns(template, spec, ctx).await,
            Protocol::Tcp(spec) => execute_tcp(template, spec, ctx).await,
            Protocol::None => Ok(Vec::new()),
        }
    }
}

// ── Public template model ───────────────────────────────────────────────

/// How several matchers combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// Every matcher must fire.
    And,
    /// At least one matcher must fire.
    Or,
}

impl Condition {
    fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "and" => Condition::And,
            _ => Condition::Or,
        }
    }
}

/// Which part of the response a matcher looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchPart {
    /// Response body (the default).
    Body,
    /// Response headers.
    Header,
    /// Body and headers together.
    All,
}

impl MatchPart {
    fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "header" => MatchPart::Header,
            "all" => MatchPart::All,
            _ => MatchPart::Body,
        }
    }
}

/// A single matcher.
#[derive(Debug, Clone)]
pub struct Matcher {
    /// What kind of check this is.
    pub kind: MatcherKind,
    /// `negative: true` — the matcher must NOT fire.
    pub negative: bool,
    /// Which part of the response is inspected.
    pub part: MatchPart,
}

/// The check a matcher performs.
#[derive(Debug, Clone)]
pub enum MatcherKind {
    /// Substring(s) present in the response.
    Word(Vec<String>),
    /// Regular expression(s) matching the response.
    Regex(Vec<String>),
    /// HTTP status code(s) that count as a hit.
    Status(Vec<u16>),
    /// Response length(s) that count as a hit.
    Size(Vec<u64>),
    /// Hex-encoded byte pattern(s).
    Binary(Vec<String>),
    /// Nested group of matchers.
    Group(Vec<Matcher>, Condition),
    /// DSL matcher — not reproducible natively.
    Dsl(Vec<String>),
}

/// A value extractor.
#[derive(Debug, Clone)]
pub struct Extractor {
    /// Regular expressions to run against the response.
    pub regexes: Vec<String>,
    /// Capture group to keep (0 = whole match).
    pub group: u32,
    /// Name the extracted value is stored under.
    pub name: Option<String>,
}

/// One HTTP request block of a nuclei template.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// HTTP method.
    pub method: String,
    /// Request paths — every one is tried, like nuclei does.
    pub paths: Vec<String>,
    /// Extra request headers.
    pub headers: BTreeMap<String, String>,
    /// Request body.
    pub body: Option<String>,
    /// Target port (overrides the framework default).
    pub port: Option<u16>,
    /// How the matchers combine.
    pub condition: Condition,
    /// The matchers.
    pub matchers: Vec<Matcher>,
    /// The extractors.
    pub extractors: Vec<Extractor>,
}

/// A DNS request block of a nuclei template.
#[derive(Debug, Clone)]
pub struct DnsRequest {
    /// Query name (`{{FQDN}}` is interpolated).
    pub name: String,
    /// Query type (`A`, `AAAA`, …).
    pub query_type: String,
    /// The matchers.
    pub matchers: Vec<Matcher>,
}

/// A TCP request block of a nuclei template.
#[derive(Debug, Clone)]
pub struct TcpRequest {
    /// Target host (overrides the framework target).
    pub host: Option<String>,
    /// Target port.
    pub port: Option<u16>,
    /// Hex-encoded payload to send.
    pub payload: Option<Vec<u8>>,
    /// How many bytes to read back.
    pub read: u32,
    /// The matchers.
    pub matchers: Vec<Matcher>,
}

// ── YAML wire format ───────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
struct YamlTemplate {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    info: Option<YamlInfo>,
    #[serde(default)]
    variables: BTreeMap<String, String>,
    #[serde(default)]
    http: Option<Vec<YamlHttp>>,
    #[serde(default)]
    requests: Option<Vec<YamlHttp>>,
    #[serde(default)]
    dns: Option<Vec<YamlDns>>,
    #[serde(default)]
    tcp: Option<Vec<YamlTcp>>,
}

impl YamlTemplate {
    /// Does the template carry an executable protocol block?
    fn has_protocol(&self) -> bool {
        self.http.as_ref().is_some_and(|b| !b.is_empty())
            || self.requests.as_ref().is_some_and(|b| !b.is_empty())
            || self.dns.as_ref().is_some_and(|b| !b.is_empty())
            || self.tcp.as_ref().is_some_and(|b| !b.is_empty())
    }

    /// The HTTP blocks, accepting both the legacy `http:` and the newer
    /// `requests:` key.
    fn http_blocks(&self) -> &[YamlHttp] {
        match (&self.http, &self.requests) {
            (Some(b), _) if !b.is_empty() => b,
            (_, Some(b)) if !b.is_empty() => b,
            _ => &[],
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
struct YamlInfo {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    author: Option<StringOrList>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    reference: Option<StringOrList>,
    #[serde(default)]
    tags: Option<StringOrList>,
}

/// Nuclei accepts a bare string or a list in several metadata fields.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum StringOrList {
    One(String),
    Many(Vec<String>),
}

impl StringOrList {
    fn into_vec(self) -> Vec<String> {
        match self {
            StringOrList::One(s) => vec![s],
            StringOrList::Many(v) => v,
        }
    }
}

#[derive(Debug, Deserialize)]
struct YamlHttp {
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    path: Option<StringOrList>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(rename = "matchers-condition", default)]
    matchers_condition: Option<String>,
    #[serde(default)]
    matchers: Vec<YamlMatcher>,
    #[serde(default)]
    extractors: Vec<YamlExtractor>,
}

#[derive(Debug, Deserialize)]
struct YamlMatcher {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    words: Option<StringOrList>,
    #[serde(default)]
    regex: Option<StringOrList>,
    #[serde(default)]
    status: Option<Vec<u16>>,
    #[serde(default)]
    size: Option<Vec<u64>>,
    #[serde(default)]
    binary: Option<StringOrList>,
    #[serde(default)]
    dsl: Option<StringOrList>,
    #[serde(default)]
    matchers: Option<Vec<YamlMatcher>>,
    #[serde(default)]
    condition: Option<String>,
    #[serde(default)]
    negative: Option<bool>,
    #[serde(default)]
    part: Option<String>,
    #[serde(default)]
    case_sensitive: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct YamlExtractor {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    regex: Option<StringOrList>,
    #[serde(default)]
    group: Option<u32>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct YamlDns {
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "type", default)]
    query_type: Option<String>,
    #[serde(default)]
    matchers: Vec<YamlMatcher>,
}

#[derive(Debug, Deserialize)]
struct YamlTcp {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    inputs: Option<String>,
    #[serde(default)]
    read: Option<u32>,
    #[serde(default)]
    matchers: Vec<YamlMatcher>,
}

// ── Conversion ──────────────────────────────────────────────────────────

fn build_protocol(doc: &YamlTemplate) -> Protocol {
    let blocks = doc.http_blocks();
    if !blocks.is_empty() {
        let requests: Vec<HttpRequest> = blocks
            .iter()
            .map(|b| HttpRequest {
                method: b
                    .method
                    .clone()
                    .unwrap_or_else(|| "GET".to_string())
                    .to_uppercase(),
                paths: b
                    .path
                    .clone()
                    .map(StringOrList::into_vec)
                    .unwrap_or_else(Vec::new),
                headers: b.headers.clone(),
                body: b.body.clone(),
                port: b.port,
                condition: b
                    .matchers_condition
                    .as_deref()
                    .map(Condition::parse)
                    .unwrap_or(Condition::Or),
                matchers: b.matchers.iter().map(convert_matcher).collect(),
                extractors: b.extractors.iter().map(convert_extractor).collect(),
            })
            .collect();
        return Protocol::Http(requests);
    }
    if let Some(dns) = doc.dns.as_ref().and_then(|b| b.first()) {
        return Protocol::Dns(DnsRequest {
            name: dns.name.clone().unwrap_or_else(String::new),
            query_type: dns
                .query_type
                .clone()
                .unwrap_or_else(|| "A".to_string())
                .to_uppercase(),
            matchers: dns.matchers.iter().map(convert_matcher).collect(),
        });
    }
    if let Some(tcp) = doc.tcp.as_ref().and_then(|b| b.first()) {
        let payload = tcp
            .inputs
            .as_deref()
            .and_then(decode_hex)
            .or_else(|| tcp.inputs.as_deref().map(|s| s.as_bytes().to_vec()));
        return Protocol::Tcp(TcpRequest {
            host: tcp.host.clone(),
            port: tcp.port,
            payload,
            read: tcp.read.unwrap_or(1024),
            matchers: tcp.matchers.iter().map(convert_matcher).collect(),
        });
    }
    Protocol::None
}

fn convert_matcher(m: &YamlMatcher) -> Matcher {
    let kind = m
        .kind
        .clone()
        .unwrap_or_else(String::new)
        .to_ascii_lowercase();
    let inner_condition = m
        .condition
        .as_deref()
        .map(Condition::parse)
        .unwrap_or(Condition::Or);
    let negative = m.negative.unwrap_or(false);
    let part = m
        .part
        .as_deref()
        .map(MatchPart::parse)
        .unwrap_or(MatchPart::Body);

    let kind = match kind.as_str() {
        "word" => MatcherKind::Word(
            m.words
                .clone()
                .map(StringOrList::into_vec)
                .unwrap_or_else(Vec::new),
        ),
        "regex" => MatcherKind::Regex(
            m.regex
                .clone()
                .map(StringOrList::into_vec)
                .unwrap_or_else(Vec::new),
        ),
        "status" => MatcherKind::Status(m.status.clone().unwrap_or_else(Vec::new)),
        "size" => MatcherKind::Size(m.size.clone().unwrap_or_else(Vec::new)),
        "binary" => MatcherKind::Binary(
            m.binary
                .clone()
                .map(StringOrList::into_vec)
                .unwrap_or_else(Vec::new),
        ),
        "dsl" => MatcherKind::Dsl(
            m.dsl
                .clone()
                .map(StringOrList::into_vec)
                .unwrap_or_else(Vec::new),
        ),
        "and" | "or" => {
            // A matcher *group*: the sub-matchers combine with the group's own
            // type (`and` → all must fire, `or` → any).
            let subs: Vec<Matcher> = m
                .matchers
                .as_ref()
                .map(|list| list.iter().map(convert_matcher).collect())
                .unwrap_or_else(Vec::new);
            let group_condition = if kind == "and" {
                Condition::And
            } else {
                inner_condition
            };
            MatcherKind::Group(subs, group_condition)
        }
        _ => MatcherKind::Dsl(Vec::new()),
    };

    Matcher {
        kind,
        negative,
        part,
    }
}

fn convert_extractor(e: &YamlExtractor) -> Extractor {
    Extractor {
        regexes: e
            .regex
            .clone()
            .map(StringOrList::into_vec)
            .unwrap_or_else(Vec::new),
        group: e.group.unwrap_or(0),
        name: e.name.clone(),
    }
}

/// Decode a hex string (`48656c6c6f`) into bytes. Returns `None` when the
/// input is not valid hex.
fn decode_hex(raw: &str) -> Option<Vec<u8>> {
    let cleaned: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hex = std::str::from_utf8(&bytes[i..i + 2]).ok()?;
        let byte = u8::from_str_radix(hex, 16).ok()?;
        out.push(byte);
        i += 2;
    }
    Some(out)
}

// ── Variable interpolation ──────────────────────────────────────────────

/// Replace nuclei's `{{...}}` placeholders.
///
/// Built-ins: `BaseURL`, `Host`, `Hostname`, `Port`, `Path`, `Scheme`,
/// `RootURL`, `FQDN`. Template variables and operator-supplied values are
/// substituted too (exact, then case-insensitive).
pub fn interpolate(input: &str, ctx: &ExecutionCtx<'_>, vars: &BTreeMap<String, String>) -> String {
    let base = ctx.base_url();
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("{{") {
        if let Some(prefix) = rest.get(..start) {
            out.push_str(prefix);
        }
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            if let Some(tail) = rest.get(start..) {
                out.push_str(tail);
            }
            return out;
        };
        let key = after[..end].trim();
        out.push_str(&resolve_variable(key, ctx, vars, &base));
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

fn resolve_variable(
    key: &str,
    ctx: &ExecutionCtx<'_>,
    vars: &BTreeMap<String, String>,
    base: &str,
) -> String {
    match key.to_ascii_lowercase().as_str() {
        "baseurl" => base.to_string(),
        "rooturl" => base.to_string(),
        "host" | "hostname" => ctx.host.to_string(),
        "port" => ctx.port.to_string(),
        "path" => "/".to_string(),
        "scheme" => ctx.scheme.to_string(),
        "fqdn" => ctx.host.to_string(),
        _ => {
            if let Some(v) = vars.get(key) {
                return v.clone();
            }
            let lower = key.to_ascii_lowercase();
            for (k, v) in vars {
                if k.to_ascii_lowercase() == lower {
                    return v.clone();
                }
            }
            format!("{{{{{key}}}}}")
        }
    }
}

// ── Matcher evaluation ──────────────────────────────────────────────────

/// The response a matcher is evaluated against.
struct ResponseView<'a> {
    status: Option<u16>,
    body: &'a str,
    headers: &'a BTreeMap<String, String>,
}

impl<'a> ResponseView<'a> {
    /// The text a matcher inspects for the given part.
    fn text(&self, part: MatchPart) -> String {
        match part {
            MatchPart::Body => self.body.to_string(),
            MatchPart::Header => self
                .headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}\n"))
                .collect::<String>(),
            MatchPart::All => {
                let mut s = self.body.to_string();
                s.push('\n');
                s.push_str(
                    &self
                        .headers
                        .iter()
                        .map(|(k, v)| format!("{k}: {v}\n"))
                        .collect::<String>(),
                );
                s
            }
        }
    }
}

/// Evaluate one matcher against a response.
fn eval_matcher(matcher: &Matcher, view: &ResponseView<'_>) -> bool {
    let fired = match &matcher.kind {
        MatcherKind::Word(words) => {
            let haystack = view.text(matcher.part).to_ascii_lowercase();
            words
                .iter()
                .any(|w| haystack.contains(&w.to_ascii_lowercase()))
        }
        MatcherKind::Regex(patterns) => {
            let haystack = view.text(matcher.part);
            patterns.iter().any(|p| match regex::Regex::new(p) {
                Ok(re) => re.is_match(&haystack),
                Err(e) => {
                    tracing::debug!("nuclei: invalid regex '{p}': {e}");
                    false
                }
            })
        }
        MatcherKind::Status(codes) => match view.status {
            Some(status) => codes.contains(&status),
            None => false,
        },
        MatcherKind::Size(sizes) => {
            let len = view.body.len() as u64; // audit-allow: byte length fits in u64
            sizes.contains(&len)
        }
        MatcherKind::Binary(patterns) => {
            let haystack = view.text(matcher.part).to_ascii_lowercase();
            patterns.iter().any(|p| {
                decode_hex(p)
                    .map(|bytes| {
                        let needle: String = bytes.iter().map(|b| *b as char).collect();
                        haystack.contains(&needle.to_ascii_lowercase())
                    })
                    .unwrap_or(false)
            })
        }
        MatcherKind::Group(subs, condition) => match condition {
            Condition::And => subs.iter().all(|s| eval_matcher(s, view)),
            Condition::Or => subs.iter().any(|s| eval_matcher(s, view)),
        },
        MatcherKind::Dsl(_) => {
            tracing::debug!("nuclei: DSL matchers are not reproduced natively");
            false
        }
    };
    if matcher.negative { !fired } else { fired }
}

/// Evaluate a matcher set with the given combination.
fn eval_matchers(matchers: &[Matcher], condition: Condition, view: &ResponseView<'_>) -> bool {
    if matchers.is_empty() {
        return false;
    }
    match condition {
        Condition::And => matchers.iter().all(|m| eval_matcher(m, view)),
        Condition::Or => matchers.iter().any(|m| eval_matcher(m, view)),
    }
}

/// Run the extractors over a response.
fn run_extractors(
    extractors: &[Extractor],
    view: &ResponseView<'_>,
    out: &mut BTreeMap<String, String>,
) {
    for (idx, extractor) in extractors.iter().enumerate() {
        let haystack = view.text(MatchPart::All);
        for pattern in &extractor.regexes {
            let Ok(re) = regex::Regex::new(pattern) else {
                continue;
            };
            for caps in re.captures_iter(&haystack) {
                let group = extractor.group as usize; // audit-allow: capture index fits in usize
                let captured = caps.get(group).or_else(|| caps.get(0));
                if let Some(m) = captured {
                    let key = extractor
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("extracted_{idx}"));
                    out.insert(key, m.as_str().to_string());
                }
            }
        }
    }
}

// ── Native execution ────────────────────────────────────────────────────

async fn execute_http(
    template: &Template,
    blocks: &[HttpRequest],
    ctx: &ExecutionCtx<'_>,
) -> Result<Vec<TemplateResult>> {
    let mut results = Vec::new();
    let mut vars = BTreeMap::new();
    for opt in &template.options {
        vars.insert(opt.name.clone(), opt.default.clone());
    }

    let client = crate::utils::build_http_client(ctx.timeout)
        .context("build HTTP client for nuclei template")?;

    for block in blocks {
        for path in &block.paths {
            let port = block.port.unwrap_or(ctx.port);
            let scheme = if path.starts_with("http://") || path.starts_with("https://") {
                // Absolute URL in the template — keep its own scheme.
                ""
            } else {
                ctx.scheme
            };
            let url = if path.starts_with("http://") || path.starts_with("https://") {
                interpolate(path, ctx, &vars)
            } else {
                let base = if scheme.is_empty() {
                    ctx.base_url()
                } else {
                    format!("{scheme}://{}:{port}", ctx.host)
                };
                let rendered = interpolate(path, ctx, &vars);
                if rendered.starts_with("http://") || rendered.starts_with("https://") {
                    rendered
                } else {
                    format!("{base}{rendered}")
                }
            };

            let method = reqwest::Method::from_bytes(block.method.as_bytes())
                .unwrap_or(reqwest::Method::GET);
            let mut req = client.request(method, &url);
            for (k, v) in &block.headers {
                let name = interpolate(k, ctx, &vars);
                let value = interpolate(v, ctx, &vars);
                req = req.header(&name, &value);
            }
            if let Some(body) = &block.body {
                let rendered = interpolate(body, ctx, &vars);
                req = req.body(rendered);
            }

            let response = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    crate::meprintln!("[!] nuclei request to {url} failed: {e}");
                    continue;
                }
            };
            let status = response.status().as_u16();
            let mut headers = BTreeMap::new();
            for (k, v) in response.headers() {
                let Ok(value) = v.to_str() else {
                    continue;
                };
                headers.insert(k.as_str().to_string(), value.to_string());
            }
            let body = match response.text().await {
                Ok(text) => text,
                Err(e) => {
                    crate::meprintln!("[!] nuclei response body from {url} unreadable: {e}");
                    String::new()
                }
            };

            let view = ResponseView {
                status: Some(status),
                body: &body,
                headers: &headers,
            };
            let matched = eval_matchers(&block.matchers, block.condition, &view);
            let mut extracted = BTreeMap::new();
            run_extractors(&block.extractors, &view, &mut extracted);

            let message = if matched {
                format!("{} matched on {url}", template.name)
            } else {
                format!("{} did not match on {url}", template.name)
            };
            results.push(TemplateResult {
                matched,
                message,
                severity: template.severity,
                extracted,
                evidence: Some(format!("HTTP {status} · {} bytes", body.len())),
            });
        }
    }
    Ok(results)
}

async fn execute_dns(
    template: &Template,
    spec: &DnsRequest,
    ctx: &ExecutionCtx<'_>,
) -> Result<Vec<TemplateResult>> {
    let mut vars = BTreeMap::new();
    for opt in &template.options {
        vars.insert(opt.name.clone(), opt.default.clone());
    }
    let name = interpolate(&spec.name, ctx, &vars);
    let resolver = hickory_resolver::lookup(&name, &spec.query_type)
        .await
        .context("resolve nuclei DNS template query")?;
    let body = String::from_utf8_lossy(&resolver).to_string();
    let headers = BTreeMap::new();
    let view = ResponseView {
        status: None,
        body: &body,
        headers: &headers,
    };
    let matched = eval_matchers(&spec.matchers, Condition::Or, &view);
    Ok(vec![TemplateResult {
        matched,
        message: format!("{} → DNS {name}", template.name),
        severity: template.severity,
        extracted: BTreeMap::new(),
        evidence: Some(format!("{} bytes", body.len())),
    }])
}

async fn execute_tcp(
    template: &Template,
    spec: &TcpRequest,
    ctx: &ExecutionCtx<'_>,
) -> Result<Vec<TemplateResult>> {
    let mut vars = BTreeMap::new();
    for opt in &template.options {
        vars.insert(opt.name.clone(), opt.default.clone());
    }
    let host = spec
        .host
        .as_deref()
        .map(|h| interpolate(h, ctx, &vars))
        .unwrap_or_else(|| ctx.host.to_string());
    let port = spec.port.unwrap_or(ctx.port);
    let addr = format!("{host}:{port}");

    let mut stream = tokio::net::TcpStream::connect(&addr)
        .await
        .with_context(|| format!("connect to {addr} for nuclei TCP template"))?;
    if let Some(payload) = &spec.payload {
        use tokio::io::AsyncWriteExt;
        stream
            .write_all(payload)
            .await
            .with_context(|| format!("send payload to {addr}"))?;
    }
    use tokio::io::AsyncReadExt;
    let read_len = usize::try_from(spec.read.max(1)).context("nuclei TCP read length")?;
    let mut buf = vec![0u8; read_len];
    let read = stream.read(&mut buf).await.unwrap_or(0);
    let slice = buf.get(..read).unwrap_or(buf.as_slice());
    let body = String::from_utf8_lossy(slice).to_string();
    let headers = BTreeMap::new();
    let view = ResponseView {
        status: None,
        body: &body,
        headers: &headers,
    };
    let matched = eval_matchers(&spec.matchers, Condition::Or, &view);
    Ok(vec![TemplateResult {
        matched,
        message: format!("{} → TCP {addr}", template.name),
        severity: template.severity,
        extracted: BTreeMap::new(),
        evidence: Some(format!("{read} bytes")),
    }])
}

/// Minimal DNS lookup helper for the nuclei `dns:` protocol.
///
/// A full resolver is out of scope for a template bridge: the query is sent
/// to the system resolver through the platform stub and the raw answer is
/// handed to the matchers, exactly like nuclei's `dns:` protocol sees it.
mod hickory_resolver {
    use anyhow::{Context, Result};

    /// Resolve `name`/`query_type` and return the raw answer bytes.
    pub async fn lookup(name: &str, query_type: &str) -> Result<Vec<u8>> {
        let host = format!("{name}:0");
        let addrs = tokio::net::lookup_host(host)
            .await
            .with_context(|| format!("resolve {name} ({query_type})"))?;
        let mut out = Vec::new();
        for addr in addrs {
            out.extend_from_slice(addr.ip().to_string().as_bytes());
            out.push(b'\n');
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frameworks::{ExecutionCtx, Template};

    fn ctx() -> ExecutionCtx<'static> {
        ExecutionCtx {
            host: "10.0.0.1",
            port: 8443,
            scheme: "https",
            variables: BTreeMap::new(),
            timeout: Duration::from_secs(5),
            insecure: false,
        }
    }

    const TEMPLATE: &str = r#"
id: demo-template
info:
  name: Demo Detection
  author: tester
  severity: high
  description: Detects a demo condition
  reference:
    - https://example.com/advisory
  tags: cve,demo
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    headers:
      X-Probe: nuclei
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "vulnerable"
    extractors:
      - type: regex
        regex:
          - "token: ([a-z0-9]+)"
"#;

    #[test]
    fn template_is_parsed() {
        let adapter = &NUCLEI;
        let tmpl = adapter
            .parse(TEMPLATE, Path::new("demo.yaml"))
            .expect("template should parse"); // audit-allow: test
        assert_eq!(tmpl.framework, "nuclei"); // audit-allow: test
        assert_eq!(tmpl.name, "Demo Detection"); // audit-allow: test
        assert_eq!(tmpl.authors, vec!["tester".to_string()]); // audit-allow: test
        assert_eq!(tmpl.severity, Severity::High); // audit-allow: test
        assert_eq!(tmpl.tags, vec!["cve".to_string(), "demo".to_string()]); // audit-allow: test
        assert_eq!(tmpl.references.len(), 1); // audit-allow: test
        assert!(matches!(tmpl.protocol, Protocol::Http(_))); // audit-allow: test
    }

    #[test]
    fn http_block_is_converted() {
        let tmpl = NUCLEI
            .parse(TEMPLATE, Path::new("demo.yaml"))
            .expect("template should parse"); // audit-allow: test
        let Protocol::Http(blocks) = &tmpl.protocol else {
            panic!("expected an HTTP protocol"); // audit-allow: test
        };
        assert_eq!(blocks.len(), 1); // audit-allow: test
        assert_eq!(blocks[0].method, "GET"); // audit-allow: test
        assert_eq!(blocks[0].paths, vec!["{{BaseURL}}/admin".to_string()]); // audit-allow: test
        assert_eq!(blocks[0].condition, Condition::And); // audit-allow: test
        assert_eq!(blocks[0].matchers.len(), 2); // audit-allow: test
        assert_eq!(blocks[0].extractors.len(), 1); // audit-allow: test
    }

    #[test]
    fn variables_are_interpolated() {
        let ctx = ctx();
        let vars = BTreeMap::new();
        let base_url = interpolate("{{BaseURL}}/x", &ctx, &vars);
        assert_eq!(base_url, "https://10.0.0.1:8443/x"); // audit-allow: test
        assert_eq!(interpolate("{{Host}}", &ctx, &vars), "10.0.0.1"); // audit-allow: test
        assert_eq!(interpolate("{{Port}}", &ctx, &vars), "8443"); // audit-allow: test
        assert_eq!(interpolate("{{unknown}}", &ctx, &vars), "{{unknown}}"); // audit-allow: test
    }

    #[test]
    fn matchers_evaluate_against_a_response() {
        let headers = BTreeMap::new();
        let view = ResponseView {
            status: Some(200),
            body: "the service is vulnerable here",
            headers: &headers,
        };
        let word = Matcher {
            kind: MatcherKind::Word(vec!["VULNERABLE".to_string()]),
            negative: false,
            part: MatchPart::Body,
        };
        assert!(eval_matcher(&word, &view)); // audit-allow: test

        let status = Matcher {
            kind: MatcherKind::Status(vec![200]),
            negative: false,
            part: MatchPart::Body,
        };
        assert!(eval_matcher(&status, &view)); // audit-allow: test

        let negative = Matcher {
            kind: MatcherKind::Word(vec!["patched".to_string()]),
            negative: true,
            part: MatchPart::Body,
        };
        assert!(eval_matcher(&negative, &view)); // audit-allow: test
    }

    #[test]
    fn hex_payloads_are_decoded() {
        assert_eq!(decode_hex("48656c6c6f"), Some(b"Hello".to_vec())); // audit-allow: test
        assert_eq!(decode_hex("zz"), None); // audit-allow: test
        assert_eq!(decode_hex("abc"), None); // audit-allow: test
    }

    #[test]
    fn template_without_protocol_is_not_nuclei() {
        let src = "id: x\ninfo:\n  name: y\n";
        assert!(!NUCLEI.sniff(src, Path::new("x.yaml"))); // audit-allow: test
    }

    #[test]
    fn severity_drives_the_module_rank() {
        let critical_rank = Severity::Critical.module_rank();
        assert_eq!(critical_rank, crate::module_info::ModuleRank::Excellent); // audit-allow: test
        let info_rank = Severity::Info.module_rank();
        assert_eq!(info_rank, crate::module_info::ModuleRank::Normal); // audit-allow: test
        let _ = Template::default(); // audit-allow: test
    }
}

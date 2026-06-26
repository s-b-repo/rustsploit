//! Constants and shared types for the API endpoint scanner.
//!
//! Split out of the monolithic `api_endpoint_scanner.rs` so the static lists
//! (user agents, spoof headers, injection seeds) live alongside the
//! configuration struct that consumes them.

use crate::native::payload_engine::MutatorConfig;
use reqwest::Method;

pub(super) const CHROME_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
];

pub(super) const SPOOF_HEADERS: &[&str] = &[
    "X-Forwarded-For", "X-Forwarded-Host", "X-Client-IP", "X-Remote-IP", "X-Remote-Addr",
    "X-Host", "X-Originating-IP", "Client-IP", "True-Client-IP", "Cluster-Client-IP",
    "X-ProxyUser-Ip", "Via", "X-Real-IP", "Forwarded", "X-Custom-IP-Authorization",
    "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Forwarded-Port",
];

pub(super) const SQLI_PAYLOADS: &[&str] = &[
    "'", "\"", "OR 1=1", "' OR '1'='1", "\" OR \"1\"=\"1",
    "1' ORDER BY 1--+", "1' UNION SELECT 1,2,3--+",
    "admin' --", "admin' #", "' OR 1=1--",
];

pub(super) const NOSQLI_PAYLOADS: &[&str] = &[
    "{$ne: null}", "{$gt: \"\"}", "{$where: \"return true\"}",
    "|| return true;", "'; return true; var foo='",
];

pub(super) const CMDI_PAYLOADS: &[&str] = &[
    "; id", "| id", "`id`", "$(id)",
    "; cat /etc/passwd", "| cat /etc/passwd",
    "& ping -c 1 127.0.0.1",
];

pub(super) const TRAVERSAL_PAYLOADS: &[&str] = &[
    "../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "../../windows/win.ini",
];

#[derive(Clone, Copy, PartialEq, Debug)]
pub(super) enum ScanModule {
    Baseline,
    Spoofing,
    SQLi,
    NoSQLi,
    CMDi,
    PathTraversal,
    IdEnumeration,
}

pub(super) struct ScanConfig {
    pub(super) target_base: String,
    pub(super) methods: Vec<Method>,
    pub(super) modules: Vec<ScanModule>,
    pub(super) use_generic_payload: bool,
    pub(super) output_dir: String,
    pub(super) sqli_payloads: Option<Vec<String>>,
    pub(super) nosqli_payloads: Option<Vec<String>>,
    pub(super) cmdi_payloads: Option<Vec<String>>,
    pub(super) traversal_payloads: Option<Vec<String>>,
    // ID Enumeration Config
    pub(super) id_start: Option<usize>,
    pub(super) id_end: Option<usize>,
    pub(super) id_file_path: Option<String>,
    // Mutation Engine Config
    pub(super) mutation_enabled: bool,
    pub(super) mutator_config: MutatorConfig,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct Endpoint {
    pub(super) key: String,
    pub(super) path: String,
}

#[derive(serde::Serialize)]
pub(super) struct GenericPayload {
    pub(super) name: String,
    pub(super) description: String,
    pub(super) test: bool,
}

// src/exclusions.rs
//
// Pluggable IP exclusion lists for mass-scan operations. Replaces the
// hard-coded `utils::bruteforce::EXCLUDED_RANGES` global.
//
// Layered resolution (later overrides earlier):
//   1. Built-in defaults (`DEFAULT_EXCLUSIONS`) — bogons, RFC1918, multicast.
//   2. Tenant config — `~/.rustsploit/<tenant>/exclusions.txt` or the
//      `exclusions` global option (comma-separated CIDRs or `@/path/to/file`).
//   3. Per-scheduler-invocation override via `SchedulerLimits::exclusions`.
//
// Format: one CIDR or IP per line. `#` and `//` introduce comments. Empty
// lines ignored.

use std::path::PathBuf;
use std::sync::Arc;

use ipnetwork::IpNetwork;

/// Built-in exclusions: bogons, RFC1918, multicast, link-local. Operators
/// running internal-only scans can override via `setg exclusions internal`
/// to disable these (the literal string `internal` selects an empty list
/// for operators who want to scan their own infrastructure).
pub const DEFAULT_EXCLUSIONS: &[&str] = &[
    // RFC1918 + reserved
    "10.0.0.0/8",
    "127.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "0.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
    // Cloudflare anycast
    "1.0.0.1/32",
    "1.1.1.1/32",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    // Google public DNS
    "8.8.8.8/32",
    "8.8.4.4/32",
];

/// Resolved exclusion list for one scheduler invocation.
#[derive(Debug, Clone)]
pub struct ExclusionSet {
    nets: Vec<IpNetwork>,
}

impl ExclusionSet {
    /// Parse a slice of CIDR strings, warning on invalid entries.
    pub fn from_strs<I, S>(strs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let nets = strs
            .into_iter()
            .filter_map(|s| {
                match s.as_ref().parse::<IpNetwork>() {
                    Ok(net) => Some(net),
                    Err(e) => {
                        eprintln!("[!] Invalid exclusion entry '{}': {}", s.as_ref(), e);
                        None
                    }
                }
            })
            .collect();
        Self { nets }
    }

    /// The standard built-in default list.
    pub fn defaults() -> Self {
        Self::from_strs(DEFAULT_EXCLUSIONS.iter().copied())
    }

    /// Empty set — for "I really mean it, don't filter anything" operators.
    pub fn empty() -> Self {
        Self { nets: Vec::new() }
    }

    /// Resolve the active set: tenant config overlays the defaults.
    /// `setg exclusions ""`            → defaults
    /// `setg exclusions internal`      → empty (no filtering)
    /// `setg exclusions a.b.c.d/8,..`  → defaults + comma-separated CIDRs
    /// `setg exclusions @/path/to/file`→ defaults + lines from file
    pub fn from_global_options() -> Self {
        let scope = crate::tenant::resolve();
        let opts = scope.global_options();
        let raw = opts.try_get("exclusions").unwrap_or_default();
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Self::defaults();
        }
        if trimmed.eq_ignore_ascii_case("internal") || trimmed.eq_ignore_ascii_case("none") {
            return Self::empty();
        }
        let mut set = Self::defaults();
        if let Some(path) = trimmed.strip_prefix('@') {
            let path = path.trim();
            match read_exclusion_file(PathBuf::from(path)) {
                Ok(extra) => set.nets.extend(extra.nets),
                // Fail LOUD: an operator who pointed at a file expects their
                // custom exclusions applied. Silently falling back to defaults
                // would scan ranges they meant to exclude.
                Err(e) => tracing::warn!(
                    "exclusions: could not read '{}': {e}. Custom exclusions NOT applied — using defaults only.",
                    path
                ),
            }
        } else {
            for s in trimmed.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                match s.parse::<IpNetwork>() {
                    Ok(net) => set.nets.push(net),
                    Err(e) => tracing::warn!("exclusions: ignoring invalid CIDR '{}': {e}", s),
                }
            }
        }
        set
    }

    pub fn contains(&self, ip: std::net::IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(ip))
    }

    pub fn networks(&self) -> &[IpNetwork] {
        &self.nets
    }

    pub fn len(&self) -> usize {
        self.nets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }
}

fn read_exclusion_file(path: PathBuf) -> std::io::Result<ExclusionSet> {
    let raw = std::fs::read_to_string(&path)?;
    let lines = raw.lines().map(|l| {
        let l = l.split('#').next().unwrap_or(l);
        let l = l.split("//").next().unwrap_or(l);
        l.trim().to_string()
    });
    Ok(ExclusionSet::from_strs(lines.filter(|s| !s.is_empty())))
}

/// Convenience: shared `Arc` of the resolved set for the active tenant.
pub fn shared() -> Arc<ExclusionSet> {
    Arc::new(ExclusionSet::from_global_options())
}

use serde::{Serialize, Deserialize};
use colored::*;

/// Module metadata — returned by optional `pub fn info() -> ModuleInfo` in modules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub description: String,
    pub authors: Vec<String>,
    /// CVE IDs, URLs, EDB references, etc.
    pub references: Vec<String>,
    /// ISO date string, e.g. "2024-01-15"
    pub disclosure_date: Option<String>,
    pub rank: ModuleRank,
}

/// Reliability/safety rank for modules (inspired by Metasploit ranking).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModuleRank {
    /// Reliable, no crash risk
    Excellent,
    /// Usually works
    Great,
    /// Default rank
    Good,
    /// May cause instability
    Normal,
    /// Rarely works
    Low,
    /// Requires manual steps
    Manual,
}

impl std::fmt::Display for ModuleRank {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModuleRank::Excellent => write!(f, "Excellent"),
            ModuleRank::Great => write!(f, "Great"),
            ModuleRank::Good => write!(f, "Good"),
            ModuleRank::Normal => write!(f, "Normal"),
            ModuleRank::Low => write!(f, "Low"),
            ModuleRank::Manual => write!(f, "Manual"),
        }
    }
}

/// Result of a non-destructive vulnerability check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckResult {
    Vulnerable(String),
    NotVulnerable(String),
    Unknown(String),
    Error(String),
}

impl std::fmt::Display for CheckResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckResult::Vulnerable(msg) => write!(f, "Vulnerable: {}", msg),
            CheckResult::NotVulnerable(msg) => write!(f, "Not Vulnerable: {}", msg),
            CheckResult::Unknown(msg) => write!(f, "Unknown: {}", msg),
            CheckResult::Error(msg) => write!(f, "Error: {}", msg),
        }
    }
}

/// Pretty-print module info to the console.
pub fn display_module_info(module_path: &str, info: &ModuleInfo) {
    crate::mprintln!();
    crate::mprintln!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    crate::mprintln!("{}", "║                       Module Information                      ║".cyan());
    crate::mprintln!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    crate::mprintln!();
    crate::mprintln!("  {:<16} {}", "Path:".bold(), module_path);
    crate::mprintln!("  {:<16} {}", "Name:".bold(), info.name);
    crate::mprintln!("  {:<16} {}", "Rank:".bold(), format!("{}", info.rank).green());
    if let Some(ref date) = info.disclosure_date {
        crate::mprintln!("  {:<16} {}", "Disclosed:".bold(), date);
    }
    crate::mprintln!();
    crate::mprintln!("  {}", "Description:".bold());
    for line in info.description.lines() {
        crate::mprintln!("    {}", line);
    }
    crate::mprintln!();
    if !info.authors.is_empty() {
        crate::mprintln!("  {}", "Authors:".bold());
        for author in &info.authors {
            crate::mprintln!("    - {}", author);
        }
        crate::mprintln!();
    }
    if !info.references.is_empty() {
        crate::mprintln!("  {}", "References:".bold());
        for reference in &info.references {
            crate::mprintln!("    - {}", reference);
        }
        crate::mprintln!();
    }
}


use colored::*;
use serde::{Deserialize, Serialize};

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
    println!();
    println!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║                       Module Information                      ║".cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    println!();
    println!("  {:<16} {}", "Path:".bold(), module_path);
    println!("  {:<16} {}", "Name:".bold(), info.name);
    println!("  {:<16} {}", "Rank:".bold(), format!("{}", info.rank).green());
    if let Some(ref date) = info.disclosure_date {
        println!("  {:<16} {}", "Disclosed:".bold(), date);
    }
    println!();
    println!("  {}", "Description:".bold());
    for line in info.description.lines() {
        println!("    {}", line);
    }
    println!();
    if !info.authors.is_empty() {
        println!("  {}", "Authors:".bold());
        for author in &info.authors {
            println!("    - {}", author);
        }
        println!();
    }
    if !info.references.is_empty() {
        println!("  {}", "References:".bold());
        for reference in &info.references {
            println!("    - {}", reference);
        }
        println!();
    }
}


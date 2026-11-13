// src/utils/modules.rs
//
// Module discovery, listing, and search functions.
// Discovery uses the build-time generated registry (via commands::discover_modules)
// for reliable operation regardless of CWD.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use colored::*;

use super::sanitize::MAX_MODULE_PATH_LENGTH;

/// Maximum file size for general text file loading (100 MB).
/// Wordlists bypass this via `load_lines_uncapped`.
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Checks if a module path exists in the build-time registry.
pub fn module_exists(module_path: &str) -> bool {
    if module_path.is_empty() || module_path.len() > MAX_MODULE_PATH_LENGTH {
        return false;
    }
    if module_path.contains("..") || module_path.contains("//") {
        return false;
    }
    crate::commands::discover_modules_cached()
        .iter()
        .any(|m| m == module_path)
}

/// Lists available modules, optionally filtered by category.
///
/// `filter` is a category prefix (`exploits`, `scanners`, `creds`, ...). An
/// empty filter lists everything.
///
/// Unlike the old implementation this does NOT colour each path at random:
/// the random colour made two consecutive listings impossible to diff, which
/// defeats the point of a listing.
pub fn list_all_modules(filter: &str) {
    let filter = filter.trim();
    let modules = crate::commands::discover_modules();
    let selected: Vec<String> = if filter.is_empty() {
        modules
    } else {
        let prefix = format!("{filter}/");
        modules
            .into_iter()
            .filter(|m| m.starts_with(&prefix) || m == filter)
            .collect()
    };

    if selected.is_empty() {
        if filter.is_empty() {
            crate::mprintln!("{}", "No modules found.".red());
        } else {
            crate::mprintln!("{}", format!("No modules in category '{filter}'.").red());
            crate::mprintln!(
                "{}",
                format!("Categories: {}", crate::commands::categories().join(", ")).dimmed()
            );
        }
        return;
    }

    crate::mprintln!("{}", "Available modules:".bold().underline());
    crate::mprintln!();
    let mut grouped = std::collections::BTreeMap::new();
    for module in &selected {
        let parts: Vec<&str> = module.split('/').collect();
        let category = parts.first().unwrap_or(&"Other").to_string();
        grouped
            .entry(category)
            .or_insert_with(Vec::new)
            .push(module.clone());
    }
    for (category, paths) in grouped {
        crate::mprintln!("{}:", category.blue().bold());
        let mut last_subcategory = String::new();
        for path in paths {
            let parts: Vec<&str> = path.split('/').collect();
            let subcategory = if parts.len() >= 3 {
                parts[..2].join("/")
            } else {
                category.clone()
            };
            if !last_subcategory.is_empty() && subcategory != last_subcategory {
                crate::mprintln!();
            }
            last_subcategory = subcategory;
            crate::mprintln!("  - {}", path);
        }
        crate::mprintln!();
    }
    crate::mprintln!(
        "\n{}",
        format!("Total: {} modules", selected.len()).dimmed()
    );
}

/// Finds and displays modules matching a keyword.
///
/// The keyword is matched against the module PATH, the module NAME, the
/// DESCRIPTION and the REFERENCES (which carry the CVE ids) — not just the
/// path. Searching for `CVE-2021-44228` or `log4shell` used to return
/// nothing because neither string appears in a module path.
pub fn find_modules(keyword: &str) {
    if keyword.is_empty() {
        crate::mprintln!("{}", "Keyword cannot be empty.".red());
        return;
    }
    if keyword.len() > 100 {
        crate::mprintln!("{}", "Keyword too long (max 100 characters).".red());
        return;
    }
    let keyword_lower = keyword.to_lowercase();
    let modules = crate::commands::discover_modules();

    let mut filtered: Vec<String> = Vec::new();
    let mut with_metadata: Vec<(String, String)> = Vec::new();
    for m in modules {
        if m.to_lowercase().contains(&keyword_lower) {
            filtered.push(m);
            continue;
        }
        // Fall back to the module's own metadata. `info()` is cheap (the
        // registry is compile-time) and this is what makes a CVE id
        // searchable.
        let Some(info) = crate::commands::module_info(&m) else {
            continue;
        };
        let haystack = format!(
            "{} {} {} {}",
            info.name,
            info.description,
            info.references.join(" "),
            info.authors.join(" ")
        )
        .to_lowercase();
        if haystack.contains(&keyword_lower) {
            with_metadata.push((m.clone(), info.name));
            filtered.push(m);
        }
    }

    if filtered.is_empty() {
        crate::mprintln!(
            "{}",
            format!("No modules found matching '{}'.", keyword).red()
        );
        if let Some(suggestion) = crate::commands::suggest_module(keyword) {
            crate::mprintln!("{}", format!("  Did you mean: {}?", suggestion).yellow());
        }
        return;
    }
    crate::mprintln!(
        "{}",
        format!("Modules matching '{}':", keyword)
            .bold()
            .underline()
    );
    let mut grouped = std::collections::BTreeMap::new();
    for module in filtered {
        let parts: Vec<&str> = module.split('/').collect();
        let category = parts.first().unwrap_or(&"Other").to_string();
        grouped
            .entry(category)
            .or_insert_with(Vec::new)
            .push(module.clone());
    }
    // Count before the map is consumed by the loop below.
    let total = grouped.values().map(Vec::len).sum::<usize>();
    for (category, paths) in grouped {
        crate::mprintln!("\n{}:", category.blue().bold());
        let mut last_subcategory = String::new();
        for path in paths {
            let parts: Vec<&str> = path.split('/').collect();
            let subcategory = if parts.len() >= 3 {
                parts[..2].join("/")
            } else {
                category.clone()
            };
            if !last_subcategory.is_empty() && subcategory != last_subcategory {
                crate::mprintln!();
            }
            last_subcategory = subcategory;
            // Show the human-readable name when the match came from the
            // metadata rather than the path.
            match with_metadata.iter().find(|(p, _)| *p == path) {
                Some((_, title)) => crate::mprintln!("  - {path}  —  {title}"),
                None => crate::mprintln!("  - {path}"),
            }
        }
    }
    crate::mprintln!("\n{}", format!("Total: {total} modules").dimmed());
}

/// Streaming threshold: files larger than this use batched loading.
///
/// Canonically defined once in `crate::utils::wordlist` so every streaming
/// decision (wordlist `should_stream`, `run_bruteforce_streaming`, the FTP
/// module's pre-check) agrees on the same cutoff. Crucially this sits *below*
/// `MAX_FILE_SIZE` (the 100 MB `load_lines` hard cap) so large password lists
/// route into the streaming engine instead of hard-failing.
pub const STREAMING_THRESHOLD: u64 = crate::utils::wordlist::STREAMING_THRESHOLD;

/// Check file size for streaming decisions.
pub fn file_size<P: AsRef<Path>>(path: P) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// Read a text file to string with a size limit to prevent OOM.
/// Defaults to MAX_FILE_SIZE (100 MB). Pass a custom limit for stricter checks.
pub fn safe_read_to_string<P: AsRef<Path>>(path: P, max_bytes: Option<u64>) -> Result<String> {
    let limit = max_bytes.unwrap_or(MAX_FILE_SIZE);
    let metadata = fs::metadata(path.as_ref())
        .with_context(|| format!("Failed to stat file '{}'", path.as_ref().display()))?;
    if metadata.len() > limit {
        bail!(
            "File '{}' is too large ({:.1} MB, max {} MB)",
            path.as_ref().display(),
            metadata.len() as f64 / (1024.0 * 1024.0),
            limit / (1024 * 1024)
        );
    }
    fs::read_to_string(path.as_ref())
        .with_context(|| format!("Failed to read file '{}'", path.as_ref().display()))
}

/// Async version of safe_read_to_string.
pub async fn safe_read_to_string_async<P: AsRef<Path>>(
    path: P,
    max_bytes: Option<u64>,
) -> Result<String> {
    let limit = max_bytes.unwrap_or(MAX_FILE_SIZE);
    let metadata = tokio::fs::metadata(path.as_ref())
        .await
        .with_context(|| format!("Failed to stat file '{}'", path.as_ref().display()))?;
    if metadata.len() > limit {
        bail!(
            "File '{}' is too large ({:.1} MB, max {} MB)",
            path.as_ref().display(),
            metadata.len() as f64 / (1024.0 * 1024.0),
            limit / (1024 * 1024)
        );
    }
    tokio::fs::read_to_string(path.as_ref())
        .await
        .with_context(|| format!("Failed to read file '{}'", path.as_ref().display()))
}

/// Helper to get a safe filename in the current directory.
pub fn get_filename_in_current_dir(input: &str) -> std::path::PathBuf {
    Path::new(input)
        .file_name()
        .map(|name_os_str| std::path::PathBuf::from(format!("./{}", name_os_str.to_string_lossy())))
        .unwrap_or_else(|| std::path::PathBuf::from(input))
}

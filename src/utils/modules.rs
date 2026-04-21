// src/utils/modules.rs
//
// Module discovery, listing, and search functions.
// Discovery uses the build-time generated registry (via commands::discover_modules)
// for reliable operation regardless of CWD.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result, bail};
use colored::*;
use rand::prelude::IndexedRandom;

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
    let modules = crate::commands::discover_modules();
    modules.iter().any(|m| m == module_path)
}

/// Helper to get a random color for module display.
fn get_random_color() -> Color {
    let colors = [
        Color::Red, Color::Green, Color::Yellow, Color::Blue,
        Color::Magenta, Color::Cyan, Color::BrightRed, Color::BrightGreen,
        Color::BrightYellow, Color::BrightBlue, Color::BrightMagenta, Color::BrightCyan,
    ];
    let mut rng = rand::rng();
    *colors.choose(&mut rng).unwrap_or(&Color::Green)
}

/// Lists all available modules from the build-time generated registry.
pub fn list_all_modules() {
    crate::mprintln!("{}", "Available modules:".bold().underline());
    let modules = crate::commands::discover_modules();
    if modules.is_empty() {
        crate::mprintln!("{}", "No modules found.".red());
        return;
    }
    let mut grouped = std::collections::BTreeMap::new();
    for module in &modules {
        let parts: Vec<&str> = module.split('/').collect();
        let category = parts.get(0).unwrap_or(&"Other").to_string();
        grouped.entry(category).or_insert_with(Vec::new).push(module.clone());
    }
    crate::mprintln!();
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
            crate::mprintln!("  - {}", path.color(get_random_color()));
        }
        crate::mprintln!();
    }
    crate::mprintln!("\n{}", format!("Total: {} modules", modules.len()).dimmed());
}

/// Finds and displays modules matching a keyword.
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
    let filtered: Vec<String> = modules
        .into_iter()
        .filter(|m| m.to_lowercase().contains(&keyword_lower))
        .collect();
    if filtered.is_empty() {
        crate::mprintln!("{}", format!("No modules found matching '{}'.", keyword).red());
        return;
    }
    crate::mprintln!("{}", format!("Modules matching '{}':", keyword).bold().underline());
    let mut grouped = std::collections::BTreeMap::new();
    for module in filtered {
        let parts: Vec<&str> = module.split('/').collect();
        let category = parts.get(0).unwrap_or(&"Other").to_string();
        grouped.entry(category).or_insert_with(Vec::new).push(module.clone());
    }
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
            crate::mprintln!("  - {}", path.color(get_random_color()));
        }
    }
}

/// Helper to load lines from a file.
pub fn load_lines<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let metadata = fs::metadata(path.as_ref())
        .with_context(|| format!("Failed to stat file '{}'", path.as_ref().display()))?;
    if metadata.len() > MAX_FILE_SIZE {
        bail!(
            "File '{}' is too large ({:.1} MB, max {} MB)",
            path.as_ref().display(),
            metadata.len() as f64 / (1024.0 * 1024.0),
            MAX_FILE_SIZE / (1024 * 1024)
        );
    }
    let file = fs::File::open(path.as_ref())
        .with_context(|| format!("Failed to open file '{}'", path.as_ref().display()))?;
    let reader = BufReader::new(file);
    Ok(reader
        .lines()
        .filter_map(|line| line.ok().map(|s| s.trim().to_string()))
        .filter(|line| !line.is_empty())
        .collect())
}

/// Load lines from a wordlist of any size.
/// Files <= 250 MB are loaded into memory. Larger files are streamed in
/// batches of `batch_size` lines, calling `on_batch` for each chunk.
/// Returns the total number of lines processed.
pub fn load_lines_batched<P, F>(
    path: P,
    batch_size: usize,
    mut on_batch: F,
) -> Result<usize>
where
    P: AsRef<Path>,
    F: FnMut(Vec<String>),
{
    let file = fs::File::open(path.as_ref())
        .with_context(|| format!("Failed to open file '{}'", path.as_ref().display()))?;
    let reader = BufReader::with_capacity(256 * 1024, file);
    let mut total = 0usize;
    let mut batch = Vec::with_capacity(batch_size);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l.trim().to_string(),
            Err(_) => continue,
        };
        if line.is_empty() {
            continue;
        }
        batch.push(line);
        if batch.len() >= batch_size {
            total += batch.len();
            on_batch(std::mem::replace(&mut batch, Vec::with_capacity(batch_size)));
        }
    }
    if !batch.is_empty() {
        total += batch.len();
        on_batch(batch);
    }
    Ok(total)
}

/// Streaming threshold: files larger than this use batched loading.
pub const STREAMING_THRESHOLD: u64 = 250 * 1024 * 1024;

/// Load lines from a file without the 100 MB cap.
/// For wordlists that may be very large.
pub fn load_lines_uncapped<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let file = fs::File::open(path.as_ref())
        .with_context(|| format!("Failed to open file '{}'", path.as_ref().display()))?;
    let reader = BufReader::with_capacity(256 * 1024, file);
    Ok(reader
        .lines()
        .filter_map(|line| line.ok().map(|s| s.trim().to_string()))
        .filter(|line| !line.is_empty())
        .collect())
}

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
pub async fn safe_read_to_string_async<P: AsRef<Path>>(path: P, max_bytes: Option<u64>) -> Result<String> {
    let limit = max_bytes.unwrap_or(MAX_FILE_SIZE);
    let metadata = tokio::fs::metadata(path.as_ref()).await
        .with_context(|| format!("Failed to stat file '{}'", path.as_ref().display()))?;
    if metadata.len() > limit {
        bail!(
            "File '{}' is too large ({:.1} MB, max {} MB)",
            path.as_ref().display(),
            metadata.len() as f64 / (1024.0 * 1024.0),
            limit / (1024 * 1024)
        );
    }
    tokio::fs::read_to_string(path.as_ref()).await
        .with_context(|| format!("Failed to read file '{}'", path.as_ref().display()))
}

/// Helper to get a safe filename in the current directory.
pub fn get_filename_in_current_dir(input: &str) -> std::path::PathBuf {
    Path::new(input)
        .file_name()
        .map(|name_os_str| std::path::PathBuf::from(format!("./{}", name_os_str.to_string_lossy())))
        .unwrap_or_else(|| std::path::PathBuf::from(input))
}

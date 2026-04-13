use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use regex::Regex;
use walkdir::WalkDir;

/// Build script that generates module dispatchers for all categories found
/// under `src/modules/`. Categories are discovered dynamically — adding a new
/// subdirectory (e.g. `src/modules/payloads/`) is all that's needed.
fn main() {
    let modules_root = Path::new("src/modules");
    if !modules_root.exists() {
        eprintln!("cargo:warning=src/modules/ directory not found");
        return;
    }

    // Discover categories dynamically from subdirectories of src/modules/
    let mut categories: Vec<String> = Vec::new();
    let entries = match fs::read_dir(modules_root) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("cargo:warning=Failed to read src/modules/: {}", e);
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if !name.starts_with('.') {
                    categories.push(name.to_string());
                }
            }
        }
    }
    categories.sort();

    // Tell Cargo to rerun if any category directory changes
    for cat in &categories {
        println!("cargo:rerun-if-changed=src/modules/{}", cat);
    }

    // Compile regexes once, reuse across all categories
    let run_re = Regex::new(r"pub\s+async\s+fn\s+run\s*\(\s*[^)]*:\s*&str\s*\)").unwrap();
    let info_re = Regex::new(r"pub\s+fn\s+info\s*\(\s*\)\s*->\s*(?:crate::)?(?:module_info::)?ModuleInfo").unwrap();
    let check_re = Regex::new(r"pub\s+async\s+fn\s+check\s*\(\s*[^)]*:\s*&str\s*\)\s*->\s*(?:crate::)?(?:module_info::)?CheckResult").unwrap();

    // Generate a dispatcher for each category
    let mut registry_entries: Vec<RegistryEntry> = Vec::new();

    for cat in &categories {
        let root = format!("src/modules/{}", cat);
        let mod_prefix = format!("crate::modules::{}", cat);
        let out_file = format!("{}_dispatch.rs", dispatch_name(cat));
        let display_name = capitalize(cat);

        match generate_dispatch(&root, &out_file, &mod_prefix, &display_name, &run_re, &info_re, &check_re) {
            Ok(_module_count) => {
                registry_entries.push(RegistryEntry {
                    category: cat.clone(),
                    dispatch_name: dispatch_name(cat),
                });
            }
            Err(e) => {
                eprintln!("cargo:warning=Error generating {} dispatcher: {}", cat, e);
                std::process::exit(1);
            }
        }
    }

    // Generate unified registry file
    if let Err(e) = generate_registry(&registry_entries) {
        eprintln!("cargo:warning=Error generating module registry: {}", e);
        std::process::exit(1);
    }
}

struct RegistryEntry {
    category: String,
    dispatch_name: String,
}

/// Map category directory name to dispatch module name.
/// "exploits" → "exploit", "scanners" → "scanner", otherwise identity.
fn dispatch_name(category: &str) -> String {
    match category {
        "exploits" => "exploit".to_string(),
        "scanners" => "scanner".to_string(),
        other => other.to_string(),
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

/// Capabilities detected for each module file.
struct ModuleCapabilities {
    has_info: bool,
    has_check: bool,
}

fn generate_dispatch(
    root: &str,
    out_file: &str,
    mod_prefix: &str,
    category_name: &str,
    run_re: &Regex,
    info_re: &Regex,
    check_re: &Regex,
) -> Result<usize, Box<dyn std::error::Error>> {
    let out_dir = env::var("OUT_DIR").map_err(|_| "OUT_DIR environment variable not set")?;
    let dest_path = Path::new(&out_dir).join(out_file);

    let root_path = Path::new(root);
    if !root_path.exists() {
        return Err(format!("Module directory '{}' does not exist", root).into());
    }

    let mappings = find_modules(root_path, run_re, info_re, check_re)?;

    // Sort for deterministic output
    let mut sorted_mappings: Vec<_> = mappings.into_iter().collect();
    sorted_mappings.sort_by(|a, b| a.0.cmp(&b.0));

    // Detect duplicate short names (different full paths with same filename)
    let mut short_names: HashMap<String, Vec<String>> = HashMap::new();
    for (key, _, _) in &sorted_mappings {
        let short = key.rsplit('/').next().unwrap_or(key).to_string();
        short_names.entry(short).or_default().push(key.clone());
    }
    for (short, full_paths) in &short_names {
        if full_paths.len() > 1 {
            println!(
                "cargo:warning=Duplicate short module name '{}' in {}: {:?}. \
                 Only the first match will be reachable via short name.",
                short, root, full_paths
            );
        }
    }

    let mut file = File::create(&dest_path)?;

    writeln!(file, "// Auto-generated by build.rs - DO NOT EDIT MANUALLY\n")?;

    // Generate AVAILABLE_MODULES constant for runtime discovery
    writeln!(file, "/// List of all available modules in this category.")?;
    writeln!(file, "pub const AVAILABLE_MODULES: &[&str] = &[")?;
    for (key, _, _) in &sorted_mappings {
        writeln!(file, "    \"{}\",", key)?;
    }
    writeln!(file, "];\n")?;

    // === Run dispatcher ===
    writeln!(file, "pub async fn dispatch(module_name: &str, target: &str) -> anyhow::Result<()> {{")?;
    writeln!(file, "    match module_name {{")?;

    let mut emitted_shorts: HashSet<String> = HashSet::new();

    for (key, mod_path, _caps) in &sorted_mappings {
        let short_key = key.rsplit('/').next().unwrap_or(key);
        let mod_code_path = mod_path.replace("/", "::");

        if short_key == *key {
            writeln!(
                file,
                r#"        "{k}" => {{ {p}::{m}::run(target).await? }},"#,
                k = key, m = mod_code_path, p = mod_prefix
            )?;
        } else if emitted_shorts.insert(short_key.to_string()) {
            writeln!(
                file,
                r#"        "{short}" | "{full}" => {{ {p}::{m}::run(target).await? }},"#,
                short = short_key, full = key, m = mod_code_path, p = mod_prefix
            )?;
        } else {
            writeln!(
                file,
                r#"        "{full}" => {{ {p}::{m}::run(target).await? }},"#,
                full = key, m = mod_code_path, p = mod_prefix
            )?;
        }
    }

    writeln!(
        file,
        r#"        _ => anyhow::bail!("{} module '{{}}' not found.", module_name),"#,
        category_name
    )?;
    writeln!(file, "    }}\n    Ok(())\n}}\n")?;

    // === Info dispatcher ===
    writeln!(file, "pub fn info_dispatch(module_name: &str) -> Option<crate::module_info::ModuleInfo> {{")?;
    writeln!(file, "    match module_name {{")?;

    let mut info_emitted_shorts: HashSet<String> = HashSet::new();
    let mut info_count = 0;

    for (key, mod_path, caps) in &sorted_mappings {
        if !caps.has_info { continue; }
        info_count += 1;
        let short_key = key.rsplit('/').next().unwrap_or(key);
        let mod_code_path = mod_path.replace("/", "::");

        if short_key == *key {
            writeln!(
                file,
                r#"        "{k}" => Some({p}::{m}::info()),"#,
                k = key, m = mod_code_path, p = mod_prefix
            )?;
        } else if info_emitted_shorts.insert(short_key.to_string()) {
            writeln!(
                file,
                r#"        "{short}" | "{full}" => Some({p}::{m}::info()),"#,
                short = short_key, full = key, m = mod_code_path, p = mod_prefix
            )?;
        } else {
            writeln!(
                file,
                r#"        "{full}" => Some({p}::{m}::info()),"#,
                full = key, m = mod_code_path, p = mod_prefix
            )?;
        }
    }

    writeln!(file, "        _ => None,")?;
    writeln!(file, "    }}\n}}\n")?;

    // === Check dispatcher ===
    // Use _target prefix if no check modules to avoid unused variable warning
    let check_has_any = sorted_mappings.iter().any(|(_, _, c)| c.has_check);
    let target_param = if check_has_any { "target" } else { "_target" };
    writeln!(file, "pub async fn check_dispatch(module_name: &str, {}: &str) -> Option<crate::module_info::CheckResult> {{", target_param)?;
    writeln!(file, "    match module_name {{")?;

    let mut check_emitted_shorts: HashSet<String> = HashSet::new();
    let mut check_count = 0;

    for (key, mod_path, caps) in &sorted_mappings {
        if !caps.has_check { continue; }
        check_count += 1;
        let short_key = key.rsplit('/').next().unwrap_or(key);
        let mod_code_path = mod_path.replace("/", "::");

        if short_key == *key {
            writeln!(
                file,
                r#"        "{k}" => Some({p}::{m}::check(target).await),"#,
                k = key, m = mod_code_path, p = mod_prefix
            )?;
        } else if check_emitted_shorts.insert(short_key.to_string()) {
            writeln!(
                file,
                r#"        "{short}" | "{full}" => Some({p}::{m}::check(target).await),"#,
                short = short_key, full = key, m = mod_code_path, p = mod_prefix
            )?;
        } else {
            writeln!(
                file,
                r#"        "{full}" => Some({p}::{m}::check(target).await),"#,
                full = key, m = mod_code_path, p = mod_prefix
            )?;
        }
    }

    writeln!(file, "        _ => None,")?;
    writeln!(file, "    }}\n}}\n")?;

    // === Check availability (no target needed) ===
    writeln!(file, "/// Check if a module has a check() function without needing a target.")?;
    writeln!(file, "pub fn check_available(module_name: &str) -> bool {{")?;
    writeln!(file, "    match module_name {{")?;

    let mut check_avail_shorts: HashSet<String> = HashSet::new();

    for (key, _, caps) in &sorted_mappings {
        if !caps.has_check { continue; }
        let short_key = key.rsplit('/').next().unwrap_or(key);

        if short_key == *key {
            writeln!(file, r#"        "{k}" => true,"#, k = key)?;
        } else if check_avail_shorts.insert(short_key.to_string()) {
            writeln!(file, r#"        "{short}" | "{full}" => true,"#, short = short_key, full = key)?;
        } else {
            writeln!(file, r#"        "{full}" => true,"#, full = key)?;
        }
    }

    writeln!(file, "        _ => false,")?;
    writeln!(file, "    }}\n}}")?;

    let count = sorted_mappings.len();
    if count == 0 {
        println!("cargo:warning=No modules found in '{}' — generated empty dispatcher", root);
    }

    println!("cargo:warning=Generated {} with {} modules ({} info, {} check)", out_file, count, info_count, check_count);
    Ok(count)
}

/// Generate a unified registry file that lists all categories and their modules.
/// This is included by `src/commands/mod.rs` to avoid hard-coding categories.
fn generate_registry(entries: &[RegistryEntry]) -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = env::var("OUT_DIR")?;
    let dest = Path::new(&out_dir).join("module_registry.rs");
    let mut f = File::create(&dest)?;

    writeln!(f, "// Auto-generated by build.rs - DO NOT EDIT MANUALLY\n")?;

    // Category list
    writeln!(f, "/// All module categories discovered under src/modules/.")?;
    writeln!(f, "pub const CATEGORIES: &[&str] = &[")?;
    for e in entries {
        writeln!(f, "    \"{}\",", e.category)?;
    }
    writeln!(f, "];\n")?;

    // Unified discover function
    writeln!(f, "/// Aggregate all available modules across all categories.")?;
    writeln!(f, "pub fn all_modules() -> Vec<String> {{")?;
    writeln!(f, "    let mut modules = Vec::new();")?;
    for e in entries {
        writeln!(
            f,
            "    modules.extend(crate::commands::{}::AVAILABLE_MODULES.iter().map(|m| format!(\"{{}}/{{}}\", \"{}\", m)));",
            e.dispatch_name, e.category
        )?;
    }
    writeln!(f, "    modules")?;
    writeln!(f, "}}\n")?;

    // Unified dispatch function
    writeln!(f, "/// Dispatch a module run by category and module name.")?;
    writeln!(f, "pub async fn dispatch_by_category(category: &str, module_name: &str, target: &str) -> anyhow::Result<()> {{")?;
    writeln!(f, "    match category {{")?;
    for e in entries {
        writeln!(
            f,
            "        \"{}\" => crate::commands::{}::dispatch(module_name, target).await,",
            e.category, e.dispatch_name
        )?;
    }
    writeln!(f, "        _ => anyhow::bail!(\"Unknown module category '{{}}'\", category),")?;
    writeln!(f, "    }}")?;
    writeln!(f, "}}\n")?;

    // Unified info dispatch
    writeln!(f, "/// Get module info by category and module name.")?;
    writeln!(f, "pub fn info_by_category(category: &str, module_name: &str) -> Option<crate::module_info::ModuleInfo> {{")?;
    writeln!(f, "    match category {{")?;
    for e in entries {
        writeln!(
            f,
            "        \"{}\" => crate::commands::{}::info_dispatch(module_name),",
            e.category, e.dispatch_name
        )?;
    }
    writeln!(f, "        _ => None,")?;
    writeln!(f, "    }}")?;
    writeln!(f, "}}\n")?;

    // Unified check dispatch
    writeln!(f, "/// Run vulnerability check by category and module name.")?;
    writeln!(f, "pub async fn check_by_category(category: &str, module_name: &str, target: &str) -> Option<crate::module_info::CheckResult> {{")?;
    writeln!(f, "    match category {{")?;
    for e in entries {
        writeln!(
            f,
            "        \"{}\" => crate::commands::{}::check_dispatch(module_name, target).await,",
            e.category, e.dispatch_name
        )?;
    }
    writeln!(f, "        _ => None,")?;
    writeln!(f, "    }}")?;
    writeln!(f, "}}\n")?;

    // Check availability (no target needed)
    writeln!(f, "/// Check if a module has a check() function by category and module name.")?;
    writeln!(f, "pub fn check_available_by_category(category: &str, module_name: &str) -> bool {{")?;
    writeln!(f, "    match category {{")?;
    for e in entries {
        writeln!(
            f,
            "        \"{}\" => crate::commands::{}::check_available(module_name),",
            e.category, e.dispatch_name
        )?;
    }
    writeln!(f, "        _ => false,")?;
    writeln!(f, "    }}")?;
    writeln!(f, "}}")?;

    Ok(())
}

/// Finds all valid modules recursively using WalkDir.
/// Returns (module_key, module_path, capabilities) tuples.
fn find_modules(root: &Path, run_re: &Regex, info_re: &Regex, check_re: &Regex) -> Result<HashSet<(String, String, ModuleCapabilities)>, Box<dyn std::error::Error>> {
    let mut mappings = HashSet::new();

    for entry in WalkDir::new(root).follow_links(false).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() && path.extension().map_or(false, |e| e == "rs") {
            let file_stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if file_stem == "mod" || file_stem == "lib" { continue; }

            if let Ok(relative) = path.strip_prefix(root) {
                let rel_str = relative.with_extension("").to_string_lossy().replace("\\", "/");

                let mut content = String::new();
                if File::open(path).and_then(|mut f| f.read_to_string(&mut content)).is_ok() {
                    // Fast pre-filter: skip files that can't possibly match
                    if !content.contains("fn run") { continue; }
                    if run_re.is_match(&content) {
                        let caps = ModuleCapabilities {
                            has_info: content.contains("fn info") && info_re.is_match(&content),
                            has_check: content.contains("fn check") && check_re.is_match(&content),
                        };
                        mappings.insert((rel_str.clone(), rel_str, caps));
                    }
                }
            }
        }
    }
    Ok(mappings)
}

// Manual Hash/Eq implementations for ModuleCapabilities that only compare on the key
impl std::hash::Hash for ModuleCapabilities {
    fn hash<H: std::hash::Hasher>(&self, _state: &mut H) {
        // Intentionally empty — hashing is done on the tuple's first element
    }
}

impl PartialEq for ModuleCapabilities {
    fn eq(&self, _other: &Self) -> bool {
        true // All capabilities are "equal" for set dedup purposes
    }
}

impl Eq for ModuleCapabilities {}

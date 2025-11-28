use std::collections::HashSet;
use std::env;
use std::fs::{self, File};
use std::io::{Write};
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("scanner_dispatch.rs");
    let mut file = File::create(&dest_path).unwrap();

    let scanners_root = Path::new("src/modules/scanners");

    let mut mappings: HashSet<(String, String)> = HashSet::new();

    // Traverse all .rs files (excluding mod.rs)
    visit_all_rs(scanners_root, "".to_string(), &mut mappings).unwrap();

    // Start generating dispatch code
    writeln!(
        file,
        "pub async fn dispatch(module_name: &str, target: &str) -> anyhow::Result<()> {{\n    match module_name {{"
    ).unwrap();

    for (key, mod_path) in &mappings {
        let short_key = key.rsplit('/').next().unwrap_or(&key);
        let mod_code_path = mod_path.replace("/", "::");

        writeln!(
            file,
            r#"        "{short}" | "{full}" => {{ crate::modules::scanners::{path}::run(target).await? }},"#,
            short = short_key,
            full = key,
            path = mod_code_path
        ).unwrap();
    }

    writeln!(
        file,
        r#"        _ => anyhow::bail!("Scanner module '{{}}' not found.", module_name),"#
    ).unwrap();

    writeln!(file, "    }}\n    Ok(())\n}}").unwrap();
}

/// Recursively walk through directories, find all .rs files excluding mod.rs
fn visit_all_rs(dir: &Path, prefix: String, mappings: &mut HashSet<(String, String)>) -> std::io::Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().into_owned();

            if path.is_dir() {
                let sub_prefix = if prefix.is_empty() {
                    file_name.clone()
                } else {
                    format!("{}/{}", prefix, file_name)
                };
                visit_all_rs(&path, sub_prefix, mappings)?;
            } else if path.extension().map_or(false, |e| e == "rs") {
                if file_name == "mod.rs" {
                    continue;
                }

                let file_stem = path.file_stem().unwrap().to_string_lossy();
                let mod_path = if prefix.is_empty() {
                    file_stem.to_string()
                } else {
                    format!("{}/{}", prefix, file_stem)
                };

                // Add to mappings if not already added
                if mappings.insert((mod_path.clone(), mod_path.clone())) {
                    println!("✅ Found scanner: {}", mod_path);
                }
            }
        }
    }
    Ok(())
}

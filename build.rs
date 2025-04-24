use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use regex::Regex;

fn main() {
    println!("cargo:rerun-if-changed=src/modules/exploits");
    println!("cargo:rerun-if-changed=src/modules/creds");
    println!("cargo:rerun-if-changed=src/modules/scanners");

    generate_dispatch(
        "src/modules/exploits",
        "exploit_dispatch.rs",
        "crate::modules::exploits"
    );
    generate_dispatch(
        "src/modules/creds",
        "creds_dispatch.rs",
        "crate::modules::creds"
    );
    generate_dispatch(
        "src/modules/scanners",
        "scanner_dispatch.rs",
        "crate::modules::scanners"
    );
}

fn generate_dispatch(root: &str, out_file: &str, mod_prefix: &str) {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join(out_file);
    let mut file = File::create(&dest_path).unwrap();

    let root_path = Path::new(root);
    let mut mappings = Vec::new();
    visit_dirs(root_path, "".to_string(), &mut mappings).unwrap();

    writeln!(
        file,
        "pub async fn dispatch(module_name: &str, target: &str) -> anyhow::Result<()> {{\n    match module_name {{"
    ).unwrap();

    for (key, mod_path) in &mappings {
        writeln!(
            file,
            r#"        "{k}" => {{ {p}::{m}::run(target).await? }},"#,
            k = key,
            m = mod_path.replace("/", "::"),
            p = mod_prefix
        ).unwrap();
    }

    writeln!(
        file,
        r#"        _ => anyhow::bail!("Module '{{}}' not found.", module_name),"#
    ).unwrap();

    writeln!(file, "    }}\n    Ok(())\n}}").unwrap();
}

fn visit_dirs(dir: &Path, prefix: String, mappings: &mut Vec<(String, String)>) -> std::io::Result<()> {
    let sig_re = Regex::new(r"pub\s+async\s+fn\s+run\s*\(\s*[_a-zA-Z]+\s*:\s*&str\s*\)").unwrap();

    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                let sub_prefix = format!("{}/{}", prefix, entry.file_name().to_string_lossy());
                visit_dirs(&path, sub_prefix, mappings)?;
            } else if path.extension().map_or(false, |e| e == "rs") {
                let file_name = path.file_stem().unwrap().to_string_lossy().to_string();
                if file_name == "mod" {
                    continue;
                }

                let mod_path = format!("{}/{}", prefix, file_name)
                    .trim_start_matches('/')
                    .to_string();
                let key = mod_path.clone();

                let mut source = String::new();
                fs::File::open(&path)?.read_to_string(&mut source)?;

                if sig_re.is_match(&source) {
                    mappings.push((key.clone(), mod_path));
                    println!("✅ Registered module: {}/{}", prefix, file_name);
                } else {
                    println!("⚠️  Skipping '{}': no matching 'pub async fn run(...)'", path.display());
                }
            }
        }
    }
    Ok(())
}

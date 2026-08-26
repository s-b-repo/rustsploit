use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

pub fn load_profile(path: &Path) -> Result<HashMap<String, String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read profile '{}'", path.display()))?;

    let table: toml::Table = toml::from_str(&content)
        .with_context(|| format!("Invalid TOML in '{}'", path.display()))?;

    let mut opts: HashMap<String, String> = HashMap::new();
    for (key, value) in &table {
        let val_str = match value {
            toml::Value::String(s) => s.clone(),
            toml::Value::Integer(i) => i.to_string(),
            toml::Value::Float(f) => f.to_string(),
            toml::Value::Boolean(b) => b.to_string(),
            _ => continue,
        };
        opts.insert(key.clone(), val_str);
    }
    Ok(opts)
}

pub async fn apply_profile(path: &Path) -> Result<usize> {
    let opts = load_profile(path)?;
    let count = opts.len();
    let go = &crate::global_options::GLOBAL_OPTIONS;
    for (key, value) in &opts {
        go.set(key, value).await;
    }
    Ok(count)
}

pub async fn save_profile(path: &Path) -> Result<()> {
    let opts = crate::global_options::GLOBAL_OPTIONS.all().await;
    let mut table = toml::Table::new();
    for (key, value) in &opts {
        table.insert(key.clone(), toml::Value::String(value.clone()));
    }
    let content = toml::to_string_pretty(&table).context("Failed to serialize profile")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory '{}'", parent.display()))?;
    }
    std::fs::write(path, content)
        .with_context(|| format!("Failed to write profile '{}'", path.display()))?;
    Ok(())
}

use anyhow::Result;
use crate::modules::scanners;

pub async fn run_scan(module_name: &str, target: &str) -> Result<()> {
    match module_name {
        "sample_scanner" => {
            scanners::sample_scanner::run(target).await?;
        },
        // Add more scanner modules here ...
        _ => eprintln!("Scanner module '{}' not found.", module_name),
    }
    Ok(())
}

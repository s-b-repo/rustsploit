use anyhow::Result;
use crate::modules::scanners;

pub async fn run_scan(module_name: &str, target: &str) -> Result<()> {
    match module_name {
        "sample_scanner" => scanners::sample_scanner::run(target).await?,
        "ssdp_msearch" => scanners::ssdp_msearch::run(target).await?,
        "port_scanner" => scanners::port_scanner::run_interactive(target).await?, // ✅ interactive mode
        _ => eprintln!("Scanner module '{}' not found.", module_name),
    }

    Ok(())
}

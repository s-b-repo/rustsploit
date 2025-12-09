use anyhow::Result;

include!(concat!(env!("OUT_DIR"), "/scanner_dispatch.rs"));

pub async fn run_scan(module_name: &str, target: &str) -> Result<()> {
    dispatch(module_name, target).await
}

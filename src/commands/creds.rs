use anyhow::Result;

include!(concat!(env!("OUT_DIR"), "/creds_dispatch.rs"));

pub async fn run_cred_check(module_name: &str, target: &str) -> Result<()> {
    dispatch(module_name, target).await
}

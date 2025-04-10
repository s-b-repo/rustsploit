use anyhow::Result;
use crate::modules::creds;

pub async fn run_cred_check(module_name: &str, target: &str) -> Result<()> {
    match module_name {
        "sample_cred_check" => {
            creds::sample_cred_check::run(target).await?;
        },
        "ftp_bruteforce" => {
        creds::ftp_bruteforce::run(target).await?;
        },
        "ftp_anonymous" => {
            creds::ftp_anonymous::run(target).await?;
        },
        // Add more creds modules here ...
        _ => {
            eprintln!("Creds module '{}' not found.", module_name);
        },
    }

    Ok(())
}

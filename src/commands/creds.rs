use anyhow::{Result, bail};

use crate::modules::creds::generic::{
    ftp_anonymous,
    ftp_bruteforce,
    sample_cred_check,
    telnet_bruteforce,
};

pub async fn run_cred_check(module_name: &str, target: &str) -> Result<()> {
    match module_name {
        "generic/sample_cred_check"     => sample_cred_check::run(target).await?,
        "generic/ftp_bruteforce"    => ftp_bruteforce::run(target).await?,
        "generic/ftp_anonymous"     => ftp_anonymous::run(target).await?,
        "generic/telnet_bruteforce" => telnet_bruteforce::run(target).await?,
        _ => bail!("Creds module '{}' not found.", module_name),
    }

    Ok(())
}

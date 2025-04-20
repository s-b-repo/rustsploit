use anyhow::{Result, bail};

// Import all available credential modules
use crate::modules::creds::{
    generic::{
        ftp_anonymous,
        ftp_bruteforce,
        sample_cred_check,
        telnet_bruteforce,
        ssh_bruteforce,
        rtsp_bruteforce_advanced,
    },
    camera::acti::acti_camera_default,
};

/// Dispatch function for credential modules
pub async fn run_cred_check(module_name: &str, target: &str) -> Result<()> {
    match module_name {
        "generic/sample_cred_check"        => sample_cred_check::run(target).await?,
        "generic/ftp_bruteforce"           => ftp_bruteforce::run(target).await?,
        "generic/ftp_anonymous"            => ftp_anonymous::run(target).await?,
        "generic/telnet_bruteforce"        => telnet_bruteforce::run(target).await?,
        "generic/ssh_bruteforce"           => ssh_bruteforce::run(target).await?,
        "generic/rtsp_bruteforce_advanced" => rtsp_bruteforce_advanced::run(target).await?,
        "camera/acti/acti_camera_default"  => acti_camera_default::run(target).await?,

        _ => bail!("Creds module '{}' not found.", module_name),
    }

    Ok(())
}

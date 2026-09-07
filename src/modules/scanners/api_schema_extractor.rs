use anyhow::{Context, Result};
use colored::*;
use std::time::Duration;

use crate::module::{Finding, FindingKind, ModuleCtx, ModuleOutcome};
use crate::module_info::{ModuleInfo, ModuleRank};
use crate::utils::{build_http_client, cfg_prompt_int_range};

pub fn info() -> ModuleInfo {
    ModuleInfo {
        name: "API Schema Extractor".into(),
        description: "Parses OpenAPI/Swagger/GraphQL schemas from discovered endpoints \
            and auto-generates test requests for every documented path."
            .into(),
        authors: vec!["rustsploit contributors".into()],
        references: vec!["https://swagger.io/specification/".into()],
        disclosure_date: None,
        rank: ModuleRank::Great,
        default_port: Some(443),
    }
}

const API_SCHEMA_PATHS: &[&str] = &[
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger-ui.html",
    "/api/swagger.json",
    "/api/openapi.json",
    "/docs/api",
    "/.well-known/openid-configuration",
];

pub async fn run(ctx: &ModuleCtx) -> Result<ModuleOutcome> {
    let target = ctx
        .target
        .as_single()
        .context("requires single-host target")?;
    let timeout = Duration::from_secs(
        cfg_prompt_int_range("timeout", "Timeout (seconds)", 10, 1, 30).await? as u64,
    );
    let client = build_http_client(timeout).context("build http client")?;
    let base_url = if target.starts_with("http") {
        target.to_string()
    } else {
        format!("https://{}", target)
    };
    let mut outcome = ModuleOutcome::ok();
    let mut found_schemas: Vec<String> = Vec::new();

    crate::mprintln!(
        "{}",
        format!("[*] API Schema Discovery: {}", base_url)
            .cyan()
            .bold()
    );

    for path in API_SCHEMA_PATHS {
        if ctx.is_cancelled() {
            break;
        }
        ctx.rate_limit(target).await;
        let url = format!("{}{}", base_url, path);
        match tokio::time::timeout(timeout, client.get(&url).send()).await {
            Ok(Ok(resp)) => {
                let body = resp.text().await.unwrap_or_else(|e| {
                    tracing::trace!("body read failed: {}", e);
                    String::new()
                });
                if body.contains("\"swagger\"")
                    || body.contains("\"openapi\"")
                    || body.contains("\"paths\"")
                {
                    crate::mprintln!(
                        "{}",
                        format!("[+] API schema found at {} ({} bytes)", path, body.len())
                            .green()
                            .bold()
                    );
                    found_schemas.push(path.to_string());
                    // Extract endpoint paths from JSON
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                        if let Some(paths) = json.get("paths") {
                            if let Some(paths_obj) = paths.as_object() {
                                crate::mprintln!(
                                    "{}",
                                    format!("  [*] {} documented endpoints:", paths_obj.len())
                                        .cyan()
                                );
                                for (endpoint, _) in paths_obj.iter().take(20) {
                                    crate::mprintln!("    - {}", endpoint);
                                }
                            }
                        }
                    }
                    outcome.findings.push(Finding {
                        target: target.to_string(),
                        kind: FindingKind::Note,
                        message: format!("API schema at {}{} ({} bytes)", target, path, body.len()),
                        data: Some(
                            serde_json::json!({"host": target, "path": path, "bytes": body.len()}),
                        ),
                    });
                } else if body.contains("openid-configuration") {
                    crate::mprintln!("{}", format!("[+] OIDC discovery at {}", path).green());
                    found_schemas.push(format!("{}/.well-known/openid-configuration", target));
                    outcome.findings.push(Finding {
                        target: target.to_string(),
                        kind: FindingKind::Note,
                        message: format!("OIDC discovery at {}{}", target, path),
                        data: Some(serde_json::json!({"host": target, "type": "oidc"})),
                    });
                }
            }
            e => {
                tracing::trace!("probe timed out or connection failed: {:?}", e);
            }
        }
    }
    crate::mprintln!(
        "{}",
        format!("  Found {} schema(s).", found_schemas.len()).green()
    );
    Ok(outcome)
}
crate::register_native_module!(
    crate::module::Category::Scanners,
    "api_schema_extractor",
    native
);

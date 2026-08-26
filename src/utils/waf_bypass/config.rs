use std::time::Duration;

use super::techniques::Technique;

#[derive(Debug, Clone)]
pub struct WafBypassConfig {
    pub enabled: bool,
    pub mode: BypassMode,
    pub max_retries: u32,
    pub timeout: Duration,
    pub techniques: Vec<Technique>,
    pub stop_on_success: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassMode {
    Off,
    Incremental,
    Adaptive,
    Exhaustive,
}

impl Default for WafBypassConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: BypassMode::Incremental,
            max_retries: 5,
            timeout: Duration::from_secs(10),
            techniques: Technique::all().to_vec(),
            stop_on_success: true,
        }
    }
}

impl WafBypassConfig {
    pub async fn from_global_options() -> Self {
        let tenant = crate::tenant::resolve();
        let opts = tenant.global_options();

        let enabled = opts
            .get("waf_bypass")
            .await
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let mode = match opts.get("waf_bypass_mode").await.as_deref() {
            Some("adaptive") => BypassMode::Adaptive,
            Some("exhaustive") => BypassMode::Exhaustive,
            Some("incremental") | None => BypassMode::Incremental,
            Some("off") => BypassMode::Off,
            _ => BypassMode::Incremental,
        };

        let max_retries = opts
            .get("waf_bypass_retries")
            .await
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(5);

        let timeout = opts
            .get("waf_bypass_timeout")
            .await
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(10));

        let techniques = match opts.get("waf_bypass_techniques").await.as_deref() {
            Some("all") | None => Technique::all().to_vec(),
            Some(s) if s.is_empty() => Technique::all().to_vec(),
            Some(s) => {
                let mut techs: Vec<Technique> = Vec::new();
                for part in s.split(',') {
                    match part.trim() {
                        "get_body" => techs.push(Technique::GetBodySmuggle),
                        "encoding" | "url_encode" => {
                            techs.push(Technique::UrlEncodeSpecials);
                            techs.push(Technique::DoubleUrlEncode);
                            techs.push(Technique::UnicodeNormalize);
                        }
                        "method_override" => techs.push(Technique::MethodOverride),
                        "content_type" => techs.push(Technique::ContentTypeSpoof),
                        "header_smuggle" => techs.push(Technique::HeaderSmuggle),
                        "chunked" => techs.push(Technique::ChunkedTe),
                        "desync" => techs.push(Technique::Desync),
                        "http10" => techs.push(Technique::Http10Downgrade),
                        "websocket" => techs.push(Technique::WebSocketUpgrade),
                        "param_pollution" => techs.push(Technique::ParamPollution),
                        "case_whitespace" => techs.push(Technique::CaseWhitespace),
                        _ => {}
                    }
                }
                if techs.is_empty() {
                    Technique::all().to_vec()
                } else {
                    techs
                }
            }
        };

        Self {
            enabled,
            mode,
            max_retries,
            timeout,
            techniques,
            stop_on_success: true,
        }
    }
}

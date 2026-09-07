pub mod case_whitespace;
pub mod chunked;
pub mod content_type;
pub mod encoding;
pub mod get_body;
pub mod header_smuggle;
pub mod method_override;
pub mod origin_bypass;
pub mod param_pollution;
pub mod protocol;
pub mod websocket;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Technique {
    GetBodySmuggle,
    UrlEncodeSpecials,
    DoubleUrlEncode,
    UnicodeNormalize,
    MethodOverride,
    ContentTypeSpoof,
    HeaderSmuggle,
    ChunkedTe,
    Desync,
    Http10Downgrade,
    WebSocketUpgrade,
    ParamPollution,
    CaseWhitespace,
}

impl Technique {
    pub fn all() -> &'static [Technique] {
        &[
            Technique::GetBodySmuggle,
            Technique::UrlEncodeSpecials,
            Technique::DoubleUrlEncode,
            Technique::UnicodeNormalize,
            Technique::MethodOverride,
            Technique::ContentTypeSpoof,
            Technique::HeaderSmuggle,
            Technique::ChunkedTe,
            Technique::Desync,
            Technique::Http10Downgrade,
            Technique::WebSocketUpgrade,
            Technique::ParamPollution,
            Technique::CaseWhitespace,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            Technique::GetBodySmuggle => "GET body smuggle",
            Technique::UrlEncodeSpecials => "URL-encode specials",
            Technique::DoubleUrlEncode => "double URL-encode",
            Technique::UnicodeNormalize => "unicode normalize",
            Technique::MethodOverride => "HTTP method override",
            Technique::ContentTypeSpoof => "content-type spoofing",
            Technique::HeaderSmuggle => "header smuggling",
            Technique::ChunkedTe => "chunked transfer-encoding",
            Technique::Desync => "CL.TE/TE.CL desync",
            Technique::Http10Downgrade => "HTTP/1.0 downgrade",
            Technique::WebSocketUpgrade => "WebSocket upgrade tunnel",
            Technique::ParamPollution => "parameter pollution",
            Technique::CaseWhitespace => "case/whitespace manipulation",
        }
    }
}

pub mod config;
pub mod detection;
pub mod engine;
pub mod signatures;
pub mod techniques;

pub use config::WafBypassConfig;
pub use engine::send_with_bypass;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let cfg = WafBypassConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.max_retries, 5);
        assert_eq!(cfg.techniques.len(), 13);
    }

    #[test]
    fn technique_names() {
        for t in techniques::Technique::all() {
            let name = t.name();
            assert!(!name.is_empty());
        }
    }

    #[test]
    fn encoding_roundtrip_ascii() {
        let payload = b"hello world".to_vec();
        let encoded = techniques::encoding::encode_payload(
            &payload,
            techniques::Technique::UrlEncodeSpecials,
        )
        .unwrap();
        assert_eq!(std::str::from_utf8(&encoded).unwrap(), "hello%20world");
    }

    #[test]
    fn detection_blocked_403() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("content-type".to_string(), "text/html".to_string());
        let result = detection::is_blocked(403, "", &headers);
        assert!(result.is_some());
        if let Some(detection::BypassVerdict::Blocked { status, .. }) = result {
            assert_eq!(status, 403);
        } else {
            panic!("expected Blocked");
        }
    }

    #[test]
    fn detection_cloudflare_body() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("server".to_string(), "cloudflare".to_string());
        let result = detection::is_blocked(200, "cf-error-details here", &headers);
        assert!(result.is_some());
    }

    #[test]
    fn detection_waf_cloudflare() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("cf-ray".to_string(), "abc123".to_string());
        let wafs = detection::detect_waf(&headers, "");
        assert!(!wafs.is_empty());
        assert!(wafs.iter().any(|w| w.contains("Cloudflare")));
    }

    #[test]
    fn signatures_nonempty() {
        let sigs = signatures::known_signatures();
        assert!(!sigs.is_empty());
        for sig in sigs {
            assert!(!sig.name.is_empty());
        }
    }

    #[test]
    fn get_body_technique() {
        use http::Method;
        let mut method = Method::POST;
        let mut body: Option<Vec<u8>> = Some(b"test_payload".to_vec());
        techniques::get_body::apply(&mut method, &mut body, "https://example.com/");
        assert_eq!(method, Method::GET);
        assert_eq!(body.as_deref(), Some(b"test_payload" as &[u8]));
    }

    #[test]
    fn get_body_padding() {
        let mut body = b"payload".to_vec();
        let original_len = body.len();
        techniques::get_body::add_random_padding(&mut body);
        assert!(body.len() > original_len);
        assert!(body.ends_with(b"payload"));
    }
}

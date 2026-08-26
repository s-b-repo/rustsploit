use http::Method;

pub const TE_CL_PAIRS: &[(&str, &str)] = &[("chunked", "0"), ("chunked, identity", "0")];

pub fn cl_te_body(body: &[u8]) -> Vec<u8> {
    let mut smuggled: Vec<u8> = Vec::new();
    smuggled.extend_from_slice(b"0\r\n\r\n");
    smuggled.extend_from_slice(body);
    smuggled
}

pub fn http_10_request(url: &str) -> (Method, String) {
    (Method::GET, format!("{} HTTP/1.0", url))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn te_cl_pairs_nonempty() {
        assert!(!TE_CL_PAIRS.is_empty());
    }

    #[test]
    fn cl_te_body_wraps() {
        let result = cl_te_body(b"test");
        assert!(!result.is_empty());
        assert!(result.starts_with(b"0\r\n\r\n"));
    }

    #[test]
    fn http_10_request_works() {
        let (method, req) = http_10_request("/test");
        assert_eq!(method, Method::GET);
        assert!(req.contains("HTTP/1.0"));
    }
}

use http::Method;

pub fn apply(method: &mut Method) {
    // Method is unchanged; the caller adds override headers (OVERRIDE_HEADERS).
    tracing::trace!("method_override technique leaves {} unchanged", method);
}

pub const OVERRIDE_HEADERS: &[(&str, &str)] = &[
    ("X-HTTP-Method-Override", "POST"),
    ("X-HTTP-Method", "POST"),
    ("X-Method-Override", "POST"),
];

pub const OVERRIDE_QUERY_PARAMS: &[&str] = &["_method=POST"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_headers_nonempty() {
        assert!(!OVERRIDE_HEADERS.is_empty());
    }

    #[test]
    fn query_params_nonempty() {
        assert!(!OVERRIDE_QUERY_PARAMS.is_empty());
    }
}

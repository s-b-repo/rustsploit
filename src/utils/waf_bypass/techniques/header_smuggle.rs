pub const SMUGGLE_HEADERS: &[(&str, &str)] = &[
    ("X-Original-URL", "/"),
    ("X-Rewrite-URL", "/"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Forwarded-Host", "localhost"),
];

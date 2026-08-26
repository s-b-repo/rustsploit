pub fn chunk_body(body: &[u8], chunk_size: usize, extension: Option<&str>) -> Vec<u8> {
    let ext = extension.unwrap_or("comment=bypass");
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 0;
    while pos < body.len() {
        let end = (pos + chunk_size).min(body.len());
        let chunk = &body[pos..end];
        let size_hex = format!("{:X};{}\r\n", chunk.len(), ext);
        out.extend_from_slice(size_hex.as_bytes());
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
        pos = end;
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

pub fn chunk_sizes() -> Vec<usize> {
    vec![4, 8, 16, 32, 64]
}

pub fn chunk_extensions() -> Vec<&'static str> {
    vec!["comment=bypass", "foo=bar", ""]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_body_works() {
        let body = b"HELLO WORLD";
        let chunked = chunk_body(body, 4, None);
        assert!(!chunked.is_empty());
        assert!(chunked.ends_with(b"0\r\n\r\n"));
    }

    #[test]
    fn chunk_sizes_nonempty() {
        assert!(!chunk_sizes().is_empty());
    }

    #[test]
    fn chunk_extensions_nonempty() {
        assert!(!chunk_extensions().is_empty());
    }
}

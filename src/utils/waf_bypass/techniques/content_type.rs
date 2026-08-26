pub fn wrap_body_as_multipart(body: &[u8], boundary: &str) -> Vec<u8> {
    let mut parts: Vec<u8> = Vec::new();
    parts.extend_from_slice(b"--");
    parts.extend_from_slice(boundary.as_bytes());
    parts.extend_from_slice(b"\r\n");
    parts.extend_from_slice(b"Content-Disposition: form-data; name=\"data\"\r\n\r\n");
    parts.extend_from_slice(body);
    parts.extend_from_slice(b"\r\n--");
    parts.extend_from_slice(boundary.as_bytes());
    parts.extend_from_slice(b"--\r\n");
    parts
}

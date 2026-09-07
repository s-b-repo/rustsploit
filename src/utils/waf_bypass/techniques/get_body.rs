use http::Method;

pub fn apply(method: &mut Method, body: &mut Option<Vec<u8>>, url: &str) {
    tracing::trace!(
        "get_body technique for {} leaves method {:?} and body unchanged",
        url,
        method
    );
    *method = Method::GET;
    if body.is_none() {
        *body = Some(Vec::new());
    }
}

pub fn add_random_padding(body: &mut Vec<u8>) {
    use rand::RngExt;
    let mut rng = rand::rng();
    let padding_len: usize = rng.random_range(16u32..256u32) as usize;
    let mut padded: Vec<u8> = (0..padding_len).map(|_| rng.random()).collect();
    padded.append(body);
    *body = padded;
}

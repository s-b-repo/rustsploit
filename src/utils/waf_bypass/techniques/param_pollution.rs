pub const HPP_DUPLICATE: &[&str] = &["id=1&id=1' OR '1'='1", "id[]=1&id[]=1' OR '1'='1"];

pub const HPP_JSON_KEYS: &[&str] = &["id", "user", "name", "email", "role"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpp_duplicate_nonempty() {
        assert!(!HPP_DUPLICATE.is_empty());
    }

    #[test]
    fn hpp_json_keys_nonempty() {
        assert!(!HPP_JSON_KEYS.is_empty());
    }
}

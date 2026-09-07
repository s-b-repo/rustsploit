pub fn obfuscate_keyword(input: &str) -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                if rng.random::<bool>() {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            } else {
                c
            }
        })
        .collect()
}

pub fn insert_whitespace(input: &str) -> String {
    use rand::RngExt;
    let separators = ["\t", "\n", "/**/", "  ", "\r\n"];
    let mut rng = rand::rng();
    let mut result = String::new();
    for (i, c) in input.chars().enumerate() {
        result.push(c);
        if i < input.len() - 1 && rng.random::<f64>() < 0.3 {
            let idx: usize = rng.random_range(0usize..separators.len());
            result.push_str(separators[idx]);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscate_mixed_case() {
        let result = obfuscate_keyword("SELECT * FROM users");
        assert!(!result.is_empty());
    }

    #[test]
    fn whitespace_injection() {
        let result = insert_whitespace("UNION SELECT");
        assert!(!result.is_empty());
    }
}

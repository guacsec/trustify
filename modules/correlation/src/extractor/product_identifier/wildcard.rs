/// Returns true if value contains CSAF glob wildcards (`*` or `?`).
pub fn has_wildcards(value: &str) -> bool {
    value.contains('*') || value.contains('?')
}

/// CSAF 2.0 glob matching: `*` = zero or more chars, `?` = exactly one char.
pub fn csaf_glob_matches(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let v: Vec<char> = value.chars().collect();
    do_match(&p, 0, &v, 0)
}

fn do_match(p: &[char], pi: usize, v: &[char], vi: usize) -> bool {
    if pi == p.len() {
        return vi == v.len();
    }
    match p[pi] {
        '*' => {
            for i in vi..=v.len() {
                if do_match(p, pi + 1, v, i) {
                    return true;
                }
            }
            false
        }
        '?' => vi < v.len() && do_match(p, pi + 1, v, vi + 1),
        c => vi < v.len() && v[vi] == c && do_match(p, pi + 1, v, vi + 1),
    }
}

/// Convert a CSAF glob pattern to a SQL LIKE pattern.
///
/// Escapes LIKE metacharacters (`\`, `%`, `_`) first, then replaces
/// `*` → `%` and `?` → `_`.
pub fn csaf_glob_to_like(pattern: &str) -> String {
    let mut result = String::with_capacity(pattern.len() + 4);
    for c in pattern.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '%' => result.push_str("\\%"),
            '_' => result.push_str("\\_"),
            '*' => result.push('%'),
            '?' => result.push('_'),
            c => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn exact_match() {
        assert!(csaf_glob_matches("6925281924439", "6925281924439"));
        assert!(!csaf_glob_matches("6925281924439", "6925281924438"));
    }

    #[test]
    fn star_suffix() {
        assert!(csaf_glob_matches("6925281*", "6925281924439"));
        assert!(csaf_glob_matches("6925281*", "6925281"));
        assert!(!csaf_glob_matches("6925281*", "692528"));
    }

    #[test]
    fn question_mark() {
        assert!(csaf_glob_matches("Flip ?", "Flip 4"));
        assert!(csaf_glob_matches("Flip ?", "Flip 5"));
        assert!(!csaf_glob_matches("Flip ?", "Flip 42"));
        assert!(!csaf_glob_matches("Flip ?", "Flip "));
    }

    #[test]
    fn mixed_wildcards() {
        assert!(csaf_glob_matches("6RA801?-??V62-*", "6RA8012-34V62-0AA0"));
        assert!(!csaf_glob_matches("6RA801?-??V62-*", "6RA8012-34X62-0AA0"));
    }

    #[test]
    fn no_match() {
        assert!(!csaf_glob_matches("ABC*", "XYZ123"));
        assert!(!csaf_glob_matches("?", ""));
    }

    #[test]
    fn star_matches_empty() {
        assert!(csaf_glob_matches("*", ""));
        assert!(csaf_glob_matches("*", "anything"));
    }

    #[test]
    fn has_wildcards_detection() {
        assert!(has_wildcards("6925281*"));
        assert!(has_wildcards("Flip ?"));
        assert!(!has_wildcards("6925281924439"));
    }

    #[test]
    fn like_conversion() {
        assert_eq!(csaf_glob_to_like("6925281*"), "6925281%");
        assert_eq!(csaf_glob_to_like("Flip ?"), "Flip _");
        assert_eq!(csaf_glob_to_like("100%_done"), "100\\%\\_done");
        assert_eq!(csaf_glob_to_like("a*b?c"), "a%b_c");
    }
}

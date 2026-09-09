use std::cmp::Ordering;

/// Extract segments from an RPM version string, matching the SQL regex
/// `(\d+|[a-zA-Z]+|[~^])`. Separators (`.`, `-`, `_`, `:`, etc.) are skipped.
fn extract_segments(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut segments = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            segments.push(&s[start..i]);
        } else if b.is_ascii_alphabetic() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            segments.push(&s[start..i]);
        } else if b == b'~' || b == b'^' {
            segments.push(&s[i..i + 1]);
            i += 1;
        } else {
            i += 1;
        }
    }
    segments
}

/// RPM version comparator ported from `rpmver_cmp` SQL (m0002330 with epoch support).
///
/// Handles epoch (`N:version`), tilde (`~` sorts before everything),
/// caret (`^` sorts after base version but before the next numeric segment),
/// and standard RPM segment-by-segment comparison.
pub fn rpmver_cmp(a: &str, b: &str) -> Option<Ordering> {
    if a == b {
        return Some(Ordering::Equal);
    }

    // Extract epoch (default 0 when omitted)
    let (a_epoch, a_rest) = extract_epoch(a);
    let (b_epoch, b_rest) = extract_epoch(b);
    match a_epoch.cmp(&b_epoch) {
        Ordering::Equal => {}
        ord => return Some(ord),
    }

    let a_segs = extract_segments(a_rest);
    let b_segs = extract_segments(b_rest);
    let a_len = a_segs.len();
    let b_len = b_segs.len();
    let common = a_len.min(b_len);

    for i in 0..common {
        let mut a_seg = a_segs[i];
        let mut b_seg = b_segs[i];
        let a_is_num = a_seg.bytes().next().is_some_and(|c| c.is_ascii_digit());
        let b_is_num = b_seg.bytes().next().is_some_and(|c| c.is_ascii_digit());

        if a_is_num {
            if b_is_num {
                // Both numeric: strip leading zeros (SQL does `a_seg := ltrim(a_seg, '0')`)
                a_seg = a_seg.trim_start_matches('0');
                b_seg = b_seg.trim_start_matches('0');
                match a_seg.len().cmp(&b_seg.len()) {
                    Ordering::Equal => {} // fall through to string compare of trimmed values
                    ord => return Some(ord),
                }
            } else {
                return Some(Ordering::Greater); // numeric > alpha
            }
        } else if b_is_num {
            return Some(Ordering::Less); // alpha < numeric
        } else if a_seg == "~" {
            if b_seg != "~" {
                return Some(Ordering::Less); // ~ < everything
            }
        } else if b_seg == "~" {
            return Some(Ordering::Greater); // everything > ~
        } else if a_seg == "^" {
            if b_seg != "^" {
                return Some(Ordering::Less); // ^ < non-^ (within same position)
            }
        } else if b_seg == "^" {
            return Some(Ordering::Greater); // non-^ > ^
        }

        // String comparison of (possibly trimmed) segments
        match a_seg.cmp(b_seg) {
            Ordering::Equal => {}
            ord => return Some(ord),
        }
    }

    // Handle remaining segments after the common prefix
    let a_next = a_segs.get(a_len.min(common));
    let b_next = b_segs.get(b_len.min(common));

    // ~ at the boundary means that side is less
    if b_next.is_some_and(|s| *s == "~") {
        return Some(Ordering::Greater);
    }
    if a_next.is_some_and(|s| *s == "~") {
        return Some(Ordering::Less);
    }
    // ^ at the boundary
    if b_next.is_some_and(|s| *s == "^") {
        return Some(Ordering::Less);
    }
    if a_next.is_some_and(|s| *s == "^") {
        return Some(Ordering::Greater);
    }

    // Longer version is greater
    Some(a_len.cmp(&b_len))
}

fn extract_epoch(s: &str) -> (i64, &str) {
    if let Some(colon_pos) = s.find(':') {
        let prefix = &s[..colon_pos];
        if !prefix.is_empty()
            && prefix.bytes().all(|b| b.is_ascii_digit())
            && let Ok(epoch) = prefix.parse::<i64>()
        {
            return (epoch, &s[colon_pos + 1..]);
        }
    }
    (0, s)
}

#[cfg(test)]
mod test {
    use super::*;

    fn assert_cmp(a: &str, b: &str, expected: Ordering) {
        assert_eq!(rpmver_cmp(a, b), Some(expected), "rpmver_cmp({a:?}, {b:?})");
    }

    // Upstream RPM rpmvercmp test vectors

    // basic numeric
    #[test]
    fn numeric_equal() {
        assert_cmp("1.0", "1.0", Ordering::Equal);
    }
    #[test]
    fn numeric_less() {
        assert_cmp("1.0", "2.0", Ordering::Less);
    }
    #[test]
    fn numeric_greater() {
        assert_cmp("2.0", "1.0", Ordering::Greater);
    }
    #[test]
    fn numeric_subversion_equal() {
        assert_cmp("2.0.1", "2.0.1", Ordering::Equal);
    }
    #[test]
    fn numeric_subversion_less() {
        assert_cmp("2.0", "2.0.1", Ordering::Less);
    }
    #[test]
    fn numeric_subversion_greater() {
        assert_cmp("2.0.1", "2.0", Ordering::Greater);
    }

    // alpha suffixes
    #[test]
    fn alpha_equal() {
        assert_cmp("2.0.1a", "2.0.1a", Ordering::Equal);
    }
    #[test]
    fn alpha_greater() {
        assert_cmp("2.0.1a", "2.0.1", Ordering::Greater);
    }
    #[test]
    fn alpha_less() {
        assert_cmp("2.0.1", "2.0.1a", Ordering::Less);
    }

    // mixed alpha-numeric
    #[test]
    fn mixed_equal() {
        assert_cmp("5.5p1", "5.5p1", Ordering::Equal);
    }
    #[test]
    fn mixed_less() {
        assert_cmp("5.5p1", "5.5p2", Ordering::Less);
    }
    #[test]
    fn mixed_numeric_wins() {
        assert_cmp("5.5p10", "5.5p1", Ordering::Greater);
    }
    #[test]
    fn mixed_dot_numeric() {
        assert_cmp("10xyz", "10.1xyz", Ordering::Less);
    }
    #[test]
    fn alpha_vs_numeric() {
        assert_cmp("xyz.4", "8", Ordering::Less);
    }

    // leading zeros
    #[test]
    fn leading_zeros_equal() {
        assert_cmp("10.0001", "10.0001", Ordering::Equal);
    }
    #[test]
    fn leading_zeros_normalized_equal() {
        assert_cmp("10.0001", "10.1", Ordering::Equal);
    }
    #[test]
    fn leading_zeros_reversed() {
        assert_cmp("10.1", "10.0001", Ordering::Equal);
    }
    #[test]
    fn leading_zeros_less() {
        assert_cmp("10.0001", "10.0039", Ordering::Less);
    }

    // separator equivalence
    #[test]
    fn sep_underscore_equal() {
        assert_cmp("2_0", "2_0", Ordering::Equal);
    }
    #[test]
    fn sep_dot_underscore() {
        assert_cmp("2.0", "2_0", Ordering::Equal);
    }
    #[test]
    fn sep_plus_underscore() {
        assert_cmp("a+", "a_", Ordering::Equal);
    }
    #[test]
    fn sep_plus_underscore_prefix() {
        assert_cmp("+a", "_a", Ordering::Equal);
    }
    #[test]
    fn sep_plus_underscore_bare() {
        assert_cmp("+", "_", Ordering::Equal);
    }

    // tilde
    #[test]
    fn tilde_equal() {
        assert_cmp("1.0~rc1", "1.0~rc1", Ordering::Equal);
    }
    #[test]
    fn tilde_less_than_release() {
        assert_cmp("1.0~rc1", "1.0", Ordering::Less);
    }
    #[test]
    fn release_greater_than_tilde() {
        assert_cmp("1.0", "1.0~rc1", Ordering::Greater);
    }
    #[test]
    fn tilde_rc_ordering() {
        assert_cmp("1.0~rc1", "1.0~rc2", Ordering::Less);
    }
    #[test]
    fn tilde_nested() {
        assert_cmp("1.0~rc1~git123", "1.0~rc1", Ordering::Less);
    }

    // caret
    #[test]
    fn caret_equal() {
        assert_cmp("1.0^", "1.0^", Ordering::Equal);
    }
    #[test]
    fn caret_greater_than_release() {
        assert_cmp("1.0^", "1.0", Ordering::Greater);
    }
    #[test]
    fn release_less_than_caret() {
        assert_cmp("1.0", "1.0^", Ordering::Less);
    }
    #[test]
    fn caret_git_greater() {
        assert_cmp("1.0^git1", "1.0", Ordering::Greater);
    }
    #[test]
    fn caret_git_ordering() {
        assert_cmp("1.0^git1", "1.0^git2", Ordering::Less);
    }
    #[test]
    fn caret_less_than_dot() {
        assert_cmp("1.0^git1", "1.01", Ordering::Less);
    }
    #[test]
    fn caret_date_less_than_dot() {
        assert_cmp("1.0^20160101", "1.0.1", Ordering::Less);
    }

    // mixed tilde + caret
    #[test]
    fn tilde_caret_mixed() {
        assert_cmp("1.0~rc1^git1", "1.0~rc1", Ordering::Greater);
    }
    #[test]
    fn caret_tilde_ordering() {
        assert_cmp("1.0^git1", "1.0^git1~pre", Ordering::Greater);
    }
    #[test]
    fn tilde_in_caret_less() {
        assert_cmp("1.0^git1~pre", "1.0^git1", Ordering::Less);
    }

    // epoch
    #[test]
    fn epoch_equal() {
        assert_cmp("1:1.0", "1:1.0", Ordering::Equal);
    }
    #[test]
    fn epoch_trumps_version() {
        assert_cmp("1:1.0", "2.0", Ordering::Greater);
    }
    #[test]
    fn no_epoch_less() {
        assert_cmp("2.0", "1:1.0", Ordering::Less);
    }
    #[test]
    fn epoch_zero_equals_none() {
        assert_cmp("0:1.0", "1.0", Ordering::Equal);
    }
    #[test]
    fn no_epoch_equals_zero() {
        assert_cmp("1.0", "0:1.0", Ordering::Equal);
    }
    #[test]
    fn epoch_comparison() {
        assert_cmp("2:1.0", "1:2.0", Ordering::Greater);
    }
    #[test]
    fn epoch_comparison_reversed() {
        assert_cmp("1:2.0", "2:1.0", Ordering::Less);
    }
    #[test]
    fn same_epoch_version_less() {
        assert_cmp("1:1.0", "1:1.1", Ordering::Less);
    }
    #[test]
    fn same_epoch_version_greater() {
        assert_cmp("1:1.1", "1:1.0", Ordering::Greater);
    }

    #[test]
    fn extract_segments_basic() {
        assert_eq!(extract_segments("1.2.3"), vec!["1", "2", "3"]);
        assert_eq!(
            extract_segments("1.0~rc1^git1"),
            vec!["1", "0", "~", "rc", "1", "^", "git", "1"]
        );
    }
}

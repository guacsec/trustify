use std::cmp::Ordering;

/// Extract the numeric prefix of a Python version string — everything before
/// the first alphabetic character, `+`, or `-`.
fn extract_numeric_prefix(s: &str) -> &str {
    let end = s
        .find(|c: char| c.is_ascii_alphabetic() || c == '+' || c == '-')
        .unwrap_or(s.len());
    &s[..end]
}

/// Parse a version part: missing → 0, empty → error, non-numeric → error.
fn parse_part(s: Option<&&str>) -> Option<i64> {
    match s {
        None => Some(0),
        Some(&"") => None,
        Some(s) => s.parse().ok(),
    }
}

/// Find a PEP 440 pre-release marker (`a`, `b`, or `rc`) preceded by a digit and
/// an optional separator (`-`, `_`, `.`). Returns the marker string and optional
/// numeric suffix.
///
/// Matches the SQL pattern `\d[-_\.]?(a|b|rc)(\d*)` from m0001040.
fn find_pre_release(s: &str) -> Option<(&str, Option<i64>)> {
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        if !bytes[i].is_ascii_digit() {
            continue;
        }
        let mut j = i + 1;
        if j < bytes.len() && matches!(bytes[j], b'-' | b'_' | b'.') {
            j += 1;
        }
        if j >= bytes.len() {
            continue;
        }

        let (marker, marker_end) = if s[j..].starts_with("rc") {
            ("rc", j + 2)
        } else if bytes[j] == b'a' {
            ("a", j + 1)
        } else if bytes[j] == b'b' {
            ("b", j + 1)
        } else {
            continue;
        };

        // Extract trailing digits
        let mut num_end = marker_end;
        while num_end < bytes.len() && bytes[num_end].is_ascii_digit() {
            num_end += 1;
        }
        let num = if num_end > marker_end {
            s[marker_end..num_end].parse().ok()
        } else {
            None
        };

        return Some((marker, num));
    }
    None
}

/// Find a `postN` release marker.
fn find_post_release(s: &str) -> Option<i64> {
    let pos = s.find("post")?;
    let after = &s[pos + 4..];
    let num_str: &str = &after[..after
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after.len())];
    if num_str.is_empty() {
        return None;
    }
    num_str.parse().ok()
}

/// Find a `devN` release marker.
fn find_dev_release(s: &str) -> Option<i64> {
    let pos = s.find("dev")?;
    let after = &s[pos + 3..];
    let num_str: &str = &after[..after
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after.len())];
    if num_str.is_empty() {
        return None;
    }
    num_str.parse().ok()
}

/// Find a local version segment: `+<alphanumeric_and_dots>`.
fn find_local_version(s: &str) -> Option<&str> {
    let pos = s.find('+')?;
    let after = &s[pos + 1..];
    let end = after
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '.')
        .unwrap_or(after.len());
    if end > 0 { Some(&after[..end]) } else { None }
}

/// Python version comparator ported from `pythonver_cmp` SQL (m0001040).
///
/// Handles PEP 440 versioning: pre-release (`a`, `b`, `rc`), post-release (`postN`),
/// dev-release (`devN`), and local versions (`+suffix`).
pub fn pythonver_cmp(left: &str, right: &str) -> Option<Ordering> {
    let left_prefix = extract_numeric_prefix(left);
    let right_prefix = extract_numeric_prefix(right);

    let left_parts: Vec<&str> = left_prefix.split('.').collect();
    let right_parts: Vec<&str> = right_prefix.split('.').collect();

    let left_major: i64 = left_parts.first().and_then(|s| s.parse().ok())?;
    let left_minor: i64 = parse_part(left_parts.get(1))?;
    let left_patch: i64 = parse_part(left_parts.get(2))?;

    let right_major: i64 = right_parts.first().and_then(|s| s.parse().ok())?;
    let right_minor: i64 = parse_part(right_parts.get(1))?;
    let right_patch: i64 = parse_part(right_parts.get(2))?;

    // Compare major.minor.patch
    match left_major.cmp(&right_major) {
        Ordering::Equal => {}
        ord => return Some(ord),
    }
    match left_minor.cmp(&right_minor) {
        Ordering::Equal => {}
        ord => return Some(ord),
    }
    match left_patch.cmp(&right_patch) {
        Ordering::Equal => {}
        ord => return Some(ord),
    }

    // Pre-release: has pre < no pre
    let left_pre = find_pre_release(left);
    let right_pre = find_pre_release(right);

    match (&left_pre, &right_pre) {
        (Some(_), None) => return Some(Ordering::Less),
        (None, Some(_)) => return Some(Ordering::Greater),
        (Some((lm, ln)), Some((rm, rn))) => {
            // a < b < rc (string comparison works: "a" < "b" < "rc")
            match lm.cmp(rm) {
                Ordering::Equal => {}
                ord => return Some(ord),
            }
            match ln.cmp(rn) {
                Ordering::Equal => {}
                ord => return Some(ord),
            }
        }
        (None, None) => {}
    }

    // Post-release: has post > no post
    let left_post = find_post_release(left);
    let right_post = find_post_release(right);

    match (left_post, right_post) {
        (Some(_), None) => return Some(Ordering::Greater),
        (None, Some(_)) => return Some(Ordering::Less),
        (Some(lp), Some(rp)) => match lp.cmp(&rp) {
            Ordering::Equal => {}
            ord => return Some(ord),
        },
        (None, None) => {}
    }

    // Dev-release: has dev < no dev
    let left_dev = find_dev_release(left);
    let right_dev = find_dev_release(right);

    match (left_dev, right_dev) {
        (Some(_), None) => return Some(Ordering::Less),
        (None, Some(_)) => return Some(Ordering::Greater),
        (Some(ld), Some(rd)) => match ld.cmp(&rd) {
            Ordering::Equal => {}
            ord => return Some(ord),
        },
        (None, None) => {}
    }

    // Local version: has local > no local, string comparison between locals
    let left_local = find_local_version(left);
    let right_local = find_local_version(right);

    match (left_local, right_local) {
        (Some(_), None) => return Some(Ordering::Greater),
        (None, Some(_)) => return Some(Ordering::Less),
        (Some(ll), Some(rl)) => match ll.cmp(rl) {
            Ordering::Equal => {}
            ord => return Some(ord),
        },
        (None, None) => {}
    }

    Some(Ordering::Equal)
}

#[cfg(test)]
mod test {
    use super::*;

    fn assert_cmp(left: &str, right: &str, expected: Ordering) {
        assert_eq!(
            pythonver_cmp(left, right),
            Some(expected),
            "pythonver_cmp({left:?}, {right:?})"
        );
    }

    #[test]
    fn basic_comparison() {
        assert_cmp("1.8.3", "2.9.0", Ordering::Less);
        assert_cmp("1.8.3", "1.8.3", Ordering::Equal);
        assert_cmp("1.8.3", "1.8.2", Ordering::Greater);
    }

    #[test]
    fn missing_patch() {
        assert_cmp("1.8.3", "1.8", Ordering::Greater);
        assert_cmp("1.8", "1.8.3", Ordering::Less);
        assert_cmp("1.8", "1.8.0", Ordering::Equal);
    }

    #[test]
    fn pre_release() {
        assert_cmp("1.2.3a1", "1.2.3", Ordering::Less);
        assert_cmp("1.2.3a1", "1.2.3.b1", Ordering::Less);
        assert_cmp("1.2.3b1", "1.2.3.rc1", Ordering::Less);
        assert_cmp("1.2.3rc1", "1.2.3", Ordering::Less);
    }

    #[test]
    fn post_release() {
        assert_cmp("1.2.3.post1", "1.2.3", Ordering::Greater);
        assert_cmp("1.2.3.post2", "1.2.3.post1", Ordering::Greater);
    }

    #[test]
    fn dev_release() {
        assert_cmp("1.2.3.dev1", "1.2.3", Ordering::Less);
    }

    #[test]
    fn local_version() {
        assert_cmp("1.2.3", "1.2.3+abc", Ordering::Less);
        assert_cmp("1.2.3+abc", "1.2.3", Ordering::Greater);
        assert_cmp("1.2.3+def", "1.2.3+abc", Ordering::Greater);
        assert_cmp("1.2.3+abc", "1.2.3+def", Ordering::Less);
    }

    #[test]
    fn hyphenated_pre_release() {
        assert_cmp("1.2.3-rc0", "1.2.3", Ordering::Less);
        assert_cmp("1.2.3", "1.2.3-rc0", Ordering::Greater);
        assert_cmp("1.2.3-rc0", "1.2.3-rc0", Ordering::Equal);
    }

    #[test]
    fn version_matches_exact() {
        use super::super::{VersionRange, VersionScheme, version_matches};

        assert!(version_matches(
            "1.0.2",
            &VersionRange::Exact("1.0.2".into()),
            VersionScheme::Python,
        ));
        assert!(!version_matches(
            "1.0.2",
            &VersionRange::Exact("1.0.0".into()),
            VersionScheme::Python,
        ));
    }

    #[test]
    fn version_matches_ranges() {
        use super::super::{VersionBound, VersionRange, VersionScheme, version_matches};

        assert!(version_matches(
            "1.0.2",
            &VersionRange::Range(
                VersionBound::Unbounded,
                VersionBound::Inclusive("1.0.2".into()),
            ),
            VersionScheme::Python,
        ));

        assert!(!version_matches(
            "1.0.2",
            &VersionRange::Range(
                VersionBound::Unbounded,
                VersionBound::Exclusive("1.0.2".into()),
            ),
            VersionScheme::Python,
        ));

        assert!(version_matches(
            "1.0.2b2",
            &VersionRange::Range(
                VersionBound::Unbounded,
                VersionBound::Exclusive("1.0.2".into()),
            ),
            VersionScheme::Python,
        ));

        assert!(version_matches(
            "1.0.2",
            &VersionRange::Range(
                VersionBound::Inclusive("1.0.2".into()),
                VersionBound::Exclusive("1.0.5".into()),
            ),
            VersionScheme::Python,
        ));
    }

    #[test]
    fn commons_compress() {
        use super::super::{VersionBound, VersionRange, VersionScheme, version_matches};

        assert!(!version_matches(
            "1.26",
            &VersionRange::Range(
                VersionBound::Inclusive("1.21".into()),
                VersionBound::Exclusive("1.26".into()),
            ),
            VersionScheme::Python,
        ));
    }
}

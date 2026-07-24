/// Semver comparison, ported from the PL/pgSQL `semver_cmp` function.
///
/// Splits on `+` (build metadata, ignored), then `-` (pre-release),
/// then `.` (major.minor.patch). Pre-release identifiers are compared
/// segment-by-segment: numeric segments numerically, string segments
/// lexicographically. A version without pre-release is greater than
/// one with pre-release (e.g., `1.0.0 > 1.0.0-alpha`).
use std::cmp::Ordering;

/// Compare two semver-ish version strings.
///
/// Returns `None` if either string cannot be parsed (matches the
/// PL/pgSQL `EXCEPTION WHEN OTHERS THEN RETURN NULL` behavior).
pub fn semver_cmp(left: &str, right: &str) -> Option<Ordering> {
    let (left_release, left_pre) = parse_semver(left)?;
    let (right_release, right_pre) = parse_semver(right)?;

    // Compare major.minor.patch
    for (l, r) in left_release.iter().zip(right_release.iter()) {
        match l.cmp(r) {
            Ordering::Equal => continue,
            other => return Some(other),
        }
    }

    // Compare cardinality (more parts = greater, matching PL/pgSQL)
    match left_release.len().cmp(&right_release.len()) {
        Ordering::Equal => {}
        other => return Some(other),
    }

    // Pre-release comparison
    match (&left_pre, &right_pre) {
        (None, None) => Some(Ordering::Equal),
        (Some(_), None) => Some(Ordering::Less),
        (None, Some(_)) => Some(Ordering::Greater),
        (Some(l), Some(r)) => Some(compare_pre_release(l, r)),
    }
}

/// Parse a semver string into (release parts, optional pre-release string).
///
/// Handles: `major.minor.patch-pre+build` and lenient variants like
/// `major.minor` (patch defaults to 0).
fn parse_semver(s: &str) -> Option<(Vec<u64>, Option<String>)> {
    // Strip build metadata (everything after +)
    let without_build = s.split('+').next().unwrap_or(s);

    // Split release from pre-release (first -)
    let (release_str, pre) = match without_build.find('-') {
        Some(idx) => (&without_build[..idx], Some(without_build[idx + 1..].to_string())),
        None => (without_build, None),
    };

    // Parse release segments
    let parts: Vec<u64> = release_str
        .split('.')
        .map(|p| p.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;

    if parts.is_empty() {
        return None;
    }

    // Pad to at least 3 parts (major.minor.patch)
    let mut padded = parts;
    while padded.len() < 3 {
        padded.push(0);
    }

    Some((padded, pre))
}

/// Compare pre-release identifiers segment-by-segment.
///
/// Per semver spec: numeric identifiers are compared as integers;
/// alphanumeric identifiers are compared lexicographically; numeric
/// has lower precedence than alphanumeric; fewer fields is less than
/// more fields when all preceding fields are equal.
fn compare_pre_release(left: &str, right: &str) -> Ordering {
    let left_parts: Vec<&str> = left.split('.').collect();
    let right_parts: Vec<&str> = right.split('.').collect();

    for (l, r) in left_parts.iter().zip(right_parts.iter()) {
        let l_num = l.parse::<u64>().ok();
        let r_num = r.parse::<u64>().ok();

        let ord = match (l_num, r_num) {
            (Some(ln), Some(rn)) => ln.cmp(&rn),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => l.cmp(r),
        };

        if ord != Ordering::Equal {
            return ord;
        }
    }

    left_parts.len().cmp(&right_parts.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ordering() {
        assert_eq!(semver_cmp("1.0.0", "1.0.0"), Some(Ordering::Equal));
        assert_eq!(semver_cmp("1.0.1", "1.0.0"), Some(Ordering::Greater));
        assert_eq!(semver_cmp("1.0.0", "1.0.1"), Some(Ordering::Less));
        assert_eq!(semver_cmp("2.0.0", "1.9.9"), Some(Ordering::Greater));
    }

    #[test]
    fn prerelease_less_than_release() {
        assert_eq!(semver_cmp("1.0.0-alpha", "1.0.0"), Some(Ordering::Less));
        assert_eq!(semver_cmp("1.0.0", "1.0.0-alpha"), Some(Ordering::Greater));
    }

    #[test]
    fn prerelease_ordering() {
        assert_eq!(
            semver_cmp("1.0.0-alpha", "1.0.0-beta"),
            Some(Ordering::Less)
        );
        assert_eq!(
            semver_cmp("1.0.0-alpha.1", "1.0.0-alpha.2"),
            Some(Ordering::Less)
        );
        assert_eq!(
            semver_cmp("1.0.0-1", "1.0.0-2"),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn build_metadata_ignored() {
        assert_eq!(
            semver_cmp("1.0.0+build1", "1.0.0+build2"),
            Some(Ordering::Equal)
        );
    }

    #[test]
    fn lenient_parsing() {
        assert_eq!(semver_cmp("1.0", "1.0.0"), Some(Ordering::Equal));
        assert_eq!(semver_cmp("1", "1.0.0"), Some(Ordering::Equal));
    }

    #[test]
    fn invalid_returns_none() {
        assert_eq!(semver_cmp("not-a-version", "1.0.0"), None);
    }
}

/// Maven version comparison, ported from the PL/pgSQL `mavenver_cmp`.
///
/// Splits on the first `-` to separate the numeric release
/// (`major.minor.revision`) from a qualifier/build suffix. Versions
/// without a qualifier are greater than versions with one (opposite of
/// semver pre-release). Qualifiers are compared case-insensitively.
///
/// Note: the original PL/pgSQL had a bug (`right_numeric` checked
/// `left_qualifier_or_build` instead of `right_qualifier_or_build`).
/// This port fixes that bug.
use std::cmp::Ordering;

/// Compare two Maven version strings.
///
/// Returns `None` if either string cannot be parsed.
pub fn mavenver_cmp(left: &str, right: &str) -> Option<Ordering> {
    let (left_release, left_qual) = parse_maven(left)?;
    let (right_release, right_qual) = parse_maven(right)?;

    // Compare major.minor.revision
    for (l, r) in left_release.iter().zip(right_release.iter()) {
        match l.cmp(r) {
            Ordering::Equal => continue,
            other => return Some(other),
        }
    }

    // Compare cardinality
    match left_release.len().cmp(&right_release.len()) {
        Ordering::Equal => {}
        other => return Some(other),
    }

    // Qualifier comparison: no qualifier > has qualifier
    match (&left_qual, &right_qual) {
        (None, None) => Some(Ordering::Equal),
        (None, Some(_)) => Some(Ordering::Greater),
        (Some(_), None) => Some(Ordering::Less),
        (Some(l), Some(r)) => {
            // If both are purely numeric, compare as integers
            if let (Ok(ln), Ok(rn)) = (l.parse::<u64>(), r.parse::<u64>()) {
                return Some(ln.cmp(&rn));
            }
            // Case-insensitive lexicographic comparison
            let l_lower = l.to_lowercase();
            let r_lower = r.to_lowercase();
            Some(l_lower.cmp(&r_lower))
        }
    }
}

/// Parse a Maven version string into (release parts, optional qualifier).
///
/// The qualifier is everything after the first `-` (including the `-`).
fn parse_maven(s: &str) -> Option<(Vec<u64>, Option<String>)> {
    let (release_str, qualifier) = match s.find('-') {
        Some(idx) => (&s[..idx], Some(s[idx + 1..].to_string())),
        None => (s, None),
    };

    let parts: Vec<u64> = release_str
        .split('.')
        .map(|p| p.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;

    if parts.is_empty() {
        return None;
    }

    // Pad to at least 3 parts (major.minor.revision)
    let mut padded = parts;
    while padded.len() < 3 {
        padded.push(0);
    }

    Some((padded, qualifier))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ordering() {
        assert_eq!(mavenver_cmp("1.0.0", "1.0.0"), Some(Ordering::Equal));
        assert_eq!(mavenver_cmp("1.0.1", "1.0.0"), Some(Ordering::Greater));
        assert_eq!(mavenver_cmp("2.0.0", "1.9.9"), Some(Ordering::Greater));
    }

    #[test]
    fn qualifier_less_than_no_qualifier() {
        // In Maven, 1.0.0-SNAPSHOT < 1.0.0 (no qualifier wins)
        assert_eq!(
            mavenver_cmp("1.0.0-SNAPSHOT", "1.0.0"),
            Some(Ordering::Less)
        );
        assert_eq!(
            mavenver_cmp("1.0.0", "1.0.0-SNAPSHOT"),
            Some(Ordering::Greater)
        );
    }

    #[test]
    fn qualifier_ordering() {
        assert_eq!(
            mavenver_cmp("1.0.0-alpha", "1.0.0-beta"),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn numeric_qualifier() {
        assert_eq!(
            mavenver_cmp("1.0.0-1", "1.0.0-2"),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn case_insensitive_qualifier() {
        assert_eq!(
            mavenver_cmp("1.0.0-ALPHA", "1.0.0-alpha"),
            Some(Ordering::Equal)
        );
    }

    #[test]
    fn lenient_parsing() {
        assert_eq!(mavenver_cmp("1.0", "1.0.0"), Some(Ordering::Equal));
    }
}

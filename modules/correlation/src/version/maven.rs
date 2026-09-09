use std::cmp::Ordering;

fn is_numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Maven version comparator ported from `mavenver_cmp` SQL (m0001010).
///
/// Handles qualifier suffixes (e.g., `-beta3`, `-redhat-0001`) and extra version
/// parts beyond major.minor.revision (e.g., `4.1.108.Final`).
///
/// **Bug fix**: the SQL on line 106 uses `is_numeric(left_qualifier_or_build)` for
/// both sides; this port correctly checks each side independently.
pub fn mavenver_cmp(left: &str, right: &str) -> Option<Ordering> {
    // Split qualifier: everything from the first '-' onwards (as non-whitespace)
    let (left_version, left_qualifier) = split_qualifier(left);
    let (right_version, right_qualifier) = split_qualifier(right);

    // Split version on '.'
    let left_parts: Vec<&str> = left_version.split('.').collect();
    let right_parts: Vec<&str> = right_version.split('.').collect();

    let left_major: i64 = left_parts.first().unwrap_or(&"0").parse().ok()?;
    let left_minor: i64 = parse_part(left_parts.get(1)).ok()?;
    let left_revision: i64 = parse_part(left_parts.get(2)).ok()?;

    let right_major: i64 = right_parts.first().unwrap_or(&"0").parse().ok()?;
    let right_minor: i64 = parse_part(right_parts.get(1)).ok()?;
    let right_revision: i64 = parse_part(right_parts.get(2)).ok()?;

    // Compare major.minor.revision
    match left_major.cmp(&right_major) {
        Ordering::Equal => {}
        ord => return Some(ord),
    }
    match left_minor.cmp(&right_minor) {
        Ordering::Equal => {}
        ord => return Some(ord),
    }
    match left_revision.cmp(&right_revision) {
        Ordering::Equal => {}
        ord => return Some(ord),
    }

    // Compare cardinality of version parts (minimum 3)
    let left_card = left_parts.len().max(3);
    let right_card = right_parts.len().max(3);
    match left_card.cmp(&right_card) {
        Ordering::Equal => {}
        ord => return Some(ord),
    }

    // Compare extra version parts beyond major.minor.revision (e.g., "Final" in 4.1.108.Final)
    for i in 3..left_parts.len() {
        let l = left_parts.get(i).copied().unwrap_or("");
        let r = right_parts.get(i).copied().unwrap_or("");
        match l.cmp(r) {
            Ordering::Equal => {}
            ord => return Some(ord),
        }
    }

    // Compare qualifiers
    match (left_qualifier, right_qualifier) {
        (None, None) => Some(Ordering::Equal),
        (None, Some(_)) => {
            // No qualifier: if version has extra parts (build number), treat as lower;
            // otherwise treat as higher than a qualified version.
            if left_parts.len() > 3 {
                Some(Ordering::Less)
            } else {
                Some(Ordering::Greater)
            }
        }
        (Some(_), None) => {
            if right_parts.len() > 3 {
                Some(Ordering::Greater)
            } else {
                Some(Ordering::Less)
            }
        }
        (Some(lq), Some(rq)) => {
            // BUG FIX: SQL checks is_numeric(left) for both; we check each independently
            let l_numeric = is_numeric(lq);
            let r_numeric = is_numeric(rq);

            if l_numeric && r_numeric {
                let lb: i64 = lq.parse().ok()?;
                let rb: i64 = rq.parse().ok()?;
                Some(lb.cmp(&rb))
            } else {
                Some(lq.to_lowercase().cmp(&rq.to_lowercase()))
            }
        }
    }
}

/// Split a Maven version into (version_part, optional_qualifier).
/// The qualifier is everything from the first `-` to the end (including the `-`).
fn split_qualifier(s: &str) -> (&str, Option<&str>) {
    if let Some(pos) = s.find('-') {
        let qualifier = &s[pos..]; // includes the leading '-'
        (&s[..pos], Some(qualifier))
    } else {
        (s, None)
    }
}

/// Parse an optional version part: missing → 0, present but empty/non-numeric → error.
fn parse_part(s: Option<&&str>) -> Result<i64, ()> {
    match s {
        None => Ok(0),
        Some(&"") => Err(()),
        Some(s) => s.parse().map_err(|_| ()),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn assert_cmp(left: &str, right: &str, expected: Ordering) {
        assert_eq!(
            mavenver_cmp(left, right),
            Some(expected),
            "mavenver_cmp({left:?}, {right:?})"
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
    fn qualifier_ordering() {
        assert_cmp("1.8-beta3", "1.8-beta4", Ordering::Less);
        assert_cmp("1.8-beta-3", "1.8-beta-4", Ordering::Less);
        assert_cmp("1.8-beta4", "1.8-beta3", Ordering::Greater);
        assert_cmp("1.8-beta-4", "1.8-beta-3", Ordering::Greater);
    }

    #[test]
    fn qualifier_vs_no_qualifier() {
        assert_cmp("1.8-beta3", "1.8", Ordering::Less);
        assert_cmp("1.8", "1.8-beta-3", Ordering::Greater);
    }

    #[test]
    fn numeric_qualifier() {
        assert_cmp("1.8-1", "1.8-3", Ordering::Less);
        assert_cmp("1.8-3", "1.8-1", Ordering::Greater);
    }

    #[test]
    fn numeric_qualifier_cross_format() {
        assert_cmp("1.8-1", "1.8.0-3", Ordering::Less);
        assert_cmp("1.8-3", "1.8.0-1", Ordering::Greater);
    }

    #[test]
    fn netty_codec() {
        assert_cmp("4.1.108.Final", "4.1.108.Final-redhat-0001", Ordering::Less);
        assert_cmp(
            "4.1.108.Alpha-redhat-0001",
            "4.1.108.Final-redhat-0001",
            Ordering::Less,
        );
        assert_cmp(
            "4.1.108.Final-redhat-0001",
            "4.1.108.Final-redhat-0001",
            Ordering::Equal,
        );
        assert_cmp(
            "4.1.108.Final-redhat-0001",
            "4.1.108.Final-redhat-0002",
            Ordering::Less,
        );
    }

    #[test]
    fn version_matches_exact() {
        use super::super::{VersionRange, VersionScheme, version_matches};

        assert!(version_matches(
            "1.0.2",
            &VersionRange::Exact("1.0.2".into()),
            VersionScheme::Maven,
        ));
        assert!(!version_matches(
            "1.0.2",
            &VersionRange::Exact("1.0.0".into()),
            VersionScheme::Maven,
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
            VersionScheme::Maven,
        ));

        assert!(!version_matches(
            "1.0.2",
            &VersionRange::Range(
                VersionBound::Unbounded,
                VersionBound::Exclusive("1.0.2".into()),
            ),
            VersionScheme::Maven,
        ));

        assert!(version_matches(
            "1.0.2-beta.2",
            &VersionRange::Range(
                VersionBound::Unbounded,
                VersionBound::Exclusive("1.0.2".into()),
            ),
            VersionScheme::Maven,
        ));

        assert!(version_matches(
            "1.0.2",
            &VersionRange::Range(
                VersionBound::Inclusive("1.0.2".into()),
                VersionBound::Exclusive("1.0.5".into()),
            ),
            VersionScheme::Maven,
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
            VersionScheme::Maven,
        ));
    }

    #[test]
    fn rht_suffixen() {
        use super::super::{VersionBound, VersionRange, VersionScheme, version_matches};

        assert!(!version_matches(
            "1.26.0.redhat-00001",
            &VersionRange::Range(
                VersionBound::Inclusive("1.21".into()),
                VersionBound::Exclusive("1.26".into()),
            ),
            VersionScheme::Maven,
        ));
    }

    #[test]
    fn netty_codec_version_matches() {
        use super::super::{VersionBound, VersionRange, VersionScheme, version_matches};

        assert!(version_matches(
            "4.1.108.Final-redhat-0001",
            &VersionRange::Exact("4.1.108.Final-redhat-0001".into()),
            VersionScheme::Maven,
        ));

        assert!(version_matches(
            "4.1.108.Final-redhat-0001",
            &VersionRange::Range(
                VersionBound::Inclusive("4.1.108".into()),
                VersionBound::Exclusive("4.2".into()),
            ),
            VersionScheme::Maven,
        ));

        assert!(!version_matches(
            "4.1.108.Final-redhat-0001",
            &VersionRange::Range(
                VersionBound::Inclusive("0.0".into()),
                VersionBound::Exclusive("4.1.108.Final".into()),
            ),
            VersionScheme::Maven,
        ));
    }
}

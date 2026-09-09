use std::cmp::Ordering;

fn is_numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Lenient semver comparator ported from the `semver_cmp` SQL function.
///
/// Handles non-standard versions (extra dot-separated parts, missing minor/patch)
/// by treating missing numeric parts as 0 and comparing extra parts by cardinality.
/// Returns `None` on parse failure (non-numeric major/minor/patch).
pub fn semver_cmp(left: &str, right: &str) -> Option<Ordering> {
    // Split off build metadata (ignored for precedence)
    let (left_no_build, _) = left.split_once('+').unwrap_or((left, ""));
    let (right_no_build, _) = right.split_once('+').unwrap_or((right, ""));

    // Split off pre-release
    let (left_version, left_pre) = left_no_build
        .split_once('-')
        .map_or((left_no_build, None), |(v, p)| (v, Some(p)));
    let (right_version, right_pre) = right_no_build
        .split_once('-')
        .map_or((right_no_build, None), |(v, p)| (v, Some(p)));

    // Split version on '.'
    let left_parts: Vec<&str> = left_version.split('.').collect();
    let right_parts: Vec<&str> = right_version.split('.').collect();

    let left_major: i64 = left_parts.first().unwrap_or(&"0").parse().ok()?;
    let left_minor: i64 = left_parts.get(1).unwrap_or(&"0").parse().ok()?;
    let left_patch: i64 = left_parts.get(2).unwrap_or(&"0").parse().ok()?;

    let right_major: i64 = right_parts.first().unwrap_or(&"0").parse().ok()?;
    let right_minor: i64 = right_parts.get(1).unwrap_or(&"0").parse().ok()?;
    let right_patch: i64 = right_parts.get(2).unwrap_or(&"0").parse().ok()?;

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

    // Compare cardinality (extra version parts beyond major.minor.patch)
    let left_card = left_parts.len().max(3);
    let right_card = right_parts.len().max(3);
    match left_card.cmp(&right_card) {
        Ordering::Equal => {}
        ord => return Some(ord),
    }

    // Compare pre-release
    match (left_pre, right_pre) {
        (None, None) => Some(Ordering::Equal),
        (None, Some(_)) => Some(Ordering::Greater),
        (Some(_), None) => Some(Ordering::Less),
        (Some(lp), Some(rp)) => {
            let left_segs: Vec<&str> = lp.split('.').collect();
            let right_segs: Vec<&str> = rp.split('.').collect();

            for i in 0..11 {
                let l = left_segs.get(i);
                let r = right_segs.get(i);

                match (l, r) {
                    (None, None) => return Some(Ordering::Equal),
                    (None, Some(_)) => return Some(Ordering::Less),
                    (Some(_), None) => return Some(Ordering::Greater),
                    (Some(ls), Some(rs)) => {
                        if is_numeric(ls) && is_numeric(rs) {
                            let ln: i64 = ls.parse().ok()?;
                            let rn: i64 = rs.parse().ok()?;
                            match ln.cmp(&rn) {
                                Ordering::Equal => {}
                                ord => return Some(ord),
                            }
                        } else {
                            match ls.cmp(rs) {
                                Ordering::Equal => {}
                                ord => return Some(ord),
                            }
                        }
                    }
                }
            }
            // Exceeded max pre-release segments — matches SQL returning null
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn assert_cmp(left: &str, right: &str, expected: Ordering) {
        assert_eq!(
            semver_cmp(left, right),
            Some(expected),
            "semver_cmp({left:?}, {right:?})"
        );
    }

    #[test]
    fn precedence_chain() {
        let versions = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.2",
            "1.1.3",
        ];
        for pair in versions.windows(2) {
            assert_cmp(pair[0], pair[1], Ordering::Less);
        }
    }

    #[test]
    fn reverse_precedence_chain() {
        let versions = [
            "1.1.3",
            "1.0.2",
            "1.0.0",
            "1.0.0-rc.1",
            "1.0.0-beta.11",
            "1.0.0-beta.2",
            "1.0.0-beta",
            "1.0.0-alpha.beta",
            "1.0.0-alpha.1",
            "1.0.0-alpha",
        ];
        for pair in versions.windows(2) {
            assert_cmp(pair[0], pair[1], Ordering::Greater);
        }
    }

    #[test]
    fn equality() {
        assert_cmp("1.0.0", "1.0.0", Ordering::Equal);
    }

    #[test]
    fn comparison_helpers() {
        assert_cmp("1.0.1", "1.0.0", Ordering::Greater);
        assert_cmp("1.0.0", "1.0.1", Ordering::Less);
        assert_cmp("1.1.1", "1.2.0", Ordering::Less);
        assert_cmp("1.2.1", "1.2.0", Ordering::Greater);
    }

    #[test]
    fn version_matches_exact() {
        use super::super::{VersionRange, VersionScheme, version_matches};

        assert!(version_matches(
            "1.0.2",
            &VersionRange::Exact("1.0.2".into()),
            VersionScheme::Semver,
        ));
        assert!(!version_matches(
            "1.0.2",
            &VersionRange::Exact("1.0.0".into()),
            VersionScheme::Semver,
        ));
    }

    #[test]
    fn version_matches_inclusive_upper() {
        use super::super::{VersionBound, VersionRange, VersionScheme, version_matches};

        assert!(version_matches(
            "1.0.2",
            &VersionRange::Range(
                VersionBound::Unbounded,
                VersionBound::Inclusive("1.0.2".into()),
            ),
            VersionScheme::Semver,
        ));
    }

    #[test]
    fn version_matches_exclusive_upper() {
        use super::super::{VersionBound, VersionRange, VersionScheme, version_matches};

        assert!(!version_matches(
            "1.0.2",
            &VersionRange::Range(
                VersionBound::Unbounded,
                VersionBound::Exclusive("1.0.2".into()),
            ),
            VersionScheme::Semver,
        ));
    }

    #[test]
    fn pre_release_within_exclusive_upper() {
        use super::super::{VersionBound, VersionRange, VersionScheme, version_matches};

        assert!(version_matches(
            "1.0.2-beta.2",
            &VersionRange::Range(
                VersionBound::Unbounded,
                VersionBound::Exclusive("1.0.2".into()),
            ),
            VersionScheme::Semver,
        ));
    }

    #[test]
    fn inclusive_low_exclusive_high() {
        use super::super::{VersionBound, VersionRange, VersionScheme, version_matches};

        assert!(version_matches(
            "1.0.2",
            &VersionRange::Range(
                VersionBound::Inclusive("1.0.2".into()),
                VersionBound::Exclusive("1.0.5".into()),
            ),
            VersionScheme::Semver,
        ));
    }

    #[test]
    fn datelike_version() {
        use super::super::{VersionBound, VersionRange, VersionScheme, version_matches};

        assert!(version_matches(
            "7.1.0-0.20231218164901.0660a66.el9",
            &VersionRange::Range(
                VersionBound::Inclusive("7.1.0-0.20231218164901.0660a66.el9".into()),
                VersionBound::Exclusive("8.1.0-0.20231218164901.0660a66.el9".into()),
            ),
            VersionScheme::Semver,
        ));
    }

    #[test]
    fn shalike_version_no_match() {
        use super::super::{VersionBound, VersionRange, VersionScheme, version_matches};

        assert!(!version_matches(
            "sha256:cab90a3a2eb5bdff7a1420a6d89c64a8d32b1be7bd3ec311e483d2c3b9a47307",
            &VersionRange::Range(
                VersionBound::Inclusive("7.1.0-0.20231218164901.0660a66.el9".into()),
                VersionBound::Exclusive("8.1.0-0.20231218164901.0660a66.el9".into()),
            ),
            VersionScheme::Semver,
        ));
    }

    #[test]
    fn netty_codec_semver() {
        use super::super::{VersionBound, VersionRange, VersionScheme, version_matches};

        assert!(version_matches(
            "4.1.108.Final-redhat-0001",
            &VersionRange::Exact("4.1.108.Final-redhat-0001".into()),
            VersionScheme::Semver,
        ));

        assert!(version_matches(
            "4.1.108.Final-redhat-0001",
            &VersionRange::Range(
                VersionBound::Inclusive("4.1.108".into()),
                VersionBound::Exclusive("4.2".into()),
            ),
            VersionScheme::Semver,
        ));
    }

    #[test]
    fn commons_compress_semver() {
        use super::super::{VersionBound, VersionRange, VersionScheme, version_matches};

        assert!(!version_matches(
            "1.26",
            &VersionRange::Range(
                VersionBound::Inclusive("1.21".into()),
                VersionBound::Exclusive("1.26".into()),
            ),
            VersionScheme::Semver,
        ));
    }

    #[test]
    fn rht_suffixen_semver() {
        use super::super::{VersionBound, VersionRange, VersionScheme, version_matches};

        assert!(!version_matches(
            "1.26.0.redhat-00001",
            &VersionRange::Range(
                VersionBound::Inclusive("1.21".into()),
                VersionBound::Exclusive("1.26".into()),
            ),
            VersionScheme::Semver,
        ));
    }

    #[test]
    fn missing_minor_patch() {
        assert_cmp("1", "1.0.0", Ordering::Equal);
        assert_cmp("2", "1.9.9", Ordering::Greater);
    }
}

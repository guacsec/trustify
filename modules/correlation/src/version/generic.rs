use super::VersionBound;

/// Generic/Git version matching: equality-only against inclusive bounds,
/// with wildcard support when both bounds are unbounded.
///
/// Ported from `generic_version_matches` / `gitver_version_matches` SQL
/// functions (updated in m0002320).
pub fn generic_version_matches(version: &str, low: &VersionBound, high: &VersionBound) -> bool {
    if matches!(low, VersionBound::Unbounded) && matches!(high, VersionBound::Unbounded) {
        return true;
    }

    if let VersionBound::Inclusive(v) = low
        && version == v
    {
        return true;
    }

    if let VersionBound::Inclusive(v) = high
        && version == v
    {
        return true;
    }

    false
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn both_unbounded_is_wildcard() {
        assert!(generic_version_matches(
            "anything",
            &VersionBound::Unbounded,
            &VersionBound::Unbounded,
        ));
    }

    #[test]
    fn inclusive_low_match() {
        assert!(generic_version_matches(
            "1.0.0",
            &VersionBound::Inclusive("1.0.0".into()),
            &VersionBound::Unbounded,
        ));
    }

    #[test]
    fn inclusive_high_match() {
        assert!(generic_version_matches(
            "2.0.0",
            &VersionBound::Unbounded,
            &VersionBound::Inclusive("2.0.0".into()),
        ));
    }

    #[test]
    fn inclusive_no_match() {
        assert!(!generic_version_matches(
            "1.5.0",
            &VersionBound::Inclusive("1.0.0".into()),
            &VersionBound::Inclusive("2.0.0".into()),
        ));
    }

    #[test]
    fn exclusive_bounds_never_match() {
        assert!(!generic_version_matches(
            "1.0.0",
            &VersionBound::Exclusive("1.0.0".into()),
            &VersionBound::Unbounded,
        ));
    }

    #[test]
    fn one_unbounded_no_match() {
        assert!(!generic_version_matches(
            "different",
            &VersionBound::Inclusive("1.0.0".into()),
            &VersionBound::Unbounded,
        ));
    }
}

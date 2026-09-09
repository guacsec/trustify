pub mod generic;
pub mod maven;
pub mod python;
pub mod rpm;
pub mod semver;

use std::cmp::Ordering;

/// Version comparison scheme, independent of the entity crate's SeaORM-derived enum.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum VersionScheme {
    Generic,
    Git,
    Semver,
    Rpm,
    Python,
    Maven,
}

impl From<&str> for VersionScheme {
    fn from(s: &str) -> Self {
        match s {
            "commit" | "git" => Self::Git,
            "custom" | "generic" => Self::Generic,
            "maven" => Self::Maven,
            "npm" | "semver" | "gem" | "golang" | "nuget" | "packagist" | "hex" | "swift"
            | "pub" | "cargo" => Self::Semver,
            "python" => Self::Python,
            "rpm" => Self::Rpm,
            _ => Self::Generic,
        }
    }
}

/// A version bound in a range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionBound {
    Inclusive(String),
    Exclusive(String),
    Unbounded,
}

/// A version range specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionRange {
    Exact(String),
    Range(VersionBound, VersionBound),
}

/// Check whether `version` falls within `range` under the given `scheme`.
pub fn version_matches(version: &str, range: &VersionRange, scheme: VersionScheme) -> bool {
    match range {
        VersionRange::Exact(v) => version == v,
        VersionRange::Range(low, high) => match scheme {
            VersionScheme::Generic | VersionScheme::Git => {
                generic::generic_version_matches(version, low, high)
            }
            VersionScheme::Semver => range_matches(version, low, high, semver::semver_cmp),
            VersionScheme::Rpm => range_matches(version, low, high, rpm::rpmver_cmp),
            VersionScheme::Maven => range_matches(version, low, high, maven::mavenver_cmp),
            VersionScheme::Python => range_matches(version, low, high, python::pythonver_cmp),
        },
    }
}

/// Generic range-matching logic shared by all ordered version schemes.
///
/// Mirrors the `<scheme>_version_matches` SQL functions: both bounds unbounded is a
/// wildcard match, parse failures (cmp returning `None`) are treated as non-matching,
/// and a bound that is `Unbounded` skips its constraint.
fn range_matches(
    version: &str,
    low: &VersionBound,
    high: &VersionBound,
    cmp_fn: fn(&str, &str) -> Option<Ordering>,
) -> bool {
    if matches!(low, VersionBound::Unbounded) && matches!(high, VersionBound::Unbounded) {
        return true;
    }

    let low_cmp = match low {
        VersionBound::Inclusive(v) | VersionBound::Exclusive(v) => cmp_fn(version, v),
        VersionBound::Unbounded => None,
    };

    if let Some(ord) = low_cmp {
        match low {
            VersionBound::Inclusive(_) => {
                if ord == Ordering::Less {
                    return false;
                }
            }
            VersionBound::Exclusive(_) => {
                if ord != Ordering::Greater {
                    return false;
                }
            }
            VersionBound::Unbounded => {}
        }
    }

    let high_cmp = match high {
        VersionBound::Inclusive(v) | VersionBound::Exclusive(v) => cmp_fn(version, v),
        VersionBound::Unbounded => None,
    };

    if let Some(ord) = high_cmp {
        match high {
            VersionBound::Inclusive(_) => {
                if ord == Ordering::Greater {
                    return false;
                }
            }
            VersionBound::Exclusive(_) => {
                if ord != Ordering::Less {
                    return false;
                }
            }
            VersionBound::Unbounded => {}
        }
    }

    // If neither comparison produced a result (both unbounded after the wildcard
    // check, or all cmp calls returned None due to parse errors), no match.
    if low_cmp.is_none() && high_cmp.is_none() {
        return false;
    }

    true
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn scheme_from_str() {
        assert_eq!(VersionScheme::from("semver"), VersionScheme::Semver);
        assert_eq!(VersionScheme::from("npm"), VersionScheme::Semver);
        assert_eq!(VersionScheme::from("gem"), VersionScheme::Semver);
        assert_eq!(VersionScheme::from("golang"), VersionScheme::Semver);
        assert_eq!(VersionScheme::from("rpm"), VersionScheme::Rpm);
        assert_eq!(VersionScheme::from("maven"), VersionScheme::Maven);
        assert_eq!(VersionScheme::from("python"), VersionScheme::Python);
        assert_eq!(VersionScheme::from("git"), VersionScheme::Git);
        assert_eq!(VersionScheme::from("commit"), VersionScheme::Git);
        assert_eq!(VersionScheme::from("generic"), VersionScheme::Generic);
        assert_eq!(VersionScheme::from("custom"), VersionScheme::Generic);
        assert_eq!(VersionScheme::from("unknown"), VersionScheme::Generic);
    }

    #[test]
    fn exact_match() {
        let range = VersionRange::Exact("1.0.0".into());
        assert!(version_matches("1.0.0", &range, VersionScheme::Semver));
        assert!(!version_matches("1.0.1", &range, VersionScheme::Semver));
    }

    #[test]
    fn wildcard_match() {
        let range = VersionRange::Range(VersionBound::Unbounded, VersionBound::Unbounded);
        assert!(version_matches("anything", &range, VersionScheme::Semver));
        assert!(version_matches("1.0.0", &range, VersionScheme::Generic));
    }

    #[test]
    fn inclusive_range() {
        let range = VersionRange::Range(
            VersionBound::Inclusive("1.0.0".into()),
            VersionBound::Inclusive("2.0.0".into()),
        );
        assert!(version_matches("1.0.0", &range, VersionScheme::Semver));
        assert!(version_matches("1.5.0", &range, VersionScheme::Semver));
        assert!(version_matches("2.0.0", &range, VersionScheme::Semver));
        assert!(!version_matches("0.9.0", &range, VersionScheme::Semver));
        assert!(!version_matches("2.0.1", &range, VersionScheme::Semver));
    }

    #[test]
    fn exclusive_range() {
        let range = VersionRange::Range(
            VersionBound::Exclusive("1.0.0".into()),
            VersionBound::Exclusive("2.0.0".into()),
        );
        assert!(!version_matches("1.0.0", &range, VersionScheme::Semver));
        assert!(version_matches("1.5.0", &range, VersionScheme::Semver));
        assert!(!version_matches("2.0.0", &range, VersionScheme::Semver));
    }

    #[test]
    fn half_open_range() {
        let range = VersionRange::Range(
            VersionBound::Inclusive("1.0.0".into()),
            VersionBound::Exclusive("2.0.0".into()),
        );
        assert!(version_matches("1.0.0", &range, VersionScheme::Semver));
        assert!(version_matches("1.9.9", &range, VersionScheme::Semver));
        assert!(!version_matches("2.0.0", &range, VersionScheme::Semver));
    }

    #[test]
    fn unbounded_low() {
        let range = VersionRange::Range(
            VersionBound::Unbounded,
            VersionBound::Exclusive("2.0.0".into()),
        );
        assert!(version_matches("0.1.0", &range, VersionScheme::Semver));
        assert!(version_matches("1.9.9", &range, VersionScheme::Semver));
        assert!(!version_matches("2.0.0", &range, VersionScheme::Semver));
    }

    #[test]
    fn unbounded_high() {
        let range = VersionRange::Range(
            VersionBound::Inclusive("1.0.0".into()),
            VersionBound::Unbounded,
        );
        assert!(!version_matches("0.9.0", &range, VersionScheme::Semver));
        assert!(version_matches("1.0.0", &range, VersionScheme::Semver));
        assert!(version_matches("99.0.0", &range, VersionScheme::Semver));
    }

    #[test]
    fn parse_failure_no_match() {
        let range = VersionRange::Range(
            VersionBound::Inclusive("1.0.0".into()),
            VersionBound::Exclusive("2.0.0".into()),
        );
        assert!(!version_matches(
            "sha256:abc123",
            &range,
            VersionScheme::Semver
        ));
    }
}

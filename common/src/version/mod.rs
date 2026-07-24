/// Rust-native version comparison functions, ported from the PL/pgSQL
/// implementations in the migration SQL. These enable in-memory version
/// matching without round-tripping to PostgreSQL.
///
/// Each scheme has a `*_cmp` function returning `Option<Ordering>` and
/// a `*_version_matches` function that checks range membership. The
/// range-checking logic is factored into [`range_matches`] and reused
/// by all schemes that support ordering.
mod maven;
mod python;
mod rpm;
mod semver;

use std::cmp::Ordering;

pub use self::semver::semver_cmp;

/// A version range with optional lower and upper bounds.
///
/// Mirrors the `version_range` database table. Each bound is optional;
/// when present, the `*_inclusive` flag controls whether the boundary
/// value itself is included (`[`/`]`) or excluded (`(`/`)`).
#[derive(Debug, Clone)]
pub struct VersionRange {
    pub scheme: VersionScheme,
    pub low_version: Option<String>,
    pub low_inclusive: bool,
    pub high_version: Option<String>,
    pub high_inclusive: bool,
}

/// Version scheme identifier, matching the `version_scheme_id` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VersionScheme {
    Semver,
    Rpm,
    Maven,
    Python,
    Golang,
    Generic,
    Git,
    Npm,
    NuGet,
    Gem,
    Hex,
    Swift,
    Pub,
    Packagist,
    Cargo,
}

impl VersionScheme {
    /// Parse a scheme string (as stored in the database) into the enum.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "semver" => Some(Self::Semver),
            "rpm" => Some(Self::Rpm),
            "maven" => Some(Self::Maven),
            "python" => Some(Self::Python),
            "golang" => Some(Self::Golang),
            "generic" => Some(Self::Generic),
            "git" => Some(Self::Git),
            "npm" => Some(Self::Npm),
            "nuget" => Some(Self::NuGet),
            "gem" => Some(Self::Gem),
            "hex" => Some(Self::Hex),
            "swift" => Some(Self::Swift),
            "pub" => Some(Self::Pub),
            "packagist" => Some(Self::Packagist),
            "cargo" => Some(Self::Cargo),
            _ => None,
        }
    }
}

/// Check whether `version` falls within the given `range` using the
/// range's version scheme for ordering.
///
/// This is the Rust equivalent of the PL/pgSQL `version_matches()`
/// dispatcher.
pub fn version_matches(version: &str, range: &VersionRange) -> bool {
    match range.scheme {
        VersionScheme::Generic | VersionScheme::Git => {
            exact_version_matches(version, range)
        }
        VersionScheme::Golang => {
            let normalized = version.strip_prefix('v').unwrap_or(version);
            range_matches(normalized, range, semver::semver_cmp)
        }
        VersionScheme::Semver
        | VersionScheme::Npm
        | VersionScheme::NuGet
        | VersionScheme::Gem
        | VersionScheme::Hex
        | VersionScheme::Swift
        | VersionScheme::Pub
        | VersionScheme::Packagist
        | VersionScheme::Cargo => {
            range_matches(version, range, semver::semver_cmp)
        }
        VersionScheme::Rpm => {
            range_matches(version, range, rpm::rpmver_cmp)
        }
        VersionScheme::Maven => {
            range_matches(version, range, maven::mavenver_cmp)
        }
        VersionScheme::Python => {
            range_matches(version, range, python::pythonver_cmp)
        }
    }
}

/// Range-checking template shared by all orderable schemes.
///
/// Mirrors the PL/pgSQL `semver_version_matches` logic exactly:
/// - If `cmp_fn` returns `None` (parse error), that bound is skipped.
/// - If both bounds are unset or unparseable, returns `false`.
fn range_matches(
    version: &str,
    range: &VersionRange,
    cmp_fn: fn(&str, &str) -> Option<Ordering>,
) -> bool {
    let low_cmp = range
        .low_version
        .as_deref()
        .and_then(|low| cmp_fn(version, low));

    if let Some(ord) = low_cmp {
        if range.low_inclusive {
            if ord == Ordering::Less {
                return false;
            }
        } else if ord != Ordering::Greater {
            return false;
        }
    }

    let high_cmp = range
        .high_version
        .as_deref()
        .and_then(|high| cmp_fn(version, high));

    if let Some(ord) = high_cmp {
        if range.high_inclusive {
            if ord == Ordering::Greater {
                return false;
            }
        } else if ord != Ordering::Less {
            return false;
        }
    }

    // Both bounds unset or unparseable → no match.
    if low_cmp.is_none() && high_cmp.is_none() {
        return false;
    }

    true
}

/// Exact-equality matching for schemes without ordering (generic, git).
///
/// Only matches if the version string exactly equals an inclusive bound.
fn exact_version_matches(version: &str, range: &VersionRange) -> bool {
    if range.low_inclusive
        && range.low_version.as_deref() == Some(version)
    {
        return true;
    }
    if range.high_inclusive
        && range.high_version.as_deref() == Some(version)
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(
        scheme: VersionScheme,
        low: Option<&str>,
        low_incl: bool,
        high: Option<&str>,
        high_incl: bool,
    ) -> VersionRange {
        VersionRange {
            scheme,
            low_version: low.map(String::from),
            low_inclusive: low_incl,
            high_version: high.map(String::from),
            high_inclusive: high_incl,
        }
    }

    #[test]
    fn semver_inclusive_range() {
        let r = range(VersionScheme::Semver, Some("1.0.0"), true, Some("2.0.0"), true);
        assert!(version_matches("1.0.0", &r));
        assert!(version_matches("1.5.0", &r));
        assert!(version_matches("2.0.0", &r));
        assert!(!version_matches("0.9.0", &r));
        assert!(!version_matches("2.0.1", &r));
    }

    #[test]
    fn semver_exclusive_range() {
        let r = range(VersionScheme::Semver, Some("1.0.0"), false, Some("2.0.0"), false);
        assert!(!version_matches("1.0.0", &r));
        assert!(version_matches("1.5.0", &r));
        assert!(!version_matches("2.0.0", &r));
    }

    #[test]
    fn semver_half_open_low() {
        let r = range(VersionScheme::Semver, Some("1.0.0"), true, None, false);
        assert!(version_matches("1.0.0", &r));
        assert!(version_matches("99.0.0", &r));
        assert!(!version_matches("0.9.0", &r));
    }

    #[test]
    fn semver_half_open_high() {
        let r = range(VersionScheme::Semver, None, false, Some("2.0.0"), false);
        assert!(version_matches("1.0.0", &r));
        assert!(!version_matches("2.0.0", &r));
    }

    #[test]
    fn semver_both_null_returns_false() {
        let r = range(VersionScheme::Semver, None, false, None, false);
        assert!(!version_matches("1.0.0", &r));
    }

    #[test]
    fn generic_exact_match() {
        let r = range(VersionScheme::Generic, Some("1.2.3"), true, None, false);
        assert!(version_matches("1.2.3", &r));
        assert!(!version_matches("1.2.4", &r));
    }

    #[test]
    fn generic_non_inclusive_never_matches() {
        let r = range(VersionScheme::Generic, Some("1.2.3"), false, None, false);
        assert!(!version_matches("1.2.3", &r));
    }

    #[test]
    fn golang_strips_v_prefix() {
        let r = range(VersionScheme::Golang, Some("1.0.0"), true, Some("2.0.0"), false);
        assert!(version_matches("v1.5.0", &r));
        assert!(version_matches("1.5.0", &r));
        assert!(!version_matches("v2.0.0", &r));
    }

    #[test]
    fn semver_prerelease_less_than_release() {
        let r = range(VersionScheme::Semver, Some("1.0.0"), true, None, false);
        // 1.0.0-alpha < 1.0.0 per semver spec, so it should NOT match >= 1.0.0
        assert!(!version_matches("1.0.0-alpha", &r));
    }

    #[test]
    fn rpm_basic_range() {
        let r = range(VersionScheme::Rpm, Some("1.0"), true, Some("2.0"), false);
        assert!(version_matches("1.0", &r));
        assert!(version_matches("1.5", &r));
        assert!(!version_matches("2.0", &r));
    }

    #[test]
    fn maven_basic_range() {
        let r = range(VersionScheme::Maven, Some("1.0.0"), true, Some("2.0.0"), false);
        assert!(version_matches("1.0.0", &r));
        assert!(version_matches("1.5.0", &r));
        assert!(!version_matches("2.0.0", &r));
    }

    #[test]
    fn python_basic_range() {
        let r = range(VersionScheme::Python, Some("1.0.0"), true, Some("2.0.0"), false);
        assert!(version_matches("1.0.0", &r));
        assert!(version_matches("1.5.0", &r));
        assert!(!version_matches("2.0.0", &r));
    }

    #[test]
    fn python_prerelease_ordering() {
        let r = range(VersionScheme::Python, Some("1.0.0"), true, None, false);
        // 1.0.0a1 < 1.0.0 in PEP 440
        assert!(!version_matches("1.0.0a1", &r));
        assert!(version_matches("1.0.0", &r));
        assert!(version_matches("1.0.0post1", &r));
    }
}

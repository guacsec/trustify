use crate::graph::advisory::version::{Version, VersionInfo, VersionSpec};
use trustify_entity::version_scheme::{PurlType, VersionScheme};
use vers_like_specifier::{Comparator as VlsComparator, Vls, VlsError};
use vers_rs::{Comparator, VersError, VersVersionRange};

/// Prefix of a `vers:` URI.
const VERS_PREFIX: &str = "vers:";

/// An error parsing a CSAF version range.
#[derive(Debug, thiserror::Error)]
pub enum RangeError {
    #[error("invalid vers: {0}")]
    Vers(#[from] VersError),
    #[error("invalid vls: {0}")]
    Vls(#[from] VlsError),
    #[error("a vls must not denote a single version")]
    SingleVersion,
}

/// The version scheme of a vers type: the one of a PURL type, or `semver`. Other types (`generic`,
/// `all`, or ones without a known scheme, like `deb`) only compare equal versions.
fn vers_scheme(ty: &str) -> VersionScheme {
    match ty {
        "semver" => VersionScheme::Semver,
        _ => ty
            .parse::<PurlType>()
            .map_or(VersionScheme::Generic, VersionScheme::from),
    }
}

/// Parse a `vers:` URI and convert to one or more [`VersionInfo`] values.
pub fn parse_vers(input: &str) -> Result<Vec<VersionInfo>, VersError> {
    let range: VersVersionRange<String> = input.parse()?;
    let scheme = vers_scheme(&range.versioning_scheme);
    let constraints = range
        .constraints
        .iter()
        .map(|c| {
            let op = match c.comparator {
                Comparator::Any => Op::Any,
                Comparator::Equal => Op::Equal,
                Comparator::NotEqual => Op::NotEqual,
                Comparator::LessThan => Op::LessThan,
                Comparator::LessThanOrEqual => Op::LessThanOrEqual,
                Comparator::GreaterThan => Op::GreaterThan,
                Comparator::GreaterThanOrEqual => Op::GreaterThanOrEqual,
            };
            (op, c.version.as_str())
        })
        .collect::<Vec<_>>();
    Ok(convert_constraints(&constraints, scheme))
}

/// Parse a CSAF vers-like specifier (vls), e.g. `<4.2`, which states no versioning scheme.
///
/// The result carries [`VersionScheme::Vls`]: picking a scheme is up to the consumer.
pub fn parse_vls(input: &str) -> Result<Vec<VersionInfo>, RangeError> {
    let vls: Vls = input.parse()?;
    // CSAF 2.1: a single version isn't a valid vls
    if vls.is_single_version() {
        return Err(RangeError::SingleVersion);
    }
    let constraints = vls
        .constraints()
        .iter()
        .map(|c| {
            let op = match c.comparator() {
                VlsComparator::Equal => Op::Equal,
                VlsComparator::NotEqual => Op::NotEqual,
                VlsComparator::LessThan => Op::LessThan,
                VlsComparator::LessThanOrEqual => Op::LessThanOrEqual,
                VlsComparator::GreaterThan => Op::GreaterThan,
                VlsComparator::GreaterThanOrEqual => Op::GreaterThanOrEqual,
            };
            (op, c.version().as_str())
        })
        .collect::<Vec<_>>();
    Ok(convert_constraints(&constraints, VersionScheme::Vls))
}

/// Parse the name of a CSAF `product_version_range` branch: either a `vers:` URI, or a vls.
pub fn parse_range(input: &str) -> Result<Vec<VersionInfo>, RangeError> {
    if input.starts_with(VERS_PREFIX) {
        Ok(parse_vers(input)?)
    } else {
        parse_vls(input)
    }
}

/// The comparator of a constraint, common to vers and vls.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Any,
    Equal,
    NotEqual,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
}

fn convert_constraints(constraints: &[(Op, &str)], scheme: VersionScheme) -> Vec<VersionInfo> {
    if let [(op, version)] = constraints {
        let version = version.to_string();
        let spec = match op {
            Op::Any => VersionSpec::Range(Version::Unbounded, Version::Unbounded),
            Op::Equal => VersionSpec::Exact(version),
            Op::GreaterThan => VersionSpec::Range(Version::Exclusive(version), Version::Unbounded),
            Op::GreaterThanOrEqual => {
                VersionSpec::Range(Version::Inclusive(version), Version::Unbounded)
            }
            Op::LessThan => VersionSpec::Range(Version::Unbounded, Version::Exclusive(version)),
            Op::LessThanOrEqual => {
                VersionSpec::Range(Version::Unbounded, Version::Inclusive(version))
            }
            Op::NotEqual => VersionSpec::Range(Version::Unbounded, Version::Unbounded),
        };
        return vec![VersionInfo { scheme, spec }];
    }

    let lower = constraints
        .iter()
        .find(|(op, _)| matches!(op, Op::GreaterThan | Op::GreaterThanOrEqual));
    let upper = constraints
        .iter()
        .find(|(op, _)| matches!(op, Op::LessThan | Op::LessThanOrEqual));

    if lower.is_some() || upper.is_some() {
        let low = match lower {
            Some((Op::GreaterThanOrEqual, version)) => Version::Inclusive(version.to_string()),
            Some((_, version)) => Version::Exclusive(version.to_string()),
            None => Version::Unbounded,
        };
        let high = match upper {
            Some((Op::LessThanOrEqual, version)) => Version::Inclusive(version.to_string()),
            Some((_, version)) => Version::Exclusive(version.to_string()),
            None => Version::Unbounded,
        };
        return vec![VersionInfo {
            scheme,
            spec: VersionSpec::Range(low, high),
        }];
    }

    let equals = constraints
        .iter()
        .filter(|(op, _)| *op == Op::Equal)
        .map(|(_, version)| VersionInfo {
            scheme,
            spec: VersionSpec::Exact(version.to_string()),
        })
        .collect::<Vec<_>>();

    if !equals.is_empty() {
        return equals;
    }

    vec![VersionInfo {
        scheme,
        spec: VersionSpec::Range(Version::Unbounded, Version::Unbounded),
    }]
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[test]
    fn parse_range() {
        let result = parse_vers("vers:npm/>=1.0.0|<2.0.0").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].scheme, VersionScheme::Npm);
        assert_eq!(
            result[0].spec,
            VersionSpec::Range(
                Version::Inclusive("1.0.0".to_string()),
                Version::Exclusive("2.0.0".to_string()),
            )
        );
    }

    #[test]
    fn parse_wildcard() {
        let result = parse_vers("vers:rpm/*").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].scheme, VersionScheme::Rpm);
        assert_eq!(
            result[0].spec,
            VersionSpec::Range(Version::Unbounded, Version::Unbounded)
        );
    }

    #[test]
    fn parse_exact() {
        let result = parse_vers("vers:generic/1.2.3").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].scheme, VersionScheme::Generic);
        assert_eq!(result[0].spec, VersionSpec::Exact("1.2.3".to_string()));
    }

    #[test]
    fn parse_lower_bound_only() {
        let result = parse_vers("vers:semver/>=1.0.0").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].spec,
            VersionSpec::Range(Version::Inclusive("1.0.0".to_string()), Version::Unbounded,)
        );
    }

    #[test]
    fn parse_upper_bound_only() {
        let result = parse_vers("vers:semver/<2.0.0").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].spec,
            VersionSpec::Range(Version::Unbounded, Version::Exclusive("2.0.0".to_string()),)
        );
    }

    #[test]
    fn parse_inclusive_range() {
        let result = parse_vers("vers:semver/>=1.0.0|<=2.0.0").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].spec,
            VersionSpec::Range(
                Version::Inclusive("1.0.0".to_string()),
                Version::Inclusive("2.0.0".to_string()),
            )
        );
    }

    /// A vers type is a PURL type, naming its versioning scheme.
    #[rstest]
    #[case::pypi("pypi", VersionScheme::Python)]
    #[case::cargo("cargo", VersionScheme::Cargo)]
    #[case::gem("gem", VersionScheme::Gem)]
    #[case::golang("golang", VersionScheme::Golang)]
    #[case::nuget("nuget", VersionScheme::NuGet)]
    #[case::composer("composer", VersionScheme::Packagist)]
    #[case::semver("semver", VersionScheme::Semver)]
    #[case::generic("generic", VersionScheme::Generic)]
    #[case::deb("deb", VersionScheme::Generic)]
    fn parse_scheme(#[case] ty: &str, #[case] scheme: VersionScheme) {
        assert_eq!(
            parse_vers(&format!("vers:{ty}/>=1.0|<2.0")).unwrap(),
            vec![VersionInfo {
                scheme,
                spec: VersionSpec::Range(
                    Version::Inclusive("1.0".to_string()),
                    Version::Exclusive("2.0".to_string()),
                ),
            }]
        );
    }

    #[test]
    fn parse_error_empty() {
        assert!(parse_vers("vers:npm/").is_err());
    }

    #[test]
    fn parse_error_invalid() {
        assert!(parse_vers("not-a-vers").is_err());
    }

    /// vers and vls with the same constraints give the same bounds, only the scheme differs.
    #[rstest]
    #[case::upper("vers:npm/<4.2", "<4.2")]
    #[case::bounded("vers:npm/>=1.0|<=2.0", ">=1.0|<=2.0")]
    #[case::versions("vers:npm/1.0|1.1", "1.0|1.1")]
    fn vers_vls_equivalent(#[case] vers: &str, #[case] vls: &str) {
        let vers = super::parse_range(vers).unwrap();
        let vls = super::parse_range(vls).unwrap();
        assert_eq!(
            vers.into_iter()
                .map(|info| VersionInfo {
                    scheme: VersionScheme::Vls,
                    ..info
                })
                .collect::<Vec<_>>(),
            vls
        );
    }

    #[rstest]
    #[case::vls("<V3.0.29", vec![VersionInfo {
        scheme: VersionScheme::Vls,
        spec: VersionSpec::Range(Version::Unbounded, Version::Exclusive("V3.0.29".into())),
    }])]
    #[case::vers_all("vers:all/*", vec![VersionInfo {
        scheme: VersionScheme::Generic,
        spec: VersionSpec::Range(Version::Unbounded, Version::Unbounded),
    }])]
    fn range(#[case] input: &str, #[case] expected: Vec<VersionInfo>) {
        assert_eq!(super::parse_range(input).unwrap(), expected);
    }

    /// Not a range: free text, the vers "any" in vls, a single version, and a broken vers.
    #[rstest]
    #[case::free_text("prior to 4.2")]
    #[case::any("*")]
    #[case::single("4.2")]
    #[case::broken_vers("vers:npm/")]
    fn not_a_range(#[case] input: &str) {
        assert!(super::parse_range(input).is_err(), "{input} must not parse");
    }
}

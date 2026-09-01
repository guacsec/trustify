use crate::graph::advisory::version::{Version, VersionInfo, VersionSpec};
use trustify_entity::version_scheme::VersionScheme;
use vers_rs::{Comparator, GenericVersionRange, VersError};

/// Parse a `vers:` URI and convert to one or more [`VersionInfo`] values.
pub fn parse_vers(input: &str) -> Result<Vec<VersionInfo>, VersError> {
    let range: GenericVersionRange<String> = input.parse()?;
    let scheme = VersionScheme::from(range.versioning_scheme.as_str());
    Ok(convert_constraints(&range.constraints, scheme))
}

fn convert_constraints(
    constraints: &[vers_rs::VersionConstraint<String>],
    scheme: VersionScheme,
) -> Vec<VersionInfo> {
    if constraints.len() == 1 {
        let c = &constraints[0];
        let spec = match c.comparator {
            Comparator::Any => VersionSpec::Range(Version::Unbounded, Version::Unbounded),
            Comparator::Equal => VersionSpec::Exact(c.version.clone()),
            Comparator::GreaterThan => {
                VersionSpec::Range(Version::Exclusive(c.version.clone()), Version::Unbounded)
            }
            Comparator::GreaterThanOrEqual => {
                VersionSpec::Range(Version::Inclusive(c.version.clone()), Version::Unbounded)
            }
            Comparator::LessThan => {
                VersionSpec::Range(Version::Unbounded, Version::Exclusive(c.version.clone()))
            }
            Comparator::LessThanOrEqual => {
                VersionSpec::Range(Version::Unbounded, Version::Inclusive(c.version.clone()))
            }
            Comparator::NotEqual => VersionSpec::Range(Version::Unbounded, Version::Unbounded),
        };
        return vec![VersionInfo { scheme, spec }];
    }

    let lower = constraints.iter().find(|c| {
        matches!(
            c.comparator,
            Comparator::GreaterThan | Comparator::GreaterThanOrEqual
        )
    });
    let upper = constraints.iter().find(|c| {
        matches!(
            c.comparator,
            Comparator::LessThan | Comparator::LessThanOrEqual
        )
    });

    if lower.is_some() || upper.is_some() {
        let low = match lower {
            Some(c) if c.comparator == Comparator::GreaterThanOrEqual => {
                Version::Inclusive(c.version.clone())
            }
            Some(c) => Version::Exclusive(c.version.clone()),
            None => Version::Unbounded,
        };
        let high = match upper {
            Some(c) if c.comparator == Comparator::LessThanOrEqual => {
                Version::Inclusive(c.version.clone())
            }
            Some(c) => Version::Exclusive(c.version.clone()),
            None => Version::Unbounded,
        };
        return vec![VersionInfo {
            scheme,
            spec: VersionSpec::Range(low, high),
        }];
    }

    let equals: Vec<_> = constraints
        .iter()
        .filter(|c| c.comparator == Comparator::Equal)
        .collect();

    if !equals.is_empty() {
        return equals
            .into_iter()
            .map(|c| VersionInfo {
                scheme,
                spec: VersionSpec::Exact(c.version.clone()),
            })
            .collect();
    }

    vec![VersionInfo {
        scheme,
        spec: VersionSpec::Range(Version::Unbounded, Version::Unbounded),
    }]
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_range() {
        let result = parse_vers("vers:npm/>=1.0.0|<2.0.0").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].scheme, VersionScheme::Semver);
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

    #[test]
    fn parse_error_empty() {
        assert!(parse_vers("vers:npm/").is_err());
    }

    #[test]
    fn parse_error_invalid() {
        assert!(parse_vers("not-a-vers").is_err());
    }
}

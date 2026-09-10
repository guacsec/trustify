use super::{VersionBound, VersionRange, VersionScheme};
use crate::types::VersionConstraint;
use vers_rs::{Comparator, GenericVersionRange};

/// Parse a VERS expression into a version scheme and range.
///
/// Returns `None` for expressions that can't be parsed or represented.
pub fn parse_vers(input: &str) -> Option<VersionConstraint> {
    let range: GenericVersionRange<String> = input.parse().ok()?;
    let scheme = VersionScheme::from(range.versioning_scheme.as_str());
    let constraints = &range.constraints;

    match constraints.len() {
        1 => {
            let c = &constraints[0];
            let range = match c.comparator {
                Comparator::Any => {
                    VersionRange::Range(VersionBound::Unbounded, VersionBound::Unbounded)
                }
                Comparator::Equal => VersionRange::Exact(c.version.clone()),
                Comparator::GreaterThan => VersionRange::Range(
                    VersionBound::Exclusive(c.version.clone()),
                    VersionBound::Unbounded,
                ),
                Comparator::GreaterThanOrEqual => VersionRange::Range(
                    VersionBound::Inclusive(c.version.clone()),
                    VersionBound::Unbounded,
                ),
                Comparator::LessThan => VersionRange::Range(
                    VersionBound::Unbounded,
                    VersionBound::Exclusive(c.version.clone()),
                ),
                Comparator::LessThanOrEqual => VersionRange::Range(
                    VersionBound::Unbounded,
                    VersionBound::Inclusive(c.version.clone()),
                ),
                Comparator::NotEqual => {
                    VersionRange::Range(VersionBound::Unbounded, VersionBound::Unbounded)
                }
            };
            Some(VersionConstraint { scheme, range })
        }
        _ => {
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

            if lower.is_none() && upper.is_none() {
                return None;
            }

            let low = match lower {
                Some(c) if c.comparator == Comparator::GreaterThanOrEqual => {
                    VersionBound::Inclusive(c.version.clone())
                }
                Some(c) => VersionBound::Exclusive(c.version.clone()),
                None => VersionBound::Unbounded,
            };
            let high = match upper {
                Some(c) if c.comparator == Comparator::LessThanOrEqual => {
                    VersionBound::Inclusive(c.version.clone())
                }
                Some(c) => VersionBound::Exclusive(c.version.clone()),
                None => VersionBound::Unbounded,
            };
            Some(VersionConstraint {
                scheme,
                range: VersionRange::Range(low, high),
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn lower_exclusive_upper() {
        let vc = parse_vers("vers:rpm/>=0|<1.1.1k-9.el8_7").unwrap();
        assert_eq!(vc.scheme, VersionScheme::Rpm);
        assert!(matches!(
            vc.range,
            VersionRange::Range(_, VersionBound::Exclusive(ref v)) if v == "1.1.1k-9.el8_7"
        ));
    }

    #[test]
    fn inclusive_range() {
        let vc = parse_vers("vers:semver/>=1.0.0|<=2.0.0").unwrap();
        assert_eq!(vc.scheme, VersionScheme::Semver);
        assert_eq!(
            vc.range,
            VersionRange::Range(
                VersionBound::Inclusive("1.0.0".into()),
                VersionBound::Inclusive("2.0.0".into())
            )
        );
    }

    #[test]
    fn single_upper_bound() {
        let vc = parse_vers("vers:npm/<3.0.0").unwrap();
        assert_eq!(vc.scheme, VersionScheme::Semver);
        assert_eq!(
            vc.range,
            VersionRange::Range(
                VersionBound::Unbounded,
                VersionBound::Exclusive("3.0.0".into())
            )
        );
    }

    #[test]
    fn single_lower_bound() {
        let vc = parse_vers("vers:rpm/>=1.0").unwrap();
        assert_eq!(vc.scheme, VersionScheme::Rpm);
        assert_eq!(
            vc.range,
            VersionRange::Range(
                VersionBound::Inclusive("1.0".into()),
                VersionBound::Unbounded,
            )
        );
    }

    #[test]
    fn epoch_in_version() {
        let vc = parse_vers("vers:rpm/>=0|<1:1.8.0.502.b07-1.1.el8").unwrap();
        assert_eq!(vc.scheme, VersionScheme::Rpm);
        assert!(matches!(
            vc.range,
            VersionRange::Range(_, VersionBound::Exclusive(ref v)) if v == "1:1.8.0.502.b07-1.1.el8"
        ));
    }

    #[test]
    fn wildcard_constraint() {
        let vc = parse_vers("vers:rpm/*").unwrap();
        assert_eq!(
            vc.range,
            VersionRange::Range(VersionBound::Unbounded, VersionBound::Unbounded)
        );
    }

    #[test]
    fn invalid_prefix() {
        assert!(parse_vers("not-vers:rpm/>=0").is_none());
    }
}

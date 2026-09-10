use super::{VersionBound, VersionRange, VersionScheme};
use crate::types::VersionConstraint;

/// Parse a VERS expression into a version scheme and range.
///
/// Handles common two-constraint patterns that map to a single `VersionRange`.
/// Returns `None` for expressions that can't be represented (e.g., disjoint unions).
pub fn parse_vers(vers: &str) -> Option<VersionConstraint> {
    let rest = vers.strip_prefix("vers:")?;
    let (scheme_str, constraints_str) = rest.split_once('/')?;
    let scheme = VersionScheme::from(scheme_str);

    let constraints: Vec<_> = constraints_str.split('|').collect();

    match constraints.len() {
        1 => {
            let (bound, is_low) = parse_constraint(constraints[0])?;
            if is_low {
                Some(VersionConstraint {
                    scheme,
                    range: VersionRange::Range(bound, VersionBound::Unbounded),
                })
            } else {
                Some(VersionConstraint {
                    scheme,
                    range: VersionRange::Range(VersionBound::Unbounded, bound),
                })
            }
        }
        2 => {
            let (bound_a, a_is_low) = parse_constraint(constraints[0])?;
            let (bound_b, b_is_low) = parse_constraint(constraints[1])?;
            if a_is_low && !b_is_low {
                Some(VersionConstraint {
                    scheme,
                    range: VersionRange::Range(bound_a, bound_b),
                })
            } else if !a_is_low && b_is_low {
                Some(VersionConstraint {
                    scheme,
                    range: VersionRange::Range(bound_b, bound_a),
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Parse a single VERS constraint like `>=1.0` or `<2.0`.
/// Returns the bound and whether it's a lower bound (`true`) or upper bound (`false`).
fn parse_constraint(s: &str) -> Option<(VersionBound, bool)> {
    if let Some(v) = s.strip_prefix(">=") {
        if is_zero(v) {
            Some((VersionBound::Unbounded, true))
        } else {
            Some((VersionBound::Inclusive(v.to_string()), true))
        }
    } else if let Some(v) = s.strip_prefix('>') {
        if is_zero(v) {
            Some((VersionBound::Unbounded, true))
        } else {
            Some((VersionBound::Exclusive(v.to_string()), true))
        }
    } else if let Some(v) = s.strip_prefix("<=") {
        Some((VersionBound::Inclusive(v.to_string()), false))
    } else if let Some(v) = s.strip_prefix('<') {
        Some((VersionBound::Exclusive(v.to_string()), false))
    } else if s == "*" {
        Some((VersionBound::Unbounded, true))
    } else {
        None
    }
}

fn is_zero(v: &str) -> bool {
    v == "0" || v == "0.0" || v == "0.0.0"
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn lower_exclusive_upper() {
        let vc = parse_vers("vers:rpm/>=0|<1.1.1k-9.el8_7").unwrap();
        assert_eq!(vc.scheme, VersionScheme::Rpm);
        assert_eq!(
            vc.range,
            VersionRange::Range(
                VersionBound::Unbounded,
                VersionBound::Exclusive("1.1.1k-9.el8_7".into())
            )
        );
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
        assert_eq!(
            vc.range,
            VersionRange::Range(
                VersionBound::Unbounded,
                VersionBound::Exclusive("1:1.8.0.502.b07-1.1.el8".into())
            )
        );
    }

    #[test]
    fn three_constraints_returns_none() {
        assert!(parse_vers("vers:rpm/>=1.0|<2.0|>=3.0").is_none());
    }

    #[test]
    fn invalid_prefix() {
        assert!(parse_vers("not-vers:rpm/>=0").is_none());
    }

    #[test]
    fn wildcard_constraint() {
        let vc = parse_vers("vers:rpm/*|<2.0").unwrap();
        assert_eq!(
            vc.range,
            VersionRange::Range(
                VersionBound::Unbounded,
                VersionBound::Exclusive("2.0".into())
            )
        );
    }
}

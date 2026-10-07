use sea_orm::{IntoIdentity, Set};
use sea_query::{Condition, Expr, ExprTrait};
use serde::{Deserialize, Serialize};
use std::fmt;
use trustify_entity::version_range;
use trustify_entity::version_scheme::VersionScheme;
use uuid::Uuid;

#[derive(Clone, Eq, Hash, Debug, PartialEq, Serialize, Deserialize)]
pub struct VersionInfo {
    pub scheme: VersionScheme,
    pub spec: VersionSpec,
}

#[derive(Clone, Eq, Hash, Debug, PartialEq, Serialize, Deserialize)]
pub enum VersionSpec {
    Exact(String),
    Range(Version, Version),
}

impl fmt::Display for VersionSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Exact(value) => write!(f, "{}", value.clone()),
            Self::Range(low, high) => write!(
                f,
                "{}{}, {}{}",
                if matches!(low, Version::Inclusive(_)) {
                    "["
                } else {
                    "("
                },
                low.as_ref(),
                high.as_ref(),
                if matches!(high, Version::Inclusive(_)) {
                    "]"
                } else {
                    ")"
                }
            ),
        }
    }
}

#[derive(Clone, Eq, Hash, Debug, PartialEq, Serialize, Deserialize)]
pub enum Version {
    Inclusive(String),
    Exclusive(String),
    Unbounded,
}

impl AsRef<str> for Version {
    fn as_ref(&self) -> &str {
        match self {
            Self::Unbounded => "*",
            Self::Inclusive(value) => value,
            Self::Exclusive(value) => value,
        }
    }
}

const NAMESPACE: Uuid = Uuid::from_bytes([
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x41, 0x18, 0xa1, 0x38, 0xb8, 0x9f, 0x19, 0x35, 0xe0, 0xa7,
]);

impl VersionInfo {
    pub fn uuid(&self) -> Uuid {
        let result = Uuid::new_v5(&NAMESPACE, self.scheme.to_string().as_bytes());
        Uuid::new_v5(&result, self.spec.to_string().as_bytes())
    }

    pub fn into_active_model(self) -> version_range::ActiveModel {
        version_range::ActiveModel {
            id: Set(self.uuid()),
            version_scheme_id: Set(self.scheme),
            low_version: Set(match &self.spec {
                VersionSpec::Exact(version) => Some(version.clone()),
                VersionSpec::Range(low, _) => match low {
                    Version::Inclusive(version) | Version::Exclusive(version) => {
                        Some(version.clone())
                    }
                    Version::Unbounded => None,
                },
            }),
            low_inclusive: Set(match &self.spec {
                VersionSpec::Exact(_) => Some(true),
                VersionSpec::Range(low, _) => match low {
                    Version::Inclusive(_) => Some(true),
                    _ => Some(false),
                },
            }),
            high_version: Set(match &self.spec {
                VersionSpec::Exact(version) => Some(version.clone()),
                VersionSpec::Range(_, high) => match high {
                    Version::Inclusive(version) | Version::Exclusive(version) => {
                        Some(version.clone())
                    }
                    Version::Unbounded => None,
                },
            }),
            high_inclusive: Set(match &self.spec {
                VersionSpec::Exact(_) => Some(true),
                VersionSpec::Range(_, high) => match high {
                    Version::Inclusive(_) => Some(true),
                    _ => Some(false),
                },
            }),
        }
    }
}

impl From<VersionInfo> for Condition {
    fn from(info: VersionInfo) -> Condition {
        match info.spec {
            VersionSpec::Exact(version) => Condition::all()
                .add(Expr::col("version_scheme_id".into_identity()).eq(info.scheme))
                .add(Expr::col("low_version".into_identity()).eq(version.clone()))
                .add(Expr::col("low_inclusive".into_identity()).eq(true))
                .add(Expr::col("high_version".into_identity()).eq(version))
                .add(Expr::col("high_inclusive".into_identity()).eq(true)),

            VersionSpec::Range(low, high) => {
                let low_cond = match low {
                    Version::Inclusive(version) => Condition::all()
                        .add(Expr::col("low_version".into_identity()).eq(version))
                        .add(Expr::col("low_inclusive".into_identity()).eq(true)),
                    Version::Exclusive(version) => Condition::all()
                        .add(Expr::col("low_version".into_identity()).eq(version))
                        .add(Expr::col("low_inclusive".into_identity()).eq(false)),
                    Version::Unbounded => {
                        Condition::all().add(Expr::col("low_version".into_identity()).is_null())
                    }
                };

                let high_cond = match high {
                    Version::Inclusive(version) => Condition::all()
                        .add(Expr::col("high_version".into_identity()).eq(version))
                        .add(Expr::col("high_inclusive".into_identity()).eq(true)),
                    Version::Exclusive(version) => Condition::all()
                        .add(Expr::col("high_version".into_identity()).eq(version))
                        .add(Expr::col("high_inclusive".into_identity()).eq(false)),
                    Version::Unbounded => {
                        Condition::all().add(Expr::col("high_version".into_identity()).is_null())
                    }
                };

                Condition::all().add(low_cond).add(high_cond)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::graph::advisory::version::{Version, VersionSpec};

    #[test]
    fn test_exact_version() {
        let vs = VersionSpec::Exact("1.2.3".to_string());
        assert_eq!(vs.to_string(), "1.2.3");
    }

    #[test]
    fn test_range_inclusive() {
        let low = Version::Inclusive("2.0.0".to_string());
        let high = Version::Inclusive("3.0.0".to_string());
        let vs = VersionSpec::Range(low, high);
        assert_eq!(vs.to_string(), "[2.0.0, 3.0.0]");
    }

    #[test]
    fn test_range_exclusive() {
        let low = Version::Exclusive("2.0.0".to_string());
        let high = Version::Exclusive("3.0.0".to_string());
        let vs = VersionSpec::Range(low, high);
        assert_eq!(vs.to_string(), "(2.0.0, 3.0.0)");
    }

    #[test]
    fn test_range_mixed() {
        let low = Version::Inclusive("1.0.0".to_string());
        let high = Version::Exclusive("2.0.0".to_string());
        let vs = VersionSpec::Range(low, high);
        assert_eq!(vs.to_string(), "[1.0.0, 2.0.0)");
    }

    #[test]
    fn test_range_with_unbounded_low() {
        let low = Version::Unbounded;
        let high = Version::Inclusive("1.0.0".to_string());
        let vs = VersionSpec::Range(low, high);
        // low is unbounded so it's represented as "*"
        // Since Version::Unbounded is not an Inclusive variant, it uses a "(" as the opening bracket.
        assert_eq!(vs.to_string(), "(*, 1.0.0]");
    }

    #[test]
    fn test_range_with_unbounded_high() {
        let low = Version::Inclusive("1.0.0".to_string());
        let high = Version::Unbounded;
        let vs = VersionSpec::Range(low, high);
        // high is unbounded so it's represented as "*"
        // Since Version::Unbounded is not an Inclusive variant, it uses a ")" as the closing bracket.
        assert_eq!(vs.to_string(), "[1.0.0, *)");
    }

    #[test]
    fn test_range_both_unbounded() {
        let low = Version::Unbounded;
        let high = Version::Unbounded;
        let vs = VersionSpec::Range(low, high);
        // Both bounds are unbounded, so we expect parentheses on both sides.
        assert_eq!(vs.to_string(), "(*, *)");
    }
}

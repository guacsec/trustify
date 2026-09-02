use serde::{Deserialize, Deserializer, Serialize};
use trustify_entity::version_range;
use utoipa::ToSchema;

use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum VersionRange {
    Full {
        version_scheme_id: String,
        low_version: String,
        low_inclusive: bool,
        high_version: String,
        high_inclusive: bool,
    },
    Left {
        version_scheme_id: String,
        low_version: String,
        low_inclusive: bool,
    },
    Right {
        version_scheme_id: String,
        high_version: String,
        high_inclusive: bool,
    },
    #[serde(deserialize_with = "deserialize_unbounded")]
    Unbounded,
}

fn deserialize_unbounded<'de, D: Deserializer<'de>>(deserializer: D) -> Result<(), D::Error> {
    #[derive(Deserialize)]
    struct Probe {
        low_version: Option<String>,
        high_version: Option<String>,
    }
    let probe = Probe::deserialize(deserializer)?;
    if probe.low_version.is_none() && probe.high_version.is_none() {
        Ok(())
    } else {
        Err(serde::de::Error::custom("not unbounded"))
    }
}

impl VersionRange {
    pub fn from_entity(value: version_range::Model) -> Result<Self, Error> {
        match (
            value.low_version,
            value.low_inclusive,
            value.high_version,
            value.high_inclusive,
        ) {
            (Some(left), Some(left_inclusive), Some(right), Some(right_inclusive)) => {
                Ok(VersionRange::Full {
                    version_scheme_id: value.version_scheme_id.to_string(),
                    low_version: left,
                    low_inclusive: left_inclusive,
                    high_version: right,
                    high_inclusive: right_inclusive,
                })
            }
            (None, _, Some(right), Some(right_inclusive)) => Ok(VersionRange::Right {
                version_scheme_id: value.version_scheme_id.to_string(),
                high_version: right,
                high_inclusive: right_inclusive,
            }),
            (Some(left), Some(left_inclusive), None, _) => Ok(VersionRange::Left {
                version_scheme_id: value.version_scheme_id.to_string(),
                low_version: left,
                low_inclusive: left_inclusive,
            }),
            (None, _, None, _) => Ok(VersionRange::Unbounded),
            _ => Err(Error::Data(format!(
                "invalid version_range model: id={}",
                value.id
            ))),
        }
    }
}

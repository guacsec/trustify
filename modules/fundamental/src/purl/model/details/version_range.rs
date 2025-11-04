use serde::{Deserialize, Serialize};
use trustify_entity::version_range;
use utoipa::ToSchema;

use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum VersionRange {
    Full {
        version_scheme_id: String,
        left: String,
        left_inclusive: bool,
        right: String,
        right_inclusive: bool,
    },
    Left {
        version_scheme_id: String,
        left: String,
        left_inclusive: bool,
    },
    Right {
        version_scheme_id: String,
        right: String,
        right_inclusive: bool,
    },
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
                    left,
                    left_inclusive,
                    right,
                    right_inclusive,
                })
            }
            (None, None, Some(right), Some(right_inclusive)) => Ok(VersionRange::Right {
                version_scheme_id: value.version_scheme_id.to_string(),
                right,
                right_inclusive,
            }),
            (Some(left), Some(left_inclusive), None, None) => Ok(VersionRange::Left {
                version_scheme_id: value.version_scheme_id.to_string(),
                left,
                left_inclusive,
            }),
            _ => Err(Error::Data("invalid version_range model".into())),
        }
    }
}

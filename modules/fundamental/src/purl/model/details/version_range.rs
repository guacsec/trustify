use serde::{Deserialize, Serialize};
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
            (_, _, Some(right), Some(right_inclusive)) => Ok(VersionRange::Right {
                version_scheme_id: value.version_scheme_id.to_string(),
                high_version: right,
                high_inclusive: right_inclusive,
            }),
            (Some(left), Some(left_inclusive), _, _) => Ok(VersionRange::Left {
                version_scheme_id: value.version_scheme_id.to_string(),
                low_version: left,
                low_inclusive: left_inclusive,
            }),
            (None, _, None, _) => Err(Error::Data(format!(
                "invalid version_range model: id={} low_version and high_version are None",
                value.id
            ))),
            _ => Err(Error::Data(format!(
                "invalid version_range model: id={}",
                value.id
            ))),
        }
    }
}

pub mod cyclonedx;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

#[derive(Default, Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct AdvisoryVulnerabilityAssertions {
    pub assertions: HashMap<String, Vec<Assertion>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Assertion {
    Affected {
        start_version: String,
        end_version: String,
    },
    NotAffected {
        version: String,
    },
    Fixed {
        version: String,
    },
}

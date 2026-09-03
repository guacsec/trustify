use serde::{Deserialize, Serialize};
use trustify_entity::remediation::{self, RemediationCategory};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq)]
pub struct RemediationSummary {
    pub category: RemediationCategory,
    pub details: Option<String>,
    pub url: Option<String>,
    /// For internal use only. May be removed at any point and should not be used.
    #[schema(deprecated)]
    pub data: serde_json::Value,
}

impl RemediationSummary {
    pub fn from_entities(remediations: &[remediation::Model]) -> Vec<Self> {
        remediations
            .iter()
            .map(|r| Self {
                category: r.category.clone(),
                details: r.details.clone(),
                url: r.url.clone(),
                data: r.data.clone(),
            })
            .collect()
    }
}

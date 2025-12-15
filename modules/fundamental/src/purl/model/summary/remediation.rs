use serde::{Deserialize, Serialize};
use trustify_entity::remediation::{self, RemediationCategory};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq)]
pub struct RemediationSummary {
    pub id: Uuid,
    pub category: RemediationCategory,
    pub details: Option<String>,
    pub url: Option<String>,
    pub data: serde_json::Value,
}

impl RemediationSummary {
    pub fn from_entities(remediations: &[remediation::Model]) -> Vec<Self> {
        remediations
            .iter()
            .map(|r| Self {
                id: r.id,
                category: r.category.clone(),
                details: r.details.clone(),
                url: r.url.clone(),
                data: r.data.clone(),
            })
            .collect()
    }
}

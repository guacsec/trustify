pub mod advisory_vulnerability;

use crate::advisory::service::AdvisoryCatcher;
use crate::source_document::model::SourceDocument;
use crate::{Error, advisory::model::AdvisoryHead};
use advisory_vulnerability::AdvisoryVulnerabilitySummary;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect};
use serde::{Deserialize, Serialize};
use trustify_common::memo::Memo;
use trustify_cvss::cvss3::severity::Severity;
use trustify_entity::{self as entity};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisoryDetails {
    #[serde(flatten)]
    pub head: AdvisoryHead,

    #[serde(flatten)]
    pub source_document: SourceDocument,

    /// Vulnerabilities addressed within this advisory.
    pub vulnerabilities: Vec<AdvisoryVulnerabilitySummary>,

    /// Average (arithmetic mean) severity of the advisory aggregated from *all* related vulnerability assertions.
    #[schema(required)]
    #[deprecated]
    pub average_severity: Option<Severity>,

    /// Average (arithmetic mean) score of the advisory aggregated from *all* related vulnerability assertions.
    #[schema(required)]
    #[deprecated]
    pub average_score: Option<f64>,
}

impl AdvisoryDetails {
    #[allow(deprecated)]
    pub async fn from_entity<C: ConnectionTrait>(
        advisory: &AdvisoryCatcher,
        tx: &C,
    ) -> Result<Self, Error> {
        let vulnerabilities = entity::vulnerability::Entity::find()
            .right_join(entity::advisory_vulnerability::Entity)
            .column_as(
                entity::advisory_vulnerability::Column::VulnerabilityId,
                entity::vulnerability::Column::Id,
            )
            .filter(entity::advisory_vulnerability::Column::AdvisoryId.eq(advisory.advisory.id))
            .all(tx)
            .await?;

        let vulnerabilities =
            AdvisoryVulnerabilitySummary::from_entities(&advisory.advisory, &vulnerabilities, tx)
                .await?;

        Ok(AdvisoryDetails {
            head: AdvisoryHead::from_advisory(
                &advisory.advisory,
                Memo::Provided(advisory.issuer.clone()),
                tx,
            )
            .await?,
            source_document: SourceDocument::from_entity(&advisory.source_document),
            vulnerabilities,
            average_severity: None,
            average_score: None,
        })
    }
}

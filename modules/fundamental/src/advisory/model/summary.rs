use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect};
use serde::{Deserialize, Serialize};
use tracing::{Instrument, info_span, instrument};
use trustify_common::memo::Memo;
use trustify_entity::{advisory_vulnerability, vulnerability};
use utoipa::ToSchema;

use crate::Error;
use crate::advisory::model::{AdvisoryHead, AdvisoryVulnerabilityHead};
use crate::advisory::service::AdvisoryCatcher;
use crate::source_document::model::SourceDocument;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisorySummary {
    #[serde(flatten)]
    pub head: AdvisoryHead,

    /// Information pertaning to the underlying source document, if any.
    #[serde(flatten)]
    pub source_document: SourceDocument,

    /// Average (arithmetic mean) severity of the advisory aggregated from *all* related vulnerability assertions.
    #[schema(required)]
    #[deprecated]
    pub average_severity: Option<String>,

    /// Average (arithmetic mean) score of the advisory aggregated from *all* related vulnerability assertions.
    #[schema(required)]
    #[deprecated]
    pub average_score: Option<f64>,

    /// Vulnerabilities addressed within this advisory.
    pub vulnerabilities: Vec<AdvisoryVulnerabilityHead>,
}

impl AdvisorySummary {
    #[allow(deprecated)]
    #[instrument(
        skip_all,
        err(level=tracing::Level::INFO),
        fields(entities=entities.len())
    )]
    pub async fn from_entities<C: ConnectionTrait>(
        entities: &[AdvisoryCatcher],
        tx: &C,
    ) -> Result<Vec<Self>, Error> {
        let mut summaries = Vec::with_capacity(entities.len());

        for each in entities {
            let vulnerabilities = vulnerability::Entity::find()
                .right_join(advisory_vulnerability::Entity)
                .column_as(
                    advisory_vulnerability::Column::VulnerabilityId,
                    vulnerability::Column::Id,
                )
                .filter(advisory_vulnerability::Column::AdvisoryId.eq(each.advisory.id))
                .all(tx)
                .instrument(info_span!("find advisory vulnerabilities", advisory=%each.advisory.id))
                .await?;

            let vulnerabilities =
                AdvisoryVulnerabilityHead::from_entities(&each.advisory, &vulnerabilities, tx)
                    .await?;

            summaries.push(AdvisorySummary {
                head: AdvisoryHead::from_advisory(
                    &each.advisory,
                    Memo::Provided(each.issuer.clone()),
                    tx,
                )
                .await?,
                source_document: SourceDocument::from_entity(&each.source_document),
                average_severity: None,
                average_score: None,
                vulnerabilities,
            })
        }

        Ok(summaries)
    }
}

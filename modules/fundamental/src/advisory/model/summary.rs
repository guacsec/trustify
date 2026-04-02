use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect};
use serde::{Deserialize, Serialize};
use tracing::{Instrument, info_span, instrument};
use trustify_common::memo::Memo;
use trustify_entity::{advisory_vulnerability, advisory_vulnerability_score, vulnerability};
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

    /// Vulnerabilities addressed within this advisory.
    pub vulnerabilities: Vec<AdvisoryVulnerabilityHead>,
}

impl AdvisorySummary {
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

        // Batch-load all scores for all advisories in a single query.
        let advisory_ids = entities.iter().map(|e| e.advisory.id).collect::<Vec<_>>();
        let all_scores = advisory_vulnerability_score::Entity::find()
            .filter(advisory_vulnerability_score::Column::AdvisoryId.is_in(advisory_ids))
            .all(tx)
            .instrument(info_span!("load all advisory scores"))
            .await?;

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

            // Distribute pre-loaded scores to each vulnerability in this advisory.
            let scores_by_vuln: Vec<Vec<_>> = vulnerabilities
                .iter()
                .map(|v| {
                    all_scores
                        .iter()
                        .filter(|s| s.advisory_id == each.advisory.id && s.vulnerability_id == v.id)
                        .cloned()
                        .collect()
                })
                .collect();

            let vulnerabilities = AdvisoryVulnerabilityHead::from_entities(
                &each.advisory,
                &vulnerabilities,
                scores_by_vuln,
                tx,
            )
            .await?;

            summaries.push(AdvisorySummary {
                head: AdvisoryHead::from_advisory(
                    &each.advisory,
                    Memo::Provided(each.issuer.clone()),
                    tx,
                )
                .await?,
                source_document: SourceDocument::from_entity(&each.source_document),
                vulnerabilities,
            })
        }

        Ok(summaries)
    }
}

use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, prelude::Uuid};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{Instrument, info_span, instrument};
use trustify_common::memo::Memo;
use trustify_entity::{
    advisory_vulnerability, advisory_vulnerability_score, vulnerability, vulnerability_description,
};
use utoipa::ToSchema;

use crate::Error;
use crate::advisory::model::{AdvisoryHead, AdvisoryVulnerabilityHead};
use crate::advisory::service::AdvisoryCatcher;
use crate::common::model::ScoredVector;
use crate::source_document::model::SourceDocument;
use crate::vulnerability::model::VulnerabilityHead;

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
    /// Batch-constructs advisory summaries, loading all related data upfront
    /// instead of per-advisory.
    #[instrument(
        skip_all,
        err(level=tracing::Level::INFO),
        fields(entities=entities.len())
    )]
    pub async fn from_entities<C: ConnectionTrait>(
        entities: &[AdvisoryCatcher],
        tx: &C,
    ) -> Result<Vec<Self>, Error> {
        if entities.is_empty() {
            return Ok(vec![]);
        }

        let advisory_ids: Vec<_> = entities.iter().map(|e| e.advisory.id).collect();

        // Batch-load all scores for all advisories.
        let all_scores = advisory_vulnerability_score::Entity::find()
            .filter(advisory_vulnerability_score::Column::AdvisoryId.is_in(advisory_ids.clone()))
            .all(tx)
            .instrument(info_span!("load all advisory scores"))
            .await?;

        // Batch-load all advisory_vulnerability join records.
        let all_av = advisory_vulnerability::Entity::find()
            .filter(advisory_vulnerability::Column::AdvisoryId.is_in(advisory_ids))
            .all(tx)
            .instrument(info_span!("load all advisory vulnerabilities"))
            .await?;

        let mut scores_by_key: HashMap<(Uuid, String), Vec<advisory_vulnerability_score::Model>> =
            HashMap::new();
        for score in all_scores {
            scores_by_key
                .entry((score.advisory_id, score.vulnerability_id.clone()))
                .or_default()
                .push(score);
        }

        let mut av_by_advisory: HashMap<Uuid, Vec<advisory_vulnerability::Model>> = HashMap::new();
        let mut vuln_ids: HashSet<String> = HashSet::new();
        for av in all_av {
            vuln_ids.insert(av.vulnerability_id.clone());
            av_by_advisory.entry(av.advisory_id).or_default().push(av);
        }

        // Batch-load all vulnerability records. Entries in
        // advisory_vulnerability may reference vulnerability IDs that have
        // no row in the vulnerability table yet, so we insert stub models
        // for any missing IDs to match the original RIGHT JOIN semantics.
        let mut all_vulns: HashMap<String, vulnerability::Model> = vulnerability::Entity::find()
            .filter(vulnerability::Column::Id.is_in(vuln_ids.iter().cloned().collect::<Vec<_>>()))
            .all(tx)
            .instrument(info_span!("load all vulnerabilities"))
            .await?
            .into_iter()
            .map(|v| (v.id.clone(), v))
            .collect();

        for id in &vuln_ids {
            all_vulns
                .entry(id.clone())
                .or_insert_with(|| vulnerability::Model {
                    id: id.clone(),
                    title: None,
                    reserved: None,
                    published: None,
                    modified: None,
                    withdrawn: None,
                    cwes: None,
                    base_score: None,
                    base_severity: None,
                    base_type: None,
                    authoritative_advisory_id: None,
                    id_sort_key: None,
                });
        }

        // Batch-load descriptions for vulnerabilities that have their own title
        // (those use from_vulnerability_entity which fetches the description).
        let vulns_needing_description: Vec<String> = all_vulns
            .values()
            .filter(|v| v.title.is_some())
            .map(|v| v.id.clone())
            .collect();

        let all_descriptions: HashMap<String, String> = if vulns_needing_description.is_empty() {
            HashMap::new()
        } else {
            vulnerability_description::Entity::find()
                .filter(
                    vulnerability_description::Column::VulnerabilityId
                        .is_in(vulns_needing_description),
                )
                .filter(vulnerability_description::Column::Lang.eq("en"))
                .all(tx)
                .instrument(info_span!("load all vulnerability descriptions"))
                .await?
                .into_iter()
                .map(|d| (d.vulnerability_id, d.description))
                .collect()
        };

        // Build summaries from pre-fetched data (no more per-advisory queries).
        let mut summaries = Vec::with_capacity(entities.len());

        for each in entities {
            let advisory_vulns = av_by_advisory
                .get(&each.advisory.id)
                .map(|v| v.as_slice())
                .unwrap_or_default();

            let vulnerabilities: Vec<AdvisoryVulnerabilityHead> = advisory_vulns
                .iter()
                .filter_map(|av| {
                    let vuln = all_vulns.get(&av.vulnerability_id)?;

                    let scores: Vec<ScoredVector> = scores_by_key
                        .get(&(each.advisory.id, vuln.id.clone()))
                        .map(|s| s.iter().cloned().map(ScoredVector::from).collect())
                        .unwrap_or_default();

                    let head = if vuln.title.is_some() {
                        let description = all_descriptions.get(&vuln.id).cloned();
                        VulnerabilityHead::from_vulnerability_entity_and_description(
                            vuln,
                            description,
                        )
                    } else {
                        VulnerabilityHead::from_advisory_vulnerability_entity(av, vuln)
                    };

                    Some(AdvisoryVulnerabilityHead { head, scores })
                })
                .collect();

            summaries.push(AdvisorySummary {
                head: AdvisoryHead::from_advisory(
                    &each.advisory,
                    Memo::Provided(each.issuer.clone()),
                    tx,
                )
                .await?,
                source_document: SourceDocument::from_entity(&each.source_document),
                vulnerabilities,
            });
        }

        Ok(summaries)
    }
}

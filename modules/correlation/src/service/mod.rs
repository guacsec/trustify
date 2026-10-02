use crate::{
    error::Error,
    extractor::Extractors,
    model::{
        ComponentRef, CorrelationResult, EvidenceDetail, IdentifierRef, QueryMatch, QueryResult,
        QueryVerdict, VerdictStatus, VerdictSummary, VulnerabilityRef,
    },
};
use sea_orm::{ColumnTrait, DatabaseTransaction, EntityTrait, QueryFilter};
use std::collections::{BTreeMap, HashMap, HashSet};
use tracing::{Instrument, info_span, instrument};
use trustify_entity::{
    advisory, correlation_evidence, correlation_evidence::AssertionStatus, sbom, sbom_node,
    vulnerability,
};
use uuid::Uuid;

#[cfg(test)]
mod test;

/// Reads evidence from the database and computes verdicts.
#[derive(Default)]
pub struct CorrelationService {
    extractors: Extractors,
}

impl CorrelationService {
    /// Create a new service using the given extractors.
    pub fn new(extractors: Extractors) -> Self {
        Self { extractors }
    }

    /// Read evidence for an SBOM and compute verdicts.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn correlate_sbom(
        &self,
        sbom_id: Uuid,
        include_unmatched: bool,
        connection: &DatabaseTransaction,
    ) -> Result<CorrelationResult, Error> {
        let evidence_rows = correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
            .all(connection)
            .await?;

        let node_identifiers = self
            .extractors
            .component_identifiers(sbom_id, connection)
            .await?;

        if evidence_rows.is_empty() {
            let unmatched_components = if include_unmatched {
                Some(
                    load_unmatched_components(
                        sbom_id,
                        &HashSet::new(),
                        &node_identifiers,
                        connection,
                    )
                    .await?,
                )
            } else {
                None
            };

            return Ok(CorrelationResult {
                sbom_id,
                verdicts: Vec::new(),
                unmatched_components,
            });
        }

        let node_ids: Vec<&str> = evidence_rows
            .iter()
            .map(|e| e.node_id.as_str())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let advisory_ids: Vec<Uuid> = evidence_rows
            .iter()
            .map(|e| e.advisory_id)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let vuln_ids: Vec<&str> = evidence_rows
            .iter()
            .map(|e| e.vulnerability_id.as_str())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let nodes = sbom_node::Entity::find()
            .filter(sbom_node::Column::SbomId.eq(sbom_id))
            .filter(sbom_node::Column::NodeId.is_in(node_ids))
            .all(connection)
            .await?;

        let node_names: HashMap<&str, &str> = nodes
            .iter()
            .map(|n| (n.node_id.as_str(), n.name.as_str()))
            .collect();

        let advisory_map = load_advisory_names(&advisory_ids, connection).await?;
        let vuln_titles = load_vulnerability_titles(&vuln_ids, connection).await?;

        // Group evidence by (node_id, vulnerability_id).
        let mut groups: BTreeMap<(&str, &str), Vec<&correlation_evidence::Model>> = BTreeMap::new();
        for row in &evidence_rows {
            groups
                .entry((row.node_id.as_str(), row.vulnerability_id.as_str()))
                .or_default()
                .push(row);
        }

        let matched_node_ids: HashSet<&str> = groups.keys().map(|(node_id, _)| *node_id).collect();

        let mut verdicts = Vec::with_capacity(groups.len());
        for ((node_id, vuln_id), rows) in &groups {
            let evidence: Vec<_> = rows
                .iter()
                .map(|row| {
                    let advisory_identifier = advisory_map
                        .get(&row.advisory_id)
                        .map(String::as_str)
                        .unwrap_or("unknown")
                        .to_string();

                    EvidenceDetail {
                        id: row.id,
                        assertion_status: row.status.into(),
                        confidence: row.confidence,
                        extractor: row.extractor.clone(),
                        advisory_id: row.advisory_id,
                        advisory_identifier,
                        matched_value: row.matched_value.clone(),
                        created_at: row.created_at,
                    }
                })
                .collect();

            let status = resolve_verdict_status(rows.iter().map(|r| r.status));

            let first = rows[0];
            let advisory_identifier = advisory_map
                .get(&first.advisory_id)
                .map(String::as_str)
                .unwrap_or("unknown")
                .to_string();

            let vuln_title = vuln_titles.get(*vuln_id).cloned().flatten();

            verdicts.push(VerdictSummary {
                component: build_component_ref(
                    node_id.to_string(),
                    node_names.get(node_id).unwrap_or(node_id).to_string(),
                    &node_identifiers,
                ),
                vulnerability: VulnerabilityRef {
                    id: vuln_id.to_string(),
                    title: vuln_title,
                    advisory_id: first.advisory_id,
                    advisory_identifier,
                },
                status,
                evidence,
            });
        }

        let unmatched_components = if include_unmatched {
            Some(
                load_unmatched_components(
                    sbom_id,
                    &matched_node_ids,
                    &node_identifiers,
                    connection,
                )
                .await?,
            )
        } else {
            None
        };

        Ok(CorrelationResult {
            sbom_id,
            verdicts,
            unmatched_components,
        })
    }

    /// Query for advisory/vulnerability matches by identifier.
    ///
    /// Matches the identifier as its given kind only, groups results by
    /// vulnerability, and resolves a verdict status for each group using the
    /// same logic as SBOM correlation.
    #[instrument(skip(self, connection), err(level = tracing::Level::INFO))]
    pub async fn query_identifier(
        &self,
        identifier: IdentifierRef,
        connection: &DatabaseTransaction,
    ) -> Result<QueryResult, Error> {
        let matches = self.extractors.query(&identifier, connection).await?;

        let advisory_ids = matches
            .iter()
            .map(|a| a.advisory_id)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        let vuln_ids = matches
            .iter()
            .map(|a| a.vulnerability_id.as_str())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        let advisory_map = load_advisory_names(&advisory_ids, connection).await?;
        let vuln_titles = load_vulnerability_titles(&vuln_ids, connection).await?;

        // Group matches by vulnerability_id, keeping entity statuses for resolution.
        let mut groups = BTreeMap::<&str, Vec<(AssertionStatus, QueryMatch)>>::new();
        for assertion in &matches {
            let advisory_identifier = advisory_map
                .get(&assertion.advisory_id)
                .map(String::as_str)
                .unwrap_or("unknown")
                .to_string();

            groups
                .entry(assertion.vulnerability_id.as_str())
                .or_default()
                .push((
                    assertion.status,
                    QueryMatch {
                        kind: identifier.kind,
                        value: assertion.matched_value.clone(),
                        advisory_id: assertion.advisory_id,
                        advisory_identifier,
                        status: assertion.status.into(),
                    },
                ));
        }

        let verdicts = groups
            .into_iter()
            .map(|(vuln_id, items)| {
                let status = resolve_verdict_status(items.iter().map(|(s, _)| *s));
                let matches = items.into_iter().map(|(_, m)| m).collect();
                let vulnerability_title = vuln_titles.get(vuln_id).cloned().flatten();

                QueryVerdict {
                    vulnerability_id: vuln_id.to_string(),
                    vulnerability_title,
                    status,
                    matches,
                }
            })
            .collect();

        Ok(QueryResult {
            query: identifier,
            verdicts,
        })
    }
}

/// Resolve a verdict status from a set of assertion statuses.
///
/// Priority: Fixed > NotAffected > Affected > UnderInvestigation > None.
fn resolve_verdict_status(statuses: impl IntoIterator<Item = AssertionStatus>) -> VerdictStatus {
    let mut has_affected = false;
    let mut has_fixed = false;
    let mut has_not_affected = false;
    let mut has_under_investigation = false;

    for status in statuses {
        match status {
            AssertionStatus::Affected => has_affected = true,
            AssertionStatus::Fixed => has_fixed = true,
            AssertionStatus::NotAffected => has_not_affected = true,
            AssertionStatus::UnderInvestigation => has_under_investigation = true,
            AssertionStatus::Recommended => {}
        }
    }

    if has_fixed {
        VerdictStatus::Fixed
    } else if has_not_affected {
        VerdictStatus::NotAffected
    } else if has_affected {
        VerdictStatus::Affected
    } else if has_under_investigation {
        VerdictStatus::UnderInvestigation
    } else {
        VerdictStatus::None
    }
}

/// Load advisory identifiers by ID.
async fn load_advisory_names(
    advisory_ids: &[Uuid],
    connection: &DatabaseTransaction,
) -> Result<HashMap<Uuid, String>, Error> {
    let advisories = advisory::Entity::find()
        .filter(advisory::Column::Id.is_in(advisory_ids.iter().copied()))
        .all(connection)
        .instrument(info_span!("loading advisories"))
        .await?;

    Ok(advisories
        .into_iter()
        .map(|a| (a.id, a.identifier))
        .collect())
}

/// Load vulnerability titles by ID.
async fn load_vulnerability_titles(
    vuln_ids: &[&str],
    connection: &DatabaseTransaction,
) -> Result<HashMap<String, Option<String>>, Error> {
    let vulns = vulnerability::Entity::find()
        .filter(vulnerability::Column::Id.is_in(vuln_ids.iter().copied()))
        .all(connection)
        .instrument(info_span!("loading vulnerabilities"))
        .await?;

    Ok(vulns.into_iter().map(|v| (v.id, v.title)).collect())
}

/// Build a [`ComponentRef`] for a given node.
fn build_component_ref(
    node_id: String,
    name: String,
    node_identifiers: &HashMap<String, Vec<IdentifierRef>>,
) -> ComponentRef {
    ComponentRef {
        identifiers: node_identifiers.get(&node_id).cloned().unwrap_or_default(),
        node_id,
        name,
    }
}

/// Load all components for an SBOM, excluding those in the matched set.
async fn load_unmatched_components(
    sbom_id: Uuid,
    exclude_node_ids: &HashSet<&str>,
    node_identifiers: &HashMap<String, Vec<IdentifierRef>>,
    connection: &DatabaseTransaction,
) -> Result<Vec<ComponentRef>, Error> {
    let root_node_id = sbom::Entity::find_by_id(sbom_id)
        .one(connection)
        .instrument(info_span!("loading sbom root"))
        .await?
        .map(|s| s.node_id);

    let nodes = sbom_node::Entity::find()
        .filter(sbom_node::Column::SbomId.eq(sbom_id))
        .all(connection)
        .instrument(info_span!("loading sbom nodes"))
        .await?;

    let mut components = nodes
        .into_iter()
        .filter(|n| {
            !exclude_node_ids.contains(n.node_id.as_str())
                && root_node_id.as_deref() != Some(n.node_id.as_str())
        })
        .map(|n| build_component_ref(n.node_id, n.name, node_identifiers))
        .collect::<Vec<_>>();
    components.sort_by(|a, b| a.node_id.cmp(&b.node_id));

    Ok(components)
}

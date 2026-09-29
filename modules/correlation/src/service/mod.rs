use crate::{
    error::Error,
    evidence::{load_advisory_hashes_by_values, load_product_identifiers_by_values},
    model::{
        ComponentRef, CorrelationResult, DigestRef, EvidenceDetail, QueryMatch, QueryMatchType,
        QueryResult, QueryVerdict, VerdictStatus, VerdictSummary, VulnerabilityRef,
    },
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use std::collections::{BTreeMap, HashMap};
use tracing::{Instrument, info_span, instrument};
use trustify_entity::{
    advisory, correlation_evidence, correlation_evidence::AssertionStatus, sbom_node,
    sbom_node_checksum, vulnerability,
};
use uuid::Uuid;

#[cfg(test)]
mod test;

/// Reads evidence from the database and computes verdicts.
pub struct CorrelationService;

impl CorrelationService {
    /// Read evidence for an SBOM and compute verdicts.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn correlate_sbom<C: ConnectionTrait + Send>(
        &self,
        sbom_id: Uuid,
        connection: &C,
    ) -> Result<CorrelationResult, Error> {
        let evidence_rows = correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
            .all(connection)
            .await?;

        if evidence_rows.is_empty() {
            return Ok(CorrelationResult {
                sbom_id,
                verdicts: Vec::new(),
            });
        }

        let node_ids: Vec<&str> = evidence_rows
            .iter()
            .map(|e| e.node_id.as_str())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let advisory_ids: Vec<Uuid> = evidence_rows
            .iter()
            .map(|e| e.advisory_id)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let vuln_ids: Vec<&str> = evidence_rows
            .iter()
            .map(|e| e.vulnerability_id.as_str())
            .collect::<std::collections::HashSet<_>>()
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

        let checksums = sbom_node_checksum::Entity::find()
            .filter(sbom_node_checksum::Column::SbomId.eq(sbom_id))
            .all(connection)
            .await?;

        let mut node_checksums: HashMap<&str, Vec<DigestRef>> = HashMap::new();
        for cs in &checksums {
            node_checksums
                .entry(cs.node_id.as_str())
                .or_default()
                .push(DigestRef {
                    algorithm: cs.r#type.clone(),
                    value: cs.value.clone(),
                });
        }

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
                        match_dimension: row.match_dimension.into(),
                        assertion_status: row.status.into(),
                        confidence: row.confidence,
                        extractor: row.extractor.clone(),
                        advisory_id: row.advisory_id,
                        advisory_identifier,
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
                component: ComponentRef {
                    node_id: node_id.to_string(),
                    name: node_names.get(node_id).unwrap_or(node_id).to_string(),
                    purls: Vec::new(),
                    cpes: Vec::new(),
                    digests: node_checksums.get(node_id).cloned().unwrap_or_default(),
                },
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

        Ok(CorrelationResult { sbom_id, verdicts })
    }

    /// Query for advisory/vulnerability matches by identifier value.
    ///
    /// Searches across digest hashes and product identifiers (model numbers,
    /// serial numbers, SKUs), groups results by vulnerability, and resolves
    /// a verdict status for each group using the same logic as SBOM correlation.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn query_identifier<C: ConnectionTrait + Send>(
        &self,
        query: &str,
        connection: &C,
    ) -> Result<QueryResult, Error> {
        let query_slice: &[&str] = &[query];

        let hash_rows = load_advisory_hashes_by_values(query_slice, connection).await?;
        let pid_rows = load_product_identifiers_by_values(query_slice, connection).await?;

        if hash_rows.is_empty() && pid_rows.is_empty() {
            return Ok(QueryResult {
                query: query.to_string(),
                verdicts: Vec::new(),
            });
        }

        let advisory_ids: Vec<Uuid> = hash_rows
            .iter()
            .map(|r| r.advisory_id)
            .chain(pid_rows.iter().map(|r| r.advisory_id))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let vuln_ids: Vec<&str> = hash_rows
            .iter()
            .map(|r| r.vulnerability_id.as_str())
            .chain(pid_rows.iter().map(|r| r.vulnerability_id.as_str()))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let advisory_map = load_advisory_names(&advisory_ids, connection).await?;
        let vuln_titles = load_vulnerability_titles(&vuln_ids, connection).await?;

        // Group matches by vulnerability_id, keeping entity statuses for resolution.
        let mut groups: BTreeMap<&str, Vec<(AssertionStatus, QueryMatch)>> = BTreeMap::new();

        for row in &hash_rows {
            let advisory_identifier = advisory_map
                .get(&row.advisory_id)
                .map(String::as_str)
                .unwrap_or("unknown")
                .to_string();

            groups
                .entry(row.vulnerability_id.as_str())
                .or_default()
                .push((
                    row.status,
                    QueryMatch {
                        match_type: QueryMatchType::Digest,
                        value: format!("{}:{}", row.algorithm, row.value),
                        advisory_id: row.advisory_id,
                        advisory_identifier,
                        status: row.status.into(),
                    },
                ));
        }

        for row in &pid_rows {
            let advisory_identifier = advisory_map
                .get(&row.advisory_id)
                .map(String::as_str)
                .unwrap_or("unknown")
                .to_string();

            groups
                .entry(row.vulnerability_id.as_str())
                .or_default()
                .push((
                    row.status,
                    QueryMatch {
                        match_type: row.identifier_type.into(),
                        value: row.value.clone(),
                        advisory_id: row.advisory_id,
                        advisory_identifier,
                        status: row.status.into(),
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
            query: query.to_string(),
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
async fn load_advisory_names<C: ConnectionTrait>(
    advisory_ids: &[Uuid],
    connection: &C,
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
async fn load_vulnerability_titles<C: ConnectionTrait>(
    vuln_ids: &[&str],
    connection: &C,
) -> Result<HashMap<String, Option<String>>, Error> {
    let vulns = vulnerability::Entity::find()
        .filter(vulnerability::Column::Id.is_in(vuln_ids.iter().copied()))
        .all(connection)
        .instrument(info_span!("loading vulnerabilities"))
        .await?;

    Ok(vulns.into_iter().map(|v| (v.id, v.title)).collect())
}

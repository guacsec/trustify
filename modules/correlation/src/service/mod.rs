use crate::{
    error::Error,
    model::{
        ComponentRef, CorrelationResult, DigestRef, EvidenceDetail, QueryMatch, QueryMatchType,
        QueryResult, VerdictStatus, VerdictSummary, VulnerabilityRef,
    },
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use std::collections::{BTreeMap, HashMap};
use tracing::{Instrument, info_span, instrument};
use trustify_entity::{
    advisory, advisory_vulnerability_hash, advisory_vulnerability_product_identifier,
    correlation_evidence, sbom_node, sbom_node_checksum, vulnerability,
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

        let advisories = advisory::Entity::find()
            .filter(advisory::Column::Id.is_in(advisory_ids))
            .all(connection)
            .await?;

        let advisory_map: HashMap<Uuid, &str> = advisories
            .iter()
            .map(|a| (a.id, a.identifier.as_str()))
            .collect();

        let vulns = vulnerability::Entity::find()
            .filter(vulnerability::Column::Id.is_in(vuln_ids))
            .all(connection)
            .await?;

        let vuln_titles: HashMap<&str, Option<&str>> = vulns
            .iter()
            .map(|v| (v.id.as_str(), v.title.as_deref()))
            .collect();

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
                        .unwrap_or(&"unknown")
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

            let status = resolve_verdict_status(rows);

            let first = rows[0];
            let advisory_identifier = advisory_map
                .get(&first.advisory_id)
                .unwrap_or(&"unknown")
                .to_string();

            let vuln_title = vuln_titles
                .get(vuln_id)
                .copied()
                .flatten()
                .map(String::from);

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
    /// serial numbers, SKUs) for any advisory that references the given value.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn query_identifier<C: ConnectionTrait + Send>(
        &self,
        query: &str,
        connection: &C,
    ) -> Result<QueryResult, Error> {
        let mut matches = Vec::new();

        let hash_rows = advisory_vulnerability_hash::Entity::find()
            .filter(advisory_vulnerability_hash::Column::Value.eq(query))
            .all(connection)
            .instrument(info_span!("querying digest hashes"))
            .await?;

        let pid_rows = advisory_vulnerability_product_identifier::Entity::find()
            .filter(advisory_vulnerability_product_identifier::Column::Value.eq(query))
            .all(connection)
            .instrument(info_span!("querying product identifiers"))
            .await?;

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

        let advisories = advisory::Entity::find()
            .filter(advisory::Column::Id.is_in(advisory_ids))
            .all(connection)
            .instrument(info_span!("loading advisories"))
            .await?;

        let advisory_map: HashMap<Uuid, &str> = advisories
            .iter()
            .map(|a| (a.id, a.identifier.as_str()))
            .collect();

        let vulns = vulnerability::Entity::find()
            .filter(vulnerability::Column::Id.is_in(vuln_ids))
            .all(connection)
            .instrument(info_span!("loading vulnerabilities"))
            .await?;

        let vuln_titles: HashMap<&str, Option<&str>> = vulns
            .iter()
            .map(|v| (v.id.as_str(), v.title.as_deref()))
            .collect();

        for row in &hash_rows {
            matches.push(QueryMatch {
                match_type: QueryMatchType::Digest,
                value: format!("{}:{}", row.algorithm, row.value),
                vulnerability_id: row.vulnerability_id.clone(),
                vulnerability_title: vuln_titles
                    .get(row.vulnerability_id.as_str())
                    .copied()
                    .flatten()
                    .map(String::from),
                advisory_id: row.advisory_id,
                advisory_identifier: advisory_map
                    .get(&row.advisory_id)
                    .unwrap_or(&"unknown")
                    .to_string(),
                status: row.status.into(),
            });
        }

        for row in &pid_rows {
            matches.push(QueryMatch {
                match_type: row.identifier_type.into(),
                value: row.value.clone(),
                vulnerability_id: row.vulnerability_id.clone(),
                vulnerability_title: vuln_titles
                    .get(row.vulnerability_id.as_str())
                    .copied()
                    .flatten()
                    .map(String::from),
                advisory_id: row.advisory_id,
                advisory_identifier: advisory_map
                    .get(&row.advisory_id)
                    .unwrap_or(&"unknown")
                    .to_string(),
                status: row.status.into(),
            });
        }

        Ok(QueryResult {
            query: query.to_string(),
            matches,
        })
    }
}

fn resolve_verdict_status(evidence: &[&correlation_evidence::Model]) -> VerdictStatus {
    use trustify_entity::correlation_evidence::AssertionStatus;

    let mut has_affected = false;
    let mut has_fixed = false;
    let mut has_not_affected = false;
    let mut has_under_investigation = false;

    for row in evidence {
        match row.status {
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

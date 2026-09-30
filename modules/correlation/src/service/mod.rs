use crate::{
    error::Error,
    evidence::{
        load_advisory_hashes_by_values, load_product_identifiers_by_values,
        load_wildcard_product_identifiers,
    },
    model::{
        ComponentRef, CorrelationResult, DigestRef, EvidenceDetail, ProductIdentifierRef,
        QueryMatch, QueryMatchType, QueryResult, QueryVerdict, VerdictStatus, VerdictSummary,
        VulnerabilityRef,
    },
    wildcard::csaf_glob_matches,
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, LoaderTrait, QueryFilter};
use std::collections::{BTreeMap, HashMap, HashSet};
use tracing::{Instrument, info_span, instrument};
use trustify_common::purl::Purl;
use trustify_entity::{
    advisory, correlation_evidence, correlation_evidence::AssertionStatus, cpe, qualified_purl,
    sbom, sbom_node, sbom_node_checksum, sbom_node_cpe_ref, sbom_node_product_identifier,
    sbom_node_purl_ref, vulnerability,
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
        include_unmatched: bool,
        connection: &C,
    ) -> Result<CorrelationResult, Error> {
        let evidence_rows = correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
            .all(connection)
            .await?;

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

        let node_purls = load_node_purls(sbom_id, connection).await?;
        let node_cpes = load_node_cpes(sbom_id, connection).await?;
        let node_pids = load_node_product_identifiers(sbom_id, connection).await?;

        if evidence_rows.is_empty() {
            let unmatched_components = if include_unmatched {
                Some(
                    load_unmatched_components(
                        sbom_id,
                        &HashSet::new(),
                        &node_checksums,
                        &node_purls,
                        &node_cpes,
                        &node_pids,
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
                    &node_checksums,
                    &node_purls,
                    &node_cpes,
                    &node_pids,
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
                    &node_checksums,
                    &node_purls,
                    &node_cpes,
                    &node_pids,
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
        let mut pid_rows = load_product_identifiers_by_values(query_slice, connection).await?;

        let wildcard_pids = load_wildcard_product_identifiers(connection).await?;
        pid_rows.extend(
            wildcard_pids
                .into_iter()
                .filter(|ap| csaf_glob_matches(&ap.value, query)),
        );

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

/// Load PURL strings for each node in the SBOM.
async fn load_node_purls<C: ConnectionTrait>(
    sbom_id: Uuid,
    connection: &C,
) -> Result<HashMap<String, Vec<String>>, Error> {
    let purl_refs = sbom_node_purl_ref::Entity::find()
        .filter(sbom_node_purl_ref::Column::SbomId.eq(sbom_id))
        .all(connection)
        .instrument(info_span!("loading purl refs"))
        .await?;

    let qualified_purls = purl_refs
        .load_one(qualified_purl::Entity, connection)
        .instrument(info_span!("loading qualified purls"))
        .await?;

    let mut result: HashMap<String, Vec<String>> = HashMap::new();
    for (purl_ref, qp) in purl_refs.into_iter().zip(qualified_purls) {
        if let Some(qp) = qp {
            result
                .entry(purl_ref.node_id)
                .or_default()
                .push(Purl::from(qp.purl).to_string());
        }
    }

    Ok(result)
}

/// Load CPE strings for each node in the SBOM.
async fn load_node_cpes<C: ConnectionTrait>(
    sbom_id: Uuid,
    connection: &C,
) -> Result<HashMap<String, Vec<String>>, Error> {
    let cpe_refs = sbom_node_cpe_ref::Entity::find()
        .filter(sbom_node_cpe_ref::Column::SbomId.eq(sbom_id))
        .all(connection)
        .instrument(info_span!("loading cpe refs"))
        .await?;

    let cpes = cpe_refs
        .load_one(cpe::Entity, connection)
        .instrument(info_span!("loading cpes"))
        .await?;

    let mut result: HashMap<String, Vec<String>> = HashMap::new();
    for (cpe_ref, cpe_model) in cpe_refs.into_iter().zip(cpes) {
        if let Some(cpe_model) = cpe_model {
            result
                .entry(cpe_ref.node_id)
                .or_default()
                .push(cpe_model.to_string());
        }
    }

    Ok(result)
}

/// Build a [`ComponentRef`] for a given node.
fn build_component_ref(
    node_id: String,
    name: String,
    node_checksums: &HashMap<&str, Vec<DigestRef>>,
    node_purls: &HashMap<String, Vec<String>>,
    node_cpes: &HashMap<String, Vec<String>>,
    node_pids: &HashMap<String, Vec<ProductIdentifierRef>>,
) -> ComponentRef {
    ComponentRef {
        digests: node_checksums
            .get(node_id.as_str())
            .cloned()
            .unwrap_or_default(),
        purls: node_purls.get(&node_id).cloned().unwrap_or_default(),
        cpes: node_cpes.get(&node_id).cloned().unwrap_or_default(),
        product_identifiers: node_pids.get(&node_id).cloned().unwrap_or_default(),
        node_id,
        name,
    }
}

/// Load product identifiers for each node in the SBOM.
async fn load_node_product_identifiers<C: ConnectionTrait>(
    sbom_id: Uuid,
    connection: &C,
) -> Result<HashMap<String, Vec<ProductIdentifierRef>>, Error> {
    let rows = sbom_node_product_identifier::Entity::find()
        .filter(sbom_node_product_identifier::Column::SbomId.eq(sbom_id))
        .all(connection)
        .instrument(info_span!("loading product identifiers"))
        .await?;

    let mut result: HashMap<String, Vec<ProductIdentifierRef>> = HashMap::new();
    for row in rows {
        result
            .entry(row.node_id)
            .or_default()
            .push(ProductIdentifierRef {
                identifier_type: row.identifier_type.into(),
                value: row.value,
            });
    }

    Ok(result)
}

/// Load all components for an SBOM, excluding those in the matched set.
async fn load_unmatched_components<C: ConnectionTrait>(
    sbom_id: Uuid,
    exclude_node_ids: &HashSet<&str>,
    node_checksums: &HashMap<&str, Vec<DigestRef>>,
    node_purls: &HashMap<String, Vec<String>>,
    node_cpes: &HashMap<String, Vec<String>>,
    node_pids: &HashMap<String, Vec<ProductIdentifierRef>>,
    connection: &C,
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

    let components = nodes
        .into_iter()
        .filter(|n| {
            !exclude_node_ids.contains(n.node_id.as_str())
                && root_node_id.as_deref() != Some(n.node_id.as_str())
        })
        .map(|n| {
            build_component_ref(
                n.node_id,
                n.name,
                node_checksums,
                node_purls,
                node_cpes,
                node_pids,
            )
        })
        .collect();

    Ok(components)
}

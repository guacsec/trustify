use crate::{
    error::Error,
    extractor::Extractors,
    model::{
        ComponentRef, CorrelationResult, EvidenceContext, EvidenceDetail, IdentifierRef,
        MatchedValue, QueryMatch, QueryResult, QueryVerdict, ResolutionRequest, SbomVerdictCounts,
        VerdictStatus, VerdictSummary, VulnerabilityRef,
    },
};
use sea_orm::{ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryFilter};
use std::collections::{BTreeMap, HashMap, HashSet};
use tracing::{Instrument, info_span, instrument};
use trustify_entity::{
    advisory, assertion_context, correlation_evidence, correlation_evidence::AssertionStatus,
    correlation_evidence_context, sbom, sbom_node, vulnerability,
};
use uuid::Uuid;

pub mod option;
pub mod statement;
pub mod weighting;

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

    /// Count verdicts using the same weighted resolver, with compact batched provider inputs.
    ///
    /// Returns one entry per requested SBOM, in the requested order, with zero counts for SBOMs
    /// without evidence (or unknown SBOMs).
    #[instrument(skip_all, fields(sboms = sbom_ids.len()), err(level = tracing::Level::INFO))]
    pub async fn count_verdicts(
        &self,
        sbom_ids: &[Uuid],
        connection: &DatabaseTransaction,
    ) -> Result<Vec<SbomVerdictCounts>, Error> {
        if sbom_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut evidence = Vec::new();
        for chunk in sbom_ids.chunks(1000) {
            evidence.extend(
                correlation_evidence::Entity::find()
                    .filter(correlation_evidence::Column::SbomId.is_in(chunk.iter().copied()))
                    .all(connection)
                    .await?,
            );
        }
        let advisory_ids = evidence
            .iter()
            .map(|e| e.advisory_id)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let snapshot = weighting::PolicySnapshot::load(connection, sbom_ids, &advisory_ids).await?;
        let identifiers = weighting::store::provider_identifiers(connection, sbom_ids).await?;
        let mut groups = BTreeMap::<(Uuid, &str, &str), Vec<&correlation_evidence::Model>>::new();
        for row in &evidence {
            groups
                .entry((row.sbom_id, &row.node_id, &row.vulnerability_id))
                .or_default()
                .push(row);
        }
        let mut counts = HashMap::<Uuid, SbomVerdictCounts>::new();
        for ((sbom_id, node_id, _), rows) in groups {
            let request = ResolutionRequest::default();
            let policy = snapshot.effective(Some(sbom_id), Some(node_id), &request)?;
            let node_identifiers = identifiers
                .get(&(sbom_id, node_id.to_string()))
                .map(Vec::as_slice)
                .unwrap_or_default();
            let provider = snapshot.component_provider(
                Some(sbom_id),
                Some(node_id),
                node_identifiers,
                &policy,
            );
            let inputs = rows
                .iter()
                .map(|row| decision_evidence(row, &snapshot))
                .collect::<Result<Vec<_>, _>>()?;
            let decision = weighting::resolve(&inputs, provider, &policy, false)?;
            let count = counts.entry(sbom_id).or_default();
            match decision.status {
                VerdictStatus::Affected => count.affected += 1,
                VerdictStatus::Fixed => count.fixed += 1,
                VerdictStatus::NotAffected => count.not_affected += 1,
                VerdictStatus::UnderInvestigation => count.under_investigation += 1,
                VerdictStatus::None => count.none += 1,
            }
        }
        Ok(sbom_ids
            .iter()
            .map(|id| SbomVerdictCounts {
                sbom_id: *id,
                ..counts.get(id).cloned().unwrap_or_default()
            })
            .collect())
    }

    /// Read evidence for an SBOM and compute verdicts.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn correlate_sbom(
        &self,
        sbom_id: Uuid,
        include_unmatched: bool,
        connection: &DatabaseTransaction,
    ) -> Result<CorrelationResult, Error> {
        self.correlate_sbom_with(
            sbom_id,
            include_unmatched,
            &ResolutionRequest::default(),
            connection,
        )
        .await
    }

    pub async fn correlate_sbom_with(
        &self,
        sbom_id: Uuid,
        include_unmatched: bool,
        request: &ResolutionRequest,
        connection: &DatabaseTransaction,
    ) -> Result<CorrelationResult, Error> {
        if !request.product_context.is_empty() {
            return Err(Error::BadRequest(
                "Product context is only supported for identifier queries".into(),
            ));
        }
        weighting::engine::validate_weights(&request.overrides)?;
        let mut query = correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::SbomId.eq(sbom_id));
        if let Some(node) = &request.node_id {
            query = query.filter(correlation_evidence::Column::NodeId.eq(node));
        }
        if let Some(vulnerability) = &request.vulnerability_id {
            query = query.filter(correlation_evidence::Column::VulnerabilityId.eq(vulnerability));
        }
        let evidence_rows = query.all(connection).await?;

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
        let snapshot =
            weighting::PolicySnapshot::load(connection, &[sbom_id], &advisory_ids).await?;
        let vuln_titles = load_vulnerability_titles(&vuln_ids, connection).await?;
        let mut contexts =
            load_evidence_contexts(evidence_rows.iter().map(|e| e.id), connection).await?;

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
            let policy = snapshot.effective(Some(sbom_id), Some(node_id), request)?;
            let identifiers = node_identifiers
                .get(*node_id)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let component_provider =
                snapshot.component_provider(Some(sbom_id), Some(node_id), identifiers, &policy);
            let inputs = rows
                .iter()
                .map(|row| decision_evidence(row, &snapshot))
                .collect::<Result<Vec<_>, _>>()?;

            let evidence: Vec<_> = rows
                .iter()
                .zip(&inputs)
                .map(|(row, input)| {
                    let advisory = AdvisoryName::of(&advisory_map, row.advisory_id);
                    let provider = policy.provider(&input.provider, "assertion source");

                    EvidenceDetail {
                        id: row.id,
                        assertion_status: row.status.into(),
                        confidence: row.confidence,
                        extractor: row.extractor.clone(),
                        advisory_id: row.advisory_id,
                        advisory_identifier: advisory.identifier,
                        advisory_type: advisory.r#type,
                        matched_value: row.matched_value.clone().and_then(|value| {
                            serde_json::from_value(value)
                                .inspect_err(|err| {
                                    tracing::warn!("failed to parse matched value: {err}")
                                })
                                .ok()
                        }),
                        contexts: contexts.remove(&row.id).unwrap_or_default(),
                        provider_match: weighting::provider_match(&component_provider, &provider),
                        provider,
                        created_at: row.created_at,
                    }
                })
                .collect();

            let decision = weighting::resolve(
                &inputs,
                component_provider.clone(),
                &policy,
                request.include_explanation,
            )?;
            let status = decision.status;
            let resolution = decision.summary;

            let first = rows
                .iter()
                .find(|row| Some(row.advisory_id) == decision.winning_advisory)
                .copied()
                .unwrap_or(rows[0]);
            let advisory = AdvisoryName::of(&advisory_map, first.advisory_id);

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
                    advisory_identifier: advisory.identifier,
                    advisory_type: advisory.r#type,
                },
                status,
                resolution,
                component_provider,
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
        self.query_identifier_with(identifier, &ResolutionRequest::default(), connection)
            .await
    }

    pub async fn query_identifier_with(
        &self,
        identifier: IdentifierRef,
        request: &ResolutionRequest,
        connection: &DatabaseTransaction,
    ) -> Result<QueryResult, Error> {
        if request.node_id.is_some() || request.group_id.is_some() {
            return Err(Error::BadRequest(
                "Node and group selection require an SBOM target".into(),
            ));
        }
        weighting::engine::validate_weights(&request.overrides)?;
        let mut matches = self
            .extractors
            .query_with_context(&identifier, &request.product_context, connection)
            .await?;
        if let Some(vulnerability) = &request.vulnerability_id {
            matches.retain(|a| &a.vulnerability_id == vulnerability);
        }

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
        let snapshot = weighting::PolicySnapshot::load(connection, &[], &advisory_ids).await?;
        let policy = snapshot.effective(None, None, request)?;
        let mut provider_identifiers = vec![identifier.clone()];
        provider_identifiers.extend(request.product_context.clone());
        let component_provider =
            snapshot.component_provider(None, None, &provider_identifiers, &policy);
        let vuln_titles = load_vulnerability_titles(&vuln_ids, connection).await?;

        // Group matches by vulnerability_id, keeping entity statuses for resolution.
        let mut groups = BTreeMap::<&str, Vec<(AssertionStatus, QueryMatch)>>::new();
        for assertion in &matches {
            let advisory = AdvisoryName::of(&advisory_map, assertion.advisory_id);

            groups
                .entry(assertion.vulnerability_id.as_str())
                .or_default()
                .push((
                    assertion.status,
                    QueryMatch {
                        kind: identifier.kind,
                        value: assertion.matched_value.clone(),
                        advisory_id: assertion.advisory_id,
                        advisory_identifier: advisory.identifier,
                        advisory_type: advisory.r#type,
                        status: assertion.status.into(),
                        extractor: assertion.extractor.to_string(),
                        confidence: assertion.confidence,
                    },
                ));
        }

        let mut verdicts = Vec::new();
        for (vuln_id, items) in groups {
            let inputs = items
                .iter()
                .map(|(status, m)| weighting::DecisionEvidence {
                    reference: Uuid::new_v5(
                        &m.advisory_id,
                        serde_json::json!([m.extractor, m.value, m.status])
                            .to_string()
                            .as_bytes(),
                    )
                    .to_string(),
                    advisory_id: m.advisory_id,
                    status: (*status).into(),
                    confidence: m.confidence,
                    extractor: m.extractor.clone(),
                    value: Some(m.value.clone()),
                    provider: m
                        .value
                        .source_provider
                        .clone()
                        .or_else(|| snapshot.advisory_providers.get(&m.advisory_id).cloned())
                        .unwrap_or_default(),
                })
                .collect::<Vec<_>>();
            let decision = weighting::resolve(
                &inputs,
                component_provider.clone(),
                &policy,
                request.include_explanation,
            )?;
            verdicts.push(QueryVerdict {
                vulnerability_id: vuln_id.into(),
                vulnerability_title: vuln_titles.get(vuln_id).cloned().flatten(),
                status: decision.status,
                resolution: decision.summary,
                matches: items.into_iter().map(|(_, m)| m).collect(),
            });
        }

        Ok(QueryResult {
            query: identifier,
            verdicts,
        })
    }
}

fn decision_evidence(
    row: &correlation_evidence::Model,
    snapshot: &weighting::PolicySnapshot,
) -> Result<weighting::DecisionEvidence, Error> {
    let value = row
        .matched_value
        .clone()
        .map(serde_json::from_value::<MatchedValue>)
        .transpose()
        .map_err(Error::MatchedValue)?;
    let provider = value
        .as_ref()
        .and_then(|v| v.source_provider.clone())
        .or_else(|| snapshot.advisory_providers.get(&row.advisory_id).cloned())
        .unwrap_or_default();
    Ok(weighting::DecisionEvidence {
        reference: row.id.to_string(),
        advisory_id: row.advisory_id,
        status: row.status.into(),
        confidence: row.confidence,
        extractor: row.extractor.clone(),
        value,
        provider,
    })
}

/// The identifier and format of an advisory, for references to it.
#[derive(Clone)]
struct AdvisoryName {
    identifier: String,
    /// The format, from the `type` label the ingestor sets.
    r#type: Option<String>,
}

impl AdvisoryName {
    /// The name of an advisory, `unknown` if it isn't loaded.
    fn of(names: &HashMap<Uuid, AdvisoryName>, id: Uuid) -> Self {
        names.get(&id).cloned().unwrap_or_else(|| Self {
            identifier: "unknown".to_string(),
            r#type: None,
        })
    }
}

/// Load advisory identifiers and formats by ID.
async fn load_advisory_names(
    advisory_ids: &[Uuid],
    connection: &DatabaseTransaction,
) -> Result<HashMap<Uuid, AdvisoryName>, Error> {
    let advisories = advisory::Entity::find()
        .filter(advisory::Column::Id.is_in(advisory_ids.iter().copied()))
        .all(connection)
        .instrument(info_span!("loading advisories"))
        .await?;

    Ok(advisories
        .into_iter()
        .map(|a| {
            let r#type = a.labels.0.get("type").cloned();
            (
                a.id,
                AdvisoryName {
                    identifier: a.identifier,
                    r#type,
                },
            )
        })
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

/// The contexts of evidence, keyed by evidence ID, best confidence first.
async fn load_evidence_contexts(
    evidence_ids: impl IntoIterator<Item = Uuid>,
    connection: &impl ConnectionTrait,
) -> Result<HashMap<Uuid, Vec<EvidenceContext>>, Error> {
    let evidence_ids = evidence_ids.into_iter().collect::<Vec<_>>();
    let mut result = HashMap::<_, Vec<_>>::new();
    for chunk in evidence_ids.chunks(5000) {
        let links = correlation_evidence_context::Entity::find()
            .filter(correlation_evidence_context::Column::EvidenceId.is_in(chunk.iter().copied()))
            .find_also_related(assertion_context::Entity)
            .all(connection)
            .instrument(info_span!("loading evidence contexts"))
            .await?;
        for (link, context) in links {
            let (name, category) = context
                .map(|context| (context.name, context.category.map(Into::into)))
                .unwrap_or_default();
            result
                .entry(link.evidence_id)
                .or_default()
                .push(EvidenceContext {
                    context_id: link.context_id,
                    name,
                    category,
                    source: link.source.into(),
                    distance: link.distance,
                    node_identifier: link.node_identifier,
                    context_identifier: link.context_identifier,
                    confidence: link.confidence,
                });
        }
    }
    for contexts in result.values_mut() {
        contexts.sort_by(|a, b| {
            b.confidence
                .total_cmp(&a.confidence)
                .then_with(|| a.node_identifier.cmp(&b.node_identifier))
        });
    }
    Ok(result)
}

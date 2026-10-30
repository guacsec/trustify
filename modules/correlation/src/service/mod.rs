use crate::{
    error::Error,
    extractor::{Extractors, SourceAssertionRef},
    model::{
        ComponentRef, CorrelationResult, EvidenceContext, EvidenceDetail, EvidenceRemediation,
        IdentifierRef, MatchedValue, QueryMatch, QueryResult, QueryVerdict, ResolutionRequest,
        SbomVerdictCounts, ScoreRef, VerdictSummary, VulnerabilityRef,
    },
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, FromQueryResult, QueryFilter,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use tracing::{Instrument, info_span, instrument};
use trustify_entity::{
    advisory, advisory_vulnerability_score, advisory_vulnerability_upstream, assertion_context,
    correlation_evidence, correlation_evidence::AssertionStatus, correlation_evidence_context,
    sbom, sbom_node, vulnerability,
};
use uuid::Uuid;

pub mod confidence;
pub mod extraction;
pub mod freshness;
pub mod option;
mod pagination;
pub mod projection;
mod remediation;
pub mod resolution;
pub mod statement;

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

    /// Read counts from the last completed verdict snapshots, without resolving evidence.
    pub async fn count_verdicts(
        &self,
        sbom_ids: &[Uuid],
        connection: &DatabaseTransaction,
    ) -> Result<Vec<SbomVerdictCounts>, Error> {
        projection::counts(sbom_ids, connection).await
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
        resolution::provider::ResolutionContext::new(Vec::new(), request)?;
        let freshness = freshness::for_sboms(connection, &[sbom_id])
            .await?
            .remove(&sbom_id)
            .unwrap_or_default();
        let sbom_name = load_sbom_name(sbom_id, connection).await?;
        let mut query = correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::SbomId.eq(sbom_id));
        if let Some(node) = &request.node_id {
            query = query.filter(correlation_evidence::Column::NodeId.eq(node));
        }
        if let Some(vulnerability) = &request.vulnerability_id {
            query = query.filter(correlation_evidence::Column::VulnerabilityId.eq(vulnerability));
        }
        let evidence_rows = query.all(connection).await?;

        let verdicts = self
            .verdicts(sbom_id, request, &evidence_rows, connection)
            .await?;
        let unmatched_components = if include_unmatched {
            let node_identifiers = self
                .extractors
                .component_identifiers(sbom_id, None, connection)
                .await?;
            let matched = evidence_rows
                .iter()
                .map(|row| row.node_id.as_str())
                .collect();
            Some(load_unmatched_components(sbom_id, &matched, &node_identifiers, connection).await?)
        } else {
            None
        };
        Ok(CorrelationResult {
            sbom_id,
            sbom_name,
            freshness,
            verdicts,
            unmatched_components,
        })
    }

    /// Resolve complete evidence groups selected by either a preview or a page.
    async fn verdicts(
        &self,
        sbom_id: Uuid,
        request: &ResolutionRequest,
        evidence_rows: &[correlation_evidence::Model],
        connection: &DatabaseTransaction,
    ) -> Result<Vec<VerdictSummary>, Error> {
        if evidence_rows.is_empty() {
            return Ok(Vec::new());
        }
        let node_ids = evidence_rows
            .iter()
            .map(|e| e.node_id.as_str())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        let node_identifiers = self
            .extractors
            .component_identifiers(sbom_id, Some(&node_ids), connection)
            .await?;

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
            resolution::ProviderSnapshot::load(connection, &[sbom_id], &advisory_ids).await?;
        let vuln_titles = load_vulnerability_titles(&vuln_ids, connection).await?;
        let mut contexts =
            load_evidence_contexts(evidence_rows.iter().map(|e| e.id), connection).await?;
        let mut remediations = load_evidence_remediations(evidence_rows, connection).await?;
        let upstream = load_upstream(evidence_rows, connection).await?;
        let mut scores = load_scores(&advisory_ids, &vuln_ids, connection).await?;

        // Group evidence by (node_id, vulnerability_id).
        let mut groups: BTreeMap<(&str, &str), Vec<&correlation_evidence::Model>> = BTreeMap::new();
        for row in evidence_rows {
            groups
                .entry((row.node_id.as_str(), row.vulnerability_id.as_str()))
                .or_default()
                .push(row);
        }

        let mut verdicts = Vec::with_capacity(groups.len());
        for ((node_id, vuln_id), rows) in &groups {
            let context = snapshot.context(request)?;
            let identifiers = node_identifiers
                .get(*node_id)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let component_provider =
                snapshot.component_provider(Some(sbom_id), Some(node_id), identifiers, &context);
            let inputs = rows
                .iter()
                .map(|row| {
                    Ok(resolution::DecisionEvidence {
                        contexts: contexts.remove(&row.id).unwrap_or_default(),
                        remediations: remediations.remove(&row.id).unwrap_or_default(),
                        ..decision_evidence(row, &snapshot)?
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?;

            let evidence: Vec<_> = rows
                .iter()
                .zip(&inputs)
                .map(|(row, input)| {
                    let advisory = AdvisoryName::of(&advisory_map, row.advisory_id);
                    let provider = context.provider(&input.provider, "assertion source");

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
                        contexts: input.contexts.clone(),
                        confidence_factors: input.factors.clone(),
                        remediations: input.remediations.clone(),
                        provider_match: resolution::provider_match(&component_provider, &provider),
                        provider,
                        created_at: row.created_at,
                    }
                })
                .collect();

            let decision = resolution::resolve(
                &inputs,
                component_provider.clone(),
                &context,
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
                    upstream: rows
                        .iter()
                        .filter_map(|row| {
                            upstream.get(&(row.advisory_id, row.vulnerability_id.clone()))
                        })
                        .flatten()
                        .cloned()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                    scores: scores
                        .remove(&(first.advisory_id, vuln_id.to_string()))
                        .unwrap_or_default(),
                },
                status,
                resolution,
                component_provider,
                evidence,
            });
        }

        Ok(verdicts)
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
        if request.node_id.is_some() {
            return Err(Error::BadRequest(
                "Node selection requires an SBOM target".into(),
            ));
        }
        resolution::provider::ResolutionContext::new(Vec::new(), request)?;
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
        let snapshot = resolution::ProviderSnapshot::load(connection, &[], &advisory_ids).await?;
        let context = snapshot.context(request)?;
        let mut provider_identifiers = vec![identifier.clone()];
        provider_identifiers.extend(request.product_context.clone());
        let component_provider =
            snapshot.component_provider(None, None, &provider_identifiers, &context);
        let vuln_titles = load_vulnerability_titles(&vuln_ids, connection).await?;
        let mut scores = load_scores(&advisory_ids, &vuln_ids, connection).await?;

        let remediations = remediation::Remediations::load(
            matches
                .iter()
                .flat_map(|assertion| assertion.source_assertions.iter().copied()),
            connection,
        )
        .await?;

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
                        remediations: remediations.for_sources(
                            assertion.advisory_id,
                            &assertion.vulnerability_id,
                            &assertion.source_assertions,
                        ),
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
                .map(|(status, m)| resolution::DecisionEvidence {
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
                    value: Some(m.value.clone()),
                    provider: m
                        .value
                        .source_provider
                        .clone()
                        .or_else(|| snapshot.advisory_providers.get(&m.advisory_id).cloned())
                        .unwrap_or_default(),
                    contexts: Vec::new(),
                    factors: Vec::new(),
                    remediations: m.remediations.clone(),
                })
                .collect::<Vec<_>>();
            let decision = resolution::resolve(
                &inputs,
                component_provider.clone(),
                &context,
                request.include_explanation,
            )?;
            verdicts.push(QueryVerdict {
                vulnerability_id: vuln_id.into(),
                vulnerability_title: vuln_titles.get(vuln_id).cloned().flatten(),
                scores: decision
                    .winning_advisory
                    .and_then(|advisory_id| scores.remove(&(advisory_id, vuln_id.to_string())))
                    .unwrap_or_default(),
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
    snapshot: &resolution::ProviderSnapshot,
) -> Result<resolution::DecisionEvidence, Error> {
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
    Ok(resolution::DecisionEvidence {
        reference: row.id.to_string(),
        advisory_id: row.advisory_id,
        status: row.status.into(),
        confidence: row.confidence,
        value,
        provider,
        contexts: Vec::new(),
        remediations: Vec::new(),
        factors: serde_json::from_value(row.confidence_factors.clone())
            .inspect_err(|err| tracing::warn!("failed to parse confidence factors: {err}"))
            .unwrap_or_default(),
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

/// Load the name of an SBOM, which is the name of its root node.
async fn load_sbom_name(
    sbom_id: Uuid,
    connection: &DatabaseTransaction,
) -> Result<Option<String>, Error> {
    let Some(sbom) = sbom::Entity::find_by_id(sbom_id).one(connection).await? else {
        return Ok(None);
    };

    Ok(sbom_node::Entity::find_by_id((sbom_id, sbom.node_id))
        .one(connection)
        .await?
        .map(|node| node.name))
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

/// The upstream vulnerabilities of the advisories of evidence, keyed by advisory and vulnerability.
async fn load_upstream(
    evidence: &[correlation_evidence::Model],
    connection: &impl ConnectionTrait,
) -> Result<HashMap<(Uuid, String), Vec<String>>, Error> {
    let advisories = evidence
        .iter()
        .map(|e| e.advisory_id)
        .collect::<BTreeSet<_>>();
    if advisories.is_empty() {
        return Ok(HashMap::new());
    }
    let mut result = HashMap::<_, Vec<_>>::new();
    for row in advisory_vulnerability_upstream::Entity::find()
        .filter(advisory_vulnerability_upstream::Column::AdvisoryId.is_in(advisories))
        .all(connection)
        .instrument(info_span!("loading upstream vulnerabilities"))
        .await?
    {
        result
            .entry((row.advisory_id, row.vulnerability_id))
            .or_default()
            .push(row.upstream_id);
    }
    Ok(result)
}

/// Load the CVSS scores of the advisories' vulnerabilities, keyed by advisory and vulnerability,
/// ordered as [`VulnerabilityRef::scores`].
async fn load_scores(
    advisory_ids: &[Uuid],
    vuln_ids: &[&str],
    connection: &impl ConnectionTrait,
) -> Result<HashMap<(Uuid, String), Vec<ScoreRef>>, Error> {
    let rows = advisory_vulnerability_score::Entity::find()
        .filter(
            advisory_vulnerability_score::Column::AdvisoryId.is_in(advisory_ids.iter().copied()),
        )
        .filter(
            advisory_vulnerability_score::Column::VulnerabilityId.is_in(vuln_ids.iter().copied()),
        )
        .all(connection)
        .instrument(info_span!("loading scores"))
        .await?;

    let mut result = HashMap::<_, Vec<ScoreRef>>::new();
    for row in rows {
        result
            .entry((row.advisory_id, row.vulnerability_id.clone()))
            .or_default()
            .push(row.into());
    }
    for scores in result.values_mut() {
        scores.sort_by(|a, b| {
            b.version
                .cmp(&a.version)
                .then_with(|| b.score.total_cmp(&a.score))
        });
        // e.g. CSAF states a score per product group, often with the same vector
        scores.dedup_by(|a, b| a.version == b.version && a.vector == b.vector);
    }
    Ok(result)
}

/// Remediations of the source assertions that survived matching, keyed by evidence ID.
async fn load_evidence_remediations(
    evidence: &[correlation_evidence::Model],
    connection: &impl ConnectionTrait,
) -> Result<HashMap<Uuid, Vec<EvidenceRemediation>>, Error> {
    let references = evidence
        .iter()
        .map(|row| {
            serde_json::from_value::<BTreeSet<SourceAssertionRef>>(row.source_assertions.clone())
                .map(|sources| (row, sources))
                .map_err(Error::MatchedValue)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let remediations = remediation::Remediations::load(
        references
            .iter()
            .flat_map(|(_, sources)| sources.iter().copied()),
        connection,
    )
    .await?;
    let mut result = HashMap::new();
    for (row, sources) in references {
        let values = remediations.for_sources(row.advisory_id, &row.vulnerability_id, &sources);
        if !values.is_empty() {
            result.insert(row.id, values);
        }
    }
    Ok(result)
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
                    distance: u32::try_from(link.distance)?,
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

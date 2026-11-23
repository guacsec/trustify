use crate::{
    error::Error,
    extractor::{
        Assertion, Extractors, SourceAssertionRef,
        context::{NodeCpe, format_cpe},
    },
    model::{
        ComponentRef, CorrelationResult, EvidenceContext, EvidenceDetail, EvidenceRemediation,
        IdentifierKind, IdentifierRef, MatchedValue, QueryMatch, QueryResult, QueryVerdict,
        ResolutionRequest, SbomVerdictCounts, ScoreRef, VerdictSummary, VulnerabilityRef,
    },
    service::resolution::ProviderSnapshot,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, FromQueryResult, QueryFilter,
    QuerySelect, Value,
    sea_query::{Expr, ExprTrait, PgFunc, SimpleExpr},
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use tracing::{Instrument, info_span, instrument};
use trustify_common::{db::chunk::chunked_with, purl::Purl};
use trustify_entity::{
    advisory, advisory_vulnerability_score, advisory_vulnerability_upstream, assertion_context,
    correlation_evidence::AssertionStatus, correlation_evidence_context,
    correlation_evidence_detail, sbom, sbom_node, vulnerability,
};
use uuid::Uuid;

mod class;
pub mod confidence;
pub mod detail;
pub mod extraction;
pub mod freshness;
pub mod option;
mod pagination;
pub mod projection;
mod remediation;
pub mod resolution;
pub mod statement;
pub mod tuning;

#[cfg(test)]
mod test;

/// Reads evidence from the database and computes verdicts.
#[derive(Default)]
pub struct CorrelationService {
    extractors: Extractors,
}

/// Advisory metadata shared by the winners of one recommendation report.
///
/// Matches and verdicts are never cached. Drop this value at the end of the report so another
/// request reloads provider aliases and advisory metadata from its own transaction.
pub struct ReportQueryCache {
    providers: ProviderSnapshot,
    advisory_names: HashMap<Uuid, AdvisoryName>,
    loaded_advisories: HashSet<Uuid>,
}

impl ReportQueryCache {
    /// Reuse the provider snapshot already loaded to identify the report's component suppliers.
    pub fn new(providers: ProviderSnapshot) -> Self {
        Self {
            providers,
            advisory_names: HashMap::new(),
            loaded_advisories: HashSet::new(),
        }
    }

    async fn load(
        &mut self,
        advisory_ids: &[Uuid],
        connection: &DatabaseTransaction,
    ) -> Result<(), Error> {
        let missing = advisory_ids
            .iter()
            .filter(|id| !self.loaded_advisories.contains(*id))
            .copied()
            .collect::<Vec<_>>();
        for missing in chunked_with(1, missing) {
            let names = load_advisory_names(&missing, connection).await?;
            self.providers
                .load_advisories(connection, missing.iter().copied())
                .await?;
            self.advisory_names.extend(names);
            self.loaded_advisories.extend(missing);
        }
        Ok(())
    }
}

/// Request-local raw candidate matches and source metadata, reusable across independent contexts.
///
/// No scoped match or verdict is retained here; each resolution reapplies its own product context.
/// Advisory eligibility and source metadata are a snapshot for one request, not a cross-request cache.
pub struct PreparedPurlCandidates {
    assertions: HashMap<Purl, Vec<Assertion>>,
    metadata: QueryMetadata,
}

/// Vulnerability/source metadata loaded once for a batch, without any selected verdicts.
struct QueryMetadata {
    eligible_advisories: HashSet<Uuid>,
    titles: HashMap<String, Option<String>>,
    scores: HashMap<(Uuid, String), Vec<ScoreRef>>,
    remediations: remediation::Remediations,
}

impl QueryMetadata {
    async fn load<'a>(
        assertions: impl IntoIterator<Item = &'a Assertion>,
        connection: &DatabaseTransaction,
    ) -> Result<Self, Error> {
        let mut assertions = assertions.into_iter().collect::<Vec<_>>();
        let ids = assertions
            .iter()
            .map(|assertion| assertion.advisory_id)
            .collect::<HashSet<_>>();
        // Advisory eligibility is request-local metadata, shared by all targets and contexts.
        let mut eligible_advisories = HashSet::new();
        for ids in chunked_with(1, ids) {
            eligible_advisories.extend(
                advisory::Entity::find()
                    .select_only()
                    .column(advisory::Column::Id)
                    .filter(advisory::Column::Id.is_in(ids))
                    .filter(advisory::Column::Deprecated.eq(false))
                    .into_tuple::<Uuid>()
                    .all(connection)
                    .instrument(info_span!("loading eligible advisories"))
                    .await?,
            );
        }
        assertions.retain(|assertion| eligible_advisories.contains(&assertion.advisory_id));
        let advisories = eligible_advisories.iter().copied().collect::<Vec<_>>();
        let vulnerabilities = assertions
            .iter()
            .map(|assertion| assertion.vulnerability_id.as_str())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut titles = HashMap::new();
        for chunk in chunked_with(1, vulnerabilities.iter().copied()) {
            titles.extend(load_vulnerability_titles(&chunk, connection).await?);
        }
        let mut scores = HashMap::new();
        for advisory_chunk in chunked_with(2, advisories.iter().copied()) {
            for vulnerability_chunk in chunked_with(2, vulnerabilities.iter().copied()) {
                scores
                    .extend(load_scores(&advisory_chunk, &vulnerability_chunk, connection).await?);
            }
        }
        let remediations = remediation::Remediations::load(
            assertions
                .iter()
                .flat_map(|assertion| assertion.source_assertions.iter().copied()),
            connection,
        )
        .await?;
        Ok(Self {
            eligible_advisories,
            titles,
            scores,
            remediations,
        })
    }
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
        let evidence_rows = pagination::evidence_query(sbom_id, request)
            .all(connection)
            .await?;

        let mut snapshot = resolution::ProviderSnapshot::load_sboms(connection, &[sbom_id]).await?;
        let verdicts = self
            .verdicts(sbom_id, request, &evidence_rows, &mut snapshot, connection)
            .await?;
        let verdicts =
            class::expand(sbom_id, verdicts, request.node_id.as_deref(), connection).await?;
        let unmatched_components = if include_unmatched {
            let node_identifiers = self
                .extractors
                .component_identifiers(sbom_id, None, connection)
                .await?;
            let representatives = evidence_rows
                .iter()
                .map(|row| row.node_id.clone())
                .collect();
            let members = class::members(sbom_id, representatives, connection).await?;
            let matched = members.values().flatten().map(String::as_str).collect();
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
        evidence_rows: &[correlation_evidence_detail::Model],
        snapshot: &mut resolution::ProviderSnapshot,
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
            .filter(is_any(
                sbom_node::Column::NodeId,
                node_ids.iter().map(ToString::to_string).collect(),
            ))
            .all(connection)
            .await?;

        let node_names: HashMap<&str, &str> = nodes
            .iter()
            .map(|n| (n.node_id.as_str(), n.name.as_str()))
            .collect();

        let advisory_map = load_advisory_names(&advisory_ids, connection).await?;
        snapshot
            .load_advisories(connection, advisory_ids.iter().copied())
            .await?;
        let snapshot = &*snapshot;
        let vuln_titles = load_vulnerability_titles(&vuln_ids, connection).await?;
        let mut contexts =
            load_evidence_contexts(evidence_rows.iter().map(|e| e.id), connection).await?;
        let mut remediations = load_evidence_remediations(evidence_rows, connection).await?;
        let upstream = load_upstream(evidence_rows, connection).await?;
        let mut scores = load_scores(&advisory_ids, &vuln_ids, connection).await?;

        // Group evidence by (node_id, vulnerability_id).
        let mut groups: BTreeMap<(&str, &str), Vec<&correlation_evidence_detail::Model>> =
            BTreeMap::new();
        for row in evidence_rows {
            groups
                .entry((row.node_id.as_str(), row.vulnerability_id.as_str()))
                .or_default()
                .push(row);
        }

        let context = snapshot.context(request)?;
        let mut verdicts = Vec::with_capacity(groups.len());
        for ((node_id, vuln_id), rows) in &groups {
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
                        ..decision_evidence(row, snapshot)?
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

    /// Resolves an ad-hoc identifier with optional caller-supplied product/provider context.
    pub async fn query_identifier_with(
        &self,
        identifier: IdentifierRef,
        request: &ResolutionRequest,
        connection: &DatabaseTransaction,
    ) -> Result<QueryResult, Error> {
        self.query_identifier_in_context(identifier, request, None, None, connection)
            .await
    }

    /// Resolves an identifier with the original weighted CPE context of an SBOM component.
    ///
    /// This internal report route preserves source/distance instead of treating CPEs as local.
    /// It cannot be combined with ad-hoc product context or an SBOM node-selection request.
    pub async fn query_identifier_with_node_context(
        &self,
        identifier: IdentifierRef,
        request: &ResolutionRequest,
        node_cpes: &[NodeCpe],
        connection: &DatabaseTransaction,
    ) -> Result<QueryResult, Error> {
        self.query_identifier_in_context(identifier, request, Some(node_cpes), None, connection)
            .await
    }

    /// Resolve a report winner with weighted node context and request-scoped advisory metadata.
    pub async fn query_identifier_with_node_context_cached(
        &self,
        identifier: IdentifierRef,
        request: &ResolutionRequest,
        node_cpes: &[NodeCpe],
        cache: &mut ReportQueryCache,
        connection: &DatabaseTransaction,
    ) -> Result<QueryResult, Error> {
        self.query_identifier_in_context(
            identifier,
            request,
            Some(node_cpes),
            Some(cache),
            connection,
        )
        .await
    }

    /// Resolves recommendation candidates with transient assertions through normal PURL matching.
    ///
    /// Matching is batched; only advisory/provider metadata is cached, never scoped matches or
    /// verdicts. Additional assertions must already identify the exact candidate they apply to.
    /// They retain their source/context and participate in the same resolution as stored evidence.
    ///
    /// Returns one result per input candidate in input order, including repeated PURLs. Assertions
    /// supplied for repeated PURLs are combined before matching. `request` may set provider and
    /// vulnerability filters, but node selection and ad-hoc `product_context` are rejected.
    /// `node_cpes: None` uses context-free query rules; `Some(&[])` supplies a known-empty node
    /// context, while nonempty contexts retain each CPE's source and distance for weighting.
    /// Invalid resolution requests, database failures, and invalid source metadata return errors.
    pub async fn query_purl_candidates(
        &self,
        candidates: &[(Purl, Vec<Assertion>)],
        request: &ResolutionRequest,
        node_cpes: Option<&[NodeCpe]>,
        cache: &mut ReportQueryCache,
        connection: &DatabaseTransaction,
    ) -> Result<Vec<QueryResult>, Error> {
        let prepared = self.prepare_purl_candidates(candidates, connection).await?;
        let targets = candidates
            .iter()
            .map(|(purl, _)| purl.clone())
            .collect::<Vec<_>>();
        let results = Self::query_prepared_purl_candidates(
            &prepared, &targets, request, node_cpes, cache, connection,
        )
        .await?;
        Ok(targets
            .into_iter()
            .filter_map(|purl| results.get(&purl).cloned())
            .collect())
    }

    /// Deduplicates and extracts a request's candidates once, including source metadata in batches.
    ///
    /// Equal PURLs share their supplied assertions. The result retains unscoped evidence and an
    /// advisory-eligibility snapshot only for the current request/transaction; each later query
    /// must apply its own provider and weighted node context. No PURL or evidence is persisted.
    /// Database failures and invalid source metadata return errors.
    pub async fn prepare_purl_candidates(
        &self,
        candidates: &[(Purl, Vec<Assertion>)],
        connection: &DatabaseTransaction,
    ) -> Result<PreparedPurlCandidates, Error> {
        let mut unique = HashMap::<Purl, Vec<Assertion>>::new();
        for (purl, assertions) in candidates {
            unique
                .entry(purl.clone())
                .or_default()
                .extend(assertions.iter().cloned());
        }
        let mut targets = unique.into_iter().collect::<Vec<_>>();
        targets.sort_by_cached_key(|(purl, _)| purl.to_string());
        let identifiers = targets
            .iter()
            .map(|(purl, assertions)| {
                (
                    IdentifierRef {
                        kind: IdentifierKind::Purl,
                        value: purl.to_string(),
                    },
                    assertions.clone(),
                )
            })
            .collect::<Vec<_>>();
        let groups = self
            .extractors
            .match_candidates(&identifiers, connection)
            .await?;
        let metadata = QueryMetadata::load(groups.iter().flatten(), connection).await?;
        Ok(PreparedPurlCandidates {
            assertions: targets
                .into_iter()
                .map(|(purl, _)| purl)
                .zip(groups)
                .collect(),
            metadata,
        })
    }

    /// Resolves prepared raw matches for only these targets under this independent provider/context.
    ///
    /// Returns a map keyed by the requested PURLs, without an ordering guarantee; repeated targets
    /// produce one entry, and targets absent from `prepared` have no verdicts. `request` may set
    /// provider and vulnerability filters, but node selection and ad-hoc `product_context` return
    /// `BadRequest`. `node_cpes: None` applies context-free rules; `Some(&[])` represents a known
    /// empty context. Source/distance weights are preserved for supplied CPEs. Prepared evidence
    /// and metadata are reused, but scoped assertions and verdicts are recomputed for this call.
    /// Database failures and invalid resolution/source metadata also return errors.
    pub async fn query_prepared_purl_candidates(
        prepared: &PreparedPurlCandidates,
        targets: &[Purl],
        request: &ResolutionRequest,
        node_cpes: Option<&[NodeCpe]>,
        cache: &mut ReportQueryCache,
        connection: &DatabaseTransaction,
    ) -> Result<HashMap<Purl, QueryResult>, Error> {
        if request.node_id.is_some() || !request.product_context.is_empty() {
            return Err(Error::BadRequest(
                "Candidate queries accept weighted node context, not ad-hoc context or node selection".into(),
            ));
        }
        cache.providers.context(request)?;
        let groups = targets
            .iter()
            .map(|purl| prepared.assertions.get(purl).cloned().unwrap_or_default())
            .collect();
        let groups = Extractors::scope_candidates(groups, node_cpes, connection).await?;
        let advisory_ids = groups
            .iter()
            .flatten()
            .map(|assertion| assertion.advisory_id)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        cache.load(&advisory_ids, connection).await?;
        let mut results = HashMap::with_capacity(targets.len());
        for (purl, assertions) in targets.iter().zip(groups) {
            let identifier = IdentifierRef {
                kind: IdentifierKind::Purl,
                value: purl.to_string(),
            };
            results.insert(
                purl.clone(),
                Self::resolve_query_matches(
                    identifier,
                    request,
                    node_cpes,
                    assertions,
                    Some(&mut *cache),
                    connection,
                    Some(&prepared.metadata),
                )
                .await?,
            );
        }
        Ok(results)
    }

    /// Shares provider resolution and verdict assembly between ad-hoc and weighted-node queries.
    async fn query_identifier_in_context(
        &self,
        identifier: IdentifierRef,
        request: &ResolutionRequest,
        node_cpes: Option<&[NodeCpe]>,
        cache: Option<&mut ReportQueryCache>,
        connection: &DatabaseTransaction,
    ) -> Result<QueryResult, Error> {
        if node_cpes.is_some() && !request.product_context.is_empty() {
            return Err(Error::BadRequest(
                "Weighted node context cannot be combined with ad-hoc product context".into(),
            ));
        }
        if request.node_id.is_some() {
            return Err(Error::BadRequest(
                "Node selection requires an SBOM target".into(),
            ));
        }
        resolution::provider::ResolutionContext::new(Vec::new(), request)?;
        let matches = if let Some(cpes) = node_cpes {
            self.extractors
                .query_with_node_context(&identifier, cpes, connection)
                .await?
        } else {
            self.extractors
                .query_with_context(&identifier, &request.product_context, connection)
                .await?
        };
        Self::resolve_query_matches(
            identifier, request, node_cpes, matches, cache, connection, None,
        )
        .await
    }

    /// Assembles query verdicts identically for extracted and transient candidate evidence.
    async fn resolve_query_matches(
        identifier: IdentifierRef,
        request: &ResolutionRequest,
        node_cpes: Option<&[NodeCpe]>,
        mut matches: Vec<Assertion>,
        cache: Option<&mut ReportQueryCache>,
        connection: &DatabaseTransaction,
        metadata: Option<&QueryMetadata>,
    ) -> Result<QueryResult, Error> {
        if let Some(vulnerability) = &request.vulnerability_id {
            matches.retain(|a| &a.vulnerability_id == vulnerability);
        }

        let fresh_metadata;
        let metadata = if let Some(metadata) = metadata {
            metadata
        } else {
            fresh_metadata = QueryMetadata::load(&matches, connection).await?;
            &fresh_metadata
        };
        matches.retain(|assertion| {
            metadata
                .eligible_advisories
                .contains(&assertion.advisory_id)
        });

        let advisory_ids = matches
            .iter()
            .map(|a| a.advisory_id)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        let fresh_names;
        let fresh_snapshot;
        let (advisory_map, snapshot) = if let Some(cache) = cache {
            cache.load(&advisory_ids, connection).await?;
            (&cache.advisory_names, &cache.providers)
        } else {
            fresh_names = load_advisory_names(&advisory_ids, connection).await?;
            fresh_snapshot = ProviderSnapshot::load(connection, &[], &advisory_ids).await?;
            (&fresh_names, &fresh_snapshot)
        };
        let context = snapshot.context(request)?;
        let mut provider_identifiers = vec![identifier.clone()];
        provider_identifiers.extend(request.product_context.clone());
        if let Some(cpes) = node_cpes {
            provider_identifiers.extend(cpes.iter().map(|item| IdentifierRef {
                kind: IdentifierKind::Cpe,
                value: format_cpe(&item.cpe),
            }));
        }
        let component_provider =
            snapshot.component_provider(None, None, &provider_identifiers, &context);
        // Group matches by vulnerability_id, keeping entity statuses for resolution.
        let mut groups = BTreeMap::<&str, Vec<(AssertionStatus, QueryMatch)>>::new();
        for assertion in &matches {
            let advisory = AdvisoryName::of(advisory_map, assertion.advisory_id);

            groups
                .entry(assertion.vulnerability_id.as_str())
                .or_default()
                .push((
                    assertion.status,
                    QueryMatch {
                        remediations: metadata.remediations.for_sources(
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
                vulnerability_title: metadata.titles.get(vuln_id).cloned().flatten(),
                scores: decision
                    .winning_advisory
                    .and_then(|advisory_id| {
                        metadata
                            .scores
                            .get(&(advisory_id, vuln_id.to_string()))
                            .cloned()
                    })
                    .unwrap_or_default(),
                status: decision.status,
                winning_advisory_id: decision.winning_advisory,
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
    row: &correlation_evidence_detail::Model,
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

/// `column = ANY($1)`: one array parameter, instead of one parameter per value of an `IN` list.
fn is_any<C, T>(column: C, values: Vec<T>) -> SimpleExpr
where
    C: ColumnTrait,
    Value: From<Vec<T>>,
{
    Expr::col(column.as_column_ref()).eq(SimpleExpr::FunctionCall(PgFunc::any(Value::from(values))))
}

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

/// Load advisory identifiers and formats by ID.
async fn load_advisory_names(
    advisory_ids: &[Uuid],
    connection: &DatabaseTransaction,
) -> Result<HashMap<Uuid, AdvisoryName>, Error> {
    let advisories = advisory::Entity::find()
        .filter(is_any(advisory::Column::Id, advisory_ids.to_vec()))
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
        .filter(is_any(vulnerability::Column::Id, owned(vuln_ids)))
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
    evidence: &[correlation_evidence_detail::Model],
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
        .filter(is_any(
            advisory_vulnerability_score::Column::AdvisoryId,
            advisory_ids.to_vec(),
        ))
        .filter(is_any(
            advisory_vulnerability_score::Column::VulnerabilityId,
            owned(vuln_ids),
        ))
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
    evidence: &[correlation_evidence_detail::Model],
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

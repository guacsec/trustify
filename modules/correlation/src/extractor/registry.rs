use super::{
    Assertion, Extractor, MatchPart, MatchSink, NodeIdentifier, NodeMatch, NodeRef,
    class::{classify, members},
    context::{self, NodeCpe, Scope, Scoper},
    cpe::CpeExtractor,
    digest::DigestExtractor,
    product_identifier::ProductIdentifierExtractor,
    purl::PurlExtractor,
    version::retain_in_range,
    writer::EvidenceWriter,
};
use crate::{
    error::Error,
    model::IdentifierRef,
    service::{
        freshness::{lock_revision, lock_sboms},
        tuning::DEFAULT_MATCH_BATCH,
    },
};
use sea_orm::DatabaseTransaction;
use std::{
    borrow::{Borrow, Cow},
    collections::{BTreeMap, BTreeSet, HashMap},
    mem::take,
    slice,
    sync::Arc,
};
use tracing::{Span, field, instrument};
use uuid::Uuid;

/// Receives the progress of extracting an SBOM.
#[async_trait::async_trait]
pub trait ExtractionProgress: Send + Sync {
    /// `done` of all `total` chunks of the SBOM are extracted, across all extractors.
    async fn chunks_done(&self, done: usize, total: usize);
}

/// Ignores the progress.
#[async_trait::async_trait]
impl ExtractionProgress for () {
    async fn chunks_done(&self, _done: usize, _total: usize) {}
}

/// The set of active extractors.
pub struct Extractors {
    extractors: Vec<Box<dyn Extractor>>,
    /// The number of identifiers an SBOM is matched with at once.
    chunk: usize,
    /// The number of matches of an SBOM held before their evidence is written.
    match_batch: usize,
}

impl Default for Extractors {
    /// All known extractors. This is the single place to register a new one.
    fn default() -> Self {
        Self::new(vec![
            Box::new(DigestExtractor),
            Box::new(ProductIdentifierExtractor),
            Box::new(PurlExtractor),
            Box::new(CpeExtractor),
        ])
    }
}

impl Extractors {
    /// Create a registry from an explicit set of extractors.
    pub fn new(extractors: Vec<Box<dyn Extractor>>) -> Self {
        Self {
            extractors,
            chunk: CHUNK,
            match_batch: DEFAULT_MATCH_BATCH,
        }
    }

    /// Match SBOMs in chunks of about `chunk` identifiers instead of the default.
    #[cfg(test)]
    pub fn with_chunk(self, chunk: usize) -> Self {
        Self { chunk, ..self }
    }

    /// Write the evidence of an SBOM once about `match_batch` matches are held, see
    /// [`WorkerConfig::match_batch`](crate::service::tuning::WorkerConfig::match_batch).
    pub fn with_match_batch(self, match_batch: usize) -> Self {
        Self {
            match_batch,
            ..self
        }
    }

    /// Match the identifiers of an SBOM against advisories and store evidence.
    ///
    /// Returns the number of evidence entries produced.
    pub async fn extract_for_sbom(
        &self,
        sbom_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<usize, Error> {
        self.extract_for_sbom_reporting(sbom_id, &(), tx).await
    }

    /// Like [`Self::extract_for_sbom`], reporting the chunks extracted to `progress`.
    #[instrument(skip(self, progress, tx), err(level = tracing::Level::INFO))]
    pub async fn extract_for_sbom_reporting(
        &self,
        sbom_id: Uuid,
        progress: &dyn ExtractionProgress,
        tx: &DatabaseTransaction,
    ) -> Result<usize, Error> {
        lock_revision(tx).await?;
        lock_sboms(tx, vec![sbom_id]).await?;
        // the other members of a class have the same evidence as its representative
        let representatives = classify(sbom_id, tx).await?;

        // the chunks of all extractors up front, to know how many there are
        let mut work = Vec::with_capacity(self.extractors.len());
        for extractor in &self.extractors {
            let mut node_identifiers = extractor.sbom_identifiers(sbom_id, None, tx).await?;
            node_identifiers.retain(|id| representatives.contains(&id.node.node_id));
            if !node_identifiers.is_empty() {
                work.push((extractor, node_chunks(node_identifiers, self.chunk)));
            }
        }
        let all_chunks = work.iter().map(|(_, chunks)| chunks.len()).sum();
        progress.chunks_done(0, all_chunks).await;

        let mut total = 0;
        let mut done = 0;
        let mut scoper = Scoper::default();
        for (extractor, chunks) in work {
            let total_chunks = chunks.len();
            let mut count = 0;
            for (index, chunk) in chunks.into_iter().enumerate() {
                count += extract_chunk(
                    extractor.as_ref(),
                    chunk,
                    (index, total_chunks),
                    &mut scoper,
                    self.match_batch,
                    tx,
                )
                .await?;
                done += 1;
                if all_chunks > 1 {
                    tracing::info!(extractor = extractor.id(), %sbom_id, chunk = done, chunks = all_chunks, "extracted chunk of SBOM");
                }
                progress.chunks_done(done, all_chunks).await;
            }

            tracing::info!(extractor = extractor.id(), %sbom_id, evidence_count = count, "extraction for SBOM complete");
            total += count;
        }
        Ok(total)
    }

    /// Match the assertions of an advisory against SBOMs and store evidence.
    ///
    /// Returns the number of evidence entries produced.
    #[instrument(skip(self, tx), err(level = tracing::Level::INFO))]
    pub async fn extract_for_advisory(
        &self,
        advisory_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<usize, Error> {
        lock_revision(tx).await?;
        let mut batches = Vec::new();
        let mut sboms = BTreeSet::new();
        for extractor in &self.extractors {
            let matches = extractor.match_advisory(advisory_id, tx).await?;
            sboms.extend(matches.iter().map(|m| m.node.sbom_id));
            batches.push((extractor.id(), matches));
        }
        lock_sboms(tx, sboms.into_iter().collect()).await?;
        let mut total = 0;
        let mut scoper = Scoper::default();
        // the evidence of the other members of a class is the one of its representative
        let nodes = batches
            .iter()
            .flat_map(|(_, matches)| matches.iter().map(|m| m.node.clone()))
            .collect();
        let members = members(nodes, tx).await?;
        for (extractor_id, matches) in batches {
            let matches = matches
                .into_iter()
                .filter(|m| !members.contains(&m.node))
                .map(|NodeMatch { node, assertion }| (node, Cow::Owned(assertion)))
                .collect::<Vec<_>>();
            if matches.is_empty() {
                continue;
            }

            let matches = retain_in_range(matches, tx).await?;
            let count = write_scoped(matches, &mut scoper, tx).await?;

            tracing::info!(extractor = extractor_id, %advisory_id, evidence_count = count, "extraction for advisory complete");
            total += count;
        }
        Ok(total)
    }

    /// Identifiers of an SBOM's nodes, keyed by node ID, sorted by kind and value.
    ///
    /// `None` selects all nodes; `Some(nodes)` restricts the lookup to those node IDs.
    /// An empty node list selects no identifiers.
    pub async fn component_identifiers(
        &self,
        sbom_id: Uuid,
        nodes: Option<&[&str]>,
        tx: &DatabaseTransaction,
    ) -> Result<HashMap<String, Vec<IdentifierRef>>, Error> {
        let mut result = HashMap::<_, Vec<_>>::new();
        for extractor in &self.extractors {
            for n in extractor.sbom_identifiers(sbom_id, nodes, tx).await? {
                result.entry(n.node.node_id).or_default().push(n.identifier);
            }
        }
        for identifiers in result.values_mut() {
            identifiers.sort_by(|a, b| (a.kind, &a.value).cmp(&(b.kind, &b.value)));
        }
        Ok(result)
    }

    /// Match a single identifier against advisories, using all extractors.
    ///
    /// Extractors ignore identifiers of kinds they don't handle, so only the
    /// extractor responsible for the identifier's kind contributes matches.
    pub async fn query(
        &self,
        identifier: &IdentifierRef,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<Assertion>, Error> {
        self.query_with_context(identifier, &[], tx).await
    }

    /// Queries ad-hoc identifiers, treating explicitly supplied CPEs as component-local.
    pub async fn query_with_context(
        &self,
        identifier: &IdentifierRef,
        context_identifiers: &[IdentifierRef],
        tx: &DatabaseTransaction,
    ) -> Result<Vec<Assertion>, Error> {
        use sea_orm::TryIntoModel;
        use trustify_entity::correlation_evidence_context::ContextSource;
        let mut node = Vec::new();
        for item in context_identifiers {
            match item.kind {
                crate::model::IdentifierKind::Cpe => {
                    let cpe = item
                        .value
                        .parse::<trustify_common::cpe::Cpe>()
                        .map_err(|e| Error::BadRequest(format!("Invalid context CPE: {e}")))?;
                    node.push(NodeCpe {
                        cpe: trustify_entity::cpe::ActiveModel::from(cpe).try_into_model()?,
                        source: ContextSource::Node,
                        distance: 0,
                    });
                }
                crate::model::IdentifierKind::Purl => {
                    let purl = item
                        .value
                        .parse::<trustify_common::purl::Purl>()
                        .map_err(|e| Error::BadRequest(format!("Invalid context PURL: {e}")))?;
                    if let Some((cpe, source)) = context::rpm::rpm_context(&purl) {
                        node.push(NodeCpe {
                            cpe,
                            source,
                            distance: 0,
                        });
                    }
                }
                _ => {
                    return Err(Error::BadRequest(
                        "Product context accepts CPEs and PURLs".into(),
                    ));
                }
            }
        }
        self.query_scoped(
            identifier,
            (!context_identifiers.is_empty()).then_some(node.as_slice()),
            tx,
        )
        .await
    }

    /// Queries with original SBOM CPE sources/distances, including an empty known node context.
    pub async fn query_with_node_context(
        &self,
        identifier: &IdentifierRef,
        node_cpes: &[NodeCpe],
        tx: &DatabaseTransaction,
    ) -> Result<Vec<Assertion>, Error> {
        self.query_scoped(identifier, Some(node_cpes), tx).await
    }

    /// Shares matching while distinguishing context-free queries from known node context.
    async fn query_scoped(
        &self,
        identifier: &IdentifierRef,
        node: Option<&[NodeCpe]>,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<Assertion>, Error> {
        let mut assertions = Vec::new();
        for extractor in &self.extractors {
            assertions.extend(
                extractor
                    .match_identifiers(slice::from_ref(&vec![identifier.clone()]), tx)
                    .await?
                    .into_iter()
                    .map(|m| m.assertion),
            );
        }
        // Preserve the existing context-free query semantics. With supplied context, apply
        // the same compatibility and confidence calculation used during SBOM extraction.
        let contexts =
            context::load_contexts(assertions.iter().filter_map(|a| a.context_id), tx).await?;
        let mut result = Vec::<Assertion>::new();
        for mut assertion in assertions {
            if let Some(node) = node {
                let scope = context::scope(
                    assertion.context_id.and_then(|id| contexts.get(&id)),
                    node,
                    &[],
                    assertion.requires_context,
                );
                if scope == Scope::Dropped {
                    continue;
                }
                if let Some(factor) = scope.factor() {
                    assertion.apply(factor);
                }
            } else if assertion.requires_context {
                continue;
            }
            assertion.context_id = None;
            let sources = std::mem::take(&mut assertion.source_assertions);
            if let Some(existing) = result.iter_mut().find(|existing| {
                let mut value = (*existing).clone();
                value.source_assertions.clear();
                value == assertion
            }) {
                existing.source_assertions.extend(sources);
            } else {
                assertion.source_assertions = sources;
                result.push(assertion);
            }
        }
        Ok(result)
    }
}

/// The default number of identifiers an SBOM is matched with at once.
///
/// Bounds the matches held in memory: a large SBOM matches tens of millions of assertions before
/// scoping, as context-dependent and fallback assertions are only dropped by the [`Scoper`].
const CHUNK: usize = 5_000;

/// Split the identifiers of an SBOM into chunks of about `size` identifiers.
///
/// The identifiers of a node stay in one chunk, as the [`EvidenceWriter`] merges the evidence of
/// a node in memory (its confidence and ranges), and only its source assertions when writing.
/// Nodes are ordered by their identifiers, so a chunk covers few packages, and a package is
/// looked up by few chunks.
fn node_chunks(identifiers: Vec<NodeIdentifier>, size: usize) -> Vec<Vec<NodeIdentifier>> {
    let mut nodes = BTreeMap::<NodeRef, Vec<NodeIdentifier>>::new();
    for identifier in identifiers {
        nodes
            .entry(identifier.node.clone())
            .or_default()
            .push(identifier);
    }
    let mut nodes = nodes.into_values().collect::<Vec<_>>();
    for node in &mut nodes {
        node.sort_by(|a, b| a.identifier.value.cmp(&b.identifier.value));
    }
    fn first(node: &[NodeIdentifier]) -> Option<&str> {
        node.first().map(|i| i.identifier.value.as_str())
    }
    nodes.sort_by(|a, b| first(a).cmp(&first(b)));

    let mut chunks = Vec::new();
    let mut chunk = Vec::new();
    for node in nodes {
        chunk.extend(node);
        if chunk.len() >= size {
            chunks.push(take(&mut chunk));
        }
    }
    if !chunk.is_empty() {
        chunks.push(chunk);
    }
    chunks
}

/// Match one chunk of an SBOM's identifiers, and write the evidence in range and scope.
///
/// The matches are written whenever about `match_batch` are held, after all matches of a node.
/// Returns the number of evidence entries written.
#[instrument(
    skip_all,
    fields(
        extractor = extractor.id(),
        chunk = position.0,
        chunks = position.1,
        identifiers = chunk.len(),
        matches = field::Empty,
        in_range = field::Empty,
        evidence = field::Empty,
        writes = field::Empty,
    ),
    err(level = tracing::Level::INFO)
)]
async fn extract_chunk(
    extractor: &dyn Extractor,
    chunk: Vec<NodeIdentifier>,
    position: (usize, usize),
    scoper: &mut Scoper,
    match_batch: usize,
    tx: &DatabaseTransaction,
) -> Result<usize, Error> {
    let span = Span::current();
    // the identifiers of a node are next to each other, see `node_chunks`
    let mut nodes = Vec::<NodeRef>::new();
    let mut components = Vec::<Vec<IdentifierRef>>::new();
    for NodeIdentifier { node, identifier } in chunk {
        match (nodes.last(), components.last_mut()) {
            (Some(last), Some(identifiers)) if *last == node => identifiers.push(identifier),
            _ => {
                nodes.push(node);
                components.push(vec![identifier]);
            }
        }
    }
    let mut writer = StreamWriter::new(&nodes, scoper, match_batch, tx);
    extractor.match_parts(&components, &mut writer, tx).await?;
    writer.flush().await?;

    span.record("matches", writer.matches);
    span.record("in_range", writer.in_range);
    span.record("evidence", writer.evidence);
    span.record("writes", writer.writes);
    Ok(writer.evidence)
}

/// Writes the evidence of matches handed over in parts, whenever about `match_batch` are held,
/// and only after all matches of a node.
struct StreamWriter<'a> {
    nodes: &'a [NodeRef],
    scoper: &'a mut Scoper,
    match_batch: usize,
    tx: &'a DatabaseTransaction,
    /// The matches not written yet, of complete nodes only: a node (index) and the assertions of
    /// its part, shared by the nodes of the part instead of a copy each.
    pending: Vec<(usize, Arc<[Assertion]>)>,
    /// The number of pending matches.
    held: usize,
    matches: usize,
    in_range: usize,
    evidence: usize,
    writes: usize,
}

impl<'a> StreamWriter<'a> {
    fn new(
        nodes: &'a [NodeRef],
        scoper: &'a mut Scoper,
        match_batch: usize,
        tx: &'a DatabaseTransaction,
    ) -> Self {
        Self {
            nodes,
            scoper,
            match_batch,
            tx,
            pending: Vec::new(),
            held: 0,
            matches: 0,
            in_range: 0,
            evidence: 0,
            writes: 0,
        }
    }

    /// Write the evidence of the pending matches, and forget what was loaded for their nodes.
    async fn flush(&mut self) -> Result<(), Error> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let pending = take(&mut self.pending);
        self.held = 0;
        let nodes = self.nodes;
        // borrowed: only the matches in scope are copied, into the evidence
        let matches = pending
            .iter()
            .filter_map(|(node, assertions)| Some((nodes.get(*node)?, assertions)))
            .flat_map(|(node, assertions)| {
                assertions
                    .iter()
                    .map(move |assertion| (node, Cow::Borrowed(assertion)))
            })
            .collect::<Vec<_>>();
        let matches = retain_in_range(matches, self.tx).await?;
        self.in_range += matches.len();
        self.evidence += write_scoped(matches, self.scoper, self.tx).await?;
        self.writes += 1;
        // the matches of a node are complete, so what's loaded for it isn't needed again
        self.scoper.forget_nodes();
        Ok(())
    }
}

#[async_trait::async_trait]
impl MatchSink for StreamWriter<'_> {
    async fn accept(&mut self, part: MatchPart) -> Result<(), Error> {
        let assertions = Arc::<[Assertion]>::from(part.assertions);
        // a part has all matches of its components: write after any of them, not within one
        for component in part.components {
            if component >= self.nodes.len() {
                continue;
            }
            self.pending.push((component, assertions.clone()));
            self.held += assertions.len();
            self.matches += assertions.len();
            if self.held >= self.match_batch {
                self.flush().await?;
            }
        }
        Ok(())
    }
}

/// Scope matches by their contexts, and write the evidence of the remaining ones.
///
/// Returns the number of evidence entries written.
/// The assertions can be borrowed: only the ones in scope are copied.
async fn write_scoped<N: Borrow<NodeRef>>(
    matches: Vec<(N, Cow<'_, Assertion>)>,
    scoper: &mut Scoper,
    tx: &DatabaseTransaction,
) -> Result<usize, Error> {
    scoper
        .prepare(
            matches
                .iter()
                .map(|(node, assertion)| (node.borrow(), assertion.as_ref())),
            tx,
        )
        .await?;

    let mut writer = EvidenceWriter::new();
    for (node, assertion) in matches {
        let node = node.borrow();
        let scope = scoper.scope(node, &assertion);
        if matches!(scope, Scope::Dropped) {
            continue;
        }
        let mut assertion = assertion.into_owned();
        if let Some(factor) = scope.factor() {
            assertion.apply(factor);
        }
        match scope {
            Scope::Dropped => {}
            Scope::Unscoped { .. } => writer.add(node, assertion)?,
            Scope::Matched { links, .. } => writer.add_in_context(node, assertion, links)?,
            Scope::Unconfirmed { link, .. } => {
                writer.add_in_context(node, assertion, vec![link])?
            }
        }
    }
    writer.write(tx).await
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::model::{IdentifierKind, MatchedRange, MatchedValue};
    use sea_orm::{FromQueryResult, TransactionTrait};
    use test_context::test_context;
    use trustify_common::db::sql;
    use trustify_test_context::TrustifyContext;

    fn identifier(node: &str, value: &str) -> NodeIdentifier {
        NodeIdentifier {
            node: NodeRef {
                sbom_id: Uuid::nil(),
                node_id: node.into(),
            },
            identifier: IdentifierRef {
                kind: IdentifierKind::Purl,
                value: value.into(),
            },
        }
    }

    /// A node's identifiers stay together, and nodes are ordered by their identifiers.
    #[test]
    fn chunks_keep_nodes_together() {
        let chunks = node_chunks(
            vec![
                identifier("a", "pkg:rpm/redhat/zlib@1"),
                identifier("b", "pkg:rpm/redhat/kernel@2"),
                identifier("a", "pkg:rpm/redhat/zlib@1?arch=x86_64"),
                identifier("c", "pkg:rpm/redhat/kernel@1"),
                identifier("b", "pkg:rpm/redhat/kernel@2?arch=x86_64"),
            ],
            2,
        );
        assert_eq!(
            chunks,
            vec![
                vec![
                    identifier("c", "pkg:rpm/redhat/kernel@1"),
                    identifier("b", "pkg:rpm/redhat/kernel@2"),
                    identifier("b", "pkg:rpm/redhat/kernel@2?arch=x86_64"),
                ],
                vec![
                    identifier("a", "pkg:rpm/redhat/zlib@1"),
                    identifier("a", "pkg:rpm/redhat/zlib@1?arch=x86_64"),
                ],
            ]
        );
    }

    /// A row of evidence, as written.
    #[derive(Debug, PartialEq, FromQueryResult)]
    struct EvidenceRow {
        node_id: String,
        confidence: f64,
        matched_value: Option<serde_json::Value>,
    }

    /// The evidence of an SBOM, as written.
    async fn evidence(sbom_id: Uuid, tx: &DatabaseTransaction) -> anyhow::Result<Vec<EvidenceRow>> {
        Ok(EvidenceRow::find_by_statement(sql(
            "SELECT node_id, confidence, matched_value FROM correlation_evidence WHERE sbom_id = $1 ORDER BY id",
            vec![sbom_id.into()],
        ))
        .all(tx)
        .await?)
    }

    /// The matches of a node are written together, also when they exceed the batch: two matches
    /// of the same evidence are merged (all of their ranges) before writing, which writing them
    /// one by one would lose.
    #[test_context(TrustifyContext)]
    #[test_log::test(actix_web::test)]
    async fn writes_the_matches_of_a_node_together(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom_id = Uuid::parse_str(
            &ctx.ingest_document(
                "scenarios/S5_positive_baseline_openssl_el8/sbom_openssl_el8_below-fix.cdx.json",
            )
            .await?
            .id,
        )?;
        ctx.ingest_document("scenarios/S5_positive_baseline_openssl_el8/vex/CVE-2023-0215.json.xz")
            .await?;

        let tx = ctx.db.begin().await?;
        // the identifiers of each node, judged together like `extract_chunk` does
        let mut by_node = BTreeMap::<NodeRef, Vec<IdentifierRef>>::new();
        for id in PurlExtractor.sbom_identifiers(sbom_id, None, &tx).await? {
            by_node.entry(id.node).or_default().push(id.identifier);
        }
        let (all_nodes, components): (Vec<_>, Vec<_>) = by_node.into_iter().unzip();
        let matches = PurlExtractor.match_identifiers(&components, &tx).await?;
        // a match in the scope of its node, so its evidence is written
        let mut scoper = Scoper::default();
        scoper
            .prepare(
                matches
                    .iter()
                    .map(|m| (&all_nodes[m.component], &m.assertion)),
                &tx,
            )
            .await?;
        let matched = matches
            .into_iter()
            .find(|m| {
                !matches!(
                    scoper.scope(&all_nodes[m.component], &m.assertion),
                    Scope::Dropped
                )
            })
            .ok_or_else(|| anyhow::anyhow!("no match in scope"))?;
        let nodes = vec![all_nodes[matched.component].clone()];
        // the same evidence, found once more with another range
        let found = matched.assertion.clone();
        let mut again = matched.assertion;
        let other = MatchedRange {
            scheme: "rpm".into(),
            low: None,
            high: None,
        };
        again.matched_value.ranges = vec![other.clone()];
        tx.rollback().await?;

        let mut written = Vec::new();
        for match_batch in [usize::MAX, 1] {
            let tx = ctx.db.begin().await?;
            let mut scoper = Scoper::default();
            let mut writer = StreamWriter::new(&nodes, &mut scoper, match_batch, &tx);
            writer
                .accept(MatchPart {
                    components: vec![0],
                    assertions: vec![found.clone(), again.clone()],
                })
                .await?;
            writer.flush().await?;
            let counts = (
                writer.matches,
                writer.in_range,
                writer.evidence,
                writer.writes,
            );
            written.push((counts, evidence(sbom_id, &tx).await?));
            tx.rollback().await?;
        }

        let [(_, at_once), (counts, batched)] = written.as_slice() else {
            anyhow::bail!("two runs");
        };
        assert_eq!((*counts, batched), ((2, 2, 1, 1), at_once));
        let mut ranges = found.matched_value.ranges;
        ranges.push(other);
        ranges.sort();
        assert_eq!(
            at_once
                .iter()
                .map(|e| {
                    e.matched_value
                        .clone()
                        .map(serde_json::from_value::<MatchedValue>)
                        .transpose()
                        .map(|value| value.map(|value| value.ranges))
                })
                .collect::<Result<Vec<_>, _>>()?,
            vec![Some(ranges)]
        );
        Ok(())
    }
}

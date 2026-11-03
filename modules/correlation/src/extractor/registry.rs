use super::{
    Assertion, Extractor, IdentifierMatch, NodeIdentifier, NodeMatch, NodeRef,
    context::{Scope, Scoper},
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
    service::freshness::{lock_revision, lock_sboms},
};
use sea_orm::DatabaseTransaction;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    mem::take,
    slice,
};
use tracing::{Span, field, instrument};
use uuid::Uuid;

/// The set of active extractors.
pub struct Extractors {
    extractors: Vec<Box<dyn Extractor>>,
    /// The number of identifiers an SBOM is matched with at once.
    chunk: usize,
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
        }
    }

    /// Match SBOMs in chunks of about `chunk` identifiers instead of the default.
    #[cfg(test)]
    pub fn with_chunk(self, chunk: usize) -> Self {
        Self { chunk, ..self }
    }

    /// Match the identifiers of an SBOM against advisories and store evidence.
    ///
    /// Returns the number of evidence entries produced.
    #[instrument(skip(self, tx), err(level = tracing::Level::INFO))]
    pub async fn extract_for_sbom(
        &self,
        sbom_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<usize, Error> {
        lock_revision(tx).await?;
        lock_sboms(tx, vec![sbom_id]).await?;
        let mut total = 0;
        let mut scoper = Scoper::default();
        for extractor in &self.extractors {
            let node_identifiers = extractor.sbom_identifiers(sbom_id, None, tx).await?;
            if node_identifiers.is_empty() {
                continue;
            }

            let chunks = node_chunks(node_identifiers, self.chunk);
            let total_chunks = chunks.len();
            let mut count = 0;
            for (index, chunk) in chunks.into_iter().enumerate() {
                count += extract_chunk(
                    extractor.as_ref(),
                    chunk,
                    (index, total_chunks),
                    &mut scoper,
                    tx,
                )
                .await?;
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
        for (extractor_id, matches) in batches {
            if matches.is_empty() {
                continue;
            }

            let matches = matches
                .into_iter()
                .map(|NodeMatch { node, assertion }| (node, assertion))
                .collect::<Vec<_>>();
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

    pub async fn query_with_context(
        &self,
        identifier: &IdentifierRef,
        context_identifiers: &[IdentifierRef],
        tx: &DatabaseTransaction,
    ) -> Result<Vec<Assertion>, Error> {
        use super::context::{self, NodeCpe};
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
        let mut assertions = Vec::new();
        for extractor in &self.extractors {
            assertions.extend(
                extractor
                    .match_identifiers(slice::from_ref(identifier), tx)
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
            if context_identifiers.is_empty() {
                if assertion.requires_context {
                    continue;
                }
            } else {
                let scope = context::scope(
                    assertion.context_id.and_then(|id| contexts.get(&id)),
                    &node,
                    &[],
                    assertion.requires_context,
                );
                if scope == Scope::Dropped {
                    continue;
                }
                if let Some(factor) = scope.factor() {
                    assertion.apply(factor);
                }
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
    ),
    err(level = tracing::Level::INFO)
)]
async fn extract_chunk(
    extractor: &dyn Extractor,
    chunk: Vec<NodeIdentifier>,
    position: (usize, usize),
    scoper: &mut Scoper,
    tx: &DatabaseTransaction,
) -> Result<usize, Error> {
    let span = Span::current();
    let identifiers = chunk
        .iter()
        .map(|n| n.identifier.clone())
        .collect::<Vec<_>>();
    let matches = extractor
        .match_identifiers(&identifiers, tx)
        .await?
        .into_iter()
        .filter_map(|IdentifierMatch { index, assertion }| {
            chunk.get(index).map(|node| (node.node.clone(), assertion))
        })
        .collect::<Vec<_>>();
    span.record("matches", matches.len());

    let matches = retain_in_range(matches, tx).await?;
    span.record("in_range", matches.len());

    let count = write_scoped(matches, scoper, tx).await?;
    span.record("evidence", count);
    Ok(count)
}

/// Scope matches by their contexts, and write the evidence of the remaining ones.
///
/// Returns the number of evidence entries written.
async fn write_scoped(
    matches: Vec<(NodeRef, Assertion)>,
    scoper: &mut Scoper,
    tx: &DatabaseTransaction,
) -> Result<usize, Error> {
    scoper
        .prepare(
            matches.iter().map(|(node, assertion)| (node, assertion)),
            tx,
        )
        .await?;

    let mut writer = EvidenceWriter::new();
    for (node, mut assertion) in matches {
        let scope = scoper.scope(&node, &assertion);
        if let Some(factor) = scope.factor() {
            assertion.apply(factor);
        }
        match scope {
            Scope::Dropped => {}
            Scope::Unscoped { .. } => writer.add(&node, assertion)?,
            Scope::Matched { links, .. } => writer.add_in_context(&node, assertion, links)?,
            Scope::Unconfirmed { link, .. } => {
                writer.add_in_context(&node, assertion, vec![link])?
            }
        }
    }
    writer.write(tx).await
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::model::IdentifierKind;

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
}

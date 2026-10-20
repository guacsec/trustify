use super::{
    Assertion, Extractor, IdentifierMatch, NodeMatch, NodeRef,
    context::{Scope, Scoper},
    cpe::CpeExtractor,
    digest::DigestExtractor,
    product_identifier::ProductIdentifierExtractor,
    purl::PurlExtractor,
    version::retain_in_range,
    writer::EvidenceWriter,
};
use crate::{error::Error, model::IdentifierRef};
use sea_orm::DatabaseTransaction;
use std::{
    collections::{BTreeSet, HashMap},
    slice,
};
use tracing::instrument;
use uuid::Uuid;

/// The set of active extractors.
pub struct Extractors(Vec<Box<dyn Extractor>>);

impl Default for Extractors {
    /// All known extractors. This is the single place to register a new one.
    fn default() -> Self {
        Self(vec![
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
        Self(extractors)
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
        crate::service::freshness::lock_revision(tx).await?;
        crate::service::freshness::lock_sboms(tx, vec![sbom_id]).await?;
        let mut total = 0;
        let mut scoper = Scoper::default();
        for extractor in &self.0 {
            let node_identifiers = extractor.sbom_identifiers(sbom_id, tx).await?;
            if node_identifiers.is_empty() {
                continue;
            }

            let identifiers = node_identifiers
                .iter()
                .map(|n| n.identifier.clone())
                .collect::<Vec<_>>();
            let matches = extractor
                .match_identifiers(&identifiers, tx)
                .await?
                .into_iter()
                .filter_map(|IdentifierMatch { index, assertion }| {
                    node_identifiers
                        .get(index)
                        .map(|node| (node.node.clone(), assertion))
                })
                .collect::<Vec<_>>();
            let matches = retain_in_range(matches, tx).await?;

            let count = write_scoped(matches, &mut scoper, tx).await?;

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
        crate::service::freshness::lock_revision(tx).await?;
        let mut batches = Vec::new();
        let mut sboms = BTreeSet::new();
        for extractor in &self.0 {
            let matches = extractor.match_advisory(advisory_id, tx).await?;
            sboms.extend(matches.iter().map(|m| m.node.sbom_id));
            batches.push((extractor.id(), matches));
        }
        crate::service::freshness::lock_sboms(tx, sboms.into_iter().collect()).await?;
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

    /// All identifiers of all nodes of an SBOM, keyed by node ID, sorted by kind and value.
    pub async fn component_identifiers(
        &self,
        sbom_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<HashMap<String, Vec<IdentifierRef>>, Error> {
        let mut result = HashMap::<_, Vec<_>>::new();
        for extractor in &self.0 {
            for n in extractor.sbom_identifiers(sbom_id, tx).await? {
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
        for extractor in &self.0 {
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
            if !result.contains(&assertion) {
                result.push(assertion);
            }
        }
        Ok(result)
    }
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

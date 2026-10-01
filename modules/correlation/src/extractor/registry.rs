use super::{
    Assertion, Extractor, IdentifierMatch, NodeMatch, cpe::CpeExtractor, digest::DigestExtractor,
    product_identifier::ProductIdentifierExtractor, purl::PurlExtractor, writer::EvidenceWriter,
};
use crate::{error::Error, model::IdentifierRef};
use sea_orm::DatabaseTransaction;
use std::collections::HashMap;
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
    ) -> Result<u64, Error> {
        let mut total = 0;
        for extractor in &self.0 {
            let node_identifiers = extractor.sbom_identifiers(sbom_id, tx).await?;
            if node_identifiers.is_empty() {
                continue;
            }

            let identifiers = node_identifiers
                .iter()
                .map(|n| n.identifier.clone())
                .collect::<Vec<_>>();
            let matches = extractor.match_identifiers(&identifiers, tx).await?;

            let mut writer = EvidenceWriter::new(extractor.id());
            for IdentifierMatch { index, assertion } in matches {
                if let Some(node) = node_identifiers.get(index) {
                    writer.add(&node.node, assertion);
                }
            }
            let count = writer.write(tx).await?;

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
    ) -> Result<u64, Error> {
        let mut total = 0;
        for extractor in &self.0 {
            let matches = extractor.match_advisory(advisory_id, tx).await?;
            if matches.is_empty() {
                continue;
            }

            let mut writer = EvidenceWriter::new(extractor.id());
            for NodeMatch { node, assertion } in matches {
                writer.add(&node, assertion);
            }
            let count = writer.write(tx).await?;

            tracing::info!(extractor = extractor.id(), %advisory_id, evidence_count = count, "extraction for advisory complete");
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

    /// Match a free-text query against advisories, using all extractors.
    pub async fn query(
        &self,
        query: &str,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<(IdentifierRef, Assertion)>, Error> {
        let mut result = Vec::new();
        for extractor in &self.0 {
            let identifiers = extractor.parse_query(query);
            if identifiers.is_empty() {
                continue;
            }
            for IdentifierMatch { index, assertion } in
                extractor.match_identifiers(&identifiers, tx).await?
            {
                if let Some(identifier) = identifiers.get(index) {
                    result.push((identifier.clone(), assertion));
                }
            }
        }
        Ok(result)
    }
}

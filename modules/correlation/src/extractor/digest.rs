//! Correlation by digest: `sbom_node_checksum` ↔ `advisory_vulnerability_hash`.

use super::{Assertion, Extractor, IdentifierMatch, NodeIdentifier, NodeMatch, NodeRef};
use crate::{
    error::Error,
    model::{IdentifierKind, IdentifierRef},
};
use sea_orm::{ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryFilter};
use std::collections::HashMap;
use tracing::{Instrument, info_span, instrument};
use trustify_common::hashing::normalize_algorithm;
use trustify_entity::{advisory_vulnerability_hash, sbom_node_checksum};
use uuid::Uuid;

/// Extracts correlation evidence by matching checksums/digests.
///
/// Identifier values use the format `<algorithm>:<value>`, with a normalized algorithm.
/// A value without an algorithm (only possible from a query) matches any algorithm.
pub struct DigestExtractor;

const CONFIDENCE: f64 = 1.0;

fn format_digest(algorithm: &str, value: &str) -> String {
    format!("{algorithm}:{value}")
}

/// Split a digest identifier into an optional (normalized) algorithm and the value.
fn parse_digest(value: &str) -> (Option<String>, &str) {
    match value.split_once(':') {
        Some((algorithm, value)) => (Some(normalize_algorithm(algorithm)), value),
        None => (None, value),
    }
}

#[async_trait::async_trait]
impl Extractor for DigestExtractor {
    fn id(&self) -> &'static str {
        "digest"
    }

    #[instrument(skip(self, tx), err(level = tracing::Level::INFO))]
    async fn sbom_identifiers(
        &self,
        sbom_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeIdentifier>, Error> {
        let checksums = sbom_node_checksum::Entity::find()
            .filter(sbom_node_checksum::Column::SbomId.eq(sbom_id))
            .all(tx)
            .await?;

        Ok(checksums
            .into_iter()
            .map(|cs| NodeIdentifier {
                identifier: IdentifierRef {
                    kind: IdentifierKind::Digest,
                    value: format_digest(&normalize_algorithm(&cs.r#type), &cs.value),
                },
                node: NodeRef {
                    sbom_id: cs.sbom_id,
                    node_id: cs.node_id,
                },
            })
            .collect())
    }

    /// Look up advisory hashes by digest value.
    ///
    /// Indexes the digest identifiers by their hash value (one value may occur for several
    /// identifiers), then loads all `advisory_vulnerability_hash` rows having one of those values,
    /// in chunks. A row matches an identifier if the algorithms are equal, or if the identifier
    /// has no algorithm (a query by bare value). Algorithms are normalized on both sides, so e.g.
    /// `SHA-256` and `sha256` are the same.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    async fn match_identifiers(
        &self,
        identifiers: &[IdentifierRef],
        tx: &DatabaseTransaction,
    ) -> Result<Vec<IdentifierMatch>, Error> {
        // hash value -> [(index, algorithm)]
        let mut value_map = HashMap::<&str, Vec<(usize, Option<String>)>>::new();
        for (idx, identifier) in identifiers.iter().enumerate() {
            if identifier.kind != IdentifierKind::Digest {
                continue;
            }
            let (algorithm, value) = parse_digest(&identifier.value);
            value_map.entry(value).or_default().push((idx, algorithm));
        }

        if value_map.is_empty() {
            return Ok(Vec::new());
        }

        let values = value_map.keys().copied().collect::<Vec<_>>();
        let advisory_hashes = load_advisory_hashes_by_values(&values, tx).await?;

        let mut result = Vec::new();
        for ah in advisory_hashes {
            let Some(entries) = value_map.get(ah.value.as_str()) else {
                continue;
            };
            for (idx, algorithm) in entries {
                if algorithm.as_ref().is_none_or(|a| *a == ah.algorithm) {
                    result.push(IdentifierMatch {
                        index: *idx,
                        assertion: Assertion {
                            advisory_id: ah.advisory_id,
                            vulnerability_id: ah.vulnerability_id.clone(),
                            status: ah.status,
                            confidence: CONFIDENCE,
                            matched_value: format_digest(&ah.algorithm, &ah.value),
                        },
                    });
                }
            }
        }

        Ok(result)
    }

    /// Look up SBOM checksums by the digests of an advisory.
    ///
    /// Loads the advisory's hashes, then all `sbom_node_checksum` rows having one of their values,
    /// in chunks. A checksum matches when its normalized algorithm equals the hash's algorithm.
    #[instrument(skip(self, tx), err(level = tracing::Level::INFO))]
    async fn match_advisory(
        &self,
        advisory_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeMatch>, Error> {
        let advisory_hashes = advisory_vulnerability_hash::Entity::find()
            .filter(advisory_vulnerability_hash::Column::AdvisoryId.eq(advisory_id))
            .all(tx)
            .instrument(info_span!("loading advisory hashes"))
            .await?;

        if advisory_hashes.is_empty() {
            return Ok(Vec::new());
        }

        let mut value_map = HashMap::<&str, Vec<&advisory_vulnerability_hash::Model>>::new();
        for ah in &advisory_hashes {
            value_map.entry(ah.value.as_str()).or_default().push(ah);
        }

        let values = value_map.keys().copied().collect::<Vec<_>>();
        let checksums = load_checksums_by_values(&values, tx).await?;

        let mut result = Vec::new();
        for cs in checksums {
            let Some(entries) = value_map.get(cs.value.as_str()) else {
                continue;
            };
            let algorithm = normalize_algorithm(&cs.r#type);
            for ah in entries {
                if algorithm == ah.algorithm {
                    result.push(NodeMatch {
                        node: NodeRef {
                            sbom_id: cs.sbom_id,
                            node_id: cs.node_id.clone(),
                        },
                        assertion: Assertion {
                            advisory_id,
                            vulnerability_id: ah.vulnerability_id.clone(),
                            status: ah.status,
                            confidence: CONFIDENCE,
                            matched_value: format_digest(&ah.algorithm, &ah.value),
                        },
                    });
                }
            }
        }

        Ok(result)
    }
}

/// Load advisory_vulnerability_hash rows matching any of the given hash values.
async fn load_advisory_hashes_by_values(
    values: &[&str],
    connection: &impl ConnectionTrait,
) -> Result<Vec<advisory_vulnerability_hash::Model>, Error> {
    let mut results = Vec::new();
    for chunk in values.chunks(5000) {
        let rows = advisory_vulnerability_hash::Entity::find()
            .filter(advisory_vulnerability_hash::Column::Value.is_in(chunk.iter().copied()))
            .all(connection)
            .instrument(info_span!("loading advisory hashes by value"))
            .await?;
        results.extend(rows);
    }
    Ok(results)
}

/// Load sbom_node_checksum rows matching any of the given hash values.
async fn load_checksums_by_values(
    values: &[&str],
    connection: &impl ConnectionTrait,
) -> Result<Vec<sbom_node_checksum::Model>, Error> {
    let mut results = Vec::new();
    for chunk in values.chunks(5000) {
        let rows = sbom_node_checksum::Entity::find()
            .filter(sbom_node_checksum::Column::Value.is_in(chunk.iter().copied()))
            .all(connection)
            .instrument(info_span!("loading checksums by value"))
            .await?;
        results.extend(rows);
    }
    Ok(results)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::extractor::Extractors;
    use sea_orm::TransactionTrait;
    use test_context::test_context;
    use test_log::test;
    use trustify_entity::correlation_evidence;
    use trustify_test_context::TrustifyContext;

    /// Both directions must find matches and produce the same evidence rows.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn extract_both_directions(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document("scenarios/S18_digest_correlation/sbom/libcrypto.cdx.json")
            .await?;
        let advisory = ctx
            .ingest_document("scenarios/S18_digest_correlation/vex/vde-2025-106.json")
            .await?;
        let sbom_id = Uuid::parse_str(&sbom.id)?;
        let advisory_id = Uuid::parse_str(&advisory.id)?;

        let extractors = Extractors::new(vec![Box::new(DigestExtractor)]);
        let load = || async {
            let mut ids = correlation_evidence::Entity::find()
                .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
                .filter(correlation_evidence::Column::Extractor.eq("digest"))
                .all(&ctx.db)
                .await?
                .into_iter()
                .map(|e| e.id)
                .collect::<Vec<_>>();
            ids.sort();
            Ok::<_, anyhow::Error>(ids)
        };

        let tx = ctx.db.begin().await?;
        assert!(extractors.extract_for_sbom(sbom_id, &tx).await? > 0);
        tx.commit().await?;
        let from_sbom = load().await?;
        assert!(!from_sbom.is_empty());

        let tx = ctx.db.begin().await?;
        assert!(extractors.extract_for_advisory(advisory_id, &tx).await? > 0);
        tx.commit().await?;
        assert_eq!(from_sbom, load().await?);

        Ok(())
    }

    #[test]
    fn parse_with_algorithm() {
        let (algorithm, value) = parse_digest("SHA-256:abc");
        assert_eq!(algorithm, Some(normalize_algorithm("SHA-256")));
        assert_eq!(value, "abc");
    }

    #[test]
    fn parse_without_algorithm() {
        assert_eq!(parse_digest("abc"), (None, "abc"));
    }
}

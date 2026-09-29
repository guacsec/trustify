use crate::{error::Error, evidence::load_advisory_hashes_by_values};
use sea_orm::{ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use std::collections::HashMap;
use tracing::{Instrument, info_span, instrument};
use trustify_common::{db::chunk::EntityChunkedIter, hashing::normalize_algorithm};
use trustify_entity::{
    advisory_vulnerability_hash, correlation_evidence,
    correlation_evidence::{AssertionStatus, MatchDimension},
    sbom_node_checksum,
};
use uuid::Uuid;

const EXTRACTOR_ID: &str = "digest";
const DIGEST_NAMESPACE: Uuid = Uuid::from_bytes([
    0xd1, 0x9e, 0x57, 0xa3, 0x2b, 0x4c, 0x6d, 0x8e, 0x9f, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06,
]);

/// Generates a deterministic UUID for a correlation evidence row.
fn evidence_uuid(
    sbom_id: Uuid,
    node_id: &str,
    advisory_id: Uuid,
    vulnerability_id: &str,
    dimension: MatchDimension,
) -> Uuid {
    let mut id = Uuid::new_v5(&DIGEST_NAMESPACE, sbom_id.as_bytes());
    id = Uuid::new_v5(&id, node_id.as_bytes());
    id = Uuid::new_v5(&id, advisory_id.as_bytes());
    id = Uuid::new_v5(&id, vulnerability_id.as_bytes());
    id = Uuid::new_v5(&id, format!("{dimension:?}").as_bytes());
    id
}

/// Extracts correlation evidence by matching checksums/digests.
pub struct DigestExtractor;

impl DigestExtractor {
    /// Match SBOM component checksums against advisory hashes and insert evidence.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn extract_for_sbom<C: ConnectionTrait>(
        sbom_id: Uuid,
        connection: &C,
    ) -> Result<u64, Error> {
        let checksums = sbom_node_checksum::Entity::find()
            .filter(sbom_node_checksum::Column::SbomId.eq(sbom_id))
            .all(connection)
            .instrument(info_span!("loading sbom checksums"))
            .await?;

        if checksums.is_empty() {
            return Ok(0);
        }

        // Map hash_value -> Vec<(node_id, normalized_algorithm)>
        let mut value_map: HashMap<&str, Vec<(&str, String)>> = HashMap::new();
        for cs in &checksums {
            let normalized = normalize_algorithm(&cs.r#type);
            value_map
                .entry(cs.value.as_str())
                .or_default()
                .push((cs.node_id.as_str(), normalized));
        }

        let unique_values: Vec<&str> = value_map.keys().copied().collect();

        let advisory_hashes = load_advisory_hashes_by_values(&unique_values, connection).await?;

        let mut models = Vec::new();
        for ah in &advisory_hashes {
            if let Some(entries) = value_map.get(ah.value.as_str()) {
                for (node_id, normalized_algo) in entries {
                    if *normalized_algo == ah.algorithm {
                        let id = evidence_uuid(
                            sbom_id,
                            node_id,
                            ah.advisory_id,
                            &ah.vulnerability_id,
                            MatchDimension::Digest,
                        );
                        models.push(correlation_evidence::ActiveModel {
                            id: Set(id),
                            sbom_id: Set(sbom_id),
                            node_id: Set(node_id.to_string()),
                            advisory_id: Set(ah.advisory_id),
                            vulnerability_id: Set(ah.vulnerability_id.clone()),
                            status: Set(ah.status),
                            match_dimension: Set(MatchDimension::Digest),
                            confidence: Set(1.0),
                            extractor: Set(EXTRACTOR_ID.to_string()),
                            created_at: Set(time::OffsetDateTime::now_utc()),
                        });
                    }
                }
            }
        }

        let count = models.len() as u64;

        models.sort_by_key(|m| *m.id.as_ref());

        for batch in &models.chunked() {
            correlation_evidence::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .instrument(info_span!("inserting evidence"))
                .await?;
        }

        tracing::info!(sbom_id = %sbom_id, evidence_count = count, "digest extraction for SBOM complete");
        Ok(count)
    }

    /// Match advisory hashes against all SBOM checksums and insert evidence.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn extract_for_advisory<C: ConnectionTrait>(
        advisory_id: Uuid,
        connection: &C,
    ) -> Result<u64, Error> {
        let advisory_hashes = advisory_vulnerability_hash::Entity::find()
            .filter(advisory_vulnerability_hash::Column::AdvisoryId.eq(advisory_id))
            .all(connection)
            .instrument(info_span!("loading advisory hashes"))
            .await?;

        if advisory_hashes.is_empty() {
            return Ok(0);
        }

        // Map hash_value -> Vec<(vulnerability_id, algorithm, status)>
        let mut value_map: HashMap<&str, Vec<(&str, &str, AssertionStatus)>> = HashMap::new();
        for ah in &advisory_hashes {
            value_map.entry(ah.value.as_str()).or_default().push((
                ah.vulnerability_id.as_str(),
                ah.algorithm.as_str(),
                ah.status,
            ));
        }

        let unique_values: Vec<&str> = value_map.keys().copied().collect();

        let checksums = load_checksums_by_values(unique_values, connection).await?;

        let mut models = Vec::new();
        for cs in &checksums {
            let normalized_algo = normalize_algorithm(&cs.r#type);
            if let Some(entries) = value_map.get(cs.value.as_str()) {
                for (vuln_id, algo, status) in entries {
                    if normalized_algo == *algo {
                        let id = evidence_uuid(
                            cs.sbom_id,
                            &cs.node_id,
                            advisory_id,
                            vuln_id,
                            MatchDimension::Digest,
                        );
                        models.push(correlation_evidence::ActiveModel {
                            id: Set(id),
                            sbom_id: Set(cs.sbom_id),
                            node_id: Set(cs.node_id.clone()),
                            advisory_id: Set(advisory_id),
                            vulnerability_id: Set(vuln_id.to_string()),
                            status: Set(*status),
                            match_dimension: Set(MatchDimension::Digest),
                            confidence: Set(1.0),
                            extractor: Set(EXTRACTOR_ID.to_string()),
                            created_at: Set(time::OffsetDateTime::now_utc()),
                        });
                    }
                }
            }
        }

        let count = models.len() as u64;

        models.sort_by_key(|m| *m.id.as_ref());

        for batch in &models.chunked() {
            correlation_evidence::Entity::insert_many(batch)
                .on_conflict_do_nothing()
                .exec(connection)
                .instrument(info_span!("inserting evidence"))
                .await?;
        }

        tracing::info!(advisory_id = %advisory_id, evidence_count = count, "digest extraction for advisory complete");
        Ok(count)
    }
}

/// Load sbom_node_checksum rows matching any of the given hash values.
async fn load_checksums_by_values<C: ConnectionTrait>(
    values: Vec<&str>,
    connection: &C,
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

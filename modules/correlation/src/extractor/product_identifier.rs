use crate::{
    error::Error,
    evidence::{load_product_identifiers_by_values, load_wildcard_product_identifiers},
    wildcard::{csaf_glob_matches, csaf_glob_to_like, has_wildcards},
};
use sea_orm::{ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use std::collections::HashMap;
use tracing::{Instrument, info_span, instrument};
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::{
    advisory_vulnerability_product_identifier::{self, ProductIdentifierType},
    correlation_evidence,
    correlation_evidence::AssertionStatus,
    sbom_node_product_identifier,
};
use uuid::Uuid;

const EXTRACTOR_ID: &str = "product_identifier";
const PRODUCT_ID_NAMESPACE: Uuid = Uuid::from_bytes([
    0xa2, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x80, 0x91, 0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79,
]);

fn evidence_uuid(sbom_id: Uuid, node_id: &str, advisory_id: Uuid, vulnerability_id: &str) -> Uuid {
    let mut id = Uuid::new_v5(&PRODUCT_ID_NAMESPACE, sbom_id.as_bytes());
    id = Uuid::new_v5(&id, node_id.as_bytes());
    id = Uuid::new_v5(&id, advisory_id.as_bytes());
    id = Uuid::new_v5(&id, vulnerability_id.as_bytes());
    id
}

/// Extracts correlation evidence by matching SBOM product identifiers
/// (SKU, model number, serial number) against advisory product identifiers.
pub struct ProductIdentifierExtractor;

impl ProductIdentifierExtractor {
    /// Match SBOM node product identifiers against advisory product identifiers.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn extract_for_sbom<C: ConnectionTrait>(
        sbom_id: Uuid,
        connection: &C,
    ) -> Result<u64, Error> {
        let sbom_identifiers = sbom_node_product_identifier::Entity::find()
            .filter(sbom_node_product_identifier::Column::SbomId.eq(sbom_id))
            .all(connection)
            .instrument(info_span!("loading sbom product identifiers"))
            .await?;

        if sbom_identifiers.is_empty() {
            return Ok(0);
        }

        let mut value_map: HashMap<&str, Vec<(&str, ProductIdentifierType)>> = HashMap::new();
        for si in &sbom_identifiers {
            value_map
                .entry(si.value.as_str())
                .or_default()
                .push((si.node_id.as_str(), si.identifier_type));
        }

        let unique_values: Vec<&str> = value_map.keys().copied().collect();
        let advisory_pids = load_product_identifiers_by_values(&unique_values, connection).await?;

        let mut models = Vec::new();
        for ap in &advisory_pids {
            if let Some(entries) = value_map.get(ap.value.as_str()) {
                for (node_id, id_type) in entries {
                    if *id_type == ap.identifier_type {
                        let id =
                            evidence_uuid(sbom_id, node_id, ap.advisory_id, &ap.vulnerability_id);
                        models.push(correlation_evidence::ActiveModel {
                            id: Set(id),
                            sbom_id: Set(sbom_id),
                            node_id: Set(node_id.to_string()),
                            advisory_id: Set(ap.advisory_id),
                            vulnerability_id: Set(ap.vulnerability_id.clone()),
                            status: Set(ap.status),
                            confidence: Set(1.0),
                            extractor: Set(EXTRACTOR_ID.to_string()),
                            matched_value: Set(Some(ap.value.clone())),
                            created_at: Set(time::OffsetDateTime::now_utc()),
                        });
                    }
                }
            }
        }

        let wildcard_pids = load_wildcard_product_identifiers(connection).await?;
        for ap in &wildcard_pids {
            for (&sbom_value, entries) in &value_map {
                if csaf_glob_matches(&ap.value, sbom_value) {
                    for (node_id, id_type) in entries {
                        if *id_type == ap.identifier_type {
                            let id = evidence_uuid(
                                sbom_id,
                                node_id,
                                ap.advisory_id,
                                &ap.vulnerability_id,
                            );
                            models.push(correlation_evidence::ActiveModel {
                                id: Set(id),
                                sbom_id: Set(sbom_id),
                                node_id: Set(node_id.to_string()),
                                advisory_id: Set(ap.advisory_id),
                                vulnerability_id: Set(ap.vulnerability_id.clone()),
                                status: Set(ap.status),
                                confidence: Set(1.0),
                                extractor: Set(EXTRACTOR_ID.to_string()),
                                matched_value: Set(Some(ap.value.clone())),
                                created_at: Set(time::OffsetDateTime::now_utc()),
                            });
                        }
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

        tracing::info!(sbom_id = %sbom_id, evidence_count = count, "product identifier extraction for SBOM complete");
        Ok(count)
    }

    /// Match advisory product identifiers against all SBOM node product identifiers.
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    pub async fn extract_for_advisory<C: ConnectionTrait>(
        advisory_id: Uuid,
        connection: &C,
    ) -> Result<u64, Error> {
        let advisory_pids = advisory_vulnerability_product_identifier::Entity::find()
            .filter(advisory_vulnerability_product_identifier::Column::AdvisoryId.eq(advisory_id))
            .all(connection)
            .instrument(info_span!("loading advisory product identifiers"))
            .await?;

        if advisory_pids.is_empty() {
            return Ok(0);
        }

        let mut value_map: HashMap<&str, Vec<(&str, ProductIdentifierType, AssertionStatus)>> =
            HashMap::new();
        for ap in &advisory_pids {
            value_map.entry(ap.value.as_str()).or_default().push((
                ap.vulnerability_id.as_str(),
                ap.identifier_type,
                ap.status,
            ));
        }

        let (exact_values, wildcard_values): (Vec<&str>, Vec<&str>) =
            value_map.keys().copied().partition(|v| !has_wildcards(v));

        let sbom_pids = load_sbom_product_identifiers_by_values(exact_values, connection).await?;

        let mut wildcard_sbom_pids = Vec::new();
        for pattern in &wildcard_values {
            let like = csaf_glob_to_like(pattern);
            let rows = sbom_node_product_identifier::Entity::find()
                .filter(sbom_node_product_identifier::Column::Value.like(&like))
                .all(connection)
                .instrument(info_span!("loading sbom identifiers by wildcard"))
                .await?;
            wildcard_sbom_pids.extend(rows);
        }

        let all_sbom_pids = sbom_pids.iter().chain(wildcard_sbom_pids.iter());

        let mut models = Vec::new();
        for si in all_sbom_pids {
            let matching_entries = value_map
                .iter()
                .filter(|(pattern, _)| {
                    if has_wildcards(pattern) {
                        csaf_glob_matches(pattern, &si.value)
                    } else {
                        **pattern == si.value.as_str()
                    }
                })
                .flat_map(|(pattern, entries)| entries.iter().map(move |e| (*pattern, e)));

            for (pattern, (vuln_id, id_type, status)) in matching_entries {
                if si.identifier_type == *id_type {
                    let id = evidence_uuid(si.sbom_id, &si.node_id, advisory_id, vuln_id);
                    models.push(correlation_evidence::ActiveModel {
                        id: Set(id),
                        sbom_id: Set(si.sbom_id),
                        node_id: Set(si.node_id.clone()),
                        advisory_id: Set(advisory_id),
                        vulnerability_id: Set(vuln_id.to_string()),
                        status: Set(*status),
                        confidence: Set(1.0),
                        extractor: Set(EXTRACTOR_ID.to_string()),
                        matched_value: Set(Some(pattern.to_string())),
                        created_at: Set(time::OffsetDateTime::now_utc()),
                    });
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

        tracing::info!(advisory_id = %advisory_id, evidence_count = count, "product identifier extraction for advisory complete");
        Ok(count)
    }
}

async fn load_sbom_product_identifiers_by_values<C: ConnectionTrait>(
    values: Vec<&str>,
    connection: &C,
) -> Result<Vec<sbom_node_product_identifier::Model>, Error> {
    let mut results = Vec::new();
    for chunk in values.chunks(5000) {
        let rows = sbom_node_product_identifier::Entity::find()
            .filter(sbom_node_product_identifier::Column::Value.is_in(chunk.iter().copied()))
            .all(connection)
            .instrument(info_span!("loading sbom product identifiers by value"))
            .await?;
        results.extend(rows);
    }
    Ok(results)
}

#[cfg(test)]
mod test {
    use super::*;
    use sea_orm::EntityTrait;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::TrustifyContext;

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn sku_match_from_sbom(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document("scenarios/S19_sku_correlation/sbom/jbl_flip4.cdx.json")
            .await?;
        let advisory = ctx
            .ingest_document("scenarios/S19_sku_correlation/vex/hbsa-2025-0003.json")
            .await?;

        let sbom_id = Uuid::parse_str(&sbom.id)?;
        let advisory_id = Uuid::parse_str(&advisory.id)?;

        let sbom_pids = sbom_node_product_identifier::Entity::find()
            .filter(sbom_node_product_identifier::Column::SbomId.eq(sbom_id))
            .all(&ctx.db)
            .await?;
        assert!(
            !sbom_pids.is_empty(),
            "SBOM product identifiers should have been ingested"
        );

        let count = ProductIdentifierExtractor::extract_for_sbom(sbom_id, &ctx.db).await?;
        assert!(count > 0, "should produce at least one evidence row");

        let evidence = correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
            .filter(correlation_evidence::Column::AdvisoryId.eq(advisory_id))
            .filter(correlation_evidence::Column::Extractor.eq(EXTRACTOR_ID))
            .all(&ctx.db)
            .await?;
        assert!(
            !evidence.is_empty(),
            "SKU-based evidence should exist between SBOM and advisory"
        );
        assert_eq!(evidence[0].confidence, 1.0);
        assert_eq!(evidence[0].vulnerability_id, "CVE-2025-41725");

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn model_number_match(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document("scenarios/S19_sku_correlation/sbom/jbl_flip4.cdx.json")
            .await?;
        ctx.ingest_document("scenarios/S19_sku_correlation/vex/hbsa-2025-0003.json")
            .await?;

        let sbom_id = Uuid::parse_str(&sbom.id)?;

        ProductIdentifierExtractor::extract_for_sbom(sbom_id, &ctx.db).await?;

        let model_evidence = correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
            .filter(correlation_evidence::Column::Extractor.eq(EXTRACTOR_ID))
            .filter(correlation_evidence::Column::NodeId.eq("comp-flip4-fw"))
            .all(&ctx.db)
            .await?;
        assert!(
            !model_evidence.is_empty(),
            "model number match should produce evidence for firmware component"
        );

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn extract_for_advisory_finds_matches(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document("scenarios/S19_sku_correlation/sbom/jbl_flip4.cdx.json")
            .await?;
        let advisory = ctx
            .ingest_document("scenarios/S19_sku_correlation/vex/hbsa-2025-0003.json")
            .await?;

        let sbom_id = Uuid::parse_str(&sbom.id)?;
        let advisory_id = Uuid::parse_str(&advisory.id)?;

        let count = ProductIdentifierExtractor::extract_for_advisory(advisory_id, &ctx.db).await?;
        assert!(count > 0, "should produce evidence from advisory direction");

        let evidence = correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
            .filter(correlation_evidence::Column::AdvisoryId.eq(advisory_id))
            .filter(correlation_evidence::Column::Extractor.eq(EXTRACTOR_ID))
            .all(&ctx.db)
            .await?;
        assert!(!evidence.is_empty());

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn no_match_without_advisory(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document("scenarios/S19_sku_correlation/sbom/jbl_flip4.cdx.json")
            .await?;
        let sbom_id = Uuid::parse_str(&sbom.id)?;

        let count = ProductIdentifierExtractor::extract_for_sbom(sbom_id, &ctx.db).await?;
        assert_eq!(count, 0, "no advisory means no matches");

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn wildcard_sku_match_from_sbom(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document("scenarios/S19_sku_correlation/sbom/jbl_flip4.cdx.json")
            .await?;
        let advisory = ctx
            .ingest_document("scenarios/S19_sku_correlation/vex/hbsa-2025-0004.json")
            .await?;

        let sbom_id = Uuid::parse_str(&sbom.id)?;
        let advisory_id = Uuid::parse_str(&advisory.id)?;

        let count = ProductIdentifierExtractor::extract_for_sbom(sbom_id, &ctx.db).await?;
        assert!(count > 0, "wildcard SKU pattern should match");

        let evidence = correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
            .filter(correlation_evidence::Column::AdvisoryId.eq(advisory_id))
            .filter(correlation_evidence::Column::Extractor.eq(EXTRACTOR_ID))
            .all(&ctx.db)
            .await?;
        assert!(
            !evidence.is_empty(),
            "wildcard SKU-based evidence should exist"
        );
        assert_eq!(evidence[0].vulnerability_id, "CVE-2026-50001");

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn wildcard_match_from_advisory(ctx: &TrustifyContext) -> anyhow::Result<()> {
        ctx.ingest_document("scenarios/S19_sku_correlation/sbom/jbl_flip4.cdx.json")
            .await?;
        let advisory = ctx
            .ingest_document("scenarios/S19_sku_correlation/vex/hbsa-2025-0004.json")
            .await?;

        let advisory_id = Uuid::parse_str(&advisory.id)?;

        let count = ProductIdentifierExtractor::extract_for_advisory(advisory_id, &ctx.db).await?;
        assert!(
            count > 0,
            "wildcard advisory patterns should match SBOM values"
        );

        Ok(())
    }
}

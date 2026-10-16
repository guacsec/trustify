//! Correlation by product identifier (SKU, model number, serial number):
//! `sbom_node_product_identifier` ↔ `advisory_vulnerability_product_identifier`.
//!
//! Advisory values may contain CSAF glob wildcards (see [`wildcard`]).

pub mod wildcard;

use super::{Assertion, Extractor, IdentifierMatch, NodeIdentifier, NodeMatch, NodeRef};
use crate::{
    error::Error,
    model::{IdentifierKind, IdentifierRef, MatchedValue},
};
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryFilter,
};
use std::collections::HashMap;
use tracing::{Instrument, info_span, instrument};
use trustify_entity::{
    advisory_vulnerability_product_identifier::{self, ProductIdentifierType},
    sbom_node_product_identifier,
};
use uuid::Uuid;
use wildcard::{csaf_glob_matches, csaf_glob_to_like, has_wildcards};

/// Extracts correlation evidence by matching SBOM product identifiers
/// (SKU, model number, serial number) against advisory product identifiers.
pub struct ProductIdentifierExtractor;

/// ID of the extractor, and type of its evidence.
const ID: &str = "product_identifier";

const CONFIDENCE: f64 = 1.0;

/// Map an identifier kind to a product identifier type, if it is one.
fn identifier_type(kind: IdentifierKind) -> Option<ProductIdentifierType> {
    match kind {
        IdentifierKind::Sku => Some(ProductIdentifierType::Sku),
        IdentifierKind::ModelNumber => Some(ProductIdentifierType::ModelNumber),
        IdentifierKind::SerialNumber => Some(ProductIdentifierType::SerialNumber),
        IdentifierKind::Digest | IdentifierKind::Purl | IdentifierKind::Cpe => None,
    }
}

fn assertion(ap: &advisory_vulnerability_product_identifier::Model) -> Assertion {
    Assertion {
        extractor: ID,
        advisory_id: ap.advisory_id,
        vulnerability_id: ap.vulnerability_id.clone(),
        status: ap.status,
        confidence: CONFIDENCE,
        matched_value: MatchedValue::new(ap.value.clone()),
        context_id: ap.assertion_context_id,
        requires_context: false,
    }
}

#[async_trait::async_trait]
impl Extractor for ProductIdentifierExtractor {
    fn id(&self) -> &'static str {
        ID
    }

    #[instrument(skip(self, tx), err(level = tracing::Level::INFO))]
    async fn sbom_identifiers(
        &self,
        sbom_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeIdentifier>, Error> {
        let rows = sbom_node_product_identifier::Entity::find()
            .filter(sbom_node_product_identifier::Column::SbomId.eq(sbom_id))
            .all(tx)
            .await?;

        Ok(rows
            .into_iter()
            .map(|row| NodeIdentifier {
                identifier: IdentifierRef {
                    kind: row.identifier_type.into(),
                    value: row.value,
                },
                node: NodeRef {
                    sbom_id: row.sbom_id,
                    node_id: row.node_id,
                },
            })
            .collect())
    }

    /// Look up advisory product identifiers by value, exactly and by CSAF glob patterns.
    ///
    /// Indexes the SKU, model number and serial number identifiers by value, then:
    ///
    /// 1. Exact values: loads all advisory rows having one of the values, in chunks.
    /// 2. Patterns: loads all advisory rows whose value contains a wildcard (`*`, `?`), across all
    ///    advisories, and matches each against every identifier value in memory.
    ///
    /// In both cases, the identifier type must be equal (a SKU only matches a SKU).
    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    async fn match_identifiers(
        &self,
        identifiers: &[IdentifierRef],
        tx: &DatabaseTransaction,
    ) -> Result<Vec<IdentifierMatch>, Error> {
        // value -> [(index, type)]
        let mut value_map = HashMap::<&str, Vec<(usize, ProductIdentifierType)>>::new();
        for (idx, identifier) in identifiers.iter().enumerate() {
            if let Some(id_type) = identifier_type(identifier.kind) {
                value_map
                    .entry(identifier.value.as_str())
                    .or_default()
                    .push((idx, id_type));
            }
        }

        if value_map.is_empty() {
            return Ok(Vec::new());
        }

        let mut result = Vec::new();
        let mut push_matches =
            |ap: &advisory_vulnerability_product_identifier::Model,
             entries: &[(usize, ProductIdentifierType)]| {
                for (idx, id_type) in entries {
                    if *id_type == ap.identifier_type {
                        result.push(IdentifierMatch {
                            index: *idx,
                            assertion: assertion(ap),
                        });
                    }
                }
            };

        let values = value_map.keys().copied().collect::<Vec<_>>();
        for ap in load_product_identifiers_by_values(&values, tx).await? {
            if let Some(entries) = value_map.get(ap.value.as_str()) {
                push_matches(&ap, entries);
            }
        }

        for ap in load_wildcard_product_identifiers(tx).await? {
            for (value, entries) in &value_map {
                if csaf_glob_matches(&ap.value, value) {
                    push_matches(&ap, entries);
                }
            }
        }

        Ok(result)
    }

    /// Look up SBOM product identifiers by the identifiers of an advisory, which may be patterns.
    ///
    /// Splits the advisory's values into exact values and CSAF glob patterns:
    ///
    /// 1. Exact values: loads SBOM rows having one of the values, in chunks.
    /// 2. Patterns: each pattern is translated into a SQL `LIKE` expression, loading the candidate
    ///    SBOM rows with one query per pattern.
    ///
    /// The candidates are then checked against all advisory values in memory (exact or glob
    /// match), requiring the same identifier type.
    #[instrument(skip(self, tx), err(level = tracing::Level::INFO))]
    async fn match_advisory(
        &self,
        advisory_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeMatch>, Error> {
        let advisory_pids = advisory_vulnerability_product_identifier::Entity::find()
            .filter(advisory_vulnerability_product_identifier::Column::AdvisoryId.eq(advisory_id))
            .all(tx)
            .instrument(info_span!("loading advisory product identifiers"))
            .await?;

        if advisory_pids.is_empty() {
            return Ok(Vec::new());
        }

        let mut value_map =
            HashMap::<&str, Vec<&advisory_vulnerability_product_identifier::Model>>::new();
        for ap in &advisory_pids {
            value_map.entry(ap.value.as_str()).or_default().push(ap);
        }

        let (exact_values, wildcard_values): (Vec<&str>, Vec<&str>) =
            value_map.keys().copied().partition(|v| !has_wildcards(v));

        let mut sbom_pids = load_sbom_product_identifiers_by_values(&exact_values, tx).await?;

        for pattern in &wildcard_values {
            let like = csaf_glob_to_like(pattern);
            let rows = sbom_node_product_identifier::Entity::find()
                .filter(sbom_node_product_identifier::Column::Value.like(&like))
                .all(tx)
                .instrument(info_span!("loading sbom identifiers by wildcard"))
                .await?;
            sbom_pids.extend(rows);
        }

        let mut result = Vec::new();
        for si in sbom_pids {
            let matching = value_map
                .iter()
                .filter(|(pattern, _)| {
                    if has_wildcards(pattern) {
                        csaf_glob_matches(pattern, &si.value)
                    } else {
                        **pattern == si.value.as_str()
                    }
                })
                .flat_map(|(_, entries)| entries);

            for ap in matching {
                if si.identifier_type == ap.identifier_type {
                    result.push(NodeMatch {
                        node: NodeRef {
                            sbom_id: si.sbom_id,
                            node_id: si.node_id.clone(),
                        },
                        assertion: assertion(ap),
                    });
                }
            }
        }

        Ok(result)
    }
}

/// Load advisory_vulnerability_product_identifier rows matching any of the given values.
async fn load_product_identifiers_by_values(
    values: &[&str],
    connection: &impl ConnectionTrait,
) -> Result<Vec<advisory_vulnerability_product_identifier::Model>, Error> {
    let mut results = Vec::new();
    for chunk in values.chunks(5000) {
        let rows = advisory_vulnerability_product_identifier::Entity::find()
            .filter(
                advisory_vulnerability_product_identifier::Column::Value
                    .is_in(chunk.iter().copied()),
            )
            .all(connection)
            .instrument(info_span!("loading product identifiers by value"))
            .await?;
        results.extend(rows);
    }
    Ok(results)
}

// ponytail: loads all wildcard rows globally; add boolean column/index if table grows large
/// Load advisory product identifier rows whose value contains CSAF glob wildcards.
async fn load_wildcard_product_identifiers(
    connection: &impl ConnectionTrait,
) -> Result<Vec<advisory_vulnerability_product_identifier::Model>, Error> {
    Ok(advisory_vulnerability_product_identifier::Entity::find()
        .filter(
            Condition::any()
                .add(advisory_vulnerability_product_identifier::Column::Value.like("%*%"))
                .add(advisory_vulnerability_product_identifier::Column::Value.like("%?%")),
        )
        .all(connection)
        .instrument(info_span!("loading wildcard product identifiers"))
        .await?)
}

/// Load sbom_node_product_identifier rows matching any of the given values.
async fn load_sbom_product_identifiers_by_values(
    values: &[&str],
    connection: &impl ConnectionTrait,
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
    use crate::extractor::Extractors;
    use sea_orm::{QueryOrder, TransactionTrait};
    use test_context::test_context;
    use test_log::test;
    use trustify_entity::{
        correlation_evidence, correlation_evidence_context,
        correlation_evidence_context::ContextSource,
    };
    use trustify_test_context::TrustifyContext;

    const EXTRACTOR_ID: &str = "product_identifier";

    fn extractors() -> Extractors {
        Extractors::new(vec![Box::new(ProductIdentifierExtractor)])
    }

    async fn extract_for_sbom(ctx: &TrustifyContext, sbom_id: Uuid) -> anyhow::Result<usize> {
        let tx = ctx.db.begin().await?;
        let count = extractors().extract_for_sbom(sbom_id, &tx).await?;
        tx.commit().await?;
        Ok(count)
    }

    async fn extract_for_advisory(
        ctx: &TrustifyContext,
        advisory_id: Uuid,
    ) -> anyhow::Result<usize> {
        let tx = ctx.db.begin().await?;
        let count = extractors().extract_for_advisory(advisory_id, &tx).await?;
        tx.commit().await?;
        Ok(count)
    }

    /// The evidence of an SBOM, by node: its confidence and context links.
    async fn evidence_of(
        ctx: &TrustifyContext,
        sbom_id: Uuid,
    ) -> anyhow::Result<
        Vec<(
            String,
            String,
            f64,
            Vec<(ContextSource, String, String, f64)>,
        )>,
    > {
        let mut result = Vec::new();
        for evidence in correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
            .filter(correlation_evidence::Column::Extractor.eq(EXTRACTOR_ID))
            .order_by_asc(correlation_evidence::Column::NodeId)
            .all(&ctx.db)
            .await?
        {
            let links = correlation_evidence_context::Entity::find()
                .filter(correlation_evidence_context::Column::EvidenceId.eq(evidence.id))
                .order_by_asc(correlation_evidence_context::Column::NodeIdentifier)
                .order_by_asc(correlation_evidence_context::Column::ContextIdentifier)
                .all(&ctx.db)
                .await?
                .into_iter()
                .map(|link| {
                    (
                        link.source,
                        link.node_identifier,
                        link.context_identifier,
                        link.confidence,
                    )
                })
                .collect();
            result.push((
                evidence.node_id,
                evidence.vulnerability_id,
                evidence.confidence,
                links,
            ));
        }
        Ok(result)
    }

    /// Only the firmware is affected, not the device it is installed on. Contained in the device,
    /// the device's SKUs confirm the product the statement is about.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn sku_confirms_firmware_in_assembly(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document("scenarios/S19_sku_correlation/sbom/jbl_flip4_assembly.cdx.json")
            .await?;
        ctx.ingest_document("scenarios/S19_sku_correlation/vex/hbsa-2025-0003.json")
            .await?;
        let sbom_id = Uuid::parse_str(&sbom.id)?;

        extract_for_sbom(ctx, sbom_id).await?;

        let link = |sku: &str| {
            (
                ContextSource::AncestorNode,
                format!("sku:{sku}"),
                format!("sku:{sku}"),
                0.9,
            )
        };
        assert_eq!(
            evidence_of(ctx, sbom_id).await?,
            vec![(
                "comp-flip4-fw".to_string(),
                "CVE-2025-41725".to_string(),
                0.9,
                vec![link("050036337366"), link("6925281924439")]
            )]
        );

        Ok(())
    }

    /// Next to the device, nothing confirms the product the firmware is stated in.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn model_number_match(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document("scenarios/S19_sku_correlation/sbom/jbl_flip4.cdx.json")
            .await?;
        ctx.ingest_document("scenarios/S19_sku_correlation/vex/hbsa-2025-0003.json")
            .await?;
        let sbom_id = Uuid::parse_str(&sbom.id)?;

        extract_for_sbom(ctx, sbom_id).await?;

        assert_eq!(
            evidence_of(ctx, sbom_id).await?,
            vec![(
                "comp-flip4-fw".to_string(),
                "CVE-2025-41725".to_string(),
                0.7,
                vec![(
                    ContextSource::Unconfirmed,
                    String::new(),
                    "sku:050036337366, sku:6925281924439".to_string(),
                    0.7
                )]
            )]
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

        let count = extract_for_advisory(ctx, advisory_id).await?;
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

    /// Both directions must produce the same evidence rows (same deterministic IDs).
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn both_directions_produce_same_evidence(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document("scenarios/S19_sku_correlation/sbom/jbl_flip4.cdx.json")
            .await?;
        let advisory = ctx
            .ingest_document("scenarios/S19_sku_correlation/vex/hbsa-2025-0003.json")
            .await?;

        let sbom_id = Uuid::parse_str(&sbom.id)?;
        let advisory_id = Uuid::parse_str(&advisory.id)?;

        let load = || async {
            let mut ids = correlation_evidence::Entity::find()
                .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
                .all(&ctx.db)
                .await?
                .into_iter()
                .map(|e| e.id)
                .collect::<Vec<_>>();
            ids.sort();
            Ok::<_, anyhow::Error>(ids)
        };

        extract_for_sbom(ctx, sbom_id).await?;
        let from_sbom = load().await?;
        assert!(!from_sbom.is_empty());

        extract_for_advisory(ctx, advisory_id).await?;
        assert_eq!(from_sbom, load().await?);

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn no_match_without_advisory(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document("scenarios/S19_sku_correlation/sbom/jbl_flip4.cdx.json")
            .await?;
        let sbom_id = Uuid::parse_str(&sbom.id)?;

        let count = extract_for_sbom(ctx, sbom_id).await?;
        assert_eq!(count, 0, "no advisory means no matches");

        Ok(())
    }

    /// The wildcard model number matches the firmware; the wildcard SKU of the device series is
    /// what would have confirmed it.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn wildcard_model_number_match_from_sbom(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document("scenarios/S19_sku_correlation/sbom/jbl_flip4.cdx.json")
            .await?;
        ctx.ingest_document("scenarios/S19_sku_correlation/vex/hbsa-2025-0004.json")
            .await?;
        let sbom_id = Uuid::parse_str(&sbom.id)?;

        extract_for_sbom(ctx, sbom_id).await?;

        assert_eq!(
            evidence_of(ctx, sbom_id).await?,
            vec![(
                "comp-flip4-fw".to_string(),
                "CVE-2026-50001".to_string(),
                0.7,
                vec![(
                    ContextSource::Unconfirmed,
                    String::new(),
                    "sku:6925281*".to_string(),
                    0.7
                )]
            )]
        );

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

        let count = extract_for_advisory(ctx, advisory_id).await?;
        assert!(
            count > 0,
            "wildcard advisory patterns should match SBOM values"
        );

        Ok(())
    }
}

//! Correlation by product identifier (SKU, model number, serial number):
//! `sbom_node_product_identifier` ↔ `advisory_vulnerability_product_identifier`.
//!
//! Advisory values may contain CSAF glob wildcards (see [`wildcard`]).

pub mod wildcard;

use super::{Assertion, Extractor, IdentifierMatch, NodeIdentifier, NodeMatch, NodeRef};
use crate::{
    error::Error,
    model::{ConfidenceFactor, ConfidenceReason, IdentifierKind, IdentifierRef, MatchedValue},
};
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, DatabaseTransaction, EntityTrait, QueryFilter,
};
use std::collections::{BTreeSet, HashMap};
use tracing::{Instrument, info_span, instrument};
use trustify_entity::{
    advisory_vulnerability_product_identifier::{self, ProductIdentifierType},
    sbom_node_product_identifier, version_range,
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

/// The version ranges of advisory product identifiers, by ID.
type Ranges = HashMap<Uuid, version_range::Model>;

/// The assertion of an advisory product identifier. The identifier names a product, its versions
/// are the ones of the product's version range, checked against the node's version.
fn assertion(ap: &advisory_vulnerability_product_identifier::Model, ranges: &Ranges) -> Assertion {
    let mut matched_value = MatchedValue::new(ap.value.clone());
    matched_value.ranges = ap
        .version_range_id
        .and_then(|id| ranges.get(&id))
        .map(|range| range.clone().into())
        .into_iter()
        .collect();
    Assertion {
        extractor: ID,
        advisory_id: ap.advisory_id,
        vulnerability_id: ap.vulnerability_id.clone(),
        status: ap.status,
        confidence: CONFIDENCE,
        factors: vec![ConfidenceFactor::new(
            ConfidenceReason::ProductIdentifier,
            CONFIDENCE,
        )],
        matched_value,
        context_id: ap.assertion_context_id,
        requires_context: false,
        version_range_id: ap.version_range_id,
    }
}

/// Load the version ranges of advisory product identifiers.
async fn load_ranges<'a>(
    rows: impl IntoIterator<Item = &'a advisory_vulnerability_product_identifier::Model>,
    connection: &impl ConnectionTrait,
) -> Result<Ranges, Error> {
    let ids = rows
        .into_iter()
        .filter_map(|row| row.version_range_id)
        .collect::<BTreeSet<_>>();
    if ids.is_empty() {
        return Ok(Ranges::new());
    }
    Ok(version_range::Entity::find()
        .filter(version_range::Column::Id.is_in(ids))
        .all(connection)
        .instrument(info_span!("loading product version ranges"))
        .await?
        .into_iter()
        .map(|range| (range.id, range))
        .collect())
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

        let values = value_map.keys().copied().collect::<Vec<_>>();
        let exact = load_product_identifiers_by_values(&values, tx).await?;
        let wildcards = load_wildcard_product_identifiers(tx).await?;
        let ranges = load_ranges(exact.iter().chain(&wildcards), tx).await?;

        let mut result = Vec::new();
        let mut push_matches =
            |ap: &advisory_vulnerability_product_identifier::Model,
             entries: &[(usize, ProductIdentifierType)]| {
                for (idx, id_type) in entries {
                    if *id_type == ap.identifier_type {
                        result.push(IdentifierMatch {
                            index: *idx,
                            assertion: assertion(ap, &ranges),
                        });
                    }
                }
            };

        for ap in &exact {
            if let Some(entries) = value_map.get(ap.value.as_str()) {
                push_matches(ap, entries);
            }
        }

        for ap in &wildcards {
            for (value, entries) in &value_map {
                if csaf_glob_matches(&ap.value, value) {
                    push_matches(ap, entries);
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
        let ranges = load_ranges(&advisory_pids, tx).await?;

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
                        assertion: assertion(ap, &ranges),
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
    use crate::{extractor::Extractors, model::ContextSource as ApiContextSource};
    use sea_orm::{QueryOrder, TransactionTrait};
    use serde_json::{Value, json};
    use test_context::test_context;
    use test_log::test;
    use trustify_entity::{
        correlation_evidence::{self, AssertionStatus},
        correlation_evidence_context,
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

    /// The evidence of an SBOM, by node: vulnerability, status, confidence, the matched value and
    /// context links.
    async fn evidence_of(ctx: &TrustifyContext, sbom_id: Uuid) -> anyhow::Result<Vec<Evidence>> {
        let mut result = Vec::new();
        for evidence in correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
            .filter(correlation_evidence::Column::Extractor.eq(EXTRACTOR_ID))
            .order_by_asc(correlation_evidence::Column::NodeId)
            .order_by_asc(correlation_evidence::Column::VulnerabilityId)
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
            result.push(Evidence {
                node_id: evidence.node_id,
                vulnerability_id: evidence.vulnerability_id,
                status: evidence.status,
                confidence: evidence.confidence,
                factors: serde_json::from_value(evidence.confidence_factors)?,
                matched_value: evidence.matched_value.unwrap_or_default(),
                links,
            });
        }
        Ok(result)
    }

    /// An evidence row, as compared by the tests.
    #[derive(Debug, PartialEq)]
    struct Evidence {
        node_id: String,
        vulnerability_id: String,
        status: AssertionStatus,
        confidence: f64,
        factors: Vec<ConfidenceFactor>,
        matched_value: Value,
        links: Vec<(ContextSource, String, String, f64)>,
    }

    /// The factors of a product identifier match, in a confirmed or unconfirmed product.
    fn factors(product: Option<ConfidenceFactor>) -> Vec<ConfidenceFactor> {
        let mut factors = vec![ConfidenceFactor::new(
            ConfidenceReason::ProductIdentifier,
            1.0,
        )];
        factors.extend(product);
        factors
    }

    /// The factor of a product confirmed by the parent's SKUs.
    fn by_parent() -> Option<ConfidenceFactor> {
        Some(ConfidenceFactor::new(
            ConfidenceReason::ProductConfirmed {
                source: ApiContextSource::AncestorNode,
                distance: 1,
                source_factor: Some(0.9),
                wildcard_factor: Some(1.0),
            },
            0.9,
        ))
    }

    /// The factor of a product nothing confirms.
    fn not_confirmed() -> Option<ConfidenceFactor> {
        Some(ConfidenceFactor::new(
            ConfidenceReason::ProductNotConfirmed,
            0.7,
        ))
    }

    /// The SKUs of the JBL Flip 4 in HBSA-2025-0003, as recorded on an unconfirmed context link.
    const FLIP4_SKUS: &str = "sku:050036336109, sku:050036336116, sku:050036336123, \
        sku:050036336130, sku:050036336147, sku:050036337366, sku:050036337373, sku:050036337380, \
        sku:050036337397, sku:050036337403, sku:050036337441, sku:6925281922404, sku:6925281922411, \
        sku:6925281922428, sku:6925281922435, sku:6925281922442, sku:6925281924408, sku:6925281924415, \
        sku:6925281924422, sku:6925281924439, sku:6925281924446, sku:6925281924545";

    /// The matched value of model number `Flip 4`, for firmware below 4.1.0 or exactly 4.1.0.
    fn flip4(fixed: bool) -> Value {
        let range = match fixed {
            false => json!({"scheme": "semver", "high": {"version": "4.1.0", "inclusive": false}}),
            true => json!({
                "scheme": "generic",
                "low": {"version": "4.1.0", "inclusive": true},
                "high": {"version": "4.1.0", "inclusive": true},
            }),
        };
        json!({"origin": "stated", "identifier": "Flip 4", "ranges": [range]})
    }

    /// Ingest an S19 SBOM and advisory, and extract the evidence of the SBOM.
    async fn s19(ctx: &TrustifyContext, sbom: &str, advisory: &str) -> anyhow::Result<Uuid> {
        let sbom = ctx
            .ingest_document(&format!("scenarios/S19_sku_correlation/sbom/{sbom}"))
            .await?;
        ctx.ingest_document(&format!("scenarios/S19_sku_correlation/vex/{advisory}"))
            .await?;
        let sbom_id = Uuid::parse_str(&sbom.id)?;
        extract_for_sbom(ctx, sbom_id).await?;
        Ok(sbom_id)
    }

    /// Only the firmware is affected, not the device it is installed on. Contained in the device,
    /// the device's SKUs confirm the product the statement is about. The firmware's version is
    /// below 4.1.0, so the statement of the fixed 4.1.0 doesn't apply.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn sku_confirms_firmware_in_assembly(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom_id = s19(ctx, "jbl_flip4_assembly.cdx.json", "hbsa-2025-0003.json").await?;

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
            vec![Evidence {
                node_id: "comp-flip4-fw".into(),
                vulnerability_id: "CVE-2025-41725".into(),
                status: AssertionStatus::Affected,
                confidence: 0.9,
                factors: factors(by_parent()),
                matched_value: flip4(false),
                links: vec![link("050036337366"), link("6925281924439")],
            }]
        );

        Ok(())
    }

    /// The firmware 4.1.0 is only in the fixed statement.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn fixed_firmware_version(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom_id = s19(
            ctx,
            "jbl_flip4_assembly_fw_4.1.0.cdx.json",
            "hbsa-2025-0003.json",
        )
        .await?;

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
            vec![Evidence {
                node_id: "comp-flip4-fw".into(),
                vulnerability_id: "CVE-2025-41725".into(),
                status: AssertionStatus::Fixed,
                confidence: 0.9,
                factors: factors(by_parent()),
                matched_value: flip4(true),
                links: vec![link("050036337366"), link("6925281924439")],
            }]
        );

        Ok(())
    }

    /// Next to the device, nothing confirms the product the firmware is stated in.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn model_number_match(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom_id = s19(ctx, "jbl_flip4.cdx.json", "hbsa-2025-0003.json").await?;

        assert_eq!(
            evidence_of(ctx, sbom_id).await?,
            vec![Evidence {
                node_id: "comp-flip4-fw".into(),
                vulnerability_id: "CVE-2025-41725".into(),
                status: AssertionStatus::Affected,
                confidence: 0.7,
                factors: factors(not_confirmed()),
                matched_value: flip4(false),
                links: vec![(
                    ContextSource::Unconfirmed,
                    String::new(),
                    FLIP4_SKUS.to_string(),
                    0.7
                )],
            }]
        );

        Ok(())
    }

    /// A product stated without a relationship is affected through its own SKU, in all versions.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn sku_of_device(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom_id = s19(ctx, "jbl_flip5.cdx.json", "hbsa-2025-0002.json").await?;

        assert_eq!(
            evidence_of(ctx, sbom_id).await?,
            vec![Evidence {
                node_id: "comp-flip5-device".into(),
                vulnerability_id: "CVE-2024-2105".into(),
                status: AssertionStatus::Affected,
                confidence: 1.0,
                factors: factors(None),
                matched_value: json!({"origin": "stated", "identifier": "050036359160"}),
                links: vec![],
            }]
        );

        Ok(())
    }

    /// A node without a version is in no version range.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn no_version_no_range(ctx: &TrustifyContext) -> anyhow::Result<()> {
        use crate::extractor::version::retain_in_range;

        let sbom = ctx
            .ingest_document("scenarios/S19_sku_correlation/sbom/jbl_flip4.cdx.json")
            .await?;
        let advisory = ctx
            .ingest_document("scenarios/S19_sku_correlation/vex/hbsa-2025-0003.json")
            .await?;
        let sbom_id = Uuid::parse_str(&sbom.id)?;

        let tx = ctx.db.begin().await?;
        let matches = ProductIdentifierExtractor
            .match_advisory(Uuid::parse_str(&advisory.id)?, &tx)
            .await?
            .into_iter()
            .filter(|m| m.node.sbom_id == sbom_id)
            .map(|m| {
                (
                    NodeRef {
                        sbom_id,
                        // no package, so no version
                        node_id: "unknown".into(),
                    },
                    m.assertion,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 2);
        assert_eq!(retain_in_range(matches, &tx).await?, vec![]);

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
        let sbom_id = s19(ctx, "jbl_flip4.cdx.json", "hbsa-2025-0004.json").await?;

        assert_eq!(
            evidence_of(ctx, sbom_id).await?,
            vec![Evidence {
                node_id: "comp-flip4-fw".into(),
                vulnerability_id: "CVE-2026-50001".into(),
                status: AssertionStatus::Affected,
                confidence: 0.7,
                factors: factors(not_confirmed()),
                matched_value: json!({
                    "origin": "stated",
                    "identifier": "Flip ?",
                    "ranges": [{"scheme": "semver", "high": {"version": "5.0.0", "inclusive": false}}],
                }),
                links: vec![(
                    ContextSource::Unconfirmed,
                    String::new(),
                    "sku:6925281*".to_string(),
                    0.7
                )],
            }]
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

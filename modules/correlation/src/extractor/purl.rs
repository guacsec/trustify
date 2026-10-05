//! Correlation by PURL: `sbom_node_purl_ref` ↔ `purl_status`.
//!
//! Unlike digest/product_identifier which use exact value matching, PURL
//! matching requires version-range evaluation via the `version_matches()`
//! PostgreSQL function.

use super::{Assertion, Extractor, IdentifierMatch, NodeIdentifier, NodeMatch, NodeRef};
use crate::{
    error::Error,
    model::{IdentifierKind, IdentifierRef},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, FromQueryResult, JoinType,
    LoaderTrait, QueryFilter, QuerySelect, RelationTrait,
    sea_query::{Asterisk, Expr, Func, SimpleExpr},
};
use std::collections::HashMap;
use tracing::{Instrument, info_span, instrument};
use trustify_common::{db::VersionMatches, purl::Purl};
use trustify_entity::{
    base_purl, correlation_evidence::AssertionStatus, purl_status, qualified_purl,
    sbom_node_purl_ref, status, version_range, versioned_purl,
};
use uuid::Uuid;

/// Extracts correlation evidence by matching SBOM PURLs against advisory
/// `purl_status` entries via base-package identity and version-range matching.
pub struct PurlExtractor;

const CONFIDENCE: f64 = 1.0;

fn map_status(slug: &str) -> Option<AssertionStatus> {
    match slug {
        "affected" => Some(AssertionStatus::Affected),
        "fixed" => Some(AssertionStatus::Fixed),
        "not_affected" => Some(AssertionStatus::NotAffected),
        "under_investigation" => Some(AssertionStatus::UnderInvestigation),
        "recommended" => Some(AssertionStatus::Recommended),
        _ => None,
    }
}

fn format_base_purl(ty: &str, namespace: Option<&str>, name: &str) -> String {
    Purl {
        ty: ty.to_string(),
        namespace: namespace.map(String::from),
        name: name.to_string(),
        version: None,
        qualifiers: Default::default(),
    }
    .to_string()
}

fn version_matches_filter() -> SimpleExpr {
    SimpleExpr::FunctionCall(
        Func::cust(VersionMatches)
            .arg(Expr::col((
                versioned_purl::Entity,
                versioned_purl::Column::Version,
            )))
            .arg(Expr::col((version_range::Entity, Asterisk))),
    )
}

#[derive(FromQueryResult)]
struct PurlStatusMatch {
    advisory_id: Uuid,
    vulnerability_id: String,
    slug: String,
    versioned_purl_id: Uuid,
    base_purl_type: String,
    base_purl_namespace: Option<String>,
    base_purl_name: String,
}

#[derive(FromQueryResult)]
struct AdvisoryPurlMatch {
    advisory_id: Uuid,
    vulnerability_id: String,
    slug: String,
    sbom_id: Uuid,
    node_id: String,
    base_purl_type: String,
    base_purl_namespace: Option<String>,
    base_purl_name: String,
}

#[async_trait::async_trait]
impl Extractor for PurlExtractor {
    fn id(&self) -> &'static str {
        "purl"
    }

    #[instrument(skip(self, tx), err(level = tracing::Level::INFO))]
    async fn sbom_identifiers(
        &self,
        sbom_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeIdentifier>, Error> {
        let purl_refs = sbom_node_purl_ref::Entity::find()
            .filter(sbom_node_purl_ref::Column::SbomId.eq(sbom_id))
            .all(tx)
            .instrument(info_span!("loading purl refs"))
            .await?;

        let qualified_purls = purl_refs
            .load_one(qualified_purl::Entity, tx)
            .instrument(info_span!("loading qualified purls"))
            .await?;

        Ok(purl_refs
            .into_iter()
            .zip(qualified_purls)
            .filter_map(|(purl_ref, qp)| {
                Some(NodeIdentifier {
                    identifier: IdentifierRef {
                        kind: IdentifierKind::Purl,
                        value: Purl::from(qp?.purl).to_string(),
                    },
                    node: NodeRef {
                        sbom_id: purl_ref.sbom_id,
                        node_id: purl_ref.node_id,
                    },
                })
            })
            .collect())
    }

    #[instrument(skip_all, err(level = tracing::Level::INFO))]
    async fn match_identifiers(
        &self,
        identifiers: &[IdentifierRef],
        tx: &DatabaseTransaction,
    ) -> Result<Vec<IdentifierMatch>, Error> {
        // versioned_purl_id -> [input indices]
        let mut vp_map = HashMap::<Uuid, Vec<usize>>::new();
        for (idx, identifier) in identifiers.iter().enumerate() {
            if identifier.kind != IdentifierKind::Purl {
                continue;
            }
            let Ok(purl) = identifier.value.parse::<Purl>() else {
                continue;
            };
            if purl.version.is_none() {
                continue;
            }
            vp_map.entry(purl.version_uuid()).or_default().push(idx);
        }

        if vp_map.is_empty() {
            return Ok(Vec::new());
        }

        let vp_ids: Vec<_> = vp_map.keys().copied().collect();
        let mut result = Vec::new();

        for chunk in vp_ids.chunks(5000) {
            let rows = load_purl_status_matches(chunk, tx).await?;
            for row in rows {
                let Some(status) = map_status(&row.slug) else {
                    continue;
                };
                let Some(indices) = vp_map.get(&row.versioned_purl_id) else {
                    continue;
                };
                let matched_value = format_base_purl(
                    &row.base_purl_type,
                    row.base_purl_namespace.as_deref(),
                    &row.base_purl_name,
                );
                for &idx in indices {
                    result.push(IdentifierMatch {
                        index: idx,
                        assertion: Assertion {
                            advisory_id: row.advisory_id,
                            vulnerability_id: row.vulnerability_id.clone(),
                            status,
                            confidence: CONFIDENCE,
                            matched_value: matched_value.clone(),
                        },
                    });
                }
            }
        }

        Ok(result)
    }

    #[instrument(skip(self, tx), err(level = tracing::Level::INFO))]
    async fn match_advisory(
        &self,
        advisory_id: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeMatch>, Error> {
        let rows = load_advisory_purl_matches(advisory_id, tx).await?;

        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let status = map_status(&row.slug)?;
                let matched_value = format_base_purl(
                    &row.base_purl_type,
                    row.base_purl_namespace.as_deref(),
                    &row.base_purl_name,
                );
                Some(NodeMatch {
                    node: NodeRef {
                        sbom_id: row.sbom_id,
                        node_id: row.node_id,
                    },
                    assertion: Assertion {
                        advisory_id: row.advisory_id,
                        vulnerability_id: row.vulnerability_id,
                        status,
                        confidence: CONFIDENCE,
                        matched_value,
                    },
                })
            })
            .collect())
    }
}

// ponytail: context_cpe_id ignored — all purl_status matches included; add CPE context filtering when needed
// ponytail: ad-hoc PURLs not in DB won't match; add fallback with literal version_matches when needed

/// Load purl_status rows matching any of the given versioned_purl IDs via
/// version-range evaluation.
///
/// Join chain: versioned_purl → base_purl → purl_status → version_range + status,
/// filtered by `version_matches(versioned_purl.version, version_range.*)`.
async fn load_purl_status_matches(
    versioned_purl_ids: &[Uuid],
    connection: &impl ConnectionTrait,
) -> Result<Vec<PurlStatusMatch>, Error> {
    Ok(versioned_purl::Entity::find()
        .select_only()
        .column_as(purl_status::Column::AdvisoryId, "advisory_id")
        .column_as(purl_status::Column::VulnerabilityId, "vulnerability_id")
        .column_as(status::Column::Slug, "slug")
        .column_as(versioned_purl::Column::Id, "versioned_purl_id")
        .column_as(base_purl::Column::Type, "base_purl_type")
        .column_as(base_purl::Column::Namespace, "base_purl_namespace")
        .column_as(base_purl::Column::Name, "base_purl_name")
        .join(
            JoinType::InnerJoin,
            versioned_purl::Relation::BasePurl.def(),
        )
        .join(JoinType::InnerJoin, base_purl::Relation::PurlStatus.def())
        .join(
            JoinType::InnerJoin,
            purl_status::Relation::VersionRange.def(),
        )
        .join(JoinType::InnerJoin, purl_status::Relation::Status.def())
        .filter(versioned_purl::Column::Id.is_in(versioned_purl_ids.iter().copied()))
        .filter(version_matches_filter())
        .into_model::<PurlStatusMatch>()
        .all(connection)
        .instrument(info_span!("loading purl status matches"))
        .await?)
}

/// Load SBOM nodes matching an advisory's PURL-based assertions.
///
/// Join chain: purl_status → base_purl → versioned_purl → qualified_purl → sbom_node_purl_ref,
/// plus purl_status → version_range + status, filtered by `version_matches`.
async fn load_advisory_purl_matches(
    advisory_id: Uuid,
    connection: &impl ConnectionTrait,
) -> Result<Vec<AdvisoryPurlMatch>, Error> {
    Ok(purl_status::Entity::find()
        .select_only()
        .column(purl_status::Column::AdvisoryId)
        .column(purl_status::Column::VulnerabilityId)
        .column_as(status::Column::Slug, "slug")
        .column_as(sbom_node_purl_ref::Column::SbomId, "sbom_id")
        .column_as(sbom_node_purl_ref::Column::NodeId, "node_id")
        .column_as(base_purl::Column::Type, "base_purl_type")
        .column_as(base_purl::Column::Namespace, "base_purl_namespace")
        .column_as(base_purl::Column::Name, "base_purl_name")
        .join(
            JoinType::InnerJoin,
            purl_status::Relation::VersionRange.def(),
        )
        .join(JoinType::InnerJoin, purl_status::Relation::Status.def())
        .join(JoinType::InnerJoin, purl_status::Relation::BasePurl.def())
        .join(
            JoinType::InnerJoin,
            base_purl::Relation::VersionedPurls.def(),
        )
        .join(
            JoinType::InnerJoin,
            versioned_purl::Relation::QualifiedPurl.def(),
        )
        .join(
            JoinType::InnerJoin,
            qualified_purl::Relation::SbomNode.def(),
        )
        .filter(purl_status::Column::AdvisoryId.eq(advisory_id))
        .filter(version_matches_filter())
        .into_model::<AdvisoryPurlMatch>()
        .all(connection)
        .instrument(info_span!("loading advisory purl matches"))
        .await?)
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

    const EXTRACTOR_ID: &str = "purl";

    fn extractors() -> Extractors {
        Extractors::new(vec![Box::new(PurlExtractor)])
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

    /// Both directions must find matches and produce the same evidence rows.
    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn extract_both_directions(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document(
                "scenarios/S5_positive_baseline_openssl_el8/sbom_openssl_el8_below-fix.cdx.json",
            )
            .await?;
        ctx.ingest_document("scenarios/S5_positive_baseline_openssl_el8/cve/CVE-2023-0215.json")
            .await?;
        let advisory = ctx
            .ingest_document("scenarios/S5_positive_baseline_openssl_el8/vex/CVE-2023-0215.json.xz")
            .await?;

        let sbom_id = Uuid::parse_str(&sbom.id)?;
        let advisory_id = Uuid::parse_str(&advisory.id)?;

        let load = || async {
            let mut ids = correlation_evidence::Entity::find()
                .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
                .filter(correlation_evidence::Column::Extractor.eq(EXTRACTOR_ID))
                .all(&ctx.db)
                .await?
                .into_iter()
                .map(|e| e.id)
                .collect::<Vec<_>>();
            ids.sort();
            Ok::<_, anyhow::Error>(ids)
        };

        let tx = ctx.db.begin().await?;
        assert!(extractors().extract_for_sbom(sbom_id, &tx).await? > 0);
        tx.commit().await?;
        let from_sbom = load().await?;
        assert!(!from_sbom.is_empty());

        let tx = ctx.db.begin().await?;
        assert!(extractors().extract_for_advisory(advisory_id, &tx).await? > 0);
        tx.commit().await?;
        assert_eq!(from_sbom, load().await?);

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn purl_match_from_sbom(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document(
                "scenarios/S5_positive_baseline_openssl_el8/sbom_openssl_el8_below-fix.cdx.json",
            )
            .await?;
        ctx.ingest_document("scenarios/S5_positive_baseline_openssl_el8/cve/CVE-2023-0215.json")
            .await?;
        let advisory = ctx
            .ingest_document("scenarios/S5_positive_baseline_openssl_el8/vex/CVE-2023-0215.json.xz")
            .await?;

        let sbom_id = Uuid::parse_str(&sbom.id)?;
        let advisory_id = Uuid::parse_str(&advisory.id)?;

        let count = extract_for_sbom(ctx, sbom_id).await?;
        assert!(count > 0, "should produce at least one evidence row");

        let evidence = correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
            .filter(correlation_evidence::Column::AdvisoryId.eq(advisory_id))
            .filter(correlation_evidence::Column::Extractor.eq(EXTRACTOR_ID))
            .all(&ctx.db)
            .await?;
        assert!(
            !evidence.is_empty(),
            "PURL-based evidence should exist between SBOM and advisory"
        );
        assert_eq!(evidence[0].confidence, 1.0);
        assert!(evidence[0].vulnerability_id.starts_with("CVE-"));

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn no_match_without_advisory(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document(
                "scenarios/S5_positive_baseline_openssl_el8/sbom_openssl_el8_below-fix.cdx.json",
            )
            .await?;
        let sbom_id = Uuid::parse_str(&sbom.id)?;

        let count = extract_for_sbom(ctx, sbom_id).await?;
        assert_eq!(count, 0, "no advisory means no matches");

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(actix_web::test)]
    async fn extract_for_advisory_finds_matches(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom = ctx
            .ingest_document(
                "scenarios/S5_positive_baseline_openssl_el8/sbom_openssl_el8_below-fix.cdx.json",
            )
            .await?;
        ctx.ingest_document("scenarios/S5_positive_baseline_openssl_el8/cve/CVE-2023-0215.json")
            .await?;
        let advisory = ctx
            .ingest_document("scenarios/S5_positive_baseline_openssl_el8/vex/CVE-2023-0215.json.xz")
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
}

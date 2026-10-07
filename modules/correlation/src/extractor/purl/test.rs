use super::*;
use crate::{extractor::Extractors, model::RangeBound};
use sea_orm::TransactionTrait;
use test_context::test_context;
use test_log::test;
use trustify_entity::correlation_evidence;
use trustify_test_context::TrustifyContext;

const S5_SBOM: &str =
    "scenarios/S5_positive_baseline_openssl_el8/sbom_openssl_el8_below-fix.cdx.json";
const S5_VEX: &str = "scenarios/S5_positive_baseline_openssl_el8/vex/CVE-2023-0215.json.xz";

fn extractors() -> Extractors {
    Extractors::new(vec![Box::new(PurlExtractor)])
}

async fn extract_for_sbom(ctx: &TrustifyContext, sbom_id: Uuid) -> anyhow::Result<usize> {
    let tx = ctx.db.begin().await?;
    let count = extractors().extract_for_sbom(sbom_id, &tx).await?;
    tx.commit().await?;
    Ok(count)
}

async fn extract_for_advisory(ctx: &TrustifyContext, advisory_id: Uuid) -> anyhow::Result<usize> {
    let tx = ctx.db.begin().await?;
    let count = extractors().extract_for_advisory(advisory_id, &tx).await?;
    tx.commit().await?;
    Ok(count)
}

/// (node, vulnerability, type, status, confidence, matched value)
type Evidence = (
    String,
    String,
    String,
    AssertionStatus,
    f64,
    Option<MatchedValue>,
);

/// All PURL evidence of an SBOM (stated and derived by rules), sorted.
async fn load_evidence(ctx: &TrustifyContext, sbom_id: Uuid) -> anyhow::Result<Vec<Evidence>> {
    let mut evidence = correlation_evidence::Entity::find()
        .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
        .filter(
            correlation_evidence::Column::Extractor.is_in(
                [PLAIN, STREAM]
                    .into_iter()
                    .chain(rule::rules().iter().map(|r| r.id())),
            ),
        )
        .all(&ctx.db)
        .await?
        .into_iter()
        .map(|e| {
            Ok((
                e.node_id,
                e.vulnerability_id,
                e.extractor,
                e.status,
                e.confidence,
                e.matched_value
                    .map(serde_json::from_value::<MatchedValue>)
                    .transpose()?,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    evidence.sort_by(|a, b| (&a.0, &a.1, &a.2).cmp(&(&b.0, &b.1, &b.2)));
    Ok(evidence)
}

/// Ranges of the given scheme, fixed in the given versions (exclusive upper bounds).
fn fixed_in(scheme: &str, versions: &[&str]) -> Vec<MatchedRange> {
    versions
        .iter()
        .map(|fixed| MatchedRange {
            scheme: scheme.into(),
            low: None,
            high: Some(RangeBound {
                version: (*fixed).into(),
                inclusive: false,
            }),
        })
        .collect()
}

/// Both directions must find matches and produce the same evidence rows.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn extract_both_directions(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let sbom = ctx.ingest_document(S5_SBOM).await?;
    let advisory = ctx.ingest_document(S5_VEX).await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;
    let advisory_id = Uuid::parse_str(&advisory.id)?;

    assert!(extract_for_sbom(ctx, sbom_id).await? > 0);
    let from_sbom = load_evidence(ctx, sbom_id).await?;
    assert!(!from_sbom.is_empty());

    correlation_evidence::Entity::delete_many()
        .exec(&ctx.db)
        .await?;

    assert!(extract_for_advisory(ctx, advisory_id).await? > 0);
    assert_eq!(load_evidence(ctx, sbom_id).await?, from_sbom);

    Ok(())
}

const RH_FIXED: &str = "purl_rh_fixed";

const S9_VEX: &str = "scenarios/S9_substream_openssl_el8/vex/CVE-2023-0286.json.xz";

/// Ingest the documents, extract from the SBOM, and return its PURL evidence.
async fn evidence_of(
    ctx: &TrustifyContext,
    sbom: &str,
    vex: &str,
) -> anyhow::Result<Vec<Evidence>> {
    let sbom = ctx.ingest_document(sbom).await?;
    ctx.ingest_document(vex).await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;
    extract_for_sbom(ctx, sbom_id).await?;
    load_evidence(ctx, sbom_id).await
}

/// Red Hat only states fixed versions. An `el8` package is affected by the `el8_*` fixes it is
/// below (sharing the major only), not by the `el9_*` ones.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn rh_fixed_major(ctx: &TrustifyContext) -> anyhow::Result<()> {
    assert_eq!(
        evidence_of(ctx, S5_SBOM, S5_VEX).await?,
        vec![(
            "pkg-openssl".to_string(),
            "CVE-2023-0215".to_string(),
            RH_FIXED.to_string(),
            AssertionStatus::Affected,
            0.72,
            Some(MatchedValue {
                identifier: "pkg:rpm/redhat/openssl".into(),
                ranges: fixed_in("rpm", &["1:1.1.1k-9.el8_6", "1:1.1.1k-9.el8_7"]),
            }),
        )]
    );

    Ok(())
}

/// An `el8_2` package below the fix is affected by the `el8_2` fix only, not the GA (`el8_7`) one.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn rh_fixed_exact(ctx: &TrustifyContext) -> anyhow::Result<()> {
    assert_eq!(
        evidence_of(
            ctx,
            "scenarios/S9_substream_openssl_el8/sbom_openssl_el8.2_below-fix.cdx.json",
            S9_VEX
        )
        .await?,
        vec![(
            "pkg-openssl".to_string(),
            "CVE-2023-0286".to_string(),
            RH_FIXED.to_string(),
            AssertionStatus::Affected,
            0.9,
            Some(MatchedValue {
                identifier: "pkg:rpm/redhat/openssl".into(),
                ranges: fixed_in("rpm", &["1:1.1.1c-21.el8_2"]),
            }),
        )]
    );

    Ok(())
}

/// A package at the fixed version only matches the stated fixed version.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn rh_fixed_at_fix(ctx: &TrustifyContext) -> anyhow::Result<()> {
    assert_eq!(
        evidence_of(
            ctx,
            "scenarios/S9_substream_openssl_el8/sbom_openssl_el8.2_patched.cdx.json",
            S9_VEX
        )
        .await?,
        vec![(
            "pkg-openssl".to_string(),
            "CVE-2023-0286".to_string(),
            STREAM.to_string(),
            AssertionStatus::Fixed,
            1.0,
            Some(MatchedValue {
                identifier: "pkg:rpm/redhat/openssl".into(),
                ranges: vec![MatchedRange {
                    scheme: "rpm".into(),
                    low: Some(RangeBound {
                        version: "1:1.1.1c-21.el8_2".into(),
                        inclusive: true,
                    }),
                    high: Some(RangeBound {
                        version: "1:1.1.1c-21.el8_2".into(),
                        inclusive: true,
                    }),
                }],
            }),
        )]
    );

    Ok(())
}

/// Stated ranges are scoped by stream too: an `el8` package matches the `el8_6` range (sharing the
/// major only), not the `el9_0` one. The publisher isn't Red Hat, so no rule applies.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn stated_stream_range(ctx: &TrustifyContext) -> anyhow::Result<()> {
    assert_eq!(
        evidence_of(ctx, S5_SBOM, "correlation/stream-ranges.json").await?,
        vec![(
            "pkg-openssl".to_string(),
            "CVE-2023-0215".to_string(),
            STREAM.to_string(),
            AssertionStatus::Affected,
            0.8,
            Some(MatchedValue {
                identifier: "pkg:rpm/redhat/openssl".into(),
                ranges: fixed_in("rpm", &["1:1.1.1k-9.el8_6"]),
            }),
        )]
    );

    Ok(())
}

/// A non-RPM package is matched by version range only, and reported as plain evidence.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn plain_match(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let sbom = ctx
        .ingest_document(
            "scenarios/S6_positive_baseline_osv_urllib3/sbom_urllib3_affected.cdx.json",
        )
        .await?;
    ctx.ingest_document("scenarios/S6_positive_baseline_osv_urllib3/osv/GHSA-g4mx-q9vg-27p4.json")
        .await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;

    assert!(extract_for_sbom(ctx, sbom_id).await? > 0);

    assert_eq!(
        load_evidence(ctx, sbom_id).await?,
        vec![(
            "pkg-urllib3".to_string(),
            "CVE-2023-45803".to_string(),
            PLAIN.to_string(),
            AssertionStatus::Affected,
            1.0,
            Some(MatchedValue {
                identifier: "pkg:pypi/urllib3".into(),
                ranges: vec![
                    MatchedRange {
                        scheme: "generic".into(),
                        low: Some(RangeBound {
                            version: "1.26.17".into(),
                            inclusive: true,
                        }),
                        high: Some(RangeBound {
                            version: "1.26.17".into(),
                            inclusive: true,
                        }),
                    },
                    MatchedRange {
                        scheme: "python".into(),
                        low: Some(RangeBound {
                            version: "0".into(),
                            inclusive: true,
                        }),
                        high: Some(RangeBound {
                            version: "1.26.18".into(),
                            inclusive: false,
                        }),
                    },
                ],
            }),
        )]
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn no_match_without_advisory(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let sbom = ctx.ingest_document(S5_SBOM).await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;

    let count = extract_for_sbom(ctx, sbom_id).await?;
    assert_eq!(count, 0, "no advisory means no matches");

    Ok(())
}

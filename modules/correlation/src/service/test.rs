use crate::extractor::Extractors;
use crate::{
    model::{
        ApiAssertionStatus, ComponentRef, CorrelationResult, IdentifierKind, IdentifierRef,
        MatchedValue, QueryMatch, QueryResult, QueryVerdict, SbomVerdictCounts, VerdictStatus,
    },
    service::CorrelationService,
};
use rstest::rstest;
use sea_orm::{ActiveModelTrait, Set, TransactionTrait};
use std::collections::BTreeMap;
use test_context::test_context;
use test_log::test;
use trustify_entity::correlation_evidence::{self, AssertionStatus};
use trustify_test_context::{TrustifyContext, document_bytes};
use uuid::Uuid;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn empty_sbom_returns_no_verdicts(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let service = CorrelationService::default();
    let tx = ctx.db.begin().await?;
    let result = service.correlate_sbom(Uuid::new_v4(), false, &tx).await?;
    assert!(result.verdicts.is_empty());
    assert!(result.unmatched_components.is_none());
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn evidence_produces_verdict(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let sbom = ctx.ingest_document("spdx/simple.json").await?;
    let advisory = ctx.ingest_document("csaf/cve-2023-33201.json").await?;

    let sbom_id = Uuid::parse_str(&sbom.id)?;
    let advisory_id = Uuid::parse_str(&advisory.id)?;

    let evidence = correlation_evidence::ActiveModel {
        id: Set(Uuid::new_v4()),
        sbom_id: Set(sbom_id),
        node_id: Set("SPDXRef-Package".to_string()),
        advisory_id: Set(advisory_id),
        vulnerability_id: Set("CVE-2023-33201".to_string()),
        status: Set(AssertionStatus::Affected),

        confidence: Set(0.95),
        extractor: Set("digest".to_string()),
        matched_value: Set(None),
        created_at: Set(time::OffsetDateTime::now_utc()),
    };
    evidence.insert(&ctx.db).await?;

    let service = CorrelationService::default();
    let tx = ctx.db.begin().await?;
    let result = service.correlate_sbom(sbom_id, false, &tx).await?;

    assert_eq!(result.verdicts.len(), 1);
    let verdict = &result.verdicts[0];
    assert_eq!(verdict.vulnerability.id, "CVE-2023-33201");
    assert_eq!(verdict.status, VerdictStatus::Affected);
    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].extractor, "digest");
    assert!(result.unmatched_components.is_none());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn include_unmatched_returns_components_without_evidence(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let sbom = ctx.ingest_document("spdx/simple.json").await?;
    let advisory = ctx.ingest_document("csaf/cve-2023-33201.json").await?;

    let sbom_id = Uuid::parse_str(&sbom.id)?;
    let advisory_id = Uuid::parse_str(&advisory.id)?;

    let evidence = correlation_evidence::ActiveModel {
        id: Set(Uuid::new_v4()),
        sbom_id: Set(sbom_id),
        node_id: Set("SPDXRef-A".to_string()),
        advisory_id: Set(advisory_id),
        vulnerability_id: Set("CVE-2023-33201".to_string()),
        status: Set(AssertionStatus::Affected),

        confidence: Set(0.9),
        extractor: Set("digest".to_string()),
        matched_value: Set(None),
        created_at: Set(time::OffsetDateTime::now_utc()),
    };
    evidence.insert(&ctx.db).await?;

    let service = CorrelationService::default();
    let tx = ctx.db.begin().await?;
    let result = service.correlate_sbom(sbom_id, true, &tx).await?;

    assert_eq!(result.verdicts.len(), 1);
    assert_eq!(result.verdicts[0].component.node_id, "SPDXRef-A");

    let unmatched = result
        .unmatched_components
        .as_ref()
        .expect("should be Some");
    assert!(
        !unmatched.is_empty(),
        "should contain components without evidence"
    );
    assert!(
        !unmatched.iter().any(|c| c.node_id == "SPDXRef-A"),
        "matched component should not appear in unmatched"
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn include_unmatched_no_evidence_returns_all_components(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let sbom = ctx.ingest_document("spdx/simple.json").await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;

    let service = CorrelationService::default();
    let tx = ctx.db.begin().await?;
    let result = service.correlate_sbom(sbom_id, true, &tx).await?;

    assert!(result.verdicts.is_empty());
    let unmatched = result
        .unmatched_components
        .as_ref()
        .expect("should be Some");
    assert!(
        !unmatched.is_empty(),
        "should contain all package components"
    );

    Ok(())
}

const S18_DIGEST: &str = "d62b79b11e2ec822514b5b75fc7733e274b7efc722a3d099e10c4e1184dcf849";

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn query_digest(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let advisory = ctx
        .ingest_document("scenarios/S18_digest_correlation/vex/vde-2025-106.json")
        .await?;
    let advisory_id = Uuid::parse_str(&advisory.id)?;

    let service = CorrelationService::default();
    let tx = ctx.db.begin().await?;

    let digest = |value: String| IdentifierRef {
        kind: IdentifierKind::Digest,
        value,
    };

    let expected = |query: IdentifierRef| QueryResult {
        query,
        verdicts: vec![QueryVerdict {
            vulnerability_id: "CVE-2025-41768".into(),
            vulnerability_title: None,
            status: VerdictStatus::Fixed,
            matches: vec![QueryMatch {
                kind: IdentifierKind::Digest,
                value: MatchedValue::new(format!("sha256:{S18_DIGEST}")),
                advisory_id,
                advisory_identifier: "https://www.beckhoff.com/#VDE-2025-106".into(),
                status: ApiAssertionStatus::Fixed,
                extractor: "digest".into(),
                confidence: 1.0,
            }],
        }],
    };

    // bare value matches any algorithm
    let query = digest(S18_DIGEST.into());
    assert_eq!(
        service.query_identifier(query.clone(), &tx).await?,
        expected(query)
    );

    // explicit algorithm must match
    let query = digest(format!("sha256:{S18_DIGEST}"));
    assert_eq!(
        service.query_identifier(query.clone(), &tx).await?,
        expected(query)
    );

    let query = digest(format!("md5:{S18_DIGEST}"));
    assert_eq!(
        service.query_identifier(query.clone(), &tx).await?,
        QueryResult {
            query,
            verdicts: vec![],
        }
    );

    Ok(())
}

/// The query re-uses the extractor matching, including CSAF wildcards.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn query_wildcard_sku(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let advisory = ctx
        .ingest_document("scenarios/S19_sku_correlation/vex/hbsa-2025-0004.json")
        .await?;
    let advisory_id = Uuid::parse_str(&advisory.id)?;

    let service = CorrelationService::default();
    let tx = ctx.db.begin().await?;

    let sku = IdentifierRef {
        kind: IdentifierKind::Sku,
        value: "6925281924439".into(),
    };
    assert_eq!(
        service.query_identifier(sku.clone(), &tx).await?,
        QueryResult {
            query: sku,
            verdicts: vec![QueryVerdict {
                vulnerability_id: "CVE-2026-50001".into(),
                vulnerability_title: None,
                status: VerdictStatus::Affected,
                matches: vec![QueryMatch {
                    kind: IdentifierKind::Sku,
                    value: MatchedValue::new("6925281*"),
                    advisory_id,
                    advisory_identifier: "https://www.harman.com/#HBSA-2025-0004".into(),
                    status: ApiAssertionStatus::Affected,
                    extractor: "product_identifier".into(),
                    confidence: 1.0,
                }],
            }],
        }
    );

    // the same value as a different kind doesn't match
    let model_number = IdentifierRef {
        kind: IdentifierKind::ModelNumber,
        value: "6925281924439".into(),
    };
    assert_eq!(
        service.query_identifier(model_number.clone(), &tx).await?,
        QueryResult {
            query: model_number,
            verdicts: vec![],
        }
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn components_list_identifiers(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let sbom = ctx
        .ingest_document("scenarios/S19_sku_correlation/sbom/jbl_flip4.cdx.json")
        .await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;

    let service = CorrelationService::default();
    let tx = ctx.db.begin().await?;

    let component =
        |node_id: &str, name: &str, identifiers: &[(IdentifierKind, &str)]| ComponentRef {
            node_id: node_id.into(),
            name: name.into(),
            identifiers: identifiers
                .iter()
                .map(|(kind, value)| IdentifierRef {
                    kind: *kind,
                    value: (*value).into(),
                })
                .collect(),
        };

    assert_eq!(
        service.correlate_sbom(sbom_id, true, &tx).await?,
        CorrelationResult {
            sbom_id,
            verdicts: vec![],
            unmatched_components: Some(vec![
                component(
                    "comp-bt-lib",
                    "bluetooth-stack",
                    &[(IdentifierKind::Purl, "pkg:generic/bluetooth-stack@3.0.0")],
                ),
                component(
                    "comp-flip4-device",
                    "JBL Flip 4 Speaker",
                    &[
                        (IdentifierKind::SerialNumber, "SN-JBL-FLIP4-001"),
                        (IdentifierKind::Sku, "050036337366"),
                        (IdentifierKind::Sku, "6925281924439"),
                    ],
                ),
                component(
                    "comp-flip4-fw",
                    "JBL Flip 4 Firmware",
                    &[(IdentifierKind::ModelNumber, "Flip 4")],
                ),
                component("jbl-flip4-root", "JBL Flip 4", &[]),
            ]),
        }
    );

    Ok(())
}

/// Expected verdicts of a correlation scenario (`expected.json`).
#[derive(serde::Deserialize)]
struct Scenario {
    advisories: Vec<String>,
    /// SBOM file -> node ID -> vulnerability -> verdict status
    sboms: BTreeMap<String, BTreeMap<String, BTreeMap<String, VerdictStatus>>>,
}

/// Run a scenario: ingest its documents, extract evidence, and compare the verdicts with
/// `expected.json`. Components without a verdict must not appear.
#[test_context(TrustifyContext)]
#[rstest]
#[case("S20_cpe_range_wago")]
#[case("S21_cpe_extended_attributes_beckhoff")]
#[case("S22_cpe_third_party_openssl_phoenix")]
#[test_log::test(actix_web::test)]
async fn scenario(ctx: &TrustifyContext, #[case] name: &str) -> anyhow::Result<()> {
    let base = format!("scenarios/{name}");
    let expected: Scenario =
        serde_json::from_slice(&document_bytes(format!("{base}/expected.json")).await?)?;

    for advisory in &expected.advisories {
        ctx.ingest_document(&format!("{base}/{advisory}")).await?;
    }

    let service = CorrelationService::default();
    for (sbom, expected) in expected.sboms {
        let sbom_id = Uuid::parse_str(&ctx.ingest_document(&format!("{base}/{sbom}")).await?.id)?;

        let tx = ctx.db.begin().await?;
        Extractors::default().extract_for_sbom(sbom_id, &tx).await?;
        tx.commit().await?;

        let tx = ctx.db.begin().await?;
        let mut actual = BTreeMap::<_, BTreeMap<_, _>>::new();
        for verdict in service.correlate_sbom(sbom_id, false, &tx).await?.verdicts {
            actual
                .entry(verdict.component.node_id)
                .or_default()
                .insert(verdict.vulnerability.id, verdict.status);
        }

        assert_eq!(actual, expected, "{name}: {sbom}");

        // the counts must agree with the verdicts
        let mut counts = SbomVerdictCounts {
            sbom_id,
            ..Default::default()
        };
        for status in actual.values().flat_map(BTreeMap::values) {
            match status {
                VerdictStatus::Affected => counts.affected += 1,
                VerdictStatus::Fixed => counts.fixed += 1,
                VerdictStatus::NotAffected => counts.not_affected += 1,
                VerdictStatus::UnderInvestigation => counts.under_investigation += 1,
                VerdictStatus::None => counts.none += 1,
            }
        }
        assert_eq!(
            service.count_verdicts(&[sbom_id], &tx).await?,
            vec![counts],
            "{name}: {sbom}"
        );
    }

    Ok(())
}

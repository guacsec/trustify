use crate::extractor::Extractors;
use crate::{
    model::{
        ApiAssertionStatus, AssertionOrigin, ComponentRef, CorrelationResult, IdentifierKind,
        IdentifierRef, MatchedValue, QueryMatch, QueryResult, QueryVerdict, SbomVerdictCounts,
        VerdictStatus,
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
            resolution: crate::model::ResolutionSummary {
                decision_weight: 0.625,
                confidence: 1.0,
                has_conflict: false,
                explanation: None,
            },
            vulnerability_id: "CVE-2025-41768".into(),
            vulnerability_title: None,
            status: VerdictStatus::Fixed,
            matches: vec![QueryMatch {
                kind: IdentifierKind::Digest,
                value: MatchedValue::new(format!("sha256:{S18_DIGEST}")),
                advisory_id,
                advisory_identifier: "https://www.beckhoff.com/#VDE-2025-106".into(),
                advisory_type: Some("csaf".into()),
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
                resolution: crate::model::ResolutionSummary {
                    decision_weight: 0.625,
                    confidence: 1.0,
                    has_conflict: false,
                    explanation: None
                },
                vulnerability_id: "CVE-2026-50001".into(),
                vulnerability_title: None,
                status: VerdictStatus::Affected,
                matches: vec![QueryMatch {
                    kind: IdentifierKind::Sku,
                    value: MatchedValue::new("6925281*"),
                    advisory_id,
                    advisory_identifier: "https://www.harman.com/#HBSA-2025-0004".into(),
                    advisory_type: Some("csaf".into()),
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

/// Expected verdicts of a correlation scenario (`expected*.json`).
#[derive(serde::Deserialize)]
struct Scenario {
    advisories: Vec<String>,
    /// SBOM file -> node ID -> vulnerability -> verdict status
    sboms: BTreeMap<String, BTreeMap<String, BTreeMap<String, VerdictStatus>>>,
}

/// Run a scenario: ingest its documents, extracting evidence after each one as the extraction
/// worker does, and compare the verdicts with the selected manifest. Components without a verdict
/// must not appear. Separate manifests isolate advisory formats. The verdicts must not depend on
/// whether the SBOMs or the advisories come first.
#[test_context(TrustifyContext)]
#[rstest]
#[case::s1_combined("S1_crossstream_bind-libs", "expected.json")]
#[case::s2_combined("S2_wrongscheme_golang_oci", "expected.json")]
#[case::s3_combined("S3_wrongproduct_hummingbird_curl", "expected.json")]
#[case::s4_combined("S4_wrongproduct_satellite_chardet", "expected.json")]
#[case::s4_cve("S4_wrongproduct_satellite_chardet", "expected-cve.json")]
#[case::s4_vex("S4_wrongproduct_satellite_chardet", "expected-vex.json")]
#[case::s5_combined("S5_positive_baseline_openssl_el8", "expected.json")]
#[case::s5_cve("S5_positive_baseline_openssl_el8", "expected-cve.json")]
#[case::s5_vex("S5_positive_baseline_openssl_el8", "expected-vex.json")]
#[case::s6_combined("S6_positive_baseline_osv_urllib3", "expected.json")]
#[case::s8_combined("S8_epoch_mismatch_openjdk", "expected.json")]
#[case::s8_cve("S8_epoch_mismatch_openjdk", "expected-cve.json")]
#[case::s8_vex("S8_epoch_mismatch_openjdk", "expected-vex.json")]
#[case::s9_combined("S9_substream_openssl_el8", "expected.json")]
#[case::s9_cve("S9_substream_openssl_el8", "expected-cve.json")]
#[case::s9_vex("S9_substream_openssl_el8", "expected-vex.json")]
#[case::s10_combined("S10_combined_describing_cpe", "expected.json")]
#[case::s10_cve("S10_combined_describing_cpe", "expected-cve.json")]
#[case::s10_osv("S10_combined_describing_cpe", "expected-osv.json")]
#[case::s10_vex("S10_combined_describing_cpe", "expected-vex.json")]
#[case::s12_combined("S12_notaffected_ignored_thunderbird", "expected.json")]
#[case::s11_reviewed("S11_bareaffected_substream_firefox", "expected-reviewed.json")]
#[case::s12_control("S12_notaffected_ignored_thunderbird", "expected-control.json")]
#[case::s13_combined("S13_aliasless_osv_drop", "expected.json")]
#[case::s14_combined("S14_productstatus_versionfilter_netty", "expected.json")]
#[case::s15_combined("S15_versioncmp_rpm_openssh", "expected.json")]
#[case::s16_combined("S16_crossscheme_purlquery_golang", "expected.json")]
#[case::s17_combined("S17_crossproduct_ocp_kernel_go", "expected.json")]
#[case::s18_combined("S18_crossproduct_curl_notaffected", "expected.json")]
#[case::s20_combined("S20_cpe_range_wago", "expected.json")]
#[case::s21_combined("S21_cpe_extended_attributes_beckhoff", "expected.json")]
#[case::s22_combined("S22_cpe_third_party_openssl_phoenix", "expected.json")]
#[case::s23_combined("S23_suse_codestream_openssl", "expected.json")]
#[case::s24_combined("S24_rhel10_minor_streams_ubi10", "expected.json")]
#[case::s25_combined("S25_cve_package_url", "expected.json")]
#[case::s26_combined("S26_cve_cpe_applicability_kernel", "expected.json")]
#[case::s27_combined("S27_cve_identifier_synonyms_log4j", "expected.json")]
#[case::s29_provider("S29_provider_weighting", "expected.json")]
#[case::s28_regression("S28_fixed_then_regression", "expected.json")]
#[test_log::test(actix_web::test)]
async fn scenario(
    ctx: &TrustifyContext,
    #[case] name: &str,
    #[case] expectations: &str,
    #[values(false, true)] sboms_first: bool,
) -> anyhow::Result<()> {
    let base = format!("scenarios/{name}");
    let expected: Scenario =
        serde_json::from_slice(&document_bytes(format!("{base}/{expectations}")).await?)?;

    if name == "S29_provider_weighting" {
        let tx = ctx.db.begin().await?;
        for provider in ["A", "B"] {
            super::weighting::store::save_alias(
                None,
                crate::model::ProviderAliasData {
                    provider: provider.into(),
                    aliases: vec![format!("name:Provider {provider}")],
                },
                &tx,
            )
            .await?;
        }
        tx.commit().await?;
    }
    let extractors = Extractors::default();
    let ingest_advisories = async || -> anyhow::Result<()> {
        for advisory in &expected.advisories {
            let id = ctx.ingest_document(&format!("{base}/{advisory}")).await?.id;
            let tx = ctx.db.begin().await?;
            extractors
                .extract_for_advisory(Uuid::parse_str(&id)?, &tx)
                .await?;
            tx.commit().await?;
        }
        Ok(())
    };

    if !sboms_first {
        ingest_advisories().await?;
    }
    let mut sboms = Vec::with_capacity(expected.sboms.len());
    for (sbom, expected) in &expected.sboms {
        let sbom_id = Uuid::parse_str(&ctx.ingest_document(&format!("{base}/{sbom}")).await?.id)?;
        let tx = ctx.db.begin().await?;
        extractors.extract_for_sbom(sbom_id, &tx).await?;
        tx.commit().await?;
        sboms.push((sbom, sbom_id, expected));
    }
    if sboms_first {
        ingest_advisories().await?;
    }

    let service = CorrelationService::default();
    for (sbom, sbom_id, expected) in sboms {
        let tx = ctx.db.begin().await?;
        let mut actual = BTreeMap::<_, BTreeMap<_, _>>::new();
        for verdict in service
            .correlate_sbom_with(
                sbom_id,
                false,
                &crate::model::ResolutionRequest {
                    include_explanation: name == "S23_suse_codestream_openssl",
                    ..Default::default()
                },
                &tx,
            )
            .await?
            .verdicts
        {
            if name == "S23_suse_codestream_openssl"
                && verdict.component.name == "openssl"
                && verdict.vulnerability.id == "CVE-2025-9230"
            {
                assert!(verdict.resolution.has_conflict);
                assert!(verdict.resolution.explanation.as_ref().unwrap().tie_break);
            }
            actual
                .entry(verdict.component.node_id)
                .or_default()
                .insert(verdict.vulnerability.id, verdict.status);
        }

        assert_eq!(
            &actual, expected,
            "{name} ({expectations}): {sbom}, SBOMs first: {sboms_first}"
        );

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

/// Both the materialized and live paths retain the statements explaining a regression.
#[test_context(TrustifyContext)]
#[rstest]
#[test_log::test(actix_web::test)]
async fn regression_evidence_and_query(
    ctx: &TrustifyContext,
    #[values("cdx", "spdx")] format: &str,
    #[values(false, true)] sboms_first: bool,
) -> anyhow::Result<()> {
    const BASE: &str = "scenarios/S28_fixed_then_regression";
    let extractors = Extractors::default();
    let ingest_advisory = async || -> anyhow::Result<()> {
        let advisory = ctx
            .ingest_document(&format!("{BASE}/vex/regression.json"))
            .await?;
        let tx = ctx.db.begin().await?;
        extractors
            .extract_for_advisory(Uuid::parse_str(&advisory.id)?, &tx)
            .await?;
        tx.commit().await?;
        Ok(())
    };
    if !sboms_first {
        ingest_advisory().await?;
    }
    let sbom = ctx
        .ingest_document(&format!("{BASE}/sbom/regression.{format}.json"))
        .await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;
    let tx = ctx.db.begin().await?;
    extractors.extract_for_sbom(sbom_id, &tx).await?;
    tx.commit().await?;
    if sboms_first {
        ingest_advisory().await?;
    }

    let tx = ctx.db.begin().await?;
    let service = CorrelationService::default();
    let result = service.correlate_sbom(sbom_id, false, &tx).await?;
    let node = if format == "cdx" {
        "regression"
    } else {
        "SPDXRef-regression"
    };
    let regression = result
        .verdicts
        .iter()
        .find(|v| v.component.node_id == node)
        .unwrap();
    assert_eq!(regression.status, VerdictStatus::Affected);
    assert!(regression.evidence.iter().any(|e| {
        e.assertion_status == ApiAssertionStatus::Affected
            && e.matched_value
                .as_ref()
                .is_some_and(|v| v.origin == AssertionOrigin::Stated)
    }));
    assert!(regression.evidence.iter().any(|e| {
        e.assertion_status == ApiAssertionStatus::Fixed
            && e.matched_value
                .as_ref()
                .is_some_and(|v| v.origin == AssertionOrigin::PublisherPolicy)
    }));

    for (version, major, status) in [
        (1, 9, Some(VerdictStatus::Affected)),
        (2, 9, Some(VerdictStatus::Fixed)),
        (3, 9, Some(VerdictStatus::Affected)),
        (4, 9, Some(VerdictStatus::Fixed)),
        (5, 9, Some(VerdictStatus::Fixed)),
        (3, 8, None),
    ] {
        let query = service
            .query_identifier(
                IdentifierRef {
                    kind: IdentifierKind::Purl,
                    value: format!(
                        "pkg:rpm/redhat/demo-regression@1.0-{version}.el{major}?arch=x86_64"
                    ),
                },
                &tx,
            )
            .await?;
        assert_eq!(
            query.verdicts.iter().map(|v| v.status).collect::<Vec<_>>(),
            status.into_iter().collect::<Vec<_>>()
        );
        if version == 3 && major == 9 {
            let matches = &query.verdicts[0].matches;
            assert!(
                matches
                    .iter()
                    .any(|m| m.status == ApiAssertionStatus::Affected
                        && m.value.origin == AssertionOrigin::Stated)
            );
            assert!(matches.iter().any(|m| m.status == ApiAssertionStatus::Fixed
                && m.value.origin == AssertionOrigin::PublisherPolicy));
        }
    }
    let identifier = IdentifierRef {
        kind: IdentifierKind::Purl,
        value: "pkg:rpm/redhat/demo-regression@1.0-3.el9?arch=x86_64".into(),
    };
    for (major, expected) in [(8, 0), (9, 1)] {
        let contextual = service
            .query_identifier_with(
                identifier.clone(),
                &crate::model::ResolutionRequest {
                    product_context: vec![IdentifierRef {
                        kind: IdentifierKind::Cpe,
                        value: format!("cpe:/o:redhat:enterprise_linux:{major}"),
                    }],
                    ..Default::default()
                },
                &tx,
            )
            .await?;
        assert_eq!(contextual.verdicts.len(), expected);
    }
    Ok(())
}

/// Settings re-resolve existing evidence at every scope, without a re-extraction.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn provider_policy_inheritance_and_preview(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use super::weighting::store;
    use crate::model::{
        PolicyScope, ProviderAliasData, ResolutionRequest, WeightOverrides, WeightPolicyData,
    };
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use trustify_entity::{sbom_group, sbom_group_assignment};
    let tx = ctx.db.begin().await?;
    for provider in ["A", "B"] {
        store::save_alias(
            None,
            ProviderAliasData {
                provider: provider.into(),
                aliases: vec![format!("name:Provider {provider}")],
            },
            &tx,
        )
        .await?;
    }
    tx.commit().await?;
    for file in ["cve/providers.json", "osv/generic.json"] {
        ctx.ingest_document(&format!("scenarios/S29_provider_weighting/{file}"))
            .await?;
    }
    let sbom = ctx
        .ingest_document("scenarios/S29_provider_weighting/sbom/providers.cdx.json")
        .await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;
    let tx = ctx.db.begin().await?;
    Extractors::default().extract_for_sbom(sbom_id, &tx).await?;
    tx.commit().await?;
    let tx = ctx.db.begin().await?;
    let service = CorrelationService::default();
    let rows = correlation_evidence::Entity::find()
        .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
        .all(&tx)
        .await?;
    let request = ResolutionRequest {
        include_explanation: true,
        node_id: Some("b-build".into()),
        ..Default::default()
    };
    let read = service
        .correlate_sbom_with(sbom_id, false, &request, &tx)
        .await?;
    let verdict = &read.verdicts[0];
    assert_eq!(verdict.status, VerdictStatus::NotAffected);
    assert!(verdict.resolution.has_conflict);
    assert_eq!(verdict.evidence.len(), 3);
    let trace = verdict.resolution.explanation.as_ref().unwrap();
    assert_eq!(trace.component_provider.provider.as_deref(), Some("B"));
    assert_eq!(trace.component_provider.source, "component supplier");
    assert_eq!(
        trace
            .evidence
            .iter()
            .filter(|e| e.provider.provider.as_deref() == Some("B"))
            .count(),
        1
    );
    assert!(verdict.resolution.confidence > 0.0 && verdict.resolution.confidence < 1.0);
    let original_revision = trace.policy_revision;
    let inherited = service
        .correlate_sbom_with(
            sbom_id,
            false,
            &ResolutionRequest {
                include_explanation: true,
                node_id: Some("inherited-build".into()),
                ..Default::default()
            },
            &tx,
        )
        .await?;
    let inherited_provider = &inherited.verdicts[0]
        .resolution
        .explanation
        .as_ref()
        .unwrap()
        .component_provider;
    assert_eq!(inherited_provider.provider.as_deref(), Some("A"));
    assert_eq!(inherited_provider.source, "product supplier");

    let root = Uuid::now_v7();
    let child = Uuid::now_v7();
    for (id, parent) in [(root, None), (child, Some(root))] {
        sbom_group::ActiveModel {
            id: Set(id),
            parent: Set(parent),
            name: Set(id.to_string()),
            revision: Set(Uuid::now_v7()),
            description: Set(None),
            labels: Set(Default::default()),
        }
        .insert(&tx)
        .await?;
    }
    sbom_group_assignment::ActiveModel {
        sbom_id: Set(sbom_id),
        group_id: Set(child),
    }
    .insert(&tx)
    .await?;
    for (scope, value) in [
        (PolicyScope::Instance, 1.1),
        (PolicyScope::Group { group_id: root }, 1.2),
        (PolicyScope::Group { group_id: child }, 1.3),
        (PolicyScope::Sbom { sbom_id }, 1.4),
        (
            PolicyScope::Component {
                sbom_id,
                node_id: "b-build".into(),
            },
            1.5,
        ),
    ] {
        store::save_policy(
            None,
            WeightPolicyData {
                scope,
                priority: 0,
                weights: WeightOverrides {
                    matching_provider: Some(value),
                    ..Default::default()
                },
            },
            &tx,
        )
        .await?;
        let read = service
            .correlate_sbom_with(sbom_id, false, &request, &tx)
            .await?;
        let trace = read.verdicts[0].resolution.explanation.as_ref().unwrap();
        assert_eq!(
            trace.settings["matching_provider"].value,
            serde_json::json!(value)
        );
        assert_ne!(trace.policy_revision, original_revision);
    }
    let temporary = ResolutionRequest {
        overrides: WeightOverrides {
            providers: BTreeMap::from([("B".into(), 0.0)]),
            matching_provider: Some(1.6),
            ..Default::default()
        },
        ..request.clone()
    };
    let preview = service
        .correlate_sbom_with(sbom_id, false, &temporary, &tx)
        .await?;
    assert_eq!(preview.verdicts[0].status, VerdictStatus::Affected);
    assert_eq!(
        preview.verdicts[0]
            .resolution
            .explanation
            .as_ref()
            .unwrap()
            .settings["matching_provider"]
            .origin
            .source,
        "request override"
    );
    let ordinary = service
        .correlate_sbom_with(sbom_id, false, &request, &tx)
        .await?;
    assert_eq!(ordinary.verdicts[0].status, VerdictStatus::NotAffected);
    let counts = service.count_verdicts(&[sbom_id, sbom_id], &tx).await?;
    assert_eq!(counts[0], counts[1]);
    assert_eq!((counts[0].affected, counts[0].not_affected), (2, 1));
    assert_eq!(
        correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
            .all(&tx)
            .await?,
        rows
    );
    let query = service
        .query_identifier_with(
            IdentifierRef {
                kind: IdentifierKind::Purl,
                value: "pkg:generic/demo-weighting@1.0.0".into(),
            },
            &ResolutionRequest {
                include_explanation: true,
                overrides: WeightOverrides {
                    component_provider: Some("B".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
            &tx,
        )
        .await?;
    assert_eq!(query.verdicts[0].status, VerdictStatus::NotAffected);
    assert_eq!(query.verdicts[0].matches.len(), 3);
    Ok(())
}

/// The evidence of a statement in a product lists that product, and how the component got into it.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn evidence_contexts(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use crate::model::{ContextCategory, ContextSource, EvidenceContext};

    let sbom = ctx
        .ingest_document(
            "scenarios/S16_crossscheme_purlquery_golang/sbom_golang_rpm_storage3.cdx.json",
        )
        .await?;
    ctx.ingest_document("csaf/versionless/redhat.json").await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;

    let tx = ctx.db.begin().await?;
    Extractors::default().extract_for_sbom(sbom_id, &tx).await?;
    let result = CorrelationService::default()
        .correlate_sbom(sbom_id, false, &tx)
        .await?;

    let contexts = result
        .verdicts
        .iter()
        .flat_map(|verdict| &verdict.evidence)
        .flat_map(|evidence| &evidence.contexts)
        .map(|context| EvidenceContext {
            // generated
            context_id: Uuid::nil(),
            ..context.clone()
        })
        .collect::<Vec<_>>();
    let storage = "cpe:2.3:a:redhat:storage:3:*:*:*:*:*:*:*".to_string();
    assert_eq!(
        contexts,
        [EvidenceContext {
            context_id: Uuid::nil(),
            name: "Red Hat Storage 3".into(),
            category: Some(ContextCategory::DefaultComponentOf),
            source: ContextSource::AncestorNode,
            distance: 1,
            node_identifier: storage.clone(),
            context_identifier: storage,
            confidence: 0.9,
        }]
    );

    Ok(())
}

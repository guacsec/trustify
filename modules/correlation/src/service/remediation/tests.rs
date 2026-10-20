use crate::{
    extractor::Extractors,
    model::{
        EvidenceRemediation, IdentifierKind, IdentifierRef, RemediationCategory, ResolutionRequest,
        VerdictStatus,
    },
    service::CorrelationService,
};
use rstest::rstest;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};
use serde_json::{Value, json};
use test_context::test_context;
use trustify_entity::{correlation_evidence, correlation_evidence::SourceAssertionRef};
use trustify_test_context::{TrustifyContext, document_bytes};
use uuid::Uuid;

const CVE: &str = "CVE-2099-2738";
const PLATFORM: &str = "cpe:2.3:h:scope:device:1.0.0:*:*:*:*:*:*:*";

fn cpe(version: u8) -> String {
    format!("cpe:2.3:a:scope:widget:{version}.0.0:*:*:*:*:*:*:*")
}
fn fix(version: u8) -> EvidenceRemediation {
    EvidenceRemediation {
        category: RemediationCategory::VendorFix,
        details: Some(format!("Fix for widget {version}")),
        url: Some(format!("https://example.com/fix/{version}")),
    }
}

async fn advisory(form: &str) -> anyhow::Result<Value> {
    let mut document: Value =
        serde_json::from_slice(&document_bytes("csaf/cve-2023-0044.json").await?)?;
    document["document"]["tracking"]["id"] = json!("remediation-scopes");
    document["product_tree"] = json!({
        "branches": [{"category": "vendor", "name": "Scope", "branches": [
            {"category": "product_name", "name": "Widget", "branches": [
                {"category": "product_version", "name": "1.0.0", "product": {
                    "name": "Widget 1", "product_id": "p1", "product_identification_helper": {
                        "purl": "pkg:generic/widget@1.0.0", "cpe": cpe(1),
                        "hashes": [{"filename": "widget.bin", "file_hashes": [{"algorithm": "SHA-256", "value": "a".repeat(64)}]}],
                        "skus": ["widget-sku"], "model_numbers": ["widget-model"], "serial_numbers": ["widget-serial"]
                    }}},
                {"category": "product_version", "name": "2.0.0", "product": {
                    "name": "Widget 2", "product_id": "p2", "product_identification_helper": {
                        "purl": "pkg:generic/widget@2.0.0", "cpe": cpe(2),
                        "hashes": [{"filename": "widget.bin", "file_hashes": [{"algorithm": "sha256", "value": "b".repeat(64)}]}],
                        "skus": ["widget-sku"], "model_numbers": ["widget-model"], "serial_numbers": ["widget-serial"]
                    }}}
            ]}
        ]}],
        "full_product_names": [{"name": "Device", "product_id": "device", "product_identification_helper": {"cpe": PLATFORM}}],
        "relationships": [
            {"category": "installed_on", "product_reference": "p1", "relates_to_product_reference": "device", "full_product_name": {"name": "Widget 1 on device", "product_id": "r1"}},
            {"category": "installed_on", "product_reference": "p2", "relates_to_product_reference": "device", "full_product_name": {"name": "Widget 2 on device", "product_id": "r2"}}
        ],
        "product_groups": [
            {"group_id": "g1", "product_ids": ["r1"]},
            {"group_id": "g1-duplicate", "product_ids": ["r1"]},
            {"group_id": "g2", "product_ids": ["r2"]}
        ]
    });
    let remediations = (1..=2)
        .map(|version| {
            let mut remediation = serde_json::to_value(fix(version)).unwrap();
            match form {
                "direct" => remediation["product_ids"] = json!([format!("r{version}")]),
                "groups" => remediation["group_ids"] = json!([format!("g{version}")]),
                "mixed" => {
                    remediation["product_ids"] = json!([format!("r{version}")]);
                    remediation["group_ids"] = if version == 1 {
                        json!(["g1", "g1-duplicate"])
                    } else {
                        json!(["g2"])
                    };
                }
                _ => unreachable!(),
            }
            remediation
        })
        .collect::<Vec<_>>();
    document["vulnerabilities"] = json!([{
        "cve": CVE, "product_status": {"known_affected": ["r1", "r2"]},
        "remediations": remediations
    }]);
    Ok(document)
}

fn sbom(platform: &str) -> Value {
    let components = (1..=2).map(|version| json!({
        "type": "firmware", "bom-ref": format!("widget-{version}"), "name": "widget", "version": format!("{version}.0.0"),
        "purl": format!("pkg:generic/widget@{version}.0.0"), "cpe": cpe(version),
        "hashes": [{"alg": "SHA-256", "content": if version == 1 { "a".repeat(64) } else { "b".repeat(64) }}],
        "properties": [
            {"name": "cdx:device:sku", "value": "widget-sku"},
            {"name": "cdx:device:gs1:gmn", "value": "widget-model"},
            {"name": "cdx:device:serialNumber", "value": "widget-serial"}
        ]
    })).collect::<Vec<_>>();
    json!({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "device", "bom-ref": "device", "name": "device", "version": "1.0.0", "cpe": platform}},
        "components": components,
        "dependencies": [{"ref": "device", "dependsOn": ["widget-1", "widget-2"]}]
    })
}

#[test_context(TrustifyContext)]
#[rstest]
#[case::direct("direct")]
#[case::groups("groups")]
#[case::mixed("mixed")]
#[test_log::test(actix_web::test)]
async fn remediation_scopes(
    ctx: &TrustifyContext,
    #[case] form: &str,
    #[values(false, true)] from_advisory: bool,
) -> anyhow::Result<()> {
    let document = advisory(form).await?;
    let advisory = ctx
        .ingest_read(serde_json::to_vec(&document)?.as_slice())
        .await?;
    let advisory_id = Uuid::parse_str(&advisory.id)?;
    let sbom_result = ctx
        .ingest_read(serde_json::to_vec(&sbom(PLATFORM))?.as_slice())
        .await?;
    let sbom_id = Uuid::parse_str(&sbom_result.id)?;
    let tx = ctx.db.begin().await?;
    let extractors = Extractors::default();
    if from_advisory {
        extractors.extract_for_advisory(advisory_id, &tx).await?;
    } else {
        extractors.extract_for_sbom(sbom_id, &tx).await?;
    }
    // Repeat extraction must preserve the exact source set, including ON CONFLICT handling.
    extractors.extract_for_sbom(sbom_id, &tx).await?;
    tx.commit().await?;
    let service = CorrelationService::default();
    let tx = ctx.db.begin().await?;
    let request = ResolutionRequest {
        include_explanation: true,
        ..Default::default()
    };
    let result = service
        .correlate_sbom_with(sbom_id, false, &request, &tx)
        .await?;
    assert_eq!(result.verdicts.len(), 2);
    for verdict in &result.verdicts {
        let version = if verdict.component.node_id == "widget-1" {
            1
        } else {
            2
        };
        assert_eq!(verdict.status, VerdictStatus::Affected);
        let kinds = verdict
            .evidence
            .iter()
            .map(|e| e.extractor.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            kinds,
            ["purl", "cpe", "digest", "product_identifier"].into()
        );
        for evidence in &verdict.evidence {
            assert_eq!(evidence.remediations, vec![fix(version)], "{evidence:?}");
        }
        for evidence in &verdict.resolution.explanation.as_ref().unwrap().evidence {
            assert_eq!(evidence.remediations, vec![fix(version)]);
        }
    }
    assert_eq!(
        service.count_verdicts(&[sbom_id], &tx).await?[0].remediations,
        2
    );
    let evidence = correlation_evidence::Entity::find()
        .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
        .all(&tx)
        .await?;
    for row in &evidence {
        let sources: std::collections::BTreeSet<SourceAssertionRef> =
            serde_json::from_value(row.source_assertions.clone())?;
        // The three product identifiers merge into one evidence record.
        assert_eq!(
            sources.len(),
            if row.extractor == "product_identifier" {
                3
            } else {
                1
            }
        );
    }
    // Pre-upgrade evidence without source references keeps its existing PURL lookup.
    let mut legacy = evidence
        .iter()
        .find(|row| row.extractor == "purl" && row.node_id == "widget-1")
        .unwrap()
        .clone();
    legacy.source_assertions = json!([]);
    let legacy_id = legacy.id;
    assert_eq!(
        super::super::load_evidence_remediations(&[legacy], &tx).await?[&legacy_id],
        vec![fix(1)]
    );

    // These PURL-based products retain the legacy PURL associations. Product-status
    // associations are covered with product-version CSAF fixtures in the ingestor tests.
    use trustify_entity::{remediation_product_status, remediation_purl_status};
    assert_eq!(
        remediation_purl_status::Entity::find()
            .all(&tx)
            .await?
            .len(),
        2
    );
    assert_eq!(
        remediation_product_status::Entity::find()
            .all(&tx)
            .await?
            .len(),
        0
    );
    for (kind, value) in [
        (IdentifierKind::Purl, "pkg:generic/widget@1.0.0".to_owned()),
        (IdentifierKind::Cpe, cpe(1)),
        (IdentifierKind::Digest, format!("sha256:{}", "a".repeat(64))),
        (IdentifierKind::Sku, "widget-sku".to_owned()),
        (IdentifierKind::ModelNumber, "widget-model".to_owned()),
        (IdentifierKind::SerialNumber, "widget-serial".to_owned()),
    ] {
        let query = service
            .query_identifier_with(
                IdentifierRef { kind, value },
                &ResolutionRequest {
                    include_explanation: true,
                    product_context: vec![IdentifierRef {
                        kind: IdentifierKind::Cpe,
                        value: PLATFORM.into(),
                    }],
                    ..Default::default()
                },
                &tx,
            )
            .await?;
        assert_eq!(query.verdicts.len(), 1, "{kind:?}");
        for matched in &query.verdicts[0].matches {
            // A bare SKU/model/serial query does not name a version: both versions may match,
            // but each retains only its own remediation.
            let version = if matched
                .value
                .ranges
                .iter()
                .any(|range| range.low.as_ref().is_some_and(|b| b.version == "2.0.0"))
            {
                2
            } else {
                1
            };
            assert_eq!(
                matched.remediations,
                vec![fix(version)],
                "{kind:?}: {matched:?}"
            );
        }
        for explained in &query.verdicts[0]
            .resolution
            .explanation
            .as_ref()
            .unwrap()
            .evidence
        {
            assert_eq!(explained.remediations.len(), 1);
        }
    }
    tx.commit().await?;
    // The same subject on a contradictory platform must not inherit either remediation.
    let wrong = ctx
        .ingest_read(
            serde_json::to_vec(&sbom("cpe:2.3:h:scope:device:2.0.0:*:*:*:*:*:*:*"))?.as_slice(),
        )
        .await?;
    let tx = ctx.db.begin().await?;
    let wrong_id = Uuid::parse_str(&wrong.id)?;
    extractors.extract_for_sbom(wrong_id, &tx).await?;
    assert!(
        service
            .correlate_sbom(wrong_id, false, &tx)
            .await?
            .verdicts
            .is_empty()
    );
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn unresolved_remediation_targets_warn_without_widening(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let mut document = advisory("groups").await?;
    document["vulnerabilities"][0]["remediations"][0]["group_ids"] = json!(["missing-group"]);
    document["vulnerabilities"][0]["remediations"][1]["product_ids"] = json!(["missing-product"]);
    document["vulnerabilities"][0]["remediations"][1]
        .as_object_mut()
        .unwrap()
        .remove("group_ids");
    let advisory = ctx
        .ingest_read(serde_json::to_vec(&document)?.as_slice())
        .await?;
    assert!(
        advisory
            .warnings
            .iter()
            .any(|w| w.contains("missing-group"))
    );
    assert!(
        advisory
            .warnings
            .iter()
            .any(|w| w.contains("missing-product"))
    );
    let tx = ctx.db.begin().await?;
    let query = CorrelationService::default()
        .query_identifier(
            IdentifierRef {
                kind: IdentifierKind::Purl,
                value: "pkg:generic/widget@1.0.0".into(),
            },
            &tx,
        )
        .await?;
    assert!(!query.verdicts.is_empty());
    assert!(
        query
            .verdicts
            .iter()
            .flat_map(|v| &v.matches)
            .all(|m| m.remediations.is_empty())
    );
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn wago_group_remediations(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let sbom = ctx
        .ingest_document("scenarios/S20_cpe_range_wago/sbom/pfc200_fw_4.8.9.cdx.json")
        .await?;
    ctx.ingest_document("scenarios/S20_cpe_range_wago/vex/vde-2025-081.json")
        .await?;
    let tx = ctx.db.begin().await?;
    let id = Uuid::parse_str(&sbom.id)?;
    Extractors::default().extract_for_sbom(id, &tx).await?;
    let result = CorrelationService::default()
        .correlate_sbom(id, false, &tx)
        .await?;
    assert!(!result.verdicts.is_empty());
    for evidence in result.verdicts.iter().flat_map(|v| &v.evidence) {
        assert_eq!(evidence.remediations.len(), 1);
        assert!(
            evidence.remediations[0]
                .details
                .as_ref()
                .unwrap()
                .contains("4.10.0")
        );
    }
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn remediations_preserve_advisory_and_vulnerability_provenance(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    use std::collections::BTreeMap;
    let mut expected = BTreeMap::new();
    for advisory_number in 1..=2 {
        let mut document = advisory("groups").await?;
        document["document"]["tracking"]["id"] =
            json!(format!("remediation-provenance-{advisory_number}"));
        let mut vulnerabilities = Vec::new();
        for vulnerability_number in 1..=2 {
            let mut vulnerability = document["vulnerabilities"][0].clone();
            let cve = format!("CVE-2099-273{vulnerability_number}");
            vulnerability["cve"] = json!(cve);
            let categories = [
                "vendor_fix",
                "workaround",
                "mitigation",
                "no_fix_planned",
                "none_available",
            ];
            let remediations = categories
                .into_iter().map(|category| json!({
                    "category": category, "details": format!("{advisory_number}/{vulnerability_number}/{category}"), "group_ids": ["g1"]
                })).collect::<Vec<_>>();
            vulnerability["remediations"] = json!(remediations);
            vulnerabilities.push(vulnerability);
        }
        document["vulnerabilities"] = json!(vulnerabilities);
        let result = ctx
            .ingest_read(serde_json::to_vec(&document)?.as_slice())
            .await?;
        expected.insert(Uuid::parse_str(&result.id)?, advisory_number);
    }
    let tx = ctx.db.begin().await?;
    let result = CorrelationService::default()
        .query_identifier(
            IdentifierRef {
                kind: IdentifierKind::Purl,
                value: "pkg:generic/widget@1.0.0".into(),
            },
            &tx,
        )
        .await?;
    assert_eq!(result.verdicts.len(), 2);
    for verdict in &result.verdicts {
        let vulnerability_number = if verdict.vulnerability_id == "CVE-2099-2731" {
            1
        } else {
            2
        };
        assert_eq!(verdict.matches.len(), 2);
        for matched in &verdict.matches {
            assert_eq!(matched.remediations.len(), 5);
            let prefix = format!("{}/{vulnerability_number}/", expected[&matched.advisory_id]);
            assert!(
                matched.remediations.iter().all(|r| r
                    .details
                    .as_ref()
                    .unwrap()
                    .starts_with(&prefix))
            );
        }
    }
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn derived_evidence_retains_source_remediations(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let mut document = advisory("groups").await?;
    document["document"]["publisher"]["namespace"] = json!("https://www.redhat.com");
    document["vulnerabilities"][0]["product_status"] = json!({"fixed": ["r2"]});
    // Generic versions support equality only; use Cargo's ordered version scheme for inference.
    let document =
        serde_json::to_string(&document)?.replace("pkg:generic/widget", "pkg:cargo/widget");
    ctx.ingest_read(document.as_bytes()).await?;
    let document =
        serde_json::to_string(&sbom(PLATFORM))?.replace("pkg:generic/widget", "pkg:cargo/widget");
    let sbom = ctx.ingest_read(document.as_bytes()).await?;
    let sbom_id = Uuid::parse_str(&sbom.id)?;
    let tx = ctx.db.begin().await?;
    Extractors::default().extract_for_sbom(sbom_id, &tx).await?;
    let request = ResolutionRequest {
        include_explanation: true,
        ..Default::default()
    };
    let service = CorrelationService::default();
    let result = service
        .correlate_sbom_with(sbom_id, false, &request, &tx)
        .await?;
    let verdict = result
        .verdicts
        .iter()
        .find(|v| v.component.node_id == "widget-1")
        .unwrap();
    assert_eq!(verdict.status, VerdictStatus::Affected);
    let inferred = verdict
        .evidence
        .iter()
        .find(|e| e.extractor == "purl_fixed_as_first_fixed_before")
        .unwrap();
    assert_eq!(inferred.remediations, vec![fix(2)]);
    let request = ResolutionRequest {
        product_context: vec![IdentifierRef {
            kind: IdentifierKind::Cpe,
            value: PLATFORM.into(),
        }],
        ..request
    };
    let query = service
        .query_identifier_with(
            IdentifierRef {
                kind: IdentifierKind::Purl,
                value: "pkg:cargo/widget@1.0.0".into(),
            },
            &request,
            &tx,
        )
        .await?;
    let matched = query.verdicts[0]
        .matches
        .iter()
        .find(|m| m.extractor == "purl_fixed_as_first_fixed_before")
        .unwrap();
    assert_eq!(matched.remediations, inferred.remediations);
    // Unlike the legacy range/status reconstruction, source lookup also works when the
    // evidence's affected range was derived from a fixed statement.
    assert_eq!(query.verdicts[0].status, VerdictStatus::Affected);
    Ok(())
}

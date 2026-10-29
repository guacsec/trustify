use super::*;
use crate::service::projection::publish_for_test;
use sea_orm::{ActiveModelTrait, Set, TransactionTrait};
use test_context::test_context;
use trustify_common::model::Paginated;
use trustify_test_context::TrustifyContext;

async fn fixture(ctx: &TrustifyContext) -> anyhow::Result<(Uuid, Uuid)> {
    // Reverse insertion order, mixed case and non-ASCII IDs exercise the explicit C ordering.
    let ids = (0..30)
        .rev()
        .map(|n| format!("node-{n:02}"))
        .chain(["A", "a", "é", "z", "unmatched-2", "unmatched-1"].map(str::to_string));
    let document = serde_json::json!({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "components": ids.map(|id| serde_json::json!({"type": "library", "bom-ref": id, "name": id, "purl": "pkg:generic/example@1"})).collect::<Vec<_>>()
    });
    let sbom_id = Uuid::parse_str(
        &ctx.ingest_read(serde_json::to_vec(&document)?.as_slice())
            .await?
            .id,
    )?;
    let advisory_id = Uuid::parse_str(&ctx.ingest_document("csaf/cve-2023-33201.json").await?.id)?;
    for node in (0..30)
        .rev()
        .map(|n| format!("node-{n:02}"))
        .chain(["A", "a", "é", "z"].map(str::to_string))
    {
        for vulnerability in ["CVE-2", "CVE-1"] {
            for extractor in ["digest", "cpe"] {
                correlation_evidence::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    sbom_id: Set(sbom_id),
                    node_id: Set(node.clone()),
                    advisory_id: Set(advisory_id),
                    vulnerability_id: Set(vulnerability.into()),
                    status: Set(AssertionStatus::Affected),
                    confidence: Set(1.0),
                    extractor: Set(extractor.into()),
                    matched_value: Set(None),
                    created_at: Set(time::OffsetDateTime::now_utc()),
                    confidence_factors: Set(serde_json::json!([])),
                    source_assertions: Set(
                        serde_json::json!([{"kind": "digest", "id": Uuid::new_v4()}]),
                    ),
                }
                .insert(&ctx.db)
                .await?;
            }
        }
    }
    let tx = ctx.db.begin().await?;
    publish_for_test(sbom_id, &tx).await?;
    tx.commit().await?;
    Ok((sbom_id, advisory_id))
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn verdict_pages_preserve_groups_filters_and_order(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let (id, _) = fixture(ctx).await?;
    let service = CorrelationService::default();
    let tx = ctx.db.begin().await?;
    let cache = PaginationCache::for_test();
    let request = ResolutionRequest {
        include_explanation: true,
        ..Default::default()
    };
    let defaults = service
        .verdict_page(id, &request, Paginated::default(), &cache, &tx)
        .await?;
    assert_eq!(defaults.items.len(), 25);
    assert_eq!(defaults.total, None);
    let mut actual = Vec::new();
    for offset in [0, 13, 26, 39, 52, 65, 78] {
        let result = service
            .verdict_page(
                id,
                &request,
                Paginated {
                    offset,
                    limit: 13,
                    total: true,
                },
                &cache,
                &tx,
            )
            .await?;
        assert_eq!(result.total, Some(68));
        for verdict in &result.items {
            assert_eq!(verdict.evidence.len(), 2);
            assert!(verdict.resolution.explanation.is_some());
            assert_eq!(verdict.component.identifiers.len(), 1);
        }
        actual.extend(result.items);
    }
    let expected = service
        .correlate_sbom_with(id, false, &request, &tx)
        .await?;
    // Evidence ordering within a verdict is unspecified; compare verdict keys.
    let keys = |items: &[VerdictSummary]| {
        items
            .iter()
            .map(|v| (v.component.node_id.clone(), v.vulnerability.id.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(keys(&actual), keys(&expected.verdicts));
    assert_eq!(actual.len(), 68);
    assert_eq!(actual[0].component.node_id, "A");
    assert_eq!(actual.last().unwrap().component.node_id, "é");
    let filtered = service
        .verdict_page(
            id,
            &ResolutionRequest {
                node_id: Some("node-01".into()),
                vulnerability_id: Some("CVE-2".into()),
                ..Default::default()
            },
            Paginated {
                total: true,
                ..Default::default()
            },
            &cache,
            &tx,
        )
        .await?;
    assert_eq!(filtered.total, Some(1));
    assert_eq!(filtered.items.len(), 1);
    assert_eq!(filtered.items[0].vulnerability.id, "CVE-2");
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn unmatched_pages_exclude_root_and_all_matched_nodes(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let (id, _) = fixture(ctx).await?;
    let service = CorrelationService::default();
    let tx = ctx.db.begin().await?;
    let cache = PaginationCache::for_test();
    let mut ids = Vec::new();
    for offset in 0..3 {
        let page = service
            .unmatched_page(
                id,
                None,
                Paginated {
                    offset,
                    limit: 1,
                    total: true,
                },
                &cache,
                &tx,
            )
            .await?;
        assert_eq!(page.total, Some(2));
        ids.extend(page.items.into_iter().map(|n| {
            assert_eq!(n.identifiers.len(), 1);
            n.node_id
        }));
    }
    assert_eq!(ids, ["unmatched-1", "unmatched-2"]);
    let page = service
        .unmatched_page(
            id,
            Some("node-00"),
            Paginated {
                total: true,
                ..Default::default()
            },
            &cache,
            &tx,
        )
        .await?;
    assert_eq!(page.total, Some(0));
    assert!(page.items.is_empty());
    let page = service
        .unmatched_page(id, Some("unmatched-2"), Paginated::default(), &cache, &tx)
        .await?;
    assert_eq!(page.total, None);
    assert_eq!(page.items[0].node_id, "unmatched-2");
    Ok(())
}

/// Invalid resolver input proves zero-limit requests and pages beyond the end do not hydrate
/// evidence. Stored pages remain available even when newer inputs are invalid.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn count_only_skips_resolution(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (id, _) = fixture(ctx).await?;
    let service = CorrelationService::default();
    let tx = ctx.db.begin().await?;
    tx.execute_unprepared("UPDATE correlation_evidence SET matched_value = '\"invalid\"'::jsonb")
        .await?;
    let cache = PaginationCache::for_test();
    for total in [false, true] {
        for (offset, limit) in [(0, 0), (500, 0), (500, 1)] {
            let page = service
                .verdict_page(
                    id,
                    &ResolutionRequest::default(),
                    Paginated {
                        offset,
                        limit,
                        total,
                    },
                    &cache,
                    &tx,
                )
                .await?;
            assert!(page.items.is_empty());
            assert_eq!(page.total, total.then_some(68));
            let page = service
                .unmatched_page(
                    id,
                    None,
                    Paginated {
                        offset,
                        limit: 0,
                        total,
                    },
                    &cache,
                    &tx,
                )
                .await?;
            assert!(page.items.is_empty());
            assert_eq!(page.total, total.then_some(2));
        }
    }
    assert!(
        service
            .verdict_page(
                id,
                &ResolutionRequest::default(),
                Paginated::default(),
                &cache,
                &tx
            )
            .await
            .is_ok()
    );
    Ok(())
}

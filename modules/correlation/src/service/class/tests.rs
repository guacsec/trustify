use crate::{
    extractor::Extractors,
    model::{ResolutionRequest, VerdictStatus, VerdictSummary},
    service::{CorrelationService, projection},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, TransactionTrait};
use test_context::test_context;
use test_log::test;
use trustify_common::{db::pagination_cache::PaginationCache, model::Paginated};
use trustify_entity::{correlation_evidence, correlation_node_class};
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

/// An SBOM with three copies of an affected package (`a`, `b`, `c`), another affected version
/// (`d`), and a package without advisories (`e`). Returns the IDs of the SBOM and the advisory.
async fn fixture(ctx: &TrustifyContext) -> anyhow::Result<(Uuid, Uuid)> {
    let component = |id: &str, version: &str| {
        serde_json::json!({
            "type": "library", "bom-ref": id, "name": format!("urllib3-{id}"), "version": version,
            "purl": format!("pkg:pypi/urllib3@{version}"),
        })
    };
    let document = serde_json::json!({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "components": [
            component("c", "1.26.17"),
            component("a", "1.26.17"),
            component("b", "1.26.17"),
            component("d", "1.26.16"),
            {"type": "library", "bom-ref": "e", "name": "other", "version": "1", "purl": "pkg:pypi/other@1"},
        ],
    });
    let sbom_id = Uuid::parse_str(
        &ctx.ingest_read(serde_json::to_vec(&document)?.as_slice())
            .await?
            .id,
    )?;
    let advisory_id = Uuid::parse_str(
        &ctx.ingest_document(
            "scenarios/S6_positive_baseline_osv_urllib3/osv/GHSA-g4mx-q9vg-27p4.json",
        )
        .await?
        .id,
    )?;
    Ok((sbom_id, advisory_id))
}

/// The nodes with evidence, sorted.
async fn evidence_nodes(ctx: &TrustifyContext, sbom_id: Uuid) -> anyhow::Result<Vec<String>> {
    let mut nodes = correlation_evidence::Entity::find()
        .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
        .all(&ctx.db)
        .await?
        .into_iter()
        .map(|e| e.node_id)
        .collect::<Vec<_>>();
    nodes.sort();
    nodes.dedup();
    Ok(nodes)
}

/// (node, name, vulnerability, status) of verdicts.
fn keys(verdicts: &[VerdictSummary]) -> Vec<(String, String, String, VerdictStatus)> {
    verdicts
        .iter()
        .map(|v| {
            (
                v.component.node_id.clone(),
                v.component.name.clone(),
                v.vulnerability.id.clone(),
                v.status,
            )
        })
        .collect()
}

fn affected(node: &str) -> (String, String, String, VerdictStatus) {
    (
        node.to_string(),
        format!("urllib3-{node}"),
        "CVE-2023-45803".to_string(),
        VerdictStatus::Affected,
    )
}

/// Copies of a package share the evidence and verdicts of the first one, and still have them,
/// per node, in both directions and in all reads.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn copies_share_evidence_and_verdicts(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (sbom_id, advisory_id) = fixture(ctx).await?;
    let extractors = Extractors::default();

    let tx = ctx.db.begin().await?;
    extractors.extract_for_sbom(sbom_id, &tx).await?;
    tx.commit().await?;

    let classes = correlation_node_class::Entity::find()
        .filter(correlation_node_class::Column::SbomId.eq(sbom_id))
        .order_by_asc(correlation_node_class::Column::NodeId)
        .all(&ctx.db)
        .await?
        .into_iter()
        .map(|c| (c.node_id, c.representative_node_id))
        .collect::<Vec<_>>();
    let class = |node: &str, representative: &str| (node.to_string(), representative.to_string());
    assert_eq!(
        classes,
        vec![
            class("CycloneDX-doc-ref", "CycloneDX-doc-ref"),
            class("a", "a"),
            class("b", "a"),
            class("c", "a"),
            class("d", "d"),
            class("e", "e"),
        ]
    );
    assert_eq!(evidence_nodes(ctx, sbom_id).await?, vec!["a", "d"]);

    // the advisory direction finds the same, for the representatives only
    correlation_evidence::Entity::delete_many()
        .exec(&ctx.db)
        .await?;
    let tx = ctx.db.begin().await?;
    extractors.extract_for_advisory(advisory_id, &tx).await?;
    tx.commit().await?;
    assert_eq!(evidence_nodes(ctx, sbom_id).await?, vec!["a", "d"]);

    let service = CorrelationService::default();
    let tx = ctx.db.begin().await?;
    let expected = vec![affected("a"), affected("b"), affected("c"), affected("d")];

    // live
    let result = service.correlate_sbom(sbom_id, true, &tx).await?;
    assert_eq!(keys(&result.verdicts), expected);
    assert_eq!(
        result
            .unmatched_components
            .unwrap_or_default()
            .into_iter()
            .map(|c| c.node_id)
            .collect::<Vec<_>>(),
        vec!["e"]
    );
    let only_b = service
        .correlate_sbom_with(
            sbom_id,
            false,
            &ResolutionRequest {
                node_id: Some("b".into()),
                ..Default::default()
            },
            &tx,
        )
        .await?;
    assert_eq!(keys(&only_b.verdicts), vec![affected("b")]);

    // published
    projection::publish_for_test(sbom_id, &tx).await?;
    let cache = PaginationCache::for_test();
    let page = service
        .verdict_page(
            sbom_id,
            &ResolutionRequest::default(),
            Paginated {
                total: true,
                ..Default::default()
            },
            &cache,
            &tx,
        )
        .await?;
    assert_eq!(page.total, Some(4));
    assert_eq!(keys(&page.items), expected);
    let page = service
        .verdict_page(
            sbom_id,
            &ResolutionRequest {
                node_id: Some("c".into()),
                ..Default::default()
            },
            Paginated::default(),
            &cache,
            &tx,
        )
        .await?;
    assert_eq!(keys(&page.items), vec![affected("c")]);

    let counts = projection::counts(&[sbom_id], &tx).await?;
    assert_eq!(
        counts
            .iter()
            .map(|c| (
                c.affected,
                c.fixed,
                c.not_affected,
                c.under_investigation,
                c.none
            ))
            .collect::<Vec<_>>(),
        vec![(4, 0, 0, 0, 0)]
    );

    let unmatched = service
        .unmatched_page(sbom_id, None, Paginated::default(), &cache, &tx)
        .await?;
    assert_eq!(
        unmatched
            .items
            .into_iter()
            .map(|c| c.node_id)
            .collect::<Vec<_>>(),
        vec!["e"]
    );

    Ok(())
}

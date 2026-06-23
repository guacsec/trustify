use crate::{
    config::AnalysisConfig,
    model,
    service::{AnalysisService, ComponentReference, QueryOptions},
};
use test_context::test_context;
use trustify_common::{db::ReadOnly, model::Paginated};
use trustify_test_context::TrustifyContext;

/// Compute the maximum depth of the descendant tree.
fn max_descendant_depth(nodes: &[model::Node]) -> u64 {
    fn depth(nodes: &[model::Node]) -> u64 {
        nodes
            .iter()
            .map(|node| match &node.descendants {
                Some(children) if !children.is_empty() => 1 + depth(children),
                _ => 1,
            })
            .max()
            .unwrap_or(0)
    }

    nodes
        .iter()
        .map(|node| match &node.descendants {
            Some(children) if !children.is_empty() => depth(children),
            _ => 0,
        })
        .max()
        .unwrap_or(0)
}

/// Collect all node_ids at a given depth level in the descendant tree.
fn node_ids_at_depth(nodes: &[model::Node], target_depth: u64) -> Vec<String> {
    fn collect(nodes: &[model::Node], current: u64, target: u64, result: &mut Vec<String>) {
        for node in nodes {
            if current == target {
                result.push(node.base.node_id.clone());
            }
            if let Some(children) = &node.descendants {
                collect(children, current + 1, target, result);
            }
        }
    }

    let mut result = Vec::new();
    for node in nodes {
        if let Some(children) = &node.descendants {
            collect(children, 1, target_depth, &mut result);
        }
    }
    result
}

/// Verify that traversing into an external SBOM consumes depth.
///
/// simple-ext-a has node "A" with:
///   - descendant "B" (in SBOM-A, 1 level deep)
///   - external reference "DocumentRef-ext-b:SPDXRef-A" (1 level deep)
///     which resolves to SBOM-B's "SPDXRef-A", whose descendant "B" is 2 levels deep total.
///
/// With unlimited depth, we should see descendants at depth 2 (inside the external SBOM).
/// With depth=1, the external hop should consume the single available level,
/// leaving no budget to traverse further into SBOM-B.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn external_sbom_traversal_consumes_depth(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple-ext-a.json", "spdx/simple-ext-b.json"])
        .await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));

    // With high depth, we should see descendants inside the external SBOM.
    let result = service
        .retrieve(
            ComponentReference::Name("A"),
            QueryOptions {
                descendants: 10,
                ..Default::default()
            },
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Unlimited depth result: {result:#?}");

    // We expect results from SBOM-A (which has "A")
    assert!(
        !result.items.is_empty(),
        "should find component A in SBOM-A"
    );

    let deep = max_descendant_depth(&result.items);
    assert!(
        deep >= 2,
        "with high depth, should traverse into external SBOM (got depth {deep})"
    );

    // With depth=1, the external hop consumes the single level of depth.
    // We should see direct descendants but NOT their children in the external SBOM.
    let result_shallow = service
        .retrieve(
            ComponentReference::Name("A"),
            QueryOptions {
                descendants: 1,
                ..Default::default()
            },
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Depth=1 result: {result_shallow:#?}");

    let shallow = max_descendant_depth(&result_shallow.items);
    assert!(
        shallow <= 1,
        "with depth=1, external traversal should not go deeper than 1 (got depth {shallow})"
    );

    // With depth=2, we should be able to see one level inside the external SBOM.
    let result_mid = service
        .retrieve(
            ComponentReference::Name("A"),
            QueryOptions {
                descendants: 2,
                ..Default::default()
            },
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Depth=2 result: {result_mid:#?}");

    let mid = max_descendant_depth(&result_mid.items);
    assert!(
        mid <= 2,
        "with depth=2, should not exceed 2 levels (got depth {mid})"
    );

    // Verify that the depth=2 result does see nodes in the external SBOM
    // (the external hop costs 1, leaving 1 for traversal inside)
    let depth_2_ids = node_ids_at_depth(&result_mid.items, 2);
    log::debug!("Node IDs at depth 2: {depth_2_ids:?}");

    // At depth 2 we should find SPDXRef-B from the external SBOM-B
    // (DocumentRef-ext-b:SPDXRef-A at depth 1, then SPDXRef-B at depth 2)
    assert!(
        !depth_2_ids.is_empty(),
        "with depth=2, should see nodes inside the external SBOM at depth 2"
    );

    Ok(())
}

use crate::{
    config::AnalysisConfig,
    service::{
        AnalysisService, ComponentReference, QueryOptions,
        test::warnings::{ChainKeys, Direction, Key, collect_warnings},
    },
};
use rstest::rstest;
use test_context::test_context;
use trustify_common::model::Paginated;
use trustify_test_context::{IngestionResult, TrustifyContext};

#[test_context(TrustifyContext)]
#[rstest]
#[case(QueryOptions{ descendants: u64::MAX, ..Default::default() }, 22)]
#[case(QueryOptions{ ancestors: u64::MAX, ..Default::default() }, 40)]
#[test_log::test(tokio::test)]
async fn test_circular_deps_cyclonedx_service_count(
    ctx: &TrustifyContext,
    #[case] query: QueryOptions,
    #[case] len: usize,
) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["cyclonedx/cyclonedx-circular.json"])
        .await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());

    let analysis_graph = service
        .retrieve(
            ComponentReference::Name("junit-bom"),
            query,
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::info!("response: {analysis_graph:#?}");

    // assert warnings

    let warnings = collect_warnings(&analysis_graph.items);
    assert_eq!(warnings.len(), len);

    // assert result count

    assert_eq!(analysis_graph.total, 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[case(QueryOptions{ descendants: u64::MAX, ..Default::default() }, Direction::Descendant, ["B", "C", "A"])]
#[case(QueryOptions{ ancestors: u64::MAX, ..Default::default() }, Direction::Ancestor, ["C", "B", "A"])]
#[test_log::test(tokio::test)]
async fn test_circular_deps_cyclonedx_service<const N: usize>(
    ctx: &TrustifyContext,
    #[case] query: QueryOptions,
    #[case] direction: Direction,
    #[case] chain: [&str; N],
) -> Result<(), anyhow::Error> {
    let [sbom] = ctx
        .ingest_documents(["cyclonedx/loop.json"])
        .await?
        .into_id();

    let service = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());

    let analysis_graph = service
        .retrieve(
            ComponentReference::Name("A"),
            query,
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::info!("response: {analysis_graph:#?}");

    // assert warnings

    let warnings = collect_warnings(&analysis_graph.items);

    assert_eq!(warnings.len(), 1);
    assert_eq!(
        Vec::from_iter(warnings),
        [(
            Key::top(&sbom, "A")
                .chain(direction, &sbom, chain),
            &["This node was already visited. Possible relationship loop. Skipping further processing.".to_string()][..]
        )
        ]
    );

    assert_eq!(analysis_graph.total, 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[case(QueryOptions{ descendants: u64::MAX, ..Default::default() }, Direction::Descendant, ["SPDXRef-B", "SPDXRef-C", "SPDXRef-A"])]
#[case(QueryOptions{ ancestors: u64::MAX, ..Default::default() }, Direction::Ancestor, ["SPDXRef-C", "SPDXRef-B", "SPDXRef-A"])]
#[test_log::test(tokio::test)]
async fn test_circular_deps_spdx_service<const N: usize>(
    ctx: &TrustifyContext,
    #[case] query: QueryOptions,
    #[case] direction: Direction,
    #[case] chain: [&str; N],
) -> Result<(), anyhow::Error> {
    let [sbom] = ctx.ingest_documents(["spdx/loop.json"]).await?.into_id();

    let service = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());

    let analysis_graph = service
        .retrieve(
            ComponentReference::Name("A"),
            query,
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::info!("response: {analysis_graph:#?}");

    // assert warnings

    let warnings = collect_warnings(&analysis_graph.items);

    assert_eq!(warnings.len(), 1);
    assert_eq!(
        Vec::from_iter(warnings),
        [(
            Key::top(&sbom, "SPDXRef-A")
                .chain(direction, &sbom, chain),
                &["This node was already visited. Possible relationship loop. Skipping further processing.".to_string()][..]
        )
        ]
    );

    assert_eq!(analysis_graph.total, 1);

    Ok(())
}

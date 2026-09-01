mod cache_eviction;
mod external_depth;
mod query;
mod recursive;
mod warnings;

use super::*;
use crate::{
    model::*,
    test::{Node, *},
};
use futures::future::try_join_all;
use std::{str::FromStr, time::SystemTime};
use test_context::test_context;
use test_log::test;
use trustify_common::{
    cpe::Cpe,
    db::query::Query,
    model::{BinaryByteSize, Paginated},
    purl::Purl,
    sbom::spdx::fix_license,
};
use trustify_test_context::{TrustifyContext, document, spdx::fix_spdx_rels};

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_analysis_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json", "spdx/simple.json"])
        .await?; //double ingestion intended

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));

    let analysis_graph = service
        .retrieve(
            &Query::q("DD"),
            QueryOptions::ancestors(),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Before: {analysis_graph:#?}");
    let analysis_graph = analysis_graph.root_traces();
    log::debug!("After: {analysis_graph:#?}");

    assert_root_traces(&analysis_graph.items, |traces| {
        assert!(
            matches!(
                traces[..],
                [[
                    ..,
                    Node {
                        id: "SPDXRef-AA",
                        purls: ["pkg:rpm/redhat/AA@0.0.0?arch=src"],
                        ..
                    }
                ]]
            ),
            "doesn't match: {traces:#?}"
        );
    });
    assert_eq!(analysis_graph.total, Some(1));

    // ensure we set implicit relationship on components with no defined relationships
    let analysis_graph = service
        .retrieve(
            &Query::q("EE"),
            QueryOptions::ancestors(),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Before: {analysis_graph:#?}");
    let analysis_graph = analysis_graph.roots();
    log::debug!("After: {analysis_graph:#?}");

    assert_eq!(analysis_graph.total, Some(1));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_analysis_cyclonedx_service(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["cyclonedx/simple.json", "cyclonedx/simple.json"])
        .await?; //double ingestion intended

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));

    let analysis_graph = service
        .retrieve(
            &Query::q("DD"),
            QueryOptions::ancestors(),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Before: {analysis_graph:#?}");
    let analysis_graph = analysis_graph.root_traces();
    log::debug!("After: {analysis_graph:#?}");

    assert_root_traces(&analysis_graph.items, |traces| {
        assert!(
            matches!(
                traces[..],
                [[
                    ..,
                    Node {
                        id: "aa",
                        name: "AA",
                        purls: ["pkg:rpm/redhat/AA@0.0.0?arch=src"],
                        ..
                    }
                ]]
            ),
            "doesn't match: {traces:#?}"
        );
    });
    assert_eq!(analysis_graph.total, Some(1));

    // ensure we set implicit relationship on components with no defined relationships
    let analysis_graph = service
        .retrieve(
            &Query::q("EE"),
            QueryOptions::ancestors(),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Before: {analysis_graph:#?}");
    let analysis_graph = analysis_graph.root_traces();
    log::debug!("After: {analysis_graph:#?}");

    assert_eq!(analysis_graph.total, Some(1));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_by_name_analysis_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));

    let analysis_graph = service
        .retrieve(
            ComponentReference::Name("B"),
            QueryOptions::ancestors(),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Result: {analysis_graph:#?}");

    let analysis_graph = analysis_graph.root_traces();

    assert_root_traces(&analysis_graph.items, |traces| {
        assert_eq!(
            traces,
            &[&[
                Node {
                    id: "SPDXRef-A",
                    name: "A",
                    version: "1",
                    cpes: &["cpe:/a:redhat:simple:1:*:el9:*"],
                    purls: &["pkg:rpm/redhat/A@0.0.0?arch=src"],
                },
                Node {
                    id: "SPDXRef-DOCUMENT",
                    name: "simple",
                    version: "",
                    cpes: &[],
                    purls: &[],
                },
            ]]
        );
    });

    assert_eq!(analysis_graph.total, Some(1));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn simple_by_name_analysis_service_filter_rel(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));

    let analysis_graph = service
        .retrieve(
            ComponentReference::Name("B"),
            QueryOptions {
                relationships: HashSet::from_iter([Relationship::Contains]),
                ..QueryOptions::ancestors()
            },
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Result: {analysis_graph:#?}");

    let analysis_graph = analysis_graph.root_traces();

    assert_root_traces(&analysis_graph.items, |traces| {
        assert_eq!(
            traces,
            &[&[Node {
                id: "SPDXRef-A",
                name: "A",
                version: "1",
                cpes: &["cpe:/a:redhat:simple:1:*:el9:*"],
                purls: &["pkg:rpm/redhat/A@0.0.0?arch=src"],
            },]]
        );
    });

    assert_eq!(analysis_graph.total, Some(1));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_by_purl_analysis_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));

    let component_purl: Purl = Purl::from_str("pkg:rpm/redhat/B@0.0.0").map_err(Error::Purl)?;

    let analysis_graph = service
        .retrieve(
            &component_purl,
            QueryOptions::ancestors(),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Before: {analysis_graph:#?}");
    let analysis_graph = analysis_graph.root_traces();
    log::debug!("After: {analysis_graph:#?}");

    assert_root_traces(&analysis_graph.items, |traces| {
        assert_eq!(
            traces,
            [[
                Node {
                    id: "SPDXRef-A",
                    name: "A",
                    version: "1",
                    purls: &["pkg:rpm/redhat/A@0.0.0?arch=src"],
                    cpes: &["cpe:/a:redhat:simple:1:*:el9:*"],
                },
                Node {
                    id: "SPDXRef-DOCUMENT",
                    name: "simple",
                    version: "",
                    cpes: &[],
                    purls: &[],
                }
            ]]
        );
    });

    assert_eq!(analysis_graph.total, Some(1));
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_quarkus_analysis_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));

    let analysis_graph = service
        .retrieve(
            &Query::q("spymemcached"),
            QueryOptions::ancestors(),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Before: {analysis_graph:#?}");
    let analysis_graph = analysis_graph.root_traces();
    log::debug!("After: {analysis_graph:#?}");

    assert_root_traces(&analysis_graph.items, |traces| {
        assert!(traces.contains(&[
                        Node {
                            id: "SPDXRef-e24fec28-1001-499c-827f-2e2e5f2671b5",
                            name: "quarkus-bom",
                            version: "3.2.12.Final-redhat-00002",
                            cpes: &["cpe:/a:redhat:quarkus:3.2:*:el8:*",],
                            purls: &[
                                "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.12.Final-redhat-00002?repository_url=https:%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=pom"
                            ],
                        },
                        Node {
                            id: "SPDXRef-DOCUMENT",
                            name: "quarkus-bom-3.2.12.Final-redhat-00002",
                            version: "",
                            cpes: &[],
                            purls: &[],
                        },
                    ].as_slice()
            ),
            "doesn't match: {traces:#?}"
        );
    });

    assert_eq!(analysis_graph.total, Some(2));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_status_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));
    let all_graphs = service.load_all_graphs(&ctx.db).await?;
    assert_eq!(all_graphs.len(), 1);

    let analysis_status = service.status(&ctx.db, false).await?;
    assert_eq!(analysis_status.sbom_count, 1);
    assert_eq!(analysis_status.graph_count, 1);
    assert_eq!(analysis_status.graph_memory, 2152);
    assert!(analysis_status.details.is_none());

    service.clear_all_graphs()?;

    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let analysis_status = service.status(&ctx.db, false).await?;

    assert_eq!(analysis_status.sbom_count, 3);
    assert_eq!(analysis_status.graph_count, 0);
    assert_eq!(analysis_status.graph_memory, 0);
    assert!(analysis_status.details.is_none());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_cache_size_used(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));
    assert_eq!(service.cache_size_used(), 0u64);

    let all_graphs = service.load_all_graphs(&ctx.db).await?;
    assert_eq!(all_graphs.len(), 1);

    let kb = 1024;
    let small_sbom_size = service.cache_size_used();

    assert!(small_sbom_size > 2 * kb);
    assert!(small_sbom_size < 3 * kb);

    ctx.ingest_documents(["spdx/quarkus-bom-3.2.11.Final-redhat-00001.json"])
        .await?;
    let all_graphs = service.load_all_graphs(&ctx.db).await?;
    assert_eq!(all_graphs.len(), 2);

    let big_sbom_size = service.cache_size_used() - small_sbom_size;
    log::warn!("{big_sbom_size:?}");
    assert!(big_sbom_size > 420 * kb);
    assert!(big_sbom_size < 430 * kb);

    // Now lets try it with small cache that can at least fit the small bom
    let service = AnalysisService::new(
        AnalysisConfig {
            max_cache_size: BinaryByteSize::from(small_sbom_size * 2),
            ..Default::default()
        },
        ReadOnly::new(ctx.db.clone()),
    );

    let all_graphs = service.load_all_graphs(&ctx.db).await?;
    // we should be able to load all the graphs even if they can't fit in the cache.
    assert_eq!(all_graphs.len(), 2);

    // but the cache should only contain the first sbom
    assert_eq!(small_sbom_size, service.cache_size_used());
    assert_eq!(1u64, service.cache_len());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_deps_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));

    let analysis_graph = service
        .retrieve(
            &Query::q("AA"),
            QueryOptions::descendants(),
            Paginated {
                total: true,
                ..Paginated::default()
            },
            &ctx.db,
        )
        .await?;

    assert_eq!(analysis_graph.total, Some(1));

    // ensure we set implicit relationship on components with no defined relationships
    let analysis_graph = service
        .retrieve(
            &Query::q("EE"),
            QueryOptions::ancestors(),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Before: {analysis_graph:#?}");
    let analysis_graph = analysis_graph.roots();
    log::debug!("After: {analysis_graph:#?}");

    assert_eq!(analysis_graph.total, Some(1));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_deps_cyclonedx_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["cyclonedx/simple.json"]).await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));

    let analysis_graph = service
        .retrieve(
            &Query::q("AA"),
            QueryOptions::descendants(),
            Paginated {
                total: true,
                ..Paginated::default()
            },
            &ctx.db,
        )
        .await?;

    assert_eq!(analysis_graph.total, Some(1));

    // ensure we set implicit relationship on component with no defined relationships
    let analysis_graph = service
        .retrieve(
            &Query::q("EE"),
            QueryOptions::ancestors(),
            Paginated::default(),
            &ctx.db,
        )
        .await?
        .roots();
    assert_eq!(analysis_graph.total, Some(1));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_by_name_deps_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));

    let analysis_graph = service
        .retrieve(
            ComponentReference::Name("A"),
            QueryOptions::descendants(),
            Paginated {
                total: true,
                ..Paginated::default()
            },
            &ctx.db,
        )
        .await?;

    assert_eq!(analysis_graph.items.len(), 1);
    assert_eq!(analysis_graph.total, Some(1));

    assert_eq!(
        &*analysis_graph.items[0].purl,
        [Purl::from_str("pkg:rpm/redhat/A@0.0.0?arch=src")?]
    );
    assert_eq!(
        &*analysis_graph.items[0].cpe,
        [Cpe::from_str("cpe:/a:redhat:simple:1::el9")?]
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_simple_by_purl_deps_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));

    let component_purl: Purl =
        Purl::from_str("pkg:rpm/redhat/AA@0.0.0?arch=src").map_err(Error::Purl)?;

    let analysis_graph = service
        .retrieve(
            &component_purl,
            QueryOptions::descendants(),
            Paginated {
                total: true,
                ..Paginated::default()
            },
            &ctx.db,
        )
        .await?;

    assert_eq!(
        &*analysis_graph.items[0].purl,
        [Purl::from_str("pkg:rpm/redhat/AA@0.0.0?arch=src")?]
    );

    assert_eq!(analysis_graph.total, Some(1));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_quarkus_deps_service(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));

    let analysis_graph = service
        .retrieve(
            &Query::q("spymemcached"),
            QueryOptions::descendants(),
            Paginated {
                total: true,
                ..Paginated::default()
            },
            &ctx.db,
        )
        .await?;

    assert_eq!(analysis_graph.total, Some(2));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_retrieve_all_sbom_roots_by_name(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/quarkus-bom-3.2.11.Final-redhat-00001.json"])
        .await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));
    let component_name = "quarkus-vertx-http".to_string();

    let analysis_graph = service
        .retrieve(
            &Query::q(&component_name),
            QueryOptions::ancestors(),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    let analysis_graph = analysis_graph.roots();

    log::debug!("Result: {analysis_graph:#?}");

    let sbom_id = analysis_graph
        .items
        .last()
        .unwrap()
        .sbom_id
        .parse::<Uuid>()?;

    let roots = service
        .retrieve_single(
            sbom_id,
            ComponentReference::Name(&component_name),
            QueryOptions::ancestors(),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("Before: {roots:#?}");
    let roots = roots.root_traces();
    log::debug!("After: {roots:#?}");

    assert_root_traces(&roots.items, |traces| {
        assert!(
            matches!(
                traces,
                [[
                    ..,
                    Node {
                        name: "quarkus-bom-3.2.11.Final-redhat-00001",
                        ..
                    }
                ]]
            ),
            "doesn't match: {traces:#?}"
        );
    });

    Ok(())
}

/// Run a standard scenario with a larger file, to check the performance.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn load_performance(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let (spdx, _) =
        document::<serde_json::Value>("openshift-container-storage-4.8.z.json.xz").await?;
    let (spdx, _) = fix_license(&(), spdx);
    let spdx = fix_spdx_rels(serde_json::from_value(spdx)?);

    log::info!("Start ingestion");

    ctx.ingest_json(spdx).await?;

    log::info!("Start populating graph");

    let start = SystemTime::now();
    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));
    service.load_all_graphs(&ctx.db).await?;

    log::info!(
        "Loading took: {}",
        humantime::format_duration(start.elapsed()?)
    );

    Ok(())
}

/// Run a standard scenario with a larger file, loading in parallel, to check the performance.
///
/// This should have the same performance as [`load_performance`].
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn load_performance_parallel(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let (spdx, _) =
        document::<serde_json::Value>("openshift-container-storage-4.8.z.json.xz").await?;
    let (spdx, _) = fix_license(&(), spdx);
    let spdx = fix_spdx_rels(serde_json::from_value(spdx)?);

    log::info!("Start ingestion");

    ctx.ingest_json(spdx).await?;

    log::info!("Start populating graph");

    let start = SystemTime::now();
    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));

    let mut tasks = vec![];
    for _ in 0..10 {
        tasks.push(service.load_all_graphs(&ctx.db));
    }

    try_join_all(tasks).await?;

    log::info!(
        "Loading took: {}",
        humantime::format_duration(start.elapsed()?)
    );

    // now that all are loaded, it should be instant

    let start = SystemTime::now();

    let mut tasks = vec![];
    for _ in 0..10 {
        tasks.push(service.load_all_graphs(&ctx.db));
    }

    try_join_all(tasks).await?;

    log::info!(
        "Loading (phase 2) took: {}",
        humantime::format_duration(start.elapsed()?)
    );

    // done

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn resolve_sbom_cdx_external_node_sbom(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // ingest cdx example
    ctx.ingest_document("cyclonedx/simple-ext-a.json").await?;
    let get_external_sbom =
        resolve_external_sbom("urn:cdx:a4f16b62-fea9-42c1-8365-d72d3cef37d1/2#a", &ctx.db).await?;
    assert_eq!(get_external_sbom, None);
    // now ingest cdx sbom referred in "cyclonedx/simple-ext-b.json"
    ctx.ingest_document("cyclonedx/simple-ext-b.json").await?;
    let get_external_sbom =
        resolve_external_sbom("urn:cdx:a4f16b62-fea9-42c1-8365-d72d3cef37d1/2#a", &ctx.db).await?;
    assert!(get_external_sbom.is_some());
    if let Some(ResolvedSbom {
        node_id: external_node_id,
        ..
    }) = get_external_sbom
    {
        assert_eq!(external_node_id, "a");
    } else {
        panic!("failed getting node_id from external sbom.");
    }
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn resolve_sbom_spdx_external_node_sbom(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // now try spdx example
    ctx.ingest_document("spdx/simple-ext-a.json").await?;
    let get_external_sbom = resolve_external_sbom("DocumentRef-ext-b:SPDXRef-A", &ctx.db).await?;
    assert_eq!(get_external_sbom, None);
    // now ingest spdx sbom referred in "spdx/simple-ext-b.json"
    ctx.ingest_document("spdx/simple-ext-b.json").await?;
    let get_external_sbom = resolve_external_sbom("DocumentRef-ext-b:SPDXRef-A", &ctx.db).await?;
    assert!(get_external_sbom.is_some());
    if let Some(ResolvedSbom {
        node_id: external_node_id,
        ..
    }) = get_external_sbom
    {
        assert_eq!(external_node_id, "SPDXRef-A");
    } else {
        panic!("failed getting node_id from external sbom.");
    }
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn resolve_sbom_spdx_rh_variant_external_node_sbom(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    // now ingest rh product example "spdx/rh/product_component/rhel-9.2-eus.spdx.json"
    ctx.ingest_document("spdx/rh/product_component/rhel-9.2-eus.spdx.json")
        .await?;
    let get_external_sbom = resolve_external_sbom(
        "SPDXRef-RHEL-9.2-EUS:SPDXRef-openssl-3.0.7-18.el9-2",
        &ctx.db,
    )
    .await?;
    assert_eq!(get_external_sbom, None);

    // now ingest rh component spdx "spdx/rh/product_component/openssl-3.0.7-18.el9_2.spdx.json"
    ctx.ingest_document("spdx/rh/product_component/openssl-3.0.7-18.el9_2.spdx.json")
        .await?;
    let get_external_sbom = resolve_external_sbom(
        "SPDXRef-RHEL-9.2-EUS:SPDXRef-openssl-3.0.7-18.el9-2",
        &ctx.db,
    )
    .await?;

    if let Some(ResolvedSbom {
        sbom_id: external_sbom_id,
        node_id: external_node_id,
        ..
    }) = get_external_sbom
    {
        assert_eq!(external_node_id, "SPDXRef-SRPM".to_string());
        let sbom = sbom::Entity::find()
            .filter(sbom::Column::SbomId.eq(external_sbom_id))
            .one(&ctx.db)
            .await;
        assert_eq!(
            sbom.unwrap().unwrap().document_id,
            Some("https://www.redhat.com/openssl-3.0.7-18.el9_2.spdx.json".to_string()),
        )
    } else {
        panic!("failed getting node_id from external sbom.");
    }

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn resolve_sbom_cdx_rh_variant_external_node_sbom(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    // now ingest rh product example "cyclonedx/rh/product_component/rhel-9.2-eus.cdx.json"
    ctx.ingest_document("cyclonedx/rh/product_component/rhel-9.2-eus.cdx.json")
        .await?;
    let get_external_sbom = resolve_external_sbom(
        "Red Hat Enterprise Linux 9.2 EUS:pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src",
        &ctx.db,
    )
    .await?;
    assert_eq!(get_external_sbom, None);

    // now ingest rh component spdx "cyclonedx/rh/product_component/openssl-3.0.7-18.el9_2.cdx.json"
    ctx.ingest_document("cyclonedx/rh/product_component/openssl-3.0.7-18.el9_2.cdx.json")
        .await?;
    let get_external_sbom = resolve_external_sbom(
        "Red Hat Enterprise Linux 9.2 EUS:pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src",
        &ctx.db,
    )
    .await?;

    if let Some(ResolvedSbom {
        sbom_id: external_sbom_id,
        node_id: external_node_id,
        ..
    }) = get_external_sbom
    {
        assert_eq!(
            external_node_id,
            "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src".to_string()
        );
        let sbom = sbom::Entity::find()
            .filter(sbom::Column::SbomId.eq(external_sbom_id))
            .one(&ctx.db)
            .await;
        assert_eq!(
            sbom.unwrap().unwrap().document_id,
            Some("urn:uuid:223234df-bb5b-49af-a896-143736f7d806/1".to_string()),
        )
    } else {
        panic!("failed getting external sbom.");
    }

    Ok(())
}

/// Verify that pagination limits the number of hydrated nodes.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_pagination_limits_hydration(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));

    // When: request with limit=1 and total=true
    let result = service
        .retrieve(
            &Query::q("spymemcached"),
            QueryOptions::ancestors(),
            Paginated {
                offset: 0,
                limit: 1,
                total: true,
            },
            &ctx.db,
        )
        .await?;

    // Then: only 1 item returned but total reflects all matches
    assert_eq!(result.items.len(), 1);
    assert_eq!(result.total, Some(2));

    Ok(())
}

/// Verify that offset produces different results from different pages.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_pagination_offset(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));

    // Given: page 1 (offset=0, limit=1)
    let page1 = service
        .retrieve(
            &Query::q("spymemcached"),
            QueryOptions::ancestors(),
            Paginated {
                offset: 0,
                limit: 1,
                total: false,
            },
            &ctx.db,
        )
        .await?;

    // Given: page 2 (offset=1, limit=1)
    let page2 = service
        .retrieve(
            &Query::q("spymemcached"),
            QueryOptions::ancestors(),
            Paginated {
                offset: 1,
                limit: 1,
                total: false,
            },
            &ctx.db,
        )
        .await?;

    // Then: both pages have 1 item each
    assert_eq!(page1.items.len(), 1);
    assert_eq!(page2.items.len(), 1);

    // Then: the items are different (from different SBOMs)
    assert_ne!(&page1.items[0].base.sbom_id, &page2.items[0].base.sbom_id);

    // Given: combined page (offset=0, limit=2)
    let combined = service
        .retrieve(
            &Query::q("spymemcached"),
            QueryOptions::ancestors(),
            Paginated {
                offset: 0,
                limit: 2,
                total: true,
            },
            &ctx.db,
        )
        .await?;

    // Then: union of page1 + page2 matches the combined result
    assert_eq!(combined.items.len(), 2);
    assert_eq!(combined.total, Some(2));

    Ok(())
}

/// Verify that pagination correctly spans across multiple SBOM graph boundaries.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_pagination_cross_graph(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ReadOnly::new(ctx.db.clone()));

    // Given: a query that matches nodes across both SBOMs
    let all = service
        .retrieve(
            &Query::q("spymemcached"),
            QueryOptions::default(),
            Paginated {
                offset: 0,
                limit: 100,
                total: true,
            },
            &ctx.db,
        )
        .await?;

    let total = all.total.unwrap_or(0) as usize;
    assert!(total >= 2, "need at least 2 matches across SBOMs");

    // When: paginate through all results one at a time
    let mut collected_sbom_ids = Vec::new();
    for i in 0..total {
        let page = service
            .retrieve(
                &Query::q("spymemcached"),
                QueryOptions::default(),
                Paginated {
                    offset: i as u64,
                    limit: 1,
                    total: false,
                },
                &ctx.db,
            )
            .await?;

        assert_eq!(page.items.len(), 1, "page at offset {i} should have 1 item");
        collected_sbom_ids.push(page.items[0].base.sbom_id.clone());
    }

    // Then: all items are accounted for (no duplicates, no gaps)
    assert_eq!(collected_sbom_ids.len(), total);
    let unique: std::collections::HashSet<_> = collected_sbom_ids.iter().collect();
    assert_eq!(unique.len(), total, "no duplicate items across pages");

    // Then: offset beyond total returns empty
    let beyond = service
        .retrieve(
            &Query::q("spymemcached"),
            QueryOptions::default(),
            Paginated {
                offset: total as u64,
                limit: 1,
                total: true,
            },
            &ctx.db,
        )
        .await?;

    assert!(beyond.items.is_empty());
    assert_eq!(beyond.total, Some(total as u64));

    Ok(())
}

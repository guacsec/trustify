#![allow(clippy::expect_used)]

mod cyclonedx;
mod details;
mod graph;
mod issue_1535;
mod license;
mod reingest;
mod spdx;

use sea_orm::{DatabaseTransaction, TransactionTrait};
use std::time::Instant;
use tracing::{Instrument, info_span, instrument};
use trustify_common::db::pagination_cache::PaginationCache;
use trustify_common::{db::Database, hashing::Digests};
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_module_ingestor::{
    graph::{
        Graph,
        sbom::{self, SbomContext, SbomInformation},
    },
    service::Discard,
};
use trustify_test_context::{TrustifyContext, document_bytes};

#[allow(dead_code)]
pub struct WithContext {
    pub sbom: SbomContext,
    pub db: Database,
    pub graph: Graph,
    pub service: SbomService,
}

#[instrument(skip(ctx, p, i, c, f))]
pub async fn test_with<B, P, I, C, F>(
    ctx: &TrustifyContext,
    sbom: &str,
    p: P,
    i: I,
    c: C,
    f: F,
) -> anyhow::Result<()>
where
    P: FnOnce(&[u8]) -> anyhow::Result<B>,
    for<'a> I: AsyncFnOnce(&'a SbomContext, B, &'a DatabaseTransaction) -> anyhow::Result<()>,
    C: FnOnce(&B) -> SbomInformation,
    F: AsyncFnOnce(WithContext) -> anyhow::Result<()>,
{
    // The `ctx` must live until the end of this function. Otherwise, it will tear down the database
    // while we're testing. So we take the `db` and offer it to the test, but we hold on the `ctx`
    // instance until that test returns.

    let db = &ctx.db;
    let graph = Graph::new(db.clone());
    let service = SbomService::new(db.clone(), PaginationCache::for_test());

    let start = Instant::now();
    let sbom = info_span!("parse json")
        .in_scope(|| async {
            let bytes = document_bytes(sbom).await?;
            p(&bytes[..])
        })
        .await?;

    let parse_time = start.elapsed();

    let tx = db.begin().await?;

    let start = Instant::now();
    let ctx = graph
        .ingest_sbom(
            ("source", "test.com/my-sbom.json"),
            &Digests::digest("10"),
            Some("document-id".to_string()),
            c(&sbom),
            &tx,
        )
        .await?
        .into_inner();
    let ingest_time_1 = start.elapsed();

    let start = Instant::now();
    i(&ctx, sbom, &tx).await?;
    let ingest_time_2 = start.elapsed();

    // commit

    let start = Instant::now();
    tx.commit().await?;
    let commit_time = start.elapsed();

    // now test

    let start = Instant::now();
    f(WithContext {
        sbom: ctx,
        db: db.clone(),
        graph,
        service,
    })
    .instrument(info_span!("assert"))
    .await?;
    let test_time = start.elapsed();

    // log durations

    log::info!("parse: {}", humantime::Duration::from(parse_time));
    log::info!("ingest 1: {}", humantime::Duration::from(ingest_time_1));
    log::info!("ingest 2: {}", humantime::Duration::from(ingest_time_2));
    log::info!("commit: {}", humantime::Duration::from(commit_time));
    log::info!("test: {}", humantime::Duration::from(test_time));

    Ok(())
}

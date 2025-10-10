#![allow(clippy::expect_used)]

use actix_http::StatusCode;
use actix_web::test::TestRequest;
use anyhow::bail;
use bytes::BytesMut;
use futures_util::TryStreamExt;
use sea_orm::ConnectionTrait;
use strum::VariantArray;
use test_context::test_context;
use test_log::test;
use trustify_common::model::Paginated;
use trustify_common::{id::Id, purl::Purl};
use trustify_entity::relationship::Relationship;
use trustify_module_fundamental::{
    Config, configure,
    sbom::{model::SbomNodeReference, service::SbomService},
};
use trustify_module_ingestor::graph::{
    purl::qualified_package::QualifiedPackageContext, sbom::SbomContext,
};
use trustify_module_storage::service::StorageBackend;
use trustify_test_context::document_bytes;

include!("../../../src/test/common.rs");

async fn related_packages_transitively<'a, C: ConnectionTrait>(
    sbom: &'a SbomContext,
    connection: &C,
) -> Result<Vec<QualifiedPackageContext<'a>>, anyhow::Error> {
    let purl = Purl::try_from("pkg:cargo/A@0.0.0").expect("must parse");

    let result = sbom
        .related_packages_transitively(Relationship::VARIANTS, &purl, connection)
        .await?;

    Ok(result)
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn infinite_loop(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = SbomService::new(ctx.db.clone());

    let result = ctx.ingest_document("spdx/loop.json").await?;

    let Id::Uuid(id) = result.id else {
        bail!("must be an id")
    };

    let sbom = ctx
        .graph
        .get_sbom_by_id(id, &ctx.db)
        .await?
        .expect("must be found");

    let packages = service
        .fetch_sbom_packages(id, Default::default(), Default::default(), &ctx.db)
        .await?;

    assert_eq!(packages.total, 3);

    let packages = related_packages_transitively(&sbom, &ctx.db).await?;

    assert_eq!(packages.len(), 3);

    let packages = service
        .describes_packages(id, Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(packages.total, 1);

    let packages = service
        .related_packages(id, None, SbomNodeReference::All, &ctx.db)
        .await?;

    log::info!("Packages: {packages:#?}");

    assert_eq!(packages.len(), 3);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn double_ref(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx.ingest_document("spdx/double-ref.json").await?;

    let Id::Uuid(id) = result.id else {
        bail!("must be an id")
    };
    let sbom = ctx
        .graph
        .get_sbom_by_id(id, &ctx.db)
        .await?
        .expect("must be found");

    let service = SbomService::new(ctx.db.clone());
    let packages = service
        .fetch_sbom_packages(id, Default::default(), Default::default(), &ctx.db)
        .await?;

    assert_eq!(packages.total, 3);

    let packages = related_packages_transitively(&sbom, &ctx.db).await?;

    assert_eq!(packages.len(), 3);

    let packages = service
        .related_packages(id, None, SbomNodeReference::All, &ctx.db)
        .await?;

    log::info!("Packages: {packages:#?}");

    assert_eq!(packages.len(), 3);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn self_ref(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx.ingest_document("spdx/self.json").await?;

    let Id::Uuid(id) = result.id else {
        bail!("must be an id")
    };
    let sbom = ctx
        .graph
        .get_sbom_by_id(id, &ctx.db)
        .await?
        .expect("must be found");

    let service = SbomService::new(ctx.db.clone());
    let packages = service
        .fetch_sbom_packages(id, Default::default(), Default::default(), &ctx.db)
        .await?;

    assert_eq!(packages.total, 0);

    let packages = related_packages_transitively(&sbom, &ctx.db).await?;

    assert_eq!(packages.len(), 0);

    let packages = service
        .related_packages(id, None, SbomNodeReference::All, &ctx.db)
        .await?;

    log::info!("Packages: {packages:#?}");

    assert_eq!(packages.len(), 0);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn self_ref_package(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx.ingest_document("spdx/self-package.json").await?;

    let Id::Uuid(id) = result.id else {
        bail!("must be an id")
    };
    let sbom = ctx
        .graph
        .get_sbom_by_id(id, &ctx.db)
        .await?
        .expect("must be found");

    let service = SbomService::new(ctx.db.clone());
    let packages = service
        .fetch_sbom_packages(id, Default::default(), Default::default(), &ctx.db)
        .await?;

    assert_eq!(packages.total, 1);

    let packages = related_packages_transitively(&sbom, &ctx.db).await?;

    assert_eq!(packages.len(), 1);

    let packages = service
        .related_packages(id, None, SbomNodeReference::All, &ctx.db)
        .await?;

    log::info!("Packages: {packages:#?}");

    assert_eq!(packages.len(), 1);

    let packages = service
        .related_packages(id, None, SbomNodeReference::Package("SPDXRef-A"), &ctx.db)
        .await?;

    log::info!("Packages: {packages:#?}");

    assert_eq!(packages.len(), 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn special_char(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx.ingest_document("spdx/TC-1817-1.json").await?;

    let Id::Uuid(id) = result.id else {
        bail!("must be an id")
    };

    let service = SbomService::new(ctx.db.clone());
    let packages = service
        .fetch_sbom_packages(id, Default::default(), Default::default(), &ctx.db)
        .await?;

    assert_eq!(packages.total, 105);

    let sbom = service
        .fetch_sbom_summary(result.id, &ctx.db)
        .await
        .ok()
        .flatten()
        .expect("must be found");

    let stream = ctx
        .storage
        .retrieve(sbom.source_document.try_into().expect("must be converted"))
        .await?
        .expect("must be found");
    let data: BytesMut = stream.try_collect().await?;

    assert_eq!(data.len(), 124250);

    Ok(())
}

/// test to see some error message, instead of plain failure
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn ingest_broken_refs(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx
        .ingest_document("spdx/broken-refs.json")
        .await
        .expect_err("must fail");

    assert_eq!(
        result.to_string(),
        "invalid content: Invalid reference: SPDXRef-0068e307-de91-4e82-b407-7a41217f9758"
    );

    Ok(())
}

/// test to see some error message and 400, instead of plain failure
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn ingest_broken_refs_api(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let request = TestRequest::post()
        .uri("/api/v2/sbom")
        .set_payload(document_bytes("spdx/broken-refs.json").await?)
        .to_request();

    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

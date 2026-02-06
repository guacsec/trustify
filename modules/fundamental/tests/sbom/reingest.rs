use bytes::Bytes;
use serde_json::Value;
use std::str::FromStr;
use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_common::db::query::Query;
use trustify_common::id::Id;
use trustify_common::model::Paginated;
use trustify_common::purl::Purl;
use trustify_module_fundamental::sbom::model::SbomExternalPackageReference;
use trustify_module_fundamental::sbom::{model::details::SbomDetails, service::SbomService};
use trustify_module_ingestor::service::{Cache, Format};
use trustify_test_context::{TrustifyContext, document_bytes};

fn assert_sboms(sbom1: &SbomDetails, sbom2: &SbomDetails) {
    assert_eq!(sbom1.summary.head.name, "RHWA-NHC-0.4-RHEL-8");
    assert_eq!(sbom2.summary.head.name, "RHWA-NHC-0.4-RHEL-8");
    assert_eq!(sbom1.summary.described_by.len(), 1);
    assert_eq!(sbom2.summary.described_by.len(), 1);
}

fn assert_by_cleaning_id(sbom1: &mut SbomDetails, sbom2: &mut SbomDetails) {
    sbom1.summary.described_by[0].id = "".into();
    sbom2.summary.described_by[0].id = "".into();
    assert_eq!(sbom1.summary.described_by[0], sbom2.summary.described_by[0]);
}

/// We re-ingest two versions of the same quarkus SBOM. However, as the quarkus SBOM doesn't have
/// anything in common other than the filename (which doesn't matter), these are considered two
/// different SBOMs.
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test)]
async fn quarkus(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sbom = SbomService::new(ctx.db.clone());

    // ingest the first version
    let result1 = ctx
        .ingest_document("quarkus/v1/quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;

    assert_eq!(result1.document_id, Some("https://access.redhat.com/security/data/sbom/beta/spdx/quarkus-bom-b52acd7c-3a3f-441e-aef0-bbdaa1ec8acf".to_string()));

    // ingest the second version
    let result2 = ctx
        .ingest_document("quarkus/v2/quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;

    assert_eq!(
        result2.document_id,
        Some("https://access.redhat.com/security/data/sbom/spdx/quarkus-bom-2.13.8.Final-redhat-00004".to_string())
    );

    // now start testing

    assert_ne!(result1.id, result2.id);

    let mut sbom1 = sbom
        .fetch_sbom_details(Id::parse_uuid(result1.id)?, vec![], &ctx.db)
        .await?
        .expect("v1 must be found");
    log::info!("SBOM1: {sbom1:?}");

    let mut sbom2 = sbom
        .fetch_sbom_details(Id::parse_uuid(result2.id)?, vec![], &ctx.db)
        .await?
        .expect("v2 must be found");
    log::info!("SBOM2: {sbom2:?}");

    // both sboms have different names

    assert_eq!(sbom1.summary.head.name, "quarkus-bom");
    assert_eq!(
        sbom2.summary.head.name,
        "quarkus-bom-2.13.8.Final-redhat-00004"
    );
    assert_eq!(sbom1.summary.described_by.len(), 1);
    assert_eq!(sbom2.summary.described_by.len(), 1);

    // clear the ID as that one will be different

    assert_by_cleaning_id(&mut sbom1, &mut sbom2);

    // but both sboms can be found by the same purl

    let purl = "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=pom";

    let sboms = sbom
        .find_related_sboms(
            SbomExternalPackageReference::Purl(&Purl::from_str(purl).expect("must parse")),
            Paginated::default(),
            Query::default(),
            &ctx.db,
        )
        .await?;

    assert_eq!(sboms.total, 2);

    // done

    Ok(())
}

/// Re-ingest two versions of nhc. They to have the same name and mostly the same name and
/// document id/namespace. However, they still get ingested as two different SBOMs.
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test)]
async fn nhc(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sbom = SbomService::new(ctx.db.clone());

    // ingest the first version
    let result1 = ctx.ingest_document("nhc/v1/nhc-0.4.z.json.xz").await?;

    assert_eq!(
        result1.document_id,
        Some("https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8".to_string())
    );

    // ingest the second version
    let result2 = ctx.ingest_document("nhc/v2/nhc-0.4.z.json.xz").await?;

    assert_eq!(
        result2.document_id,
        Some("https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8".to_string())
    );

    // now start testing

    assert_ne!(result1.id, result2.id);

    let mut sbom1 = sbom
        .fetch_sbom_details(Id::parse_uuid(result1.id)?, vec![], &ctx.db)
        .await?
        .expect("v1 must be found");
    log::info!("SBOM1: {sbom1:?}");

    let mut sbom2 = sbom
        .fetch_sbom_details(Id::parse_uuid(result2.id)?, vec![], &ctx.db)
        .await?
        .expect("v2 must be found");
    log::info!("SBOM2: {sbom2:?}");

    // both sboms have the same name
    assert_sboms(&sbom1, &sbom2);

    // clear the ID as that one will be different

    assert_by_cleaning_id(&mut sbom1, &mut sbom2);

    // done

    Ok(())
}

/// Re-ingest the same version of nhc twice.
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test)]
async fn nhc_same(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sbom = SbomService::new(ctx.db.clone());

    // ingest the first version
    let result1 = ctx.ingest_document("nhc/v1/nhc-0.4.z.json.xz").await?;

    assert_eq!(
        result1.document_id,
        Some("https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8".to_string())
    );

    // ingest the same version again
    let result2 = ctx.ingest_document("nhc/v1/nhc-0.4.z.json.xz").await?;

    assert_eq!(
        result2.document_id,
        Some("https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8".to_string())
    );

    // now start testing

    // in this case, we get the same ID, as the digest of the content is the same

    assert_eq!(result1.id, result2.id);

    let mut sbom1 = sbom
        .fetch_sbom_details(Id::parse_uuid(result1.id)?, vec![], &ctx.db)
        .await?
        .expect("v1 must be found");
    log::info!("SBOM1: {sbom1:?}");

    let mut sbom2 = sbom
        .fetch_sbom_details(Id::parse_uuid(result2.id)?, vec![], &ctx.db)
        .await?
        .expect("v2 must be found");
    log::info!("SBOM2: {sbom2:?}");

    // both sboms have the same name

    assert_sboms(&sbom1, &sbom2);

    // clear the ID as that one will be different

    assert_by_cleaning_id(&mut sbom1, &mut sbom2);

    // done

    Ok(())
}

/// Re-ingest the same version of nhc twice, but reformat the second one.
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test)]
async fn nhc_same_content(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sbom = SbomService::new(ctx.db.clone());

    // ingest the first version
    let result1 = ctx.ingest_document("nhc/v1/nhc-0.4.z.json.xz").await?;

    assert_eq!(
        result1.document_id,
        Some("https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8".to_string())
    );

    // ingest the second version
    let bytes = {
        // re-serialize file (non-pretty)
        let json: Value =
            serde_json::from_slice(&document_bytes("nhc/v1/nhc-0.4.z.json.xz").await?)?;
        &serde_json::to_vec(&json).map(Bytes::from)?
    };
    let result2 = ctx
        .db
        .transaction(async |tx| {
            ctx.ingestor
                .ingest(
                    bytes,
                    Format::SBOM,
                    ("source", "test"),
                    None,
                    Cache::Skip,
                    tx,
                )
                .await
        })
        .await?;

    assert_eq!(
        result2.document_id,
        Some("https://access.redhat.com/security/data/sbom/spdx/RHWA-NHC-0.4-RHEL-8".to_string())
    );

    // now start testing

    // in this case, we get a different ID, as the digest doesn't match

    assert_ne!(result1.id, result2.id);

    let mut sbom1 = sbom
        .fetch_sbom_details(Id::parse_uuid(result1.id)?, vec![], &ctx.db)
        .await?
        .expect("v1 must be found");
    log::info!("SBOM1: {sbom1:?}");

    let mut sbom2 = sbom
        .fetch_sbom_details(Id::parse_uuid(result2.id)?, vec![], &ctx.db)
        .await?
        .expect("v2 must be found");
    log::info!("SBOM2: {sbom2:?}");

    // both sboms have the same name

    assert_sboms(&sbom1, &sbom2);

    // clear the ID as that one will be different

    assert_by_cleaning_id(&mut sbom1, &mut sbom2);

    // done

    Ok(())
}

/// Run syft twice on the same container.
///
/// This should be the same SBOM, as it's built from exactly the same container. However, conforming
/// to the SPDX spec, the document gets a new "document namespace".
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test)]
async fn syft_rerun(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sbom = SbomService::new(ctx.db.clone());

    // ingest the first version
    let result1 = ctx.ingest_document("syft-ubi-example/v1.json.xz").await?;

    assert_eq!(
        result1.document_id,
        Some("https://anchore.com/syft/image/registry.access.redhat.com/ubi9/ubi-f41e17d4-e739-4d33-ab2e-48c95b856220".to_string())
    );

    // ingest the second version
    let result2 = ctx.ingest_document("syft-ubi-example/v2.json.xz").await?;

    assert_eq!(
        result2.document_id,
        Some("https://anchore.com/syft/image/registry.access.redhat.com/ubi9/ubi-768a701e-12fb-4ed1-a03b-463b784b01bf".to_string())
    );

    // now start testing

    // in this case, we get the same ID, as the digest of the content is the same

    assert_ne!(result1.id, result2.id);

    let mut sbom1 = sbom
        .fetch_sbom_details(Id::parse_uuid(result1.id)?, vec![], &ctx.db)
        .await?
        .expect("v1 must be found");
    log::info!("SBOM1: {sbom1:?}");

    let mut sbom2 = sbom
        .fetch_sbom_details(Id::parse_uuid(result2.id)?, vec![], &ctx.db)
        .await?
        .expect("v2 must be found");
    log::info!("SBOM2: {sbom2:?}");

    // both sboms have the same name

    assert_eq!(
        sbom1.summary.head.name,
        "registry.access.redhat.com/ubi9/ubi"
    );
    assert_eq!(
        sbom2.summary.head.name,
        "registry.access.redhat.com/ubi9/ubi"
    );
    assert_eq!(sbom1.summary.described_by.len(), 1);
    assert_eq!(sbom2.summary.described_by.len(), 1);

    // clear the ID as that one will be different

    assert_by_cleaning_id(&mut sbom1, &mut sbom2);

    // done

    Ok(())
}

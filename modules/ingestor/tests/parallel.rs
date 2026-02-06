//! Testing parallel operations

use bytes::Bytes;
use csaf::Csaf;
use serde_json::Value;
use spdx_rs::models::SPDX;
use std::str::FromStr;
use test_context::{futures, test_context};
use test_log::test;
use tracing::instrument;
use trustify_common::{cpe::Cpe, purl::Purl, sbom::spdx::parse_spdx};
use trustify_module_ingestor::{
    graph::{
        cpe::CpeCreator,
        purl::creator::PurlCreator,
        sbom::{LicenseCreator, LicenseInfo},
    },
    service::{Cache, Discard, Format},
};
use trustify_test_context::{TrustifyContext, document_bytes, spdx::fix_spdx_rels};
use uuid::Uuid;

/// Ingest x SBOMs in parallel
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn sbom_parallel(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    const NUM: usize = 25;

    let data = document_bytes("quarkus-bom-2.13.8.Final-redhat-00004.json").await?;
    // let data = document_bytes("openshift-container-storage-4.8.z.json.xz").await?;
    let json: Value = serde_json::from_slice(&data)?;
    let (sbom, _) = parse_spdx(&Discard, json)?;
    let sbom = fix_spdx_rels(sbom);

    // turn into 10 different SBOMs, and begin ingesting

    let mut tasks = vec![];
    for _ in 0..NUM {
        let spdx = duplicate_sbom(&sbom)?;
        let next = serde_json::to_vec(&spdx)?;

        let service = ctx.ingestor.clone();
        let db = ctx.db.clone();

        tasks.push(async move {
            db.transaction(async |tx| {
                service
                    .ingest(&next, Format::SPDX, (), None, Cache::Skip, tx)
                    .await
            })
            .await?;

            Ok::<_, anyhow::Error>(())
        });
    }

    // progress ingestion tasks

    let result = futures::future::join_all(tasks).await;

    // now test

    assert_all_ok(NUM, result);

    // done

    Ok(())
}

/// Turn an existing sbom into a new one, which has a different identity (and maybe data) then
/// the original one.
///
/// This is intended to be used when multiple SBOMs of a similar structure/size are required.
fn duplicate_sbom(spdx: &SPDX) -> anyhow::Result<SPDX> {
    let mut spdx = spdx.clone();
    spdx.document_creation_information.spdx_document_namespace = Uuid::new_v4().to_string();

    for (n, pkg) in spdx.package_information.iter_mut().enumerate() {
        for ext in &mut pkg.external_reference {
            if n % 2 == 0 && ext.reference_type == "purl" {
                let mut purl = Purl::from_str(&ext.reference_locator)?;
                // purl.name = format!("{}{}", purl.name, Uuid::new_v4());
                purl.version = purl
                    .version
                    .map(|version| format!("{}.{}", version, Uuid::new_v4()));
            }
        }
    }

    Ok(spdx)
}

/// Assert that all results are ok. Logs errors other of failures.
fn assert_all_ok<T>(num: usize, result: Vec<Result<T, anyhow::Error>>) {
    assert_eq!(num, result.len());

    let ok = result
        .iter()
        .filter(|r| match r {
            Ok(_) => true,
            Err(err) => {
                log::warn!("failed: {err}");
                false
            }
        })
        .count();

    assert_eq!(num, ok);
}

/// Ingest x CSAF documents in parallel
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn csaf_parallel(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    const NUM: usize = 25;

    let data = document_bytes("csaf/cve-2023-33201.json").await?;
    let csaf: Csaf = serde_json::from_slice(&data)?;

    // turn into 10 different SBOMs, and begin ingesting

    let mut tasks = vec![];
    for _ in 0..NUM {
        let mut next = csaf.clone();
        next.document.tracking.id = Uuid::new_v4().to_string();
        let next = serde_json::to_vec(&next)?;

        let service = ctx.ingestor.clone();
        let db = ctx.db.clone();

        tasks.push(async move {
            db.transaction(async |tx| {
                service
                    .ingest(&next, Format::CSAF, (), None, Cache::Skip, tx)
                    .await
            })
            .await?;

            Ok::<_, anyhow::Error>(())
        });
    }

    // progress ingestion tasks

    let result = futures::future::join_all(tasks).await;

    // now test

    assert_all_ok(NUM, result);

    // done

    Ok(())
}

/// Ingest x * y PURLs in parallel
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn purl_creator(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    const NUM: usize = 25;
    const ITEMS: usize = 25;

    let mut tasks = vec![];

    for _ in 0..NUM {
        let db = ctx.db.clone();
        tasks.push(async move {
            let mut creator = PurlCreator::new();

            for i in 0..ITEMS {
                creator.add(Purl {
                    ty: "cargo".to_string(),
                    namespace: None,
                    name: format!("name{i}"),
                    version: None,
                    qualifiers: Default::default(),
                });
            }

            creator.create(&db).await?;

            Ok::<_, anyhow::Error>(())
        });
    }

    // progress ingestion tasks

    let result = futures::future::join_all(tasks).await;

    // now test

    assert_all_ok(NUM, result);

    // done

    Ok(())
}

/// Ingest x * y CPEs in parallel
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn cpe_creator(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    const NUM: usize = 25;
    const ITEMS: usize = 25;

    let mut tasks = vec![];

    for _ in 0..NUM {
        let db = ctx.db.clone();
        tasks.push(async move {
            let mut creator = CpeCreator::new();

            for i in 0..ITEMS {
                creator.add(Cpe::from_str(&format!(
                    "cpe:/a:acme:product:1.0:update{i}:-:en-us"
                ))?);
            }

            creator.create(&db).await?;

            Ok::<_, anyhow::Error>(())
        });
    }

    // progress ingestion tasks

    let result = futures::future::join_all(tasks).await;

    // now test

    assert_all_ok(NUM, result);

    // done

    Ok(())
}

/// Ingest x * y licenses in parallel
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn license_creator(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    const NUM: usize = 25;
    const ITEMS: usize = 100;

    let mut tasks = vec![];

    for _ in 0..NUM {
        let db = ctx.db.clone();
        tasks.push(async move {
            let mut creator = LicenseCreator::new();

            for i in 0..ITEMS {
                creator.add(&LicenseInfo {
                    license: format!("FOO-{i}"),
                });
                creator.add(&LicenseInfo {
                    license: format!("BAR-{i}"),
                });
            }

            creator.create(&db).await?;

            Ok::<_, anyhow::Error>(())
        });
    }

    // progress ingestion tasks

    let result = futures::future::join_all(tasks).await;

    // now test

    assert_all_ok(NUM, result);

    // done

    Ok(())
}

/// Ingest advisories in parallel
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn advisories_parallel(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let mut data = vec![];
    data.push(document_bytes("osv/GHSA-gqp3-2cvr-x8m3.json.bz2").await?);
    data.push(document_bytes("osv/GHSA-h3gc-qfqq-6h8f.json.bz2").await?);
    let mut tasks = vec![];
    data.iter().for_each(|advisory| {
        let next = advisory.clone();
        let service = ctx.ingestor.clone();
        let db = ctx.db.clone();
        tasks.push(async move {
            db.transaction(async |tx| {
                service
                    .ingest(&next, Format::Advisory, (), None, Cache::Skip, tx)
                    .await
            })
            .await?;
            Ok::<_, anyhow::Error>(())
        });
    });

    // progress ingestion tasks
    let result = futures::future::join_all(tasks).await;

    // now test
    assert_all_ok(data.len(), result);

    // done
    Ok(())
}

/// Ingest SBOMs and Advisories in parallel
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn sbom_advisories_parallel(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Load all SBOMs from parallel test data
    let mut sbom_data = vec![];
    sbom_data.push(document_bytes("cyclonedx/rhel-9.2-eus.cdx.json.bz2").await?);
    sbom_data.push(document_bytes("spdx/rhel-9.2-eus.spdx.json.bz2").await?);

    // Load all advisories from parallel test data
    let mut advisory_data: Vec<Bytes> = vec![];
    advisory_data.push(document_bytes("csaf/RHSA-2024_2705.json.bz2").await?);
    advisory_data.push(document_bytes("csaf/RHSA-CVE-2024-29025.json.bz2").await?);

    // Create tasks for SBOM ingestion
    let mut sbom_tasks = vec![];
    sbom_data.iter().for_each(|sbom| {
        let next = sbom.clone();
        let service = ctx.ingestor.clone();
        let db = ctx.db.clone();
        sbom_tasks.push(async move {
            db.transaction(async |tx| {
                service
                    .ingest(&next, Format::SBOM, (), None, Cache::Skip, tx)
                    .await
            })
            .await?;
            Ok::<_, anyhow::Error>(())
        });
    });

    // Create tasks for advisory ingestion
    let mut advisory_tasks = vec![];
    advisory_data.iter().for_each(|advisory| {
        let next = advisory.clone();
        let service = ctx.ingestor.clone();
        let db = ctx.db.clone();
        advisory_tasks.push(async move {
            db.transaction(async |tx| {
                service
                    .ingest(&next, Format::Advisory, (), None, Cache::Skip, tx)
                    .await
            })
            .await?;
            Ok::<_, anyhow::Error>(())
        });
    });

    // Progress ingestion tasks concurrently
    let (sbom_result, advisory_result) = futures::future::join(
        futures::future::join_all(sbom_tasks),
        futures::future::join_all(advisory_tasks),
    )
    .await;

    // Verify all ingestions succeeded
    let mut all_results = sbom_result;
    all_results.extend(advisory_result);
    assert_all_ok(sbom_data.len() + advisory_data.len(), all_results);

    Ok(())
}

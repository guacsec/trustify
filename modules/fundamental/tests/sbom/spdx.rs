mod aliases;
mod corner_cases;
mod external;
mod issue_1417;
mod issue_552;
mod parallel;
mod perf;
mod reingest;

use super::*;
use serde_json::Value;
use std::str::FromStr;
use test_context::test_context;
use test_log::test;
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::model::Paginated;
use trustify_common::{id::Id, purl::Purl, sbom::spdx::parse_spdx};
use trustify_entity::relationship::Relationship;
use trustify_module_fundamental::{
    purl::model::{PurlHead, summary::purl::PurlSummary},
    sbom::{model::Which, service::SbomService},
};
use trustify_test_context::{TrustifyContext, spdx::fix_spdx_rels};

#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test)]
async fn parse_spdx_quarkus(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    test_with_spdx(
        ctx,
        "quarkus/v1/quarkus-bom-2.13.8.Final-redhat-00004.json",
        |WithContext { service, sbom, .. }| async move {
            let described = service
                .describes_packages(sbom.sbom.sbom_id, Paginated::default(), &ctx.db)
                .await?;
            log::debug!("{described:#?}");
            assert_eq!(1, described.items.len());
            let first = &described.items[0];

            assert_eq!(first.id, "SPDXRef-b52acd7c-3a3f-441e-aef0-bbdaa1ec8acf");
            assert_eq!(first.name, "quarkus-bom");
            assert_eq!(first.version, Some("2.13.8.Final-redhat-00004".to_string()));

            assert!(matches!(
                &first.purl[0],
                PurlSummary {
                    head: PurlHead {
                        purl,
                        ..
                    },
                    ..
                }
                if *purl == Purl::from_str("pkg:maven/com.redhat.quarkus.platform/quarkus-bom@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=pom")?
            ));

            assert_eq!(
                first.cpe[0],
                "cpe:/a:redhat:quarkus:2.13:*:el8:*"
            );

            let contains = service
                .related_packages(
                    sbom.sbom.sbom_id,
                    Relationship::Contains,
                    first,
                    &ctx.db,
                )
                .await?;

            log::debug!("{}", contains.len());

            assert!(contains.len() > 500);

            assert_eq!(sbom.sbom.authors, vec!["Organization: Red Hat Product Security (secalert@redhat.com)".to_string()]);
            assert_eq!(sbom.sbom.suppliers, vec!["Organization: Red Hat".to_string()]);

            Ok(())
        },
    ).await
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_parse_spdx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    test_with_spdx(
        ctx,
        "ubi9-9.2-755.1697625012.json",
        |WithContext { service, sbom, .. }| async move {
            let described = service
                .describes_packages(sbom.sbom.sbom_id, Paginated::default(), &ctx.db)
                .await?;

            assert_eq!(1, described.total);
            let first = &described.items[0];

            let contains = service
                .fetch_related_packages(
                    sbom.sbom.sbom_id,
                    Default::default(),
                    Paginated::default(),
                    Which::Left,
                    first,
                    Some(Relationship::Contains),
                    &ctx.db,
                )
                .await?
                .items;

            log::debug!("{}", contains.len());

            assert!(contains.len() > 500);

            Ok(())
        },
    )
    .await
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn ingest_spdx_broken_refs(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sbom = SbomService::new(ctx.db.clone());

    let err = ctx
        .ingest_document("spdx/broken-refs.json")
        .await
        .expect_err("must not ingest");

    assert_eq!(
        err.to_string(),
        "invalid content: Invalid reference: SPDXRef-0068e307-de91-4e82-b407-7a41217f9758"
    );

    let result = sbom
        .fetch_sboms(
            Default::default(),
            Default::default(),
            Default::default(),
            &ctx.db,
        )
        .await?;

    // there must be no traces, everything must be rolled back
    assert_eq!(result.total, 0);

    Ok(())
}

#[instrument(skip(ctx, f))]
pub async fn test_with_spdx<F>(ctx: &TrustifyContext, sbom: &str, f: F) -> anyhow::Result<()>
where
    F: AsyncFnOnce(WithContext) -> anyhow::Result<()>,
{
    test_with(
        ctx,
        sbom,
        |data| {
            let json: Value = serde_json::from_slice(data)?;
            let (sbom, _) = parse_spdx(&Discard, json)?;
            Ok(fix_spdx_rels(sbom))
        },
        async move |ctx, sbom, tx| {
            ctx.ingest_spdx(sbom.clone(), &Discard, tx).await?;
            Ok(())
        },
        |sbom| sbom::spdx::Information(sbom).into(),
        f,
    )
    .await
}

/// check ingest timestamp
#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test)]
async fn ingested_timestamp(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let start = OffsetDateTime::now_utc();

    test_with_spdx(
        ctx,
        "quarkus/v1/quarkus-bom-2.13.8.Final-redhat-00004.json",
        |WithContext { service, sbom, .. }| async move {
            let sbom = service
                .fetch_sbom_summary(Id::Uuid(sbom.sbom.sbom_id), &ctx.db)
                .await?
                .expect("must find the document");

            let ingested = sbom.source_document.ingested;
            let now = OffsetDateTime::now_utc();
            assert!(ingested > start && ingested < now);

            Ok(())
        },
    )
    .await
}

use std::convert::TryInto;
use std::str::FromStr;
use test_context::test_context;
use test_log::test;
use trustify_common::db::pagination_cache::PaginationCache;
use trustify_common::hashing::Digests;
use trustify_common::purl::Purl;
use trustify_common::sbom::SbomLocator;
use trustify_entity::relationship::Relationship;
use trustify_module_fundamental::purl::model::PurlHead;
use trustify_module_fundamental::purl::model::summary::purl::PurlSummary;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn ingest_sboms(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let system = &ctx.graph;

    let sbom_v1 = system
        .ingest_sbom(
            ("source", "http://sbom.com/test.json"),
            &Digests::digest("8"),
            Some("a".to_string()),
            (),
            &ctx.db,
        )
        .await?;
    let sbom_v1_again = system
        .ingest_sbom(
            ("source", "http://sbom.com/test.json"),
            &Digests::digest("8"),
            Some("b".to_string()),
            (),
            &ctx.db,
        )
        .await?;
    let sbom_v2 = system
        .ingest_sbom(
            ("source", "http://sbom.com/test.json"),
            &Digests::digest("9"),
            Some("c".to_string()),
            (),
            &ctx.db,
        )
        .await?;

    let _other_sbom = system
        .ingest_sbom(
            ("source", "http://sbom.com/other.json"),
            &Digests::digest("10"),
            Some("d".to_string()),
            (),
            &ctx.db,
        )
        .await?;

    assert_eq!(sbom_v1.sbom.sbom_id, sbom_v1_again.sbom.sbom_id);

    assert_ne!(sbom_v1.sbom.sbom_id, sbom_v2.sbom.sbom_id);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn ingest_and_fetch_sboms_describing_purls(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let system = &ctx.graph;

    let sbom_v1 = system
        .ingest_sbom(
            ("source", "http://sbom.com/test.json"),
            &Digests::digest("8"),
            Some("a".to_string()),
            (),
            &ctx.db,
        )
        .await?;
    let sbom_v2 = system
        .ingest_sbom(
            ("source", "http://sbom.com/test.json"),
            &Digests::digest("9"),
            Some("b".to_string()),
            (),
            &ctx.db,
        )
        .await?;
    let sbom_v3 = system
        .ingest_sbom(
            ("source", "http://sbom.com/test.json"),
            &Digests::digest("10"),
            Some("c".to_string()),
            (),
            &ctx.db,
        )
        .await?;

    sbom_v1
        .ingest_describes_package(
            "pkg:maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
            (),
            &ctx.db,
        )
        .await?;

    sbom_v2
        .ingest_describes_package(
            "pkg:maven/io.quarkus/quarkus-core@1.2.3".try_into()?,
            (),
            &ctx.db,
        )
        .await?;

    sbom_v3
        .ingest_describes_package(
            "pkg:maven/io.quarkus/quarkus-core@1.9.3".try_into()?,
            (),
            &ctx.db,
        )
        .await?;

    let found = system
        .locate_sboms(
            SbomLocator::Purl("pkg:maven/io.quarkus/quarkus-core@1.2.3".try_into()?),
            &ctx.db,
        )
        .await?;

    assert_eq!(2, found.len());
    assert!(found.contains(&sbom_v1));
    assert!(found.contains(&sbom_v2));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn ingest_and_locate_sboms_describing_cpes(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let system = &ctx.graph;

    let sbom_v1 = system
        .ingest_sbom(
            ("source", "http://sbom.com/test.json"),
            &Digests::digest("8"),
            Some("a".to_string()),
            (),
            &ctx.db,
        )
        .await?;
    let sbom_v2 = system
        .ingest_sbom(
            ("source", "http://sbom.com/test.json"),
            &Digests::digest("9"),
            Some("b".to_string()),
            (),
            &ctx.db,
        )
        .await?;
    let sbom_v3 = system
        .ingest_sbom(
            ("source", "http://sbom.com/test.json"),
            &Digests::digest("10"),
            Some("c".to_string()),
            (),
            &ctx.db,
        )
        .await?;

    sbom_v1
        .ingest_describes_cpe22("cpe:/a:redhat:quarkus:2.13::el8".parse()?, (), &ctx.db)
        .await?;

    sbom_v2
        .ingest_describes_cpe22("cpe:/a:redhat:quarkus:2.13::el8".parse()?, (), &ctx.db)
        .await?;

    sbom_v3
        .ingest_describes_cpe22("cpe:/a:redhat:not-quarkus:2.13::el8".parse()?, (), &ctx.db)
        .await?;

    let found = system
        .locate_sboms(
            SbomLocator::Cpe("cpe:/a:redhat:quarkus:2.13::el8".parse()?),
            &ctx.db,
        )
        .await?;

    assert_eq!(2, found.len());
    assert!(found.contains(&sbom_v1));
    assert!(found.contains(&sbom_v2));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn transitive_dependency_of(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let system = &ctx.graph;

    let sbom1 = system
        .ingest_sbom(
            ("source", "http://sbomsRus.gov/thing1.json"),
            &Digests::digest("8675309"),
            Some("a".to_string()),
            (),
            &ctx.db,
        )
        .await?;

    sbom1
        .ingest_package_relates_to_package(
            Purl::from_str("pkg:maven/io.quarkus/transitive-a@1.2.3")?,
            Relationship::Dependency,
            Purl::from_str("pkg:maven/io.quarkus/transitive-b@1.2.3")?,
            (),
            &ctx.db,
        )
        .await?;

    sbom1
        .ingest_package_relates_to_package(
            Purl::from_str("pkg:maven/io.quarkus/transitive-b@1.2.3")?,
            Relationship::Dependency,
            Purl::from_str("pkg:maven/io.quarkus/transitive-c@1.2.3")?,
            (),
            &ctx.db,
        )
        .await?;

    sbom1
        .ingest_package_relates_to_package(
            Purl::from_str("pkg:maven/io.quarkus/transitive-c@1.2.3")?,
            Relationship::Dependency,
            Purl::from_str("pkg:maven/io.quarkus/transitive-d@1.2.3")?,
            (),
            &ctx.db,
        )
        .await?;

    sbom1
        .ingest_package_relates_to_package(
            Purl::from_str("pkg:maven/io.quarkus/transitive-c@1.2.3")?,
            Relationship::Dependency,
            Purl::from_str("pkg:maven/io.quarkus/transitive-e@1.2.3")?,
            (),
            &ctx.db,
        )
        .await?;

    sbom1
        .ingest_package_relates_to_package(
            Purl::from_str("pkg:maven/io.quarkus/transitive-b@1.2.3")?,
            Relationship::Dependency,
            Purl::from_str("pkg:maven/io.quarkus/transitive-d@1.2.3")?,
            (),
            &ctx.db,
        )
        .await?;

    let _results = sbom1
        .related_packages_transitively(
            &[Relationship::Dependency],
            &"pkg:maven/io.quarkus/transitive-a@1.2.3".try_into()?,
            &ctx.db,
        )
        .await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn ingest_package_relates_to_package_dependency_of(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let system = &ctx.graph;
    let fetch = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

    let sbom1 = system
        .ingest_sbom(
            ("source", "http://sbomsRus.gov/thing1.json"),
            &Digests::digest("8675309"),
            Some("a".to_string()),
            (),
            &ctx.db,
        )
        .await?;

    sbom1
        .ingest_package_relates_to_package(
            Purl::from_str("pkg:maven/io.quarkus/quarkus-core@1.2.3")?,
            Relationship::Dependency,
            Purl::from_str("pkg:maven/io.quarkus/quarkus-postgres@1.2.3")?,
            (),
            &ctx.db,
        )
        .await?;

    let sbom2 = system
        .ingest_sbom(
            ("source", "http://sbomsRus.gov/thing2.json"),
            &Digests::digest("8675308"),
            Some("b".to_string()),
            (),
            &ctx.db,
        )
        .await?;

    sbom2
        .ingest_package_relates_to_package(
            Purl::from_str("pkg:maven/io.quarkus/quarkus-core@1.2.3")?,
            Relationship::Dependency,
            Purl::from_str("pkg:maven/io.quarkus/quarkus-sqlite@1.2.3")?,
            (),
            &ctx.db,
        )
        .await?;

    let dependencies = fetch
        .related_packages(
            sbom1.sbom.sbom_id,
            Relationship::Dependency,
            "pkg:maven/io.quarkus/quarkus-core@1.2.3",
            &ctx.db,
        )
        .await?;

    assert_eq!(1, dependencies.len());

    assert!(matches!(
        &dependencies[0].purl[0],
        PurlSummary {
            head: PurlHead {
                purl,
                ..
            },
            ..
        }
        if *purl == Purl::from_str("pkg:maven/io.quarkus/quarkus-postgres@1.2.3")?
    ));

    let dependencies = fetch
        .related_packages(
            sbom2.sbom.sbom_id,
            Relationship::Dependency,
            "pkg:maven/io.quarkus/quarkus-core@1.2.3",
            &ctx.db,
        )
        .await?;

    assert_eq!(1, dependencies.len());

    assert!(matches!(
        &dependencies[0].purl[0],
        PurlSummary {
            head: PurlHead {
                purl,
                ..
            },
            ..
        }
        if *purl == Purl::from_str("pkg:maven/io.quarkus/quarkus-sqlite@1.2.3")?
    ));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn sbom_vulnerabilities(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let system = &ctx.graph;

    log::debug!("{system:?}");

    let sbom = system
        .ingest_sbom(
            ("source", "http://sbomsRus.gov/thing1.json"),
            &Digests::digest("8675309"),
            Some("a".to_string()),
            (),
            &ctx.db,
        )
        .await?;

    log::debug!("-------------------- A");

    sbom.ingest_describes_package("pkg:oci/my-app@1.2.3".try_into()?, (), &ctx.db)
        .await?;
    log::debug!("-------------------- B");

    sbom.ingest_package_relates_to_package(
        Purl::from_str("pkg:oci/my-app@1.2.3")?,
        Relationship::Dependency,
        Purl::from_str("pkg:maven/io.quarkus/quarkus-core@1.2.3")?,
        (),
        &ctx.db,
    )
    .await?;
    log::debug!("-------------------- C");

    sbom.ingest_package_relates_to_package(
        Purl::from_str("pkg:maven/io.quarkus/quarkus-core@1.2.3")?,
        Relationship::Dependency,
        Purl::from_str("pkg:maven/io.quarkus/quarkus-postgres@1.2.3")?,
        (),
        &ctx.db,
    )
    .await?;
    log::debug!("-------------------- D");

    sbom.ingest_package_relates_to_package(
        Purl::from_str("pkg:maven/io.quarkus/quarkus-postgres@1.2.3")?,
        Relationship::Dependency,
        Purl::from_str("pkg:maven/postgres/postgres-driver@1.2.3")?,
        (),
        &ctx.db,
    )
    .await?;

    let advisory = system
        .ingest_advisory(
            "RHSA-1",
            ("source", "http://redhat.com/secdata/RHSA-1"),
            &Digests::digest("7"),
            (),
            &ctx.db,
        )
        .await?;

    let _advisory_vulnerability = advisory
        .link_to_vulnerability("CVE-00000001", None, &ctx.db)
        .await?;

    Ok(())
}

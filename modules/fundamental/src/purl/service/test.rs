use crate::{
    advisory::service::AdvisoryService,
    purl::{model::details::purl::StatusContext, service::PurlService},
    sbom::service::SbomService,
};
use std::str::FromStr;
use test_context::test_context;
use test_log::test;
use trustify_common::{
    db::query::{Query, q},
    id::Id,
    model::Paginated,
    purl::Purl,
};
use trustify_test_context::TrustifyContext;

async fn ingest_extra_packages(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.graph
        .ingest_package(&Purl::from_str("pkg:maven/org.myspace/tom")?, &ctx.db)
        .await?;
    ctx.graph
        .ingest_package(&Purl::from_str("pkg:rpm/sendmail")?, &ctx.db)
        .await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn types(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new();

    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?repository_url=http://jboss.org")?,
            &ctx.db,
        )
        .await?;

    ingest_extra_packages(ctx).await?;

    let types = service.purl_types(&ctx.db).await?;

    assert_eq!(2, types.len());

    let rpm = types.iter().find(|e| e.head.name == "rpm");
    let maven = types.iter().find(|e| e.head.name == "maven");

    assert!(rpm.is_some());
    assert!(maven.is_some());

    let rpm = rpm.unwrap();
    let maven = maven.unwrap();

    assert_eq!(rpm.counts.base, 1);
    assert_eq!(rpm.counts.version, 0);
    assert_eq!(rpm.counts.package, 0);

    assert_eq!(maven.counts.base, 2);
    assert_eq!(maven.counts.version, 1);
    assert_eq!(maven.counts.package, 2);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn packages_for_type(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new();

    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.4")?,
            &ctx.db,
        )
        .await?;

    log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.5")?,
            &ctx.db,
        )
        .await?;

    ingest_extra_packages(ctx).await?;

    let packages = service
        .base_purls_by_type("maven", Query::default(), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(packages.total, 2);

    assert!(
        packages
            .items
            .iter()
            .any(|e| e.head.purl.to_string() == "pkg:maven/org.apache/log4j")
    );

    assert!(
        packages
            .items
            .iter()
            .any(|e| e.head.purl.to_string() == "pkg:maven/org.myspace/tom")
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn packages_for_type_with_filtering(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new();

    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.4")?,
            &ctx.db,
        )
        .await?;

    log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.5")?,
            &ctx.db,
        )
        .await?;

    ingest_extra_packages(ctx).await?;

    let packages = service
        .base_purls_by_type("maven", q("myspace"), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(packages.total, 1);

    assert!(
        packages
            .items
            .iter()
            .any(|e| e.head.purl.to_string() == "pkg:maven/org.myspace/tom")
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn package(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new();

    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?repository_url=http://maven.org")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?repository_url=http://jboss.org")?,
            &ctx.db,
        )
        .await?;

    let _log4j_124 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.4")?,
            &ctx.db,
        )
        .await?;

    log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.5")?,
            &ctx.db,
        )
        .await?;

    let tom = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.myspace/tom")?, &ctx.db)
        .await?;

    tom.ingest_package_version(&Purl::from_str("pkg:maven/org.myspace/tom@1.1.1")?, &ctx.db)
        .await?;

    tom.ingest_package_version(&Purl::from_str("pkg:maven/org.myspace/tom@9.9.9")?, &ctx.db)
        .await?;

    ctx.graph
        .ingest_package(&Purl::from_str("pkg:rpm/sendmail")?, &ctx.db)
        .await?;

    let bind = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:rpm/bind")?, &ctx.db)
        .await?;

    bind.ingest_package_version(&Purl::from_str("pkg:rpm/bind@4.4.4")?, &ctx.db)
        .await?;

    let results = service
        .base_purl("maven", Some("org.apache".to_string()), "log4j", &ctx.db)
        .await?;

    assert!(results.is_some());

    let log4j = results.unwrap();

    assert_eq!("pkg:maven/org.apache/log4j", log4j.head.purl.to_string());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn package_version(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new();

    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=11")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=17")?,
            &ctx.db,
        )
        .await?;

    let log4j_345 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5")?,
            &ctx.db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    let results = service
        .versioned_purl(
            "maven",
            Some("org.apache".to_string()),
            "log4j",
            "1.2.3",
            &ctx.db,
        )
        .await?;

    assert!(results.is_some());

    let log4j_123 = results.unwrap();

    assert_eq!(
        "pkg:maven/org.apache/log4j@1.2.3",
        log4j_123.head.purl.to_string()
    );

    assert_eq!(2, log4j_123.purls.len());

    assert!(
        log4j_123
            .purls
            .iter()
            .any(|e| e.purl.to_string() == "pkg:maven/org.apache/log4j@1.2.3?jdk=11")
    );

    assert!(
        log4j_123
            .purls
            .iter()
            .any(|e| e.purl.to_string() == "pkg:maven/org.apache/log4j@1.2.3?jdk=17")
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn package_version_by_uuid(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new();

    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=11")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=17")?,
            &ctx.db,
        )
        .await?;

    let log4j_345 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5")?,
            &ctx.db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    let result = service
        .versioned_purl_by_uuid(&log4j_123.package_version.id, &ctx.db)
        .await?;

    assert!(result.is_some());

    let log4j_123 = result.unwrap();

    assert_eq!(
        "pkg:maven/org.apache/log4j@1.2.3",
        log4j_123.head.purl.to_string()
    );

    assert_eq!(2, log4j_123.purls.len());

    assert!(
        log4j_123
            .purls
            .iter()
            .any(|e| e.purl.to_string() == "pkg:maven/org.apache/log4j@1.2.3?jdk=11")
    );

    assert!(
        log4j_123
            .purls
            .iter()
            .any(|e| e.purl.to_string() == "pkg:maven/org.apache/log4j@1.2.3?jdk=17")
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn packages(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new();

    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=11")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=17")?,
            &ctx.db,
        )
        .await?;

    let log4j_345 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5")?,
            &ctx.db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    let quarkus = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.jboss/quarkus")?, &ctx.db)
        .await?;

    let quarkus_123 = quarkus
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.jboss/quarkus@1.2.3")?,
            &ctx.db,
        )
        .await?;

    quarkus_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.jboss/quarkus@1.2.3?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    let results = service
        .base_purls(q("log4j"), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(1, results.items.len());

    let results = service
        .base_purls(q("quarkus"), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(1, results.items.len());

    let results = service
        .base_purls(q("jboss"), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(1, results.items.len());

    let results = service
        .base_purls(q("maven"), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(2, results.items.len());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn qualified_packages(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new();

    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=11")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=17")?,
            &ctx.db,
        )
        .await?;

    let log4j_345 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5")?,
            &ctx.db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    let quarkus = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.jboss/quarkus")?, &ctx.db)
        .await?;

    let quarkus_123 = quarkus
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.jboss/quarkus@1.2.3")?,
            &ctx.db,
        )
        .await?;

    quarkus_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.jboss/quarkus@1.2.3?repository_url=http://jboss.org/")?,
            &ctx.db,
        )
        .await?;

    let results = service
        .purls(q("log4j"), Paginated::default(), &ctx.db)
        .await?;

    log::debug!("{results:#?}");
    assert_eq!(3, results.items.len());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn qualified_packages_filter_by_license(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new();

    let _mtv = ctx.ingest_document("spdx/mtv-2.6.json").await?;

    let results = service
        .purls(
            q("license=GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    // log::debug!("{results:#?}");
    // MTV SBOM contains 2 packages with the specified license
    assert_eq!(2, results.items.len());

    let results = service
        .purls(
            q("license=GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD&libstdc++"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("{results:#?}");
    assert_eq!(1, results.items.len());

    let results = service
        .purls(
            q("license=GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD|Apache License 2.0"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("{results:#?}");
    assert_eq!(4, results.items.len());

    let results = service
        .purls(
            q("license~GPLv3+ with exceptions|Apache"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("{results:#?}");
    // 'GPLv3+ with exceptions' is used in:
    // "LicenseRef-12" => used in 2 packages
    // "LicenseRef-16" => used in 1 package
    //
    // 'Apache' is used in:
    // "LicenseRef-0" => used in 2 packages
    // "LicenseRef-Apache" => never used in any package
    // + directly declared in 52 packages
    // Total = used in 57 packages
    assert_eq!(57, results.items.len());

    let results = service
        .purls(
            q("license=GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD&lib"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("{results:#?}");
    assert_eq!(2, results.items.len());

    ctx.ingest_document("cyclonedx/rh/latest_filters/container/quay_builder_qemu_rhcos_rhel8_2025-02-24/quay-builder-qemu-rhcos-rhel-8-amd64.json")
        .await?;
    let results = service
        .purls(
            q("license=GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD&lib"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("{results:#?}");
    assert_eq!(4, results.items.len());

    let results = service
        .purls(
            q("license=GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD&lib&version=8.5.0-22.el8_10"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("{results:#?}");
    assert_eq!(2, results.items.len());

    let results = service
        .purls(
            q("license=GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD"),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    log::debug!("{results:#?}");
    assert_eq!(0, results.items.len());

    // Negative test: empty license query
    let empty_results = service
        .purls(q("license="), Paginated::default(), &ctx.db)
        .await?;
    log::debug!("Empty license query results: {empty_results:#?}");
    // Should return no items or handle gracefully
    assert_eq!(0, empty_results.items.len());

    // Negative test: malformed license query
    let malformed_results = service
        .purls(q("license=!!!not_a_license"), Paginated::default(), &ctx.db)
        .await?;
    log::debug!("Malformed license query results: {malformed_results:#?}");
    // Should return no items or handle gracefully
    assert_eq!(0, malformed_results.items.len());

    // Negative test: invalid license query
    let invalid_results = service
        .purls(q("license=INVALID_LICENSE"), Paginated::default(), &ctx.db)
        .await?;
    log::debug!("Invalid license query results: {invalid_results:#?}");
    // Should return no items or handle gracefully
    assert_eq!(0, invalid_results.items.len());

    // Pagination for just having the total count
    let results = service
        .purls(
            q("license=GPLv3+ and GPLv3+ with exceptions and GPLv2+ with exceptions and LGPLv2+ and BSD"),
            Paginated {
                offset: 0,
                limit: 1,
            },
            &ctx.db,
        )
        .await?;

    log::debug!("{results:#?}");
    assert_eq!(1, results.items.len());
    assert_eq!(4, results.total);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn statuses(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new();
    ctx.ingest_documents(["osv/RUSTSEC-2021-0079.json", "cve/CVE-2021-32714.json"])
        .await?;

    ctx.ingestor
        .graph()
        .ingest_qualified_package(&Purl::from_str("pkg:cargo/hyper@0.14.1")?, &ctx.db)
        .await?;

    let results = service
        .purls(Query::default(), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(1, results.items.len());

    let uuid = results.items[0].head.uuid;

    let results = service
        .purl_by_uuid(&uuid, Default::default(), &ctx.db)
        .await?;

    assert_eq!(uuid, results.unwrap().head.uuid);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn contextual_status(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new();

    ctx.ingest_document("csaf/rhsa-2024_3666.json").await?;

    let results = service
        .purls(Query::default(), Paginated::default(), &ctx.db)
        .await?;

    let tomcat_jsp = results
        .items
        .iter()
        .find(|e| e.head.purl.to_string().contains("tomcat-jsp"));

    assert!(tomcat_jsp.is_some());

    let tomcat_jsp = tomcat_jsp.unwrap();

    let uuid = tomcat_jsp.head.uuid;

    let tomcat_jsp = service
        .purl_by_uuid(&uuid, Default::default(), &ctx.db)
        .await?;

    assert!(tomcat_jsp.is_some());

    let tomcat_jsp = tomcat_jsp.unwrap();

    assert_eq!(1, tomcat_jsp.advisories.len());

    let advisory = &tomcat_jsp.advisories[0];

    log::debug!("{advisory:#?}");

    assert_eq!(2, advisory.status.len());

    assert!( advisory.status.iter().any(|status| {
        matches!( &status.context , Some(StatusContext::Cpe(cpe)) if cpe == "cpe:/a:redhat:enterprise_linux:8:*:appstream:*")
        && status.vulnerability.identifier == "CVE-2024-24549" && status.status == "fixed"
    }));

    assert!( advisory.status.iter().any(|status| {
        matches!( &status.context , Some(StatusContext::Cpe(cpe)) if cpe == "cpe:/a:redhat:enterprise_linux:8:*:appstream:*")
            && status.vulnerability.identifier == "CVE-2024-23672" && status.status == "fixed"
    }));

    let versioned = service
        .versioned_purl_by_uuid(&tomcat_jsp.version.uuid, &ctx.db)
        .await?
        .unwrap();

    assert_eq!(1, versioned.advisories.len());

    let advisory = &versioned.advisories[0];

    log::debug!("{advisory:#?}");

    assert_eq!(2, advisory.status.len());

    assert!(advisory.status.iter().any(|status| {
        status.vulnerability.identifier == "CVE-2024-24549" && status.status == "fixed"
    }));

    assert!(advisory.status.iter().any(|status| {
        status.vulnerability.identifier == "CVE-2024-23672" && status.status == "fixed"
    }));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn gc_purls(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let purl_service = PurlService::new();
    assert_eq!(
        0,
        purl_service
            .purls(Query::default(), Paginated::default(), &ctx.db)
            .await?
            .items
            .len()
    );

    // ingest an sbom..
    let quarkus_sbom = ctx
        .ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;

    // it creates lots of purls
    assert_eq!(
        880,
        purl_service
            .purls(Query::default(), Paginated::default(), &ctx.db)
            .await?
            .items
            .len()
    );

    // ingest another sbom..
    let ubi9_sbom = ctx.ingest_document("ubi9-9.2-755.1697625012.json").await?;

    // it now we have more purls
    assert_eq!(
        1490,
        purl_service
            .purls(Query::default(), Paginated::default(), &ctx.db)
            .await?
            .items
            .len()
    );

    // delete the sbom...
    async fn delete_sbom_and_advisories(
        ctx: &TrustifyContext,
        id: Id,
    ) -> Result<(), anyhow::Error> {
        let svc = SbomService::new(ctx.db.clone());
        let sbom = svc
            .fetch_sbom_details(id, vec![], &ctx.db)
            .await?
            .expect("fetch_sbom");
        assert!(svc.delete_sbom(sbom.summary.head.id, &ctx.db).await?);

        // delete the advisories in the sbom...
        let svc = AdvisoryService::new(ctx.db.clone());
        for a in sbom.advisories {
            assert!(svc.delete_advisory(a.head.uuid, &ctx.db).await?);
        }
        Ok(())
    }

    // delete the ubi sbom....
    delete_sbom_and_advisories(ctx, ubi9_sbom.id).await?;

    // it should leave behind orphaned purls
    let result = purl_service
        .purls(Query::default(), Paginated::default(), &ctx.db)
        .await?;
    assert_eq!(1490, result.items.len());

    // running the gc, should delete those orphaned purls
    let deleted_records_count = purl_service.gc_purls(&ctx.db).await?;
    assert_eq!(978, deleted_records_count);

    let result = purl_service
        .purls(Query::default(), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(880, result.items.len());

    // delete the quarkus sbom....
    delete_sbom_and_advisories(ctx, quarkus_sbom.id).await?;

    // it should leave behind orphaned purls
    let result = purl_service
        .purls(Query::default(), Paginated::default(), &ctx.db)
        .await?;
    assert_eq!(880, result.items.len());

    // running the gc, should delete those orphaned purls
    let deleted_records_count = purl_service.gc_purls(&ctx.db).await?;
    assert_eq!(2639, deleted_records_count);

    let result = purl_service
        .purls(Query::default(), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(0, result.items.len());
    Ok(())
}

async fn ingest_some_log4j_data(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let log4j = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, &ctx.db)
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=11")?,
            &ctx.db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn unqualified_purl_by_purl(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new();

    ingest_some_log4j_data(ctx).await?;

    let purl = "pkg:maven/org.apache/log4j@1.2.3";

    let results = service
        .purl_by_purl(&Purl::from_str(purl)?, Default::default(), &ctx.db)
        .await?
        .unwrap();

    log::debug!("{results:#?}");
    assert_eq!(results.head.purl.to_string(), purl);
    assert_eq!(results.version.version, "1.2.3");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn base_purl_by_purl(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new();

    ingest_some_log4j_data(ctx).await?;

    let results = service
        .base_purl_by_purl(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    assert!(!results.unwrap().versions.is_empty());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn versioned_base_purl_by_purl(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = PurlService::new();

    ingest_some_log4j_data(ctx).await?;

    let results = service
        .versioned_purl_by_purl(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?,
            &ctx.db,
        )
        .await?;

    assert!(!results.unwrap().purls.is_empty());

    Ok(())
}

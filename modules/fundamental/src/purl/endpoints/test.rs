use crate::purl::model::details::base_purl::BasePurlDetails;
use crate::purl::model::summary::base_purl::BasePurlSummary;
use crate::purl::model::summary::purl::PurlSummary;
use crate::test::caller;
use actix_web::test::TestRequest;
use serde_json::{Value, json};
use std::str::FromStr;
use test_context::test_context;
use test_log::test;
use trustify_common::db::Database;
use trustify_common::model::PaginatedResults;
use trustify_common::purl::Purl;
use trustify_module_ingestor::graph::Graph;
use trustify_test_context::{TrustifyContext, call::CallService, subset::ContainsSubset};
use urlencoding::encode;
use uuid::Uuid;

async fn setup(db: &Database, graph: &Graph) -> Result<(), anyhow::Error> {
    let log4j = graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, db)
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?, db)
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=11")?,
            db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=17")?,
            db,
        )
        .await?;

    let log4j_345 = log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@3.4.5")?, db)
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            db,
        )
        .await?;

    let sendmail = graph
        .ingest_package(&Purl::from_str("pkg:rpm/sendmail")?, db)
        .await?;

    let _sendmail_444 = sendmail
        .ingest_package_version(&Purl::from_str("pkg:rpm/sendmail@4.4.4")?, db)
        .await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn base_purls(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    setup(&ctx.db, &ctx.graph).await?;
    let app = caller(ctx).await?;

    let uri = "/api/v2/purl/base?q=log4j";
    let request = TestRequest::get().uri(uri).to_request();
    let log4j: PaginatedResults<BasePurlSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(1, log4j.items.len());

    let uri = format!("/api/v2/purl/base/{}", log4j.items[0].head.uuid);
    let request = TestRequest::get().uri(&uri).to_request();
    let response: BasePurlDetails = app.call_and_read_body_json(request).await;
    assert_eq!(log4j.items[0].head.uuid, response.head.uuid);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn qualified_packages(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    setup(&ctx.db, &ctx.graph).await?;
    let app = caller(ctx).await?;

    let uri = "/api/v2/purl?q=log4j";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<PurlSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(3, response.items.len());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn qualified_packages_filtering(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    setup(&ctx.db, &ctx.graph).await?;
    let app = caller(ctx).await?;

    let uri = format!("/api/v2/purl?q={}", encode("type=maven"));
    let request = TestRequest::get().uri(&uri).to_request();
    let response: PaginatedResults<PurlSummary> = app.call_and_read_body_json(request).await;
    assert_eq!(3, response.items.len());

    ctx.ingestor
        .graph()
        .ingest_qualified_package(
            &Purl::from_str("pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386")?,
            &ctx.db,
        )
        .await?;
    let uri = format!("/api/v2/purl?q={}", encode("type=rpm&arch=i386"));
    let request = TestRequest::get().uri(&uri).to_request();
    let response: PaginatedResults<PurlSummary> = app.call_and_read_body_json(request).await;
    assert_eq!(1, response.items.len());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn package_with_status(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingestor
        .graph()
        .ingest_qualified_package(&Purl::from_str("pkg:cargo/hyper@0.14.1")?, &ctx.db)
        .await?;

    ctx.ingest_documents(["osv/RUSTSEC-2021-0079.json", "cve/CVE-2021-32714.json"])
        .await?;

    let app = caller(ctx).await?;

    let uri = "/api/v2/purl?q=hyper";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<PurlSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(1, response.items.len());

    let uuid = response.items[0].head.uuid;

    let uri = format!("/api/v2/purl/{uuid}");

    let request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");

    assert_eq!(uuid, Uuid::parse_str(response["uuid"].as_str().unwrap())?);
    assert_eq!(
        "high",
        response["advisories"][0]["status"][0]["average_severity"]
    );
    assert_eq!(
        "CVE-2021-32714",
        response["advisories"][0]["status"][0]["vulnerability"]["identifier"]
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn purl_component_queries(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let purl = Purl::from_str("pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25")?;
    let uuid = ctx
        .ingestor
        .graph()
        .ingest_qualified_package(&purl, &ctx.db)
        .await?
        .qualified_package
        .id;
    let query = async |query| {
        let app = caller(ctx).await.unwrap();
        let uri = format!("/api/v2/purl?q={}", urlencoding::encode(query));
        let request = TestRequest::get().uri(&uri).to_request();
        let response: PaginatedResults<PurlSummary> = app.call_and_read_body_json(request).await;
        tracing::debug!(test = "", "{response:#?}");
        assert_eq!(1, response.items.len(), "'q={query}'");
        assert_eq!(uuid, response.items[0].head.uuid, "'q={query}'");
        assert_eq!(purl, response.items[0].head.purl, "'q={query}'");
    };

    for each in [
        "curl",
        "fedora",
        "type=rpm",
        "namespace=fedora",
        "name=curl",
        "name~url&namespace~dora",
        "version=7.50.3-1.fc25",
        "version>=7.49",
        "version<=7.51",
        "version>6",
        "version<8",
        "distro~fedora",
        "arch=i386&name=curl",
    ] {
        query(each).await;
    }

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn purl_filter_queries(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/quarkus-bom-3.2.11.Final-redhat-00001.json"])
        .await?;

    const PURL: &str = "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=pom";

    let query = async |query| {
        let app = caller(ctx).await.unwrap();
        let uri = format!("/api/v2/purl?q={}&sort=purl:qualifiers:type", encode(query));
        let request = TestRequest::get().uri(&uri).to_request();
        let response: PaginatedResults<PurlSummary> = app.call_and_read_body_json(request).await;
        tracing::debug!(test = "", "{response:#?}");
        assert_eq!(1, response.items.len(), "'q={query}'");
        assert_eq!(PURL, response.items[0].head.purl.to_string(), "'q={query}'");
    };

    for each in [
        r"purl=pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?repository_url=https://maven.repository.redhat.com/ga/\&type=pom",
        "purl~pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001&qualifiers:type=pom&repository_url=https://maven.repository.redhat.com/ga/",
        "purl~pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001&purl:qualifiers:type=pom&purl:qualifiers:repository_url=https://maven.repository.redhat.com/ga/",
        // "purl~quarkus-bom@3.2.11.Final-redhat", // cross-component query
        "qualifiers:type=pom&type=maven", // note the two types
        "quarkus-bom&qualifiers:type=pom&type=maven", // full text search filtered to match 1
        "ty=maven&purl:ty=maven&type=maven&purl:type=maven&purl:qualifiers:type=pom&qualifiers:type=pom",
    ] {
        query(each).await;
    }

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_purl_license_details(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents(["spdx/OCP-TOOLS-4.11-RHEL-8.json"])
        .await?;

    let uri = "/api/v2/purl?q=graphite2";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<PurlSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(1, response.items.len());

    let uuid = response.items[0].head.uuid;

    let uri = format!("/api/v2/purl/{uuid}");

    let request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    let expected_result = json!({
      "uuid": "7ff60cd2-d779-586e-b829-cc6d51750450",
      "purl": "pkg:rpm/redhat/graphite2@1.3.10-10.el8?arch=ppc64le",
      "version": {
        "uuid": "57664d22-7f7f-56a0-9c38-9b0dc203b322",
        "purl": "pkg:rpm/redhat/graphite2@1.3.10-10.el8",
        "version": "1.3.10-10.el8"
      },
      "base": {
        "uuid": "ba5eb886-34f6-5830-8902-a6182a6a8d7d",
        "purl": "pkg:rpm/redhat/graphite2"
      },
      "advisories": [],
      "licenses": [
        {
          "license_name": "(LicenseRef-8 OR LicenseRef-0 OR LicenseRef-MPL) AND (LicenseRef-Netscape OR LicenseRef-0 OR LicenseRef-8)",
          "license_type": "declared"
        },
        {
          "license_name": "NOASSERTION",
          "license_type": "concluded"
        }
      ],
      "licenses_ref_mapping": [
        {
          "license_id": "LicenseRef-Netscape",
          "license_name": "Netscape"
        },
        {
          "license_id": "LicenseRef-MPL",
          "license_name": "MPL"
        },
        {
          "license_id": "LicenseRef-8",
          "license_name": "LGPLv2+"
        },
        {
          "license_id": "LicenseRef-0",
          "license_name": "GPLv2+"
        }
      ]
    });
    assert!(expected_result.contains_subset(response.clone()));
    Ok(())
}

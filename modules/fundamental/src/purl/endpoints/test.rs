use crate::{
    purl::model::{
        details::base_purl::BasePurlDetails,
        summary::{base_purl::BasePurlSummary, purl::PurlSummary},
    },
    test::caller,
};
use actix_web::test::TestRequest;
use rstest::rstest;
use serde_json::{Value, json};
use std::str::FromStr;
use test_context::test_context;
use test_log::test;
use trustify_common::{db::Database, model::PaginatedResults, purl::Purl};
use trustify_module_ingestor::graph::Graph;
use trustify_test_context::{TrustifyContext, call::CallService, subset::ContainsSubset};
use urlencoding::encode;
use uuid::Uuid;

async fn recommend(app: &impl CallService, purls: &[&str]) -> Value {
    app.call_and_read_body_json(
        TestRequest::post()
            .uri("/api/v3/purl/recommend")
            .set_json(json!({ "purls": purls }))
            .to_request(),
    )
    .await
}

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

    let uri = "/api/v3/purl/base?q=log4j";
    let request = TestRequest::get().uri(uri).to_request();
    let log4j: PaginatedResults<BasePurlSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(1, log4j.items.len());

    let uri = format!("/api/v3/purl/base/{}", log4j.items[0].head.uuid);
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

    let uri = "/api/v3/purl?q=log4j";
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

    let uri = format!("/api/v3/purl?q={}", encode("type=maven"));
    let request = TestRequest::get().uri(&uri).to_request();
    let response: PaginatedResults<PurlSummary> = app.call_and_read_body_json(request).await;
    assert_eq!(3, response.items.len());

    ctx.graph
        .ingest_qualified_package(
            &Purl::from_str("pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386")?,
            &ctx.db,
        )
        .await?;
    let uri = format!("/api/v3/purl?q={}", encode("type=rpm&arch=i386"));
    let request = TestRequest::get().uri(&uri).to_request();
    let response: PaginatedResults<PurlSummary> = app.call_and_read_body_json(request).await;
    assert_eq!(1, response.items.len());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn package_with_status(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.graph
        .ingest_qualified_package(&Purl::from_str("pkg:cargo/hyper@0.14.1")?, &ctx.db)
        .await?;

    ctx.ingest_documents(["osv/RUSTSEC-2021-0079.json", "cve/CVE-2021-32714.json"])
        .await?;

    let app = caller(ctx).await?;

    let uri = "/api/v3/purl?q=hyper";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<PurlSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(1, response.items.len());

    let uuid = response.items[0].head.uuid;

    let uri = format!("/api/v3/purl/{uuid}");

    let request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");

    assert_eq!(uuid, Uuid::parse_str(response["uuid"].as_str().unwrap())?);
    assert_eq!(
        response["advisories"][0]["status"][0]["scores"],
        json!([
            {"type": "3.1", "value": 9.1, "severity": "critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"},
            {"type": "3.1", "value": 5.9, "severity": "medium",   "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"},
        ])
    );
    assert_eq!(
        "CVE-2021-32714",
        response["advisories"][0]["status"][0]["vulnerability"]["identifier"]
    );
    // Deprecated average fields must not appear.
    assert_eq!(
        response["advisories"][0]["status"][0]["average_score"],
        Value::Null
    );
    assert_eq!(
        response["advisories"][0]["status"][0]["average_severity"],
        Value::Null
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn purl_component_queries(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let purl = Purl::from_str("pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25")?;
    let uuid = ctx
        .graph
        .ingest_qualified_package(&purl, &ctx.db)
        .await?
        .qualified_package
        .id;
    let query = async |query| {
        let app = caller(ctx).await.unwrap();
        let uri = format!("/api/v3/purl?q={}", urlencoding::encode(query));
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
        let uri = format!("/api/v3/purl?q={}&sort=purl:qualifiers:type", encode(query));
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

    let uri = "/api/v3/purl?q=graphite2";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<PurlSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(1, response.items.len());

    let uuid = response.items[0].head.uuid;

    let uri = format!("/api/v3/purl/{uuid}");

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
          "license_name": "(LGPLv2+ OR GPLv2+ OR MPL) AND (Netscape OR GPLv2+ OR LGPLv2+)",
          "license_type": "declared"
        },
        {
          "license_name": "NOASSERTION",
          "license_type": "concluded"
        }
      ],
      "licenses_ref_mapping": []
    });
    assert!(expected_result.contains_subset(response.clone()));
    Ok(())
}

/// Verifies that duplicate input PURLs are deduplicated and recommendations include the correct upgraded package and vulnerabilities.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given advisories for multiple CVEs are ingested
    ctx.ingest_documents([
        "cve/CVE-2022-45787.json",
        "cve/CVE-2023-28867.json",
        "cve/CVE-2024-29025.json",
    ])
    .await?;

    // When requesting recommendations for a duplicated PURL
    let app = caller(ctx).await?;
    let recommendations = recommend(
        &app,
        &[
            "pkg:maven/jakarta.el/jakarta.el-api@3.0.3",
            "pkg:maven/jakarta.el/jakarta.el-api@3.0.3",
        ],
    )
    .await;

    log::info!("{recommendations:#?}");

    // Then a single recommendation entry is returned with both CVEs
    assert_eq!(
        recommendations["recommendations"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        recommendations["recommendations"]
            .as_object()
            .unwrap()
            ["pkg:maven/jakarta.el/jakarta.el-api@3.0.3"]
            .as_array()
            .unwrap()
            .len(),
            1
    );
    assert_eq!(
        recommendations["recommendations"]["pkg:maven/jakarta.el/jakarta.el-api@3.0.3"][0]["package"],
        "pkg:maven/jakarta.el/jakarta.el-api@3.0.3.redhat-00002",
    );

    let mut cves = recommendations["recommendations"]["pkg:maven/jakarta.el/jakarta.el-api@3.0.3"]
        [0]["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|val| val["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    cves.sort();
    assert_eq!(cves, vec!["CVE-2022-45787", "CVE-2023-28867"]);

    Ok(())
}

/// Verifies that PURLs without a version produce no recommendations.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_no_version(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given advisories are ingested
    ctx.ingest_documents(["cve/CVE-2022-45787.json", "cve/CVE-2023-28867.json"])
        .await?;

    // When requesting recommendations for a PURL without a version
    let app = caller(ctx).await?;
    let recommendations = recommend(&app, &["pkg:maven/jakarta.el/jakarta.el-api"]).await;

    log::info!("{recommendations:#?}");

    // Then no recommendations are returned
    assert_eq!(
        recommendations["recommendations"]
            .as_object()
            .unwrap()
            .len(),
        0
    );

    Ok(())
}

/// Verifies that duplicate advisories for the same CVE produce a single vulnerability entry.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_dedup(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given a Red Hat package and two duplicate advisories for the same CVE
    ctx.graph
        .ingest_qualified_package(
            &Purl::from_str("pkg:cargo/hyper@0.14.1-redhat-00001")?,
            &ctx.db,
        )
        .await?;

    ctx.ingest_documents([
        "osv/RUSTSEC-2021-0079.json",
        "osv/RUSTSEC-2021-0079-DUPLICATE.json",
    ])
    .await?;

    // When requesting recommendations
    let app = caller(ctx).await?;
    let recommendations = recommend(&app, &["pkg:cargo/hyper@0.14.1"]).await;

    log::info!("{recommendations:#?}");

    // Then the recommendation contains a single deduplicated vulnerability
    let entry =
        &recommendations["recommendations"].as_object().unwrap()["pkg:cargo/hyper@0.14.1"][0];
    assert_eq!(entry["vulnerabilities"].as_array().unwrap().len(), 1);
    assert_eq!(
        entry["vulnerabilities"].as_array().unwrap()[0]["id"]
            .as_str()
            .unwrap(),
        "CVE-2021-32714"
    );

    Ok(())
}

/// Verifies that a custom vulnerability status is reflected in the recommendation response.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_other_status(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
    use trustify_entity::{purl_status, status};

    // Given a package with a vulnerability whose status is overridden to a custom value
    ctx.graph
        .ingest_qualified_package(
            &Purl::from_str("pkg:cargo/hyper@0.14.1-redhat-00001")?,
            &ctx.db,
        )
        .await?;

    ctx.ingest_documents(["osv/RUSTSEC-2021-0079.json"]).await?;

    let custom_status_id = Uuid::new_v4();
    let custom_status = status::ActiveModel {
        id: Set(custom_status_id),
        slug: Set("custom_status".to_string()),
        name: Set("Custom Status".to_string()),
        description: Set(Some("A custom status for testing".to_string())),
    };
    status::Entity::insert(custom_status).exec(&ctx.db).await?;

    let purl_statuses = purl_status::Entity::find()
        .filter(purl_status::Column::VulnerabilityId.eq("CVE-2021-32714"))
        .all(&ctx.db)
        .await?;

    assert!(!purl_statuses.is_empty());

    for ps in purl_statuses {
        let mut active: purl_status::ActiveModel = ps.into();
        active.status_id = Set(custom_status_id);
        active.update(&ctx.db).await?;
    }

    // When requesting recommendations
    let app = caller(ctx).await?;
    let recommendations = recommend(&app, &["pkg:cargo/hyper@0.14.1"]).await;

    log::info!("{recommendations:#?}");

    // Then the vulnerability status reflects the custom status
    let entry =
        &recommendations["recommendations"].as_object().unwrap()["pkg:cargo/hyper@0.14.1"][0];
    let vulns = entry["vulnerabilities"].as_array().unwrap();
    let vuln = vulns
        .iter()
        .find(|v| v["id"].as_str().unwrap() == "CVE-2021-32714")
        .unwrap();

    assert_eq!(vuln["status"], "custom_status");

    Ok(())
}

/// Verifies that PURLs with no matching base package or an unparseable version produce the expected empty response.
#[test_context(TrustifyContext)]
#[rstest]
#[case::unknown_purl(
    "pkg:maven/com.example/nonexistent@1.0.0",
    json!({"pkg:maven/com.example/nonexistent@1.0.0": []})
)]
#[case::invalid_version(
    "pkg:maven/jakarta.el/jakarta.el-api@not-a-version",
    json!({})
)]
#[test_log::test(actix_web::test)]
async fn get_recommendations_no_match(
    ctx: &TrustifyContext,
    #[case] purl: &str,
    #[case] expected: Value,
) -> Result<(), anyhow::Error> {
    // Given an advisory is ingested
    ctx.ingest_documents(["cve/CVE-2022-45787.json"]).await?;

    // When requesting recommendations for a non-matching PURL
    let app = caller(ctx).await?;
    let recommendations = recommend(&app, &[purl]).await;

    // Then the response matches the expected empty result
    assert_eq!(recommendations["recommendations"], expected);

    Ok(())
}

/// Verifies that recommendations work for PURLs without a namespace (e.g., cargo packages).
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_no_namespace(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given a Red Hat package with no namespace
    ctx.graph
        .ingest_qualified_package(
            &Purl::from_str("pkg:cargo/serde@1.0.0-redhat-00001")?,
            &ctx.db,
        )
        .await?;

    // When requesting recommendations
    let app = caller(ctx).await?;
    let recommendations = recommend(&app, &["pkg:cargo/serde@1.0.0"]).await;

    // Then the recommendation returns the Red Hat package
    assert_eq!(
        recommendations["recommendations"],
        json!({
            "pkg:cargo/serde@1.0.0": [{
                "package": "pkg:cargo/serde@1.0.0-redhat-00001",
                "vulnerabilities": []
            }]
        })
    );

    Ok(())
}

/// Verifies correct handling of mixed input: a known PURL, an unknown PURL, and a versionless PURL.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_mixed(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given an advisory is ingested
    ctx.ingest_documents(["cve/CVE-2022-45787.json"]).await?;

    // When requesting recommendations for a mix of known, unknown, and versionless PURLs
    let app = caller(ctx).await?;
    let recommendations = recommend(
        &app,
        &[
            "pkg:maven/jakarta.el/jakarta.el-api@3.0.3",
            "pkg:maven/com.example/nonexistent@1.0.0",
            "pkg:maven/jakarta.el/jakarta.el-api",
        ],
    )
    .await;

    // Then known PURLs get recommendations and unknown PURLs get empty arrays
    let entry = &recommendations["recommendations"]["pkg:maven/jakarta.el/jakarta.el-api@3.0.3"];
    assert_eq!(
        entry[0]["package"],
        "pkg:maven/jakarta.el/jakarta.el-api@3.0.3.redhat-00002"
    );
    assert_eq!(
        entry[0]["vulnerabilities"],
        json!([{"id": "CVE-2022-45787", "status": "NotAffected", "remediations": []}])
    );
    assert_eq!(
        recommendations["recommendations"]["pkg:maven/com.example/nonexistent@1.0.0"],
        json!([])
    );

    Ok(())
}

/// Verifies that the versioned PURL (without qualifiers) is returned as the package string when no qualified PURL exists.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_fallback_package_str(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    // Given a versioned PURL without a qualified PURL
    let base = ctx
        .graph
        .ingest_package(&Purl::from_str("pkg:cargo/tokio")?, &ctx.db)
        .await?;
    base.ingest_package_version(
        &Purl::from_str("pkg:cargo/tokio@1.0.0-redhat-00001")?,
        &ctx.db,
    )
    .await?;

    // When requesting recommendations
    let app = caller(ctx).await?;
    let recommendations = recommend(&app, &["pkg:cargo/tokio@1.0.0"]).await;

    // Then the versioned PURL is returned as the package string
    let recs = recommendations["recommendations"].as_object().unwrap();
    assert_eq!(recs.len(), 1);

    let rec_list = recs["pkg:cargo/tokio@1.0.0"].as_array().unwrap();
    assert_eq!(rec_list.len(), 1);

    let package = rec_list[0]["package"].as_str().unwrap();
    assert_eq!(package, "pkg:cargo/tokio@1.0.0-redhat-00001");

    Ok(())
}

/// Verifies that a "fixed" vulnerability status maps to the Fixed VexStatus and uses the status name in the response.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_fixed_status(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
    use trustify_entity::{purl_status, status};

    // Given a package with a vulnerability whose status is set to "fixed"
    ctx.graph
        .ingest_qualified_package(
            &Purl::from_str("pkg:cargo/hyper@0.14.1-redhat-00001")?,
            &ctx.db,
        )
        .await?;

    ctx.ingest_documents(["osv/RUSTSEC-2021-0079.json"]).await?;

    let fixed_status = status::Entity::find()
        .filter(status::Column::Slug.eq("fixed"))
        .one(&ctx.db)
        .await?;

    let status_id = if let Some(s) = fixed_status {
        s.id
    } else {
        let id = Uuid::new_v4();
        let new_status = status::ActiveModel {
            id: Set(id),
            slug: Set("fixed".to_string()),
            name: Set("Fixed".to_string()),
            description: Set(Some("Vulnerability has been fixed".to_string())),
        };
        status::Entity::insert(new_status).exec(&ctx.db).await?;
        id
    };

    let purl_statuses = purl_status::Entity::find()
        .filter(purl_status::Column::VulnerabilityId.eq("CVE-2021-32714"))
        .all(&ctx.db)
        .await?;

    for ps in purl_statuses {
        let mut active: purl_status::ActiveModel = ps.into();
        active.status_id = Set(status_id);
        active.update(&ctx.db).await?;
    }

    // When requesting recommendations
    let app = caller(ctx).await?;
    let recommendations = recommend(&app, &["pkg:cargo/hyper@0.14.1"]).await;

    // Then the vulnerability status is reported as "Fixed"
    let entry =
        &recommendations["recommendations"].as_object().unwrap()["pkg:cargo/hyper@0.14.1"][0];
    let vuln = entry["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"].as_str().unwrap() == "CVE-2021-32714")
        .unwrap();

    assert_eq!(vuln["status"], "Fixed");

    Ok(())
}

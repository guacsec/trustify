use crate::{
    Config,
    purl::{
        model::{
            details::base_purl::BasePurlDetails,
            summary::{base_purl::BasePurlSummary, purl::PurlSummary},
        },
        service::PurlService,
    },
    test::{caller, caller_with},
};
use actix_web::test::TestRequest;
use regex::Regex;
use rstest::rstest;
use sea_orm::ConnectionTrait;

/// Returns a Config with a pattern matching dot- and hyphen-separated vendor rebuilds (e.g. `3.0.3.redhat-00002`, `0.14.1-redhat-00001`).
///
/// `expect` is acceptable here: the regex is a hardcoded literal whose validity is known at
/// compile time, and in test setup code a panic is the correct failure signal.
#[allow(clippy::expect_used)]
fn vendor_config() -> Config {
    Config {
        recommend_patterns: PurlService::default_recommend_patterns(),
        ..Default::default()
    }
}
use serde_json::{Value, json};
use std::{collections::BTreeSet, str::FromStr};
use test_context::test_context;
use test_log::test;
use trustify_common::{
    db::{Database, pagination_cache::PaginationCache},
    model::PaginatedResults,
    purl::Purl,
};
use trustify_entity::source_document;
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

    const PURL: &str = "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?repository_url=https:%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=pom";

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
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let recommendations = recommend(
        &app,
        &[
            "pkg:maven/jakarta.el/jakarta.el-api@3.0.3",
            "pkg:maven/jakarta.el/jakarta.el-api@3.0.3",
        ],
    )
    .await;

    tracing::info!("{recommendations:#?}");

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

/// Verifies that /recommend returns correct per-stream recommendations when multiple
/// advisories exist for the same CVE on the same base PURL with different version streams,
/// and that each stream's vulnerability metadata reflects its own advisory status.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_multi_stream(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given two advisories for the same CVE, each fixing a different version stream
    // with distinguishable statuses so cross-contamination is detectable
    ctx.ingest_json(minimal_csaf_vex(
        "TEST-MULTI-STREAM-001",
        "Test Product Stream 1",
        &[(
            "test-lib-1.0.0.redhat-00001",
            "pkg:maven/org.example/test-lib@1.0.0.redhat-00001",
        )],
        &[("CVE-2099-10001", "fixed", &[0])],
    ))
    .await?;
    ctx.ingest_json(minimal_csaf_vex(
        "TEST-MULTI-STREAM-002",
        "Test Product Stream 2",
        &[(
            "test-lib-2.0.0.redhat-00001",
            "pkg:maven/org.example/test-lib@2.0.0.redhat-00001",
        )],
        &[("CVE-2099-10001", "known_affected", &[0])],
    ))
    .await?;

    // When requesting recommendations for both base versions
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let recommendations = recommend(
        &app,
        &[
            "pkg:maven/org.example/test-lib@1.0.0",
            "pkg:maven/org.example/test-lib@2.0.0",
        ],
    )
    .await;

    tracing::info!("{recommendations:#?}");

    // Then each base version gets its own stream's vendor rebuild
    let rec_1 = &recommendations["recommendations"]["pkg:maven/org.example/test-lib@1.0.0"];
    assert_eq!(rec_1.as_array().unwrap().len(), 1);
    assert_eq!(
        rec_1[0]["package"],
        "pkg:maven/org.example/test-lib@1.0.0.redhat-00001"
    );

    let rec_2 = &recommendations["recommendations"]["pkg:maven/org.example/test-lib@2.0.0"];
    assert_eq!(rec_2.as_array().unwrap().len(), 1);
    assert_eq!(
        rec_2[0]["package"],
        "pkg:maven/org.example/test-lib@2.0.0.redhat-00001"
    );

    // And each recommendation carries its own stream's vulnerability status
    let vuln_1 = &rec_1[0]["vulnerabilities"].as_array().unwrap()[0];
    assert_eq!(vuln_1["id"], "CVE-2099-10001");
    assert_eq!(vuln_1["status"], "Fixed");

    let vuln_2 = &rec_2[0]["vulnerabilities"].as_array().unwrap()[0];
    assert_eq!(vuln_2["id"], "CVE-2099-10001");
    assert_eq!(vuln_2["status"], "Affected");

    Ok(())
}

/// Deletes the persisted versioned/qualified PURL rows so the winner is advisory-synthesized.
async fn drop_persisted_version(
    ctx: &TrustifyContext,
    name: &str,
    version: &str,
) -> Result<(), anyhow::Error> {
    ctx.db
        .execute_unprepared(&format!(
            "DELETE FROM qualified_purl WHERE versioned_purl_id IN ( \
                 SELECT vp.id FROM versioned_purl vp \
                 JOIN base_purl bp ON bp.id = vp.base_purl_id \
                 WHERE bp.name = '{name}' AND vp.version = '{version}')"
        ))
        .await?;
    let deleted = ctx
        .db
        .execute_unprepared(&format!(
            "DELETE FROM versioned_purl WHERE version = '{version}' \
             AND base_purl_id = (SELECT id FROM base_purl WHERE name = '{name}')"
        ))
        .await?;
    assert_eq!(deleted.rows_affected(), 1);
    Ok(())
}

/// Conflicting sources must both survive, with their advisory identifiers.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_multi_advisory_statuses(ctx: &TrustifyContext) -> anyhow::Result<()> {
    for (id, status) in [("VENDOR-FIX", "fixed"), ("UPSTREAM", "known_affected")] {
        ctx.ingest_json(minimal_csaf_vex(
            id,
            "Crosslib Product",
            &[(
                "crosslib",
                "pkg:maven/com.example/crosslib@1.0.0.redhat-00001",
            )],
            &[("CVE-2099-30001", status, &[0])],
        ))
        .await?;
    }
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let response = recommend(&app, &["pkg:maven/com.example/crosslib@1.0.0"]).await;
    assert_eq!(
        response["recommendations"]["pkg:maven/com.example/crosslib@1.0.0"][0]["vulnerabilities"],
        json!([
            {"id": "CVE-2099-30001", "status": "Affected", "remediations": [], "advisory_id": "https://test.example.com/#UPSTREAM"},
            {"id": "CVE-2099-30001", "status": "Fixed", "remediations": [], "advisory_id": "https://test.example.com/#VENDOR-FIX"}
        ])
    );
    Ok(())
}

/// Republishing an advisory must not expose the superseded assessment.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_ignores_deprecated_revisions(ctx: &TrustifyContext) -> anyhow::Result<()> {
    for (date, status) in [
        ("2024-01-15T00:00:00+00:00", "known_affected"),
        ("2024-02-15T00:00:00+00:00", "fixed"),
    ] {
        ctx.ingest_json(minimal_csaf_vex_at(
            "REV-1",
            date,
            "Revision Product",
            &[("revlib", "pkg:maven/com.example/revlib@1.0.0.redhat-00001")],
            &[("CVE-2099-40001", status, &[0])],
        ))
        .await?;
    }
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let response = recommend(&app, &["pkg:maven/com.example/revlib@1.0.0"]).await;
    assert_eq!(
        response["recommendations"]["pkg:maven/com.example/revlib@1.0.0"][0]["vulnerabilities"],
        json!([{"id": "CVE-2099-40001", "status": "Fixed", "remediations": [], "advisory_id": "https://test.example.com/#REV-1"}])
    );
    Ok(())
}

/// A deprecated exact-version fix must not seed the highest synthetic recommendation.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_excludes_deprecated_synthetic_candidates(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    for (date, version, status) in [
        ("2024-01-15T00:00:00+00:00", "1.0.0.redhat-00002", "fixed"),
        (
            "2024-02-15T00:00:00+00:00",
            "1.0.0.redhat-00001",
            "known_affected",
        ),
    ] {
        ctx.ingest_json(minimal_csaf_vex_at(
            "STALE-CANDIDATE",
            date,
            "Candidate Product",
            &[(
                "candidate",
                &format!("pkg:maven/com.example/candidate@{version}"),
            )],
            &[("CVE-2099-40002", status, &[0])],
        ))
        .await?;
    }
    drop_persisted_version(ctx, "candidate", "1.0.0.redhat-00002").await?;
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let response = recommend(&app, &["pkg:maven/com.example/candidate@1.0.0"]).await;
    assert_eq!(
        response["recommendations"]["pkg:maven/com.example/candidate@1.0.0"][0]["package"],
        "pkg:maven/com.example/candidate@1.0.0.redhat-00001"
    );
    Ok(())
}

/// Multiple product contexts in one advisory must yield one assessment, not duplicate rows.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_no_duplicates_for_multi_stream_vex(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document("csaf/RHSA-CVE-2024-29025.json.bz2")
        .await?;
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let response = recommend(&app, &["pkg:maven/com.cronutils/cron-utils@9.2.1"]).await;
    let vulnerabilities = response["recommendations"]["pkg:maven/com.cronutils/cron-utils@9.2.1"]
        [0]["vulnerabilities"]
        .as_array()
        .unwrap();
    assert_eq!(vulnerabilities.len(), 1);
    assert_eq!(vulnerabilities[0]["id"], "CVE-2024-29025");
    assert_eq!(vulnerabilities[0]["status"], "NotAffected");
    assert_eq!(
        vulnerabilities[0]["advisory_id"],
        "https://www.redhat.com/#CVE-2024-29025"
    );
    assert!(
        !vulnerabilities[0]["remediations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    Ok(())
}

/// Moves the status of `cve` onto a new version range with the given bounds.
async fn set_status_range(
    ctx: &TrustifyContext,
    cve: &str,
    (low, low_inclusive): (&str, bool),
    (high, high_inclusive): (&str, bool),
) -> Result<(), anyhow::Error> {
    let range_id = Uuid::new_v4();
    let updated = ctx
        .db
        .execute_unprepared(&format!(
            "WITH new_range AS ( \
                 INSERT INTO version_range \
                     (id, version_scheme_id, low_version, low_inclusive, high_version, high_inclusive) \
                 SELECT '{range_id}', version_scheme_id, '{low}', {low_inclusive}, \
                        '{high}', {high_inclusive} \
                 FROM version_range \
                 WHERE id = (SELECT version_range_id FROM purl_status \
                             WHERE vulnerability_id = '{cve}') \
                 RETURNING id) \
             UPDATE purl_status SET version_range_id = (SELECT id FROM new_range) \
             WHERE vulnerability_id = '{cve}'"
        ))
        .await?;
    assert_eq!(updated.rows_affected(), 1);
    Ok(())
}

/// Returns `{cve -> status}` for the first recommendation of `input`, asserting the winner.
async fn recommended_statuses(
    ctx: &TrustifyContext,
    input: &str,
    expected_winner: &str,
) -> Result<BTreeSet<(String, String)>, anyhow::Error> {
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let recommendations = recommend(&app, &[input]).await;
    let rec = &recommendations["recommendations"][input][0];
    assert_eq!(rec["package"], expected_winner);
    Ok(rec["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["id"].as_str().unwrap().to_string(),
                v["status"].as_str().unwrap().to_string(),
            )
        })
        .collect())
}

/// Returns the reported vulnerabilities of `input` in the report for `sbom_id`, asserting the winner.
async fn reported_vulnerabilities(
    ctx: &TrustifyContext,
    sbom_id: Uuid,
    input: &str,
    expected_winner: &str,
) -> Result<BTreeSet<String>, anyhow::Error> {
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[sbom_id]).await;
    let package = report["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["purl"] == input)
        .unwrap();
    assert_eq!(package["recommended_purl"], expected_winner);
    Ok(package["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect())
}

/// Verifies advisory-only winners retain version-specific vulnerability metadata in recommendations and reports.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_advisory_only(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_json(minimal_csaf_vex(
        "TEST-ADVISORY-ONLY-001",
        "Test Product Advisory Only",
        &[
            (
                "advlib-1.0.0.redhat-00001",
                "pkg:maven/com.example/advlib@1.0.0.redhat-00001",
            ),
            (
                "advlib-2.0.0.redhat-00001",
                "pkg:maven/com.example/advlib@2.0.0.redhat-00001",
            ),
        ],
        &[
            ("CVE-2099-20001", "fixed", &[0]),
            ("CVE-2099-20002", "fixed", &[1]),
        ],
    ))
    .await?;
    let sbom_id = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "sbom-advisory-only-report",
            "00000000-0000-0000-0000-200000000002",
            &[
                ("advlib", "1.0.0", "pkg:maven/com.example/advlib@1.0.0"),
                ("advlib", "2.0.0", "pkg:maven/com.example/advlib@2.0.0"),
            ],
        ))
        .await?
        .id,
    )?;
    drop_persisted_version(ctx, "advlib", "1.0.0.redhat-00001").await?;
    drop_persisted_version(ctx, "advlib", "2.0.0.redhat-00001").await?;

    for (input, winner, cve) in [
        (
            "pkg:maven/com.example/advlib@1.0.0",
            "pkg:maven/com.example/advlib@1.0.0.redhat-00001",
            "CVE-2099-20001",
        ),
        (
            "pkg:maven/com.example/advlib@2.0.0",
            "pkg:maven/com.example/advlib@2.0.0.redhat-00001",
            "CVE-2099-20002",
        ),
    ] {
        assert_eq!(
            recommended_statuses(ctx, input, winner).await?,
            [(cve.to_string(), "Fixed".to_string())].into()
        );
        assert_eq!(
            reported_vulnerabilities(ctx, sbom_id, input, winner).await?,
            [cve.to_string()].into()
        );
    }

    Ok(())
}

/// Older CSAF marks the exact rebuild "fixed" for CVE-X; newer OSV marks the Maven range
/// [1.0.0, 1.0.1), which contains 1.0.0.redhat-00001, "affected" for CVE-X and CVE-Y.
async fn setup_range_scenario(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_json(minimal_csaf_vex(
        "TEST-RANGE-EXACT-001",
        "Test Product Range",
        &[(
            "rangelib-1.0.0.redhat-00001",
            "pkg:maven/com.example/rangelib@1.0.0.redhat-00001",
        )],
        &[("CVE-2099-30001", "fixed", &[0])],
    ))
    .await?;
    for (id, cve) in [
        ("TEST-OSV-RANGE-0001", "CVE-2099-30001"),
        ("TEST-OSV-RANGE-0002", "CVE-2099-30002"),
    ] {
        ctx.ingest_json(minimal_osv_maven_range(
            id,
            cve,
            "2025-06-01T00:00:00Z",
            "com.example:rangelib",
            "1.0.0",
            "1.0.1",
        ))
        .await?;
    }
    Ok(())
}

/// Exact and range-based assessments from different advisories are both retained.
fn expected_range_statuses() -> BTreeSet<(String, String)> {
    [
        ("CVE-2099-30001".to_string(), "Affected".to_string()),
        ("CVE-2099-30001".to_string(), "Fixed".to_string()),
        ("CVE-2099-30002".to_string(), "Affected".to_string()),
    ]
    .into()
}

/// Control: persisted winner honours range-based statuses.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_range_statuses_persisted_winner(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    setup_range_scenario(ctx).await?;
    let statuses = recommended_statuses(
        ctx,
        "pkg:maven/com.example/rangelib@1.0.0",
        "pkg:maven/com.example/rangelib@1.0.0.redhat-00001",
    )
    .await?;
    assert_eq!(statuses, expected_range_statuses());
    Ok(())
}

/// Synthesized winner must see the same range-based statuses.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_range_statuses_synthesized_winner(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    setup_range_scenario(ctx).await?;
    drop_persisted_version(ctx, "rangelib", "1.0.0.redhat-00001").await?;
    let statuses = recommended_statuses(
        ctx,
        "pkg:maven/com.example/rangelib@1.0.0",
        "pkg:maven/com.example/rangelib@1.0.0.redhat-00001",
    )
    .await?;
    assert_eq!(statuses, expected_range_statuses());
    Ok(())
}

/// An exact "fixed" status whose low bound is made exclusive: the empty range (v, v].
async fn setup_exclusive_bound_scenario(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_json(minimal_csaf_vex(
        "TEST-BOUND-001",
        "Test Product Bound",
        &[(
            "boundlib-1.0.0.redhat-00001",
            "pkg:maven/com.example/boundlib@1.0.0.redhat-00001",
        )],
        &[("CVE-2099-31001", "fixed", &[0])],
    ))
    .await?;
    let updated = ctx
        .db
        .execute_unprepared(
            "UPDATE version_range SET low_inclusive = false WHERE id IN ( \
                 SELECT ps.version_range_id FROM purl_status ps \
                 JOIN base_purl bp ON bp.id = ps.base_purl_id \
                 WHERE bp.name = 'boundlib')",
        )
        .await?;
    assert_eq!(updated.rows_affected(), 1);
    Ok(())
}

/// Control: VersionMatches rejects the empty range for a persisted winner.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_exclusive_bound_persisted_winner(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    setup_exclusive_bound_scenario(ctx).await?;
    let statuses = recommended_statuses(
        ctx,
        "pkg:maven/com.example/boundlib@1.0.0",
        "pkg:maven/com.example/boundlib@1.0.0.redhat-00001",
    )
    .await?;
    assert!(statuses.is_empty(), "unexpected statuses: {statuses:?}");
    Ok(())
}

/// Synthesized winner must not pick up the empty range's status.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_exclusive_bound_synthesized_winner(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    setup_exclusive_bound_scenario(ctx).await?;
    drop_persisted_version(ctx, "boundlib", "1.0.0.redhat-00001").await?;
    let statuses = recommended_statuses(
        ctx,
        "pkg:maven/com.example/boundlib@1.0.0",
        "pkg:maven/com.example/boundlib@1.0.0.redhat-00001",
    )
    .await?;
    assert!(statuses.is_empty(), "unexpected statuses: {statuses:?}");
    Ok(())
}

/// Verifies that reports give a synthesized winner the same ranged statuses as a persisted one.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_range_statuses_synthesized_winner(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    // Given an exact fixed status and a fixed status over the range [1.0.0, 1.0.1)
    ctx.ingest_json(minimal_csaf_vex(
        "TEST-RANGE-REPORT-001",
        "Test Product Range Report",
        &[(
            "rangereportlib-1.0.0.redhat-00001",
            "pkg:maven/com.example/rangereportlib@1.0.0.redhat-00001",
        )],
        &[
            ("CVE-2099-30101", "fixed", &[0]),
            ("CVE-2099-30102", "fixed", &[0]),
        ],
    ))
    .await?;
    set_status_range(ctx, "CVE-2099-30101", ("1.0.0", true), ("1.0.1", false)).await?;
    let sbom_id = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "sbom-range-report-synthetic",
            "00000000-0000-0000-0000-000000000431",
            &[(
                "rangereportlib",
                "1.0.0",
                "pkg:maven/com.example/rangereportlib@1.0.0",
            )],
        ))
        .await?
        .id,
    )?;
    let input = "pkg:maven/com.example/rangereportlib@1.0.0";
    let winner = "pkg:maven/com.example/rangereportlib@1.0.0.redhat-00001";

    // When reporting with the persisted winner, then with the synthesized one
    let persisted = reported_vulnerabilities(ctx, sbom_id, input, winner).await?;
    drop_persisted_version(ctx, "rangereportlib", "1.0.0.redhat-00001").await?;
    let synthesized = reported_vulnerabilities(ctx, sbom_id, input, winner).await?;

    // Then both include the ranged status
    assert_eq!(
        persisted,
        ["CVE-2099-30101".to_string(), "CVE-2099-30102".to_string()].into()
    );
    assert_eq!(synthesized, persisted);

    Ok(())
}

/// Verifies that reports reject an empty exclusive range for synthesized and persisted winners alike.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_exclusive_bound_synthesized_winner(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    // Given an inclusive exact fixed status and one moved onto the empty range (v, v]
    ctx.ingest_json(minimal_csaf_vex(
        "TEST-BOUND-REPORT-001",
        "Test Product Bound Report",
        &[(
            "boundreportlib-1.0.0.redhat-00001",
            "pkg:maven/com.example/boundreportlib@1.0.0.redhat-00001",
        )],
        &[
            ("CVE-2099-31101", "fixed", &[0]),
            ("CVE-2099-31102", "fixed", &[0]),
        ],
    ))
    .await?;
    set_status_range(
        ctx,
        "CVE-2099-31102",
        ("1.0.0.redhat-00001", false),
        ("1.0.0.redhat-00001", true),
    )
    .await?;
    let sbom_id = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "sbom-bound-report-synthetic",
            "00000000-0000-0000-0000-000000000432",
            &[(
                "boundreportlib",
                "1.0.0",
                "pkg:maven/com.example/boundreportlib@1.0.0",
            )],
        ))
        .await?
        .id,
    )?;
    let input = "pkg:maven/com.example/boundreportlib@1.0.0";
    let winner = "pkg:maven/com.example/boundreportlib@1.0.0.redhat-00001";

    // When reporting with the persisted winner, then with the synthesized one
    let persisted = reported_vulnerabilities(ctx, sbom_id, input, winner).await?;
    drop_persisted_version(ctx, "boundreportlib", "1.0.0.redhat-00001").await?;
    let synthesized = reported_vulnerabilities(ctx, sbom_id, input, winner).await?;

    // Then only the inclusive status is reported
    assert_eq!(persisted, ["CVE-2099-31101".to_string()].into());
    assert_eq!(synthesized, persisted);

    Ok(())
}

/// Verifies that high remediation fan-out is loaded without exceeding PostgreSQL's parameter limit.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_high_remediation_fanout(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    // Given a fixed status with more remediation links than PostgreSQL permits as bind parameters
    ctx.ingest_json(minimal_csaf_vex(
        "TEST-REMEDIATION-FANOUT-001",
        "Test Product Remediation Fanout",
        &[(
            "fanoutlib-1.0.0.redhat-00001",
            "pkg:maven/com.example/fanoutlib@1.0.0.redhat-00001",
        )],
        &[("CVE-2099-50001", "fixed", &[0])],
    ))
    .await?;
    let remediation_links = ctx
        .db
        .execute_unprepared(
            "WITH target_status AS ( \
                 SELECT id, advisory_id, vulnerability_id \
                 FROM purl_status WHERE vulnerability_id = 'CVE-2099-50001' \
             ), new_remediations AS ( \
                 INSERT INTO remediation (advisory_id, vulnerability_id, category, data) \
                  SELECT advisory_id, vulnerability_id, 'vendor_fix', \
                         jsonb_build_object('index', generated.index) \
                  FROM target_status CROSS JOIN generate_series(1, 65536) AS generated(index) \
                 RETURNING id \
             ) \
             INSERT INTO remediation_purl_status (remediation_id, purl_status_id) \
             SELECT new_remediations.id, target_status.id \
             FROM new_remediations CROSS JOIN target_status",
        )
        .await?;
    assert_eq!(remediation_links.rows_affected(), 65_536);

    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let input = "pkg:maven/com.example/fanoutlib@1.0.0";
    for synthesized in [false, true] {
        if synthesized {
            drop_persisted_version(ctx, "fanoutlib", "1.0.0.redhat-00001").await?;
        }

        // When requesting the recommendation for a persisted, then a synthesized winner
        let recommendations = recommend(&app, &[input]).await;
        let recommendation = &recommendations["recommendations"][input][0];

        // Then all remediation metadata is returned without a bind-parameter failure
        assert_eq!(
            recommendation["package"],
            "pkg:maven/com.example/fanoutlib@1.0.0.redhat-00001"
        );
        let vulnerabilities = recommendation["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulnerabilities.len(), 1, "synthesized: {synthesized}");
        assert_eq!(vulnerabilities[0]["id"], "CVE-2099-50001");
        assert_eq!(
            vulnerabilities[0]["remediations"].as_array().unwrap().len(),
            65_536,
            "synthesized: {synthesized}"
        );
    }

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
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let recommendations = recommend(&app, &["pkg:maven/jakarta.el/jakarta.el-api"]).await;

    tracing::info!("{recommendations:#?}");

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

/// Distinct advisory sources for the same CVE must each be reported once.
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
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let recommendations = recommend(&app, &["pkg:cargo/hyper@0.14.1"]).await;

    tracing::info!("{recommendations:#?}");

    // Then both advisory assessments survive without duplicate context rows.
    let entry =
        &recommendations["recommendations"].as_object().unwrap()["pkg:cargo/hyper@0.14.1"][0];
    let vulnerabilities = entry["vulnerabilities"].as_array().unwrap();
    assert_eq!(vulnerabilities.len(), 2);
    assert_eq!(vulnerabilities[0]["advisory_id"], "DUPLICATE");
    assert_eq!(vulnerabilities[1]["advisory_id"], "RUSTSEC-2021-0079");
    for vulnerability in vulnerabilities {
        assert_eq!(vulnerability["id"], "CVE-2021-32714");
        assert_eq!(vulnerability["status"], "Affected");
        // This release's OSV loader does not ingest fix remediations.
        assert_eq!(vulnerability["remediations"], json!([]));
    }

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
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let recommendations = recommend(&app, &["pkg:cargo/hyper@0.14.1"]).await;

    tracing::info!("{recommendations:#?}");

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
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
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
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
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
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
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
        json!([{"id": "CVE-2022-45787", "status": "NotAffected", "remediations": [], "advisory_id": "https://www.redhat.com/#CVE-2022-45787"}])
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
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
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
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
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

/// Verifies that the recommend endpoint returns empty when no patterns are configured.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_no_patterns(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given the Hyper advisory and a redhat-patched version ingested
    ctx.ingest_documents(["osv/RUSTSEC-2021-0079.json", "cve/CVE-2021-32714.json"])
        .await?;
    ctx.graph
        .ingest_qualified_package(
            &Purl::from_str("pkg:cargo/hyper@0.14.1.redhat-00001")?,
            &ctx.db,
        )
        .await?;

    // When requesting recommendations with no patterns configured
    let app = caller_with(
        ctx,
        Config {
            recommend_patterns: vec![],
            ..Default::default()
        },
        PaginationCache::for_test(),
    )
    .await?;
    let recommendations = recommend(&app, &["pkg:cargo/hyper@0.14.1"]).await;

    // Then no recommendations are returned
    let items = &recommendations["recommendations"]["pkg:cargo/hyper@0.14.1"];
    assert!(
        items.as_array().is_none_or(|v| v.is_empty()),
        "expected no recommendations when patterns are empty, got: {items}"
    );

    Ok(())
}

/// Verifies that the highest vendor rebuild number is recommended when multiple rebuilds exist.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_highest_rebuild_selected(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    // Given two vendor rebuilds of the same upstream version
    ctx.graph
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/jakarta.el/jakarta.el-api@3.0.3.redhat-00001")?,
            &ctx.db,
        )
        .await?;
    ctx.graph
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/jakarta.el/jakarta.el-api@3.0.3.redhat-00002")?,
            &ctx.db,
        )
        .await?;
    ctx.ingest_documents(["cve/CVE-2022-45787.json", "cve/CVE-2023-28867.json"])
        .await?;

    // When requesting recommendations
    let app = caller_with(
        ctx,
        Config {
            recommend_patterns: vec![Regex::new(r"^(.+)\.redhat-[0-9]+$").expect("valid pattern")],
            ..Default::default()
        },
        PaginationCache::for_test(),
    )
    .await?;
    let recommendations = recommend(&app, &["pkg:maven/jakarta.el/jakarta.el-api@3.0.3"]).await;

    // Then the highest rebuild (redhat-00002) is returned, not an arbitrary one
    assert_eq!(
        recommendations["recommendations"]["pkg:maven/jakarta.el/jakarta.el-api@3.0.3"][0]["package"],
        "pkg:maven/jakarta.el/jakarta.el-api@3.0.3.redhat-00002",
    );

    Ok(())
}

/// Verifies that all patterns are evaluated and the highest vendor rebuild across all patterns is returned.
/// With find_map, only pattern 1's match is considered; filter_map+max_by evaluates both.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_recommendations_best_across_patterns(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    // Given pattern 1 matches myorg-00001 and pattern 2 matches redhat-00002.
    // "3.0.3.redhat-00002" > "3.0.3.myorg-00001" lexicographically (r > m),
    // so the correct answer is redhat-00002. With find_map only pattern 1 fires
    // and would return myorg-00001 — proving the bug.
    ctx.graph
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/jakarta.el/jakarta.el-api@3.0.3.myorg-00001")?,
            &ctx.db,
        )
        .await?;
    ctx.graph
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/jakarta.el/jakarta.el-api@3.0.3.redhat-00002")?,
            &ctx.db,
        )
        .await?;
    ctx.ingest_documents(["cve/CVE-2022-45787.json", "cve/CVE-2023-28867.json"])
        .await?;

    // When requesting recommendations with pattern 1 matching myorg and pattern 2 matching redhat
    let app = caller_with(
        ctx,
        Config {
            recommend_patterns: vec![
                Regex::new(r"^(.+)\.myorg-[0-9]+$").expect("valid pattern 1"),
                Regex::new(r"^(.+)\.redhat-[0-9]+$").expect("valid pattern 2"),
            ],
            ..Default::default()
        },
        PaginationCache::for_test(),
    )
    .await?;
    let recommendations = recommend(&app, &["pkg:maven/jakarta.el/jakarta.el-api@3.0.3"]).await;

    // Then the redhat-00002 rebuild wins (lexicographically greater than myorg-00001),
    // confirming all patterns were evaluated and the best result selected.
    assert_eq!(
        recommendations["recommendations"]["pkg:maven/jakarta.el/jakarta.el-api@3.0.3"][0]["package"],
        "pkg:maven/jakarta.el/jakarta.el-api@3.0.3.redhat-00002",
    );

    Ok(())
}

// ── Recommendation report tests ────────────────────────────────────────────

async fn recommend_report_req(app: &impl CallService, sbom_ids: &[Uuid]) -> Value {
    app.call_and_read_body_json(
        TestRequest::post()
            .uri("/api/v3/purl/recommend/report")
            .set_json(json!({ "sbom_ids": sbom_ids }))
            .to_request(),
    )
    .await
}

/// Builds a minimal CycloneDX 1.4 SBOM JSON with the given packages.
///
/// `serial` must be unique across ingested documents to prevent deduplication.
/// `packages` is a slice of `(name, version, purl)` tuples.
fn minimal_cdx(name: &str, serial: &str, packages: &[(&str, &str, &str)]) -> Value {
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "serialNumber": format!("urn:uuid:{serial}"),
        "metadata": {
            "component": {"type": "application", "name": name, "version": "1.0"}
        },
        "components": packages.iter().map(|(n, v, p)| json!({
            "type": "library",
            "name": n,
            "version": v,
            "purl": p,
        })).collect::<Vec<_>>()
    })
}

/// Verifies that a report for two SBOMs returns correct aggregated data.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_aggregated_data(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given CVE advisories that create both upstream and vendor versioned PURLs in the DB
    ctx.ingest_documents(["cve/CVE-2022-45787.json", "cve/CVE-2023-28867.json"])
        .await?;

    // And two SBOMs each containing the upstream jakarta.el-api@3.0.3
    let sbom1 = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "sbom-report-1",
            "00000000-0000-0000-0000-000000000001",
            &[(
                "jakarta.el-api",
                "3.0.3",
                "pkg:maven/jakarta.el/jakarta.el-api@3.0.3",
            )],
        ))
        .await?
        .id,
    )?;
    let sbom2 = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "sbom-report-2",
            "00000000-0000-0000-0000-000000000002",
            &[(
                "jakarta.el-api",
                "3.0.3",
                "pkg:maven/jakarta.el/jakarta.el-api@3.0.3",
            )],
        ))
        .await?
        .id,
    )?;

    // When generating the report
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[sbom1, sbom2]).await;

    tracing::info!("{report:#?}");

    // Then the impact summary reflects 2 SBOMs and 1 distinct addressable package
    assert_eq!(report["impact_summary"]["sboms_with_recommendations"], 2);
    assert_eq!(report["impact_summary"]["addressable_packages"], 1);

    // And each winning advisory has its own row, without counting the package twice.
    let packages = report["packages"].as_array().unwrap();
    let mut found_in = vec![sbom1, sbom2];
    found_in.sort();
    assert_eq!(
        json!(packages),
        json!([
            {"purl": "pkg:maven/jakarta.el/jakarta.el-api@3.0.3", "recommended_purl": "pkg:maven/jakarta.el/jakarta.el-api@3.0.3.redhat-00002",
             "advisory_id": "https://www.redhat.com/#CVE-2022-45787", "vulnerabilities": ["CVE-2022-45787"], "found_in": found_in},
            {"purl": "pkg:maven/jakarta.el/jakarta.el-api@3.0.3", "recommended_purl": "pkg:maven/jakarta.el/jakarta.el-api@3.0.3.redhat-00002",
             "advisory_id": "https://www.redhat.com/#CVE-2023-28867", "vulnerabilities": ["CVE-2023-28867"], "found_in": found_in}
        ])
    );

    // And each SBOM shows 1 addressable package
    let sboms = report["sboms"].as_array().unwrap();
    assert_eq!(sboms.len(), 2);
    for sbom in sboms {
        assert_eq!(sbom["addressable_packages"], 1);
    }

    Ok(())
}

/// Verifies that the same package in two SBOMs appears once with both SBOM IDs in found_in.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_deduplication(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given a CVE advisory that creates the upstream and vendor versioned PURLs
    ctx.ingest_documents(["cve/CVE-2022-45787.json"]).await?;

    // And two SBOMs each containing the same upstream package
    let sbom1 = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "sbom-dedup-1",
            "00000000-0000-0000-0000-000000000003",
            &[(
                "jakarta.el-api",
                "3.0.3",
                "pkg:maven/jakarta.el/jakarta.el-api@3.0.3",
            )],
        ))
        .await?
        .id,
    )?;
    let sbom2 = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "sbom-dedup-2",
            "00000000-0000-0000-0000-000000000004",
            &[(
                "jakarta.el-api",
                "3.0.3",
                "pkg:maven/jakarta.el/jakarta.el-api@3.0.3",
            )],
        ))
        .await?
        .id,
    )?;

    // When generating the report for both SBOMs
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[sbom1, sbom2]).await;

    // Then the package appears exactly once
    let packages = report["packages"].as_array().unwrap();
    assert_eq!(
        packages.len(),
        1,
        "expected exactly one deduplicated package"
    );

    // And found_in contains both SBOM IDs
    let found_in = packages[0]["found_in"].as_array().unwrap();
    assert_eq!(found_in.len(), 2, "expected both SBOM IDs in found_in");

    let mut found_ids: Vec<String> = found_in
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    found_ids.sort();
    let mut expected = vec![sbom1.to_string(), sbom2.to_string()];
    expected.sort();
    assert_eq!(found_ids, expected);

    Ok(())
}

/// Verifies that the report returns 413 package_limit_exceeded when total packages exceed the limit.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_package_limit_exceeded(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    use actix_web::http::StatusCode;

    // Given an SBOM with one package
    let sbom_id = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "sbom-limit",
            "00000000-0000-0000-0000-000000000005",
            &[(
                "jakarta.el-api",
                "3.0.3",
                "pkg:maven/jakarta.el/jakarta.el-api@3.0.3",
            )],
        ))
        .await?
        .id,
    )?;

    // When the package limit is 0 (always exceeded)
    let app = caller_with(
        ctx,
        Config {
            recommend_patterns: PurlService::default_recommend_patterns(),
            recommend_report_package_limit: 0,
            ..Default::default()
        },
        PaginationCache::for_test(),
    )
    .await?;
    let resp = app
        .call_service(
            TestRequest::post()
                .uri("/api/v3/purl/recommend/report")
                .set_json(json!({ "sbom_ids": [sbom_id] }))
                .to_request(),
        )
        .await;

    // Then 413 is returned with the package_limit_exceeded error code
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body: Value = actix_web::test::read_body_json(resp).await;
    assert_eq!(body["error"], "package_limit_exceeded");

    Ok(())
}

/// Verifies that SBOMs with no matching recommendations return a valid empty report with zero counts.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_empty_result(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given an SBOM with a package that has no vendor recommendation in the DB
    let sbom_id = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "sbom-empty",
            "00000000-0000-0000-0000-000000000006",
            &[("some-lib", "1.0.0", "pkg:maven/com.example/some-lib@1.0.0")],
        ))
        .await?
        .id,
    )?;

    // When generating the report (no advisories → no vendor patches available)
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[sbom_id]).await;

    // Then the report has zero counts and an empty packages list
    assert_eq!(report["impact_summary"]["sboms_with_recommendations"], 0);
    assert_eq!(report["impact_summary"]["addressable_packages"], 0);
    assert_eq!(report["packages"].as_array().unwrap().len(), 0);
    assert_eq!(report["sboms"][0]["addressable_packages"], 0);

    Ok(())
}

/// Verifies that when no recommendation patterns are configured, the endpoint returns 422
/// because the Recommendations capability is not active.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_no_patterns(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    use actix_web::http::StatusCode;

    // Given an SBOM with a package
    let sbom_id = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "sbom-no-patterns",
            "00000000-0000-0000-0000-000000000007",
            &[(
                "jakarta.el-api",
                "3.0.3",
                "pkg:maven/jakarta.el/jakarta.el-api@3.0.3",
            )],
        ))
        .await?
        .id,
    )?;

    // When requesting a report with no recommendation patterns configured
    let app = caller_with(
        ctx,
        Config {
            recommend_patterns: vec![],
            ..Default::default()
        },
        PaginationCache::for_test(),
    )
    .await?;

    let resp = app
        .call_service(
            TestRequest::post()
                .uri("/api/v3/purl/recommend/report")
                .set_json(json!({ "sbom_ids": [sbom_id] }))
                .to_request(),
        )
        .await;

    // Then the capability gate rejects the request
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    Ok(())
}

/// Verifies that only vulnerabilities addressed by the recommended PURL (fixed/not_affected)
/// appear in the report; affected/under_investigation CVEs are excluded.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_filters_to_addressed_vulns(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    // Given CVE-2022-45787 has status "not_affected" for jakarta.el-api@3.0.3.redhat-00002
    // (the vendor patch found by the redhat pattern)
    ctx.ingest_documents(["cve/CVE-2022-45787.json"]).await?;

    // And an SBOM containing the upstream package
    let sbom_id = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "sbom-vuln-filter",
            "00000000-0000-0000-0000-000000000008",
            &[(
                "jakarta.el-api",
                "3.0.3",
                "pkg:maven/jakarta.el/jakarta.el-api@3.0.3",
            )],
        ))
        .await?
        .id,
    )?;

    // When generating the report
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[sbom_id]).await;

    tracing::info!("{report:#?}");

    // Then the vendor patch is found (package entry exists)
    let packages = report["packages"].as_array().unwrap();
    assert_eq!(packages.len(), 1);
    assert_eq!(
        packages[0]["recommended_purl"],
        "pkg:maven/jakarta.el/jakarta.el-api@3.0.3.redhat-00002"
    );

    // And the not_affected CVE DOES appear — it is addressed by the recommendation
    let vulns = packages[0]["vulnerabilities"].as_array().unwrap();
    assert!(
        vulns.iter().any(|v| v.as_str() == Some("CVE-2022-45787")),
        "CVE-2022-45787 (not_affected) should appear in vulnerabilities, got: {vulns:?}"
    );

    // And per-SBOM vulnerability_count reflects addressed vulnerabilities
    assert_eq!(report["sboms"][0]["vulnerability_count"], 1);
    assert_eq!(report["sboms"][0]["addressable_packages"], 1);

    Ok(())
}

/// Builds a minimal CSAF VEX advisory JSON with given product and vulnerability statuses.
///
/// `tracking_id` must be unique across ingested documents.
/// `product_name` is the parent product context (e.g., "Test Product 1.0").
/// `components` is a slice of `(component_name, purl)`.
/// `vulns` is a slice of `(cve_id, csaf_status, component_indices)` where `csaf_status`
/// is one of "fixed", "known_affected", "known_not_affected", "under_investigation"
/// and `component_indices` indexes into the `components` slice.
fn minimal_csaf_vex(
    tracking_id: &str,
    product_name: &str,
    components: &[(&str, &str)],
    vulns: &[(&str, &str, &[usize])],
) -> Value {
    minimal_csaf_vex_at(
        tracking_id,
        MINIMAL_CSAF_RELEASE_DATE,
        product_name,
        components,
        vulns,
    )
}

const MINIMAL_CSAF_RELEASE_DATE: &str = "2024-01-15T00:00:00+00:00";

/// Builds a dated revision so ingestion can deprecate the previous advisory.
fn minimal_csaf_vex_at(
    tracking_id: &str,
    release_date: &str,
    product_name: &str,
    components: &[(&str, &str)],
    vulns: &[(&str, &str, &[usize])],
) -> Value {
    let component_branches: Vec<Value> = components
        .iter()
        .map(|(name, purl)| {
            json!({
                "category": "product_version",
                "name": name,
                "product": {
                    "name": name,
                    "product_id": name,
                    "product_identification_helper": { "purl": purl }
                }
            })
        })
        .collect();

    let relationships: Vec<Value> = components
        .iter()
        .map(|(name, _)| {
            json!({
                "category": "default_component_of",
                "full_product_name": {
                    "name": format!("{name} as a component of {product_name}"),
                    "product_id": format!("{product_name}:{name}")
                },
                "product_reference": name,
                "relates_to_product_reference": product_name
            })
        })
        .collect();

    let vulnerabilities: Vec<Value> = vulns
        .iter()
        .map(|(cve, status, indices)| {
            let product_ids: Vec<String> = indices
                .iter()
                .map(|&i| format!("{}:{}", product_name, components[i].0))
                .collect();
            let mut product_status = serde_json::Map::new();
            product_status.insert(status.to_string(), json!(product_ids));
            json!({
                "cve": *cve,
                "product_status": product_status
            })
        })
        .collect();

    json!({
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "publisher": {
                "category": "vendor",
                "name": "Test Vendor",
                "namespace": "https://test.example.com"
            },
            "title": format!("Test VEX {tracking_id}"),
            "tracking": {
                "current_release_date": release_date,
                "id": tracking_id,
                "initial_release_date": MINIMAL_CSAF_RELEASE_DATE,
                "revision_history": [{
                    "date": "2024-01-15T00:00:00+00:00",
                    "number": "1",
                    "summary": "Initial"
                }],
                "status": "final",
                "version": "1"
            }
        },
        "product_tree": {
            "branches": [{
                "category": "vendor",
                "name": "Test Vendor",
                "branches": [{
                    "category": "product_name",
                    "name": product_name,
                    "product": {
                        "name": product_name,
                        "product_id": product_name
                    }
                }, {
                    "category": "product_name",
                    "name": "Components",
                    "branches": component_branches
                }]
            }],
            "relationships": relationships
        },
        "vulnerabilities": vulnerabilities
    })
}

/// Builds a minimal OSV advisory with one Maven ecosystem version range.
fn minimal_osv_maven_range(
    id: &str,
    cve: &str,
    modified: &str,
    group_artifact: &str,
    introduced: &str,
    fixed: &str,
) -> Value {
    json!({
        "schema_version": "1.4.0",
        "id": id,
        "modified": modified,
        "published": modified,
        "aliases": [cve],
        "summary": format!("Test OSV {id}"),
        "affected": [{
            "package": { "ecosystem": "Maven", "name": group_artifact },
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [{ "introduced": introduced }, { "fixed": fixed }]
            }]
        }]
    })
}

/// Verifies that only addressed CVEs (fixed/not_affected) appear; affected CVEs are excluded.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_mixed_vuln_statuses(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given a VEX advisory where the vendor backport fixes CVE-A but not CVE-B
    let component = "mylib-1.0.0.redhat-00001";
    let purl = "pkg:maven/com.example/mylib@1.0.0.redhat-00001";
    ctx.ingest_json(minimal_csaf_vex(
        "TEST-MIXED-STATUS-001",
        "Test Product 1.0",
        &[(component, purl)],
        &[
            ("CVE-2024-90001", "fixed", &[0]),
            ("CVE-2024-90002", "known_affected", &[0]),
        ],
    ))
    .await?;

    // And an SBOM containing the upstream package
    let sbom_id = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "sbom-mixed-status",
            "00000000-0000-0000-0000-100000000001",
            &[("mylib", "1.0.0", "pkg:maven/com.example/mylib@1.0.0")],
        ))
        .await?
        .id,
    )?;

    // When generating the report
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[sbom_id]).await;

    tracing::info!("{report:#?}");

    // Then the package appears with only the fixed CVE
    let packages = report["packages"].as_array().unwrap();
    assert_eq!(packages.len(), 1, "expected one addressable package");
    assert_eq!(
        packages[0]["recommended_purl"],
        "pkg:maven/com.example/mylib@1.0.0.redhat-00001"
    );

    let vulns: Vec<&str> = packages[0]["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        vulns.contains(&"CVE-2024-90001"),
        "fixed CVE should appear, got: {vulns:?}"
    );
    assert!(
        !vulns.contains(&"CVE-2024-90002"),
        "affected CVE should not appear, got: {vulns:?}"
    );

    // And counts reflect addressed vulnerabilities only
    assert_eq!(report["impact_summary"]["addressable_packages"], 1);
    assert_eq!(report["sboms"][0]["vulnerability_count"], 1);

    Ok(())
}

/// An upstream assessment must not erase a fix from the component's actual provider.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_vendor_fix_with_newer_upstream_affected(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    // Given an older fixing provider and newer, conflicting upstream evidence.
    for (id, date, status) in [
        ("REPORT-VENDOR", "2024-01-15T00:00:00+00:00", "fixed"),
        (
            "REPORT-ALSO-VENDOR",
            "2024-01-15T00:00:00+00:00",
            "known_not_affected",
        ),
        (
            "REPORT-UPSTREAM",
            "2024-02-15T00:00:00+00:00",
            "known_affected",
        ),
    ] {
        let mut advisory = minimal_csaf_vex_at(
            id,
            date,
            "Report Crosslib Product",
            &[(
                "crosslib",
                "pkg:maven/com.example/crosslib@1.0.0.redhat-00001",
            )],
            &[("CVE-2099-50001", status, &[0])],
        );
        let (publisher, namespace) = if id == "REPORT-VENDOR" {
            ("Red Hat", "https://www.redhat.com")
        } else {
            ("Upstream", "https://upstream.example.org")
        };
        advisory["document"]["publisher"]["name"] = json!(publisher);
        advisory["document"]["publisher"]["namespace"] = json!(namespace);
        ctx.ingest_json(advisory).await?;
    }
    let mut sbom = minimal_cdx(
        "report-cross-source",
        "00000000-0000-0000-0000-300000000001",
        &[("crosslib", "1.0.0", "pkg:maven/com.example/crosslib@1.0.0")],
    );
    sbom["components"][0]["supplier"] = json!({"name": "Red Hat"});
    let sbom_id = Uuid::parse_str(&ctx.ingest_json(sbom).await?.id)?;

    // When resolving the recommendation in that component's provider context.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[sbom_id]).await;

    // Then the actual provider's fix supplies the exact addressed CVE and provenance.
    let packages = report["packages"].as_array().unwrap();
    assert_eq!(packages.len(), 1);
    assert_eq!(
        packages[0]["recommended_purl"],
        "pkg:maven/com.example/crosslib@1.0.0.redhat-00001"
    );
    assert_eq!(packages[0]["vulnerabilities"], json!(["CVE-2099-50001"]));
    assert_eq!(
        packages[0]["advisory_id"],
        "https://www.redhat.com/#REPORT-VENDOR"
    );
    assert_eq!(report["impact_summary"]["addressable_packages"], 1);
    assert_eq!(report["sboms"][0]["vulnerability_count"], 1);
    Ok(())
}

/// A non-addressing winner must defeat a conflicting positive assessment before counting CVEs.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_newer_affected_vs_older_not_affected(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    // Given the reviewer's exact older-not-affected/newer-affected assessments.
    for (id, date, status) in [
        (
            "F1-UPSTREAM-NA",
            "2024-01-15T00:00:00+00:00",
            "known_not_affected",
        ),
        (
            "F1-VENDOR-AFFECTED",
            "2024-02-15T00:00:00+00:00",
            "known_affected",
        ),
    ] {
        ctx.ingest_json(minimal_csaf_vex_at(
            id,
            date,
            "F1 Product",
            &[("f1lib", "pkg:maven/com.example/f1lib@1.0.0.redhat-00002")],
            &[("CVE-2099-81001", status, &[0])],
        ))
        .await?;
    }
    let sbom_id = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "review-f1",
            "00000000-0000-0000-0000-f10000000001",
            &[("f1lib", "1.0.0", "pkg:maven/com.example/f1lib@1.0.0")],
        ))
        .await?
        .id,
    )?;

    // When generating a report for the upstream package.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[sbom_id]).await;

    // Then the selected affected assessment addresses nothing, matching merged main.
    assert_eq!(report["sboms"][0]["vulnerability_count"], 0);
    assert_eq!(report["sboms"][0]["addressable_packages"], 0);
    assert_eq!(report["packages"], json!([]));
    assert_eq!(
        report["impact_summary"],
        json!({
            "sboms_with_recommendations": 0, "addressable_packages": 0
        })
    );
    Ok(())
}

/// Separate winning advisories retain their own CVEs while duplicate components count once.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_advisory_attribution(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given the reviewer's two sources addressing different CVEs for the same build.
    for (id, date, cve, status) in [
        (
            "F3-VENDOR-A",
            "2024-01-15T00:00:00+00:00",
            "CVE-2099-83001",
            "fixed",
        ),
        (
            "F3-UPSTREAM-B",
            "2024-03-15T00:00:00+00:00",
            "CVE-2099-83002",
            "known_not_affected",
        ),
    ] {
        ctx.ingest_json(minimal_csaf_vex_at(
            id,
            date,
            "F3 Product",
            &[("f3lib", "pkg:maven/com.example/f3lib@1.0.0.redhat-00001")],
            &[(cve, status, &[0])],
        ))
        .await?;
    }
    let mut sbom_ids = Vec::new();
    for (name, serial) in [
        ("review-f3-a", "00000000-0000-0000-0000-f30000000001"),
        ("review-f3-b", "00000000-0000-0000-0000-f30000000002"),
    ] {
        sbom_ids.push(Uuid::parse_str(
            &ctx.ingest_json(minimal_cdx(
                name,
                serial,
                &[
                    ("f3lib", "1.0.0", "pkg:maven/com.example/f3lib@1.0.0"),
                    ("f3lib", "1.0.0", "pkg:maven/com.example/f3lib@1.0.0"),
                ],
            ))
            .await?
            .id,
        )?);
    }
    let mut found_in = sbom_ids.clone();
    found_in.sort();

    // When resolving identical components across both SBOMs.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &sbom_ids).await;

    // Then each source is credited only with its own CVE and exact SBOM membership.
    assert_eq!(
        report["packages"],
        json!([
            {
                "purl": "pkg:maven/com.example/f3lib@1.0.0",
                "recommended_purl": "pkg:maven/com.example/f3lib@1.0.0.redhat-00001",
                "advisory_id": "https://test.example.com/#F3-UPSTREAM-B",
                "vulnerabilities": ["CVE-2099-83002"], "found_in": found_in
            },
            {
                "purl": "pkg:maven/com.example/f3lib@1.0.0",
                "recommended_purl": "pkg:maven/com.example/f3lib@1.0.0.redhat-00001",
                "advisory_id": "https://test.example.com/#F3-VENDOR-A",
                "vulnerabilities": ["CVE-2099-83001"], "found_in": found_in
            }
        ])
    );
    assert_eq!(
        report["impact_summary"],
        json!({
            "sboms_with_recommendations": 2, "addressable_packages": 1
        })
    );
    assert_eq!(
        report["sboms"],
        json!([
            {"id": sbom_ids[0], "name": "review-f3-a", "addressable_packages": 1, "vulnerability_count": 2},
            {"id": sbom_ids[1], "name": "review-f3-b", "addressable_packages": 1, "vulnerability_count": 2}
        ])
    );
    Ok(())
}

/// Twelve-package reports return complete values in the same canonical order on every request.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_order_stable(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given twelve independently addressable packages in the reviewer's ordering fixture.
    let names = (0..12).map(|i| format!("f4lib{i:02}")).collect::<Vec<_>>();
    let vendor_purls = names
        .iter()
        .map(|n| format!("pkg:maven/com.example/{n}@1.0.0.redhat-00001"))
        .collect::<Vec<_>>();
    let upstream_purls = names
        .iter()
        .map(|n| format!("pkg:maven/com.example/{n}@1.0.0"))
        .collect::<Vec<_>>();
    let components = names
        .iter()
        .zip(&vendor_purls)
        .map(|(n, p)| (n.as_str(), p.as_str()))
        .collect::<Vec<_>>();
    let indices = (0..12).collect::<Vec<_>>();
    ctx.ingest_json(minimal_csaf_vex(
        "F4-ORDER",
        "F4 Product",
        &components,
        &[("CVE-2099-84001", "fixed", &indices)],
    ))
    .await?;
    let inputs = names
        .iter()
        .zip(&upstream_purls)
        .map(|(n, p)| (n.as_str(), "1.0.0", p.as_str()))
        .collect::<Vec<_>>();
    let sbom_id = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "review-f4",
            "00000000-0000-0000-0000-f40000000001",
            &inputs,
        ))
        .await?
        .id,
    )?;
    let expected = upstream_purls
        .iter()
        .zip(&vendor_purls)
        .map(|(upstream, vendor)| {
            json!({
                "purl": upstream, "recommended_purl": vendor,
                "advisory_id": "https://test.example.com/#F4-ORDER",
                "vulnerabilities": ["CVE-2099-84001"], "found_in": [sbom_id]
            })
        })
        .collect::<Vec<_>>();
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;

    // When repeating the identical report request ten times.
    for _ in 0..10 {
        let report = recommend_report_req(&app, &[sbom_id]).await;

        // Then exact ordered values also prove that no package or CVE was dropped.
        assert_eq!(report["packages"].as_array().unwrap().len(), 12);
        assert_eq!(report["packages"], json!(expected));
        assert_eq!(report["impact_summary"]["addressable_packages"], 12);
        assert_eq!(report["sboms"][0]["vulnerability_count"], 1);
    }
    Ok(())
}

/// Builds one stable-ID component so source recovery can be tested independently of ingestion.
fn report_source_cdx(serial: &str) -> Value {
    let mut doc = minimal_cdx(
        "source-recovery",
        serial,
        &[("crosslib", "1.0.0", "pkg:maven/com.example/crosslib@1.0.0")],
    );
    doc["metadata"]["component"]["bom-ref"] = json!("root");
    doc["components"][0]["bom-ref"] = json!("component");
    doc["components"][0]["supplier"] = json!({"name": "Red Hat"});
    doc
}

/// Ingests a vendor-fixed build and an upstream SBOM for recovery failure tests.
async fn ingest_report_source_fixture(ctx: &TrustifyContext, doc: Value) -> anyhow::Result<Uuid> {
    ctx.ingest_json(minimal_csaf_vex(
        "RECOVERY-FIX",
        "Recovery Product",
        &[(
            "crosslib",
            "pkg:maven/com.example/crosslib@1.0.0.redhat-00001",
        )],
        &[("CVE-2099-74460", "fixed", &[0])],
    ))
    .await?;
    Ok(Uuid::parse_str(&ctx.ingest_json(doc).await?.id)?)
}

/// Reads the source metadata without changing it, for controlled storage fault fixtures.
async fn report_source_metadata(
    ctx: &TrustifyContext,
    id: Uuid,
) -> anyhow::Result<source_document::Model> {
    use sea_orm::EntityTrait;
    use trustify_entity::{sbom, source_document};
    let sbom = sbom::Entity::find_by_id(id).one(&ctx.db).await?.unwrap();
    Ok(source_document::Entity::find_by_id(sbom.source_document_id)
        .one(&ctx.db)
        .await?
        .unwrap())
}

/// One missing source must fail the request, not silently produce a partial aggregate.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_source_missing(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use actix_web::{http::StatusCode, test::read_body_json};
    use sea_orm::{ActiveModelTrait, Set};
    use trustify_entity::source_document;

    // Given two SBOMs with a valid recommendation, but one source object is unavailable.
    let first = ingest_report_source_fixture(
        ctx,
        report_source_cdx("00000000-0000-0000-0000-744600000001"),
    )
    .await?;
    let second = ingest_report_source_fixture(
        ctx,
        report_source_cdx("00000000-0000-0000-0000-744600000002"),
    )
    .await?;
    let metadata = report_source_metadata(ctx, second).await?;
    source_document::ActiveModel {
        id: Set(metadata.id),
        sha256: Set("00".repeat(32)),
        ..Default::default()
    }
    .update(&ctx.db)
    .await?;

    // When requesting a combined report.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v3/purl/recommend/report")
                .set_json(json!({"sbom_ids": [first, second]}))
                .to_request(),
        )
        .await;

    // Then no apparently complete subset is returned.
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = read_body_json(response).await;
    assert_eq!(body["error"], "ReportEvidenceUnavailable");
    assert!(body.get("packages").is_none());
    Ok(())
}

/// Unreadable source data is an explicit error, never evidence of an absent supplier.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_source_corrupt(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use actix_web::{http::StatusCode, test::read_body_json};
    use hex::encode as encode_hex;
    use sea_orm::{ActiveModelTrait, Set};
    use std::io::Cursor;
    use trustify_entity::source_document;
    use trustify_module_storage::service::StorageBackend;

    // Given a source reference whose object can be read but no longer parsed.
    let id = ingest_report_source_fixture(
        ctx,
        report_source_cdx("00000000-0000-0000-0000-744600000003"),
    )
    .await?;
    let metadata = report_source_metadata(ctx, id).await?;
    let corrupt = ctx.storage.store(Cursor::new(b"{broken".to_vec())).await?;
    source_document::ActiveModel {
        id: Set(metadata.id),
        sha256: Set(encode_hex(corrupt.digests.sha256)),
        ..Default::default()
    }
    .update(&ctx.db)
    .await?;

    // When generating the report.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v3/purl/recommend/report")
                .set_json(json!({"sbom_ids": [id]}))
                .to_request(),
        )
        .await;

    // Then the failure is visible and contains no partial report.
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = read_body_json(response).await;
    assert_eq!(body["error"], "ReportEvidenceUnavailable");
    assert!(body.get("packages").is_none());
    Ok(())
}

/// Source-size preflight prevents parsing an oversized document regardless of package count.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_source_size_limit(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use actix_web::{http::StatusCode, test::read_body_json};
    use sea_orm::{ActiveModelTrait, Set};
    use trustify_entity::source_document;

    // Given one reportable package in a source exceeding the 64 MiB recovery limit.
    let id = ingest_report_source_fixture(
        ctx,
        report_source_cdx("00000000-0000-0000-0000-744600000004"),
    )
    .await?;
    let metadata = report_source_metadata(ctx, id).await?;
    source_document::ActiveModel {
        id: Set(metadata.id),
        size: Set(64 * 1024 * 1024 + 1),
        ..Default::default()
    }
    .update(&ctx.db)
    .await?;

    // When generating a report below the existing package-count limit.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v3/purl/recommend/report")
                .set_json(json!({"sbom_ids": [id]}))
                .to_request(),
        )
        .await;

    // Then the independent source-byte limit is explicit.
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body: Value = read_body_json(response).await;
    assert_eq!(body["error"], "ReportEvidenceLimitExceeded");
    Ok(())
}

/// Anonymous indistinguishable components with different suppliers cannot be assigned by order.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_source_ambiguous(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use actix_web::{http::StatusCode, test::read_body_json};

    // Given two anonymous components whose only distinguishing input was discarded at ingestion.
    let mut doc = report_source_cdx("00000000-0000-0000-0000-744600000005");
    doc["components"][0]
        .as_object_mut()
        .unwrap()
        .remove("bom-ref");
    let mut second = doc["components"][0].clone();
    second["supplier"] = json!({"name": "Another Supplier"});
    doc["components"].as_array_mut().unwrap().push(second);
    let id = ingest_report_source_fixture(ctx, doc).await?;

    // When recovery would need to guess which supplier belongs to each stored random node ID.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v3/purl/recommend/report")
                .set_json(json!({"sbom_ids": [id]}))
                .to_request(),
        )
        .await;

    // Then attribution ambiguity is not silently converted into a successful report.
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body: Value = read_body_json(response).await;
    assert_eq!(body["error"], "ReportEvidenceAmbiguous");
    Ok(())
}

/// Builds real provider and CPE attribution instead of inferring authority from an advisory title.
fn report_provider_vex(
    id: &str,
    namespace: &str,
    publisher: &str,
    cpe: &str,
    status: &str,
) -> Value {
    let mut doc = minimal_csaf_vex_at(
        id,
        MINIMAL_CSAF_RELEASE_DATE,
        "Report Product",
        &[(
            "crosslib",
            "pkg:maven/com.example/crosslib@1.0.0.redhat-00001",
        )],
        &[("CVE-2099-74461", status, &[0])],
    );
    doc["document"]["publisher"]["namespace"] = json!(namespace);
    doc["document"]["publisher"]["name"] = json!(publisher);
    doc["product_tree"]["branches"][0]["branches"][0]["product"]["product_identification_helper"] =
        json!({"cpe": cpe});
    doc
}

/// Explicit component provider authority selects both addressing and non-addressing verdicts.
#[test_context(TrustifyContext)]
#[rstest]
#[case::fixed("fixed", "known_affected", json!([{"advisory_id": "https://www.redhat.com/#PROVIDER-VENDOR", "vulnerabilities": ["CVE-2099-74461"]}]), 1)]
#[case::affected("known_affected", "known_not_affected", json!([]), 0)]
#[test_log::test(actix_web::test)]
async fn recommend_report_component_provider(
    ctx: &TrustifyContext,
    #[case] vendor_status: &str,
    #[case] upstream_status: &str,
    #[case] expected: Value,
    #[case] addressed: usize,
) -> anyhow::Result<()> {
    // Given conflicting real publishers for the same exact recommendation and product context.
    let cpe = "cpe:/a:example:report-product:1.0";
    ctx.ingest_json(report_provider_vex(
        "PROVIDER-VENDOR",
        "https://www.redhat.com",
        "Red Hat",
        cpe,
        vendor_status,
    ))
    .await?;
    let mut upstream = report_provider_vex(
        "PROVIDER-UPSTREAM",
        "https://upstream.example.org",
        "Upstream",
        cpe,
        upstream_status,
    );
    upstream["document"]["tracking"]["current_release_date"] = json!("2024-03-15T00:00:00+00:00");
    ctx.ingest_json(upstream).await?;
    let mut doc = report_source_cdx("00000000-0000-0000-0000-744610000001");
    doc["components"][0]["cpe"] = json!(cpe);
    let id = Uuid::parse_str(&ctx.ingest_json(doc).await?.id)?;

    // When resolving the component's Red Hat supplier rather than choosing by advisory date.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[id]).await;

    // Then the selected source/status controls both report membership and provenance.
    let packages = report["packages"].as_array().unwrap();
    let selected = packages
        .iter()
        .map(|p| {
            assert_eq!(p["purl"], "pkg:maven/com.example/crosslib@1.0.0");
            assert_eq!(
                p["recommended_purl"],
                "pkg:maven/com.example/crosslib@1.0.0.redhat-00001"
            );
            assert_eq!(p["found_in"], json!([id]));
            json!({"advisory_id": p["advisory_id"], "vulnerabilities": p["vulnerabilities"]})
        })
        .collect::<Vec<_>>();
    assert_eq!(json!(selected), expected);
    assert_eq!(report["impact_summary"]["addressable_packages"], addressed);
    assert_eq!(report["sboms"][0]["vulnerability_count"], addressed);
    Ok(())
}

/// Stored UnderInvestigation evidence from the component provider defeats an upstream fix.
/// CSAF UnderInvestigation ingestion is not supported on this release and is outside this task.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_authoritative_under_investigation(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set, sea_query::Expr};
    use trustify_entity::{advisory, purl_status, status};

    // Given actual stored UnderInvestigation evidence, rather than an ignored CSAF input field.
    let cpe = "cpe:/a:example:report-product:1.0";
    ctx.ingest_json(report_provider_vex(
        "INVESTIGATING-VENDOR",
        "https://www.redhat.com",
        "Red Hat",
        cpe,
        "known_affected",
    ))
    .await?;
    ctx.ingest_json(report_provider_vex(
        "INVESTIGATING-UPSTREAM",
        "https://upstream.example.org",
        "Upstream",
        cpe,
        "fixed",
    ))
    .await?;
    let vendor = advisory::Entity::find()
        .filter(advisory::Column::Identifier.eq("https://www.redhat.com/#INVESTIGATING-VENDOR"))
        .one(&ctx.db)
        .await?
        .unwrap();
    let status_id = Uuid::new_v4();
    status::Entity::insert(status::ActiveModel {
        id: Set(status_id),
        slug: Set("under_investigation".into()),
        name: Set("Under investigation".into()),
        description: Set(None),
    })
    .exec(&ctx.db)
    .await?;
    let changed = purl_status::Entity::update_many()
        .col_expr(purl_status::Column::StatusId, Expr::value(status_id))
        .filter(purl_status::Column::AdvisoryId.eq(vendor.id))
        .exec(&ctx.db)
        .await?;
    assert_eq!(changed.rows_affected, 1);
    let mut doc = report_source_cdx("00000000-0000-0000-0000-744610000005");
    doc["components"][0]["cpe"] = json!(cpe);
    let id = Uuid::parse_str(&ctx.ingest_json(doc).await?.id)?;

    // When the report resolves all eligible statuses before filtering addressing outcomes.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[id]).await;

    // Then the authoritative investigation is not advertised as addressed.
    assert_eq!(report["packages"], json!([]));
    assert_eq!(report["impact_summary"]["addressable_packages"], 0);
    assert_eq!(report["sboms"][0]["vulnerability_count"], 0);
    Ok(())
}

/// Missing sources are irrelevant when no active addressing assessment can produce a report row.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_unneeded_source(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};
    use trustify_entity::purl_status;

    // Given a persisted vendor candidate with no assessments and an unavailable original SBOM.
    let id = ingest_report_source_fixture(
        ctx,
        report_source_cdx("00000000-0000-0000-0000-744610000006"),
    )
    .await?;
    purl_status::Entity::delete_many().exec(&ctx.db).await?;
    let metadata = report_source_metadata(ctx, id).await?;
    source_document::ActiveModel {
        id: Set(metadata.id),
        sha256: Set("00".repeat(32)),
        ..Default::default()
    }
    .update(&ctx.db)
    .await?;

    // When no positive outcome is even possible, there is no supplier evidence to resolve.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[id]).await;

    // Then the known-empty report does not unnecessarily depend on blob availability.
    assert_eq!(report["packages"], json!([]));
    assert_eq!(
        report["impact_summary"],
        json!({"sboms_with_recommendations": 0, "addressable_packages": 0})
    );
    assert_eq!(report["sboms"][0]["vulnerability_count"], 0);
    Ok(())
}

/// An explicit but unresolved supplier must prevent fallback to a matching product supplier.
#[test_context(TrustifyContext)]
#[rstest]
#[case::empty(json!({}))]
#[case::unknown(json!({"name": "Unknown Supplier"}))]
#[test_log::test(actix_web::test)]
async fn recommend_report_unresolved_supplier(
    ctx: &TrustifyContext,
    #[case] supplier: Value,
) -> anyhow::Result<()> {
    // Given a Red Hat product whose component explicitly has no resolvable provider.
    let cpe = "cpe:/a:example:report-product:1.0";
    ctx.ingest_json(report_provider_vex(
        "UNRESOLVED-FIX",
        "https://www.redhat.com",
        "Red Hat",
        cpe,
        "fixed",
    ))
    .await?;
    ctx.ingest_json(report_provider_vex(
        "UNRESOLVED-AFFECTED",
        "https://upstream.example.org",
        "Upstream",
        cpe,
        "known_affected",
    ))
    .await?;
    let mut doc = report_source_cdx("00000000-0000-0000-0000-744610000002");
    doc["metadata"]["supplier"] = json!({"name": "Red Hat"});
    doc["components"][0]["supplier"] = supplier;
    doc["components"][0]["cpe"] = json!(cpe);
    let id = Uuid::parse_str(&ctx.ingest_json(doc).await?.id)?;

    // When equal-authority conflicting statuses must fall through to status priority.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[id]).await;

    // Then affected wins; the unrelated product supplier cannot turn this into a vendor fix.
    assert_eq!(report["packages"], json!([]));
    assert_eq!(report["impact_summary"]["addressable_packages"], 0);
    assert_eq!(report["sboms"][0]["vulnerability_count"], 0);
    Ok(())
}

/// Swapped local/root contexts for one PURL must produce different per-SBOM verdicts.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_weighted_component_contexts(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given equal-provider assessments distinguished by product version and local/root specificity.
    let fixed = "cpe:/a:example:report-product:1.0";
    let affected = "cpe:/a:example:report-product:2.0";
    ctx.ingest_json(report_provider_vex(
        "WEIGHTED-FIX",
        "https://www.redhat.com",
        "Red Hat",
        fixed,
        "fixed",
    ))
    .await?;
    ctx.ingest_json(report_provider_vex(
        "WEIGHTED-AFFECTED",
        "https://www.redhat.com",
        "Red Hat",
        affected,
        "known_affected",
    ))
    .await?;
    let mut ids = Vec::new();
    for (serial, local, root) in [
        ("00000000-0000-0000-0000-744610000003", fixed, affected),
        ("00000000-0000-0000-0000-744610000004", affected, fixed),
    ] {
        let mut doc = report_source_cdx(serial);
        doc["components"][0]["cpe"] = json!(local);
        doc["metadata"]["component"]["cpe"] = json!(root);
        ids.push(Uuid::parse_str(&ctx.ingest_json(doc).await?.id)?);
    }

    // When resolving before collapsing the PURL across SBOMs.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &ids).await;

    // Then only the local-fixed context contributes a row and counts.
    assert_eq!(
        report["packages"],
        json!([{
            "purl": "pkg:maven/com.example/crosslib@1.0.0",
            "recommended_purl": "pkg:maven/com.example/crosslib@1.0.0.redhat-00001",
            "advisory_id": "https://www.redhat.com/#WEIGHTED-FIX",
            "vulnerabilities": ["CVE-2099-74461"], "found_in": [ids[0]]
        }])
    );
    assert_eq!(report["sboms"][0]["vulnerability_count"], 1);
    assert_eq!(report["sboms"][1]["vulnerability_count"], 0);
    assert_eq!(
        report["impact_summary"],
        json!({"sboms_with_recommendations": 1, "addressable_packages": 1})
    );
    Ok(())
}

/// A stated fix outranks the release-generated affected-before range of a later fix.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_stated_fix_beats_generated_affected(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    // Given one Red Hat document fixing the same CVE in two upstream version lines.
    let mut advisory = minimal_csaf_vex(
        "ORIGIN-FIXES",
        "Origin Product",
        &[
            ("lib-v1", "pkg:maven/com.example/lib@1.0.0.redhat-00001"),
            ("lib-v2", "pkg:maven/com.example/lib@2.0.0.redhat-00001"),
        ],
        &[("CVE-2099-74501", "fixed", &[0, 1])],
    );
    advisory["document"]["publisher"]["namespace"] = json!("https://www.redhat.com");
    advisory["document"]["publisher"]["name"] = json!("Red Hat");
    ctx.ingest_json(advisory).await?;
    let id = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "origin-report",
            "00000000-0000-0000-0000-745010000001",
            &[("lib", "1.0.0", "pkg:maven/com.example/lib@1.0.0")],
        ))
        .await?
        .id,
    )?;
    // When the older fixed version also matches the generated affected-before-v2 row.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[id]).await;
    // Then inferred evidence cannot erase the stated fix or its exact provenance.
    assert_eq!(
        report["packages"],
        json!([{
            "purl": "pkg:maven/com.example/lib@1.0.0", "recommended_purl": "pkg:maven/com.example/lib@1.0.0.redhat-00001",
            "advisory_id": "https://www.redhat.com/#ORIGIN-FIXES", "vulnerabilities": ["CVE-2099-74501"], "found_in": [id]
        }])
    );
    assert_eq!(report["sboms"][0]["vulnerability_count"], 1);
    Ok(())
}

/// Provider identifiers on a component remain available even when they have no recommendation candidate.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_retains_nonwinning_identifiers(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use trustify_entity::{qualified_purl, sbom_node_purl_ref};
    // Given Maven assessments and an additional RPM identity identifying the component's provider.
    let cpe = "cpe:/a:example:report-product:1.0";
    ctx.ingest_json(report_provider_vex(
        "IDENTITY-VENDOR",
        "https://www.redhat.com",
        "Red Hat",
        cpe,
        "fixed",
    ))
    .await?;
    ctx.ingest_json(report_provider_vex(
        "IDENTITY-UPSTREAM",
        "https://upstream.example.org",
        "Upstream",
        cpe,
        "known_affected",
    ))
    .await?;
    let mut doc = report_source_cdx("00000000-0000-0000-0000-745020000001");
    doc["specVersion"] = json!("1.6");
    doc["components"][0]["supplier"] = Value::Null;
    doc["components"][0]["cpe"] = json!(cpe);
    doc["components"][0]["evidence"] = json!({"identity":[{"field":"purl","confidence":1.0,"concludedValue":"pkg:rpm/redhat/crosslib@1.0.0"}]});
    let id = Uuid::parse_str(&ctx.ingest_json(doc).await?.id)?;
    let input = sbom_node_purl_ref::Entity::find()
        .filter(sbom_node_purl_ref::Column::SbomId.eq(id))
        .find_also_related(qualified_purl::Entity)
        .all(&ctx.db)
        .await?;
    assert_eq!(
        input
            .iter()
            .map(|(_, purl)| purl.as_ref().unwrap().purl.ty.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["maven", "rpm"])
    );
    // When only the Maven identifier can produce a vendor candidate.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[id]).await;
    // Then candidate filtering must not remove the RPM provider hint from that same component.
    assert_eq!(
        report["packages"],
        json!([{
            "purl":"pkg:maven/com.example/crosslib@1.0.0", "recommended_purl":"pkg:maven/com.example/crosslib@1.0.0.redhat-00001",
            "advisory_id":"https://www.redhat.com/#IDENTITY-VENDOR", "vulnerabilities":["CVE-2099-74461"], "found_in":[id]
        }])
    );
    Ok(())
}

/// RPM qualifiers supply product context even when the SBOM contains no explicit CPEs.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_rpm_qualifier_context(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given equal-provider assessments of the same RPM build in different RHEL products.
    for (id, cpe, status) in [
        ("RPM-RHEL8", "cpe:/o:redhat:enterprise_linux:8", "fixed"),
        (
            "RPM-RHEL9",
            "cpe:/o:redhat:enterprise_linux:9",
            "known_affected",
        ),
    ] {
        let mut advisory =
            report_provider_vex(id, "https://www.redhat.com", "Red Hat", cpe, status);
        advisory["product_tree"]["branches"][0]["branches"][1]["branches"][0]["product"]["product_identification_helper"]
            ["purl"] = json!("pkg:rpm/redhat/crosslib@1.0.0.redhat-00001");
        ctx.ingest_json(advisory).await?;
    }
    let id = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "rpm-report",
            "00000000-0000-0000-0000-745030000001",
            &[(
                "crosslib",
                "1.0.0",
                "pkg:rpm/redhat/crosslib@1.0.0?distro=rhel-8",
            )],
        ))
        .await?
        .id,
    )?;
    // When the qualifier must confirm RHEL8 and reject the comparable RHEL9 context.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[id]).await;
    // Then the selected fix retains its product-specific membership and provenance.
    assert_eq!(
        report["packages"],
        json!([{
            "purl":"pkg:rpm/redhat/crosslib@1.0.0", "recommended_purl":"pkg:rpm/redhat/crosslib@1.0.0.redhat-00001",
            "advisory_id":"https://www.redhat.com/#RPM-RHEL8", "vulnerabilities":["CVE-2099-74461"], "found_in":[id]
        }])
    );
    Ok(())
}

/// An explicit affected range stays stated even when a fix generates the identical legacy row UUID.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_stated_origin_wins_collision(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    // Given a stated v1 fix and a different advisory explicitly affecting versions below v2.
    let cpe = "cpe:/a:example:report-product:1.0";
    ctx.ingest_json(report_provider_vex(
        "COLLISION-FIX",
        "https://www.redhat.com",
        "Red Hat",
        cpe,
        "fixed",
    ))
    .await?;
    let mut affected = report_provider_vex(
        "COLLISION-AFFECTED",
        "https://www.redhat.com",
        "Red Hat",
        cpe,
        "known_affected",
    );
    let mut later = affected["product_tree"]["branches"][0]["branches"][1]["branches"][0].clone();
    later["name"] = json!("crosslib-fixed2");
    later["product"]["name"] = json!("crosslib-fixed2");
    later["product"]["product_id"] = json!("crosslib-fixed2");
    later["product"]["product_identification_helper"]["purl"] =
        json!("pkg:maven/com.example/crosslib@2.0.0.redhat-00001");
    let branch = &mut affected["product_tree"]["branches"][0]["branches"][1]["branches"][0];
    branch["category"] = json!("product_version_range");
    branch["name"] = json!("vers:maven/<2.0.0.redhat-00001");
    branch["product"]["product_identification_helper"]["purl"] =
        json!("pkg:maven/com.example/crosslib");
    affected["product_tree"]["branches"][0]["branches"][1]["branches"]
        .as_array_mut()
        .unwrap()
        .push(later);
    affected["product_tree"]["relationships"].as_array_mut().unwrap().push(json!({
        "category":"default_component_of","full_product_name":{"name":"later fix","product_id":"Report Product:crosslib-fixed2"},
        "product_reference":"crosslib-fixed2","relates_to_product_reference":"Report Product"
    }));
    affected["vulnerabilities"][0]["product_status"]["fixed"] =
        json!(["Report Product:crosslib-fixed2"]);
    ctx.ingest_json(affected).await?;
    let mut doc = report_source_cdx("00000000-0000-0000-0000-745010000002");
    doc["components"][0]["cpe"] = json!(cpe);
    let id = Uuid::parse_str(&ctx.ingest_json(doc).await?.id)?;
    // When the explicit VERS range and generated affected-before range have the same stored UUID.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[id]).await;
    // Then direct evidence is not demoted by a range-shape heuristic or a duplicate generated origin.
    assert_eq!(report["packages"], json!([]));
    assert_eq!(report["sboms"][0]["vulnerability_count"], 0);
    Ok(())
}

/// A missing advisory source is irrelevant to a CVE with no possible addressing assessment.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_unneeded_origin_source(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
    use trustify_entity::advisory;
    // Given an addressable CVE and another CVE whose only matched row is generated affected evidence.
    ctx.ingest_json(minimal_csaf_vex(
        "UNNEEDED-ORIGIN-POSITIVE",
        "Origin Product",
        &[("lib", "pkg:maven/com.example/lib@1.0.0.redhat-00001")],
        &[("CVE-2099-74504", "known_not_affected", &[0])],
    ))
    .await?;
    let mut negative = minimal_csaf_vex(
        "UNNEEDED-ORIGIN-NEGATIVE",
        "Origin Product",
        &[("lib", "pkg:maven/com.example/lib@2.0.0.redhat-00001")],
        &[("CVE-2099-74505", "fixed", &[0])],
    );
    negative["document"]["publisher"]["namespace"] = json!("https://www.redhat.com");
    ctx.ingest_json(negative).await?;
    let negative = advisory::Entity::find()
        .filter(advisory::Column::Identifier.eq("https://www.redhat.com/#UNNEEDED-ORIGIN-NEGATIVE"))
        .one(&ctx.db)
        .await?
        .unwrap();
    source_document::ActiveModel {
        id: Set(negative.source_document_id),
        sha256: Set("00".repeat(32)),
        ..Default::default()
    }
    .update(&ctx.db)
    .await?;
    let id = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "unneeded-origin",
            "00000000-0000-0000-0000-745040000001",
            &[("lib", "1.0.0", "pkg:maven/com.example/lib@1.0.0")],
        ))
        .await?
        .id,
    )?;
    // When only the first CVE can contribute to report rows, regardless of the second one's origin.
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[id]).await;
    // Then required-evidence failure policy does not introduce an unnecessary source dependency.
    assert_eq!(
        report["packages"],
        json!([{
            "purl":"pkg:maven/com.example/lib@1.0.0","recommended_purl":"pkg:maven/com.example/lib@1.0.0.redhat-00001",
            "advisory_id":"https://test.example.com/#UNNEEDED-ORIGIN-POSITIVE","vulnerabilities":["CVE-2099-74504"],"found_in":[id]
        }])
    );
    Ok(())
}

/// A superseded fixed revision must not address a CVE once the current revision says affected.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_ignores_deprecated_fixed_revision(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    for (date, status) in [
        ("2024-01-15T00:00:00+00:00", "fixed"),
        ("2024-02-15T00:00:00+00:00", "known_affected"),
    ] {
        ctx.ingest_json(minimal_csaf_vex_at(
            "REPORT-REVISION",
            date,
            "Report Revision Product",
            &[("revlib", "pkg:maven/com.example/revlib@1.0.0.redhat-00001")],
            &[("CVE-2099-50002", status, &[0])],
        ))
        .await?;
    }
    let sbom_id = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "report-revision",
            "00000000-0000-0000-0000-300000000002",
            &[("revlib", "1.0.0", "pkg:maven/com.example/revlib@1.0.0")],
        ))
        .await?
        .id,
    )?;
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[sbom_id]).await;
    assert_eq!(report["packages"], json!([]));
    assert_eq!(report["impact_summary"]["addressable_packages"], 0);
    assert_eq!(report["sboms"][0]["vulnerability_count"], 0);
    Ok(())
}

/// Verifies that a package with zero fixed/not_affected CVEs is excluded from the report.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn recommend_report_excludes_unaddressed_package(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    // Given a VEX where the vendor version is affected (not fixed) for the only CVE
    let component = "badlib-2.0.0.redhat-00001";
    let purl = "pkg:maven/com.example/badlib@2.0.0.redhat-00001";
    ctx.ingest_json(minimal_csaf_vex(
        "TEST-ALL-AFFECTED-001",
        "Test Product 2.0",
        &[(component, purl)],
        &[("CVE-2024-90003", "known_affected", &[0])],
    ))
    .await?;

    // And an SBOM containing the upstream package
    let sbom_id = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "sbom-all-affected",
            "00000000-0000-0000-0000-200000000001",
            &[("badlib", "2.0.0", "pkg:maven/com.example/badlib@2.0.0")],
        ))
        .await?
        .id,
    )?;

    // When generating the report
    let app = caller_with(ctx, vendor_config(), PaginationCache::for_test()).await?;
    let report = recommend_report_req(&app, &[sbom_id]).await;

    tracing::info!("{report:#?}");

    // Then no packages appear — none are addressable
    let packages = report["packages"].as_array().unwrap();
    assert_eq!(
        packages.len(),
        0,
        "package with zero addressed CVEs should be excluded"
    );

    // And counts reflect no addressable packages
    assert_eq!(report["impact_summary"]["addressable_packages"], 0);
    assert_eq!(report["sboms"][0]["addressable_packages"], 0);
    assert_eq!(report["sboms"][0]["vulnerability_count"], 0);

    Ok(())
}

/// Verifies that importing a Red Hat Lightwell OSV advisory does not change another vendor's
/// recommendation assessment for the same upstream CVE and package (non-Lightwell builds).
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn lightwell_preserves_redhat_recommendations(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    // Given a Red Hat `fixed` assessment for the winner, an SBOM with the upstream build,
    // and the recommendations before any Lightwell import
    let input = "pkg:maven/io.netty/netty-codec-dns@4.1.132.Final";
    let winner = "pkg:maven/io.netty/netty-codec-dns@4.1.132.Final-redhat-00001";
    let cve = "CVE-2026-42579";
    ctx.ingest_json(minimal_csaf_vex(
        "REVIEW-LIGHTWELL-RECOMMEND-001",
        "Red Hat Review Product",
        &[("netty-codec-dns-redhat", winner)],
        &[(cve, "fixed", &[0])],
    ))
    .await?;
    let sbom_id = Uuid::parse_str(
        &ctx.ingest_json(minimal_cdx(
            "review-lightwell-upstream",
            "00000000-0000-0000-0000-000000284600",
            &[("netty-codec-dns", "4.1.132.Final", input)],
        ))
        .await?
        .id,
    )?;
    let app = caller_with(
        ctx,
        Config {
            recommend_patterns: vec![Regex::new(r"^(.+)[.-]redhat-[0-9]+$")?],
            ..Default::default()
        },
        PaginationCache::for_test(),
    )
    .await?;
    let before = recommend(&app, &[input]).await;
    let before_report = recommend_report_req(&app, &[sbom_id]).await;
    // Look the CVE up by ID: the order of `vulnerabilities` is not part of the contract.
    let cve_status = |response: &Value| {
        response["recommendations"][input][0]["vulnerabilities"]
            .as_array()
            .and_then(|vulns| vulns.iter().find(|vuln| vuln["id"] == cve))
            .map(|vuln| vuln["status"].clone())
    };
    assert_eq!(before["recommendations"][input][0]["package"], winner);
    assert_eq!(cve_status(&before), Some(Value::from("Fixed")));
    assert_eq!(before_report["packages"].as_array().unwrap().len(), 1);

    // When the unmodified Lightwell advisory for the same CVE and package is imported
    ctx.ingest_document("osv/RHLW-2026-02416b185203289c.json")
        .await?;
    let after = recommend(&app, &[input]).await;
    let after_report = recommend_report_req(&app, &[sbom_id]).await;

    // Then the Red Hat recommendation and the report are unchanged
    assert_eq!(after["recommendations"][input][0]["package"], winner);
    assert_eq!(
        cve_status(&after),
        Some(Value::from("Fixed")),
        "Lightwell must not override another vendor's fixed assessment",
    );
    assert_eq!(after_report["packages"], before_report["packages"]);
    // Known gap, same as on main (#2833): the Lightwell range is stored on the base PURL, so
    // an additional `RHLW-…` finding is still listed for the non-Lightwell winner. Fixing this
    // needs vendor/repository-aware matching, tracked upstream in TC-7423.
    Ok(())
}

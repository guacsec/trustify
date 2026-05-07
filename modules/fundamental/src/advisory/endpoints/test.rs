use crate::{
    advisory::model::{AdvisoryDetails, AdvisorySummary},
    test::{caller, caller_with, label::Api},
};
use actix_http::StatusCode;
use actix_web::{body::MessageBody, test::TestRequest};
use hex::ToHex;
use jsonpath_rust::JsonPath;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;
use test_context::test_context;
use test_log::test;
use time::OffsetDateTime;
use trustify_common::{
    db::pagination_cache::PaginationCache, error::ErrorInformation, hashing::Digests,
    model::PaginatedResults,
};
use trustify_entity::{advisory_vulnerability_score, labels::Labels};
use trustify_module_ingestor::{
    graph::{advisory::AdvisoryInformation, cvss::ScoreCreator},
    model::IngestResult,
    service::Format,
};
use trustify_module_storage::service::{StorageBackend, StorageKey};
use trustify_test_context::{TrustifyContext, call::CallService, document_bytes};
use urlencoding::encode;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn all_advisories(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let advisory = ctx
        .graph
        .ingest_advisory(
            "RHSA-1",
            ("source", "http://redhat.com/"),
            &Digests::digest("RHSA-1"),
            AdvisoryInformation {
                id: "RHSA-1".to_string(),
                title: Some("RHSA-1".to_string()),
                version: None,
                issuer: None,
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            &ctx.db,
        )
        .await?;

    advisory
        .link_to_vulnerability("CVE-123", None, &ctx.db)
        .await?;

    // Use ScoreCreator to write to advisory_vulnerability_score table
    let mut score_creator = ScoreCreator::new(advisory.advisory.id);
    score_creator.add(trustify_module_ingestor::graph::cvss::ScoreInformation {
        vulnerability_id: "CVE-123".to_string(),
        r#type: advisory_vulnerability_score::ScoreType::V3_0,
        vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N".to_string(),
        score: 0.0,
        severity: advisory_vulnerability_score::Severity::None,
    });
    score_creator.create(&ctx.db).await?;

    ctx.graph
        .ingest_advisory(
            "RHSA-2",
            ("source", "http://redhat.com/"),
            &Digests::digest("RHSA-2"),
            AdvisoryInformation {
                id: "RHSA-2".to_string(),
                title: Some("RHSA-2".to_string()),
                version: None,
                issuer: None,
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            &ctx.db,
        )
        .await?;

    let uri = "/api/v3/advisory?total=true";

    let request = TestRequest::get().uri(uri).to_request();

    let response: Value = app.call_and_read_body_json(request).await;

    assert_eq!(2, response["total"]);

    let items = response["items"].as_array().unwrap();

    // RHSA-1: has one vulnerability with a score.
    let rhsa_1 = items
        .iter()
        .find(|e| e["identifier"] == "RHSA-1")
        .expect("RHSA-1 must be in the list");

    assert_eq!(rhsa_1["title"], "RHSA-1");
    assert_eq!(rhsa_1["vulnerabilities"].as_array().unwrap().len(), 1);

    let cve_123 = &rhsa_1["vulnerabilities"][0];
    assert_eq!(cve_123["identifier"], "CVE-123");
    // base_score is null — the vulnerability was not ingested with one.
    assert_eq!(cve_123["base_score"], Value::Null);
    // Structured scores must carry all four fields including the vector.
    assert_eq!(
        cve_123["scores"],
        json!([{"type": "3.0", "value": 0.0, "severity": "none",
                "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}])
    );
    // Old per-vulnerability scalar fields must not appear.
    assert_eq!(cve_123["score"], Value::Null);
    assert_eq!(cve_123["severity"], Value::Null);
    // Old advisory-level average fields must not appear.
    assert_eq!(rhsa_1["average_score"], Value::Null);
    assert_eq!(rhsa_1["average_severity"], Value::Null);

    // RHSA-2: no vulnerabilities linked.
    let rhsa_2 = items
        .iter()
        .find(|e| e["identifier"] == "RHSA-2")
        .expect("RHSA-2 must be in the list");

    assert_eq!(rhsa_2["title"], "RHSA-2");
    assert_eq!(rhsa_2["vulnerabilities"].as_array().unwrap().len(), 0);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn one_advisory(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let advisory1 = ctx
        .graph
        .ingest_advisory(
            "RHSA-1",
            ("source", "http://redhat.com/"),
            &Digests::digest("RHSA-1"),
            AdvisoryInformation {
                id: "RHSA-1".to_string(),
                title: Some("RHSA-1".to_string()),
                version: None,
                issuer: Some("Red Hat Product Security".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            &ctx.db,
        )
        .await?;

    let advisory2 = ctx
        .graph
        .ingest_advisory(
            "RHSA-2",
            ("source", "http://redhat.com/"),
            &Digests::digest("RHSA-2"),
            AdvisoryInformation {
                id: "RHSA-2".to_string(),
                title: Some("RHSA-2".to_string()),
                version: None,
                issuer: Some("Red Hat Product Security".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            &ctx.db,
        )
        .await?;

    advisory2
        .link_to_vulnerability("CVE-123", None, &ctx.db)
        .await?;

    // Use ScoreCreator to write to advisory_vulnerability_score table
    let mut score_creator = ScoreCreator::new(advisory2.advisory.id);
    score_creator.add(trustify_module_ingestor::graph::cvss::ScoreInformation {
        vulnerability_id: "CVE-123".to_string(),
        r#type: advisory_vulnerability_score::ScoreType::V3_0,
        vector: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N".to_string(),
        score: 6.8,
        severity: advisory_vulnerability_score::Severity::Medium,
    });
    score_creator.create(&ctx.db).await?;

    let uri = format!("/api/v3/advisory/urn:uuid:{}", advisory2.advisory.id);

    let request = TestRequest::get().uri(&uri).to_request();

    let response: Value = app.call_and_read_body_json(request).await;

    assert_eq!(
        response.clone().query("$.issuer.name")?,
        [&json!("Red Hat Product Security")]
    );

    let scores = response.query("$.vulnerabilities[*].scores[*]")?;

    log::debug!("{scores:#?}");

    assert_eq!(
        scores,
        [
            &json!({"type": "3.0", "value": 6.8, "severity": "medium", "vector": "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N"})
        ]
    );

    // cvss3_scores must not appear — it was removed.
    let old = response.query("$.vulnerabilities[*].cvss3_scores")?;
    assert!(old.is_empty(), "cvss3_scores must not be present");
    // Old per-vulnerability scalar fields must not appear.
    let old = response.query("$.vulnerabilities[*].score")?;
    assert!(old.is_empty(), "score must not be present");
    let old = response.query("$.vulnerabilities[*].severity")?;
    assert!(old.is_empty(), "severity must not be present");
    // Old advisory-level aggregate fields must not appear.
    assert_eq!(response["average_score"], Value::Null);
    assert_eq!(response["average_severity"], Value::Null);

    let uri = format!("/api/v3/advisory/urn:uuid:{}", advisory1.advisory.id);

    let request = TestRequest::get().uri(&uri).to_request();

    let response: Value = app.call_and_read_body_json(request).await;

    let vulns = response.query("$.vulnerabilities")?;

    assert_eq!(vulns, [&json!([])]);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn one_advisory_by_uuid(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.graph
        .ingest_advisory(
            "RHSA-1",
            ("source", "http://redhat.com/"),
            &Digests::digest("RHSA-1"),
            AdvisoryInformation {
                id: "RHSA-1".to_string(),
                title: Some("RHSA-1".to_string()),
                version: None,
                issuer: Some("Red Hat Product Security".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            &ctx.db,
        )
        .await?;

    let advisory = ctx
        .graph
        .ingest_advisory(
            "RHSA-2",
            ("source", "http://redhat.com/"),
            &Digests::digest("RHSA-1"),
            AdvisoryInformation {
                id: "RHSA-2".to_string(),
                title: Some("RHSA-2".to_string()),
                version: None,
                issuer: Some("Red Hat Product Security".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            &ctx.db,
        )
        .await?;

    let uuid = advisory.advisory.id;

    advisory
        .link_to_vulnerability("CVE-123", None, &ctx.db)
        .await?;

    // Use ScoreCreator to write to advisory_vulnerability_score table
    let mut score_creator = ScoreCreator::new(advisory.advisory.id);
    score_creator.add(trustify_module_ingestor::graph::cvss::ScoreInformation {
        vulnerability_id: "CVE-123".to_string(),
        r#type: advisory_vulnerability_score::ScoreType::V3_0,
        vector: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N".to_string(),
        score: 6.8,
        severity: advisory_vulnerability_score::Severity::Medium,
    });
    score_creator.create(&ctx.db).await?;

    let uri = format!("/api/v3/advisory/{}", uuid.urn());

    let request = TestRequest::get().uri(&uri).to_request();

    let response: Value = app.call_and_read_body_json(request).await;

    log::debug!("{response:#?}");

    assert_eq!(
        response.clone().query("$.issuer.name")?,
        [&json!("Red Hat Product Security")]
    );

    let scores = response.query("$.vulnerabilities[*].scores[*]")?;

    log::debug!("{scores:#?}");

    assert_eq!(
        scores,
        [
            &json!({"type": "3.0", "value": 6.8, "severity": "medium", "vector": "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N"})
        ]
    );

    // cvss3_scores must not appear — it was removed.
    let old = response.query("$.vulnerabilities[*].cvss3_scores")?;
    assert!(old.is_empty(), "cvss3_scores must not be present");
    // Old per-vulnerability scalar fields must not appear.
    let old = response.query("$.vulnerabilities[*].score")?;
    assert!(old.is_empty(), "score must not be present");
    let old = response.query("$.vulnerabilities[*].severity")?;
    assert!(old.is_empty(), "severity must not be present");
    // Old advisory-level aggregate fields must not appear.
    assert_eq!(response["average_score"], Value::Null);
    assert_eq!(response["average_severity"], Value::Null);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn search_advisories(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    async fn query(app: &impl CallService, q: &str) -> PaginatedResults<AdvisorySummary> {
        let uri = format!(
            "/api/v3/advisory?total=true&q={}&sort={}",
            urlencoding::encode(q),
            urlencoding::encode("ingested:desc")
        );
        let req = TestRequest::get().uri(&uri).to_request();
        app.call_and_read_body_json(req).await
    }
    let app = caller(ctx).await?;

    // No results before ingestion
    let result = query(&app, "").await;
    assert_eq!(result.total, Some(0));

    // ingest some advisories
    ctx.ingest_documents(["mitre/CVE-2024-27088.json", "mitre/CVE-2024-28111.json"])
        .await?;

    let result = query(&app, "").await;
    assert_eq!(result.total, Some(2));
    assert_eq!(result.items[0].head.identifier, "CVE-2024-28111");
    let result = query(&app, "ingested>last week").await;
    assert_eq!(result.total, Some(2));
    assert_eq!(result.items[0].head.identifier, "CVE-2024-28111");
    let result = query(&app, "csv").await;
    assert_eq!(result.total, Some(1));
    assert_eq!(result.items[0].head.identifier, "CVE-2024-28111");
    let result = query(&app, "function#copy").await;
    assert_eq!(result.total, Some(1));
    assert_eq!(result.items[0].head.identifier, "CVE-2024-27088");
    let result = query(&app, "tostringtokens").await;
    assert_eq!(result.total, Some(1));
    assert_eq!(result.items[0].head.identifier, "CVE-2024-27088");
    let result = query(&app, "es5-ext").await;
    assert_eq!(result.items[0].head.identifier, "CVE-2024-27088");
    assert_eq!(result.total, Some(1));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn rejected_cve(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let query = async |expected_count, q| {
        let app = caller(ctx).await.unwrap();
        let uri = format!("/api/v3/advisory?total=true&q={}", urlencoding::encode(q));
        let req = TestRequest::get().uri(&uri).to_request();
        let response: Value = app.call_and_read_body_json(req).await;
        tracing::debug!(test = "", "{response:#?}");
        assert_eq!(expected_count, response["total"], "for {q}");
    };

    // ingest 2 CVE's, 1 rejected
    ctx.ingest_documents(["cve/CVE-2024-25704.json", "cve/CVE-2024-29025.json"])
        .await?;

    query(2, "labels:type=cve").await;
    query(1, "withdrawn=\x00&identifier=CVE-2024-29025").await;
    query(1, "withdrawn!=\x00&identifier=CVE-2024-25704").await;
    query(1, "withdrawn=2024-04-25T18:21:10.150Z").await;
    query(1, "withdrawn<2025-01-01").await;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_default_csaf_format(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let payload = document_bytes("csaf/cve-2023-33201.json").await?;

    let uri = "/api/v3/advisory";
    let request = TestRequest::post()
        .uri(uri)
        .set_payload(payload)
        .to_request();

    let result: IngestResult = app.call_and_read_body_json(request).await;
    log::debug!("{result:?}");

    assert_eq!(
        result.document_id,
        Some("https://www.redhat.com/#CVE-2023-33201".to_string())
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_default_csaf_format_multiple(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let files = vec![
        "csaf/cve-2023-0044.json",
        "csaf/rhsa-2023_5835.json",
        "csaf/rhsa-2024_2776.json",
        "csaf/CVE-2023-20862.json",
        "csaf/rhsa-2024_2049.json",
        "csaf/cve-2023-33201.json",
        "csaf/rhsa-2024_2784.json",
        "csaf/rhsa-2024_2054.json",
        "csaf/rhsa-2024_3351.json",
        "csaf/CVE-2024-5154.json",
        "csaf/rhsa-2024_2071.json",
        "csaf/rhsa-2024_3666.json",
        "csaf/RHBA-2024_1440.json",
        "csaf/rhsa-2024-2705.json",
    ];

    let uri = "/api/v3/advisory";

    for file in files {
        let payload = document_bytes(file).await?;

        let request = TestRequest::post()
            .uri(uri)
            .set_payload(payload)
            .to_request();

        let result: IngestResult = app.call_and_read_body_json(request).await;
        log::debug!("{result:?}");
    }

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_osv_format(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let payload = document_bytes("osv/RUSTSEC-2021-0079.json").await?;

    let uri = "/api/v3/advisory";
    let request = TestRequest::post()
        .uri(uri)
        .set_payload(payload)
        .to_request();

    let result: IngestResult = app.call_and_read_body_json(request).await;
    assert_eq!(result.document_id, Some("RUSTSEC-2021-0079".to_string()));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_cve_format(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let payload = document_bytes("mitre/CVE-2024-27088.json").await?;

    let uri = "/api/v3/advisory";
    let request = TestRequest::post()
        .uri(uri)
        .set_payload(payload)
        .to_request();

    let result: IngestResult = app.call_and_read_body_json(request).await;
    assert_eq!(result.document_id, Some("CVE-2024-27088".to_string()));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_unknown_format(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let uri = "/api/v3/advisory";
    let request = TestRequest::post().uri(uri).to_request();

    let response = app.call_service(request).await;
    log::debug!("response: {response:?}");

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Wrong HTTP response status"
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_with_labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let payload = document_bytes("csaf/cve-2023-33201.json").await?;

    let uri = "/api/v3/advisory?labels.foo=bar&labels.bar=baz";
    let request = TestRequest::post()
        .uri(uri)
        .set_payload(payload)
        .to_request();

    let result: IngestResult = app.call_and_read_body_json(request).await;
    log::debug!("{result:?}");
    assert_eq!(
        result.document_id,
        Some("https://www.redhat.com/#CVE-2023-33201".to_string())
    );

    // now check the labels

    let request = TestRequest::get()
        .uri(&format!("/api/v3/advisory/urn:uuid:{}", result.id))
        .to_request();
    let result: AdvisoryDetails = app.call_and_read_body_json(request).await;

    assert_eq!(
        result.head.labels,
        Labels::new()
            .add("foo", "bar")
            .add("bar", "baz")
            .add("type", "csaf")
    );

    // done

    Ok(())
}

const DOC: &str = "csaf/cve-2023-33201.json";

/// Test downloading a document by its SHA256 digest
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn download_advisory(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let digest: String = Sha256::digest(document_bytes(DOC).await?).encode_hex();
    let app = caller(ctx).await?;
    ctx.ingest_document(DOC).await?;
    let uri = format!("/api/v3/advisory/sha256:{digest}/download");
    let request = TestRequest::get().uri(&uri).to_request();
    let doc: Value = app.call_and_read_body_json(request).await;
    assert_eq!(doc["document"]["tracking"]["id"], "CVE-2023-33201");

    Ok(())
}

/// Test downloading a document by its upload ID
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn download_advisory_by_id(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let result = ctx.ingest_document(DOC).await?;
    let uri = format!("/api/v3/advisory/urn:uuid:{}/download", result.id);
    let request = TestRequest::get().uri(&uri).to_request();
    let doc: Value = app.call_and_read_body_json(request).await;
    assert_eq!(doc["document"]["tracking"]["id"], "CVE-2023-33201");

    Ok(())
}

/// Test updating labels
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn update_labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    crate::test::label::update_labels(ctx, Api::Advisory, DOC, "csaf").await
}

/// Test updating labels, for a document that does not exist
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn update_labels_not_found(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    crate::test::label::update_labels_not_found(ctx, Api::Advisory, DOC).await
}

/// Test deleing an advisory
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn delete_advisory(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let storage = &ctx.storage;
    let doc = ctx.ingest_document(DOC).await?;

    let advisory_list: PaginatedResults<AdvisorySummary> = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/advisory?total=true")
                .to_request(),
        )
        .await;
    assert_eq!(advisory_list.total, Some(1));
    let key: StorageKey = advisory_list.items[0].source_document.clone().try_into()?;
    assert!(storage.retrieve(key.clone()).await?.is_some());

    // first delete should succeed
    let response = app
        .call_service(
            TestRequest::delete()
                .uri(&format!("/api/v3/advisory/urn:uuid:{}", doc.id))
                .to_request(),
        )
        .await;

    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);
    assert!(storage.retrieve(key).await?.is_none());

    // check that the document is gone
    let advisory_list: PaginatedResults<AdvisorySummary> = app
        .call_and_read_body_json(
            TestRequest::get()
                .uri("/api/v3/advisory?total=true")
                .to_request(),
        )
        .await;
    assert_eq!(advisory_list.total, Some(0));

    // second delete should fail
    let response = app
        .call_service(
            TestRequest::delete()
                .uri(&format!("/api/v3/advisory/urn:uuid:{}", doc.id))
                .to_request(),
        )
        .await;

    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn query_advisories_by_label(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let query = async |q| {
        let app = caller(ctx).await.unwrap();
        let uri = format!("/api/v3/advisory?total=true&q={}", encode(q));
        let req = TestRequest::get().uri(&uri).to_request();
        let response: Value = app.call_and_read_body_json(req).await;
        assert_eq!(1, response["total"], "for {q}");
    };
    ctx.ingest_document_as(
        DOC,
        Format::CSAF,
        [
            ("type", "csaf"),
            ("source", "test"),
            ("importer", "none"),
            ("file", "cve-2023-33201.json"),
            ("datasetFile", "none"),
            ("foo", "bar"),
            ("pfx/app.first-name", "carlos"),
        ],
    )
    .await?;

    query("labels:type!=spdx").await;
    query("labels:type!~zap").await;
    query("labels:type~af").await;
    query("labels:type=csaf").await;
    query("labels:type=csaf&labels:source=test").await;
    query("labels:type=csaf&labels:source=test&labels:importer=none").await;
    query(
        "labels:type=csaf&labels:source=test&labels:importer=none&labels:file=cve-2023-33201.json",
    )
    .await;
    query("labels:type=csaf&labels:source=test&labels:importer=none&labels:file=cve-2023-33201.json&labels:datasetFile=none").await;
    query("labels:file>aaah.json").await;
    query("labels:datasetFile<zilch").await;
    query("label:foo=bar").await;
    query("label:type=csaf").await;
    query("label:importer=some|none").await;
    query("label:type!=spdx").await;
    query("labels:type~af&labels:foo>aah").await;
    query("labels:importer~one&label:file~33201").await;
    query("labels:pfx/app.first-name=carlos").await;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn advisory_with_null_severity(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await.unwrap();
    let id = ctx
        .ingest_document("cve/CVE-1999-0001.json")
        .await?
        .id
        .to_string();
    let uri = format!("/api/v3/advisory/urn:uuid:{id}");
    let req = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(req).await;
    tracing::debug!(test = "", "{response:#?}");

    assert_eq!(Value::Null, response["average_severity"]);
    assert_eq!(Value::Null, response["average_score"]);
    assert_eq!(Value::Null, response["vulnerabilities"][0]["severity"]);
    assert_eq!(Value::Null, response["vulnerabilities"][0]["score"]);

    Ok(())
}

async fn test_label(
    ctx: &TrustifyContext,
    query: &str,
    limit: impl Into<Option<u64>>,
    result: Value,
) -> anyhow::Result<()> {
    let app = caller(ctx).await.unwrap();

    let _id = ctx
        .ingest_document("cve/CVE-1999-0001.json")
        .await?
        .id
        .to_string();

    let mut uri = format!("/api/v3/advisory-labels?filter_text={}", encode(query));

    if let Some(limit) = limit.into() {
        uri.push_str(&format!("&limit={limit}"));
    }

    let req = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(req).await;
    tracing::debug!(test = "", "{response:#?}");

    assert_eq!(response, result,);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn all_labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    test_label(
        ctx,
        "",
        None,
        json!([
            { "key": "source", "value": "TrustifyContext"},
            { "key": "type", "value": "cve"}
        ]),
    )
    .await?;

    test_label(
        ctx,
        "v",
        None,
        json!([
            { "key": "type", "value": "cve"}
        ]),
    )
    .await?;

    test_label(
        ctx,
        "yp",
        None,
        json!([
            { "key": "type", "value": "cve"}
        ]),
    )
    .await?;

    test_label(ctx, "%", None, json!([])).await?;

    test_label(
        ctx,
        "",
        1u64,
        json!([
            { "key": "source", "value": "TrustifyContext"},
        ]),
    )
    .await?;

    Ok(())
}

/// Verify that exceeding the configured max limit returns 400 with the correct header and body.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_advisories_limit_exceeded(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let cache = PaginationCache::new(Duration::ZERO, 10);
    let app = caller_with(ctx, Default::default(), cache).await?;

    let request = TestRequest::get()
        .uri("/api/v3/advisory?limit=50")
        .to_request();
    let response = app.call_service(request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let header = response
        .headers()
        .get("X-Pagination-Max-Limit")
        .expect("missing X-Pagination-Max-Limit header");
    assert_eq!(header.to_str().unwrap(), "10");

    let body = response.into_body().try_into_bytes().unwrap();
    let info: ErrorInformation =
        serde_json::from_slice(&body).expect("response body should be valid JSON");
    assert_eq!(info.error, "LimitExceeded");
    assert!(info.message.contains("10"));

    Ok(())
}

use std::str::FromStr;

use actix_http::Request;
use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::test::TestRequest;
use actix_web::{App, Error};
use jsonpath_rust::JsonPathQuery;
use serde_json::{json, Value};
use test_context::test_context;
use test_log::test;
use time::OffsetDateTime;

use trustify_common::db::test::TrustifyContext;
use trustify_common::model::PaginatedResults;
use trustify_common::purl::Purl;
use trustify_cvss::cvss3::{
    AttackComplexity, AttackVector, Availability, Confidentiality, Cvss3Base, Integrity,
    PrivilegesRequired, Scope, UserInteraction,
};
use trustify_model::advisory::AdvisorySummary;
use trustify_module_ingestor::graph::Graph;
use trustify_module_ingestor::{graph::advisory::AdvisoryInformation, service::IngestorService};

async fn query<S, B>(app: &S, q: &str) -> PaginatedResults<AdvisorySummary>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody,
{
    let uri = format!("/api/v1/advisory?q={}", urlencoding::encode(q));
    let req = TestRequest::get().uri(&uri).to_request();
    actix_web::test::call_and_read_body_json(app, req).await
}

async fn ingest(service: &IngestorService, data: &[u8]) -> String {
    use tokio_util::io::ReaderStream;
    use trustify_module_ingestor::service::Format;
    service
        .ingest(
            "unit-test",
            Some("Capt Pickles Industrial Conglomerate".to_string()),
            Format::from_bytes(data).unwrap(),
            ReaderStream::new(data),
        )
        .await
        .unwrap()
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn all_advisories(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Graph::new(db.clone());

    let app = actix_web::test::init_service(
        App::new().configure(|config| crate::endpoints::configure(config, db)),
    )
    .await;

    let advisory = graph
        .ingest_advisory(
            "RHSA-1",
            "http://redhat.com/",
            "8675309",
            AdvisoryInformation {
                title: Some("RHSA-1".to_string()),
                issuer: None,
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let advisory_vuln = advisory.link_to_vulnerability("CVE-123", ()).await?;
    advisory_vuln
        .ingest_cvss3_score(
            Cvss3Base {
                minor_version: 0,
                av: AttackVector::Network,
                ac: AttackComplexity::Low,
                pr: PrivilegesRequired::None,
                ui: UserInteraction::None,
                s: Scope::Unchanged,
                c: Confidentiality::None,
                i: Integrity::None,
                a: Availability::None,
            },
            (),
        )
        .await?;

    graph
        .ingest_advisory(
            "RHSA-2",
            "http://redhat.com/",
            "8675319",
            AdvisoryInformation {
                title: Some("RHSA-2".to_string()),
                issuer: None,
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let uri = "/api/v1/advisory";

    let request = TestRequest::get().uri(uri).to_request();

    let response: PaginatedResults<AdvisorySummary> =
        actix_web::test::call_and_read_body_json(&app, request).await;

    assert_eq!(2, response.items.len());

    let rhsa_1 = &response
        .items
        .iter()
        .find(|e| e.head.identifier == "RHSA-1");

    assert!(rhsa_1.is_some());

    let rhsa_1 = rhsa_1.unwrap();

    assert!(rhsa_1
        .vulnerabilities
        .iter()
        .any(|e| e.head.identifier == "CVE-123"));

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn one_advisory(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Graph::new(db.clone());

    let app = actix_web::test::init_service(
        App::new().configure(|config| crate::endpoints::configure(config, db)),
    )
    .await;

    graph
        .ingest_advisory(
            "RHSA-1",
            "http://redhat.com/",
            "8675309",
            AdvisoryInformation {
                title: Some("RHSA-1".to_string()),
                issuer: Some("Red Hat Product Security".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let advisory = graph
        .ingest_advisory(
            "RHSA-2",
            "http://redhat.com/",
            "8675319",
            AdvisoryInformation {
                title: Some("RHSA-2".to_string()),
                issuer: Some("Red Hat Product Security".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let advisory_vuln = advisory.link_to_vulnerability("CVE-123", ()).await?;
    advisory_vuln
        .ingest_cvss3_score(
            Cvss3Base {
                minor_version: 0,
                av: AttackVector::Network,
                ac: AttackComplexity::Low,
                pr: PrivilegesRequired::High,
                ui: UserInteraction::None,
                s: Scope::Changed,
                c: Confidentiality::High,
                i: Integrity::None,
                a: Availability::None,
            },
            (),
        )
        .await?;

    advisory_vuln
        .ingest_not_affected_package_version(&Purl::from_str("pkg://maven/log4j/log4j@1.2.3")?, ())
        .await?;

    let uri = "/api/v1/advisory/8675319";

    let request = TestRequest::get().uri(uri).to_request();

    let response: Value = actix_web::test::call_and_read_body_json(&app, request).await;

    log::debug!("{:#?}", response);

    assert_eq!(
        response.clone().path("$.issuer").unwrap(),
        json!(["Red Hat Product Security"])
    );

    let cvss3_scores = response
        .path("$.vulnerabilities[*].cvss3_scores.*")
        .unwrap();

    log::debug!("{:#?}", cvss3_scores);

    assert_eq!(
        cvss3_scores,
        json!(["CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N"])
    );

    let uri = "/api/v1/advisory/8675309";

    let request = TestRequest::get().uri(uri).to_request();

    let response: Value = actix_web::test::call_and_read_body_json(&app, request).await;

    let vulns = response.path("$.vulnerabilities").unwrap();

    assert_eq!(vulns, json!([[]]));

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn search_advisories(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    use crate::endpoints::configure;
    use actix_web::test::init_service;
    use trustify_module_storage::service::fs::FileSystemBackend;

    let db = ctx.db;
    let graph = Graph::new(db.clone());
    let (storage, _) = FileSystemBackend::for_test().await?;
    let ingestor = IngestorService::new(graph, storage);
    let app = init_service(App::new().configure(|config| configure(config, db))).await;
    let mut _response: PaginatedResults<AdvisorySummary>;

    // No results before ingestion
    let result = query(&app, "").await;
    assert_eq!(result.total, 0);

    // ingest some advisories
    let data = include_bytes!("../../../../etc/test-data/mitre/CVE-2024-27088.json");
    let _id = ingest(&ingestor, data).await;
    let data = include_bytes!("../../../../etc/test-data/mitre/CVE-2024-28111.json");
    let _id = ingest(&ingestor, data).await;

    let result = query(&app, "").await;
    assert_eq!(result.total, 2);
    let result = query(&app, "csv").await;
    assert_eq!(result.total, 1);
    assert_eq!(result.items[0].head.identifier, "CVE-2024-28111");
    let result = query(&app, "function#copy").await;
    assert_eq!(result.total, 1);
    assert_eq!(result.items[0].head.identifier, "CVE-2024-27088");
    let result = query(&app, "tostringtokens").await;
    assert_eq!(result.total, 1);
    assert_eq!(result.items[0].head.identifier, "CVE-2024-27088");
    let result = query(&app, "es5-ext").await;
    assert_eq!(result.items[0].head.identifier, "CVE-2024-27088");
    assert_eq!(result.total, 1);

    Ok(())
}

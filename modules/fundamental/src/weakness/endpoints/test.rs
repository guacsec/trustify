use crate::test::caller;
use crate::weakness::model::{WeaknessDetails, WeaknessSummary};
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use test_context::test_context;
use test_log::test;
use trustify_common::model::PaginatedResults;
use trustify_test_context::{TrustifyContext, call::CallService, document_read};
use zip::ZipArchive;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_weaknesses(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let zip = document_read("cwec_latest.xml.zip")?;

    let mut archive = ZipArchive::new(zip)?;

    let entry = archive.by_index(0)?;

    ctx.ingest_read(entry).await?;

    let app = caller(ctx).await?;

    let uri = "/api/v3/weakness?total=true";

    let request = TestRequest::get().uri(uri).to_request();

    let response: PaginatedResults<WeaknessSummary> = app.call_and_read_body_json(request).await;

    assert!(response.total.expect("total should be present") > 900);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn query_weaknesses(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let zip = document_read("cwec_latest.xml.zip")?;

    let mut archive = ZipArchive::new(zip)?;

    let entry = archive.by_index(0)?;

    ctx.ingest_read(entry).await?;

    let app = caller(ctx).await?;

    let uri = "/api/v3/weakness?q=struts&total=true";

    let request = TestRequest::get().uri(uri).to_request();

    let response: PaginatedResults<WeaknessSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(response.total, Some(4));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_weakness(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let zip = document_read("cwec_latest.xml.zip")?;

    let mut archive = ZipArchive::new(zip)?;

    let entry = archive.by_index(0)?;

    ctx.ingest_read(entry).await?;

    let app = caller(ctx).await?;

    let uri = "/api/v3/weakness/CWE-1004";

    let request = TestRequest::get().uri(uri).to_request();

    let response: WeaknessDetails = app.call_and_read_body_json(request).await;

    assert_eq!(response.head.id, "CWE-1004");
    assert!(response.head.description.is_some());

    let desc = response.head.description.unwrap();
    assert!(desc.starts_with("The product uses a cookie to store"));

    assert!(response.extended_description.is_some());
    let ext_desc = response.extended_description.unwrap();
    assert!(ext_desc.starts_with("The HttpOnly flag directs compatible browsers"));

    assert!(response.child_of.is_some());

    let child_of = response.child_of.unwrap();

    assert_eq!(1, child_of.len());
    assert!(child_of.contains(&"CWE-732".to_string()));

    let uri = "/api/v3/weakness/CWE-FOO";
    let request = TestRequest::get().uri(uri).to_request();
    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

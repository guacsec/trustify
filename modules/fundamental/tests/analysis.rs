//! Testing full circle: ingest, analysis

use actix_http::{Request, StatusCode};
use actix_web::test::TestRequest;
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_module_fundamental::{Config, configure};
use trustify_test_context::{document_bytes_raw, subset::ContainsSubset};

include!("../src/test/common.rs");

async fn assert_status(app: &impl CallService, sboms: usize, graphs: usize) {
    let request: Request = TestRequest::get()
        .uri("/api/v2/analysis/status")
        .to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    assert_eq!(response["sbom_count"], sboms);
    assert_eq!(response["graph_count"], graphs);
}

/// this should ingest an SBOM, not eagerly load, but then lazy load it into the graph.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_lazy_load(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller_with(ctx, Config::default(), PaginationCache::for_test()).await?;

    let request = TestRequest::post()
        .uri("/api/v2/sbom")
        .set_payload(document_bytes_raw("spdx/simple.json").await?)
        .to_request();

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // after ingestion with the default flags, we should have one SBOM, but not loaded it

    assert_status(&app, 1, 0).await;

    // now perform a query

    let uri = format!(
        "/api/v2/analysis/component/{}?ancestors=10",
        urlencoding::encode("pkg:rpm/redhat/A@0.0.0?arch=src")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::debug!("{}", serde_json::to_string_pretty(&response)?);

    assert!(
        response.contains_subset(json!({
            "items": [ {
                "name": "A",
                "version": "1",
                "ancestors": [ {
                    "node_id": "SPDXRef-DOCUMENT",
                    "relationship": "describes",
                    "name": "simple",
                    "version": "",
                }]
            }]
        })),
        "should be contained in: {response}"
    );

    // after the query, we should have the SBOM loaded in the graph as well

    assert_status(&app, 1, 1).await;

    // done

    Ok(())
}

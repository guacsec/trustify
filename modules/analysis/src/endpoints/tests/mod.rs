mod cyclonedx;
mod dot;
mod latest_filters;
pub mod req;
mod rh_variant;
mod spdx;

use crate::test::caller;
use actix_http::Request;
use actix_web::test::TestRequest;
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyContext, call::CallService, subset::ContainsSubset};
use urlencoding::encode;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_simple_retrieve_analysis_endpoint(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    //should match multiple components
    let uri = "/api/v2/analysis/component?q=B&ancestors=10";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ "pkg:rpm/redhat/BB@0.0.0" ]
        }]
    })));
    assert_eq!(&response["total"], 2);

    //should match a single component
    let uri = "/api/v2/analysis/component?q=BB&ancestors=10";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ "pkg:rpm/redhat/BB@0.0.0" ],
            "ancestors": [{
                "purl": [ "pkg:rpm/redhat/AA@0.0.0?arch=src" ]
            }]
        }]
    })));
    assert_eq!(&response["total"], 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_simple_retrieve_by_name_analysis_endpoint(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let uri = "/api/v2/analysis/component/B?ancestors=10";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ "pkg:rpm/redhat/B@0.0.0" ],
            "ancestors": [{
                "purl": [ "pkg:rpm/redhat/A@0.0.0?arch=src" ]
            }]
        }]
    })));
    assert_eq!(&response["total"], 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_simple_retrieve_by_purl_analysis_endpoint(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let uri = format!(
        "/api/v2/analysis/component/{}?ancestors=10",
        urlencoding::encode("pkg:rpm/redhat/B@0.0.0")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ "pkg:rpm/redhat/B@0.0.0" ],
            "ancestors": [{
                "purl": [ "pkg:rpm/redhat/A@0.0.0?arch=src" ]
            }]
        }]
    })));
    assert_eq!(&response["total"], 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_quarkus_retrieve_analysis_endpoint(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let purl = "pkg:maven/net.spy/spymemcached@2.12.1?type=jar";
    let uri = "/api/v2/analysis/component?q=spymemcached&ancestors=10";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [
            {
                "purl": [ purl ],
                "document_id": "https://access.redhat.com/security/data/sbom/spdx/quarkus-bom-3.2.11.Final-redhat-00001",
                "ancestors": [{
                    "purl": [ "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=pom" ]
                }]
            },
            {
                "purl": [ purl ],
                "document_id": "https://access.redhat.com/security/data/sbom/spdx/quarkus-bom-3.2.12.Final-redhat-00002",
                "ancestors": [{
                    "purl": [ "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.12.Final-redhat-00002?repository_url=https://maven.repository.redhat.com/ga/&type=pom" ]
                }]
            }
        ]
    })));
    assert_eq!(&response["total"], 2);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_status_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    // prime the graph hashmap
    let uri = "/api/v2/analysis/component?q=BB";
    let load1 = TestRequest::get().uri(uri).to_request();
    let _response: Value = app.call_and_read_body_json(load1).await;

    let uri = "/api/v2/analysis/status";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    assert_eq!(response["sbom_count"], 1);
    assert_eq!(response["graph_count"], 1);

    // ingest duplicate sbom which has different date
    ctx.ingest_documents(["spdx/simple-dup.json"]).await?;

    let uri = "/api/v2/analysis/status";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    assert_eq!(response["sbom_count"], 2);
    assert_eq!(response["graph_count"], 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_simple_dep_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let uri = "/api/v2/analysis/component?q=A&ancestors=10&descendants=10";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    tracing::debug!(test = "", "{response:#?}");

    assert!(response.contains_subset(json!({
        "items": [
            {
                "purl": [ "pkg:rpm/redhat/A@0.0.0?arch=src" ],
                "descendants": [
                    {
                        "purl": [ "pkg:rpm/redhat/B@0.0.0" ]
                    },
                ]
            },
            {
                "purl": [ "pkg:rpm/redhat/AA@0.0.0?arch=src" ],
                "descendants": [
                    {
                        "purl": [ "pkg:rpm/redhat/BB@0.0.0" ],
                        "descendants": [
                            {
                                "purl": [ "pkg:rpm/redhat/DD@0.0.0" ],
                                "descendants": [{
                                    "name": "FF",
                                    "relationship": "contains",
                                    "purl": []
                                }]
                            },
                            {
                                "purl": [ "pkg:rpm/redhat/CC@0.0.0" ]
                            }
                        ]
                    }
                ]
            }
        ]
    })));

    assert_eq!(&response["total"], 2);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_simple_dep_by_name_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let uri = "/api/v2/analysis/component/A?descendants=10";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ "pkg:rpm/redhat/A@0.0.0?arch=src" ],
            "descendants": [
                {
                    "purl": [ "pkg:rpm/redhat/B@0.0.0" ]
                }
            ]
        }]
    })));
    assert_eq!(&response["total"], 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_simple_dep_by_purl_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let purl = "pkg:rpm/redhat/AA@0.0.0?arch=src";
    let uri = format!(
        "/api/v2/analysis/component/{}?descendants=10",
        urlencoding::encode(purl)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ purl ],
            "descendants": [{
                "purl": [ "pkg:rpm/redhat/BB@0.0.0" ]
            }]
        }]
    })));
    assert_eq!(&response["total"], 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_quarkus_dep_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let purl = "pkg:maven/net.spy/spymemcached@2.12.1?type=jar";
    let uri = "/api/v2/analysis/component?q=spymemcached&descendants=10";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [
            {
                "purl": [ purl ],
                "document_id": "https://access.redhat.com/security/data/sbom/spdx/quarkus-bom-3.2.11.Final-redhat-00001"
            },
            {
                "purl": [ purl ],
                "document_id": "https://access.redhat.com/security/data/sbom/spdx/quarkus-bom-3.2.12.Final-redhat-00002"
            }
        ]
    })));
    assert_eq!(&response["total"], 2);

    Ok(())
}

/// find a component by purl
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn quarkus_component_by_purl(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let purl = "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=pom";
    let uri = format!("/api/v2/analysis/component/{}", urlencoding::encode(purl));
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ purl ],
            "cpe": ["cpe:/a:redhat:quarkus:3.2:*:el8:*"]
        }]
    })));
    assert_eq!(&response["total"], 1);

    Ok(())
}

/// find a component by cpe
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn quarkus_component_by_cpe(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let cpe = "cpe:/a:redhat:quarkus:3.2:*:el8:*";
    let uri = format!(
        "/api/v2/analysis/component/{}",
        urlencoding::encode("cpe:/a:redhat:quarkus:3.2::el8")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [
            {
                "purl": [ "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=pom" ],
                "cpe": [ cpe ]
            },
            {
                "purl": [ "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.12.Final-redhat-00002?repository_url=https://maven.repository.redhat.com/ga/&type=pom" ],
                "cpe": [ cpe ]
            }
        ]
    })));
    assert_eq!(&response["total"], 2);

    Ok(())
}

async fn query(ctx: &TrustifyContext, query: &str) -> Value {
    let app = caller(ctx).await.unwrap();
    let uri = format!("/api/v2/analysis/component?q={}&limit=0", encode(query));
    let request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");
    response
}

/// find a component by query
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn find_component_by_query(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/quarkus-bom-3.2.11.Final-redhat-00001.json"])
        .await?;

    const PURL: &str = "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=pom";

    for each in [
        r"purl=pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?repository_url=https://maven.repository.redhat.com/ga/\&type=pom",
        "purl~pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001&purl:qualifiers:type=pom&purl:qualifiers:repository_url=https://maven.repository.redhat.com/ga/",
        "purl~pkg:maven/com.redhat.quarkus.platform/quarkus-bom@",
        "purl~pkg:maven/com.redhat.quarkus.platform/quarkus-bom",
        // "purl~pkg:maven/com.redhat.quarkus.platform/quarkus-bo", <-- not all partial purl's will match
        "purl:name=quarkus-bom",
        "cpe=cpe:/a:redhat:quarkus:3.2::el8",
        "cpe~cpe:/a:redhat:quarkus:3.2::el8",
        "cpe~cpe:/a:redhat:quarkus:3.2",
        "cpe~cpe:/a::quarkus",
        "purl~quarkus",                   // invalid PURL results in a full-text search
        "cpe~redhat",                     // invalid CPE results in a full-text search
        "purl~quarkus&cpe~redhat",        // essentially the same as `quarkus|redhat`
        "purl~quarkus&cpe~cpe:/a:redhat", // valid CPE, invalid PURL so full-text search
    ] {
        assert!(
            query(ctx, each).await.contains_subset(json!({
                "items": [{
                    "purl": [ PURL ],
                    "cpe": ["cpe:/a:redhat:quarkus:3.2:*:el8:*"]
                }]
            })),
            "test failed for '{each}'"
        );
    }

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn find_components_without_namespace(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/rhelai1_binary.json"]).await?;

    const PURL: &str = "pkg:nuget/NGX@31.0.15.5356";

    for each in [
        "purl~pkg:nuget/NGX",
        // "purl~pkg:nuget/NGX@",
        "purl=pkg:nuget/NGX@31.0.15.5356",
        // "pkg:nuget/NGX@31.0.15.5356",
    ] {
        assert!(
            query(ctx, each).await.contains_subset(json!({
                "items": [{
                    "purl": [ PURL ],
                }]
            })),
            "for {each}"
        );
    }

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_retrieve_query_params_endpoint(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    // filter on node_id
    let uri = "/api/v2/analysis/component?q=node_id%3DSPDXRef-A&descendants=10";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(response["items"][0]["name"], "A");
    assert_eq!(&response["total"], 1);

    // filter on node_id
    let uri = "/api/v2/analysis/component?q=node_id%3DSPDXRef-B&ascendants=10";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(response["items"][0]["name"], "B");
    assert_eq!(&response["total"], 1);

    // filter on node_id & name
    let uri = "/api/v2/analysis/component?q=node_id%3DSPDXRef-B%26name%3DB&ascendants=10";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(response["items"][0]["name"], "B");
    assert_eq!(&response["total"], 1);

    // filter on sbom_id (which has urn:uuid: prefix)
    let sbom_id = response["items"][0]["sbom_id"].as_str().unwrap();
    let uri = format!("/api/v2/analysis/component?q=sbom_id={sbom_id}&ascendants=10");
    let request: Request = TestRequest::get().uri(uri.clone().as_str()).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(&response["total"], 9);

    // negative test
    let uri = "/api/v2/analysis/component?q=sbom_id=urn:uuid:99999999-9999-9999-9999-999999999999&ascendants=10";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(&response["total"], 0);

    // negative test
    let uri = "/api/v2/analysis/component?q=node_id%3DSPDXRef-B%26name%3DA&ascendants=10";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    assert_eq!(&response["total"], 0);
    Ok(())
}

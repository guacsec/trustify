mod cyclonedx;
mod dot;
mod latest_filters;
pub mod req;
mod rh_variant;
mod spdx;

use crate::test::caller;
use actix_http::Request;
use actix_web::test::TestRequest;
use req::*;
use rstest::rstest;
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyContext, call::CallService, subset::ContainsSubset};

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_simple_retrieve_analysis_endpoint(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    //should match multiple components
    let response: Value = app
        .req(Req {
            what: What::Q("B"),
            ancestors: Some(10),
            ..Req::default()
        })
        .await?;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ "pkg:rpm/redhat/BB@0.0.0" ]
        }]
    })));
    assert_eq!(&response["total"], 2);

    //should match a single component
    let response: Value = app
        .req(Req {
            what: What::Q("BB"),
            ancestors: Some(10),
            ..Req::default()
        })
        .await?;
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

    let response: Value = app
        .req(Req {
            what: What::Id("B"),
            ancestors: Some(10),
            ..Req::default()
        })
        .await?;
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

    let response: Value = app
        .req(Req {
            what: What::Id("pkg:rpm/redhat/B@0.0.0"),
            ancestors: Some(10),
            ..Req::default()
        })
        .await?;
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
    let response: Value = app
        .req(Req {
            what: What::Q("spymemcached"),
            ancestors: Some(10),
            ..Req::default()
        })
        .await?;
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
    let _response: Value = app
        .req(Req {
            what: What::Q("BB"),
            ..Req::default()
        })
        .await?;

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

    let response: Value = app
        .req(Req {
            what: What::Q("A"),
            ancestors: Some(10),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;

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

    let response: Value = app
        .req(Req {
            what: What::Id("A"),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;
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
    let response: Value = app
        .req(Req {
            what: What::Id(purl),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;
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
    let response: Value = app
        .req(Req {
            what: What::Q("spymemcached"),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;
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
    let response: Value = app
        .req(Req {
            what: What::Id(purl),
            ..Req::default()
        })
        .await?;
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
    let response: Value = app
        .req(Req {
            what: What::Id("cpe:/a:redhat:quarkus:3.2::el8"),
            ..Req::default()
        })
        .await?;
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
    let response: Value = app
        .req(Req {
            what: What::Q(query),
            limit: Some(0),
            ..Req::default()
        })
        .await
        .unwrap();
    tracing::debug!(test = "", "{response:#?}");
    response
}

/// find a component by query
#[test_context(TrustifyContext)]
#[rstest]
#[case(r"purl=pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?repository_url=https://maven.repository.redhat.com/ga/\&type=pom")]
#[case(
    "purl~pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001&purl:qualifiers:type=pom&purl:qualifiers:repository_url=https://maven.repository.redhat.com/ga/"
)]
#[case("purl~pkg:maven/com.redhat.quarkus.platform/quarkus-bom@")]
#[case("purl~pkg:maven/com.redhat.quarkus.platform/quarkus-bom")]
// #[case("purl~pkg:maven/com.redhat.quarkus.platform/quarkus-bo")] // <-- not all partial purl's will match
#[case("purl:name=quarkus-bom")]
#[case("cpe=cpe:/a:redhat:quarkus:3.2::el8")]
#[case("cpe~cpe:/a:redhat:quarkus:3.2::el8")]
#[case("cpe~cpe:/a:redhat:quarkus:3.2")]
#[case("cpe~cpe:/a::quarkus")]
#[case("purl~quarkus")] // invalid PURL results in a full-text search
#[case("cpe~redhat")] // invalid CPE results in a full-text search
#[case("purl~quarkus&cpe~redhat")] // essentially the same as `quarkus|redhat`
#[case("purl~quarkus&cpe~cpe:/a:redhat")] // valid CPE, invalid PURL so full-text search
#[test_log::test(actix_web::test)]
async fn find_component_by_query(
    ctx: &TrustifyContext,
    #[case] query_str: &str,
) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/quarkus-bom-3.2.11.Final-redhat-00001.json"])
        .await?;

    const PURL: &str = "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=pom";

    assert!(
        query(ctx, query_str).await.contains_subset(json!({
            "items": [{
                "purl": [ PURL ],
                "cpe": ["cpe:/a:redhat:quarkus:3.2:*:el8:*"]
            }]
        })),
        "test failed for '{query_str}'"
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[case("purl~pkg:nuget/NGX")]
// #[case("purl~pkg:nuget/NGX@")]
#[case("purl=pkg:nuget/NGX@31.0.15.5356")]
// #[case("pkg:nuget/NGX@31.0.15.5356")]
#[test_log::test(actix_web::test)]
async fn find_components_without_namespace(
    ctx: &TrustifyContext,
    #[case] query_str: &str,
) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/rhelai1_binary.json"]).await?;

    const PURL: &str = "pkg:nuget/NGX@31.0.15.5356";

    assert!(
        query(ctx, query_str).await.contains_subset(json!({
            "items": [{
                "purl": [ PURL ],
            }]
        })),
        "for {query_str}"
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[case( // filter on node_id with descendants
    Req {
        what: What::Q("node_id=SPDXRef-A"),
        descendants: Some(10),
        ..Req::default()
    },
    Some("A"),
    1
)]
#[case( // filter on node_id with ancestors
    Req {
        what: What::Q("node_id=SPDXRef-B"),
        ancestors: Some(10),
        ..Req::default()
    },
    Some("B"),
    1
)]
#[case( // filter on node_id & name
    Req {
        what: What::Q("node_id=SPDXRef-B&name=B"),
        ancestors: Some(10),
        ..Req::default()
    },
    Some("B"),
    1
)]
#[case( // negative test: non-existent sbom_id
    Req {
        what: What::Q("sbom_id=urn:uuid:99999999-9999-9999-9999-999999999999"),
        ancestors: Some(10),
        ..Req::default()
    },
    None,
    0
)]
#[case( // negative test: mismatched node_id and name
    Req {
        what: What::Q("node_id=SPDXRef-B&name=A"),
        ancestors: Some(10),
        ..Req::default()
    },
    None,
    0
)]
#[test_log::test(actix_web::test)]
async fn test_retrieve_query_params_endpoint(
    ctx: &TrustifyContext,
    #[case] req: Req<'_>,
    #[case] expected_name: Option<&str>,
    #[case] expected_total: usize,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let response: Value = app.req(req).await?;

    if let Some(name) = expected_name {
        assert_eq!(response["items"][0]["name"], name);
    }
    assert_eq!(&response["total"], expected_total);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn test_retrieve_query_params_endpoint_sbom_id(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    // First get a response to extract sbom_id
    let response: Value = app
        .req(Req {
            what: What::Q("node_id=SPDXRef-B&name=B"),
            ancestors: Some(10),
            ..Req::default()
        })
        .await?;

    // filter on sbom_id (which has urn:uuid: prefix)
    let sbom_id = response["items"][0]["sbom_id"].as_str().unwrap();
    let response: Value = app
        .req(Req {
            what: What::Q(&format!("sbom_id={sbom_id}")),
            ancestors: Some(10),
            ..Req::default()
        })
        .await?;
    assert_eq!(&response["total"], 9);

    Ok(())
}

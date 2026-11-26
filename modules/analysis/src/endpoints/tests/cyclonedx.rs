use super::req::*;
use crate::test::caller;
use actix_http::{Request, StatusCode};
use actix_web::test::TestRequest;
use jsonpath_rust::JsonPath;
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_test_context::{
    TrustifyContext, call::CallService, document_bytes, subset::ContainsSubset,
};

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn cdx_generated_from(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["cyclonedx/openssl-3.0.7-18.el9_2.cdx_1.6.sbom.json"])
        .await?;

    // Find all deps of src rpm
    let src = "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src";
    let response: Value = app
        .req(Req {
            what: What::Id(src),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;
    tracing::debug!(test = "", "{response:#?}");

    let deps = response.query(&format!(
        "$.items[?(@.node_id=='{src}')].descendants[?(@.relationship=='generates')]"
    ))?;
    assert_eq!(35, deps.len());

    // Ensure binary rpm GeneratedFrom src rpm
    let x86 = "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=x86_64";
    let response: Value = app
        .req(Req {
            what: What::Id(x86),
            ancestors: Some(10),
            ..Req::default()
        })
        .await?;
    tracing::debug!(test = "", "{response:#?}");
    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ x86 ],
            "ancestors": [{
                "relationship": "generates",
                "purl": [ src ]
            }]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn cdx_variant_of(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["cyclonedx/66FF73123BB3489.json"])
        .await?;

    // Find all deps of parent
    let parent = "pkg:oci/ose-console@sha256:c2d69e860b7457eb42f550ba2559a0452ec3e5c9ff6521d758c186266247678e?arch=s390x&os=linux&tag=v4.14.0-202412110104.p0.g350e1ea.assembly.stream.el8";
    let child = "pkg:oci/openshift-ose-console@sha256:94a0d7feec34600a858c8e383ee0e8d5f4a077f6bbc327dcad8762acfcf40679";

    let response: Value = app
        .req(Req {
            what: What::Id(parent),
            ancestors: Some(10),
            ..Req::default()
        })
        .await?;
    tracing::debug!(test = "", "{response:#?}");

    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ parent ],
            "ancestors": [{
                "relationship": "variant",
                "purl": [ child ]
            }]
        }]
    })));

    // Ensure child is variant of src
    let response: Value = app
        .req(Req {
            what: What::Id(child),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;
    tracing::debug!(test = "", "{response:#?}");

    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ child ],
            "descendants": [{
                "relationship": "variant",
                "purl": [ parent ]
            }]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn cdx_ancestor_of(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["cyclonedx/openssl-3.0.7-18.el9_2.cdx_1.6.sbom.json"])
        .await?;

    let parent_query = "pkg:generic/openssl@3.0.7?checksum=SHA-512:1aea183b0b6650d9d5e7ba87b613bb1692c71720b0e75377b40db336b40bad780f7e8ae8dfb9f60841eeb4381f4b79c4c5043210c96e7cb51f90791b80c8285e&download_url=https://pkgs.devel.redhat.com/repo/openssl/openssl-3.0.7-hobbled.tar.gz/sha512/1aea183b0b6650d9d5e7ba87b613bb1692c71720b0e75377b40db336b40bad780f7e8ae8dfb9f60841eeb4381f4b79c4c5043210c96e7cb51f90791b80c8285e/openssl-3.0.7-hobbled.tar.gz";
    let parent_expected = "pkg:generic/openssl@3.0.7?checksum=SHA-512:1aea183b0b6650d9d5e7ba87b613bb1692c71720b0e75377b40db336b40bad780f7e8ae8dfb9f60841eeb4381f4b79c4c5043210c96e7cb51f90791b80c8285e&download_url=https:%2F%2Fpkgs.devel.redhat.com%2Frepo%2Fopenssl%2Fopenssl-3.0.7-hobbled.tar.gz%2Fsha512%2F1aea183b0b6650d9d5e7ba87b613bb1692c71720b0e75377b40db336b40bad780f7e8ae8dfb9f60841eeb4381f4b79c4c5043210c96e7cb51f90791b80c8285e%2Fopenssl-3.0.7-hobbled.tar.gz";
    let child = "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src";

    // Ensure parent has ancestors that include the child
    let response: Value = app
        .req(Req {
            what: What::Id(parent_query),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;
    log::debug!("{response:#?}");

    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ parent_expected ],
            "descendants": [{
                "relationship": "ancestor_of",
                "purl": [ child ]
            }]
        }]
    })));

    // Ensure parent has deps that include the child
    let response: Value = app
        .req(Req {
            what: What::Id(child),
            ancestors: Some(10),
            ..Req::default()
        })
        .await?;
    log::debug!("{response:#?}");

    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ child ],
            "ancestors": [{
                "relationship": "ancestor_of",
                "purl": [ parent_expected ]
            }]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn resolve_cdx_external_reference(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_document("cyclonedx/simple-ext-a.json").await?;
    let _response = app
        .req(Req {
            what: What::Id("A"),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;

    ctx.ingest_document("cyclonedx/simple-ext-b.json").await?;
    let response: Value = app
        .req(Req {
            what: What::Id("A"),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;

    //ensure we match on external node urn:cdx:a4f16b62-fea9-42c1-8365-d72d3cef37d1/2#a
    assert!(response.contains_subset(json!({
        "items": [ {
            "descendants": [ {
                "node_id": "urn:cdx:a4f16b62-fea9-42c1-8365-d72d3cef37d1/2#a",
                "name":"a",
                "document_id":"urn:cdx:a4f16b62-fea9-42c1-8365-d72d3cef37d1/1",
                "relationship":"dependency",
                "descendants":[
                    {
                        "node_id":"b",
                        "name":"B",
                        "relationship":"dependency",
                        "document_id":"urn:cdx:a4f16b62-fea9-42c1-8365-d72d3cef37d1/2"
                    }
                ]
            }]
        }]
    })));

    Ok(())
}

/// Assert that an analysis endpoint answers with HTTP 200 and a non-empty result set.
async fn assert_analysis_ok(app: &impl CallService, uri: &str) -> Result<Value, anyhow::Error> {
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response = app.call_service(request).await;
    let status = response.status();
    let body = actix_web::test::read_body(response).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "{uri} must tolerate an SBOM without metadata.timestamp, got {status}: {}",
        String::from_utf8_lossy(&body)
    );

    let response: Value = serde_json::from_slice(&body)?;
    assert!(
        response["total"].as_u64().unwrap_or(0) > 0,
        "{uri} returned no matching components: {response:#?}"
    );

    Ok(response)
}

/// A valid CycloneDX SBOM may omit `metadata.timestamp`. `cyclonedx/application.cdx.json`
/// is such a document: it was produced by the CycloneDX Maven plugin in reproducible-build
/// mode (`cdx:reproducible: enabled`) and carries no timestamp.
///
/// Ingestion stores `published = NULL` for it. The analysis load path must tolerate that
/// instead of failing to decode the row, which previously surfaced as an HTTP 500
/// `{"error":"Internal"}`.
///
/// See the historical report in TC-2523 and the upstream bug tracked from TC-1883.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn cdx_without_metadata_timestamp(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["cyclonedx/application.cdx.json"])
        .await?;

    assert_analysis_ok(
        &app,
        "/api/v3/analysis/component/spring-petclinic?total=true",
    )
    .await?;

    Ok(())
}

/// The `latest` selection path must also tolerate documents without a timestamp.
///
/// It needs a product/release pair to resolve a CPE context, so this reuses the real
/// NetworkManager pair from the latest-filter tests and removes `metadata.timestamp`
/// in memory, which is the shape reproducible-build producers emit.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn cdx_without_metadata_timestamp_latest(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    const DIR: &str = "cyclonedx/rh/latest_filters/rpm/NetworkManager/network_manager_2025-02-17/";
    for name in [
        "1.46.0-26.el9_4-product.json",
        "1.46.0-26.el9_4-release.json",
    ] {
        let bytes = document_bytes(format!("{DIR}{name}")).await?;
        let mut doc: Value = serde_json::from_slice(&bytes)?;
        if let Some(metadata) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            metadata.remove("timestamp");
        }
        ctx.ingest_json(doc).await?;
    }

    assert_analysis_ok(
        &app,
        "/api/v3/analysis/latest/component/NetworkManager-libnm-devel?total=true",
    )
    .await?;

    Ok(())
}

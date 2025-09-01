use crate::test::caller;
use actix_http::Request;
use actix_web::test::TestRequest;
use jsonpath_rust::JsonPath;
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyContext, call::CallService, subset::ContainsSubset};

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn spdx_generated_from(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/openssl-3.0.7-18.el9_2.spdx.json"])
        .await?;

    // Find all deps of src rpm
    let src = "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src";
    let uri = format!(
        "/api/v2/analysis/component/{}?descendants=10",
        urlencoding::encode(src)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::debug!("{response:#?}");

    let deps = response.query(
        "$.items[?(@.node_id=='SPDXRef-SRPM')].descendants[?(@.relationship=='generates')]",
    )?;
    assert_eq!(35, deps.len());

    // Ensure binary rpm GeneratedFrom src rpm
    let x86 = "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=x86_64";
    let uri = format!(
        "/api/v2/analysis/component/{}?ancestors=10",
        urlencoding::encode(x86)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::debug!("{response:#?}");

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
#[ignore = "circular references in ubi sbom"]
async fn spdx_variant_of(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["ubi9-9.2-755.1697625012.json"])
        .await?;

    let parents = [
        "pkg:oci/ubi9-container@sha256:d4c5d9c980678267b81c3c197a4a0dd206382111c912875a6cdffc6ca319b769?arch=aarch64&repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012",
        "pkg:oci/ubi9-container@sha256:204383c3d96c0e6c7154c91d07764f92035738dd67aa8896679f7feb73f66bfd?arch=x86_64&repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012",
        "pkg:oci/ubi9-container@sha256:721ca837c80c8b98752010a17ffccbdf17a0d260ddd916b7097f04187f6aa3a8?arch=s390x&repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012",
        "pkg:oci/ubi9-container@sha256:9a6092cdd8e7f4361ea3f508ae6d6d3d9dbb9458a921ab09e4cc006c0a7f0a61?arch=ppc64le&repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012",
    ];
    let child = "pkg:oci/ubi9-container@sha256:2f168398c538b287fd705519b83cd5b604dc277ef3d9f479c28a2adb4d830a49?repository_url=registry.redhat.io/ubi9&tag=9.2-755.1697625012";

    // Ensure variant relationships
    for parent in parents {
        let uri = format!(
            "/api/v2/analysis/component/{}?descendants=10",
            urlencoding::encode(parent)
        );
        let request: Request = TestRequest::get().uri(&uri).to_request();
        let response: Value = app.call_and_read_body_json(request).await;
        tracing::debug!(test = "", "{response:#?}");

        assert!(response.contains_subset(json!({
            "items": [{
                "purl": [ parent ],
                "descendants": [{
                    "relationship": "variant",
                    "purl": [ child ]
                }]
            }]
        })));
    }

    let uri = format!(
        "/api/v2/analysis/component/{}?ancestors=10",
        urlencoding::encode(child)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");

    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ child ],
            "ancestors": [
                {
                    "relationship": "variant",
                    "purl": [ parents[0] ]
                },
                {
                    "relationship": "variant",
                    "purl": [ parents[1] ]
                },
                {
                    "relationship": "variant",
                    "purl": [ parents[2] ]
                },
                {
                    "relationship": "variant",
                    "purl": [ parents[3] ]
                }
            ]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn spdx_ancestor_of(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/1178.json"]).await?;

    let parent = "pkg:generic/upstream-component@0.0.0?arch=src";
    let child = "pkg:rpm/redhat/B@0.0.0";

    // Ensure parent has ancestors that include the child
    let uri = format!(
        "/api/v2/analysis/component/{}?descendants=10",
        urlencoding::encode(parent)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");

    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ parent ],
            "descendants": [{
                "relationship": "ancestor_of",
                "purl": [ child ]
            }]
        }]
    })));

    // Ensure child has ancestors that include the parent
    let uri = format!(
        "/api/v2/analysis/component/{}?ancestors=10",
        urlencoding::encode(child)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");

    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ child ],
            "ancestors": [{
                "relationship": "ancestor_of",
                "purl": [ parent ]
            }]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn spdx_package_of(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // test case for the simple case of "relationshipType": "PACKAGE_OF" spdx relationships:
    // https://github.com/guacsec/trustify/issues/1140

    let app = caller(ctx).await?;
    ctx.ingest_document("spdx/SATELLITE-6.15-RHEL-8.json")
        .await?;

    let purl = "pkg:rpm/redhat/rubygem-google-cloud-compute@0.5.0-1.el8sat?arch=src";

    // Ensure child has an ancestor that includes it
    let uri = format!(
        "/api/v2/analysis/component/{}?ancestors=10",
        urlencoding::encode(purl)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::debug!("{}", serde_json::to_string_pretty(&response)?);

    assert!(response.contains_subset(json!({
        "items": [ {
            "ancestors": [ {
                "relationship": "package",
                "name": "SATELLITE-6.15-RHEL-8",
                "version": "6.15",
            }]
        }]
    })));

    // Ensure the product contains the component
    let uri = format!(
        "/api/v2/analysis/component?q={}&descendants=10",
        urlencoding::encode("SATELLITE-6.15-RHEL-8")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::debug!("{}", serde_json::to_string_pretty(&response)?);

    assert!(response.contains_subset(json!({
        "items": [ {
            "descendants": [ {
                "relationship": "package",
                "name": "rubygem-google-cloud-compute",
                "version": "0.5.0-1.el8sat"
            }]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn spdx_only_contains_relationships(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // test case for the simple case of filtering descendants "relationshipType": "CONTAINS" spdx relationships:
    // https://github.com/guacsec/trustify/issues/1232

    let app = caller(ctx).await?;
    ctx.ingest_document("spdx/SATELLITE-6.15-RHEL-8.json")
        .await?;

    let purl = "pkg:rpm/redhat/rubygem-google-cloud-compute@0.5.0-1.el8sat?arch=src";

    let uri = format!(
        "/api/v2/analysis/component/{}?descendants=10&relationships=contains",
        urlencoding::encode(purl)
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::debug!("{}", serde_json::to_string_pretty(&response)?);

    assert!(response.contains_subset(json!({
        "items": [ {
            "descendants": [ {
                "relationship": "contains",
                "name": "rubygem-google-cloud-compute-doc",
                "version": "0.5.0-1.el8sat",
            }]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn resolve_spdx_external_reference(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_document("spdx/simple-ext-a.json").await?;
    let uri = "/api/v2/analysis/component/A?descendants=10".to_string();
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response = app.call_service(request).await;
    assert_eq!(200, response.response().status());

    ctx.ingest_document("spdx/simple-ext-b.json").await?;
    let uri = "/api/v2/analysis/component/A?descendants=10".to_string();
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    //ensure we match on external node DocumentRef-ext-b:SPDXRef-A
    assert!(response.contains_subset(json!({
        "items": [ {
            "descendants": [ {
                "node_id": "DocumentRef-ext-b:SPDXRef-A",
                "name":"SPDXRef-A",
                "document_id":"uri:simple-ext-a",
                "relationship":"package",
                "descendants":[
                    {
                        "node_id":"SPDXRef-B",
                        "name":"B",
                        "relationship":"contains",
                        "document_id":"uri:simple-ext-b"
                    }
                ]
            }]
        }]
    })));

    Ok(())
}

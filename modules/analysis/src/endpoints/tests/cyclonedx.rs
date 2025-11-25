use super::req::*;
use crate::test::caller;
use jsonpath_rust::JsonPath;
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyContext, subset::ContainsSubset};

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

    let parent = "pkg:generic/openssl@3.0.7?checksum=SHA-512:1aea183b0b6650d9d5e7ba87b613bb1692c71720b0e75377b40db336b40bad780f7e8ae8dfb9f60841eeb4381f4b79c4c5043210c96e7cb51f90791b80c8285e&download_url=https://pkgs.devel.redhat.com/repo/openssl/openssl-3.0.7-hobbled.tar.gz/sha512/1aea183b0b6650d9d5e7ba87b613bb1692c71720b0e75377b40db336b40bad780f7e8ae8dfb9f60841eeb4381f4b79c4c5043210c96e7cb51f90791b80c8285e/openssl-3.0.7-hobbled.tar.gz";
    let child = "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src";

    // Ensure parent has ancestors that include the child
    let response: Value = app
        .req(Req {
            what: What::Id(parent),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;
    log::debug!("{response:#?}");

    assert!(response.contains_subset(json!({
        "items": [{
            "purl": [ parent ],
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
                "purl": [ parent ]
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

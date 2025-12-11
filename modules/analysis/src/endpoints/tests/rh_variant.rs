use super::req::*;
use crate::test::{Join, caller};
use rstest::rstest;
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyContext, subset::ContainsSubset};

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn resolve_rh_variant_prod_comp_src_binary_spdx_external_reference(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_document("spdx/rh/product_component/rhel-9.2-eus.spdx.json")
        .await?;
    let _response = app
        .req(Req {
            what: What::Id("SPDXRef-openssl-3.0.7-18.el9-2"),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;

    ctx.ingest_document("spdx/rh/product_component/openssl-3.0.7-18.el9_2.spdx.json")
        .await?;

    let response: Value = app
        .req(Req {
            what: What::Id("cpe:/a:redhat:rhel_eus:9.2::appstream"),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;

    assert!(response.contains_subset(json!({
        "items": [ {
            "node_id": "SPDXRef-RHEL-9.2-EUS",
            "name": "Red Hat Enterprise Linux",
            "version": "9.2 EUS",
            "published": "2006-08-14 02:34:56+00",
            "document_id": "https://www.redhat.com/rhel-9.2-eus.spdx.json",
            "product_name": "Red Hat Enterprise Linux",
            "product_version": "9.2 EUS",
            "descendants": [
            {
                "node_id": "SPDXRef-openssl-3.0.7-18.el9-2",
                "name": "openssl",
                "version": "3.0.7-18.el9_2",
                "published": "2006-08-14 02:34:56+00",
                "document_id": "https://www.redhat.com/rhel-9.2-eus.spdx.json",
                "product_name": "Red Hat Enterprise Linux",
                "product_version": "9.2 EUS",
                "relationship": "package",
                "descendants": [
                {
                  "node_id": "SPDXRef-RHEL-9.2-EUS:SPDXRef-openssl-3.0.7-18.el9-2",
                  "name": "SPDXRef-openssl-3.0.7-18.el9-2",
                  "published": "2006-08-14 02:34:56+00",
                  "document_id": "https://www.redhat.com/rhel-9.2-eus.spdx.json",
                  "product_name": "Red Hat Enterprise Linux",
                  "product_version": "9.2 EUS",
                  "relationship": "package",
                  "descendants": [
                    {
                      "node_id": "SPDXRef-s390x-openssl-perl",
                      "name": "openssl-perl",
                      "version": "3.0.7-18.el9_2",
                      "published": "2006-08-14 02:34:56+00",
                      "document_id": "https://www.redhat.com/openssl-3.0.7-18.el9_2.spdx.json",
                      "relationship": "generates",
                    }]
                }]
            }]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn resolve_rh_variant_prod_comp_src_binary_spdx_external_reference_ancestors(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_document("spdx/rh/product_component/rhel-9.2-eus.spdx.json")
        .await?;
    let _response = app
        .req(Req {
            what: What::Id("SPDXRef-openssl-3.0.7-18.el9-2"),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;

    ctx.ingest_document("spdx/rh/product_component/openssl-3.0.7-18.el9_2.spdx.json")
        .await?;

    let response: Value = app
        .req(Req {
            what: What::Id("openssl-perl"),
            ancestors: Some(10),
            ..Req::default()
        })
        .await?;

    assert!(response.contains_subset(json!({
        "items": [ {
            "node_id": "SPDXRef-aarch64-openssl-perl",
            "name": "openssl-perl",
            "version": "3.0.7-18.el9_2",
            "published": "2006-08-14 02:34:56+00",
            "document_id": "https://www.redhat.com/openssl-3.0.7-18.el9_2.spdx.json",
            "ancestors":[
                {
                "node_id": "SPDXRef-SRPM",
                "name": "openssl",
                "version": "3.0.7-18.el9_2",
                "published": "2006-08-14 02:34:56+00",
                "document_id": "https://www.redhat.com/openssl-3.0.7-18.el9_2.spdx.json",
                "product_name": "openssl",
                "product_version": "3.0.7-18.el9_2",
                "relationship": "generates",
                "ancestors": [
                    {
                        "node_id": "SPDXRef-DOCUMENT",
                        "name": "openssl-3.0.7-18.el9_2",
                        "version": "",
                        "published": "2006-08-14 02:34:56+00",
                        "document_id": "https://www.redhat.com/openssl-3.0.7-18.el9_2.spdx.json",
                        "product_name": "openssl",
                        "product_version": "3.0.7-18.el9_2",
                        "relationship": "describes"
                    },
                    {
                    "node_id": "SPDXRef-openssl-3.0.7-18.el9-2",
                    "purl": [
                        "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&repository_id=rhel-9-for-aarch64-baseos-eus-source-rpms",
                        "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&repository_id=rhel-9-for-s390x-baseos-eus-source-rpms",
                        "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&repository_id=rhel-9-for-ppc64le-baseos-eus-source-rpms",
                        "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&repository_id=rhel-9-for-i686-baseos-eus-source-rpms",
                        "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&repository_id=rhel-9-for-x86_64-baseos-eus-source-rpms",
                        "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&repository_id=rhel-9-for-aarch64-baseos-aus-source-rpms",
                        "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&repository_id=rhel-9-for-s390x-baseos-aus-source-rpms",
                        "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&repository_id=rhel-9-for-ppc64le-baseos-aus-source-rpms",
                        "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&repository_id=rhel-9-for-i686-baseos-aus-source-rpms",
                        "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&repository_id=rhel-9-for-x86_64-baseos-aus-source-rpms",
                        "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&repository_id=rhel-9-for-aarch64-baseos-e4s-source-rpms",
                        "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&repository_id=rhel-9-for-s390x-baseos-e4s-source-rpms",
                        "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&repository_id=rhel-9-for-ppc64le-baseos-e4s-source-rpms",
                        "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&repository_id=rhel-9-for-i686-baseos-e4s-source-rpms",
                        "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&repository_id=rhel-9-for-x86_64-baseos-e4s-source-rpms"
                    ],
                    "name": "openssl",
                    "version": "3.0.7-18.el9_2",
                    "published": "2006-08-14 02:34:56+00",
                    "document_id": "https://www.redhat.com/rhel-9.2-eus.spdx.json",
                    "product_name": "Red Hat Enterprise Linux",
                    "product_version": "9.2 EUS",
                    "relationship": "package",
                    }]
                }]
            }]

    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn resolve_rh_variant_prod_comp_cdx_external_reference(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_document("cyclonedx/rh/product_component/openssl-3.0.7-18.el9_2.cdx.json")
        .await?;
    ctx.ingest_document("cyclonedx/rh/product_component/rhel-9.2-eus.cdx.json")
        .await?;

    let response: Value = app
        .req(Req {
            what: What::Id("cpe:/a:redhat:rhel_eus:9.2::appstream"),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;

    assert!(response.contains_subset(json!({
      "items": [
        {
          "node_id": "Red Hat Enterprise Linux 9.2 EUS",
          "document_id": "urn:uuid:337d9115-4e7c-4e76-b389-51f7aed6eba8/1",
          "name": "Red Hat Enterprise Linux",
          "descendants": [
            {
              "node_id": "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src",
              "name": "openssl",
              "document_id": "urn:uuid:337d9115-4e7c-4e76-b389-51f7aed6eba8/1",
              "product_name": "Red Hat Enterprise Linux",
              "product_version": "9.2 EUS",
              "relationship": "generates",
              "descendants": [
                {
                    "node_id": "Red Hat Enterprise Linux 9.2 EUS:pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src",
                    "document_id": "urn:uuid:337d9115-4e7c-4e76-b389-51f7aed6eba8/1",
                    "relationship": "package",
                    "descendants": [{
                        "node_id": "pkg:rpm/redhat/openssl-perl@3.0.7-18.el9_2?arch=s390x",
                        "name": "openssl-perl",
                        "document_id": "urn:uuid:223234df-bb5b-49af-a896-143736f7d806/1"
                    }]
                }
              ]
            }
          ]
        }
      ]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[test_log::test(actix_web::test)]
#[ignore = "wait for data change"]
async fn resolve_rh_variant_prod_comp_product_b_cdx_external_reference(
    ctx: &TrustifyContext,
    #[values(true, false)] prime_cache: bool,
) -> Result<(), anyhow::Error> {
    // make sure when multiple products refer to the same component
    let _load = ctx
        .ingest_documents(
            "cyclonedx/rh/product_component/".join(&[
                "rhel-9.2-eus.cdx.json",
                "product-b.cdx.json",
                "openssl-3.0.7-18.el9_2.cdx.json",
            ][..])
        )
        .await?;

    let app = caller(ctx).await?;

    ctx.ingest_document("cyclonedx/rh/product_component/rhel-9.2-eus.cdx.json")
        .await?;
    if prime_cache {
        let _response = app.req(Req::default()).await?;
    }

    let response: Value = app
        .req(Req {
            what: What::Id("pkg:rpm/redhat/openssl-perl@3.0.7-18.el9_2?arch=aarch64"),
            ancestors: Some(10),
            ..Req::default()
        })
        .await?;

    assert!(response.contains_subset(json!({
      "items": [
        {
            "node_id": "pkg:rpm/redhat/openssl-perl@3.0.7-18.el9_2?arch=aarch64",
            "purl": [
            "pkg:rpm/redhat/openssl-perl@3.0.7-18.el9_2?arch=aarch64"
            ],
            "name": "openssl-perl",
            "version": "3.0.7-18.el9_2",
            "published": "2006-08-14 02:34:56+00",
            "document_id": "urn:uuid:223234df-bb5b-49af-a896-143736f7d806/1",
            "product_name": "openssl",
            "product_version": "3.0.7-18.el9_2",
            "ancestors":[
                {
                "node_id": "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src",
                "purl": [
                "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src"
                ],
                "name": "openssl",
                "version": "3.0.7-18.el9_2",
                "published": "2006-08-14 02:34:56+00",
                "document_id": "urn:uuid:223234df-bb5b-49af-a896-143736f7d806/1",
                "product_name": "openssl",
                "product_version": "3.0.7-18.el9_2",
                "relationship": "generates",
                 "ancestors":[
                    {
                        "node_id": "CycloneDX-doc-ref",
                        "document_id": "urn:uuid:223234df-bb5b-49af-a896-143736f7d806/1",
                        "product_name": "openssl",
                        "product_version": "3.0.7-18.el9_2",
                        "relationship": "describes",
                    },
                    {
                        "node_id": "pkg:generic/openssl@3.0.7?download_url=https://github.com/(RH openssl midstream repo)/archive/refs/tags/3.0.7.tar.gz",
                        "document_id": "urn:uuid:223234df-bb5b-49af-a896-143736f7d806/1",
                        "product_name": "openssl",
                        "product_version": "3.0.7-18.el9_2",
                        "relationship": "ancestor_of",
                    },
                    {
                        "node_id": "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src",
                        "name": "openssl",
                        "version": "3.0.7-18.el9_2",
                        "published": "2006-08-14 02:34:56+00",
                        "document_id": "urn:uuid:337d9115-4e7c-4e76-b389-51f7aed6eba8/1",
                        "product_name": "Red Hat Enterprise Linux",
                        "product_version": "9.2 EUS",
                        "relationship": "package",
                    },
                    {
                        "node_id": "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src",
                        "name": "openssl",
                        "version": "3.0.7-18.el9_2",
                        "document_id": "urn:uuid:d9115337-4e7c-764e-89b3-eba851f7aed6/1",
                        "product_name": "Red Hat productb",
                        "product_version": "1",
                        "relationship": "package"
                    }
                ]
            }]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[test_log::test(actix_web::test)]
async fn resolve_rh_variant_prod_comp_cdx_external_reference_ancestors(
    ctx: &TrustifyContext,
    #[values(true, false)] prime_cache: bool,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let _load = ctx
        .ingest_documents([
            "cyclonedx/rh/product_component/openssl-3.0.7-18.el9_2.cdx.json",
            "cyclonedx/rh/product_component/rhel-9.2-eus.cdx.json",
        ])
        .await?;

    // prime graph
    if prime_cache {
        let _response = app.req(Req::default()).await?;
    }

    // search for a dependency "pkg:rpm/redhat/openssl-perl@3.0.7-18.el9_2?arch=aarch64"
    let response: Value = app
        .req(Req {
            what: What::Id("pkg:rpm/redhat/openssl-perl@3.0.7-18.el9_2?arch=aarch64"),
            ancestors: Some(10),
            ..Req::default()
        })
        .await?;

    assert!(response.contains_subset(json!({
      "items": [
        {
             "node_id": "pkg:rpm/redhat/openssl-perl@3.0.7-18.el9_2?arch=aarch64",
            "purl": [
                "pkg:rpm/redhat/openssl-perl@3.0.7-18.el9_2?arch=aarch64"
            ],
            "name": "openssl-perl",
            "version": "3.0.7-18.el9_2",
            "published": "2006-08-14 02:34:56+00",
            "document_id": "urn:uuid:223234df-bb5b-49af-a896-143736f7d806/1",
            "product_name": "openssl",
            "product_version": "3.0.7-18.el9_2",
            "ancestors":[
            {
                "node_id": "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src",
                "purl": [
                "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src"
                ],
                "name": "openssl",
                "version": "3.0.7-18.el9_2",
                "published": "2006-08-14 02:34:56+00",
                "document_id": "urn:uuid:223234df-bb5b-49af-a896-143736f7d806/1",
                "product_name": "openssl",
                "product_version": "3.0.7-18.el9_2",
                "relationship": "generates",
                "ancestors":[
                {
                    "node_id": "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src",
                    "name": "openssl",
                    "version": "3.0.7-18.el9_2",
                    "published": "2006-08-14 02:34:56+00",
                    "document_id": "urn:uuid:337d9115-4e7c-4e76-b389-51f7aed6eba8/1",
                    "product_name": "Red Hat Enterprise Linux",
                    "product_version": "9.2 EUS",
                    "relationship": "package"
                }]
            }]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn resolve_rh_variant_prod_comp_cdx_external_reference_curl(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_document("cyclonedx/rh/product_component/RHEL-8.10.0.Z.MAIN+EUS.json")
        .await?;
    let _response = app
        .req(Req {
            what: What::Id("cpe:/o:redhat:enterprise_linux:8.10::baseos"),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;

    ctx.ingest_document(
        "cyclonedx/rh/product_component/RHEL-8.10.0.Z_curl@7.61.1-34.el8_10.2.json",
    )
    .await?;
    let response: Value = app
        .req(Req {
            what: What::Id("cpe:/o:redhat:enterprise_linux:8.10::baseos"),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;

    log::debug!("{response:?}");

    assert!(response.contains_subset(json!({
      "items": [
        {
          "node_id": "RHEL-8.10.0.Z.MAIN+EUS",
          "document_id": "urn:uuid:6895f8e0-2bfd-331c-97f9-97369ef1f3ee/1",
          "name": "Red Hat Enterprise Linux 8",
          "descendants": [
            {
              "node_id": "pkg:rpm/redhat/curl@7.61.1-34.el8_10.2?arch=src",
              "name": "curl",
              "document_id": "urn:uuid:6895f8e0-2bfd-331c-97f9-97369ef1f3ee/1",
              "relationship": "generates",
              "descendants":[
                {
                    "relationship": "package",
                }]
            }]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn resolve_rh_variant_source_binary_cdx_external_reference(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_document("cyclonedx/rh/rpm_src_binary/example_rpm_source.json")
        .await?;
    let _response = app
        .req(Req {
            what: What::Id("cpe:/a:redhat:rhel_eus:9.4::appstream"),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;

    ctx.ingest_document("cyclonedx/rh/rpm_src_binary/example_rpm_binaries.json")
        .await?;
    let response: Value = app
        .req(Req {
            what: What::Id("cpe:/a:redhat:rhel_eus:9.4::appstream"),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;

    log::debug!("{response:?}");

    assert!(response.contains_subset(json!({
      "items": [
        {
            "node_id": "RHEL-9.4.0.Z.EUS",
            "name": "Red Hat Enterprise Linux 9.4 Extended Update Support",
            "version": "RHEL-9.4.0.Z.EUS",
            "published": "2025-01-21 12:32:48+00",
            "document_id": "urn:uuid:f8afe2b2-c3d6-39fa-b9fc-92e5c76516ff/1",
            "descendants": [
            {
                "node_id": "pkg:rpm/redhat/iperf3@3.9-11.el9_4.1?arch=src",
                "name": "iperf3",
                "version": "3.9-11.el9_4.1",
                "published": "2025-01-21 12:32:48+00",
                "document_id": "urn:uuid:f8afe2b2-c3d6-39fa-b9fc-92e5c76516ff/1",
                "relationship": "generates",
                "descendants": [
                {
                    "node_id": "RHEL-9.4.0.Z.EUS:pkg:rpm/redhat/iperf3@3.9-11.el9_4.1?arch=src",
                    "relationship": "package",
                     "descendants": [
                        {
                          "node_id": "pkg:rpm/redhat/iperf3-devel@3.9-11.el9_4.1?arch=x86_64",
                          "document_id": "urn:uuid:a8c83882-79a5-4b47-8ba3-3973ac4e4309/1",
                          "relationship": "generates",
                        }]
                }]
            }]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn resolve_rh_variant_image_index_cdx_external_reference(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents([
        "cyclonedx/rh/image_index_variants/imagevariant_quarkus_mandrel_arm64.json",
        "cyclonedx/rh/image_index_variants/imagevariant_quarkus_mandrel_amd64.json",
        "cyclonedx/rh/image_index_variants/imageindex_quarkus_mandrel.json",
    ])
    .await?;

    let response: Value = app
        .req(Req {
            what: What::Id(
                "pkg:oci/quarkus-mandrel-for-jdk-21-rhel8@sha256%3A04b6da7bed65d56e14bd50a119b6fa9b46b534fedafb623af7c95b1a046bb66a"
            ),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;

    assert!(response.contains_subset(json!({
      "items": [
        {
            "node_id":"quarkus-mandrel-231-rhel8-container_image-index",
            "name": "quarkus/mandrel-for-jdk-21-rhel8",
            "document_id": "urn:uuid:8262934b-6d8f-30a7-a216-d933ded97451/1",
            "descendants": [
            {
              "node_id": "quarkus-mandrel-231-rhel8-container_arm64",
              "purl": [
                "pkg:oci/mandrel-for-jdk-21-rhel8@sha256:0dba39e3c6db8f7a097798d7898bb0362c32c642561b819cb02a475d596ff2a2?arch=arm64&os=linux&tag=23.1-19.1739757566"
              ],
              "name": "quarkus/mandrel-for-jdk-21-rhel8",
              "version": "sha256:0dba39e3c6db8f7a097798d7898bb0362c32c642561b819cb02a475d596ff2a2",
              "document_id": "urn:uuid:8262934b-6d8f-30a7-a216-d933ded97451/1",
              "relationship": "variant",
              "descendants": [
                {
                  "node_id": "quarkus-mandrel-231-rhel8-container_image-index:quarkus-mandrel-231-rhel8-container_arm64",
                  "name": "quarkus-mandrel-231-rhel8-container_arm64",
                  "published": "2025-02-17 02:40:50+00",
                  "document_id": "urn:uuid:8262934b-6d8f-30a7-a216-d933ded97451/1",
                  "relationship": "package",
                  "descendants": [
                    {
                      "node_id": "pkg:rpm/redhat/zlib-devel@1.2.11-25.el8?arch=aarch64&distro=rhel-8.10&package-id=a7258f3c94d69023&upstream=zlib-1.2.11-25.el8.src.rpm",
                      "name": "zlib-devel",
                      "version": "1.2.11-25.el8",
                      "published": "2025-02-17 02:40:27+00",
                      "document_id": "urn:uuid:38200326-3211-458c-8084-f24670a78ce4/1",
                      "relationship": "dependency",
                    }]
                }]
            }]
        }]
    })));
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn resolve_rh_variant_image_index_cdx_external_reference2(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents(
        "cyclonedx/rh/image_index_variants/".join(&[
            "example_container_variant_s390x.json",
            "example_container_variant_ppc.json",
            "example_container_variant_arm64.json",
            "example_container_variant_amd64.json",
            "example_container_index.json",
        ][..])
    )
    .await?;

    let response: Value = app
        .req(Req {
            what: What::Id(
                "pkg:oci/openshift-ose-openstack-cinder-csi-driver-operator@sha256%3A4e1a8039dfcd2a1ae7672d99be63777b42f9fad3baca5e9273653b447ae72fe8"
            ),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;

    assert!(response.contains_subset(json!({
      "items": [
        {
            "name": "openshift/ose-openstack-cinder-csi-driver-operator",
            "document_id": "urn:uuid:b3418a5d-8af8-3516-b9ac-5bc53628e803/1",
            "descendants": [
            {
                "node_id": "ose-openstack-cinder-csi-driver-operator-container_ppc64le",
                "purl": [
                "pkg:oci/ose-openstack-cinder-csi-driver-operator@sha256:64b4e6d6c18556f9f9dad1a9e6185c37d6ad07c72e515c475304a3a16b9eb51f?arch=ppc64le&os=linux&tag=v4.15.0-202501280037.p0.gd0c2407.assembly.stream.el8"
                ],
                "name": "openshift/ose-openstack-cinder-csi-driver-operator",
                "version": "sha256:64b4e6d6c18556f9f9dad1a9e6185c37d6ad07c72e515c475304a3a16b9eb51f",
                "published": "2025-02-06 19:23:12+00",
                "document_id": "urn:uuid:b3418a5d-8af8-3516-b9ac-5bc53628e803/1",
                "relationship": "variant",
                "descendants": [
                {
                    "node_id": "ose-openstack-cinder-csi-driver-operator-container_image-index:ose-openstack-cinder-csi-driver-operator-container_ppc64le",
                    "name": "ose-openstack-cinder-csi-driver-operator-container_ppc64le",
                    "document_id": "urn:uuid:b3418a5d-8af8-3516-b9ac-5bc53628e803/1",
                    "relationship": "package",
                    "descendants": [
                    {
                        "node_id": "pkg:rpm/redhat/zlib@1.2.11-25.el8?arch=ppc64le&distro=rhel-8.10&package-id=e4ec995f2956806f&upstream=zlib-1.2.11-25.el8.src.rpm",
                        "purl": [
                        "pkg:rpm/redhat/zlib@1.2.11-25.el8?arch=ppc64le"
                        ],
                        "name": "zlib",
                        "version": "1.2.11-25.el8",
                        "published": "2025-02-06 19:21:42+00",
                        "document_id": "urn:uuid:7e5ef761-ab77-460c-bf89-34a772842352/1",
                        "relationship": "dependency",
                    }]
                }]
            }]
        }]
    })));
    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[test_log::test(actix_web::test)]
async fn resolve_rh_variant_image_variant_cdx_external_reference_ancestors(
    ctx: &TrustifyContext,
    #[values(true, false)] prime_cache: bool,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents(
        "cyclonedx/rh/image_index_variants/".join(&[
            "example_container_variant_s390x.json",
            "example_container_variant_ppc.json",
            "example_container_variant_arm64.json",
            "example_container_variant_amd64.json",
            "example_container_index.json",
        ][..])
    )
    .await?;

    // ensure analysis graphs are primed
    if prime_cache {
        let _response = app.req(Req::default()).await?;
    }

    // search for a dependency "pkg:rpm/redhat/openssl-perl@3.0.7-18.el9_2?arch=aarch64"
    let response: Value = app
        .req(Req {
            what: What::Id("pkg:rpm/redhat/zlib@1.2.11-25.el8?arch=s390x"),
            ancestors: Some(10),
            ..Req::default()
        })
        .await?;

    log::info!("{response:#?}");

    assert!(response.contains_subset(json!({
      "items": [
        {
            "node_id": "pkg:rpm/redhat/zlib@1.2.11-25.el8?arch=s390x&distro=rhel-8.10&package-id=ca5c659108941f26&upstream=zlib-1.2.11-25.el8.src.rpm",
            "purl": [
            "pkg:rpm/redhat/zlib@1.2.11-25.el8?arch=s390x"
            ],
            "cpe": [],
            "name": "zlib",
            "version": "1.2.11-25.el8",
            "published": "2025-02-06 19:22:37+00",
            "document_id": "urn:uuid:aa6b5176-94f2-4c73-90bd-613fb1e560e8/1",
            "ancestors":[
            {
                "node_id": "ose-openstack-cinder-csi-driver-operator-container_s390x",
                "purl": [
                "pkg:oci/ose-openstack-cinder-csi-driver-operator@sha256:d3d96f71664efb8c2bd9290b8e1ca9c9b93a54cecb266078c4d954a2e9c05d4d?arch=s390x&os=linux&tag=v4.15.0-202501280037.p0.gd0c2407.assembly.stream.el8"
                ],
                "name": "openshift/ose-openstack-cinder-csi-driver-operator",
                "version": "sha256:d3d96f71664efb8c2bd9290b8e1ca9c9b93a54cecb266078c4d954a2e9c05d4d",
                "published": "2025-02-06 19:22:37+00",
                "document_id": "urn:uuid:aa6b5176-94f2-4c73-90bd-613fb1e560e8/1",
                "relationship": "dependency",
                "ancestors":[
                {
                    "node_id": "ose-openstack-cinder-csi-driver-operator-container_s390x",
                    "purl": [
                    "pkg:oci/ose-openstack-cinder-csi-driver-operator@sha256:d3d96f71664efb8c2bd9290b8e1ca9c9b93a54cecb266078c4d954a2e9c05d4d?arch=s390x&os=linux&tag=v4.15.0-202501280037.p0.gd0c2407.assembly.stream.el8"
                    ],
                    "name": "openshift/ose-openstack-cinder-csi-driver-operator",
                    "version": "sha256:d3d96f71664efb8c2bd9290b8e1ca9c9b93a54cecb266078c4d954a2e9c05d4d",
                    "published": "2025-02-06 19:23:12+00",
                    "document_id": "urn:uuid:b3418a5d-8af8-3516-b9ac-5bc53628e803/1",
                    "relationship": "package",
                    "ancestors":[
                    {
                        "node_id": "ose-openstack-cinder-csi-driver-operator-container_image-index",
                        "purl": [
                        "pkg:oci/openshift-ose-openstack-cinder-csi-driver-operator@sha256:4e1a8039dfcd2a1ae7672d99be63777b42f9fad3baca5e9273653b447ae72fe8"
                        ],
                        "name": "openshift/ose-openstack-cinder-csi-driver-operator",
                        "version": "sha256:4e1a8039dfcd2a1ae7672d99be63777b42f9fad3baca5e9273653b447ae72fe8",
                        "published": "2025-02-06 19:23:12+00",
                        "document_id": "urn:uuid:b3418a5d-8af8-3516-b9ac-5bc53628e803/1",
                        "relationship": "variant",
                    }]
                }]
            }]
        }]
    })));

    Ok(())
}

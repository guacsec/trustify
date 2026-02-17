use super::req::*;
use crate::test::{Join, caller};
use jsonpath_rust::JsonPath;
use rstest::*;
use serde_json::{Value, json};
use std::cmp;
use test_context::test_context;
use trustify_test_context::{TrustifyContext, subset::ContainsSubset};

#[test_context(TrustifyContext)]
#[rstest]
#[case( // cpe search
    Req { what: What::Id("cpe:/a:redhat:quay:3::el8"), ..Req::default() },
    2
)]
#[case( // cpe latest search
    Req { what: What::Id("cpe:/a:redhat:quay:3::el8"), latest: true, ..Req::default() },
    1
)]
#[case( // purl q search
    Req { what: What::Q("pkg:oci/quay-builder-qemu-rhcos-rhel8"), ancestors: Some(10), ..Req::default() },
    6
)]
#[case( // purl q latest
    Req { what: What::Q("pkg:oci/quay-builder-qemu-rhcos-rhel8"), ancestors: Some(10), latest: true, ..Req::default() },
    2
)]
#[case( // purl partial search
    Req { what: What::Q("purl~pkg:oci/quay-builder-qemu-rhcos-rhel8"), ancestors: Some(10), ..Req::default() },
    16
)]
#[case( // purl partial latest
    Req { what: What::Q("purl~pkg:oci/quay-builder-qemu-rhcos-rhel8"), ancestors: Some(10), latest: true, ..Req::default() },
    6
)]
#[case( // purl partial search latest
    Req { what: What::Q("purl:name~quay-builder-qemu-rhcos-rhel8&purl:ty=oci"), ancestors: Some(10), latest: true, ..Req::default() },
    6
)]
#[case( // purl partial search latest
    Req { what: What::Q("pkg:rpm/redhat/harfbuzz"), ancestors: Some(10), latest: true, ..Req::default() },
    1
)]
#[test_log::test(actix_web::test)]
async fn resolve_rh_variant_latest_filter_container_cdx(
    ctx: &TrustifyContext,
    #[case] req: Req<'_>,
    #[case] total: usize,
    #[values(false, true)] prime_cache: bool,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents(
        "cyclonedx/rh/latest_filters/container/quay_builder_qemu_rhcos_rhel8_2025-02-24/"
            .join(
                &[
                    "quay-builder-qemu-rhcos-rhel-8-product.json",
                    "quay-builder-qemu-rhcos-rhel-8-image-index.json",
                    "quay-builder-qemu-rhcos-rhel-8-amd64.json",
                ][..],
            )
            .chain(
                "cyclonedx/rh/latest_filters/container/quay_builder_qemu_rhcos_rhel8_2025-04-02/"
                    .join(
                        &[
                            "quay-v3.14.0-product.json",
                            "quay-builder-qemu-rhcos-rhel8-v3.14.0-4-index.json",
                            "quay-builder-qemu-rhcos-rhel8-v3.14.0-4-binary.json",
                        ][..],
                    ),
            ),
    )
    .await?;

    if prime_cache {
        let _response = app.req(Req::default()).await?;
    }

    let mut response = app.req(req).await?;

    sort(&mut response["items"]);

    log::info!("{response:#?}");
    assert_eq!(total, response["total"]);

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[case( // cpe search
    Req { what: What::Id("cpe:/a:redhat:rhel_eus:9.4::crb"), ..Req::default() },
    2
)]
#[case( // cpe latest search
    Req { what: What::Id("cpe:/a:redhat:rhel_eus:9.4::crb"), latest: true, ..Req::default() },
    1
)]
#[case( // purl partial search
    Req { what: What::Q("pkg:rpm/redhat/NetworkManager-libnm"), ancestors: Some(10), ..Req::default() },
    30
)]
#[case( // purl partial latest search
    Req { what: What::Q("pkg:rpm/redhat/NetworkManager-libnm"), ancestors: Some(10), latest: true, ..Req::default() },
    15
)]
#[case( // purl more specific latest q search
    Req { what: What::Q("pkg:rpm/redhat/NetworkManager-libnm-devel@"), latest: true, ..Req::default() },
    5
)]
#[case( // name exact search
    Req { what: What::Id("NetworkManager-libnm-devel"), ..Req::default() },
    10
)]
#[case( // latest name exact search
    Req { what: What::Id("NetworkManager-libnm-devel"), latest: true, ..Req::default() },
    5
)]
#[test_log::test(actix_web::test)]
async fn resolve_rh_variant_latest_filter_rpms_cdx(
    ctx: &TrustifyContext,
    #[case] req: Req<'_>,
    #[case] total: usize,
    #[values(false, true)] prime_cache: bool,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents(
        "cyclonedx/rh/latest_filters/rpm/NetworkManager/network_manager_2025-02-17/"
            .join(
                &[
                    "1.46.0-26.el9_4-product.json",
                    "1.46.0-26.el9_4-release.json",
                ][..],
            )
            .chain(
                "cyclonedx/rh/latest_filters/rpm/NetworkManager/network_manager_2025-04-08/".join(
                    &[
                        "1.46.0-27.el9_4-product.json",
                        "1.46.0-27.el9_4-release.json",
                    ][..],
                ),
            ),
    )
    .await?;

    if prime_cache {
        let _response = app.req(Req::default()).await?;
    }

    let response = app.req(req).await?;

    log::info!("{response:#?}");
    assert_eq!(total, response["total"]);

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[case( // cpe search
    Req { what: What::Id("cpe:/a:redhat:camel_quarkus:3"), ..Req::default() },
    2
)]
#[case( // cpe latest search
    Req { what: What::Id("cpe:/a:redhat:camel_quarkus:3"), latest: true, ..Req::default() },
    1
)]
#[case( // purl partial search
    Req { what: What::Q("pkg:maven/io.vertx/vertx-core@"), ancestors: Some(10), ..Req::default() },
    4
)]
#[case( // purl partial latest search
    Req { what: What::Q("pkg:maven/io.vertx/vertx-core@"), latest: true, ..Req::default() },
    1
)]
#[case( // name exact search
    Req { what: What::Id("vertx-core"), ..Req::default() },
    6
)]
#[case( // latest name exact search
    Req { what: What::Id("vertx-core"), latest: true, ..Req::default() },
    2
)]
#[test_log::test(actix_web::test)]
async fn resolve_rh_variant_latest_filter_middleware_cdx(
    ctx: &TrustifyContext,
    #[case] req: Req<'_>,
    #[case] total: usize,
    #[values(false, true)] prime_cache: bool,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents(
        "cyclonedx/rh/latest_filters/middleware/maven/quarkus/".chain([
            "3.15.4/".join(
                &[
                    "product-3.15.4.json",
                    "quarkus-camel-bom-3.15.4.json",
                    "quarkus-cxf-bom-3.15.4.json",
                ][..],
            ),
            "3.20/".join(
                &[
                    "product-3.20.json",
                    "quarkus-camel-bom-3.20.json",
                    "quarkus-cxf-bom-3.20.json",
                ][..],
            ),
        ]),
    )
    .await?;

    if prime_cache {
        let _response = app.req(Req::default()).await?;
    }

    let response = app.req(req).await?;

    log::info!("{response:#?}");
    assert_eq!(total, response["total"]);

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[test_log::test(actix_web::test)]
async fn test_tc2606(
    ctx: &TrustifyContext,
    #[values(false, true)] prime_cache: bool,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents("cyclonedx/rh/latest_filters/TC-2606/".join(
        &[
            "1F5B983228BA420.json",
            "401A4500E49D44D.json",
            "74092FCBFD294FC.json",
            "80138DC9368C4D3.json",
            "B67E38F00200413.json",
            "CE8E7B92C4BD452.json",
        ][..],
    ))
    .await?;

    if prime_cache {
        let _response = app.req(Req::default()).await?;
    }

    // latest cpe search
    let response = app
        .req(Req {
            latest: true,
            what: What::Id("cpe:/a:redhat:rhel_eus:9.4::appstream"),
            descendants: Some(1),
            ..Req::default()
        })
        .await?;
    log::info!("{response:#?}");

    assert!(response.contains_subset(json!(
            {
      "items": [
        {
          "node_id": "RHEL-9.4.0.Z.EUS",
          "name": "Red Hat Enterprise Linux 9.4 Extended Update Support",
          "version": "RHEL-9.4.0.Z.EUS",
          "published": "2025-06-09 10:18:20+00",
          "document_id": "urn:uuid:501c2eae-1514-3252-a7ce-b6beed26fe62/1",
          "descendants": [
            {
              "node_id": "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src",
              "purl": [
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-s390x-appstream-eus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-aarch64-appstream-eus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-x86_64-appstream-e4s-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-s390x-appstream-e4s-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-x86_64-appstream-aus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-ppc64le-appstream-eus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-x86_64-appstream-eus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-ppc64le-appstream-e4s-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-aarch64-appstream-e4s-source-rpms__9_DOT_4"
              ],
              "name": "grafana",
              "version": "9.2.10-23.el9_4",
              "published": "2025-06-09 10:18:20+00",
              "document_id": "urn:uuid:501c2eae-1514-3252-a7ce-b6beed26fe62/1",
              "relationship": "generates"
            }
          ],
        },
        {
          "node_id": "RHEL-9.4.0.Z.EUS",
          "name": "Red Hat Enterprise Linux 9.4 Extended Update Support",
          "version": "RHEL-9.4.0.Z.EUS",
          "published": "2025-06-09 03:29:53+00",
          "document_id": "urn:uuid:b84b0b69-6d39-3b23-86c6-5c258fc730b7/1",
          "descendants": [
            {
              "node_id": "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src",
              "purl": [
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-s390x-appstream-e4s-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-aarch64-appstream-e4s-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-x86_64-appstream-e4s-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-ppc64le-appstream-eus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-s390x-appstream-eus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-ppc64le-appstream-e4s-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-x86_64-appstream-aus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-x86_64-appstream-eus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-aarch64-appstream-eus-source-rpms__9_DOT_4"
              ],
              "name": "podman",
              "version": "4.9.4-18.el9_4.1",
              "published": "2025-06-09 03:29:53+00",
              "document_id": "urn:uuid:b84b0b69-6d39-3b23-86c6-5c258fc730b7/1",
              "relationship": "generates"
            }
          ],
        }
      ],
    })));
    assert_eq!(response["total"], 2);

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[test_log::test(actix_web::test)]
async fn test_tc2677(
    ctx: &TrustifyContext,
    #[values(false, true)] prime_cache: bool,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents("cyclonedx/rh/latest_filters/TC-2677/".join(
        &[
            "54FE396D61CE4E1.json",
            "A875C1FFA263483.json",
            "D52B5B9527D4447.json",
        ][..],
    ))
    .await?;

    if prime_cache {
        let _response = app.req(Req::default()).await?;
    }

    // latest cpe search
    let response = app
        .req(Req {
            latest: true,
            what: What::Id("cpe:/a:redhat:3scale:2.15::el9"),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;

    log::info!("{response:#?}");
    assert_eq!(response["total"], 1);

    assert!(response.contains_subset(json!(
    {
  "items": [
    {
      "node_id": "3SCALE-2.15-RHEL-9",
      "cpe": [
        "cpe:/a:redhat:3scale:2.15:*:el9:*"
      ],
      "name": "3scale API Management 2.15 on RHEL 9",
      "version": "3SCALE-2.15-RHEL-9",
      "published": "2025-05-27 20:11:20+00",
      "document_id": "urn:uuid:57334e7f-c34c-3e4e-a565-d83d45fd4399/1",
      "product_name": "3scale API Management 2.15 on RHEL 9",
      "product_version": "3SCALE-2.15-RHEL-9",
      "descendants": [
        {
          "node_id": "pkg:oci/authorino-rhel9@sha256%3Aa473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87",
          "purl": [
            "pkg:oci/authorino-rhel9@sha256:a473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87?repository_url=registry.access.redhat.com/3scale-tech-preview/authorino-rhel9&tag=3scale2.15.0",
            "pkg:oci/authorino-rhel9@sha256:a473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87?repository_url=registry.access.redhat.com/3scale-tech-preview/authorino-rhel9&tag=1.1.3",
            "pkg:oci/authorino-rhel9@sha256:a473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87?repository_url=registry.access.redhat.com/3scale-tech-preview/authorino-rhel9&tag=1.1.3-1",
            "pkg:oci/authorino-rhel9@sha256:a473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87",
            "pkg:oci/authorino-rhel9@sha256:a473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87?repository_url=registry.access.redhat.com/3scale-tech-preview/authorino-rhel9&tag=3scale2.15"
          ],
          "name": "3scale-tech-preview/authorino-rhel9",
          "version": "sha256:a473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87",
          "published": "2025-05-27 20:11:20+00",
          "document_id": "urn:uuid:57334e7f-c34c-3e4e-a565-d83d45fd4399/1",
          "product_name": "3scale API Management 2.15 on RHEL 9",
          "product_version": "3SCALE-2.15-RHEL-9",
          "relationship": "generates",
          "descendants": [
            {
              "node_id": "3SCALE-2.15-RHEL-9:pkg:oci/authorino-rhel9@sha256%3Aa473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87",
              "name": "pkg:oci/authorino-rhel9@sha256%3Aa473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87",
              "version": "",
              "published": "2025-05-27 20:11:20+00",
              "document_id": "urn:uuid:57334e7f-c34c-3e4e-a565-d83d45fd4399/1",
              "product_name": "3scale API Management 2.15 on RHEL 9",
              "product_version": "3SCALE-2.15-RHEL-9",
              "relationship": "package",
            }
          ]
        }
      ]
    }
  ],
  "total": 1
})));
    Ok(())
}

/// originally test if searching for PURLs works, instead of throwing a 500 error
///
/// This was due to a missing relationship/join.
///
/// On top, this test will now verify that there is no partial PURL matching. Which got introduced
/// during the original fixing of TC-2171, but was never part of the API. It tests the same for
/// "by name" requests.
#[test_context(TrustifyContext)]
#[rstest]
// by-purl
#[case( // PURL, non-latest, fuzzy match, which must not work with IDs
    Req { what: What::Id("pkg:maven/io.vertx/vertx-core"), ..Req::default() },
    0
)]
#[case( // PURL, latest, fuzzy match, which must not work with IDs
    Req { what: What::Id("pkg:maven/io.vertx/vertx-core"), latest: true, ..Req::default() },
    0
)]
#[case( // PURL, non-latest, exact match: 2x in camel, 1x in CXF
    Req { what: What::Id("pkg:maven/io.vertx/vertx-core@4.5.13.redhat-00001?type=jar"), ..Req::default() },
    3
)]
#[case(
    // PURL, latest, exact match: 2x in camel, 1x in CXF, but one overlaps the other because of "latest".
    // Not sure that's actually correct, as both SBOMs don't have a CPE and so don't have a
    // relationship.
    Req { what: What::Id("pkg:maven/io.vertx/vertx-core@4.5.13.redhat-00001?type=jar"), latest: true, ..Req::default() },
    2
)]
// by-name
#[case( // name, non-latest, fuzzy match, which must not work with IDs
    Req { what: What::Id("vertx-co"), ..Req::default() },
    0
)]
#[case( // name, latest, fuzzy match, which must not work with IDs
    Req { what: What::Id("vertx-co"), latest: true, ..Req::default() },
    0
)]
#[case( // name, non-latest, exact match: 2x in camel, 1x in CXF
    Req { what: What::Id("vertx-core"), ..Req::default() },
    3
)]
#[case(
    // name, latest, exact match: 2x in camel, 1x in CXF, but one overlaps the other because of "latest".
    // Not sure that's actually correct, as both SBOMs don't have a CPE and so don't have a
    // relationship.
    Req { what: What::Id("vertx-core"), latest: true, ..Req::default() },
    2
)]
// by-cpe
#[case( // cpe, non-latest, fuzzy match, which must not work with IDs
    Req { what: What::Id("cpe:/a:redhat"), ..Req::default() },
    0
)]
#[case( // cpe, latest, fuzzy match, which must not work with IDs
    Req { what: What::Id("cpe:/a:redhat"), latest: true, ..Req::default() },
    0
)]
#[case( // cpe, non-latest, exact match: 1x in product
    Req { what: What::Id("cpe:/a:redhat:camel_quarkus:3"), ..Req::default() },
    1
)]
#[case(
    // cpe, latest, exact match: 1x in product
    Req { what: What::Id("cpe:/a:redhat:camel_quarkus:3"), latest: true, ..Req::default() },
    1
)]
#[test_log::test(actix_web::test)]
async fn parse_ids_find_only_exact_matches(
    ctx: &TrustifyContext,
    #[case] req: Req<'_>,
    #[case] total: usize,
    #[values(false, true)] prime_cache: bool,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents(
        "cyclonedx/rh/latest_filters/middleware/maven/quarkus/3.15.4/".join(
            &[
                "product-3.15.4.json",
                "quarkus-camel-bom-3.15.4.json",
                "quarkus-cxf-bom-3.15.4.json",
            ][..],
        ),
    )
    .await?;

    if prime_cache {
        let _response = app.req(Req::default()).await?;
    }

    let response = app.req(req).await?;
    assert_eq!(total, response["total"]);

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[test_log::test(actix_web::test)]
async fn test_tc2758(
    ctx: &TrustifyContext,
    #[values(false, true)] prime_cache: bool,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents("cyclonedx/rh/TC-2758/".join(
        &[
            "jboss-eap-7.4.0.zip.json",
            "jboss-eap-7.4.0-core-src.zip.json",
            "jboss-eap-7.4.0-installer.jar.json",
            "jboss-eap-7.4.0-javadoc.zip.json",
            "jboss-eap-7.4.0-maven-repository.zip.json",
            "jboss-eap-7.4.0-quickstarts.zip.json",
            "jboss-eap-7.4.0-server-migration-src.zip.json",
            "jboss-eap-7.4.0-src.zip.json",
            "Red Hat JBoss Enterprise Application Platform.json",
        ][..],
    ))
    .await?;

    if prime_cache {
        let _response = app.req(Req::default()).await?;
    }

    let response = app
        .req(Req {
            latest: true,
            what: What::Id("cpe:/a:redhat:jboss_enterprise_application_platform:7.4"),
            descendants: Some(100),
            ..Req::default()
        })
        .await?;

    assert_eq!(response["total"], 1);
    assert!(response.contains_subset(json!(
    {
  "items": [
    {
      "node_id": "Red Hat JBoss Enterprise Application Platform 7.4",
      "cpe": [
        "cpe:/a:redhat:jboss_enterprise_application_platform:7.4:*:*:*"
      ],
      "name": "Red Hat JBoss Enterprise Application Platform",
      "version": "Red Hat JBoss Enterprise Application Platform 7.4",
      "published": "2021-07-21 18:46:07+00",
      "document_id": "urn:uuid:aa02fa8f-6a0f-3e5f-a7b7-a29098f4b1db/1",
      "product_name": "Red Hat JBoss Enterprise Application Platform",
      "product_version": "Red Hat JBoss Enterprise Application Platform 7.4",
      "descendants": [
        {
          "node_id": "pkg:generic/jboss-eap-7.4.0-javadoc.zip",
          "name": "jboss-eap-7.4.0-javadoc.zip",
          "relationship": "generates",
          "descendants": [
            {
              "node_id": "Red Hat JBoss Enterprise Application Platform 7.4:pkg:generic/jboss-eap-7.4.0-javadoc.zip",
              "name": "pkg:generic/jboss-eap-7.4.0-javadoc.zip",
              "relationship": "package",
              "descendants": [
                {
                  "node_id": "pkg:generic/pom.xml?checksum=sha256%3A974823188145bdb517f9692341a237bdee75c8312d3c86ae0fc4d390225bb923",
                  "name": "pom.xml",
                  "relationship": "dependency",
                }]
            }]
        }]
    }],
  "total": 1
})));

    Ok(())
}

/// Sort all entries by document_id, then published, then name.
///
/// This includes recursive sorting of ancestors/descendants.
fn sort(json: &mut Value) {
    let Value::Array(items) = json else {
        return;
    };

    fn by_str(name: &str, a: &Value, b: &Value) -> cmp::Ordering {
        a[name].as_str().cmp(&b[name].as_str())
    }

    // sort list

    items.sort_unstable_by(|a, b| {
        by_str("document_id", a, b)
            .then_with(|| by_str("published", a, b))
            .then_with(|| by_str("name", a, b))
    });

    // now sort child entries

    for item in items {
        sort(&mut item["ancestors"]);
        sort(&mut item["descendants"]);
    }
}

#[test_context(TrustifyContext)]
#[rstest]
#[case( // cpe search
    Req { what: What::Id("cpe:/a:redhat:container_native_virtualization:4.17::el9"), ..Req::default() },
    2
)]
#[case( // cpe latest search
    Req { what: What::Id("cpe:/a:redhat:container_native_virtualization:4.17::el9"), latest: true, ..Req::default() },
    1
)]
#[case( // cpe search
    Req { what: What::Id("cpe:/a:redhat:enterprise_linux:9.7::appstream"), ..Req::default() },
    2
)]
#[case( // cpe latest search
    Req { what: What::Id("cpe:/a:redhat:enterprise_linux:9.7::appstream"), latest: true, ..Req::default() },
    1
)]
#[case( // cpe search
    Req { what: What::Id("cpe:/a:redhat:quarkus:3.20::el8"), ..Req::default() },
    2
)]
#[case( // cpe part search
    Req { what: What::Q("cpe:part=a"), ..Req::default() },
    8
)]
#[case( // latest cpe part search
    Req { what: What::Q("cpe:part=a"),  latest: true,..Req::default() },
    4
)]
#[case( // cpe part search
    Req { what: What::Q("cpe:part=o"), ..Req::default() },
    2
)]
#[case( // latest cpe part search
    Req { what: What::Q("cpe:part=o"),  latest: true,..Req::default() },
    1
)]
#[case( // cpe latest search
    Req { what: What::Id("cpe:/a:redhat:quarkus:3.20::el8"), latest: true, ..Req::default() },
    1
)]
#[case( // latest name exact search
    Req { what: What::Q("name=container-native-virtualization/wasp-agent-rhel9"), latest: true, ancestors: Some(10), ..Req::default() },
    1
)]
#[case( // latest name exact search
    Req { what: What::Q("name=datagrid/datagrid-8"), latest: true, ancestors: Some(10), ..Req::default() },
    1
)]
#[case( // latest name exact search
    Req { what: What::Q("name=quarkus-bom"), latest: true, ancestors: Some(10), ..Req::default() },
    1
)]
#[case( // latest name exact search
    Req { what: What::Q("name=webkit2gtk3"), latest: true, ancestors: Some(10), ..Req::default() },
    1
)]
#[case( // latest name exact search
    Req { what: What::Q("name=libsoup3"), latest: true, ancestors: Some(10), ..Req::default() },
    1
)]
#[case( // name exact search
    Req { what: What::Q("name=openssl-synthetic-test"), ancestors: Some(10), ..Req::default() },
    4
)]
#[case( // latest name exact search
    Req { what: What::Q("name=openssl-synthetic-test"),latest: true, ancestors: Some(10), ..Req::default() },
    2
)]
#[case( // name exact search
    Req { what: What::Q("name=openssl"), ancestors: Some(10), ..Req::default() },
    6
)]
#[case( // latest name exact search
    Req { what: What::Q("name=openssl"),latest: true, ancestors: Some(10), ..Req::default() },
    2
)]
#[case( // q search
    Req { what: What::Q("openssl"), ancestors: Some(10), ..Req::default() },
    24
)]
#[case( // latest q search
    Req { what: What::Q("openssl"),latest: true, ancestors: Some(10), ..Req::default() },
    12
)]
#[case( // name partial search
    Req { what: What::Q("name~openssl-synthetic"), ancestors: Some(10), ..Req::default() },
    4
)]
#[case( // name partial search
    Req { what: What::Q("name~libsoup3-devel"), ancestors: Some(10), ..Req::default() },
    8
)]
#[case( // purl partial search
    Req { what: What::Q("purl~openssl-synthetic-test"), ancestors: Some(10), ..Req::default() },
    4
)]
#[test_log::test(actix_web::test)]
async fn resolve_rh_variant_latest_filter_tc_3278(
    ctx: &TrustifyContext,
    #[case] req: Req<'_>,
    #[case] total: usize,
    #[values(false, true)] prime_cache: bool,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents("cyclonedx/rh/latest_filters/TC-3278/".chain([
        "container/cnv-4.17/latest/".join(
            &[
                "binary-2025-12-02-5C502A658F36477.json",
                "binary-2025-12-02-C0CF40B259B1491.json",
                "image-index-2025-12-02-693F980C32C444A.json",
                "product-2025-12-02-ED1F188BB5C94D8.json",
            ][..],
        ),
        "container/cnv-4.17/older/".join(
            &[
                "binary-2025-11-25-3E72AAC00183431.json",
                "binary-2025-11-25-32EBB9C7E6914AD.json",
                "image-index-2025-11-25-CBE2989E64414F5.json",
                "product-2025-11-25-D05BF995974542F.json",
            ][..],
        ),
        "container/datagrid-datagrid-8/latest/".join(
            &[
                "binary-2025-12-04-62F0D268C8094C2.json",
                "image-index-2025-12-04-2BE8E55FCB8946B.json",
                "product-2025-12-08-6483D4F2E4B1469.json",
            ][..],
        ),
        "container/datagrid-datagrid-8/older/".join(
            &[
                "binary-2025-10-06-85E079C4EC034F1.json",
                "image-index-2025-10-06-BD74B271CC444BA.json",
                "product-2025-10-07-D792D72A114A47A.json",
            ][..],
        ),
        "middleware/quarkus-3.20/latest/".join(&["product-2025-12-01-EDA6638AD2F4451.json"][..]),
        "middleware/quarkus-3.20/older/".join(&["product-2025-10-14-28954C62C811417.json"][..]),
        "rpm/libsoup3/latest/".join(
            &[
                "product-2025-12-11-E2251709C91242E.json",
                "rpm-2025-12-10-5609FCE0067D4F6.json",
            ][..],
        ),
        "rpm/libsoup3/older/".join(
            &[
                "product-2025-11-11-CD32282B963F42C.json",
                "rpm-2025-10-27-B38A3A44DA644A4.json",
            ][..],
        ),
        "rpm/webkit2gtk3/latest/".join(
            &[
                "product-2025-12-08-A9F140D67EB2408.json",
                "rpm-2025-12-05-3705CE313B0F437.json",
            ][..],
        ),
        "rpm/webkit2gtk3/older/".join(
            &[
                "product-2025-11-11-7764C2C0C91542B.json",
                "rpm-2025-10-14-CC595A02EB3545E.json",
            ][..],
        ),
    ]))
    .await?;

    if prime_cache {
        let _response = app.req(Req::default()).await?;
    }

    let mut response = app.req(req).await?;

    sort(&mut response["items"]);

    log::info!("{response:#?}");
    assert_eq!(total, response["total"]);

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[case( // purl partial search
    Req { what: What::Q("purl~pkg:rpm/redhat/firefox"), ancestors: Some(10), ..Req::default() },
    1,
    vec!["cyclonedx/rh/latest_filters/TC-2719/firefox.json"]
)]
#[case( // purl partial search
    Req { what: What::Q("purl~pkg:rpm/redhat/firefox"), latest: true, ancestors: Some(10), ..Req::default() },
    1,
    vec!["cyclonedx/rh/latest_filters/TC-2719/firefox.json"]
)]
#[case( // spdx cpe search
    Req { what: What::Id("cpe:/a:redhat:enterprise_linux:9::appstream"), ancestors: Some(10), ..Req::default() },
    2,
    vec![
        "spdx/rh/latest/TC-2719/mariadb-9.7-1763396552-binary.json",
        "spdx/rh/latest/TC-2719/mariadb-9.7-1763396552-products.json",
        "spdx/rh/latest/TC-2719/mariadb-binary.json",
        "spdx/rh/latest/TC-2719/mariadb-product.json"
    ])]
#[case( // spdx cpe latest search
    Req { what: What::Id("cpe:/a:redhat:enterprise_linux:9::appstream"), latest:true, ancestors: Some(10), ..Req::default() },
    1,
    vec![
        "spdx/rh/latest/TC-2719/mariadb-9.7-1763396552-binary.json",
        "spdx/rh/latest/TC-2719/mariadb-9.7-1763396552-products.json",
        "spdx/rh/latest/TC-2719/mariadb-binary.json",
        "spdx/rh/latest/TC-2719/mariadb-product.json"
    ])]
#[case( // spdx q name search
    Req { what: What::Q("name=mariadb-1011-9-7_arm64"), ancestors: Some(10), ..Req::default() },
    2,
    vec![
        "spdx/rh/latest/TC-2719/mariadb-9.7-1763396552-binary.json",
        "spdx/rh/latest/TC-2719/mariadb-9.7-1763396552-products.json",
        "spdx/rh/latest/TC-2719/mariadb-binary.json",
        "spdx/rh/latest/TC-2719/mariadb-product.json"
    ])]
#[case( // spdx latest q name search
    Req { what: What::Q("name=mariadb-1011-9-7_arm64"), latest:true, ancestors: Some(10), ..Req::default() },
    1,
    vec![
        "spdx/rh/latest/TC-2719/mariadb-9.7-1763396552-binary.json",
        "spdx/rh/latest/TC-2719/mariadb-9.7-1763396552-products.json",
        "spdx/rh/latest/TC-2719/mariadb-binary.json",
        "spdx/rh/latest/TC-2719/mariadb-product.json"
    ])]
#[case( // spdx q partial purl search
    Req { what: What::Q("purl~pkg:oci/mariadb-1011@"), ancestors: Some(10), ..Req::default() },
    12,
    vec![
        "spdx/rh/latest/TC-2719/mariadb-9.7-1763396552-binary.json",
        "spdx/rh/latest/TC-2719/mariadb-9.7-1763396552-products.json",
        "spdx/rh/latest/TC-2719/mariadb-binary.json",
        "spdx/rh/latest/TC-2719/mariadb-product.json"
    ])]
#[case( // spdx latest q partial purl search
    Req { what: What::Q("purl~pkg:oci/mariadb-1011@"), latest:true, ancestors: Some(10), ..Req::default() },
    6,
    vec![
        "spdx/rh/latest/TC-2719/mariadb-9.7-1763396552-binary.json",
        "spdx/rh/latest/TC-2719/mariadb-9.7-1763396552-products.json",
        "spdx/rh/latest/TC-2719/mariadb-binary.json",
        "spdx/rh/latest/TC-2719/mariadb-product.json"
    ])]
#[test_log::test(actix_web::test)]
async fn resolve_rh_variant_latest_filter_tc_2719(
    ctx: &TrustifyContext,
    #[case] req: Req<'_>,
    #[case] total: usize,
    #[case] sbom_data: Vec<&str>,
    #[values(false, true)] prime_cache: bool,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents(sbom_data).await?;

    if prime_cache {
        let _response = app.req(Req::default()).await?;
    }

    let mut response = app.req(req).await?;

    sort(&mut response["items"]);

    log::info!("{response:#?}");
    assert_eq!(total, response["total"]);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn test_tc3518(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents("spdx/rh/latest/TC-2719/".join(
        &[
            "mariadb-9.7-1763396552-binary.json",
            "mariadb-9.7-1763396552-products.json",
        ][..],
    ))
    .await?;

    let response = app
        .req(Req {
            latest: true,
            what: What::Id("cpe:/a:redhat:enterprise_linux:9::appstream"),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;

    log::debug!("{:#?}", response["items"][0]["published"]);

    let published: Vec<&str> = response
        .query("$..published")
        .expect("jsonpath query failed")
        .into_iter()
        .filter_map(|v| v.as_str())
        .collect();

    assert_eq!(
        published.as_slice(),
        &[
            "2025-11-17 17:22:07+00",
            "2025-11-17 17:22:07+00",
            "2025-11-17 17:22:07+00",
            "2025-11-17 16:38:55+00",
            "2025-11-17 16:38:55+00",
            "2025-11-17 16:38:55+00",
            "2025-11-17 16:38:55+00",
            "2025-11-17 16:38:55+00",
            "2025-11-17 16:38:55+00",
            "2025-11-17 16:38:55+00",
            "2025-11-17 16:38:55+00"
        ]
    );

    ctx.ingest_documents(
        "spdx/rh/latest/TC-2719/".join(&["mariadb-binary.json", "mariadb-product.json"][..]),
    )
    .await?;
    let response = app
        .req(Req {
            latest: true,
            what: What::Id("cpe:/a:redhat:enterprise_linux:9::appstream"),
            descendants: Some(10),
            ..Req::default()
        })
        .await?;

    let published: Vec<&str> = response
        .query("$..published")
        .expect("jsonpath query failed")
        .into_iter()
        .filter_map(|v| v.as_str())
        .collect();

    assert_eq!(
        published.as_slice(),
        &[
            "2025-12-22 17:55:59+00",
            "2025-12-22 17:55:59+00",
            "2025-12-22 17:55:59+00",
            "2025-12-22 17:21:45+00",
            "2025-12-22 17:21:45+00",
            "2025-12-22 17:21:45+00",
            "2025-12-22 17:21:45+00",
            "2025-12-22 17:21:45+00",
            "2025-12-22 17:21:45+00",
            "2025-12-22 17:21:45+00",
            "2025-12-22 17:21:45+00"
        ]
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[case( // cdx cpe search
    Req { what: What::Id("cpe:/a:redhat:jboss_enterprise_application_platform_els:7.4::el8"),latest:true, ancestors: Some(10), ..Req::default() },
    1)]
#[case( // cdx purl search
    Req { what: What::Q("purl~pkg:maven/aopalliance/aopalliance"), ancestors: Some(10), ..Req::default() },
    1)]
#[case( // cdx latest purl search
    Req { what: What::Q("purl~pkg:maven/aopalliance/aopalliance"),latest:true, ancestors: Some(10), ..Req::default() },
    1)]
#[case( // cdx purl search
    Req { what: What::Q("purl~pkg:maven/antlr/antlr"), ancestors: Some(10), ..Req::default() },
    1)]
#[case( // cdx latest purl search
    Req { what: What::Q("purl~pkg:maven/antlr/antlr"),latest:true, ancestors: Some(10), ..Req::default() },
    1)]
#[test_log::test(actix_web::test)]
async fn test_tc3624(
    ctx: &TrustifyContext,
    #[case] req: Req<'_>,
    #[case] total: usize,
    #[values(false, true)] prime_cache: bool,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents("cyclonedx/rh/latest_filters/TC-3624/".join([
        "product.json",
        "index.json",
        "binary.json",
    ]))
    .await?;

    if prime_cache {
        let _response = app.req(Req::default()).await?;
    }

    let mut response = app.req(req).await?;

    sort(&mut response["items"]);

    log::info!("{response:#?}");
    assert_eq!(total, response["total"]);

    Ok(())
}

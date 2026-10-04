use super::caller;
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use serde_json::Value;
use test_context::test_context;
use test_log::test;
use trustify_test_context::{Join, TrustifyContext, call::CallService};
use urlencoding::encode;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn latest_cpe_can_return_a_generated_spdx_document(
    ctx: &TrustifyContext,
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

    let cpe = "cpe:/a:redhat:quay:3::el8";
    let uri = format!(
        "/api/v3/analysis/latest/component/{}?generate_sbom=true&source_format=cyclonedx",
        encode(cpe)
    );
    let response = app
        .call_service(TestRequest::get().uri(&uri).to_request())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(actix_web::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/spdx+json")
    );
    let body = actix_web::test::read_body(response).await;
    let document: Value = serde_json::from_slice(&body)?;
    let _: spdx_rs::models::SPDX = serde_json::from_slice(&body)?;
    assert_eq!(document["spdxVersion"], "SPDX-2.3");
    assert_eq!(document["SPDXID"], "SPDXRef-DOCUMENT");
    assert!(
        document["packages"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
    let product = document["packages"]
        .as_array()
        .expect("packages array")
        .iter()
        .find(|package| package["SPDXID"] == "SPDXRef-Product")
        .expect("synthetic product package");
    assert!(
        product["externalRefs"]
            .as_array()
            .is_some_and(|refs| refs.iter().any(|reference| {
                reference["referenceType"] == "cpe22Type"
                    && reference["referenceLocator"]
                        .as_str()
                        .is_some_and(|locator| locator.starts_with("cpe:/a:redhat:quay:3"))
            }))
    );

    Ok(())
}

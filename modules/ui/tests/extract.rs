#![allow(clippy::expect_used)]

use std::sync::Arc;

use actix_web::{dev::ServiceResponse, test::TestRequest};
use serde_json::{Value, json};
use test_log::test;
use trustify_module_ui::endpoints::{Config, UiResources, configure, post_configure};
use trustify_test_context::{call, call::CallService, document_bytes_raw};
use trustify_ui::UI;

pub async fn caller() -> anyhow::Result<impl CallService> {
    caller_with(Config::default()).await
}

async fn caller_with(config: Config) -> anyhow::Result<impl CallService> {
    let ui = UiResources::new(&UI::default())?;

    call::caller(move |svc| {
        configure(svc, config);
        svc.map(|svc| {
            post_configure(svc, Arc::new(ui));
            svc
        });
    })
    .await
}

async fn assert_extract(
    format: impl Into<Option<&str>>,
    file: &str,
    packages: Value,
    expected_format: &str,
) -> anyhow::Result<()> {
    assert_extract_with(format, file, packages, json!([]), expected_format).await
}

async fn assert_extract_with(
    format: impl Into<Option<&str>>,
    file: &str,
    packages: Value,
    warnings: Value,
    expected_format: &str,
) -> anyhow::Result<()> {
    use actix_web::body::MessageBody;

    assert_extract_fn(format, file, async |result| {
        let result = result
            .into_body()
            .try_into_bytes()
            .expect("must receive body");
        let result: Value = serde_json::from_slice(&result).expect("body must decode as JSON");

        assert_eq!(
            result,
            json! ({
                "format": expected_format,
                "packages": packages,
                "warnings": warnings,
            })
        )
    })
    .await
}

async fn assert_extract_fn(
    format: impl Into<Option<&str>>,
    file: &str,
    f: impl AsyncFnOnce(ServiceResponse),
) -> anyhow::Result<()> {
    let app = caller().await?;

    let bytes = document_bytes_raw(file).await?;

    let mut uri = "/api/v2/ui/extract-sbom-purls?".to_string();

    if let Some(format) = format.into() {
        uri = format!("{uri}format={format}")
    }

    let request = TestRequest::post()
        .uri(&uri)
        .set_payload(bytes)
        .to_request();

    let result = app.call_service(request).await;

    f(result).await;

    Ok(())
}

fn simple_spdx_json() -> Value {
    json!({
        "A": {
            "purls": [
                "pkg:rpm/redhat/A@0.0.0?arch=src",
            ],
        },
        "AA": {
            "purls": [
                "pkg:rpm/redhat/AA@0.0.0?arch=src",
            ],
        },
        "B": {
            "purls": [
                "pkg:rpm/redhat/B@0.0.0",
            ],
        },
        "BB": {
            "purls": [
                "pkg:rpm/redhat/BB@0.0.0",
            ],
        },
        "CC": {
            "purls": [
                "pkg:rpm/redhat/CC@0.0.0",
            ],
        },
        "DD": {
            "purls": [
                "pkg:rpm/redhat/DD@0.0.0",
            ],
        },
        "EE": {
            "purls": [
                "pkg:rpm/redhat/EE@0.0.0?arch=src"
            ],
        },
        "FF": {
            "purls": [],
        }
    })
}

fn simple_cdx_json() -> Value {
    json!({
        "A": {
            "purls": [
                "pkg:rpm/redhat/A@0.0.0?arch=src",
            ],
        },
        "AA": {
            "purls": [
                "pkg:rpm/redhat/AA@0.0.0?arch=src",
            ],
        },
        "B": {
            "purls": [
                "pkg:rpm/redhat/B@0.0.0?arch=src",
            ],
        },
        "BB": {
            "purls": [
                "pkg:rpm/redhat/BB@0.0.0?arch=src",
            ],
        },
        "CC": {
            "purls": [
                "pkg:rpm/redhat/CC@0.0.0?arch=src",
            ],
        },
        "DD": {
            "purls": [
                "pkg:rpm/redhat/DD@0.0.0?arch=src",
            ],
        },
        "EE": {
            "purls": [
                "pkg:rpm/redhat/EE@0.0.0?arch=src"
            ],
        },
        "FF": {
            "purls": [
                "pkg:rpm/redhat/FF@0.0.0?arch=src"
            ],
        },
        "simple": {
            "purls": [],
        }
    })
}

/// extract a SPDX file as default format
#[test(tokio::test)]
async fn extract_spdx_default() -> anyhow::Result<()> {
    assert_extract(None, "spdx/simple.json", simple_spdx_json(), "spdx").await
}

/// extract a SPDX file as SBOM format
#[test(tokio::test)]
async fn extract_spdx_sbom() -> anyhow::Result<()> {
    assert_extract("sbom", "spdx/simple.json", simple_spdx_json(), "spdx").await
}

/// extract a SPDX file as SPDX format
#[test(tokio::test)]
async fn extract_spdx_spdx() -> anyhow::Result<()> {
    assert_extract("spdx", "spdx/simple.json", simple_spdx_json(), "spdx").await
}

/// extract a CycloneDX file as default format
#[test(tokio::test)]
async fn extract_cdx_default() -> anyhow::Result<()> {
    assert_extract(
        None,
        "cyclonedx/simple.json",
        simple_cdx_json(),
        "cyclonedx",
    )
    .await
}

/// extract a CycloneDX file as SBOM format
#[test(tokio::test)]
async fn extract_cdx_sbom() -> anyhow::Result<()> {
    assert_extract(
        "sbom",
        "cyclonedx/simple.json",
        simple_cdx_json(),
        "cyclonedx",
    )
    .await
}

/// extract a CycloneDX file as CycloneDX format
#[test(tokio::test)]
async fn extract_cdx_cdx() -> anyhow::Result<()> {
    assert_extract(
        "cyclonedx",
        "cyclonedx/simple.json",
        simple_cdx_json(),
        "cyclonedx",
    )
    .await
}

/// Asking for CycloneDX, but then providing a SPDX file should fail
#[test(tokio::test)]
async fn extract_cdx_wrong() -> anyhow::Result<()> {
    assert_extract_fn("cyclonedx", "spdx/simple.json", async |result| {
        assert_eq!(result.status(), 400)
    })
    .await
}

/// Asking for SPDX, but then providing a CDX file should fail
#[test(tokio::test)]
async fn extract_spdx_wrong() -> anyhow::Result<()> {
    assert_extract_fn("spdx", "cyclonedx/simple.json", async |result| {
        assert_eq!(result.status(), 400)
    })
    .await
}

/// Asking for advisory, which must fail
#[test(tokio::test)]
async fn extract_advisory() -> anyhow::Result<()> {
    assert_extract_fn("advisory", "csaf/cve-2023-0044.json", async |result| {
        assert_eq!(result.status(), 400)
    })
    .await
}

/// Asking for advisory, which must fail
#[test(tokio::test)]
async fn invalid_purl() -> anyhow::Result<()> {
    assert_extract_with(
        "cyclonedx",
        "cyclonedx/invalid-purl.json",
        json!({
            "A": {
                "purls": [],
            },
            "simple": {
                "purls": [],
            }
        }),
        json!(["failed to parse purl: packageurl problem missing scheme"]),
        "cyclonedx",
    )
    .await
}

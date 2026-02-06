use super::client::{ApiClient, ApiError};
use super::sbom::{ListParams, delete_by_query, list};
use serde_json::json;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper function to create a test client connected to a mock server
async fn create_test_client() -> (ApiClient, MockServer) {
    let mock_server = MockServer::start().await;
    let client = ApiClient::new(&mock_server.uri(), None, None);
    (client, mock_server)
}

/// Helper function to create a mock response with 3 SBOM items
fn create_mock_sbom_response() -> serde_json::Value {
    json!({
        "items": [
            {
                "id": "urn:uuid:019c2415-ccb6-7081-a80a-9bd15137faeb",
                "document_id": "https://access.redhat.com/security/data/sbom/spdx/MTV-2.6",
                "labels": {
                    "type": "spdx"
                },
                "data_licenses": ["CC0-1.0"],
                "published": "2024-09-17T11:31:02Z",
                "authors": ["Organization: Red Hat Product Security (secalert@redhat.com)"],
                "suppliers": [],
                "name": "MTV-2.6",
                "number_of_packages": 5388,
                "sha256": "sha256:c7caabdc60d456efbed6e3634c9969c4ca04b41216e7e951bfd44510bf565614",
                "sha384": "sha384:7c5452eee045931d53640986bf8d7e7ba7f5ffcc3956563d3e46571e5759ca7f8f64c4ba7a6c1ac316ead118d3ea8ed1",
                "sha512": "sha512:411b78bf380851082064da58a465620b707dec0f65a7c84cd2c563862d87b61d14aa4b35657ce91d9f60eb387869627a92e3eb23d35423b843df2b89c1d7e391",
                "size": 8941362,
                "ingested": "2026-02-03T15:18:54.375162Z",
                "described_by": [
                    {
                        "id": "SPDXRef-018cf2a3-f3dd-4100-b0c0-2f1fe97d0419",
                        "name": "MTV-2.6",
                        "group": null,
                        "version": "2.6",
                        "purl": [],
                        "cpe": [
                            "cpe:/a:redhat:migration_toolkit_virtualization:2.6:*:el9:*",
                            "cpe:/a:redhat:migration_toolkit_virtualization:2.6:*:el8:*"
                        ],
                        "licenses": [
                            {
                                "license_name": "NOASSERTION",
                                "license_type": "declared"
                            },
                            {
                                "license_name": "NOASSERTION",
                                "license_type": "concluded"
                            }
                        ],
                        "licenses_ref_mapping": []
                    }
                ]
            },
            {
                "id": "urn:uuid:019c2415-ccb6-7081-a80a-9bd15137faec",
                "document_id": "https://access.redhat.com/security/data/sbom/spdx/MTV-2.7",
                "labels": {
                    "type": "spdx"
                },
                "data_licenses": ["MIT"],
                "published": "2024-09-18T12:00:00Z",
                "authors": ["Organization: Red Hat Product Security (secalert@redhat.com)"],
                "suppliers": [],
                "name": "MTV-2.7",
                "number_of_packages": 400,
                "sha256": "sha256:d8ebdc60d456efbed6e3634c9969c4ca04b41216e7e951bfd44510bf565615",
                "sha384": "sha384:8d5452eee045931d53640986bf8d7e7ba7f5ffcc3956563d3e46571e5759ca7f8f64c4ba7a6c1ac316ead118d3ea8ed2",
                "sha512": "sha512:522b78bf380851082064da58a465620b707dec0f65a7c84cd2c563862d87b61d14aa4b35657ce91d9f60eb387869627a92e3eb23d35423b843df2b89c1d7e392",
                "size": 7500000,
                "ingested": "2026-02-04T10:00:00.000000Z",
                "described_by": [
                    {
                        "id": "SPDXRef-018cf2a3-f3dd-4100-b0c0-2f1fe97d0420",
                        "name": "MTV-2.7",
                        "group": null,
                        "version": "2.7",
                        "purl": [],
                        "cpe": [
                            "cpe:/a:redhat:migration_toolkit_virtualization:2.7:*:el9:*"
                        ],
                        "licenses": [
                            {
                                "license_name": "MIT",
                                "license_type": "declared"
                            }
                        ],
                        "licenses_ref_mapping": []
                    }
                ]
            },
            {
                "id": "urn:uuid:019c2415-ccb6-7081-a80a-9bd15137faed",
                "document_id": "https://access.redhat.com/security/data/sbom/spdx/MTV-2.8",
                "labels": {
                    "type": "cyclonedx"
                },
                "data_licenses": ["Apache-2.0"],
                "published": "2024-09-19T13:00:00Z",
                "authors": ["Organization: Red Hat Product Security (secalert@redhat.com)"],
                "suppliers": [],
                "name": "MTV-2.8",
                "number_of_packages": 250,
                "sha256": "sha256:e9fbdc60d456efbed6e3634c9969c4ca04b41216e7e951bfd44510bf565616",
                "sha384": "sha384:9e5452eee045931d53640986bf8d7e7ba7f5ffcc3956563d3e46571e5759ca7f8f64c4ba7a6c1ac316ead118d3ea8ed3",
                "sha512": "sha512:633b78bf380851082064da58a465620b707dec0f65a7c84cd2c563862d87b61d14aa4b35657ce91d9f60eb387869627a92e3eb23d35423b843df2b89c1d7e393",
                "size": 6000000,
                "ingested": "2026-02-05T08:00:00.000000Z",
                "described_by": [
                    {
                        "id": "SPDXRef-018cf2a3-f3dd-4100-b0c0-2f1fe97d0421",
                        "name": "MTV-2.8",
                        "group": null,
                        "version": "2.8",
                        "purl": [],
                        "cpe": [
                            "cpe:/a:redhat:migration_toolkit_virtualization:2.8:*:el9:*"
                        ],
                        "licenses": [
                            {
                                "license_name": "Apache-2.0",
                                "license_type": "declared"
                            }
                        ],
                        "licenses_ref_mapping": []
                    }
                ]
            }
        ],
        "total": 3
    })
}

#[tokio::test]
async fn test_list_sboms_success() {
    let (client, mock_server) = create_test_client().await;

    let mock_response = create_mock_sbom_response();

    Mock::given(method("GET"))
        .and(path("/api/v2/sbom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&mock_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let params = ListParams {
        q: None,
        limit: Some(10),
        offset: Some(0),
        sort: None,
    };

    let result = list(&client, &params).await;

    assert!(result.is_ok());
    let response_json: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(response_json["total"], 3);
    assert_eq!(response_json["items"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn test_delete_by_query_success() {
    let (client, mock_server) = create_test_client().await;

    let mock_response = create_mock_sbom_response();

    Mock::given(method("GET"))
        .and(path("/api/v2/sbom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&mock_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("DELETE"))
        .and(path_regex(r"^/api/v2/sbom/urn:uuid:019c.*$"))
        .respond_with(ResponseTemplate::new(204))
        .expect(3)
        .mount(&mock_server)
        .await;

    let result: Result<crate::api::sbom::DeleteResult, ApiError> =
        delete_by_query(&client, Some("name:test"), false, 2, None).await;

    assert!(result.is_ok());
    let delete_result = result.unwrap();
    assert_eq!(delete_result.total, 3);
    assert_eq!(delete_result.deleted, 3);
    assert_eq!(delete_result.skipped, 0);
    assert_eq!(delete_result.failed, 0);
}

#[tokio::test]
async fn test_delete_by_query_dry_run() {
    let (client, mock_server) = create_test_client().await;

    let mock_response = create_mock_sbom_response();

    Mock::given(method("GET"))
        .and(path("/api/v2/sbom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&mock_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result: Result<crate::api::sbom::DeleteResult, ApiError> =
        delete_by_query(&client, Some("name:test"), true, 2, None).await;

    assert!(result.is_ok());
    let delete_result = result.unwrap();
    assert_eq!(delete_result.total, 3);
    assert_eq!(delete_result.deleted, 0);
    assert_eq!(delete_result.skipped, 0);
    assert_eq!(delete_result.failed, 0);
}

#[tokio::test]
async fn test_delete_by_query_with_not_found_and_failed() {
    let (client, mock_server) = create_test_client().await;

    let mock_response = create_mock_sbom_response();

    Mock::given(method("GET"))
        .and(path("/api/v2/sbom"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&mock_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(
            "/api/v2/sbom/urn:uuid:019c2415-ccb6-7081-a80a-9bd15137faeb",
        ))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(
            "/api/v2/sbom/urn:uuid:019c2415-ccb6-7081-a80a-9bd15137faec",
        ))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(
            "/api/v2/sbom/urn:uuid:019c2415-ccb6-7081-a80a-9bd15137faed",
        ))
        .respond_with(ResponseTemplate::new(502))
        .expect(3)
        .mount(&mock_server)
        .await;

    let result: Result<crate::api::sbom::DeleteResult, ApiError> =
        delete_by_query(&client, Some("name:test"), false, 2, None).await;

    assert!(result.is_ok());
    let delete_result = result.unwrap();
    assert_eq!(delete_result.total, 3);
    assert_eq!(delete_result.deleted, 1);
    assert_eq!(delete_result.skipped, 1);
    assert_eq!(delete_result.failed, 1);
}

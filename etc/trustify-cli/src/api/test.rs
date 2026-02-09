use super::client::{ApiClient, ApiError};
use super::sbom::{ListParams, delete_by_query, list};
use crate::utils;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper function to create a test client connected to a mock server
async fn create_test_client() -> (ApiClient, MockServer) {
    let mock_server = MockServer::start().await;
    let client = ApiClient::new(&mock_server.uri(), None, None);
    (client, mock_server)
}

#[tokio::test]
async fn test_list_sboms_success() {
    let (client, mock_server) = create_test_client().await;

    let mock_response = utils::create_mock_sbom_response();

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

    let mock_response = utils::create_mock_sbom_response();

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

    let mock_response = utils::create_mock_sbom_response();

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

    let mock_response = utils::create_mock_sbom_response();

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

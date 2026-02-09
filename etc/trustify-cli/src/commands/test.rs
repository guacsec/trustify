use crate::Context;
use crate::commands::sbom::SbomCommands;
use crate::utils;
use std::process::ExitCode;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_context() -> (Context, MockServer) {
        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let client = crate::ApiClient::new(&base_url, None, None);
        let config = crate::config::Config {
            url: base_url,
            sso_url: None,
            client_id: None,
            client_secret: None,
        };

        (Context { config, client }, mock_server)
    }

    #[tokio::test]
    async fn test_delete_command_with_id_success() {
        let (ctx, mock_server) = create_test_context().await;

        Mock::given(method("DELETE"))
            .and(path("/api/v2/sbom/test-id-123"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock_server)
            .await;

        let command = SbomCommands::Delete {
            id: Some("test-id-123".to_string()),
            query: None,
            dry_run: false,
            concurrency: 10,
            limit: None,
        };

        let result = command.run(&ctx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_by_query_success() {
        let (ctx, mock_server) = create_test_context().await;

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

        let command = SbomCommands::Delete {
            id: None,
            query: Some("name:test".to_string()),
            dry_run: false,
            concurrency: 2,
            limit: None,
        };

        let result = command.run(&ctx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ExitCode::SUCCESS);
    }

    #[tokio::test]
    async fn test_delete_by_query_dry_run() {
        let (ctx, mock_server) = create_test_context().await;

        let mock_response = utils::create_mock_sbom_response();

        Mock::given(method("GET"))
            .and(path("/api/v2/sbom"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&mock_response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let command = SbomCommands::Delete {
            id: None,
            query: Some("name:test".to_string()),
            dry_run: true,
            concurrency: 2,
            limit: None,
        };

        let result = command.run(&ctx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ExitCode::SUCCESS);
    }

    #[tokio::test]
    async fn test_delete_by_query_with_not_found_and_failed() {
        let (ctx, mock_server) = create_test_context().await;

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

        let command = SbomCommands::Delete {
            id: None,
            query: Some("name:test".to_string()),
            dry_run: false,
            concurrency: 2,
            limit: None,
        };

        let result = command.run(&ctx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ExitCode::SUCCESS);
    }
}

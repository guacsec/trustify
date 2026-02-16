mod assignment;
mod create;
mod delete;
mod list;
mod update;

use crate::common::test::{GroupResponse, IfMatchType, add_if_match};
use actix_http::body::to_bytes;
use actix_web::{http, test::TestRequest};
use http::StatusCode;
use serde_json::{Value, json};
use trustify_entity::labels::Labels;
use trustify_test_context::call::CallService;

struct Update {
    id: String,
    name: String,
    parent: Option<String>,
    description: Option<Option<String>>,
    labels: Option<Labels>,
    if_match_type: IfMatchType,
    etag: String,
    expected_status: StatusCode,
}

impl Update {
    pub fn new(id: impl Into<String>, name: impl Into<String>, etag: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            parent: None,
            description: None,
            labels: None,
            if_match_type: IfMatchType::Correct,
            etag: etag.into(),
            expected_status: StatusCode::NO_CONTENT,
        }
    }

    pub fn parent(mut self, parent: Option<&str>) -> Self {
        self.parent = parent.map(|s| s.to_string());
        self
    }

    pub fn description(mut self, description: Option<impl Into<String>>) -> Self {
        self.description = Some(description.map(|s| s.into()));
        self
    }

    pub fn labels(mut self, labels: Labels) -> Self {
        self.labels = Some(labels);
        self
    }

    pub fn if_match(mut self, if_match_type: IfMatchType) -> Self {
        self.if_match_type = if_match_type;
        self
    }

    pub fn expect_status(mut self, status: StatusCode) -> Self {
        self.expected_status = status;
        self
    }

    pub async fn execute(self, app: &impl CallService) -> anyhow::Result<()> {
        let mut update_body = json!({"name": &self.name});

        if let Some(parent_id) = &self.parent {
            update_body["parent"] = json!(parent_id);
        }
        if let Some(description) = &self.description {
            update_body["description"] = json!(description);
        }
        if let Some(labels) = &self.labels {
            update_body["labels"] = serde_json::to_value(labels)?;
        }

        let request = TestRequest::put()
            .uri(&format!("/api/v2/group/sbom/{}", &self.id))
            .set_json(update_body);

        let request = add_if_match(request, self.if_match_type, &self.etag);

        let response = app.call_service(request.to_request()).await;
        assert_eq!(response.status(), self.expected_status);

        Ok(())
    }
}

/// Helper to get a group and extract etag
async fn get_group_helper(
    app: &impl CallService,
    id: &str,
) -> Result<GroupResponse, anyhow::Error> {
    let response = app
        .call_service(
            TestRequest::get()
                .uri(&format!("/api/v2/group/sbom/{}", id))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let headers = response.headers().clone();
    let body = to_bytes(response.into_body()).await.expect("must decode");
    let result: Value = serde_json::from_slice(&body)?;

    Ok(GroupResponse {
        id: id.to_string(),
        etag: headers
            .get(&http::header::ETAG)
            .expect("must have etag header")
            .to_str()
            .expect("etag must be valid string")
            .to_string(),
        location: None,
        body: result,
    })
}

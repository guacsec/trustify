use actix_http::{body::to_bytes, header::HeaderMap};
use actix_web::{http, test::TestRequest};
use anyhow::Context;
use http::StatusCode;
use serde_json::{Value, json};
use std::collections::HashMap;
use trustify_entity::labels::Labels;
use trustify_test_context::call::CallService;

#[derive(Debug, Clone, Copy)]
pub enum IfMatchType {
    Wildcard,
    Correct,
    Missing,
    Wrong,
}

pub struct GroupResponse {
    pub id: String,
    pub etag: String,
    pub location: Option<String>,
    pub body: Value,
}

pub trait FromCreateResponse: Sized {
    fn from_create_response(body: Value, headers: HeaderMap) -> Self;
}

impl FromCreateResponse for GroupResponse {
    fn from_create_response(body: Value, headers: HeaderMap) -> Self {
        let result: anyhow::Result<GroupResponse> =
            FromCreateResponse::from_create_response(body, headers);
        result.expect("failed to parse response")
    }
}

impl FromCreateResponse for anyhow::Result<GroupResponse> {
    fn from_create_response(body: Value, headers: HeaderMap) -> Self {
        let location = headers
            .get(&http::header::LOCATION)
            .context("location must be present")?
            .to_str()
            .context("location must be a string")?
            .to_string();

        let id = body["id"].as_str().context("must be a string")?.to_string();

        assert_eq!(
            location,
            format!("/api/v2/group/sbom/{id}").as_str(),
            "must return a relative URL to the group"
        );

        Ok(GroupResponse {
            id,
            etag: headers
                .get(&http::header::ETAG)
                .context("must have etag header")?
                .to_str()
                .context("etag must be valid string")
                .map(ToString::to_string)?,
            location: Some(location),
            body,
        })
    }
}

impl FromCreateResponse for () {
    fn from_create_response(_: Value, _: HeaderMap) -> Self {}
}

pub struct Create {
    name: String,
    parent: Option<String>,
    labels: Labels,
    expected_status: StatusCode,
}

impl Create {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            labels: Default::default(),
            parent: None,
            expected_status: StatusCode::CREATED,
        }
    }

    pub fn parent(mut self, parent: Option<&str>) -> Self {
        self.parent = parent.map(|s| s.to_string());
        self
    }

    pub fn labels(mut self, labels: Labels) -> Self {
        self.labels = labels;
        self
    }

    pub fn expect_status(mut self, status: StatusCode) -> Self {
        self.expected_status = status;
        self
    }

    pub async fn execute<R>(self, app: &impl CallService) -> anyhow::Result<R>
    where
        R: FromCreateResponse,
    {
        let mut request_body = json!({"name": &self.name});
        if let Some(parent_id) = &self.parent {
            request_body["parent"] = json!(parent_id);
        }
        request_body["labels"] = serde_json::to_value(self.labels)?;

        let response = app
            .call_service(
                TestRequest::post()
                    .uri("/api/v2/group/sbom")
                    .set_json(request_body)
                    .to_request(),
            )
            .await;

        assert_eq!(response.status(), self.expected_status);

        let headers = response.headers().clone();
        let body = to_bytes(response.into_body()).await.expect("must decode");
        let body: Value = serde_json::from_slice(&body)?;

        Ok(R::from_create_response(body, headers))
    }
}

pub fn add_if_match(request: TestRequest, if_match_type: IfMatchType, etag: &str) -> TestRequest {
    match if_match_type {
        IfMatchType::Correct => request.insert_header((http::header::IF_MATCH, etag)),
        IfMatchType::Wildcard => request.insert_header((http::header::IF_MATCH, "*")),
        IfMatchType::Missing => request,
        IfMatchType::Wrong => {
            request.insert_header((http::header::IF_MATCH, "\"wrong-revision-123\""))
        }
    }
}

pub struct AssignmentResponse {
    pub group_ids: Vec<String>,
    pub etag: String,
}

pub async fn read_assignments(
    app: &impl CallService,
    sbom_id: &str,
) -> anyhow::Result<AssignmentResponse> {
    let response = app
        .call_service(
            TestRequest::get()
                .uri(&format!("/api/v2/group/sbom-assignment/{}", sbom_id))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let headers = response.headers().clone();
    let group_ids: Vec<String> = actix_web::test::read_body_json(response).await;

    Ok(AssignmentResponse {
        group_ids,
        etag: headers
            .get(&http::header::ETAG)
            .expect("must have etag header")
            .to_str()
            .expect("etag must be valid string")
            .to_string(),
    })
}

pub struct UpdateAssignments {
    sbom_id: String,
    group_ids: Vec<String>,
    if_match_type: IfMatchType,
    etag: Option<String>,
    expected_status: StatusCode,
}

impl UpdateAssignments {
    pub fn new(sbom_id: impl Into<String>) -> Self {
        Self {
            sbom_id: sbom_id.into(),
            group_ids: vec![],
            if_match_type: IfMatchType::Correct,
            etag: None,
            expected_status: StatusCode::NO_CONTENT,
        }
    }

    pub fn etag(mut self, etag: impl Into<String>) -> Self {
        self.etag = Some(etag.into());
        self
    }

    pub fn group_ids(mut self, group_ids: Vec<String>) -> Self {
        self.group_ids = group_ids;
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
        let initial_etag = self.etag.clone();

        let request = TestRequest::put()
            .uri(&format!("/api/v2/group/sbom-assignment/{}", &self.sbom_id))
            .set_json(&self.group_ids);

        let request = match self.etag {
            Some(etag) => add_if_match(request, self.if_match_type, &etag),
            None => request,
        };

        let response = app.call_service(request.to_request()).await;
        assert_eq!(response.status(), self.expected_status);

        let assignments_after = read_assignments(app, &self.sbom_id).await?;

        if let Some(initial_etag) = initial_etag {
            if self.expected_status.is_success() {
                assert_ne!(
                    initial_etag, assignments_after.etag,
                    "etag should have changed after successful update"
                );
            } else {
                assert_eq!(
                    initial_etag, assignments_after.etag,
                    "etag should not have changed after failed update"
                );
            }
        }

        Ok(())
    }
}

pub struct Group {
    pub name: String,
    pub labels: Labels,
    pub children: Vec<Group>,
}

impl Group {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            labels: Default::default(),
            children: Default::default(),
        }
    }

    pub fn group(mut self, group: impl Into<Group>) -> Self {
        self.children.push(group.into());
        self
    }

    pub fn labels(mut self, labels: impl Into<Labels>) -> Self {
        self.labels = labels.into();
        self
    }
}

impl From<&str> for Group {
    fn from(value: &str) -> Self {
        Self {
            name: value.to_string(),
            children: vec![],
            labels: Labels::default(),
        }
    }
}

pub enum GroupRef {
    ByName(&'static [&'static str]),
    ById(&'static str),
}

pub fn resolve_group_refs(
    ids: &HashMap<Vec<String>, String>,
    refs: impl IntoIterator<Item = GroupRef>,
) -> String {
    refs.into_iter()
        .map(|r| {
            let resolved = match r {
                GroupRef::ByName(name) => locate_id(ids, name),
                GroupRef::ById(id) => id.to_string(),
            };
            format!("group={resolved}")
        })
        .collect::<Vec<_>>()
        .join("&")
}

pub fn locate_id(
    ids: &HashMap<Vec<String>, String>,
    id: impl IntoIterator<Item = impl ToString>,
) -> String {
    let path: Vec<String> = id.into_iter().map(|s| s.to_string()).collect();
    ids.get(&path)
        .unwrap_or_else(|| panic!("ID not found for path: {:?}", path))
        .clone()
}

pub async fn create_groups(
    app: &impl CallService,
    groups: Vec<Group>,
) -> anyhow::Result<HashMap<Vec<String>, String>> {
    let mut result = HashMap::new();

    for group in groups {
        create_group_recursive(app, group, None, vec![], &mut result).await?;
    }

    Ok(result)
}

async fn create_group_recursive(
    app: &impl CallService,
    group: Group,
    parent_id: Option<&str>,
    mut path: Vec<String>,
    result: &mut HashMap<Vec<String>, String>,
) -> anyhow::Result<()> {
    path.push(group.name.clone());

    let created: GroupResponse = Create::new(&group.name)
        .parent(parent_id)
        .labels(group.labels)
        .execute(app)
        .await?;

    result.insert(path.clone(), created.id.clone());

    for child in group.children {
        Box::pin(async {
            create_group_recursive(app, child, Some(&created.id), path.clone(), result).await
        })
        .await?;
    }

    Ok(())
}

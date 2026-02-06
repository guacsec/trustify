use crate::test::caller;
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use serde_json::{Value, json};
use std::fmt::Display;
use trustify_common::id::Id;
use trustify_entity::labels::{Labels, Update};
use trustify_test_context::{TrustifyContext, call::CallService};
use uuid::Uuid;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Api {
    Advisory,
    Sbom,
}

impl Api {
    pub fn into_uri(self, id: impl Display, suffix: Option<&str>) -> String {
        let suffix = suffix.unwrap_or("");
        match self {
            Self::Advisory => format!(
                "/api/v2/advisory/urn:uuid:{}{suffix}",
                urlencoding::encode(&id.to_string())
            ),
            Self::Sbom => format!(
                "/api/v2/sbom/urn:uuid:{}{suffix}",
                urlencoding::encode(&id.to_string())
            ),
        }
    }
}

/// get labels and assert equality
pub async fn assert_labels<C: CallService>(
    app: &C,
    api: Api,
    id: impl Display,
    labels: Value,
) -> anyhow::Result<()> {
    let request = TestRequest::get().uri(&api.into_uri(id, None)).to_request();
    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    let json: Value = actix_web::test::read_body_json(response).await;

    assert_eq!(labels, json["labels"]);

    Ok(())
}

/// Test updating labels
pub async fn update_labels(
    ctx: &TrustifyContext,
    api: Api,
    path: &str,
    r#type: &str,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let result = ctx.ingest_document(path).await?;
    let id = &result.id;

    assert_labels(
        &app,
        api,
        id,
        json!({
            "source": "TrustifyContext",
            "type": r#type,
        }),
    )
    .await?;

    // mutate labels, add one, replace one, delete one

    let request = TestRequest::patch()
        .uri(&api.into_uri(id, Some("/label")))
        .set_json(Update::new().extend([
            ("foo", Some("bar")),             // set
            ("source", Some("different")),    // replace
            ("type", None),                   // delete
            ("space ", Some(" with space ")), // with space
            ("empty", Some("")),              // empty label, aka tag
        ]))
        .to_request();
    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    assert_labels(
        &app,
        api,
        id,
        json!({
            "source": "different",
            "foo": "bar",
            "space": "with space",
            "empty": "",
        }),
    )
    .await?;

    // not perform a "replace" operation

    let request = TestRequest::put()
        .uri(&api.into_uri(id, Some("/label")))
        .set_json(Labels::new().extend([("bar", "foo"), ("foo ", " bar ")]))
        .to_request();
    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    assert_labels(
        &app,
        api,
        id,
        json!({
            "bar": "foo",
            "foo": "bar",
        }),
    )
    .await?;

    // try setting invalid labels

    let request = TestRequest::put()
        .uri(&api.into_uri(id, Some("/label")))
        .set_json(Labels::new().extend([(" ", "foo")]))
        .to_request();
    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let request = TestRequest::put()
        .uri(&api.into_uri(id, Some("/label")))
        .set_json(Labels::new().extend([("foo", "bar=baz")]))
        .to_request();
    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // done

    Ok(())
}

/// Test updating labels, for a document that does not exist
pub async fn update_labels_not_found(
    ctx: &TrustifyContext,
    api: Api,
    path: &str,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_document(path).await?;

    let request = TestRequest::patch()
        .uri(&api.into_uri(Id::Uuid(Uuid::now_v7()), Some("/label")))
        .set_json(Update::new().extend([("foo", Some("1")), ("bar", Some("2"))]))
        .to_request();

    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

use crate::service::{Error, UserPreferenceService};
use actix_web::{
    HttpResponse, Responder, delete, get,
    http::header::{self, ETag, EntityTag, IfMatch},
    put, web,
};
use trustify_auth::authenticator::user::UserDetails;
use trustify_common::{db::Database, model::Revisioned};

/// mount the "user" module
pub fn configure(svc: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    svc.app_data(web::Data::new(UserPreferenceService::new(db)))
        .service(set)
        .service(get)
        .service(delete);
}

#[utoipa::path(
    tag = "userPreferences",
    operation_id = "getUserPreferences",
    params(
        ("key", Path, description = "The key to the user preferences"),
    ),
    responses(
        (
            status = 200,
            description = "User preference stored under this key",
            body = serde_json::Value,
            headers(
                ("etag" = String, description = "Revision ID")
            )
        ),
        (status = 404, description = "The user preference key could not be found"),
    )
)]
#[get("/v3/userPreference/{key}")]
/// Get user preferences
async fn get(
    service: web::Data<UserPreferenceService>,
    key: web::Path<String>,
    user: UserDetails,
) -> Result<impl Responder, Error> {
    Ok(match service.get(user.id, key.into_inner()).await? {
        Some(Revisioned { value, revision }) => HttpResponse::Ok()
            .append_header((header::ETAG, ETag(EntityTag::new_strong(revision))))
            .json(value),
        None => HttpResponse::NotFound().finish(),
    })
}

#[utoipa::path(
    tag = "userPreferences",
    operation_id = "setUserPreferences",
    request_body = serde_json::Value,
    params(
        ("key", Path, description = "The key to the user preferences"),
        ("if-match" = Option<String>, Header, description = "The revision to update"),
    ),
    responses(
        (
            status = 200,
            description = "User preference stored under this key",
            headers(
                ("etag" = String, description = "Revision ID")
            )
        ),
        (status = 412, description = "The provided If-Match revision did not match the actual revision")
    )
)]
#[put("/v3/userPreference/{key}")]
/// Set user preferences
async fn set(
    service: web::Data<UserPreferenceService>,
    key: web::Path<String>,
    user: UserDetails,
    web::Header(if_match): web::Header<IfMatch>,
    web::Json(data): web::Json<serde_json::Value>,
) -> Result<impl Responder, Error> {
    let revision = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    };

    let Revisioned {
        value: (),
        revision,
    } = service
        .set(user.id, key.into_inner(), revision, data)
        .await?;

    Ok(HttpResponse::NoContent()
        .append_header((header::ETAG, ETag(EntityTag::new_strong(revision))))
        .finish())
}

#[utoipa::path(
    tag = "userPreferences",
    operation_id = "deleteUserPreferences",
    request_body = serde_json::Value,
    params(
        ("key", Path, description = "The key to the user preferences"),
        ("if-match" = Option<String>, Header, description = "The revision to delete"),
    ),
    responses(
        (status = 201, description = "User preferences are deleted"),
        (status = 412, description = "The provided If-Match revision did not match the actual revision")
    )
)]
#[delete("/v3/userPreference/{key}")]
/// Delete user preferences
async fn delete(
    service: web::Data<UserPreferenceService>,
    key: web::Path<String>,
    user: UserDetails,
    web::Header(if_match): web::Header<IfMatch>,
) -> Result<impl Responder, Error> {
    let revision = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    };

    service.delete(user.id, key.into_inner(), revision).await?;
    Ok(HttpResponse::NoContent().finish())
}

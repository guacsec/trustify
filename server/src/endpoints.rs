use actix_web::{
    HttpRequest, HttpResponse, get,
    http::header::AUTHORIZATION,
    web::{self},
};
use build_info::BuildInfo;
use std::sync::Arc;
use trustify_auth::authenticator::Authenticator;
use trustify_common::middleware::ReadOnlyState;
use utoipa_actix_web::service_config::ServiceConfig;

pub fn configure(svc: &mut ServiceConfig, auth: Option<Arc<Authenticator>>, read_only: bool) {
    let mut scope = utoipa_actix_web::scope("/.well-known/trustify");

    if let Some(auth) = auth {
        scope = scope.app_data(web::Data::from(auth));
    }
    scope = scope.app_data(web::Data::new(ReadOnlyState(read_only)));

    svc.service(scope.service(info));
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct Info<'a> {
    version: &'a str,
    read_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = serde_json::Object)]
    build: Option<&'a BuildInfo>,
}

build_info::build_info!(fn build_info);

#[utoipa::path(
    responses(
        (status = 200, description = "Get information", body = inline(Info)),
    ),
)]
#[get("")]
pub async fn info(
    req: HttpRequest,
    auth: Option<web::Data<Authenticator>>,
    read_only: ReadOnlyState,
) -> HttpResponse {
    let details = match auth {
        // authentication is disabled, enable details
        None => true,
        Some(auth) => {
            if let Some(bearer) = req
                .headers()
                .get(AUTHORIZATION)
                .and_then(|auth| auth.to_str().ok())
                .and_then(|auth| auth.strip_prefix("Bearer "))
            {
                // enable details if we have a valid token
                auth.validate_token(&bearer).await.is_ok()
            } else {
                // no token that we can use, disable details
                false
            }
        }
    };

    HttpResponse::Ok().json(Info {
        version: env!("CARGO_PKG_VERSION"),
        read_only: *read_only,
        build: details.then(build_info),
    })
}

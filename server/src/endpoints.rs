use actix_web::{
    HttpRequest, HttpResponse, get,
    http::header::AUTHORIZATION,
    web::{self},
};
use build_info::BuildInfo;
use std::sync::Arc;
use trustify_api::FrontendInfo;
use trustify_auth::authenticator::Authenticator;
use trustify_common::{
    capability::{ActiveCapabilities, Capability, Variants},
    middleware::ReadOnlyState,
};
use utoipa_actix_web::service_config::ServiceConfig;

pub fn configure(
    svc: &mut ServiceConfig,
    auth: Option<Arc<Authenticator>>,
    read_only: bool,
    frontend: FrontendInfo,
) {
    let mut scope = utoipa_actix_web::scope("/.well-known/trustify");

    if let Some(auth) = auth {
        scope = scope.app_data(web::Data::from(auth));
    }
    scope = scope.app_data(web::Data::new(ReadOnlyState(read_only)));
    scope = scope.app_data(web::Data::new(frontend));

    svc.service(scope.service(info));
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct Info<'a> {
    version: &'a str,
    read_only: bool,
    /// Deprecated — use the `capabilities` array instead.
    exploit_intelligence: bool,
    capabilities: Vec<String>,
    #[schema(value_type = HashMap<String, Vec<String>>)]
    variants: Variants,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = serde_json::Object)]
    build: Option<&'a BuildInfo>,
    frontend: FrontendInfo,
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
    capabilities: web::Data<ActiveCapabilities>,
    variants: web::Data<Variants>,
    frontend: web::Data<FrontendInfo>,
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
        exploit_intelligence: capabilities.contains(&Capability::ExploitIntelligence),
        capabilities: capabilities.as_sorted_vec(),
        variants: variants.get_ref().clone(),
        build: details.then(build_info),
        frontend: frontend.get_ref().clone(),
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use actix_web::{
        App,
        test::{TestRequest, call_and_read_body_json, init_service},
    };
    use rstest::rstest;
    use utoipa_actix_web::AppExt;

    #[rstest]
    #[case::enabled_writable(true, false)]
    #[case::enabled_read_only(true, true)]
    #[case::disabled_writable(false, false)]
    #[case::disabled_read_only(false, true)]
    #[actix_web::test]
    async fn correlation_discovery(#[case] enabled: bool, #[case] read_only: bool) {
        let capabilities = if enabled {
            ActiveCapabilities::from_iter([Capability::Correlation])
        } else {
            ActiveCapabilities::default()
        };
        let app = init_service(
            App::new()
                .app_data(web::Data::new(capabilities))
                .app_data(web::Data::new(Variants::default()))
                .into_utoipa_app()
                .configure(|svc| configure(svc, None, read_only, FrontendInfo { oidc: None }))
                .into_app(),
        )
        .await;
        let response: serde_json::Value = call_and_read_body_json(
            &app,
            TestRequest::get().uri("/.well-known/trustify").to_request(),
        )
        .await;
        assert_eq!(response["readOnly"], read_only);
        assert_eq!(
            response["capabilities"],
            if enabled {
                serde_json::json!(["correlation"])
            } else {
                serde_json::json!([])
            }
        );
    }
}

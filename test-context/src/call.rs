use actix_http::Request;
use actix_web::{
    App, Error,
    dev::{Service, ServiceResponse},
    web,
};
use bytes::Bytes;
use serde::de::DeserializeOwned;
use std::future::Future;
use trustify_auth::authorizer::Authorizer;
use trustify_common::middleware::StdMiddleware;
use utoipa_actix_web::{AppExt, service_config::ServiceConfig};

/// A trait wrapping an `impl Service` in a way that we can pass it as a reference.
pub trait CallService {
    fn call_service(&self, s: Request) -> impl Future<Output = ServiceResponse>;
    fn call_and_read_body(&self, r: Request) -> impl Future<Output = Bytes>;
    fn call_and_read_body_json<T: DeserializeOwned>(&self, r: Request) -> impl Future<Output = T>;
}

impl<S> CallService for S
where
    S: Service<Request, Response = ServiceResponse, Error = Error>,
{
    async fn call_service(&self, r: Request) -> ServiceResponse {
        actix_web::test::call_service(self, r).await
    }

    async fn call_and_read_body(&self, r: Request) -> Bytes {
        actix_web::test::call_and_read_body(self, r).await
    }

    async fn call_and_read_body_json<T: DeserializeOwned>(&self, r: Request) -> T {
        actix_web::test::call_and_read_body_json(self, r).await
    }
}

/// Creates a test app with endpoints scoped under `/api`.
pub async fn caller<F>(cfg_fn: F) -> anyhow::Result<impl CallService>
where
    F: FnOnce(&mut ServiceConfig),
{
    caller_app(|svc| {
        svc.service(utoipa_actix_web::scope("/api").configure(cfg_fn));
    })
    .await
}

/// Creates a test app with root-level configuration and standard middleware.
pub async fn caller_app<F>(cfg_fn: F) -> anyhow::Result<impl CallService>
where
    F: FnOnce(&mut ServiceConfig),
{
    Ok(actix_web::test::init_service(
        App::new()
            .std_middleware()
            .into_utoipa_app()
            .app_data(web::PayloadConfig::default().limit(5 * 1024 * 1024))
            .app_data(web::Data::new(Authorizer::new(None)))
            .configure(cfg_fn)
            .into_app(),
    )
    .await)
}

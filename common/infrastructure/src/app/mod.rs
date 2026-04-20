pub mod http;

use actix_cors::Cors;
use actix_web::{
    App, Error,
    body::MessageBody,
    dev::{ServiceFactory, ServiceRequest, ServiceResponse},
    middleware::{Compress, Logger},
    web,
};
use actix_web_extras::middleware::Condition;
use actix_web_httpauth::{extractors::bearer::BearerAuth, middleware::HttpAuthentication};
use futures::{FutureExt, future::LocalBoxFuture};
use opentelemetry_instrumentation_actix_web::{RequestMetrics, RequestTracing};
use std::sync::Arc;
use trustify_auth::{authenticator::Authenticator, authorizer::Authorizer};
use trustify_common::middleware::StdMiddleware;

#[derive(Default)]
pub struct AppOptions {
    pub cors: Option<Cors>,
    pub authenticator: Option<Arc<Authenticator>>,
    pub authorizer: Authorizer,
    pub logger: Option<Logger>,
    pub tracing_logger: Option<RequestTracing>,
    pub metrics: Option<RequestMetrics>,
}

/// create a new authenticator
#[allow(clippy::type_complexity)]
pub fn new_auth(
    auth: Option<Arc<Authenticator>>,
) -> Condition<
    HttpAuthentication<
        BearerAuth,
        impl Fn(
            ServiceRequest,
            BearerAuth,
        ) -> LocalBoxFuture<'static, Result<ServiceRequest, (Error, ServiceRequest)>>,
    >,
> {
    Condition::from_option(auth.map(move |authenticator| {
        HttpAuthentication::bearer(move |req, auth| {
            let authenticator = authenticator.clone();
            Box::pin(async move {
                trustify_auth::authenticator::actix::openid_validator(req, auth, authenticator)
                    .await
            })
            .boxed_local()
        })
    }))
}

/// Build a new HTTP app in a consistent way.
///
/// Adding middleware to an HTTP app is tricky, as it requires to think about the order of adding.
/// This function should capture all the logic requires to properly set up a common application,
/// allowing some choices in the process.
pub fn new_app(
    options: AppOptions,
) -> App<
    impl ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse<impl MessageBody>,
        Error = Error,
        InitError = (),
    >,
> {
    // The order of execution is last added becomes first to be executed. So if you read the
    // following lines, read them from end to start! Middleware for services will be executed after
    // the middleware here.
    App::new()
        // Reject mutating requests when in read-only mode (runs last, after auth)
        .std_middleware()
        // Handle authentication, might fail and return early
        .wrap(new_auth(options.authenticator))
        // Handle authorization
        .app_data(web::Data::new(options.authorizer))
        // Handle CORS requests, this might finish early and not pass requests to the next entry
        .wrap(Condition::from_option(options.cors))
        // Next, record metrics for the request (should never fail)
        .wrap(Condition::from_option(options.metrics))
        // Compress everything
        .wrap(Compress::default())
        // First log the request, so that we know what happens (can't fail)
        .wrap(Condition::from_option(options.logger))
        // Enable tracing logger if configured
        .wrap(Condition::from_option(options.tracing_logger))
}

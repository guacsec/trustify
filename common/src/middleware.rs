use actix_web::{
    App, Error, FromRequest, HttpRequest, HttpResponse,
    body::{BoxBody, MessageBody},
    dev::{Payload, ServiceFactory, ServiceRequest, ServiceResponse},
    http::Method,
    middleware::from_fn,
    web,
};
use std::ops::Deref;

use crate::error::ErrorInformation;

/// Shared state indicating whether the instance is in read-only mode.
///
/// Defaults to `false` (read-write) when no state is registered in app data.
#[derive(Copy, Clone, Debug, Default)]
pub struct ReadOnlyState(pub bool);

impl Deref for ReadOnlyState {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequest for ReadOnlyState {
    type Error = Error;
    type Future = std::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let state = req
            .app_data::<web::Data<ReadOnlyState>>()
            .map(|s| *s.get_ref())
            .unwrap_or_default();
        std::future::ready(Ok(state))
    }
}

/// Middleware function that rejects mutating requests with 503 when read-only mode is active.
pub async fn read_only_guard(
    state: ReadOnlyState,
    req: ServiceRequest,
    next: actix_web::middleware::Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    if *state && !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        let resp = HttpResponse::ServiceUnavailable().json(ErrorInformation::new(
            "ReadOnly",
            "This instance is in read-only mode. Mutating operations are not available.",
        ));
        return Ok(req.into_response(resp).map_into_boxed_body());
    }

    next.call(req).await.map(|resp| resp.map_into_boxed_body())
}

/// Extension trait that adds standard application middleware.
pub trait StdMiddleware {
    /// Wraps the application with standard middleware (e.g. read-only guard).
    fn std_middleware(
        self,
    ) -> App<
        impl ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse<BoxBody>,
            Error = Error,
            InitError = (),
        >,
    >;
}

impl<T, B> StdMiddleware for App<T>
where
    B: MessageBody + 'static,
    T: ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse<B>,
            Error = Error,
            InitError = (),
            Service: 'static,
        >,
{
    fn std_middleware(
        self,
    ) -> App<
        impl ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse<BoxBody>,
            Error = Error,
            InitError = (),
        >,
    > {
        self.wrap(from_fn(read_only_guard))
    }
}

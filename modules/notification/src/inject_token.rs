use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header;
use futures::future::{LocalBoxFuture, Ready, ok};
use std::task::{Context, Poll};

pub struct QueryTokenInjector;

impl<S, B> Transform<S, ServiceRequest> for QueryTokenInjector
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = QueryTokenInjectorMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(QueryTokenInjectorMiddleware { service })
    }
}

pub struct QueryTokenInjectorMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for QueryTokenInjectorMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        if req.headers().get(header::AUTHORIZATION).is_none()
            && let Some(token) = extract_token(req.query_string())
            && let Ok(value) = format!("Bearer {token}").parse()
        {
            req.headers_mut().insert(header::AUTHORIZATION, value);
        }

        let fut = self.service.call(req);
        Box::pin(fut)
    }
}

pub(crate) fn extract_token(query: &str) -> Option<&str> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == "token").then_some(value)
    })
}

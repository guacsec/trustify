use crate::RootQuery;
use actix_web::{HttpResponse, Result, guard, web};
use async_graphql::{EmptyMutation, EmptySubscription, Schema, http::GraphiQLSource};
use async_graphql_actix_web::GraphQL;
use std::sync::Arc;
use trustify_common::db::Database;
use trustify_module_ingestor::graph::Graph;

async fn index_graphiql() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(GraphiQLSource::build().endpoint("/graphql").finish()))
}

pub fn configure(svc: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let schema = Schema::build(RootQuery::default(), EmptyMutation, EmptySubscription)
        .data::<Arc<Graph>>(Arc::new(Graph::new(db.clone())))
        .data::<Arc<Database>>(Arc::new(db))
        .finish();

    svc.route(
        "/",
        web::route().guard(guard::Post()).to(GraphQL::new(schema)),
    );
}

pub fn configure_graphiql(svc: &mut utoipa_actix_web::service_config::ServiceConfig) {
    svc.route("/", web::route().guard(guard::Get()).to(index_graphiql));
}

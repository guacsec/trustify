mod query;

#[cfg(test)]
mod tests;

use super::service::{AnalysisService, QueryOptions};
use crate::{
    endpoints::query::OwnedComponentReference,
    model::{AnalysisStatus, Node},
    parse_sbom_id,
    service::render::Renderer,
};
use actix_web::{HttpResponse, Responder, get, web};
use serde_json::json;
use trustify_auth::{
    Permission, ReadSbom, ReadSystemInformation,
    authenticator::user::UserInformation,
    authorizer::{Authorizer, Require},
    utoipa::AuthResponse,
};
use trustify_common::{
    db::{Database, query::Query},
    model::{Paginated, PaginatedResults},
};
use utoipa_actix_web::service_config::ServiceConfig;

pub fn configure(config: &mut ServiceConfig, db: Database, analysis: AnalysisService) {
    config
        .app_data(web::Data::new(analysis))
        .app_data(web::Data::new(db))
        .service(get_component)
        .service(search_component)
        .service(analysis_status)
        .service(render_sbom_graph)
        .service(search_latest_component)
        .service(get_latest_component);
}

#[derive(Clone, Debug, serde::Deserialize, utoipa::IntoParams)]
struct StatusQuery {
    #[serde(default)]
    pub details: bool,
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "status",
    params(
        StatusQuery
    ),
    responses(
        AuthResponse,
        (status = 200, description = "Analysis status", body = AnalysisStatus),
    ),
)]
#[get("/v2/analysis/status")]
/// Get the status of the analysis service.
pub async fn analysis_status(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    user: UserInformation,
    authorizer: web::Data<Authorizer>,
    web::Query(StatusQuery { details }): web::Query<StatusQuery>,
    _: Require<ReadSystemInformation>,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSystemInformation)?;
    Ok(HttpResponse::Ok().json(service.status(db.as_ref(), details).await?))
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "getComponent",
    params(
        ("key" = String, Path, description = "provide component name, URL-encoded pURL, or CPE itself"),
        Paginated,
        QueryOptions,
    ),
    responses(
        AuthResponse,
        (status = 200, description = "Retrieved component(s) located by an exact match of name, pURL, or CPE", body = PaginatedResults<Node>),
    ),
)]
#[get("/v2/analysis/component/{key}")]
/// Retrieve SBOM components (packages) by name, Package URL, or CPE.
pub async fn get_component(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    key: web::Path<String>,
    web::Query(options): web::Query<QueryOptions>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let query = OwnedComponentReference::try_from(key.as_str())?;

    Ok(HttpResponse::Ok().json(
        service
            .retrieve(&query, options, paginated, db.as_ref())
            .await?,
    ))
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "searchComponent",
    params(
        Query,
        Paginated,
        QueryOptions,
    ),
    responses(
        AuthResponse,
        (status = 200, description = "Retrieved component(s) located by search", body = PaginatedResults<Node>),
    ),
)]
#[get("/v2/analysis/component")]
/// Retrieve SBOM components (packages) by a complex search.
pub async fn search_component(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(options): web::Query<QueryOptions>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(
        service
            .retrieve(&search, options, paginated, db.as_ref())
            .await?,
    ))
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "renderSbomGraph",
    params(
        ("sbom" = String, Path, description = "ID of the SBOM"),
        ("ext" = inline(Renderer), Path, description = "Renderer to use")
    ),
    responses(
        AuthResponse,
        (status = 200, description = "A rendered version of the SBOM graph in the format requested", body = String),
        (status = 404, description = "The SBOM could not be found"),
        (status = 415, description = "Unsupported rendering format"),
    ),
)]
#[get("/v2/analysis/sbom/{sbom}/render.{ext}")]
/// Render an SBOM graph
pub async fn render_sbom_graph(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    path: web::Path<(String, String)>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let (sbom, ext) = path.into_inner();

    let Ok(ext) = serde_json::from_value::<Renderer>(json!(ext)) else {
        return Ok(HttpResponse::UnsupportedMediaType().finish());
    };

    let sbom = parse_sbom_id(&sbom)?;

    let graph = service.load_graph(db.as_ref(), sbom).await?;

    if let Some((data, content_type)) = service.render(graph.as_ref(), ext) {
        Ok(HttpResponse::Ok().content_type(content_type).body(data))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "searchLatestComponent",
    params(
        Query,
        Paginated,
        QueryOptions,
    ),
    responses(
        AuthResponse,
        (status = 200, description = "Retrieved latest component(s) located by search", body = PaginatedResults<Node>),
    ),
)]
#[get("/v2/analysis/latest/component")]
/// Retrieve latest SBOM components (packages) by a complex search.
pub async fn search_latest_component(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(options): web::Query<QueryOptions>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(
        service
            .retrieve_latest(&search, options, paginated, db.as_ref())
            .await?,
    ))
}

#[utoipa::path(
    tag = "analysis",
    operation_id = "getLatestComponent",
    params(
        ("key" = String, Path, description = "provide component name, URL-encoded pURL, or CPE itself"),
        Paginated,
        QueryOptions,
    ),
    responses(
        AuthResponse,
        (status = 200, description = "Retrieved latest component(s) located by an exact match of name, pURL, or CPE", body = PaginatedResults<Node>),
    ),
)]
#[get("/v2/analysis/latest/component/{key}")]
/// Retrieve latest SBOM components (packages) by name, Package URL, or CPE.
pub async fn get_latest_component(
    service: web::Data<AnalysisService>,
    db: web::Data<Database>,
    key: web::Path<String>,
    web::Query(options): web::Query<QueryOptions>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let query = OwnedComponentReference::try_from(key.as_str())?;

    Ok(HttpResponse::Ok().json(
        service
            .retrieve_latest(&query, options, paginated, db.as_ref())
            .await?,
    ))
}

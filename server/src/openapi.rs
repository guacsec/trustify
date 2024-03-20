use utoipa::openapi::security::{OpenIdConnect, SecurityScheme};
use utoipa::{Modify, OpenApi};

#[derive(OpenApi)]
#[openapi(paths(), components(), tags())]
pub struct ApiDoc;

pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = ApiDoc::openapi();

    doc.merge(trustify_module_graph::endpoints::ApiDoc::openapi());
    doc.merge(trustify_module_importer::endpoints::ApiDoc::openapi());
    doc.merge(trustify_module_ingestor::endpoints::ApiDoc::openapi());

    doc
}

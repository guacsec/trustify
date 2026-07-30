use crate::model::{ValidationRequest, ValidationResult};
use crate::service::{Error, ValidationService};
use actix_web::{HttpResponse, Responder, delete, get, put, web};
use sea_orm::TransactionTrait;
use trustify_auth::{ReadAdvisory, ReadSbom, UpdateAdvisory, UpdateSbom, authorizer::Require};
use trustify_common::db;
use uuid::Uuid;

/// Mount the "validation" module.
pub fn configure(svc: &mut utoipa_actix_web::service_config::ServiceConfig) {
    svc.app_data(web::Data::new(ValidationService::new()))
        .service(list_sbom_validations)
        .service(upsert_sbom_validation)
        .service(delete_sbom_validation)
        .service(list_advisory_validations)
        .service(upsert_advisory_validation)
        .service(delete_advisory_validation);
}

// --- SBOM validation endpoints ---

#[utoipa::path(
    tag = "validation",
    operation_id = "listSbomValidations",
    params(
        ("id" = String, Path, description = "The SBOM identifier"),
    ),
    responses(
        (status = 200, description = "Validation results for the SBOM", body = Vec<ValidationResult>),
    )
)]
#[get("/v3/sbom/{id}/validation")]
async fn list_sbom_validations(
    service: web::Data<ValidationService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<String>,
    _: Require<ReadSbom>,
) -> Result<impl Responder, Error> {
    let entity_id = parse_entity_id(&id)?;
    let tx = db.begin().await?;
    let results = service.list("sbom", entity_id, &tx).await?;
    Ok(HttpResponse::Ok().json(results))
}

#[utoipa::path(
    tag = "validation",
    operation_id = "upsertSbomValidation",
    params(
        ("id" = String, Path, description = "The SBOM identifier"),
    ),
    request_body = ValidationRequest,
    responses(
        (status = 200, description = "Validation result created or updated", body = ValidationResult),
    )
)]
#[put("/v3/sbom/{id}/validation")]
async fn upsert_sbom_validation(
    service: web::Data<ValidationService>,
    db: web::Data<db::ReadWrite>,
    id: web::Path<String>,
    web::Json(request): web::Json<ValidationRequest>,
    _: Require<UpdateSbom>,
) -> Result<impl Responder, Error> {
    let entity_id = parse_entity_id(&id)?;
    let tx = db.begin().await?;
    let result = service.upsert("sbom", entity_id, request, &tx).await?;
    tx.commit().await?;
    Ok(HttpResponse::Ok().json(result))
}

#[utoipa::path(
    tag = "validation",
    operation_id = "deleteSbomValidation",
    params(
        ("id" = String, Path, description = "The SBOM identifier"),
        ("validation_id" = Uuid, Path, description = "The validation result ID"),
    ),
    responses(
        (status = 204, description = "Validation result deleted"),
        (status = 404, description = "Validation result not found"),
    )
)]
#[delete("/v3/sbom/{id}/validation/{validation_id}")]
async fn delete_sbom_validation(
    service: web::Data<ValidationService>,
    db: web::Data<db::ReadWrite>,
    path: web::Path<(String, Uuid)>,
    _: Require<UpdateSbom>,
) -> Result<impl Responder, Error> {
    let (_, validation_id) = path.into_inner();
    let tx = db.begin().await?;
    if service.delete(validation_id, &tx).await? {
        tx.commit().await?;
        Ok(HttpResponse::NoContent().finish())
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

// --- Advisory validation endpoints ---

#[utoipa::path(
    tag = "validation",
    operation_id = "listAdvisoryValidations",
    params(
        ("id" = String, Path, description = "The advisory identifier"),
    ),
    responses(
        (status = 200, description = "Validation results for the advisory", body = Vec<ValidationResult>),
    )
)]
#[get("/v3/advisory/{id}/validation")]
async fn list_advisory_validations(
    service: web::Data<ValidationService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<String>,
    _: Require<ReadAdvisory>,
) -> Result<impl Responder, Error> {
    let entity_id = parse_entity_id(&id)?;
    let tx = db.begin().await?;
    let results = service.list("advisory", entity_id, &tx).await?;
    Ok(HttpResponse::Ok().json(results))
}

#[utoipa::path(
    tag = "validation",
    operation_id = "upsertAdvisoryValidation",
    params(
        ("id" = String, Path, description = "The advisory identifier"),
    ),
    request_body = ValidationRequest,
    responses(
        (status = 200, description = "Validation result created or updated", body = ValidationResult),
    )
)]
#[put("/v3/advisory/{id}/validation")]
async fn upsert_advisory_validation(
    service: web::Data<ValidationService>,
    db: web::Data<db::ReadWrite>,
    id: web::Path<String>,
    web::Json(request): web::Json<ValidationRequest>,
    _: Require<UpdateAdvisory>,
) -> Result<impl Responder, Error> {
    let entity_id = parse_entity_id(&id)?;
    let tx = db.begin().await?;
    let result = service.upsert("advisory", entity_id, request, &tx).await?;
    tx.commit().await?;
    Ok(HttpResponse::Ok().json(result))
}

#[utoipa::path(
    tag = "validation",
    operation_id = "deleteAdvisoryValidation",
    params(
        ("id" = String, Path, description = "The advisory identifier"),
        ("validation_id" = Uuid, Path, description = "The validation result ID"),
    ),
    responses(
        (status = 204, description = "Validation result deleted"),
        (status = 404, description = "Validation result not found"),
    )
)]
#[delete("/v3/advisory/{id}/validation/{validation_id}")]
async fn delete_advisory_validation(
    service: web::Data<ValidationService>,
    db: web::Data<db::ReadWrite>,
    path: web::Path<(String, Uuid)>,
    _: Require<UpdateAdvisory>,
) -> Result<impl Responder, Error> {
    let (_, validation_id) = path.into_inner();
    let tx = db.begin().await?;
    if service.delete(validation_id, &tx).await? {
        tx.commit().await?;
        Ok(HttpResponse::NoContent().finish())
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

/// Extracts a UUID from an ID path parameter (handles `urn:uuid:` prefix).
fn parse_entity_id(id: &str) -> Result<Uuid, Error> {
    let raw = id.strip_prefix("urn:uuid:").unwrap_or(id);
    Uuid::parse_str(raw).map_err(|e| Error::Database(sea_orm::DbErr::Custom(e.to_string())))
}

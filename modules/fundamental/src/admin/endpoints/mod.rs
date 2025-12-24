#[cfg(test)]
mod test;

use actix_web::{HttpResponse, Responder, post, web};
use futures_util::{StreamExt, stream};
use sea_orm::{
    ColumnTrait, EntityTrait, FromQueryResult, JoinType, QueryFilter, QuerySelect, RelationTrait,
    TransactionTrait,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use trustify_auth::{DeleteSbom, authorizer::Require};
use trustify_common::db::Database;
use trustify_entity::{sbom, source_document};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::{Error, db::DatabaseExt, sbom::service::SbomService};

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, FromQueryResult)]
pub struct PrunedSbom {
    pub sbom_id: Uuid,
    pub document_id: Option<String>,
    pub published: Option<OffsetDateTime>,
    pub authors: Vec<String>,
    pub suppliers: Vec<String>,
    pub data_licenses: Vec<String>,
    pub ingested: OffsetDateTime,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PrunedSbomLog {
    pub total: u64,
    pub successful_total: u64,
    pub failed_total: u64,
    pub successful_pruned: Vec<PrunedSbom>,
    pub failed_pruned: Vec<PrunedSbom>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct PruneQuery {
    /// Number of days ago from current time to prune SBOMs
    #[param(style = Form, example = 90)]
    pub ingested: u32,
    /// If true, only return the list of SBOMs that would be deleted without actually deleting them
    #[serde(alias = "dry-run")]
    pub dry_run: bool,
    /// Number of SBOMs to process in a single batch
    #[serde(alias = "batch-size")]
    pub batch_size: u64,
    /// Maximum number of concurrent operations
    #[serde(alias = "max-concurrent", default = "default_max_concurrent")]
    #[param(minimum = 1, example = 10)]
    pub max_concurrent: usize,
}

fn default_max_concurrent() -> usize {
    1
}

/// Try to delete an SBOM by its ID.
///
/// If the deletion is successful, the PrunedSbom struct is returned.
/// If the deletion fails, the PrunedSbom struct with an error message is returned.
pub async fn try_delete_sbom(
    mut sbom: PrunedSbom,
    db: actix_web::web::Data<trustify_common::db::Database>,
    service: actix_web::web::Data<SbomService>,
) -> Result<PrunedSbom, PrunedSbom> {
    let delete_operation = async {
        let tx = db.begin().await?;
        service.delete_sbom(sbom.sbom_id, &tx).await?;
        tx.commit().await?;
        Ok::<(), Error>(())
    };

    match delete_operation.await {
        Ok(_) => Ok(sbom),
        Err(e) => {
            sbom.error = Some(e.to_string());
            Err(sbom)
        }
    }
}

#[utoipa::path(
    tag = "admin",
    operation_id = "pruneSboms",
    params(PruneQuery),
    responses(
        (status = 200, description = "List of pruned SBOMs", body = PrunedSbomLog),
        (status = 500, description = "Internal server error"),
    ),
)]
#[post("/v2/admin/sbom/prune")]
/// Prune SBOMs based on ingestion date
pub async fn prune_sboms(
    service: web::Data<SbomService>,
    db: web::Data<Database>,
    web::Query(query): web::Query<PruneQuery>,
    _: Require<DeleteSbom>,
) -> Result<impl Responder, Error> {
    // Calculate the cutoff date (current time minus the specified number of days)
    let cutoff_date = OffsetDateTime::now_utc() - time::Duration::days(query.ingested as i64);

    // Query SBOMs joined with source_document where ingested date is before the cutoff date
    let pruned_sboms: Vec<PrunedSbom> = sbom::Entity::find()
        .join(JoinType::Join, sbom::Relation::SourceDocument.def())
        .select_only()
        .column_as(sbom::Column::SbomId, "sbom_id")
        .column_as(sbom::Column::DocumentId, "document_id")
        .column_as(sbom::Column::Published, "published")
        .column_as(sbom::Column::Authors, "authors")
        .column_as(sbom::Column::Suppliers, "suppliers")
        .column_as(sbom::Column::DataLicenses, "data_licenses")
        .column_as(source_document::Column::Ingested, "ingested")
        .filter(source_document::Column::Ingested.lt(cutoff_date))
        .limit(query.batch_size)
        .into_model::<PrunedSbom>()
        .all(&db.begin_read().await?)
        .await?;

    // If not a dry run, delete the SBOMs concurrently
    if !query.dry_run {
        // Ensure max_concurrent is at least 1 to prevent stalling
        let max_concurrent = query.max_concurrent.max(1);

        // Process SBOMs concurrently and collect results
        let results: Vec<Result<PrunedSbom, PrunedSbom>> = stream::iter(pruned_sboms.clone())
            .map(move |sbom| {
                let db = db.clone();
                let service = service.clone();
                try_delete_sbom(sbom, db, service)
            })
            .buffer_unordered(max_concurrent)
            .collect()
            .await;

        // Separate successful and failed results
        let (successful_pruned, failed_pruned): (Vec<PrunedSbom>, Vec<PrunedSbom>) =
            results.into_iter().fold(
                (Vec::new(), Vec::new()),
                |(mut success, mut fail), result| {
                    match result {
                        Ok(sbom) => success.push(sbom),
                        Err(sbom) => fail.push(sbom),
                    }
                    (success, fail)
                },
            );

        let log = PrunedSbomLog {
            total: pruned_sboms.len() as u64,
            successful_total: successful_pruned.len() as u64,
            failed_total: failed_pruned.len() as u64,
            successful_pruned,
            failed_pruned,
        };

        Ok(HttpResponse::Ok().json(log))
    } else {
        // In dry run mode, build a PrunedSbomLog with all SBOMs as successful
        let log = PrunedSbomLog {
            total: pruned_sboms.len() as u64,
            successful_total: pruned_sboms.len() as u64,
            failed_total: 0,
            successful_pruned: pruned_sboms.clone(),
            failed_pruned: vec![],
        };
        Ok(HttpResponse::Ok().json(log))
    }
}

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let sbom_service = SbomService::new(db.clone());

    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(sbom_service))
        .service(prune_sboms);
}

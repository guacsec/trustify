use actix_web::{HttpResponse, ResponseError, body::BoxBody};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder,
};
use sea_query::OnConflict;
use time::OffsetDateTime;
use trustify_common::{db::DatabaseErrors, error::ErrorInformation};
use trustify_entity::document_validation;
use uuid::Uuid;

use crate::model::{ValidationRequest, ValidationResult};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database error: {0}")]
    Database(#[source] sea_orm::DbErr),
    #[error("unavailable")]
    Unavailable,
    #[error("database error: {0}")]
    Db(#[from] trustify_common::db::DbError),
}

impl From<sea_orm::DbErr> for Error {
    fn from(value: sea_orm::DbErr) -> Self {
        if value.is_read_only() {
            Error::Unavailable
        } else {
            Error::Database(value)
        }
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::Unavailable => HttpResponse::ServiceUnavailable().json(ErrorInformation {
                error: "Unavailable".into(),
                message: self.to_string(),
                details: None,
            }),
            _ => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Internal".into(),
                message: self.to_string(),
                details: None,
            }),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ValidationService;

impl ValidationService {
    /// Creates a new validation service.
    pub fn new() -> Self {
        Self
    }

    /// Upserts a validation result (insert or update on conflict of entity+source+key).
    pub async fn upsert(
        &self,
        entity_type: &str,
        entity_id: Uuid,
        request: ValidationRequest,
        connection: &impl ConnectionTrait,
    ) -> Result<ValidationResult, Error> {
        let id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let on_conflict = OnConflict::columns([
            document_validation::Column::EntityType,
            document_validation::Column::EntityId,
            document_validation::Column::Source,
            document_validation::Column::Key,
        ])
        .values([
            (
                document_validation::Column::Level,
                request.level.as_str().into(),
            ),
            (
                document_validation::Column::Message,
                request.message.clone().into(),
            ),
            (document_validation::Column::Timestamp, now.into()),
        ])
        .to_owned();

        document_validation::Entity::insert(document_validation::ActiveModel {
            id: Set(id),
            entity_type: Set(entity_type.to_string()),
            entity_id: Set(entity_id),
            level: Set(request.level.as_str().to_string()),
            message: Set(request.message.clone()),
            source: Set(request.source.clone()),
            key: Set(request.key.clone()),
            timestamp: Set(now),
        })
        .on_conflict(on_conflict)
        .exec_without_returning(connection)
        .await?;

        // Fetch the actual row (may be the updated existing one, not our new id)
        let result = document_validation::Entity::find()
            .filter(document_validation::Column::EntityType.eq(entity_type))
            .filter(document_validation::Column::EntityId.eq(entity_id))
            .filter(document_validation::Column::Source.eq(&request.source))
            .filter(document_validation::Column::Key.eq(&request.key))
            .one(connection)
            .await?
            .expect("row must exist after upsert");

        Ok(result.into())
    }

    /// Lists all validation results for a given entity.
    pub async fn list(
        &self,
        entity_type: &str,
        entity_id: Uuid,
        connection: &impl ConnectionTrait,
    ) -> Result<Vec<ValidationResult>, Error> {
        let results = document_validation::Entity::find()
            .filter(document_validation::Column::EntityType.eq(entity_type))
            .filter(document_validation::Column::EntityId.eq(entity_id))
            .order_by_desc(document_validation::Column::Timestamp)
            .all(connection)
            .await?;

        Ok(results.into_iter().map(ValidationResult::from).collect())
    }

    /// Deletes a single validation result by ID.
    pub async fn delete(&self, id: Uuid, connection: &impl ConnectionTrait) -> Result<bool, Error> {
        let result = document_validation::Entity::delete_by_id(id)
            .exec(connection)
            .await?;
        Ok(result.rows_affected > 0)
    }
}

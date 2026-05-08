use actix_web::{HttpResponse, ResponseError, body::BoxBody};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter,
    prelude::Uuid,
};
use sea_query::{Alias, Expr, OnConflict};
use trustify_common::{db::DatabaseErrors, error::ErrorInformation, model::Revisioned};
use trustify_entity::user_preferences;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mid air collision")]
    MidAirCollision,
    #[error("database error: {0}")]
    Database(#[source] sea_orm::DbErr),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("unavailable")]
    Unavailable,
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
            Error::MidAirCollision => HttpResponse::PreconditionFailed().json(ErrorInformation {
                error: "MidAirCollision".into(),
                message: self.to_string(),
                details: None,
            }),
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
pub struct UserPreferenceService;

impl UserPreferenceService {
    /// Creates a new user preference service.
    pub fn new() -> Self {
        Self
    }

    /// Sets a user preference, optionally checking the expected revision for optimistic concurrency.
    pub async fn set(
        &self,
        user_id: String,
        key: String,
        expected_revision: Option<&str>,
        data: serde_json::Value,
        connection: &impl ConnectionTrait,
    ) -> Result<Revisioned<()>, Error> {
        let next = Uuid::new_v4();

        match expected_revision {
            Some(expected_revision) => {
                // if we expect a revision, just update
                let result = user_preferences::Entity::update_many()
                    .col_expr(user_preferences::Column::Data, Expr::value(data))
                    .col_expr(user_preferences::Column::Revision, Expr::value(next))
                    .filter(user_preferences::Column::UserId.eq(user_id))
                    .filter(user_preferences::Column::Key.eq(key))
                    .filter(
                        user_preferences::Column::Revision
                            .into_expr()
                            .cast_as(Alias::new("text"))
                            .eq(expected_revision),
                    )
                    .exec(connection)
                    .await?;

                if result.rows_affected == 0 {
                    // we expected a revision, but didn't find one, we don't update it, but fail
                    Err(Error::MidAirCollision)
                } else {
                    Ok(Revisioned {
                        value: (),
                        revision: next.to_string(),
                    })
                }
            }
            None => {
                let on_conflict = OnConflict::columns([
                    user_preferences::Column::UserId,
                    user_preferences::Column::Key,
                ])
                .values([
                    (user_preferences::Column::Revision, next.into()),
                    (user_preferences::Column::Data, data.clone().into()),
                ])
                .to_owned();

                user_preferences::Entity::insert(user_preferences::ActiveModel {
                    user_id: Set(user_id),
                    key: Set(key),
                    revision: Set(next),
                    data: Set(data),
                })
                .on_conflict(on_conflict)
                .exec_without_returning(connection)
                .await?;

                Ok(Revisioned {
                    value: (),
                    revision: next.to_string(),
                })
            }
        }
    }

    /// Retrieves a user preference by user ID and key.
    pub async fn get(
        &self,
        user_id: String,
        key: String,
        connection: &impl ConnectionTrait,
    ) -> Result<Option<Revisioned<serde_json::Value>>, Error> {
        let result = user_preferences::Entity::find_by_id((user_id, key))
            .one(connection)
            .await?;

        Ok(result.map(|result| Revisioned {
            value: result.data,
            revision: result.revision.to_string(),
        }))
    }

    /// Deletes a user preference, optionally checking the expected revision.
    ///
    /// The caller must provide a transaction for atomicity when using revision checks.
    pub async fn delete(
        &self,
        user_id: String,
        key: String,
        expected_revision: Option<&str>,
        connection: &impl ConnectionTrait,
    ) -> Result<bool, Error> {
        let mut delete = user_preferences::Entity::delete_many()
            .filter(user_preferences::Column::UserId.eq(&user_id))
            .filter(user_preferences::Column::Key.eq(&key));

        if let Some(revision) = expected_revision {
            delete = delete.filter(
                user_preferences::Column::Revision
                    .into_expr()
                    .cast_as(Alias::new("text"))
                    .eq(revision),
            );
        }

        let result = delete.exec(connection).await?;

        if expected_revision.is_some() && result.rows_affected == 0 {
            // now we need to figure out if the item wasn't there or if it was modified
            if user_preferences::Entity::find_by_id((user_id, key))
                .count(connection)
                .await?
                == 0
            {
                Ok(false)
            } else {
                Err(Error::MidAirCollision)
            }
        } else {
            Ok(result.rows_affected > 0)
        }
    }
}

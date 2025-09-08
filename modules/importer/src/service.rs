use crate::model::{Importer, ImporterConfiguration, ImporterReport};
use actix_web::{HttpResponse, ResponseError, body::BoxBody};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, TransactionTrait,
};
use sea_query::{Alias, Expr, Nullable, SimpleExpr};
use std::fmt::{Debug, Display};
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::{
    db::{
        Database, DatabaseErrors,
        limiter::LimiterTrait,
        query::{Filtering, Query},
    },
    error::ErrorInformation,
    model::{Paginated, PaginatedResults, Revisioned},
};
use trustify_entity::{importer, importer_report, labels};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("importer already exists")]
    AlreadyExists,
    #[error("importer '{0}' not found")]
    NotFound(String),
    #[error("mid air collision")]
    MidAirCollision,
    #[error("unavailable")]
    Unavailable,
    #[error("database error: {0}")]
    Database(#[source] sea_orm::DbErr),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Query(#[from] trustify_common::db::query::Error),
    #[error(transparent)]
    Label(#[from] labels::Error),
}

impl From<sea_orm::DbErr> for Error {
    fn from(value: sea_orm::DbErr) -> Self {
        if value.is_duplicate() {
            Error::AlreadyExists
        } else if value.is_read_only() {
            Error::Unavailable
        } else {
            Error::Database(value)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PatchError<T>
where
    T: Debug + Display,
{
    #[error("failed to apply changes")]
    Transform(T),
    #[error(transparent)]
    Common(Error),
}

impl<T> From<Error> for PatchError<T>
where
    T: Debug + Display,
{
    fn from(value: Error) -> Self {
        Self::Common(value)
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::AlreadyExists => HttpResponse::Conflict().json(ErrorInformation {
                error: "AlreadyExists".into(),
                message: self.to_string(),
                details: None,
            }),
            Self::NotFound(_) => HttpResponse::NotFound().json(ErrorInformation {
                error: "NotFound".into(),
                message: self.to_string(),
                details: None,
            }),
            Self::MidAirCollision => HttpResponse::PreconditionFailed().json(ErrorInformation {
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

impl<T> ResponseError for PatchError<T>
where
    T: Debug + Display,
{
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            PatchError::Common(err) => err.error_response(),
            PatchError::Transform(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "PatchTransform".into(),
                message: err.to_string(),
                details: None,
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ImporterService {
    db: Database,
}

impl ImporterService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn list(&self) -> Result<Vec<Importer>, Error> {
        let mut result: Vec<_> = importer::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(Importer::try_from)
            .collect::<Result<_, _>>()?;
        result.sort_unstable_by_key(|i| (i.data.configuration.disabled, i.data.last_run));
        Ok(result)
    }

    pub async fn create(
        &self,
        name: String,
        mut configuration: ImporterConfiguration,
    ) -> Result<(), Error> {
        configuration.labels.validate_mut()?;

        let entity = importer::ActiveModel {
            name: Set(name.clone()),
            revision: Set(Uuid::new_v4()),

            state: Set(importer::State::Waiting),
            last_change: Set(OffsetDateTime::now_utc()),

            last_success: Set(None),
            last_run: Set(None),
            last_error: Set(None),

            progress_current: Set(None),
            progress_total: Set(None),
            progress_message: Set(None),

            continuation: Set(None),

            configuration: Set(serde_json::to_value(configuration)?),

            heartbeat: Set(None),
        };

        entity.insert(&self.db).await?;

        Ok(())
    }

    pub async fn read(&self, name: &str) -> Result<Option<Revisioned<Importer>>, Error> {
        let result = importer::Entity::find_by_id(name).one(&self.db).await?;

        Ok(result.map(Importer::from_revisioned).transpose()?)
    }

    /// Load a configuration, transform, and store it back (aka patch).
    ///
    /// The function loads the configuration, and then applies the provided transform function.
    ///
    /// If the revision of the loaded configuration does not match, an error is reported. Also,
    /// if the final update doesn't match the loaded revision, an error is reported.
    pub async fn patch_configuration<F, E>(
        &self,
        name: &str,
        expected_revision: Option<&str>,
        f: F,
    ) -> Result<(), PatchError<E>>
    where
        E: Debug + Display,
        F: FnOnce(ImporterConfiguration) -> Result<ImporterConfiguration, E>,
    {
        // fetch the current state
        let Some(current) = self.read(name).await? else {
            // not found -> don't update
            return Err(Error::NotFound(name.into()).into());
        };

        if let Some(expected) = expected_revision
            && expected != current.revision
        {
            // we expected something, but found something else -> abort
            return Err(Error::MidAirCollision.into());
        }

        // apply mutation

        let mut configuration =
            f(current.value.data.configuration).map_err(PatchError::Transform)?;

        // validate

        configuration
            .labels
            .validate_mut()
            .map_err(|err| PatchError::Common(err.into()))?;

        // store

        Ok(self
            .update(
                &self.db,
                name,
                Some(&current.revision),
                vec![(
                    importer::Column::Configuration,
                    Expr::value(
                        serde_json::to_value(configuration)
                            .map_err(|err| PatchError::Common(err.into()))?,
                    ),
                )],
            )
            .await?)
    }

    pub async fn update_configuration(
        &self,
        name: &str,
        expected_revision: Option<&str>,
        mut configuration: ImporterConfiguration,
    ) -> Result<(), Error> {
        configuration.labels.validate_mut()?;

        self.update(
            &self.db,
            name,
            expected_revision,
            vec![(
                importer::Column::Configuration,
                Expr::value(serde_json::to_value(configuration)?),
            )],
        )
        .await
    }

    /// Update state to indicate the start of an importer run
    #[instrument(skip(self))]
    pub async fn update_start(
        &self,
        name: &str,
        expected_revision: Option<&str>,
    ) -> Result<(), Error> {
        self.update(
            &self.db,
            name,
            expected_revision,
            vec![
                (
                    importer::Column::LastChange,
                    Expr::value(OffsetDateTime::now_utc()),
                ),
                (
                    importer::Column::State,
                    Expr::value(importer::State::Running),
                ),
            ],
        )
        .await
    }

    #[instrument(skip(self, report, continuation), err)]
    pub async fn update_finish(
        &self,
        name: &str,
        expected_revision: Option<&str>,
        start: OffsetDateTime,
        last_error: Option<String>,
        continuation: Option<serde_json::Value>,
        report: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        let tx = self.db.begin().await?;

        let now = OffsetDateTime::now_utc();
        let successful = last_error.is_none();
        let mut updates = vec![
            (importer::Column::LastError, Expr::value(last_error.clone())),
            (importer::Column::LastRun, Expr::value(start)),
            (
                importer::Column::State,
                Expr::value(importer::State::Waiting),
            ),
            (importer::Column::ProgressCurrent, Expr::value(i32::null())),
            (importer::Column::ProgressTotal, Expr::value(i32::null())),
            (
                importer::Column::ProgressMessage,
                Expr::value(String::null()),
            ),
            (importer::Column::LastChange, Expr::value(now)),
            (importer::Column::Continuation, Expr::value(continuation)),
        ];
        if successful {
            // we use the `start` marker, so that `last_success` can be used as the next `since`
            updates.push((importer::Column::LastSuccess, Expr::value(start)));
        }

        self.update(&tx, name, expected_revision, updates).await?;

        // add report

        if let Some(report) = report {
            let entity = importer_report::ActiveModel {
                id: Set(Uuid::new_v4()),
                importer: Set(name.to_string()),
                creation: Set(OffsetDateTime::now_utc()),
                error: Set(last_error),
                report: Set(report),
            };
            entity.insert(&tx).await?;
        }

        // commit

        tx.commit().await?;

        Ok(())
    }

    async fn update<C>(
        &self,
        db: &C,
        name: &str,
        expected_revision: Option<&str>,
        updates: Vec<(importer::Column, SimpleExpr)>,
    ) -> Result<(), Error>
    where
        C: ConnectionTrait,
    {
        let mut update = importer::Entity::update_many()
            .col_expr(importer::Column::Revision, Expr::value(Uuid::new_v4()))
            .filter(importer::Column::Name.eq(name));

        for (col, expr) in updates {
            update = update.col_expr(col, expr);
        }

        if let Some(revision) = expected_revision {
            update = update.filter(
                importer::Column::Revision
                    .into_expr()
                    .cast_as(Alias::new("text"))
                    .eq(revision),
            );
        }

        let result = update.exec(db).await?;

        if result.rows_affected == 0 {
            // now we need to figure out if the item wasn't there or if it was modified
            if importer::Entity::find_by_id(name).count(&self.db).await? == 0 {
                Err(Error::NotFound(name.to_string()))
            } else {
                Err(Error::MidAirCollision)
            }
        } else {
            Ok(())
        }
    }

    /// Reset the last-run timestamp and continuation token to force a new run
    #[instrument(skip(self))]
    pub async fn reset(&self, name: &str, expected_revision: Option<&str>) -> Result<(), Error> {
        self.update(
            &self.db,
            name,
            expected_revision,
            vec![
                (
                    importer::Column::LastRun,
                    Expr::value(None::<OffsetDateTime>),
                ),
                (importer::Column::ProgressCurrent, Expr::value(i32::null())),
                (importer::Column::ProgressTotal, Expr::value(i32::null())),
                (
                    importer::Column::ProgressMessage,
                    Expr::value(String::null()),
                ),
                (
                    importer::Column::Continuation,
                    Expr::value(None::<serde_json::Value>),
                ),
            ],
        )
        .await
    }

    #[instrument(skip(self))]
    pub async fn update_progress(
        &self,
        name: &str,
        expected_revision: Option<&str>,
        current: u32,
        total: u32,
    ) -> Result<(), Error> {
        self.update(
            &self.db,
            name,
            expected_revision,
            vec![
                (importer::Column::ProgressCurrent, Expr::value(current)),
                (importer::Column::ProgressTotal, Expr::value(total)),
                (
                    importer::Column::ProgressMessage,
                    Expr::value(String::null()),
                ),
            ],
        )
        .await
    }

    #[instrument(skip(self))]
    pub async fn set_progress_message(
        &self,
        name: &str,
        expected_revision: Option<&str>,
        message: &str,
    ) -> Result<(), Error> {
        self.update(
            &self.db,
            name,
            expected_revision,
            vec![(importer::Column::ProgressMessage, Expr::value(message))],
        )
        .await
    }

    #[instrument(skip(self))]
    pub async fn delete(&self, name: &str, expected_revision: Option<&str>) -> Result<bool, Error> {
        let mut delete = importer::Entity::delete_many().filter(importer::Column::Name.eq(name));

        if let Some(revision) = expected_revision {
            delete = delete.filter(
                importer::Column::Revision
                    .into_expr()
                    .cast_as(Alias::new("text"))
                    .eq(revision),
            );
        }

        let result = delete.exec(&self.db).await?;

        Ok(result.rows_affected > 0)
    }

    #[instrument(skip(self))]
    pub async fn get_reports(
        &self,
        name: &str,
        search: Query,
        paginated: Paginated,
    ) -> Result<PaginatedResults<ImporterReport>, Error> {
        let limiting = importer_report::Entity::find()
            .filter(importer_report::Column::Importer.eq(name))
            .filtering(search)?
            .order_by_desc(importer_report::Column::Creation)
            .limiting(&self.db, paginated.offset, paginated.limit);

        Ok(PaginatedResults {
            total: limiting.total().await?,
            items: limiting
                .fetch()
                .await?
                .into_iter()
                .map(ImporterReport::from)
                .collect(),
        })
    }
}

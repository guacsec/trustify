//! Options of the correlation engine, per publisher.
//!
//! An option enables an interpretation of a publisher's advisories, e.g. that their versionless
//! PURLs mean all versions. Evidence depending on an option records it (`enabled_by`). A changed
//! option applies to documents extracted afterwards.

use crate::{
    error::Error,
    model::{CorrelationOption, CorrelationOptionData, CorrelationOptionKey},
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait, QueryOrder,
};
use tracing::instrument;
use trustify_common::{
    db::{
        DatabaseErrors,
        limiter::{LimitedResult, LimiterTrait},
        pagination_cache::PaginationCache,
    },
    model::{PaginatedResults, Pagination},
};
use trustify_entity::correlation_option;
use uuid::Uuid;

/// Manages the options of the correlation engine.
pub struct OptionService {
    cache: PaginationCache,
}

impl OptionService {
    /// Create a new service.
    pub fn new(cache: PaginationCache) -> Self {
        Self { cache }
    }

    /// List the options, ordered by key and publisher namespace.
    #[instrument(skip(self, connection), err(level = tracing::Level::INFO))]
    pub async fn list<C: ConnectionTrait>(
        &self,
        paginated: impl Pagination,
        connection: &C,
    ) -> Result<PaginatedResults<CorrelationOption>, Error> {
        let limiter = correlation_option::Entity::find()
            .order_by_asc(correlation_option::Column::Key)
            .order_by_asc(correlation_option::Column::PublisherNamespace)
            .limiting(connection, paginated, &self.cache)?;

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total()).await?;

        Ok(PaginatedResults {
            items: items.into_iter().map(CorrelationOption::from).collect(),
            total,
        })
    }

    /// Get an option, `None` if it doesn't exist.
    #[instrument(skip(self, connection), err(level = tracing::Level::INFO))]
    pub async fn get<C: ConnectionTrait>(
        &self,
        id: Uuid,
        connection: &C,
    ) -> Result<Option<CorrelationOption>, Error> {
        Ok(correlation_option::Entity::find_by_id(id)
            .one(connection)
            .await?
            .map(CorrelationOption::from))
    }

    /// Create an option, returning its ID.
    ///
    /// Fails with [`Error::Conflict`] if the publisher already has an option of that key, and
    /// with [`Error::BadRequest`] if the value doesn't fit the key.
    #[instrument(skip(self, connection), err(level = tracing::Level::INFO))]
    pub async fn create<C: ConnectionTrait>(
        &self,
        data: CorrelationOptionData,
        connection: &C,
    ) -> Result<Uuid, Error> {
        let data = validate(data)?;
        let id = Uuid::now_v7();

        correlation_option::ActiveModel {
            id: Set(id),
            key: Set(data.key.into()),
            publisher_namespace: Set(data.publisher_namespace),
            value: Set(data.value),
            reason: Set(data.reason),
        }
        .insert(connection)
        .await
        .map_err(conflict)?;

        Ok(id)
    }

    /// Update an option.
    ///
    /// Fails with [`Error::NotFound`] if it doesn't exist, and like [`Self::create`].
    #[instrument(skip(self, connection), err(level = tracing::Level::INFO))]
    pub async fn update<C: ConnectionTrait>(
        &self,
        id: Uuid,
        data: CorrelationOptionData,
        connection: &C,
    ) -> Result<(), Error> {
        let data = validate(data)?;

        let Some(model) = correlation_option::Entity::find_by_id(id)
            .one(connection)
            .await?
        else {
            return Err(Error::NotFound(id.to_string()));
        };

        let mut model: correlation_option::ActiveModel = model.into();
        model.key = Set(data.key.into());
        model.publisher_namespace = Set(data.publisher_namespace);
        model.value = Set(data.value);
        model.reason = Set(data.reason);
        model.update(connection).await.map_err(conflict)?;

        Ok(())
    }

    /// Delete an option, succeeding if it doesn't exist.
    #[instrument(skip(self, connection), err(level = tracing::Level::INFO))]
    pub async fn delete<C: ConnectionTrait>(&self, id: Uuid, connection: &C) -> Result<(), Error> {
        correlation_option::Entity::delete_by_id(id)
            .exec(connection)
            .await?;
        Ok(())
    }
}

/// Check that the value fits the key, and normalize the publisher namespace.
fn validate(mut data: CorrelationOptionData) -> Result<CorrelationOptionData, Error> {
    match data.key {
        CorrelationOptionKey::VersionlessPurl | CorrelationOptionKey::FixedIsFirstFixed => {
            if !data.value.is_boolean() {
                return Err(Error::BadRequest(format!(
                    "the value of '{}' must be a boolean",
                    data.key
                )));
            }
        }
    }

    // like the publisher namespace of advisories, compared without a trailing slash
    data.publisher_namespace = data.publisher_namespace.trim_end_matches('/').to_string();
    if data.publisher_namespace.is_empty() {
        return Err(Error::BadRequest(
            "the publisher namespace must not be empty".into(),
        ));
    }

    Ok(data)
}

/// Map a duplicate key error to a conflict.
fn conflict(err: DbErr) -> Error {
    if err.is_duplicate() {
        Error::Conflict("the publisher already has an option of that key".into())
    } else {
        err.into()
    }
}

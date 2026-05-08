use crate::{
    Error,
    weakness::model::{WeaknessDetails, WeaknessSummary},
};
use sea_orm::{ConnectionTrait, EntityTrait};
use trustify_common::{
    db::{
        limiter::{LimitedResult, LimiterTrait},
        pagination_cache::PaginationCache,
        query::{Filtering, Query},
    },
    model::{PaginatedResults, Pagination},
};
use trustify_entity::weakness;

pub struct WeaknessService {
    cache: PaginationCache,
}

impl WeaknessService {
    /// Creates a new weakness service.
    pub fn new(cache: PaginationCache) -> Self {
        Self { cache }
    }

    /// Lists weaknesses matching the given query.
    pub async fn list_weaknesses<C: ConnectionTrait>(
        &self,
        query: Query,
        paginated: impl Pagination,
        connection: &C,
    ) -> Result<PaginatedResults<WeaknessSummary>, Error> {
        let limiter = weakness::Entity::find().filtering(query)?.limiting(
            connection,
            paginated,
            &self.cache,
        )?;

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total()).await?;

        Ok(PaginatedResults {
            items: WeaknessSummary::from_entities(&items).await?,
            total,
        })
    }

    /// Gets a single weakness by ID.
    pub async fn get_weakness(
        &self,
        id: &str,
        connection: &impl ConnectionTrait,
    ) -> Result<Option<WeaknessDetails>, Error> {
        if let Some(found) = weakness::Entity::find_by_id(id).one(connection).await? {
            Ok(Some(WeaknessDetails::from_entity(&found).await?))
        } else {
            Ok(None)
        }
    }
}

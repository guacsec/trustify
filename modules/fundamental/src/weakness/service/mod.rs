use crate::{
    Error,
    weakness::model::{WeaknessDetails, WeaknessSummary},
};
use sea_orm::EntityTrait;
use trustify_common::{
    db::{
        Database,
        limiter::{LimitedResult, LimiterTrait},
        pagination_cache::PaginationCache,
        query::{Filtering, Query},
    },
    model::{Paginated, PaginatedResults},
};
use trustify_entity::weakness;

pub struct WeaknessService {
    db: Database,
    cache: PaginationCache,
}

impl WeaknessService {
    pub fn new(db: Database, cache: PaginationCache) -> Self {
        Self { db, cache }
    }

    pub async fn list_weaknesses(
        &self,
        query: Query,
        paginated: Paginated,
    ) -> Result<PaginatedResults<WeaknessSummary>, Error> {
        let limiter = weakness::Entity::find().filtering(query)?.limiting(
            &self.db,
            paginated.offset,
            paginated.limit,
            &self.cache,
        );

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total).await?;

        Ok(PaginatedResults {
            items: WeaknessSummary::from_entities(&items).await?,
            total,
        })
    }

    pub async fn get_weakness(&self, id: &str) -> Result<Option<WeaknessDetails>, Error> {
        if let Some(found) = weakness::Entity::find_by_id(id).one(&self.db).await? {
            Ok(Some(WeaknessDetails::from_entity(&found).await?))
        } else {
            Ok(None)
        }
    }
}

use crate::{
    Error,
    organization::model::{OrganizationDetails, OrganizationSummary},
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use trustify_common::{
    db::{
        limiter::{LimitedResult, LimiterTrait},
        pagination_cache::PaginationCache,
        query::{Filtering, Query},
    },
    model::{PaginatedResults, Pagination},
};
use trustify_entity::organization;
use uuid::Uuid;

pub struct OrganizationService {
    cache: PaginationCache,
}

impl OrganizationService {
    pub fn new(cache: PaginationCache) -> Self {
        Self { cache }
    }

    pub async fn fetch_organizations<C: ConnectionTrait>(
        &self,
        search: Query,
        paginated: impl Pagination,
        connection: &C,
    ) -> Result<PaginatedResults<OrganizationSummary>, Error> {
        let limiter = organization::Entity::find().filtering(search)?.limiting(
            connection,
            paginated,
            &self.cache,
        )?;

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total()).await?;

        Ok(PaginatedResults {
            total,
            items: OrganizationSummary::from_entities(&items),
        })
    }
    pub async fn fetch_organization<C: ConnectionTrait>(
        &self,
        id: Uuid,
        connection: &C,
    ) -> Result<Option<OrganizationDetails>, Error> {
        if let Some(organization) = organization::Entity::find()
            .filter(organization::Column::Id.eq(id))
            .one(connection)
            .await?
        {
            Ok(Some(
                OrganizationDetails::from_entity(&organization, connection).await?,
            ))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod test;

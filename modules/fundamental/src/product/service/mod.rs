use super::model::summary::ProductSummary;
use crate::{Error, product::model::details::ProductDetails};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use trustify_common::{
    db::{
        limiter::{LimitedResult, LimiterTrait},
        pagination_cache::PaginationCache,
        query::{Filtering, Query},
    },
    model::{PaginatedResults, Pagination},
};
use trustify_entity::product;
use uuid::Uuid;

pub struct ProductService {
    cache: PaginationCache,
}

impl ProductService {
    pub fn new(cache: PaginationCache) -> Self {
        Self { cache }
    }

    pub async fn fetch_products<C: ConnectionTrait + Sync + Send>(
        &self,
        search: Query,
        paginated: impl Pagination,
        connection: &C,
    ) -> Result<PaginatedResults<ProductSummary>, Error> {
        let limiter = product::Entity::find().filtering(search)?.limiting(
            connection,
            paginated,
            &self.cache,
        )?;

        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total()).await?;

        Ok(PaginatedResults {
            total,
            items: ProductSummary::from_entities(&items, connection).await?,
        })
    }

    pub async fn fetch_product<C: ConnectionTrait + Sync + Send>(
        &self,
        id: Uuid,
        connection: &C,
    ) -> Result<Option<ProductDetails>, Error> {
        if let Some(product) = product::Entity::find()
            .find_also_related(trustify_entity::organization::Entity)
            .filter(product::Column::Id.eq(id))
            .one(connection)
            .await?
        {
            Ok(Some(
                ProductDetails::from_entity(&product.0, product.1, connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn delete_product<C: ConnectionTrait + Sync + Send>(
        &self,
        id: Uuid,
        connection: &C,
    ) -> Result<u64, Error> {
        let query = product::Entity::delete_by_id(id);

        let result = query.exec(connection).await?;

        Ok(result.rows_affected)
    }
}

#[cfg(test)]
mod test;

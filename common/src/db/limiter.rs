use crate::{
    db::{
        multi_model::{FromQueryResultMultiModel, SelectIntoMultiModel},
        pagination_cache::{LimitError, PaginationCache},
    },
    model::Paginated,
};

/// Offset and limit for a paginated query.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Page {
    /// The number of items to skip before returning results.
    pub offset: u64,
    /// The maximum number of items to return. Zero means no items are returned.
    pub limit: u64,
}

impl From<Paginated> for Page {
    fn from(
        Paginated {
            offset,
            limit,
            total: _,
        }: Paginated,
    ) -> Self {
        Self { offset, limit }
    }
}

/// Error from limiter construction, covering both DB and limit-exceeded errors.
#[derive(Debug, thiserror::Error)]
pub enum LimiterError {
    #[error(transparent)]
    Db(#[from] DbErr),
    #[error(transparent)]
    Limit(#[from] LimitError),
}
use sea_orm::{
    ConnectionTrait, DbErr, EntityTrait, FromQueryResult, Paginator, PaginatorTrait, QuerySelect,
    QueryTrait, Select, SelectModel, SelectThree, SelectThreeModel, SelectTwo, SelectTwoModel,
    Selector, SelectorTrait,
};
use sea_query::QueryStatementBuilder;
use std::num::NonZeroU64;
use tracing::instrument;

pub struct Limiter<'a, C, S1, S2>
where
    C: ConnectionTrait,
    S1: SelectorTrait + 'a,
    S2: SelectorTrait + 'a,
{
    db: &'a C,
    selector: Selector<S1>,
    paginator: Paginator<'a, C, S2>,
    cache_key: String,
    cache: &'a PaginationCache,
    limit: u64,
}

/// Result of fetching a limited query, with a deferred total count handle.
pub struct LimitedResult<'a, T, C, S>
where
    C: ConnectionTrait,
    S: SelectorTrait + 'a,
{
    pub items: Vec<T>,
    pub total: TotalCount<'a, C, S>,
}

/// Handle for computing the total count of a paginated query.
pub struct TotalCount<'a, C, S>
where
    C: ConnectionTrait,
    S: SelectorTrait + 'a,
{
    paginator: Paginator<'a, C, S>,
    cache_key: String,
    cache: &'a PaginationCache,
}

impl<'a, C, S> TotalCount<'a, C, S>
where
    C: ConnectionTrait,
    S: SelectorTrait + 'a,
{
    /// Compute the total count, using the pagination cache when possible.
    #[instrument(skip(self), err(level=tracing::Level::INFO))]
    pub async fn total(self) -> Result<u64, DbErr> {
        self.cache
            .cached_total(self.cache_key, || self.paginator.num_items())
            .await
    }

    /// Compute the total only if requested.
    #[instrument(skip(self), err(level=tracing::Level::INFO))]
    pub async fn requested(self, requested: bool) -> Result<Option<u64>, DbErr> {
        if requested {
            self.total().await.map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<'a, C, S1, S2> Limiter<'a, C, S1, S2>
where
    C: ConnectionTrait,
    S1: SelectorTrait + 'a,
    S2: SelectorTrait + 'a,
{
    /// Fetch the items and return a handle for computing the total count.
    /// If the limit is zero, no query is executed and an empty result is returned.
    #[instrument(skip(self), err(level=tracing::Level::INFO))]
    pub async fn fetch(self) -> Result<LimitedResult<'a, S1::Item, C, S2>, DbErr> {
        let items = if self.limit == 0 {
            vec![]
        } else {
            self.selector.all(self.db).await?
        };
        Ok(LimitedResult {
            items,
            total: TotalCount {
                paginator: self.paginator,
                cache_key: self.cache_key,
                cache: self.cache,
            },
        })
    }
}

/// Build a cache key from a sea-query select statement.
fn cache_key_from<Q: QueryTrait>(query: &Q) -> String {
    let (sql, values) = query.as_query().build_any(&sea_query::PostgresQueryBuilder);
    format!("{}|{:?}", sql, values)
}

pub trait LimiterTrait<'a, C>: Sized
where
    C: ConnectionTrait,
{
    type FetchSelector: SelectorTrait + 'a;
    type CountSelector: SelectorTrait + 'a;

    fn limiting(
        self,
        db: &'a C,
        page: impl Into<Page>,
        cache: &'a PaginationCache,
    ) -> Result<Limiter<'a, C, Self::FetchSelector, Self::CountSelector>, LimitError>;
}

impl<'a, C, E, M> LimiterTrait<'a, C> for Select<E>
where
    C: ConnectionTrait,
    E: EntityTrait<Model = M>,
    M: FromQueryResult + Sized + Send + Sync + 'a,
{
    type FetchSelector = SelectModel<M>;
    type CountSelector = SelectModel<M>;

    fn limiting(
        self,
        db: &'a C,
        page: impl Into<Page>,
        cache: &'a PaginationCache,
    ) -> Result<Limiter<'a, C, Self::FetchSelector, Self::CountSelector>, LimitError> {
        let page = page.into();
        let limit = cache.check_limit(page.limit)?;
        let cache_key = cache_key_from(&self);

        let selector = self
            .clone()
            .limit(NonZeroU64::new(limit).map(|limit| limit.get()))
            .offset(NonZeroU64::new(page.offset).map(|offset| offset.get()))
            .into_model();

        Ok(Limiter {
            db,
            paginator: self.paginate(db, 1),
            selector,
            cache_key,
            cache,
            limit,
        })
    }
}

pub trait LimiterAsModelTrait<'a, C>: Sized
where
    C: ConnectionTrait,
{
    fn limiting_as<M: FromQueryResult + Sync + Send>(
        self,
        db: &'a C,
        page: impl Into<Page>,
        cache: &'a PaginationCache,
    ) -> Result<Limiter<'a, C, SelectModel<M>, SelectModel<M>>, LimitError>;

    fn try_limiting_as_multi_model<M: FromQueryResultMultiModel + Sync + Send>(
        self,
        db: &'a C,
        page: impl Into<Page>,
        cache: &'a PaginationCache,
    ) -> Result<Limiter<'a, C, SelectModel<M>, SelectModel<M>>, LimiterError>;
}

impl<'a, C, E> LimiterAsModelTrait<'a, C> for Select<E>
where
    C: ConnectionTrait,
    E: EntityTrait,
{
    fn limiting_as<M: FromQueryResult + Sync + Send>(
        self,
        db: &'a C,
        page: impl Into<Page>,
        cache: &'a PaginationCache,
    ) -> Result<Limiter<'a, C, SelectModel<M>, SelectModel<M>>, LimitError> {
        let page = page.into();
        let limit = cache.check_limit(page.limit)?;
        let cache_key = cache_key_from(&self);

        let selector = self
            .clone()
            .limit(NonZeroU64::new(limit).map(|limit| limit.get()))
            .offset(NonZeroU64::new(page.offset).map(|offset| offset.get()))
            .into_model::<M>();

        Ok(Limiter {
            db,
            paginator: self.into_model::<M>().paginate(db, 1),
            selector,
            cache_key,
            cache,
            limit,
        })
    }

    fn try_limiting_as_multi_model<M: FromQueryResultMultiModel + Sync + Send>(
        self,
        db: &'a C,
        page: impl Into<Page>,
        cache: &'a PaginationCache,
    ) -> Result<Limiter<'a, C, SelectModel<M>, SelectModel<M>>, LimiterError> {
        let page = page.into();
        let limit = cache.check_limit(page.limit)?;
        let cache_key = cache_key_from(&self);

        let selector = self
            .clone()
            .limit(NonZeroU64::new(limit).map(|limit| limit.get()))
            .offset(NonZeroU64::new(page.offset).map(|offset| offset.get()))
            .try_into_multi_model::<M>()?;

        Ok(Limiter {
            db,
            paginator: self.into_model::<M>().paginate(db, 1),
            selector,
            cache_key,
            cache,
            limit,
        })
    }
}

/// Build a `Limiter` with separate fetch and count model types.
pub fn limit_selector<'a, C, E, EM, M>(
    db: &'a C,
    select: Select<E>,
    page: impl Into<Page>,
    cache: &'a PaginationCache,
) -> Result<Limiter<'a, C, SelectModel<M>, SelectModel<EM>>, LimitError>
where
    C: ConnectionTrait,
    E: EntityTrait<Model = EM>,
    M: FromQueryResult + Sized + Send + Sync + 'a,
    EM: FromQueryResult + Sized + Send + Sync + 'a,
{
    let page = page.into();
    let limit = cache.check_limit(page.limit)?;
    let cache_key = cache_key_from(&select);

    let selector = select
        .clone()
        .limit(NonZeroU64::new(limit).map(|limit| limit.get()))
        .offset(NonZeroU64::new(page.offset).map(|offset| offset.get()))
        .into_model();

    Ok(Limiter {
        db,
        paginator: select.paginate(db, 1),
        selector,
        cache_key,
        cache,
        limit,
    })
}

impl<'a, C, M1, M2, E1, E2> LimiterTrait<'a, C> for SelectTwo<E1, E2>
where
    C: ConnectionTrait,
    E1: EntityTrait<Model = M1>,
    E2: EntityTrait<Model = M2>,
    M1: FromQueryResult + Sized + Send + Sync + 'a,
    M2: FromQueryResult + Sized + Send + Sync + 'a,
{
    type FetchSelector = SelectTwoModel<M1, M2>;
    type CountSelector = SelectTwoModel<M1, M2>;

    fn limiting(
        self,
        db: &'a C,
        page: impl Into<Page>,
        cache: &'a PaginationCache,
    ) -> Result<Limiter<'a, C, Self::FetchSelector, Self::CountSelector>, LimitError> {
        let page = page.into();
        let limit = cache.check_limit(page.limit)?;
        let cache_key = cache_key_from(&self);

        let selector = self
            .clone()
            .limit(NonZeroU64::new(limit).map(|limit| limit.get()))
            .offset(NonZeroU64::new(page.offset).map(|offset| offset.get()))
            .into_model();

        Ok(Limiter {
            db,
            paginator: self.paginate(db, 1),
            selector,
            cache_key,
            cache,
            limit,
        })
    }
}

impl<'a, C, M1, M2, M3, E1, E2, E3> LimiterTrait<'a, C> for SelectThree<E1, E2, E3>
where
    C: ConnectionTrait,
    E1: EntityTrait<Model = M1>,
    E2: EntityTrait<Model = M2>,
    E3: EntityTrait<Model = M3>,
    M1: FromQueryResult + Sized + Send + Sync + 'a,
    M2: FromQueryResult + Sized + Send + Sync + 'a,
    M3: FromQueryResult + Sized + Send + Sync + 'a,
{
    type FetchSelector = SelectThreeModel<M1, M2, M3>;
    type CountSelector = SelectThreeModel<M1, M2, M3>;

    fn limiting(
        self,
        db: &'a C,
        page: impl Into<Page>,
        cache: &'a PaginationCache,
    ) -> Result<Limiter<'a, C, Self::FetchSelector, Self::CountSelector>, LimitError> {
        let page = page.into();
        let limit = cache.check_limit(page.limit)?;
        let cache_key = cache_key_from(&self);

        let selector = self
            .clone()
            .limit(NonZeroU64::new(limit).map(|limit| limit.get()))
            .offset(NonZeroU64::new(page.offset).map(|offset| offset.get()))
            .into_model();

        Ok(Limiter {
            db,
            paginator: self.paginate(db, 1),
            selector,
            cache_key,
            cache,
            limit,
        })
    }
}

use crate::{
    db::{
        limiter::{LimitedResult, limit_selector},
        pagination_cache::PaginationCache,
    },
    model::{Paginated, PaginatedResults},
};
use sea_orm::{ConnectionTrait, DbErr, EntityTrait, FromQueryResult, Select};
use std::fmt::Debug;

#[allow(async_fn_in_trait)]
pub trait Resulting: Sized + Debug {
    type Output<T>: Sized + Mappable<T>;

    async fn get<C, E, EM, M>(
        self,
        db: &C,
        query: Select<E>,
        cache: &PaginationCache,
    ) -> Result<Self::Output<M>, DbErr>
    where
        C: ConnectionTrait,
        E: EntityTrait<Model = EM>,
        EM: FromQueryResult + Send + Sync,
        M: FromQueryResult + Send + Sync;
}

impl Resulting for Paginated {
    type Output<T> = PaginatedResults<T>;

    async fn get<C, E, EM, M>(
        self,
        db: &C,
        query: Select<E>,
        cache: &PaginationCache,
    ) -> Result<Self::Output<M>, DbErr>
    where
        C: ConnectionTrait,
        E: EntityTrait<Model = EM>,
        EM: FromQueryResult + Send + Sync,
        M: FromQueryResult + Send + Sync,
    {
        let limiter = limit_selector(db, query, self.offset, self.limit, cache);
        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(self.total).await?;

        Ok(PaginatedResults { items, total })
    }
}

impl Resulting for () {
    type Output<T> = Vec<T>;

    async fn get<C, E, EM, M>(
        self,
        db: &C,
        query: Select<E>,
        _cache: &PaginationCache,
    ) -> Result<Self::Output<M>, DbErr>
    where
        C: ConnectionTrait,
        E: EntityTrait<Model = EM>,
        EM: FromQueryResult + Send + Sync,
        M: FromQueryResult + Send + Sync,
    {
        query.into_model().all(db).await
    }
}

pub trait Mappable<In>: Sized {
    fn map_all<Out, F, Mapped>(self, mut f: F) -> Mapped
    where
        F: FnMut(In) -> Out,
        Mapped: Mappable<Out>,
    {
        self.flat_map_all(|item| Some(f(item)))
    }

    fn flat_map_all<Out, F, Mapped>(self, f: F) -> Mapped
    where
        F: FnMut(In) -> Option<Out>,
        Mapped: Mappable<Out>;

    fn collect(total: Option<u64>, items: impl Iterator<Item = In>) -> Self;
}

impl<In> Mappable<In> for Vec<In> {
    fn flat_map_all<Out, F, Mapped>(self, f: F) -> Mapped
    where
        F: FnMut(In) -> Option<Out>,
        Mapped: Mappable<Out>,
    {
        Mapped::collect(Some(self.len() as _), self.into_iter().flat_map(f))
    }

    fn collect(_: Option<u64>, items: impl Iterator<Item = In>) -> Self {
        Vec::from_iter(items)
    }
}

impl<In> Mappable<In> for PaginatedResults<In> {
    fn flat_map_all<Out, F, Mapped>(self, f: F) -> Mapped
    where
        F: FnMut(In) -> Option<Out>,
        Mapped: Mappable<Out>,
    {
        Mapped::collect(self.total, self.items.into_iter().flat_map(f))
    }

    fn collect(total: Option<u64>, items: impl Iterator<Item = In>) -> Self {
        PaginatedResults {
            total,
            items: items.collect(),
        }
    }
}

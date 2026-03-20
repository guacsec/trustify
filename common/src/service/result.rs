use crate::{
    db::limiter::limit_selector,
    model::{Paginated, PaginatedResults},
};
use sea_orm::{ConnectionTrait, DbErr, EntityTrait, FromQueryResult, Select};
use std::fmt::Debug;

/// A
#[allow(async_fn_in_trait)]
pub trait Resulting: Sized + Debug {
    type Output<T>: Sized + Mappable<T>;

    async fn get<C, E, EM, M>(self, db: &C, query: Select<E>) -> Result<Self::Output<M>, DbErr>
    where
        C: ConnectionTrait,
        E: EntityTrait<Model = EM>,
        EM: FromQueryResult + Send + Sync,
        M: FromQueryResult + Send + Sync;
}

impl Resulting for Paginated {
    type Output<T> = PaginatedResults<T>;

    async fn get<C, E, EM, M>(self, db: &C, query: Select<E>) -> Result<Self::Output<M>, DbErr>
    where
        C: ConnectionTrait,
        E: EntityTrait<Model = EM>,
        EM: FromQueryResult + Send + Sync,
        M: FromQueryResult + Send + Sync,
    {
        // limit and execute

        let limiter = limit_selector(db, query, self.offset, self.limit);

        let total = limiter.total().await?;
        let items = limiter.fetch().await?;

        // collect results

        Ok(PaginatedResults { items, total })
    }
}

impl Resulting for () {
    type Output<T> = Vec<T>;

    async fn get<C, E, EM, M>(self, db: &C, query: Select<E>) -> Result<Self::Output<M>, DbErr>
    where
        C: ConnectionTrait,
        E: EntityTrait<Model = EM>,
        EM: FromQueryResult + Send + Sync,
        M: FromQueryResult + Send + Sync,
    {
        // just fetch all
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

    fn collect(total: u64, items: impl Iterator<Item = In>) -> Self;
}

impl<In> Mappable<In> for Vec<In> {
    fn flat_map_all<Out, F, Mapped>(self, f: F) -> Mapped
    where
        F: FnMut(In) -> Option<Out>,
        Mapped: Mappable<Out>,
    {
        Mapped::collect(self.len() as _, self.into_iter().flat_map(f))
    }

    fn collect(_: u64, items: impl Iterator<Item = In>) -> Self {
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

    fn collect(total: u64, items: impl Iterator<Item = In>) -> Self {
        PaginatedResults {
            total,
            items: items.collect(),
        }
    }
}

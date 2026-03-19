// SeaORM impls

use super::{Columns, Error, IntoColumns, Query, Sort};
use sea_orm::{EntityTrait, QueryFilter, QueryOrder, Select, SelectThree, SelectTwo};

/// Pass a Query instance for filtering
pub trait Filtering<T: EntityTrait> {
    fn filtering(self, search: Query) -> Result<Self, Error>
    where
        Self: Sized + QueryFilter + QueryOrder,
    {
        self.filtering_with(search, Columns::from_entity::<T>())
    }

    fn filtering_with<C: IntoColumns>(self, search: Query, context: C) -> Result<Self, Error>
    where
        Self: Sized + QueryFilter + QueryOrder,
    {
        let Query { ref q, ref sort } = search;
        let columns = context.columns();
        log::debug!("Query: q='{q}' sort='{sort}' columns={columns:#?}");

        let stmt = if q.is_empty() {
            self
        } else {
            self.filter(search.filter_for(&columns)?)
        };

        Ok(sort
            .split_terminator(',')
            .map(|s| Sort::parse(s, &columns))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .fold(stmt, |select, s| s.order_by(select)))
    }
}

/// SeaORM Select
impl<T: EntityTrait> Filtering<T> for Select<T> {}

/// SeaORM SelectTwo
impl<E, F> Filtering<E> for SelectTwo<E, F>
where
    E: EntityTrait,
    F: EntityTrait,
{
    fn filtering(self, search: Query) -> Result<Self, Error> {
        self.filtering_with(
            search,
            Columns::from_entity::<E>().add_columns(Columns::from_entity::<F>()),
        )
    }
}

/// SeaORM SelectThree
impl<E, F, G> Filtering<E> for SelectThree<E, F, G>
where
    E: EntityTrait,
    F: EntityTrait,
    G: EntityTrait,
{
    fn filtering(self, search: Query) -> Result<Self, Error> {
        self.filtering_with(
            search,
            Columns::from_entity::<E>()
                .add_columns(Columns::from_entity::<F>())
                .add_columns(Columns::from_entity::<G>()),
        )
    }
}

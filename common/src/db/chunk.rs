use sea_orm::{ActiveModelTrait, EntityTrait, Iterable};

pub trait EntityChunkedIter: Sized {
    type Item: ActiveModelTrait;

    fn chunked(self) -> impl Iterator<Item = Vec<Self::Item>>;
}

impl<T> EntityChunkedIter for T
where
    T: IntoIterator,
    <T as IntoIterator>::Item: ActiveModelTrait,
{
    type Item = T::Item;

    fn chunked(self) -> impl Iterator<Item = Vec<Self::Item>> {
        chunked(self)
    }
}

pub fn chunked<M, I>(i: I) -> impl Iterator<Item = Vec<I::Item>>
where
    M: ActiveModelTrait,
    I: IntoIterator<Item = M>,
{
    chunked_with(<M::Entity as EntityTrait>::Column::iter().count(), i)
}

/// Chunk up the iterator into batches suitable for ingesting into the database.
///
/// The idea is to create batches, which fit into the maximum number of parameters for an SQL
/// statement, when doing `insert_many`. Currently, the limit is `u16::MAX`, which is the limit
/// for PostgreSQL.
///
/// It works like this: `values` is the number of values that will be inserted per item. So the
/// batch size is `u16::MAX / values`. As there may be additional parameters, aside from the ones
/// used for inserting values, we lower the PostgreSQL limit by 128.
///
/// Also, if the number of values per entry exceeds the total maximum, we create batches of 1. This
/// will lead to an error when executing the statement (too many parameters), but that's just the
/// way it is anyway, chunking or not.
pub fn chunked_with<I>(values: usize, i: I) -> impl Iterator<Item = Vec<I::Item>>
where
    I: IntoIterator,
{
    let size = ((u16::MAX - 128) as usize / values).max(1);
    let mut i = i.into_iter();
    std::iter::from_fn(move || {
        let batch: Vec<_> = i.by_ref().take(size).collect();
        (!batch.is_empty()).then_some(batch)
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn chunks() {
        let size = (u16::MAX - 128) as usize;
        let batches: Vec<_> = chunked_with(1, 0..size * 2 + 1).map(|b| b.len()).collect();
        assert_eq!(batches, vec![size, size, 1]);
        assert_eq!(chunked_with(1, 0..0).count(), 0);
    }
}

mod bytesize;
pub use bytesize::*;

use crate::db::limiter::{LimitedResult, Limiter};
use sea_orm::{ConnectionTrait, DbErr, SelectorTrait};
use std::cmp::min;
use std::marker::PhantomData;
use utoipa::{IntoParams, ToSchema};

/// A struct wrapping an item with a revision.
///
/// If the revision should not be part of the payload, but e.g. an HTTP header (like `ETag`), this
/// struct can help carrying both pieces.
// NOTE: This struct must be synced with the version in the [`revisioned`] macro below.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
pub struct Revisioned<T> {
    /// The actual value
    pub value: T,
    /// The revision.
    ///
    /// An opaque string that should have no meaning to the user, only to the backend.
    pub revision: String,
}

#[derive(
    IntoParams, Copy, Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct Paginated {
    /// The first item to return, skipping all that come before it.
    ///
    /// NOTE: The order of items is defined by the API being called.
    #[serde(default)]
    pub offset: u64,
    /// The maximum number of entries to return.
    ///
    /// Zero means: no limit
    #[serde(default = "default::limit")]
    pub limit: u64,
    /// Whether to compute and return the total count of matching items.
    #[serde(default)]
    pub total: bool,
}

impl Paginated {
    /// Paginate an in-memory slice, optionally including the total count.
    pub fn paginate_array<T: Clone>(&self, vec: &[T]) -> PaginatedResults<T> {
        let total = if self.total {
            Some(vec.len() as u64)
        } else {
            None
        };

        if self.offset as usize > vec.len() {
            return PaginatedResults {
                items: vec![],
                total,
            };
        }

        if self.limit == 0 {
            return PaginatedResults {
                items: Vec::from(&vec[self.offset as usize..]),
                total,
            };
        }

        let end = min(self.offset as usize + self.limit as usize, vec.len());

        PaginatedResults {
            items: Vec::from(&vec[self.offset as usize..end]),
            total,
        }
    }
}

mod default {
    pub(super) const fn limit() -> u64 {
        25
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedResults<R> {
    pub items: Vec<R>,
    pub total: Option<u64>,
}

impl<T> Default for PaginatedResults<T> {
    fn default() -> Self {
        Self {
            items: vec![],
            total: None,
        }
    }
}

impl<R> PaginatedResults<R> {
    /// Create a new paginated result, optionally computing the total count.
    pub async fn new<C, S1, S2>(
        limiter: Limiter<'_, C, S1, S2>,
        paginated: Paginated,
    ) -> Result<PaginatedResults<S1::Item>, DbErr>
    where
        C: ConnectionTrait,
        S1: SelectorTrait,
        S2: SelectorTrait,
    {
        let LimitedResult { items, total } = limiter.fetch().await?;
        let total = total.requested(paginated.total).await?;

        Ok(PaginatedResults { items, total })
    }

    pub fn map<O, F: FnMut(R) -> O>(self, f: F) -> PaginatedResults<O> {
        PaginatedResults {
            items: self.items.into_iter().map(f).collect(),
            total: self.total,
        }
    }
}

#[derive(ToSchema)]
#[schema(value_type = String, format = Binary)]
pub struct BinaryData(PhantomData<Vec<u8>>);

#[cfg(test)]
mod test {
    use crate::model::{Paginated, PaginatedResults};

    #[test_log::test(test)]
    fn paginated_vec() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let paginated = Paginated {
            offset: 0,
            limit: 0,
            total: true,
        }
        .paginate_array(&data);

        assert_eq!(Some(10), paginated.total);
        assert_eq!(10, paginated.items.len());

        let paginated = Paginated {
            offset: 0,
            limit: 5,
            total: true,
        }
        .paginate_array(&data);

        assert_eq!(Some(10), paginated.total);
        assert_eq!(5, paginated.items.len());

        let paginated = Paginated {
            offset: 5,
            limit: 0,
            total: true,
        }
        .paginate_array(&data);

        assert_eq!(Some(10), paginated.total);
        assert_eq!(5, paginated.items.len());

        let paginated = Paginated {
            offset: 12,
            limit: 0,
            total: true,
        }
        .paginate_array(&data);

        assert_eq!(Some(10), paginated.total);
        assert_eq!(0, paginated.items.len());
    }

    #[test]
    fn paginated_vec_no_total() {
        let data = [1, 2, 3];

        let paginated = Paginated {
            offset: 0,
            limit: 0,
            total: false,
        }
        .paginate_array(&data);

        assert_eq!(None, paginated.total);
        assert_eq!(3, paginated.items.len());
    }

    #[test]
    fn map() {
        let input = PaginatedResults {
            items: vec![1, 2, 3],
            total: Some(10),
        };

        assert_eq!(
            input.map(|n| n.to_string()),
            PaginatedResults {
                items: vec!["1".to_string(), "2".to_string(), "3".to_string()],
                total: Some(10)
            }
        )
    }
}

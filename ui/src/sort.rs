//! Sorting of tables: the state of the sortable columns, and helpers to compare values.

use patternfly_yew::prelude::*;
use std::cmp::Ordering;
use yew::prelude::*;

/// The sort state of a table, for the `sortby` and `onsort` properties of its columns.
pub struct UseSort<C>
where
    C: Clone + Eq + 'static,
{
    pub sortby: Option<TableHeaderSortBy<C>>,
    pub onsort: Callback<TableHeaderSortBy<C>>,
}

/// Track the column and order a table is sorted by, `None` for the natural order.
#[hook]
pub fn use_sort<C>(initial: Option<TableHeaderSortBy<C>>) -> UseSort<C>
where
    C: Clone + Eq + 'static,
{
    let state = use_state_eq(|| initial);
    let onsort = use_callback(state.clone(), |sortby, state| state.set(Some(sortby)));
    UseSort {
        sortby: (*state).clone(),
        onsort,
    }
}

/// Apply the order to an ascending comparison.
pub fn ordered(order: Order, ordering: Ordering) -> Ordering {
    match order {
        Order::Ascending => ordering,
        Order::Descending => ordering.reverse(),
    }
}

/// Compare text case-insensitively, falling back to the exact text for a stable order.
pub fn text(a: &str, b: &str) -> Ordering {
    a.to_lowercase()
        .cmp(&b.to_lowercase())
        .then_with(|| a.cmp(b))
}

/// Compare optional values, a missing value last.
pub fn missing_last<T: Ord>(a: Option<T>, b: Option<T>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

#[cfg(test)]
mod test {
    use super::{missing_last, ordered, text};
    use patternfly_yew::prelude::Order;

    #[test]
    fn compare() {
        let mut values = vec!["b", "A", "a", "C"];
        values.sort_by(|a, b| text(a, b));
        assert_eq!(values, ["A", "a", "b", "C"]);

        values.sort_by(|a, b| ordered(Order::Descending, text(a, b)));
        assert_eq!(values, ["C", "b", "a", "A"]);

        let mut values = vec![None, Some(2), Some(1)];
        values.sort_by(|a, b| missing_last(*a, *b));
        assert_eq!(values, [Some(1), Some(2), None]);
    }
}

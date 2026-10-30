//! Shared collection fetching, pagination state, and loading/error presentation.
use crate::{api, model::PaginatedResults};
use patternfly_yew::prelude::*;
use serde::de::DeserializeOwned;
use std::{cell::Cell as CancelFlag, rc::Rc};
use trustify_api::correlation::VerdictFreshness;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_oauth2::prelude::use_latest_access_token;

/// Fetch a collection page with independent pagination, cancellation, and request state.
#[hook]
pub(super) fn use_collection<T: Clone + PartialEq + DeserializeOwned + 'static>(
    sbom_id: uuid::Uuid,
    collection: &'static str,
    count_only: bool,
) -> (
    PaginatedResults<T>,
    UsePagination,
    bool,
    Option<String>,
    Option<VerdictFreshness>,
    Callback<()>,
) {
    let items = use_state_eq(Vec::<T>::new);
    let total = use_state_eq(|| None::<usize>);
    let loading = use_state_eq(|| true);
    let error = use_state_eq(|| None::<String>);
    let freshness = use_state_eq(|| None::<VerdictFreshness>);
    let revision = use_state_eq(|| 0_u64);
    let refresh = {
        let revision = revision.clone();
        Callback::from(move |()| revision.set(*revision + 1))
    };
    let pagination = use_pagination(*total, || PaginationControl {
        page: 0,
        per_page: 25,
    });
    let latest_token = use_latest_access_token();
    let token = latest_token.as_ref().and_then(|t| t.access_token());
    {
        let (items, total, loading, error) =
            (items.clone(), total.clone(), loading.clone(), error.clone());
        let freshness = freshness.clone();
        use_effect_with(
            (
                sbom_id,
                collection,
                pagination.control,
                count_only,
                token,
                *revision,
            ),
            move |(sbom_id, collection, control, count_only, token, _)| {
                let (id, collection, control, count_only, token) = (
                    sbom_id.to_string(),
                    *collection,
                    *control,
                    *count_only,
                    token.clone(),
                );
                let cancelled = Rc::new(CancelFlag::new(false));
                let pending = cancelled.clone();
                loading.set(true);
                error.set(None);
                items.set(Vec::new());
                spawn_local(async move {
                    let response = api::fetch_correlation_page::<T>(
                        &id,
                        collection,
                        control.page * control.per_page,
                        if count_only { 0 } else { control.per_page },
                        true,
                        token.as_deref(),
                    )
                    .await;
                    if pending.get() {
                        return;
                    }
                    match response {
                        Ok(page) => {
                            freshness.set(page.freshness);
                            total.set(page.total.and_then(|n| usize::try_from(n).ok()));
                            items.set(page.items);
                        }
                        Err(err) => error.set(Some(err.to_string())),
                    }
                    loading.set(false);
                });
                move || cancelled.set(true)
            },
        );
    }
    (
        PaginatedResults {
            items: (*items).clone(),
            total: (*total).map(|n| n as u64),
        },
        pagination,
        *loading,
        (*error).clone(),
        (*freshness).clone(),
        refresh,
    )
}

/// Render the loading, error, or empty state of a collection page.
pub(super) fn page_status<T>(
    page: &PaginatedResults<T>,
    loading: bool,
    error: Option<&str>,
    empty: &'static str,
) -> Html {
    if loading {
        html!(<Spinner size={SpinnerSize::Md} />)
    } else if let Some(error) = error {
        html!(<Alert title="Failed to load correlation data" r#type={AlertType::Danger} inline=true><p>{error}</p></Alert>)
    } else if page.items.is_empty() {
        html!(<EmptyState title={empty} icon={Icon::InfoCircle} size={Size::Large} />)
    } else {
        Html::default()
    }
}

//! State of a view kept in the session storage of the browser, so that it is restored when
//! navigating back to the view (e.g. the page of a list).
//!
//! Storage is a convenience: if it isn't available (e.g. disabled), the defaults are used.

use patternfly_yew::prelude::*;
use serde::{Serialize, de::DeserializeOwned};
use yew::prelude::*;

/// The key of a stored value of a view.
fn storage_key(view: &str, name: &str) -> String {
    format!("trustify.{view}.{name}")
}

/// Load a stored value, `None` if there is none or it can't be read.
fn load<T: DeserializeOwned>(key: &str) -> Option<T> {
    let storage = gloo_utils::window().session_storage().ok().flatten()?;
    let value = storage.get_item(key).ok().flatten()?;
    serde_json::from_str(&value)
        .inspect_err(|err| log::debug!("ignoring stored value of {key}: {err}"))
        .ok()
}

/// Store a value, ignoring an unavailable storage.
fn save<T: Serialize>(key: &str, value: &T) {
    let Some(storage) = gloo_utils::window().session_storage().ok().flatten() else {
        return;
    };
    match serde_json::to_string(value) {
        Ok(value) => {
            if let Err(err) = storage.set_item(key, &value) {
                log::debug!("failed to store {key}: {err:?}");
            }
        }
        Err(err) => log::debug!("failed to serialize {key}: {err}"),
    }
}

/// The pagination of a view, restored from and kept in the session storage.
#[hook]
pub fn use_stored_pagination(view: &'static str, total: Option<usize>) -> UsePagination {
    let key = storage_key(view, "pagination");
    let pagination = use_pagination(total, {
        let key = key.clone();
        move || load(&key).unwrap_or_default()
    });
    use_effect_with((key, pagination.control), |(key, control)| {
        save(key, control)
    });
    pagination
}

/// A text of a view (e.g. its search), restored from and kept in the session storage.
#[hook]
pub fn use_stored_text(view: &'static str, name: &'static str) -> UseStateHandle<String> {
    let key = storage_key(view, name);
    let state = use_state_eq({
        let key = key.clone();
        move || load::<String>(&key).unwrap_or_default()
    });
    use_effect_with((key, (*state).clone()), |(key, value)| save(key, value));
    state
}

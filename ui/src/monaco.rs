//! Setup of the Monaco editor.
//!
//! The `monaco` crate's `workers` feature embeds all language workers into the WASM. Instead, the
//! workers needed are served as static files (`assets/monaco`) and loaded on demand.

use js_sys::Reflect;
use monaco::sys::{Environment, GetWorkerUrlFn};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};

const ENVIRONMENT: &str = "MonacoEnvironment";

/// The URL of the worker for a label, relative to the base URL of the page.
fn worker_url(_module_id: String, label: String) -> String {
    match label.as_str() {
        "json" => "monaco/json.worker.js",
        _ => "monaco/editor.worker.js",
    }
    .to_string()
}

/// Set up the Monaco environment, unless it is set up already.
///
/// Must be called before the first editor is created.
pub fn ensure_environment() {
    let window = gloo_utils::window();
    let key = JsValue::from_str(ENVIRONMENT);

    if Reflect::get(&window, &key).is_ok_and(|env| env.is_truthy()) {
        return;
    }

    let get_worker_url = Closure::wrap(Box::new(worker_url) as Box<GetWorkerUrlFn>);
    let env = Environment::default();
    env.set_get_worker_url(Some(get_worker_url.as_ref().unchecked_ref()));
    // The environment lives as long as the page.
    get_worker_url.forget();

    if let Err(err) = Reflect::set(&window, &key, &env) {
        log::error!("Failed to set up the Monaco environment: {err:?}");
    }
}

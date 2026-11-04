//! Numbers for display, with thousands separators.

use std::fmt;
use yew::{Html, html::IntoPropValue};

/// A number, displayed with the thousands separators of the user's locale.
///
/// Usable in `format!`, and directly in `html!`, as text or as the children of a component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Number(pub u64);

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&localized(self.0))
    }
}

/// As the only child of a component, e.g. `<Title>{ Number(n) }</Title>`.
impl IntoPropValue<Html> for Number {
    fn into_prop_value(self) -> Html {
        Html::from(self.to_string())
    }
}

/// The number in the user's locale.
#[cfg(target_arch = "wasm32")]
fn localized(value: u64) -> String {
    use wasm_bindgen::JsValue;

    let format = js_sys::Intl::NumberFormat::new(&js_sys::Array::new(), &js_sys::Object::new());
    // counts stay far below 2^53, where an f64 is exact
    format
        .format()
        .call1(&JsValue::UNDEFINED, &JsValue::from_f64(value as f64))
        .ok()
        .and_then(|formatted| formatted.as_string())
        .unwrap_or_else(|| grouped(value))
}

/// Without a browser, there is no locale: use commas.
#[cfg(not(target_arch = "wasm32"))]
fn localized(value: u64) -> String {
    grouped(value)
}

/// A number with commas as thousands separators.
fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut result = String::with_capacity(digits.len() + digits.len() / 3);
    for (n, digit) in digits.chars().enumerate() {
        if n > 0 && (digits.len() - n).is_multiple_of(3) {
            result.push(',');
        }
        result.push(digit);
    }
    result
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn grouping() {
        assert_eq!(
            [0, 7, 999, 1_000, 12_345, 999_999, 1_234_567, u64::MAX].map(|n| Number(n).to_string()),
            [
                "0",
                "7",
                "999",
                "1,000",
                "12,345",
                "999,999",
                "1,234,567",
                "18,446,744,073,709,551,615",
            ]
        );
    }
}

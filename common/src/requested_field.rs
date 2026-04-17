use isx::IsDefault;
use serde::{Deserialize, Serialize, Serializer};
use std::borrow::Cow;
use utoipa::{
    ToSchema,
    openapi::{RefOr, Schema},
};

/// Tri-state wrapper for response fields that are only included on request.
///
/// * `NotRequested` — the caller did not ask for this field; it is omitted from the response
///   (via `skip_serializing_if = "IsDefault::is_default"`).
/// * `Requested(None)` — the field was requested but no data is available; serialized as `null`.
/// * `Requested(Some(value))` — the field was requested and data is present; serialized normally.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum RequestedField<T> {
    #[default]
    NotRequested,
    Requested(Option<T>),
}

impl<T> IsDefault for RequestedField<T> {
    fn is_default(&self) -> bool {
        matches!(self, RequestedField::NotRequested)
    }
}

impl<T> From<Option<T>> for RequestedField<T> {
    fn from(option: Option<T>) -> Self {
        RequestedField::Requested(option)
    }
}

impl<T: Serialize> Serialize for RequestedField<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            RequestedField::NotRequested => serializer.serialize_none(),
            RequestedField::Requested(inner) => inner.serialize(serializer),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for RequestedField<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(RequestedField::Requested(Option::<T>::deserialize(
            deserializer,
        )?))
    }
}

impl<T: utoipa::__dev::ComposeSchema> utoipa::__dev::ComposeSchema for RequestedField<T> {
    fn compose(generics: Vec<RefOr<Schema>>) -> RefOr<Schema> {
        <Option<T> as utoipa::__dev::ComposeSchema>::compose(generics)
    }
}

impl<T: utoipa::__dev::ComposeSchema> ToSchema for RequestedField<T> {
    fn name() -> Cow<'static, str> {
        "RequestedField".into()
    }
}

/// Extension trait to construct a `RequestedField` from a boolean flag.
pub trait BoolRequestedField {
    /// Returns `Requested(f())` when `true`, `NotRequested` when `false`.
    fn then_requested<T>(self, f: impl FnOnce() -> Option<T>) -> RequestedField<T>;
}

impl BoolRequestedField for bool {
    fn then_requested<T>(self, f: impl FnOnce() -> Option<T>) -> RequestedField<T> {
        if self {
            RequestedField::Requested(f())
        } else {
            RequestedField::NotRequested
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::{Value, json};

    #[derive(Serialize, Deserialize, Debug)]
    struct Response {
        name: String,
        #[serde(default, skip_serializing_if = "IsDefault::is_default")]
        data: RequestedField<Vec<i32>>,
    }

    #[rstest]
    #[case::not_requested(RequestedField::NotRequested, None)]
    #[case::requested_none(RequestedField::Requested(None), Some(Value::Null))]
    #[case::requested_some(
        RequestedField::Requested(Some(vec![1, 2, 3])),
        Some(json!([1, 2, 3])),
    )]
    fn serialization(#[case] data: RequestedField<Vec<i32>>, #[case] expected: Option<Value>) {
        let r = Response {
            name: "test".into(),
            data,
        };
        let v = serde_json::to_value(&r).expect("serialize");
        assert_eq!(v.get("data").cloned(), expected);
    }

    #[rstest]
    #[case::absent(json!({"name": "test"}), RequestedField::NotRequested)]
    #[case::null(json!({"name": "test", "data": null}), RequestedField::Requested(None))]
    #[case::value(
        json!({"name": "test", "data": [1, 2]}),
        RequestedField::Requested(Some(vec![1, 2])),
    )]
    fn deserialization(#[case] input: Value, #[case] expected: RequestedField<Vec<i32>>) {
        let r: Response = serde_json::from_value(input).expect("deserialize");
        assert_eq!(r.data, expected);
    }

    #[rstest]
    #[case::not_requested(RequestedField::NotRequested)]
    #[case::requested_none(RequestedField::Requested(None))]
    #[case::requested_some(RequestedField::Requested(Some(vec![42])))]
    fn round_trip(#[case] data: RequestedField<Vec<i32>>) {
        let original = Response {
            name: "test".into(),
            data,
        };
        let json = serde_json::to_value(&original).expect("serialize");
        let restored: Response = serde_json::from_value(json).expect("deserialize");
        assert_eq!(original.data, restored.data);
    }

    #[rstest]
    #[case::some(Some(42), RequestedField::Requested(Some(42)))]
    #[case::none(None, RequestedField::Requested(None))]
    fn from_option(#[case] input: Option<i32>, #[case] expected: RequestedField<i32>) {
        assert_eq!(RequestedField::from(input), expected);
    }

    #[rstest]
    #[case::true_some(true, Some(42), RequestedField::Requested(Some(42)))]
    #[case::true_none(true, None, RequestedField::Requested(None))]
    #[case::false_some(false, Some(42), RequestedField::NotRequested)]
    #[case::false_none(false, None, RequestedField::NotRequested)]
    fn then_requested_cases(
        #[case] flag: bool,
        #[case] value: Option<i32>,
        #[case] expected: RequestedField<i32>,
    ) {
        assert_eq!(flag.then_requested(|| value), expected);
    }
}

use std::{
    borrow::Cow,
    collections::HashMap,
    ops::{Deref, DerefMut},
};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{ObjectBuilder, RefOr, Schema, schema::AdditionalProperties},
};

#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    ::serde::Serialize,
    ::serde::Deserialize,
    sea_orm::FromJsonQueryResult,
    schemars::JsonSchema,
)]
pub struct Labels(pub HashMap<String, String>);

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid label: {0}")]
    InvalidLabel(Cow<'static, str>),
}

impl ToSchema for Labels {
    fn name() -> Cow<'static, str> {
        "Labels".into()
    }
}

impl PartialSchema for Labels {
    fn schema() -> RefOr<Schema> {
        let value = String::schema();
        let props = AdditionalProperties::RefOr(value);
        ObjectBuilder::new()
            .additional_properties(Some(props))
            .build()
            .into()
    }
}

#[cfg(feature = "async-graphql")]
async_graphql::scalar!(Labels);

impl Labels {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_one(k: impl Into<String>, v: impl Into<String>) -> Self {
        let mut labels = HashMap::with_capacity(1);
        labels.insert(k.into(), v.into());
        Self(labels)
    }

    pub fn add(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.0.insert(k.into(), v.into());
        self
    }

    pub fn extend<I, K, V>(mut self, i: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.0
            .extend(i.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Validate labels of the current instance, or fail
    ///
    /// See [Self::validate] for details of the validation.
    pub fn validate_mut(&mut self) -> Result<(), Error> {
        let mut result = HashMap::with_capacity(self.0.len());

        for (k, v) in &self.0 {
            let k = k.trim().to_string();
            let v = v.trim().to_string();

            if k.is_empty() {
                return Err(Error::InvalidLabel("empty keys are now allowed".into()));
            }

            if k.contains('=') || k.contains('\\') {
                return Err(Error::InvalidLabel(
                    format!("key must not contain '=' or '\' ({k})").into(),
                ));
            }

            if v.contains('=') {
                return Err(Error::InvalidLabel(
                    format!("value of '{k}'contains '=', which is not allowed").into(),
                ));
            }

            result.insert(k, v);
        }

        self.0 = result;

        Ok(())
    }

    /// Validate labels, returning the result, or fail
    ///
    /// ## Rules
    ///
    /// This will apply the following rules:
    ///
    /// * First trim (start, end) all "whitespaces" (see [`str::trim`])
    /// * Then, ensure that keys are not empty
    /// * Neither keys nor values must contain the `=` character
    ///
    /// ## Mutability
    ///
    /// Trimming may result in a mutation of the original input. In cases where trimming keys
    /// results in overlapping keys, there is no guarantee of which value has precedence.
    pub fn validate(mut self) -> Result<Self, Error> {
        self.validate_mut()?;
        Ok(self)
    }
}

impl<'a> FromIterator<(&'a str, &'a str)> for Labels {
    fn from_iter<T: IntoIterator<Item = (&'a str, &'a str)>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }
}

impl From<()> for Labels {
    fn from(_: ()) -> Self {
        Default::default()
    }
}

impl<const N: usize> From<[(&str, &str); N]> for Labels {
    fn from(value: [(&str, &str); N]) -> Self {
        Self::from_iter(value)
    }
}

impl From<HashMap<String, String>> for Labels {
    fn from(value: HashMap<String, String>) -> Self {
        Self(value)
    }
}

impl From<HashMap<&str, &str>> for Labels {
    fn from(value: HashMap<&str, &str>) -> Self {
        Labels::from_iter(value)
    }
}

impl<K, V> From<(K, V)> for Labels
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    fn from((k, v): (K, V)) -> Self {
        let mut value = HashMap::with_capacity(1);
        value.insert(k.as_ref().to_string(), v.as_ref().to_string());
        Self(value)
    }
}

impl Deref for Labels {
    type Target = HashMap<String, String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Labels {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    ::serde::Serialize,
    ::serde::Deserialize,
    sea_orm::FromJsonQueryResult,
    schemars::JsonSchema,
)]
pub struct Update(pub HashMap<String, Option<String>>);

impl Update {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a label update.
    ///
    /// This will apply the provided update to the current set of labels. Updates with an empty
    /// value will remove the label.
    pub fn apply_to(self, mut labels: Labels) -> Labels {
        for (k, v) in self.0 {
            match v {
                Some(v) => {
                    labels.insert(k, v);
                }
                None => {
                    labels.remove(&k);
                }
            }
        }

        labels
    }

    pub fn add(mut self, k: impl Into<String>, v: Option<impl Into<String>>) -> Self {
        self.0.insert(k.into(), v.map(Into::into));
        self
    }

    pub fn extend<I, K, V>(mut self, i: I) -> Self
    where
        I: IntoIterator<Item = (K, Option<V>)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.0
            .extend(i.into_iter().map(|(k, v)| (k.into(), v.map(Into::into))));
        self
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl ToSchema for Update {
    fn name() -> Cow<'static, str> {
        "Update".into()
    }
}

impl PartialSchema for Update {
    fn schema() -> RefOr<Schema> {
        let value = Option::<String>::schema();
        let props = AdditionalProperties::RefOr(value);
        ObjectBuilder::new()
            .additional_properties(Some(props))
            .description(Some(r#"An update set for labels.

This is a key/value set, where the value can be a string for setting that value, or `null` for removing the label.
"#))
            .build()
            .into()
    }
}

impl<'a> FromIterator<(&'a str, Option<&'a str>)> for Update {
    fn from_iter<T: IntoIterator<Item = (&'a str, Option<&'a str>)>>(iter: T) -> Self {
        Self(
            iter.into_iter()
                .map(|(k, v)| (k.to_string(), v.map(|v| v.to_string())))
                .collect(),
        )
    }
}

impl From<()> for Update {
    fn from(_: ()) -> Self {
        Default::default()
    }
}

impl<const N: usize> From<[(&str, &str); N]> for Update {
    fn from(value: [(&str, &str); N]) -> Self {
        Self(
            value
                .into_iter()
                .map(|(k, v)| (k.to_string(), Some(v.to_string())))
                .collect(),
        )
    }
}

impl From<HashMap<String, Option<String>>> for Update {
    fn from(value: HashMap<String, Option<String>>) -> Self {
        Self(value)
    }
}

/// A module to serialize/deserialize labels with a prefix of `.labels`.
///
/// This can be embedded in a struct like this:
///
/// ```rust
/// # use trustify_entity::labels::Labels;
/// #[derive(serde::Deserialize)]
/// struct Example {
///   other_field: String,
///   #[serde(flatten, with="trustify_entity::labels::prefixed")]
///   labels: Labels,
/// }
/// ```
pub mod prefixed {
    use crate::labels::Labels;
    use serde::de::{MapAccess, Visitor};
    use serde::ser::SerializeMap;
    use serde::{Deserializer, Serializer};
    use std::fmt::Formatter;

    pub fn serialize<S: Serializer>(labels: &Labels, serializer: S) -> Result<S::Ok, S::Error> {
        let mut m = serializer.serialize_map(Some(labels.0.len()))?;
        for (k, v) in &labels.0 {
            m.serialize_key(&format!("labels.{k}"))?;
            m.serialize_value(v)?;
        }
        m.end()
    }

    pub fn deserialize<'a, D: Deserializer<'a>>(deserializer: D) -> Result<Labels, D::Error> {
        deserializer.deserialize_map(PrefixLabelsVisitor { prefix: "labels." })
    }

    struct PrefixLabelsVisitor<'p> {
        prefix: &'p str,
    }

    impl<'de> Visitor<'de> for PrefixLabelsVisitor<'_> {
        type Value = Labels;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            write!(formatter, "a map with fields prefixed by {}", self.prefix)
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut result = Labels::new();

            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if let Some(key) = key.strip_prefix(self.prefix) {
                    result.0.insert(key.to_string(), value);
                }
            }

            Ok(result)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    #[test]
    fn apply_update() {
        let original = Labels::new().extend([("foo", "1"), ("bar", "2")]);
        let modified = Update::new()
            .extend([("foo", Some("2")), ("bar", None), ("baz", Some("3"))])
            .apply_to(original);

        assert_eq!(
            modified.0,
            HashMap::from_iter([
                ("foo".to_string(), "2".to_string()),
                ("baz".to_string(), "3".to_string())
            ])
        );
    }

    #[derive(Clone, Debug, PartialEq, Eq, ::serde::Serialize, ::serde::Deserialize)]
    struct Example {
        foo: String,
        bar: i32,
        #[serde(flatten, with = "super::prefixed")]
        labels: Labels,
    }

    #[test]
    fn parse_labels() {
        assert_eq!(
            Example {
                foo: "bar".to_string(),
                bar: 42,
                labels: Labels::new().add("foo", "bar").add("bar", "42"),
            },
            serde_json::from_value(json!({
                "foo": "bar",
                "bar": 42,
                "labels.foo": "bar",
                "labels.bar": "42",
            }))
            .expect("must parse"),
        );
    }

    #[test]
    fn parse_empty_labels() {
        assert_eq!(
            Example {
                foo: "bar".to_string(),
                bar: 42,
                labels: Labels::new(),
            },
            serde_json::from_value(json!({
                "foo": "bar",
                "bar": 42,
            }))
            .expect("must parse"),
        );
    }

    #[test]
    fn serialize_labels() {
        assert_eq!(
            serde_json::to_value(Example {
                foo: "bar".to_string(),
                bar: 42,
                labels: Labels::new().add("foo", "bar").add("bar", "42"),
            })
            .expect("must serialize"),
            json!({
                "foo": "bar",
                "bar": 42,
                "labels.foo": "bar",
                "labels.bar": "42",
            }),
        );
    }

    #[test]
    fn validate_label_ok() {
        assert_eq!(
            Labels::new()
                .add("foo", "bar")
                .add("foo foo ", "bar bar ")
                .add("bar bar", " bar bar ")
                .add("buz", "  ")
                .validate(),
            Ok(Labels::new()
                .add("foo", "bar")
                .add("foo foo", "bar bar")
                .add("bar bar", "bar bar")
                .add("buz", ""))
        );
    }

    #[test]
    fn validate_label_err() {
        assert!(Labels::new().add("foo=bar", "").validate().is_err());
        assert!(Labels::new().add("   ", "foo").validate().is_err());
        assert!(Labels::new().add("  =  ", "foo").validate().is_err());
        assert!(Labels::new().add("foo", "foo=bar").validate().is_err());
        assert!(Labels::new().add("foo", "  == ").validate().is_err());
        assert!(Labels::new().add("foo\\", "bar").validate().is_err());
    }
}

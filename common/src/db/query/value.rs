use chrono::{Local, NaiveDateTime};
use human_date_parser::{ParseResult, from_human_time};
use std::sync::Arc;
use std::{cmp::Ordering, collections::HashMap, fmt::Debug};
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub enum Value<'a> {
    String(&'a str),
    Int(i32),
    Float(f64),
    Date(&'a OffsetDateTime),
    Array(Vec<Value<'a>>),
    Json(serde_json::Value),
    Custom(&'a dyn Valuable),
}

#[derive(Default)]
pub struct ValueContext<'a> {
    values: HashMap<String, Value<'a>>,
}

pub trait Context {
    fn get(&self, key: &str) -> Option<Value<'_>>;
    fn values(&self) -> impl Iterator<Item = &Value<'_>>;
}

pub trait Valuable: PartialOrd<String> + Debug {
    fn like(&self, pat: &str) -> bool;
}

impl Valuable for Value<'_> {
    fn like(&self, pat: &str) -> bool {
        match self {
            Self::String(s) => s.contains(pat),
            Self::Date(d) => d.to_string().contains(pat),
            Self::Array(a) => a.iter().any(|v| v.like(pat)),
            Self::Custom(v) => v.like(pat),
            Self::Int(_) | Self::Float(_) => false,
            Self::Json(v) => JsonValue(v).like(pat),
        }
    }
}

impl PartialEq<String> for Value<'_> {
    fn eq(&self, rhs: &String) -> bool {
        match self {
            Self::String(s) => s.eq(rhs),
            Self::Array(arr) => arr.iter().any(|v| v.eq(rhs)),
            Self::Json(v) => JsonValue(v).eq(rhs),
            Self::Custom(v) => v.eq(&rhs),
            _ => matches!(self.partial_cmp(rhs), Some(Ordering::Equal)),
        }
    }
}

impl PartialOrd<String> for Value<'_> {
    fn partial_cmp(&self, rhs: &String) -> Option<Ordering> {
        match self {
            Self::String(s) => s.partial_cmp(&rhs.as_str()),
            Self::Int(v) => match rhs.parse::<i32>() {
                Ok(i) => v.partial_cmp(&i),
                _ => None,
            },
            Self::Float(v) => match rhs.parse::<f64>() {
                Ok(i) => v.partial_cmp(&i),
                _ => None,
            },
            Self::Date(v) => {
                let now = Local::now().naive_local();
                match from_human_time(&v.to_string(), now) {
                    Ok(ParseResult::DateTime(field)) => match from_human_time(rhs, now) {
                        Ok(ParseResult::DateTime(other)) => field.partial_cmp(&other),
                        Ok(ParseResult::Date(d)) => {
                            let other = NaiveDateTime::new(d, field.time());
                            field.partial_cmp(&other)
                        }
                        Ok(ParseResult::Time(t)) => {
                            let other = NaiveDateTime::new(field.date(), t);
                            field.partial_cmp(&other)
                        }
                        _ => None,
                    },
                    _ => None,
                }
            }
            Self::Array(arr) => {
                if arr.iter().any(|v| v.eq(rhs)) {
                    Some(Ordering::Equal)
                } else if arr.iter().all(|v| v.gt(rhs)) {
                    Some(Ordering::Greater)
                } else if arr.iter().all(|v| v.lt(rhs)) {
                    Some(Ordering::Less)
                } else {
                    None
                }
            }
            Self::Json(v) => JsonValue(v).partial_cmp(rhs),
            Self::Custom(v) => v.partial_cmp(&rhs),
        }
    }
}

impl<'a, T: Valuable> From<&'a Vec<T>> for Value<'a> {
    fn from(v: &'a Vec<T>) -> Self {
        Value::Array(v.iter().map(|v| Value::Custom(v)).collect())
    }
}

impl<'a, T: Valuable> From<&'a Arc<[T]>> for Value<'a> {
    fn from(arc_slice: &'a Arc<[T]>) -> Self {
        Value::Array(
            // dereference Arc to slice `&[T]`, then iterate
            arc_slice
                .iter()
                // map each element `&T` to `Value::Custom(&T)`
                .map(|item_ref| Value::Custom(item_ref))
                .collect(),
        )
    }
}

impl Context for &ValueContext<'_> {
    fn get(&self, key: &str) -> Option<Value<'_>> {
        fn nested<'a>(json: &'a serde_json::Value, ks: &str) -> Option<Value<'a>> {
            ks.split_terminator(':')
                .try_fold(json, |obj, key| obj.get(key))
                .and_then(|v| match v {
                    serde_json::Value::String(s) => Some(Value::String(s)),
                    _ => None,
                })
        }
        self.values.get(key).cloned().or_else(|| {
            key.split_once(':').and_then(|(k, ks)| {
                self.values.get(k).and_then(|v| match &v {
                    Value::Json(json) => nested(json, ks),
                    Value::Array(arr) => Some(Value::Array(
                        arr.iter()
                            .filter_map(|v| match v {
                                Value::Json(json) => nested(json, ks),
                                _ => None,
                            })
                            .collect(),
                    )),
                    _ => None,
                })
            })
        })
    }
    fn values(&self) -> impl Iterator<Item = &Value<'_>> {
        self.values.values()
    }
}

impl<'a> ValueContext<'a> {
    pub fn put_string<S: Into<String>>(&mut self, key: S, value: &'a str) {
        self.put(key.into(), Value::String(value));
    }
    pub fn put_int<K: Into<String>>(&mut self, key: K, value: i32) {
        self.put(key.into(), Value::Int(value));
    }
    pub fn put_float<K: Into<String>>(&mut self, key: K, value: f64) {
        self.put(key.into(), Value::Float(value));
    }
    pub fn put_date<K: Into<String>>(&mut self, key: K, value: &'a OffsetDateTime) {
        self.put(key.into(), Value::Date(value));
    }
    pub fn put_array<K: Into<String>>(&mut self, key: K, value: Vec<Value<'a>>) {
        self.put(key.into(), Value::Array(value));
    }
    pub fn put_json<K: Into<String>>(&mut self, key: K, value: serde_json::Value) {
        self.put(key.into(), Value::Json(value));
    }
    pub fn put_value<K: Into<String>>(&mut self, key: K, value: Value<'a>) {
        self.put(key.into(), value);
    }
    // Convenient initialization
    pub fn from<K: Into<String>, const N: usize>(arr: [(K, Value<'a>); N]) -> Self {
        Self {
            values: HashMap::from(arr.map(|(k, v)| (k.into(), v))),
        }
    }
    fn put(&mut self, key: String, value: Value<'a>) {
        self.values
            .entry(key)
            .and_modify(|val| match val {
                Value::Array(arr) => match value.clone() {
                    Value::Array(other) => arr.extend(other),
                    v => arr.push(v),
                },
                _ => *val = Value::Array(vec![val.clone(), value.clone()]),
            })
            .or_insert(value);
    }
}

#[derive(Debug)]
struct JsonValue<'a>(&'a serde_json::Value);

impl Valuable for JsonValue<'_> {
    fn like(&self, pat: &str) -> bool {
        match self.0 {
            serde_json::Value::String(s) => s.contains(pat),
            serde_json::Value::Array(a) => a.iter().map(JsonValue).any(|v| v.like(pat)),
            serde_json::Value::Object(o) => o.values().map(JsonValue).any(|v| v.like(pat)),
            _ => false,
        }
    }
}

impl PartialOrd<String> for JsonValue<'_> {
    fn partial_cmp(&self, rhs: &String) -> Option<Ordering> {
        match self.0 {
            serde_json::Value::String(s) => s.partial_cmp(rhs),
            serde_json::Value::Array(arr) => {
                if arr.iter().any(|v| v.eq(rhs)) {
                    Some(Ordering::Equal)
                } else if arr.iter().map(JsonValue).all(|v| v.gt(rhs)) {
                    Some(Ordering::Greater)
                } else if arr.iter().map(JsonValue).all(|v| v.lt(rhs)) {
                    Some(Ordering::Less)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl PartialEq<String> for JsonValue<'_> {
    fn eq(&self, rhs: &String) -> bool {
        match self.0 {
            serde_json::Value::String(s) => s.eq(rhs),
            serde_json::Value::Array(a) => a.iter().any(|v| v.eq(rhs)),
            serde_json::Value::Object(o) => o.values().any(|v| v.eq(rhs)),
            _ => false,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::*;
    use super::*;
    use test_log::test;

    #[test(tokio::test)]
    async fn filter_values() -> Result<(), anyhow::Error> {
        use time::format_description::well_known::Rfc2822;
        let now = time::OffsetDateTime::now_utc();
        let then = OffsetDateTime::parse("Sat, 12 Jun 1993 13:25:19 GMT", &Rfc2822)?;
        let context = ValueContext::from([
            ("id", Value::String("foo")),
            ("count", Value::Int(42)),
            ("score", Value::Float(6.66)),
            ("detected", Value::Date(&then)),
            ("published", Value::Date(&now)),
        ]);
        assert!(q("oo|aa|bb&count<100&count>10&id=foo").apply(&context));
        assert!(q("score=6.66").apply(&context));
        assert!(q("count>=42&count<=42").apply(&context));
        assert!(q("published>2 days ago&published<next week").apply(&context));

        assert!(q("detected=1993-06-12").apply(&context));
        assert!(q("detected>13:20:00").apply(&context));
        assert!(q("detected~1993").apply(&context));
        assert!(q("1993").apply(&context));

        assert!(q(&format!("published={now}")).apply(&context));
        assert!(q(&format!("published={}", now.date())).apply(&context));
        assert!(q(&format!("published={}", now.time())).apply(&context));
        assert!(q(&format!("published>=today {}", now.time())).apply(&context));
        assert!(q(&format!("published>={now}")).apply(&context));
        assert!(q(&format!("published<={}", now.date())).apply(&context));
        assert!(q(&format!("published~{}", now.time())).apply(&context));

        Ok(())
    }

    #[test(tokio::test)]
    async fn filter_array_custom_values() -> Result<(), anyhow::Error> {
        use crate::purl::Purl;

        let purl = Purl::from_str("pkg:x/foo").unwrap();
        let purls = vec![Value::Custom(&purl), Value::String("pkg:x/bar")];
        let context = ValueContext::from([("purl", Value::Array(purls))]);

        assert!(q("purl=pkg:x/foo").apply(&context));
        assert!(!q("purl!=pkg:x/foo").apply(&context));
        assert!(q("purl~pkg:x").apply(&context));
        assert!(q("purl!~pkg:y").apply(&context));
        assert!(q("purl~foo").apply(&context));
        assert!(q("purl!~baz").apply(&context));
        assert!(q("purl<pkg:y/foo").apply(&context));
        assert!(q("purl>pkg:w/foo").apply(&context));
        assert!(q("purl<pkg:y").apply(&context));
        assert!(q("purl>pkg:w").apply(&context));

        assert!(q("pkg:x/foo").apply(&context));
        assert!(q("pkg:x/bar").apply(&context));
        assert!(q("foo|bar").apply(&context));
        assert!(!q("bizz|buzz").apply(&context));

        Ok(())
    }

    #[test(tokio::test)]
    async fn filter_nested_values() -> Result<(), anyhow::Error> {
        use crate::purl::Purl;
        use serde_json::{Value as Json, json};

        let purl = Purl::from_str("pkg:rpm/foo@1.0?k1=v1&k2=v2")?;
        let parts = json!({
            "ty": "rpm",
            "name": "foo",
            "version": "1.0",
        });
        let other = json!({
            "ty": "maven",
            "name": "bar",
            "version": "42",
        });

        let mut context = ValueContext::from([("purl", Value::Custom(&purl))]);
        context.put_json("qualifiers", Json::from(&purl)["qualifiers"].clone());
        context.put_json("purl", parts);
        context.put_json("purl", other); // shouldn't overwrite

        assert!(q("purl~pkg:rpm/foo").apply(&context));
        assert!(q("qualifiers:k1=v1").apply(&context));
        assert!(q("qualifiers:k2!=v1").apply(&context));
        assert!(!q("qualifiers:missing!=anything").apply(&context));
        assert!(q("purl:name=foo").apply(&context));
        assert!(q("purl:version=1.0").apply(&context));
        assert!(q("purl:version=42").apply(&context));
        assert!(!q("purl:version<1").apply(&context));
        assert!(q("42").apply(&context));
        assert!(!q("43").apply(&context));

        Ok(())
    }
}

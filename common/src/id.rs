use crate::purl::PurlErr;
use hex::ToHex;
use ring::digest::Digest;
use sea_orm::{EntityTrait, QueryFilter, Select, UpdateMany};
use sea_query::Condition;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error, Visitor},
};
use serde_json::json;
use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
    str::FromStr,
};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{Object, RefOr, Schema, Type},
};
use uuid::Uuid;

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum Id {
    Uuid(Uuid),
    Sha256(String),
    Sha384(String),
    Sha512(String),
}

impl Id {
    /// Create a `Vec<Id>` from a fields of a document.
    pub fn build_vec(sha256: String, sha384: Option<String>, sha512: Option<String>) -> Vec<Self> {
        let mut result = vec![Id::Sha256(sha256)];
        result.extend(sha384.map(Id::Sha384));
        result.extend(sha512.map(Id::Sha512));
        result
    }

    /// Get the value of the [`Id::Uuid`] variant, or return `None` if it is another variant.
    pub fn try_as_uid(&self) -> Option<Uuid> {
        match &self {
            Self::Uuid(uuid) => Some(*uuid),
            _ => None,
        }
    }
}

/// Create a filter for an ID
pub trait TryFilterForId {
    /// Return a condition, filtering for the [`Id`]. Or an `Err(IdError::UnsupportedAlgorithm)` if the ID type is not supported.
    fn try_filter(id: Id) -> Result<Condition, IdError>;
}

pub trait TrySelectForId: Sized {
    fn try_filter(self, id: Id) -> Result<Self, IdError>;
}

impl<E> TrySelectForId for Select<E>
where
    E: EntityTrait + TryFilterForId,
{
    fn try_filter(self, id: Id) -> Result<Self, IdError> {
        Ok(self.filter(E::try_filter(id)?))
    }
}

impl<E> TrySelectForId for UpdateMany<E>
where
    E: EntityTrait + TryFilterForId,
{
    fn try_filter(self, id: Id) -> Result<Self, IdError> {
        Ok(self.filter(E::try_filter(id)?))
    }
}

impl Id {
    pub fn prefix(&self) -> &'static str {
        match self {
            Id::Sha256(_) => "sha256",
            Id::Sha384(_) => "sha384",
            Id::Sha512(_) => "sha512",
            Id::Uuid(_) => "urn:uuid",
        }
    }

    pub fn value(&self) -> String {
        match self {
            Id::Sha256(inner) => inner.clone(),
            Id::Sha384(inner) => inner.clone(),
            Id::Sha512(inner) => inner.clone(),
            Id::Uuid(inner) => inner.simple().to_string(),
        }
    }

    pub fn sha256(digest: &Digest) -> Self {
        Self::from_digest(digest, Id::Sha256)
    }

    pub fn sha384(digest: &Digest) -> Self {
        Self::from_digest(digest, Id::Sha384)
    }

    pub fn sha512(digest: &Digest) -> Self {
        Self::from_digest(digest, Id::Sha512)
    }

    fn from_digest<F>(digest: &Digest, f: F) -> Self
    where
        F: FnOnce(String) -> Self,
    {
        f(digest.encode_hex())
    }

    /// Parse string as [`Uuid`] and return as [`Id::Uuid`] variant.
    pub fn parse_uuid(uuid: impl AsRef<str>) -> Result<Self, IdError> {
        Ok(Self::Uuid(
            uuid.as_ref().parse().map_err(IdError::InvalidUuid)?,
        ))
    }
}

impl ToSchema for Id {
    fn name() -> Cow<'static, str> {
        "Id".into()
    }
}

impl PartialSchema for Id {
    fn schema() -> RefOr<Schema> {
        let mut obj = Object::with_type(Type::String);
        obj.description = Some(
            r#"Identifier to a document, prefixed with the ID type.

Either an internal ID of the document with the `urn:uuid:` scheme. Or using a digest, with the digest prefix. For example, `sha256:`."#
            .to_string(),
        );
        obj.examples = vec![
            json!("urn:uuid:018123ef-a791-40d8-b62a-f70a350245d4"),
            json!("sha256:dc60aeb735c16a71b6fc56e84ddb8193e3a6d1ef0b7e958d77e78fc039a5d04e"),
        ];

        RefOr::T(Schema::Object(obj))
    }
}

impl Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(IdVisitor)
    }
}

struct IdVisitor;

impl Visitor<'_> for IdVisitor {
    type Value = Id;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("a hash key with a valid prefix")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Id::from_str(v).map_err(|e| E::custom(e.to_string()))
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Id::Sha256(inner) => {
                write!(f, "sha256:{inner}")
            }
            Id::Sha384(inner) => {
                write!(f, "sha384:{inner}")
            }
            Id::Sha512(inner) => {
                write!(f, "sha512:{inner}")
            }
            Id::Uuid(inner) => {
                write!(f, "{}", inner.urn())
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdError {
    #[error("Missing prefix")]
    MissingPrefix,
    #[error("Unsupported algorithm {0}")]
    UnsupportedAlgorithm(String),
    #[error(transparent)]
    InvalidUuid(uuid::Error),
    #[error(transparent)]
    Purl(PurlErr),
}

impl FromStr for Id {
    type Err = IdError;

    fn from_str(key: &str) -> Result<Self, Self::Err> {
        if let Some((prefix, value)) = key.split_once(':') {
            match prefix {
                "sha256" => Ok(Self::Sha256(value.to_string())),
                "sha384" => Ok(Self::Sha384(value.to_string())),
                "sha512" => Ok(Self::Sha512(value.to_string())),
                "urn" => Ok(Self::Uuid(
                    Uuid::try_parse(key).map_err(IdError::InvalidUuid)?,
                )),
                _ => Err(Self::Err::UnsupportedAlgorithm(prefix.to_string())),
            }
        } else {
            Err(Self::Err::MissingPrefix)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::id::Id;
    use serde_json::json;

    #[test]
    fn deserialize() -> Result<(), anyhow::Error> {
        let key: Id = serde_json::from_value(json!("sha256:123123"))?;

        assert_eq!(key, Id::Sha256("123123".to_string()));

        let _key: Id =
            serde_json::from_value(json!("urn:uuid:2fd0d1b7-a908-4d63-9310-d57a7f77c6df"))?;

        Ok(())
    }

    #[test]
    fn serialize() -> Result<(), anyhow::Error> {
        let key = Id::Sha256("123123".to_string());

        let raw = serde_json::to_string(&key)?;

        assert_eq!(raw, "\"sha256:123123\"");
        Ok(())
    }

    #[test]
    fn invalid() {
        assert!(Id::parse_uuid("invalid").is_err());
    }
}

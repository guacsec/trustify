use cpe::{
    cpe::Cpe as _,
    uri::{OwnedUri, Uri},
};
use deepsize::{Context, DeepSizeOf};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error, Visitor},
};
use std::{
    borrow::Cow,
    cmp::Ordering,
    fmt::{Debug, Display, Formatter},
    str::FromStr,
};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{KnownFormat, ObjectBuilder, RefOr, Schema, SchemaFormat, Type},
};
use uuid::Uuid;

use crate::db::query::Valuable;

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Cpe {
    uri: OwnedUri,
}

impl DeepSizeOf for Cpe {
    fn deep_size_of_children(&self, context: &mut Context) -> usize {
        fn comp(value: cpe::component::Component, ctx: &mut Context) -> usize {
            if let cpe::component::Component::Value(v) = value {
                v.deep_size_of_children(ctx)
            } else {
                0
            }
        }

        fn lang(lang: &cpe::cpe::Language, ctx: &mut Context) -> usize {
            if let cpe::cpe::Language::Language(v) = lang {
                v.as_str().deep_size_of_children(ctx)
            } else {
                0
            }
        }

        comp(self.uri.vendor(), context)
            + comp(self.uri.product(), context)
            + comp(self.uri.version(), context)
            + comp(self.uri.update(), context)
            + comp(self.uri.edition(), context)
            + comp(self.uri.sw_edition(), context)
            + comp(self.uri.target_sw(), context)
            + comp(self.uri.other(), context)
            + lang(self.uri.language(), context)
    }
}

impl ToSchema for Cpe {
    fn name() -> Cow<'static, str> {
        "Cpe".into()
    }
}

impl PartialSchema for Cpe {
    fn schema() -> RefOr<Schema> {
        ObjectBuilder::new()
            .schema_type(Type::String)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Uri)))
            .into()
    }
}

impl Display for Cpe {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.uri, f)
    }
}

impl Serialize for Cpe {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> Deserialize<'de> for Cpe {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(CpeVisitor)
    }
}

impl Valuable for Cpe {
    fn like(&self, other: &str) -> bool {
        match Cpe::from_str(other) {
            Ok(cpe) => cpe.uri.is_superset(&self.uri),
            _ => self.to_string().contains(other),
        }
    }
}
impl PartialOrd<String> for Cpe {
    fn partial_cmp(&self, other: &String) -> Option<Ordering> {
        match Cpe::from_str(other) {
            Ok(cpe) if self.eq(&cpe) => Some(Ordering::Equal),
            _ => self.to_string().partial_cmp(other),
        }
    }
}
impl PartialEq<String> for Cpe {
    fn eq(&self, other: &String) -> bool {
        match Cpe::from_str(other) {
            Ok(p) => self.eq(&p),
            _ => self.to_string().eq(other),
        }
    }
}

struct CpeVisitor;

impl Visitor<'_> for CpeVisitor {
    type Value = Cpe;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("a CPE")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        v.try_into().map_err(Error::custom)
    }
}

const NAMESPACE: Uuid = Uuid::from_bytes([
    0x1b, 0xf1, 0x2a, 0xd5, 0x0d, 0x67, 0x41, 0x18, 0xa1, 0x38, 0xb8, 0x9f, 0x19, 0x35, 0xe0, 0xa7,
]);

impl Cpe {
    /// Build a v5 UUID for this CPE.
    pub fn uuid(&self) -> Uuid {
        let result = Uuid::new_v5(
            &NAMESPACE,
            match self.part() {
                CpeType::Any => b"*",
                CpeType::Hardware => b"h",
                CpeType::OperatingSystem => b"o",
                CpeType::Application => b"a",
                CpeType::Empty => b"",
            },
        );

        let result = Uuid::new_v5(&result, self.vendor().as_ref().as_bytes());
        let result = Uuid::new_v5(&result, self.product().as_ref().as_bytes());
        let result = Uuid::new_v5(&result, self.version().as_ref().as_bytes());
        let result = Uuid::new_v5(&result, self.update().as_ref().as_bytes());
        let result = Uuid::new_v5(&result, self.edition().as_ref().as_bytes());

        match self.language() {
            Language::Any => Uuid::new_v5(&result, b"*"),
            Language::Language(value) => Uuid::new_v5(&result, value.as_bytes()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Component {
    Any,
    NotApplicable,
    Value(String),
}

impl AsRef<str> for Component {
    fn as_ref(&self) -> &str {
        match self {
            Self::Any => "*",
            Self::NotApplicable => "",
            Self::Value(value) => value,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Language {
    Any,
    Language(String),
}

pub enum CpeType {
    Any,
    Hardware,
    OperatingSystem,
    Application,
    Empty,
}

impl AsRef<str> for CpeType {
    fn as_ref(&self) -> &str {
        match self {
            Self::Any => "*",
            Self::Hardware => "h",
            Self::OperatingSystem => "o",
            Self::Application => "a",
            Self::Empty => "",
        }
    }
}

impl Display for CpeType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl From<cpe::cpe::CpeType> for CpeType {
    fn from(value: cpe::cpe::CpeType) -> Self {
        match value {
            cpe::cpe::CpeType::Any => Self::Any,
            cpe::cpe::CpeType::Hardware => Self::Hardware,
            cpe::cpe::CpeType::OperatingSystem => Self::OperatingSystem,
            cpe::cpe::CpeType::Application => Self::Application,
            cpe::cpe::CpeType::Empty => Self::Empty,
        }
    }
}

impl From<cpe::cpe::Language> for Language {
    fn from(value: cpe::cpe::Language) -> Self {
        match value {
            cpe::cpe::Language::Any => Self::Any,
            cpe::cpe::Language::Language(lang) => Self::Language(lang.into_string()),
        }
    }
}

impl From<cpe::component::Component<'_>> for Component {
    fn from(value: cpe::component::Component<'_>) -> Self {
        match value {
            cpe::component::Component::Any => Self::Any,
            cpe::component::Component::NotApplicable => Self::NotApplicable,
            cpe::component::Component::Value(inner) => Self::Value(inner.to_string()),
        }
    }
}

impl Cpe {
    pub fn part(&self) -> CpeType {
        self.uri.part().into()
    }

    pub fn vendor(&self) -> Component {
        self.uri.vendor().into()
    }

    pub fn product(&self) -> Component {
        self.uri.product().into()
    }

    pub fn version(&self) -> Component {
        self.uri.version().into()
    }

    pub fn update(&self) -> Component {
        self.uri.update().into()
    }

    pub fn edition(&self) -> Component {
        self.uri.edition().into()
    }

    pub fn language(&self) -> Language {
        self.uri.language().clone().into()
    }
}

impl Debug for Cpe {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.uri, f)
    }
}

impl From<Uri<'_>> for Cpe {
    fn from(uri: Uri) -> Self {
        Self {
            uri: uri.to_owned(),
        }
    }
}

impl From<OwnedUri> for Cpe {
    fn from(uri: OwnedUri) -> Self {
        Self { uri }
    }
}

impl FromStr for Cpe {
    type Err = <OwnedUri as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            uri: OwnedUri::from_str(s)?,
        })
    }
}

impl TryFrom<&str> for Cpe {
    type Error = <OwnedUri as FromStr>::Err;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            uri: OwnedUri::from_str(value)?,
        })
    }
}

impl TryFrom<String> for Cpe {
    type Error = <OwnedUri as FromStr>::Err;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

pub trait CpeCompare: cpe::cpe::Cpe {
    fn is_superset<O: CpeCompare>(&self, other: &O) -> bool {
        self.compare(other).superset()
    }

    fn compare<O: CpeCompare>(&self, other: &O) -> CpeCmpResult {
        let part = if self.part() != other.part() {
            CpeCmp::Disjoint
        } else {
            CpeCmp::Equal
        };

        let vendor = Self::component_compare(self.vendor(), other.vendor());
        let product = Self::component_compare(self.product(), other.product());
        let version = Self::component_compare(self.version(), other.version());
        let update = Self::component_compare(self.update(), other.update());
        let edition = Self::component_compare(self.edition(), other.edition());
        let language = Self::language_compare(self.language(), other.language());

        CpeCmpResult {
            part,
            vendor,
            product,
            version,
            update,
            edition,
            language,
        }
    }

    fn language_compare(source: &cpe::cpe::Language, target: &cpe::cpe::Language) -> CpeCmp {
        match (source, target) {
            (cpe::cpe::Language::Any, _) => CpeCmp::Superset,
            (_, cpe::cpe::Language::Any) => CpeCmp::Subset,
            (
                cpe::cpe::Language::Language(source_lang),
                cpe::cpe::Language::Language(target_lang),
            ) => {
                if source_lang == target_lang {
                    CpeCmp::Equal
                } else {
                    CpeCmp::Disjoint
                }
            }
        }
    }

    fn component_compare(
        source: cpe::component::Component,
        target: cpe::component::Component,
    ) -> CpeCmp {
        if source == target {
            return CpeCmp::Equal;
        }

        match (source, target) {
            (
                cpe::component::Component::Value(source_val),
                cpe::component::Component::Value(target_val),
            ) => {
                if source_val.to_lowercase() == target_val.to_lowercase() {
                    CpeCmp::Equal
                } else {
                    CpeCmp::Disjoint
                }
            }
            (cpe::component::Component::Any, _) => CpeCmp::Superset,
            (_, cpe::component::Component::Any) => CpeCmp::Subset,
            (cpe::component::Component::NotApplicable, _)
            | (_, cpe::component::Component::NotApplicable) => CpeCmp::Subset,
        }
    }
}

impl<T: cpe::cpe::Cpe> CpeCompare for T {
    // defaults are perfectly sufficient.
}

#[allow(unused)]
pub enum CpeCmp {
    Undefined,
    Superset,
    Equal,
    Subset,
    Disjoint,
}

pub struct CpeCmpResult {
    part: CpeCmp,
    vendor: CpeCmp,
    product: CpeCmp,
    version: CpeCmp,
    update: CpeCmp,
    edition: CpeCmp,
    language: CpeCmp,
}

#[allow(unused)]
impl CpeCmpResult {
    pub fn disjoint(&self) -> bool {
        matches!(self.part, CpeCmp::Disjoint)
            || matches!(self.vendor, CpeCmp::Disjoint)
            || matches!(self.product, CpeCmp::Disjoint)
            || matches!(self.version, CpeCmp::Disjoint)
            || matches!(self.update, CpeCmp::Disjoint)
            || matches!(self.edition, CpeCmp::Disjoint)
            || matches!(self.language, CpeCmp::Disjoint)
    }

    pub fn superset(&self) -> bool {
        matches!(self.part, CpeCmp::Superset | CpeCmp::Equal)
            && matches!(self.vendor, CpeCmp::Superset | CpeCmp::Equal)
            && matches!(self.product, CpeCmp::Superset | CpeCmp::Equal)
            && matches!(self.version, CpeCmp::Superset | CpeCmp::Equal)
            && matches!(self.update, CpeCmp::Superset | CpeCmp::Equal)
            && matches!(self.edition, CpeCmp::Superset | CpeCmp::Equal)
            && matches!(self.language, CpeCmp::Superset | CpeCmp::Disjoint)
    }

    pub fn subset(&self) -> bool {
        matches!(self.part, CpeCmp::Subset | CpeCmp::Equal)
            && matches!(self.vendor, CpeCmp::Subset | CpeCmp::Equal)
            && matches!(self.product, CpeCmp::Subset | CpeCmp::Equal)
            && matches!(self.version, CpeCmp::Subset | CpeCmp::Equal)
            && matches!(self.update, CpeCmp::Subset | CpeCmp::Equal)
            && matches!(self.edition, CpeCmp::Subset | CpeCmp::Equal)
            && matches!(self.language, CpeCmp::Subset | CpeCmp::Disjoint)
    }

    pub fn equal(&self) -> bool {
        matches!(self.part, CpeCmp::Equal)
            && matches!(self.vendor, CpeCmp::Equal)
            && matches!(self.product, CpeCmp::Equal)
            && matches!(self.version, CpeCmp::Equal)
            && matches!(self.update, CpeCmp::Equal)
            && matches!(self.edition, CpeCmp::Equal)
            && matches!(self.language, CpeCmp::Disjoint)
    }
}

#[macro_export]
macro_rules! apply {
    ($c: expr, $v:expr => $n:ident) => {
        if let Some($n) = &$v.$n {
            $c.$n($n);
        }
    };
    ($c: expr, $v:expr => $n:ident, $($m:ident),+) => {
        apply!($c, $v => $n );
        apply!($c, $v => $($m),+)
    };
}

#[macro_export]
macro_rules! apply_fix {
    ($c: expr, $v:expr => $n:ident) => {
        if let Some($n) = &$v.$n {
            if $n == "*" {
                $c.$n("");
            } else {
                $c.$n($n);
            }

        }
    };
    ($c: expr, $v:expr => $n:ident, $($m:tt),+) => {
        apply_fix!($c, $v => $n );
        apply_fix!($c, $v => $($m),+)
    };
}

#[macro_export]
macro_rules! impl_try_into_cpe {
    ($ty:ty) => {
        impl TryInto<::cpe::uri::OwnedUri> for &$ty {
            type Error = ::cpe::error::CpeError;

            fn try_into(self) -> Result<::cpe::uri::OwnedUri, Self::Error> {
                use $crate::apply_fix;
                use $crate::apply;

                let mut cpe = ::cpe::uri::Uri::builder();

                apply!(cpe, self => part);
                apply_fix!(cpe, self => vendor, product, version, update, edition);

                // apply the fix for the language field

                if let Some(language) = &self.language {
                    if language == "*" {
                        cpe.language("ANY");
                    } else {
                        cpe.language(language);
                    }
                }

                Ok(cpe.validate()?.to_owned())
            }
        }
    };
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn uuid_simple() {
        let cpe = Cpe::from_str("cpe:/a:redhat:enterprise_linux:9::crb").expect("must parse");
        assert_eq!(
            cpe.uuid().to_string(),
            "61bca16a-febc-5d79-8b4d-f51fa37c876d"
        );
    }
}

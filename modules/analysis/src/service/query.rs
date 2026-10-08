use serde::{Deserialize, Deserializer};
use std::collections::HashSet;
use std::str::FromStr;
use trustify_common::{cpe::Cpe, db::query::Query, purl::Purl};
use trustify_entity::relationship::Relationship;
use utoipa::IntoParams;

#[derive(Copy, Clone, Debug)]
pub enum ComponentReference<'a> {
    /// The ID of the component.
    ///
    /// This is the ID provided by the document. For CycloneDX, this is the `bom-ref`.
    Id(&'a str),
    /// The name of the component
    Name(&'a str),
    /// A PURL of the component
    Purl(&'a Purl),
    /// A CPE of the component
    Cpe(&'a Cpe),
}

impl<'a> From<&'a Cpe> for ComponentReference<'a> {
    fn from(value: &'a Cpe) -> Self {
        Self::Cpe(value)
    }
}

impl<'a> From<&'a Purl> for ComponentReference<'a> {
    fn from(value: &'a Purl) -> Self {
        Self::Purl(value)
    }
}

#[derive(Copy, Clone, Debug)]
pub enum GraphQuery<'a> {
    Component(ComponentReference<'a>),
    Query(&'a Query),
}

impl<'a> From<ComponentReference<'a>> for GraphQuery<'a> {
    fn from(reference: ComponentReference<'a>) -> Self {
        Self::Component(reference)
    }
}

impl<'a> From<&'a Cpe> for GraphQuery<'a> {
    fn from(value: &'a Cpe) -> Self {
        Self::Component(ComponentReference::Cpe(value))
    }
}

impl<'a> From<&'a Purl> for GraphQuery<'a> {
    fn from(value: &'a Purl) -> Self {
        Self::Component(ComponentReference::Purl(value))
    }
}

impl<'a> From<&'a Query> for GraphQuery<'a> {
    fn from(query: &'a Query) -> Self {
        Self::Query(query)
    }
}

/// Options when querying the graph.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, IntoParams)]
pub struct QueryOptions {
    /// The level of ancestors to return.
    ///
    /// Zero, the default, meaning none.
    #[serde(default)]
    pub ancestors: u64,
    /// The level of descendants to return.
    ///
    /// Zero, the default, meaning none.
    #[serde(default)]
    pub descendants: u64,
    /// A set of relationships to filter for, deserialized from a
    /// comma-delimited string
    ///
    /// An empty set, the default, meaning all relationships.
    #[serde(default, deserialize_with = "deserialize_relationships")]
    #[param(value_type = String)]
    pub relationships: HashSet<Relationship>,
}

/// Options specific to generating an SBOM from the latest component results.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, IntoParams)]
pub struct LatestGenerationOptions {
    #[cfg(feature = "latest_sbom_generation")]
    /// Return an aggregated SPDX SBOM instead of components.
    #[serde(default)]
    pub generate_sbom: bool,
    #[cfg(feature = "latest_sbom_generation")]
    /// Input SBOM formats included by generated output. Defaults to both.
    #[serde(default)]
    pub source_format: crate::sbom_generation::SourceFormatFilter,
    #[cfg(feature = "latest_sbom_generation")]
    /// Optional generated document name and supplier overrides.
    #[serde(default)]
    pub document_name: Option<String>,
    #[cfg(feature = "latest_sbom_generation")]
    #[serde(default)]
    pub supplier: Option<String>,
}

fn deserialize_relationships<'de, D>(deserializer: D) -> Result<HashSet<Relationship>, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = String::deserialize(deserializer)?;
    buf.split_terminator(',')
        .map(Relationship::from_str)
        .collect::<Result<HashSet<_>, _>>()
        .map_err(serde::de::Error::custom)
}

impl QueryOptions {
    pub fn any() -> Self {
        Self {
            ancestors: u64::MAX,
            descendants: u64::MAX,
            ..Default::default()
        }
    }

    pub fn ancestors() -> Self {
        Self {
            ancestors: u64::MAX,
            ..Default::default()
        }
    }

    pub fn descendants() -> Self {
        Self {
            descendants: u64::MAX,
            ..Default::default()
        }
    }
}

impl From<()> for QueryOptions {
    fn from(_: ()) -> Self {
        Self::default()
    }
}

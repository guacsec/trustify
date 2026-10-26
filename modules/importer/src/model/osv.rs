use super::*;
use std::collections::HashSet;

/// How OSV documents are retrieved. When omitted, HTTP(S) `all.json` URLs use
/// REST and all other sources use Git.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum OsvTransport {
    Git,
    Http,
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct OsvImporter {
    #[serde(flatten)]
    pub common: CommonImporter,

    /// A Git repository URL or an OSV REST index URL.
    pub source: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<OsvTransport>,

    /// Base URL for REST records (`<id>.json`). Defaults to the index directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<Url>,

    /// An optional branch. Will use the default branch otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,

    /// An optional path to start searching for documents. Will use the root of the repository otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub years: HashSet<u16>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_year: Option<u16>,
}

impl Deref for OsvImporter {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for OsvImporter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

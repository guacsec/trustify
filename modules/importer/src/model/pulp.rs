use super::*;

#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct PulpImporter {
    #[serde(flatten)]
    pub common: CommonImporter,

    /// The base URL of the Pulp repository (must serve a `PULP_MANIFEST` file)
    pub source: String,

    /// Authentication credentials for the source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<PulpAuth>,

    /// Only process files matching these patterns (glob-style)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only_patterns: Vec<String>,

    /// Number of retries when fetching individual files
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetch_retries: Option<usize>,
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
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PulpAuth {
    Basic { username: String, password: String },
    Bearer { token: String },
}

impl Deref for PulpImporter {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for PulpImporter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

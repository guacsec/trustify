use super::*;

/// Importer configuration for known-exploited-vulnerability catalogs
/// (e.g. CISA KEV).
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
pub struct KevImporter {
    /// Common importer options.
    #[serde(flatten)]
    pub common: CommonImporter,

    /// URL of the catalog document to import.
    #[serde(default = "default::source")]
    pub source: String,

    /// Catalog source identifier under which the imported entries are stored
    /// (and replaced on each run). Defaults to "cisa".
    #[serde(default)]
    pub catalog: Option<String>,
}

/// Default URL of the CISA KEV catalog document.
pub const DEFAULT_SOURCE_KEV_CATALOG: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

mod default {
    pub fn source() -> String {
        super::DEFAULT_SOURCE_KEV_CATALOG.into()
    }
}

impl Deref for KevImporter {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for KevImporter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

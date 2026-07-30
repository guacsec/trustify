use super::*;

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
    #[serde(flatten)]
    pub common: CommonImporter,

    #[serde(default = "default::source")]
    pub source: String,
}

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

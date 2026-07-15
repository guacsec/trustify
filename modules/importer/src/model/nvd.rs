use super::*;
use std::collections::HashSet;

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
pub struct NvdImporter {
    #[serde(flatten)]
    pub common: CommonImporter,

    /// The base URL of the GitHub repository publishing NVD data as per-year
    /// release assets (`CVE-<year>.json.xz` + `.meta`), in the NVD-API JSON
    /// schema. The latest release is always used.
    #[serde(default = "default::source")]
    pub source: String,

    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub years: HashSet<u16>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_year: Option<u16>,
}

pub const DEFAULT_SOURCE_NVD: &str = "https://github.com/fkie-cad/nvd-json-data-feeds";

mod default {
    pub fn source() -> String {
        super::DEFAULT_SOURCE_NVD.into()
    }
}

impl Deref for NvdImporter {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for NvdImporter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

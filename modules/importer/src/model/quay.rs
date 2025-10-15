use trustify_common::model::BinaryByteSize;

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
pub struct QuayImporter {
    #[serde(flatten)]
    pub common: CommonImporter,

    /// The name of the quay registry, e.g. quay.io
    #[serde(default = "default::source")]
    pub source: String,

    /// The API token authorizing access to the quay registry
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_token: Option<String>,

    /// The namespace of the registry to "walk"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// The max size of the ingested SBOM's (None is unlimited)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_limit: Option<BinaryByteSize>,

    /// The maximum concurrent repository fetches
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<usize>,
}

pub const DEFAULT_SOURCE_QUAY: &str = "quay.io";

mod default {
    pub fn source() -> String {
        super::DEFAULT_SOURCE_QUAY.into()
    }
}

impl Deref for QuayImporter {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for QuayImporter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

impl QuayImporter {
    pub fn repositories_url(&self, page: &str) -> String {
        // NOTE: "namespace" trumps "public", i.e. non-public may be
        // returned for a namespace
        let ns = self.namespace.as_deref().unwrap_or_default();
        format!(
            "{}/api/v1/repository?public=true&last_modified=true&next_page={page}&namespace={ns}",
            self.base_url()
        )
    }
    pub fn repository_url(&self, namespace: &str, name: &str) -> String {
        format!("{}/api/v1/repository/{namespace}/{name}", self.base_url())
    }

    pub fn base_url(&self) -> String {
        if self.source.to_lowercase().starts_with("http") {
            self.source.clone()
        } else {
            format!("https://{}", self.source)
        }
    }
}
